use std::sync::Arc;

use bloom_broker_api::{BootEpoch, ProtocolError, ProtocolErrorCode, ReadinessState, Token};
use bloom_trusted_time::{MAX_FORWARD_STEP_MS, PlatformTimeSampler};
use parking_lot::Mutex;

use crate::journal::{BrokerJournal, ClockCondition, ClockDecision, JournalError, TimeReading};

pub struct BrokerClock {
    journal: Arc<BrokerJournal>,
    sampler: PlatformTimeSampler,
    boot_epoch: BootEpoch,
    durable_clock_guard: bool,
    observation_lock: Mutex<()>,
}

impl BrokerClock {
    pub fn new(
        journal: Arc<BrokerJournal>,
        trusted_time_source: &str,
        boot_epoch: BootEpoch,
    ) -> Result<Self, ProtocolError> {
        let sampler = PlatformTimeSampler::new(trusted_time_source).map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::ClockUntrusted, error.to_string())
        })?;
        let durable_clock_guard = sampler.source().requires_durable_clock_guard();
        let clock = Self {
            journal,
            sampler,
            boot_epoch,
            durable_clock_guard,
            observation_lock: Mutex::new(()),
        };
        if !clock.journal.audit_degraded() {
            clock.observe(false)?;
        }
        Ok(clock)
    }

    pub fn observe(&self, rate_limited_mutation: bool) -> Result<ClockDecision, ProtocolError> {
        let _observation = self.observation_lock.lock();
        let reading = self.sampler.sample().map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::ClockUntrusted, error.to_string())
        })?;
        if !self.durable_clock_guard {
            // macOS administrator/root compromise is outside the service
            // boundary. Its wall clock is authoritative and legacy durable
            // clock state must not latch readiness across a restart.
            return host_wall_clock_decision(reading, self.boot_epoch.clone());
        }
        self.journal
            .observe_time(
                TimeReading {
                    utc_ms: reading.utc_ms,
                    monotonic_elapsed_ms: reading.monotonic_elapsed_ms,
                    monotonic_anchor_ns: reading.monotonic_anchor_ns,
                    boot_epoch: self.boot_epoch.clone(),
                },
                MAX_FORWARD_STEP_MS,
                rate_limited_mutation,
            )
            .map_err(clock_error)
    }

    pub fn now_ms(&self, rate_limited_mutation: bool) -> Result<u64, ProtocolError> {
        Ok(self.observe(rate_limited_mutation)?.effective_now_ms)
    }

    pub const fn uses_durable_clock_guard(&self) -> bool {
        self.durable_clock_guard
    }

    pub fn readiness(&self) -> Result<(ReadinessState, Vec<Token>), ProtocolError> {
        if self.journal.audit_degraded() {
            return Ok((
                ReadinessState::DegradedReadOnly,
                vec![Token::new("audit_journal_degraded")?],
            ));
        }
        let decision = match self.observe(false) {
            Ok(decision) => decision,
            Err(_) => {
                return Ok((
                    ReadinessState::DegradedReadOnly,
                    vec![Token::new("clock_untrusted")?],
                ));
            }
        };
        let condition = match decision.condition {
            ClockCondition::Healthy | ClockCondition::Repaired => {
                return Ok((ReadinessState::Ready, Vec::new()));
            }
            ClockCondition::ForwardJumpRejected => "clock_forward_jump",
            ClockCondition::Untrusted => "clock_untrusted",
            ClockCondition::RollbackFrozen => "clock_rollback",
        };
        Ok((
            ReadinessState::DegradedReadOnly,
            vec![Token::new(condition)?],
        ))
    }
}

fn host_wall_clock_decision(
    reading: bloom_trusted_time::PlatformTimeReading,
    boot_epoch: BootEpoch,
) -> Result<ClockDecision, ProtocolError> {
    let utc_ms = reading.utc_ms.ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorCode::ClockUntrusted,
            "platform wall clock is unavailable",
        )
    })?;
    Ok(ClockDecision {
        effective_now_ms: utc_ms,
        condition: ClockCondition::Healthy,
        observed_utc_ms: Some(utc_ms),
        monotonic_anchor_ns: reading.monotonic_anchor_ns,
        boot_epoch,
    })
}

fn clock_error(error: JournalError) -> ProtocolError {
    match error {
        JournalError::Protocol(error) => error,
        JournalError::InjectedCrash { message, .. } | JournalError::Storage(message) => {
            ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_trusted_time::PlatformTimeReading;

    #[test]
    fn host_wall_clock_accepts_forward_and_backward_changes() {
        let boot_epoch = BootEpoch::from_bytes([7; 16]);
        for utc_ms in [10_000, 40_000_000, 5_000] {
            let decision = host_wall_clock_decision(
                PlatformTimeReading {
                    utc_ms: Some(utc_ms),
                    monotonic_anchor_ns: 123,
                    monotonic_elapsed_ms: 0,
                },
                boot_epoch.clone(),
            )
            .unwrap();
            assert_eq!(decision.effective_now_ms, utc_ms);
            assert_eq!(decision.condition, ClockCondition::Healthy);
        }
    }
}
