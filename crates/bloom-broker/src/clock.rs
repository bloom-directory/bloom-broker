use std::sync::Arc;

use bloom_broker_api::{BootEpoch, ProtocolError, ProtocolErrorCode, ReadinessState, Token};
use bloom_trusted_time::{MAX_FORWARD_STEP_MS, PlatformTimeSampler};
use parking_lot::Mutex;

use crate::journal::{BrokerJournal, ClockCondition, ClockDecision, JournalError, TimeReading};

pub struct BrokerClock {
    journal: Arc<BrokerJournal>,
    sampler: PlatformTimeSampler,
    boot_epoch: BootEpoch,
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
        let clock = Self {
            journal,
            sampler,
            boot_epoch,
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

fn clock_error(error: JournalError) -> ProtocolError {
    match error {
        JournalError::Protocol(error) => error,
        JournalError::InjectedCrash { message, .. } | JournalError::Storage(message) => {
            ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message)
        }
    }
}
