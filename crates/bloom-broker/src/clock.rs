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
        let boot_epoch = durable_clock_boot_epoch(durable_clock_guard, boot_epoch)?;
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

fn durable_clock_boot_epoch(
    durable_clock_guard: bool,
    enrollment_boot_epoch: BootEpoch,
) -> Result<BootEpoch, ProtocolError> {
    if !durable_clock_guard {
        return Ok(enrollment_boot_epoch);
    }
    #[cfg(target_os = "linux")]
    {
        let boot_id_path = std::env::var_os("CREDENTIALS_DIRECTORY")
            .filter(|directory| !directory.is_empty())
            .map(std::path::PathBuf::from)
            .map(|directory| directory.join("kernel-boot-id"))
            .unwrap_or_else(|| "/proc/sys/kernel/random/boot_id".into());
        let raw = std::fs::read_to_string(&boot_id_path).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::ClockUntrusted,
                format!(
                    "read Linux kernel boot ID from {}: {error}",
                    boot_id_path.display()
                ),
            )
        })?;
        parse_linux_boot_epoch(&raw)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(ProtocolError::new(
            ProtocolErrorCode::ClockUntrusted,
            "durable clock guard requires a reviewed platform boot ID",
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_linux_boot_epoch(raw: &str) -> Result<BootEpoch, ProtocolError> {
    let mut compact = String::with_capacity(32);
    let mut segments = raw.trim().split('-');
    for expected_len in [8, 4, 4, 4, 12] {
        let segment = segments.next().ok_or_else(malformed_linux_boot_epoch)?;
        if segment.len() != expected_len || !segment.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(malformed_linux_boot_epoch());
        }
        compact.push_str(segment);
    }
    if segments.next().is_some() {
        return Err(malformed_linux_boot_epoch());
    }
    compact.make_ascii_lowercase();
    BootEpoch::new(compact).map_err(|_| malformed_linux_boot_epoch())
}

#[cfg(target_os = "linux")]
fn malformed_linux_boot_epoch() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::ClockUntrusted,
        "Linux kernel boot ID is malformed",
    )
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

    #[cfg(target_os = "linux")]
    #[test]
    fn durable_clock_uses_kernel_boot_id_instead_of_enrollment_epoch() {
        let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") else {
            return;
        };
        let expected = parse_linux_boot_epoch(&raw).unwrap();
        let selected = durable_clock_boot_epoch(true, BootEpoch::from_bytes([0xff; 16])).unwrap();
        assert_eq!(selected, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_boot_id_parser_rejects_noncanonical_input() {
        for malformed in [
            "00112233445566778899aabbccddeeff",
            "00112233-4455-6677-8899-aabbccddeef",
            "00112233-4455-6677-8899-aabbccddeefg",
            "00112233-4455-6677-8899-aabbccddeeff-extra",
        ] {
            assert!(parse_linux_boot_epoch(malformed).is_err());
        }
    }
}
