use bloom_broker::journal::{
    AuditSigner, BrokerJournal, BudgetLimits, ClockCondition, DurablePoint, FaultHook,
    JournalError, ReservationRequest, ReservationState, SlidingBudgetLimit, SlidingValueLimit,
    TimeReading, derive_batch_child_operation_id,
};
use bloom_triad_protocol::{
    ApprovalLifecycleState, Base64UrlBytes, BootEpoch, CryptoSuite, DecimalU64, DecimalU256,
    DerivationRef, Digest32, KeyRef, KeySpec, NormalizedSignature, OperationId, OperationState,
    SelectorKind, SignOperationIdentity, SignatureEncoding, SigningResult, Token,
    UnsignedSignRequest,
};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use rusqlite::Connection;
use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier},
    thread,
};
use tempfile::TempDir;

struct TestAuditSigner(SigningKey);

impl AuditSigner for TestAuditSigner {
    fn key_id(&self) -> Token {
        Token::new("broker-audit-test-1").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(&self.0.sign(message).to_bytes()))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id != &self.key_id() {
            return Err("unknown audit signing key".into());
        }
        let bytes: [u8; 64] = signature
            .decode()
            .try_into()
            .map_err(|_| "invalid audit signature length")?;
        self.0
            .verifying_key()
            .verify(message, &ed25519_dalek::Signature::from_bytes(&bytes))
            .map_err(|error| error.to_string())
    }
}

fn audit_signer() -> Arc<dyn AuditSigner> {
    Arc::new(TestAuditSigner(SigningKey::from_bytes(&[42; 32])))
}

fn memory_journal() -> BrokerJournal {
    BrokerJournal::open_in_memory(audit_signer()).unwrap()
}

fn open_journal(path: &std::path::Path) -> BrokerJournal {
    BrokerJournal::open(path, audit_signer()).unwrap()
}

fn install_reservation_approval(journal: &BrokerJournal) {
    let approval_id = digest("22");
    journal
        .create_approval_record(&approval_id, "{}", &digest("aa"), None, None)
        .unwrap();
    journal
        .activate_approval_record(&approval_id, &operation_id(250), "{}")
        .unwrap();
}

fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

fn operation_id(value: u8) -> OperationId {
    OperationId::new(format!("{value:02x}").repeat(32)).unwrap()
}

fn request(value: u8) -> UnsignedSignRequest {
    let operation_id = operation_id(value);
    let key_ref = KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("local-default").unwrap(),
        locator: "key-1".into(),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: digest("44"),
        derivation: Some(DerivationRef::Bip32Secp256k1 {
            root_key_id: Token::new("root-1").unwrap(),
            path: "m/44'/60'/0'/0/0".into(),
        }),
    };
    let identity = SignOperationIdentity {
        operation_id: operation_id.clone(),
        approval_id: digest("22"),
        key_ref: key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        ordered_payload_digests: vec![digest("33")],
        ordered_hashes: vec![digest("55")],
        petal_use_claim_digest: None,
        claim_assurance_digest: None,
        policy_version: DecimalU64::new(1),
        policy_digest: digest("66"),
    };
    let mut request = UnsignedSignRequest {
        schema: Token::new("bloom.sign-request/1").unwrap(),
        attempt_id: Digest32::new(format!("{value:02x}").repeat(32)).unwrap(),
        operation_id,
        operation_digest: identity.digest().unwrap(),
        attempt_digest: digest("00"),
        audience: Token::new("bloom-signer").unwrap(),
        issuer_service_id: Token::new("bloom-broker").unwrap(),
        issuer_boot_epoch: BootEpoch::new("77".repeat(16)).unwrap(),
        broker_signing_key_id: Token::new("broker-app-1").unwrap(),
        approval_id: identity.approval_id,
        wallet_id: Token::new("wallet-1").unwrap(),
        key_ref,
        crypto_suite: identity.crypto_suite,
        selector_kind: SelectorKind::Exact,
        ordered_payload_digests: identity.ordered_payload_digests,
        ordered_hashes: identity.ordered_hashes,
        signature_count: DecimalU64::new(1),
        petal_use_claim_digest: None,
        claim_assurance_digest: None,
        policy_version: identity.policy_version,
        policy_digest: identity.policy_digest,
        validation_receipt_digest: digest("88"),
        issued_at_ms: DecimalU64::new(1_900_000_000_000),
        not_before_ms: DecimalU64::new(1_900_000_000_000),
        expires_at_ms: DecimalU64::new(1_900_000_030_000),
    };
    request.attempt_digest = request.computed_attempt_digest().unwrap();
    request
}

fn result(request: &UnsignedSignRequest, receipt_byte: &str) -> SigningResult {
    SigningResult {
        operation_id: request.operation_id.clone(),
        operation_digest: request.operation_digest.clone(),
        signatures: vec![NormalizedSignature {
            crypto_suite: request.crypto_suite,
            bytes: Base64UrlBytes::from_bytes(&[0; 65]),
        }],
        signer_receipt_digest: digest(receipt_byte),
        broker_receipt_digest: digest("aa"),
    }
}

fn advance_to_committed(journal: &BrokerJournal, operation_id: &OperationId) {
    for state in [
        OperationState::Validated,
        OperationState::Reserved,
        OperationState::Dispatched,
        OperationState::DownstreamAccepted,
        OperationState::Committed,
    ] {
        journal.transition_operation(operation_id, state).unwrap();
    }
}

fn limits(maximum: u64) -> BudgetLimits {
    BudgetLimits {
        max_operations: maximum,
        max_signatures: maximum,
        rate_limits: vec![],
        value_limits: BTreeMap::from([(
            "eip155:1/slip44:60".into(),
            DecimalU256::parse((maximum * 10).to_string()).unwrap(),
        )]),
        rolling_value_limits: vec![],
    }
}

#[test]
fn ac10_sliding_windows_use_exact_continuous_boundaries() {
    let journal = memory_journal();
    install_reservation_approval(&journal);
    let mut bounded = limits(10);
    bounded.rate_limits = vec![SlidingBudgetLimit {
        max_operations: 2,
        max_signatures: 2,
        duration_ms: 1_000,
    }];
    assert_eq!(
        protocol_code(journal.reserve(&reservation(9), &bounded).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::ClockUntrusted
    );
    journal
        .observe_time(
            TimeReading {
                utc_ms: Some(1_000),
                monotonic_elapsed_ms: 0,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    let mut first = reservation(1);
    first.reserved_at_ms = 1_000;
    journal.reserve(&first, &bounded).unwrap();
    journal
        .observe_time(
            TimeReading {
                utc_ms: Some(1_500),
                monotonic_elapsed_ms: 500,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    let mut second = reservation(2);
    second.reserved_at_ms = 1_500;
    journal.reserve(&second, &bounded).unwrap();
    journal
        .observe_time(
            TimeReading {
                utc_ms: Some(1_999),
                monotonic_elapsed_ms: 499,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    let mut denied = reservation(3);
    denied.reserved_at_ms = 1_999;
    assert_eq!(
        protocol_code(journal.reserve(&denied, &bounded).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::LimitExceededRate
    );
    journal
        .observe_time(
            TimeReading {
                utc_ms: Some(2_000),
                monotonic_elapsed_ms: 1,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    denied.reserved_at_ms = 2_000;
    journal.reserve(&denied, &bounded).unwrap();
}

#[test]
fn reservation_fails_closed_without_canonical_active_approval() {
    let journal = memory_journal();
    assert_eq!(
        protocol_code(journal.reserve(&reservation(1), &limits(2)).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::ApprovalRevoked
    );
}

#[test]
fn ac10_clock_faults_freeze_or_advance_effective_time_fail_closed() {
    let journal = memory_journal();
    install_reservation_approval(&journal);
    let mut rate_limited = limits(10);
    rate_limited.rate_limits = vec![SlidingBudgetLimit {
        max_operations: 10,
        max_signatures: 10,
        duration_ms: 1_000,
    }];
    assert_eq!(
        journal
            .observe_time(
                TimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000,
                    boot_epoch: BootEpoch::from_bytes([1; 16]),
                },
                3_600_000,
                true,
            )
            .unwrap()
            .effective_now_ms,
        10_000
    );
    assert_eq!(
        protocol_code(
            journal
                .observe_time(
                    TimeReading {
                        utc_ms: Some(9_999),
                        monotonic_elapsed_ms: 10,
                        monotonic_anchor_ns: 1_000_000,
                        boot_epoch: BootEpoch::from_bytes([1; 16]),
                    },
                    3_600_000,
                    true,
                )
                .unwrap_err()
        ),
        bloom_triad_protocol::ProtocolErrorCode::ClockRollback
    );
    let mut blocked = reservation(30);
    blocked.reserved_at_ms = 10_000;
    assert_eq!(
        protocol_code(journal.reserve(&blocked, &rate_limited).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::ClockUntrusted
    );
    assert_eq!(
        protocol_code(
            journal
                .observe_time(
                    TimeReading {
                        utc_ms: None,
                        monotonic_elapsed_ms: 20,
                        monotonic_anchor_ns: 1_000_000,
                        boot_epoch: BootEpoch::from_bytes([1; 16]),
                    },
                    3_600_000,
                    true,
                )
                .unwrap_err()
        ),
        bloom_triad_protocol::ProtocolErrorCode::ClockUntrusted
    );
    assert_eq!(
        protocol_code(journal.reserve(&blocked, &rate_limited).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::ClockUntrusted
    );
    let forward = journal
        .observe_time(
            TimeReading {
                utc_ms: Some(10_000_000),
                monotonic_elapsed_ms: 100,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    assert_eq!(forward.effective_now_ms, 10_100);
    assert_eq!(forward.condition, ClockCondition::ForwardJumpRejected);
    let repeated_forward = journal
        .observe_time(
            TimeReading {
                utc_ms: Some(10_000_001),
                monotonic_elapsed_ms: 1,
                monotonic_anchor_ns: 2_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            false,
        )
        .unwrap();
    assert_eq!(
        repeated_forward.condition,
        ClockCondition::ForwardJumpRejected
    );
    assert_eq!(
        journal
            .audit_entries()
            .unwrap()
            .iter()
            .filter(|entry| entry.event_type == "clock.forward_jump")
            .count(),
        1
    );
    let repaired = journal.repair_clock(10_000_000).unwrap();
    assert_eq!(repaired.condition, ClockCondition::Repaired);
    journal.verify_audit_chain().unwrap();
}

#[test]
fn ac10_rolling_asset_windows_are_atomic_and_release_aware() {
    let journal = memory_journal();
    install_reservation_approval(&journal);
    let mut bounded = limits(100);
    bounded.rolling_value_limits = vec![SlidingValueLimit {
        asset_id: "eip155:1/slip44:60".into(),
        maximum: DecimalU256::parse("20").unwrap(),
        duration_ms: 1_000,
    }];
    journal
        .observe_time(
            TimeReading {
                utc_ms: Some(1_000),
                monotonic_elapsed_ms: 0,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    let mut first = reservation(1);
    first.reserved_at_ms = 1_000;
    journal.reserve(&first, &bounded).unwrap();
    journal
        .observe_time(
            TimeReading {
                utc_ms: Some(1_500),
                monotonic_elapsed_ms: 500,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    let mut second = reservation(2);
    second.reserved_at_ms = 1_500;
    journal.reserve(&second, &bounded).unwrap();
    journal
        .observe_time(
            TimeReading {
                utc_ms: Some(1_999),
                monotonic_elapsed_ms: 499,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    let mut third = reservation(3);
    third.reserved_at_ms = 1_999;
    assert_eq!(
        protocol_code(journal.reserve(&third, &bounded).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::LimitExceededValue
    );
    journal
        .finalize_reservation(
            &first.approval_id,
            &first.operation_id,
            ReservationState::Released,
        )
        .unwrap();
    journal.reserve(&third, &bounded).unwrap();

    let concurrent = memory_journal();
    install_reservation_approval(&concurrent);
    let concurrent = Arc::new(concurrent);
    concurrent
        .observe_time(
            TimeReading {
                utc_ms: Some(5_000),
                monotonic_elapsed_ms: 0,
                monotonic_anchor_ns: 1_000_000,
                boot_epoch: BootEpoch::from_bytes([1; 16]),
            },
            3_600_000,
            true,
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(11));
    let mut handles = Vec::new();
    for value in 40..50 {
        let journal = Arc::clone(&concurrent);
        let barrier = Arc::clone(&barrier);
        let bounded = bounded.clone();
        handles.push(thread::spawn(move || {
            let mut request = reservation(value);
            request.reserved_at_ms = 5_000;
            barrier.wait();
            journal.reserve(&request, &bounded)
        }));
    }
    barrier.wait();
    assert_eq!(
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(Result::is_ok)
            .count(),
        2
    );
}

fn reservation(value: u8) -> ReservationRequest {
    ReservationRequest {
        approval_id: digest("22"),
        operation_id: operation_id(value),
        operation_digest: digest("33"),
        signature_count: 1,
        reserved_at_ms: 1_900_000_000_000 + u64::from(value),
        observed_utc_ms: Some(1_900_000_000_000 + u64::from(value)),
        monotonic_anchor_ns: 1_000_000,
        clock_boot_epoch: BootEpoch::from_bytes([1; 16]),
        values: BTreeMap::from([(
            "eip155:1/slip44:60".into(),
            DecimalU256::parse("10").unwrap(),
        )]),
    }
}

fn protocol_code(error: JournalError) -> bloom_triad_protocol::ProtocolErrorCode {
    match error {
        JournalError::Protocol(error) => error.code,
        other => panic!("expected protocol error, got {other}"),
    }
}

#[test]
fn ac06_same_operation_retry_is_stable_and_conflicts_fail_closed() {
    let journal = memory_journal();
    install_reservation_approval(&journal);
    let first = request(1);
    journal.begin_sign_attempt(&first, false).unwrap();

    let mut retry = first.clone();
    retry.attempt_id = digest("ab");
    retry.issuer_boot_epoch = BootEpoch::new("cd".repeat(16)).unwrap();
    retry.issued_at_ms = DecimalU64::new(1_900_000_000_100);
    retry.not_before_ms = DecimalU64::new(1_900_000_000_100);
    retry.expires_at_ms = DecimalU64::new(1_900_000_030_100);
    retry.attempt_digest = digest("00");
    retry.attempt_digest = retry.computed_attempt_digest().unwrap();
    assert_eq!(
        journal
            .begin_sign_attempt(&retry, false)
            .unwrap()
            .operation_digest,
        first.operation_digest
    );
    let mut forbidden_retries = Vec::new();
    let mut changed = first.clone();
    changed.wallet_id = Token::new("wallet-2").unwrap();
    forbidden_retries.push(("wallet_id", changed));
    let mut changed = first.clone();
    changed.selector_kind = SelectorKind::Petal;
    forbidden_retries.push(("selector_kind", changed));
    let mut changed = first.clone();
    changed.signature_count = DecimalU64::new(2);
    forbidden_retries.push(("signature_count", changed));
    let mut changed = first.clone();
    changed.validation_receipt_digest = digest("89");
    forbidden_retries.push(("validation_receipt_digest", changed));
    let mut changed = first.clone();
    changed.issuer_service_id = Token::new("other-broker").unwrap();
    forbidden_retries.push(("issuer_service_id", changed));
    let mut changed = first.clone();
    changed.broker_signing_key_id = Token::new("broker-app-2").unwrap();
    forbidden_retries.push(("broker_signing_key_id", changed));
    let mut changed = first.clone();
    changed.audience = Token::new("other-signer").unwrap();
    forbidden_retries.push(("audience", changed));

    for (index, (field, mut changed)) in forbidden_retries.into_iter().enumerate() {
        changed.attempt_id = Digest32::new(format!("{:02x}", index + 32).repeat(32)).unwrap();
        changed.attempt_digest = digest("00");
        changed.attempt_digest = changed.computed_attempt_digest().unwrap();
        assert_eq!(
            protocol_code(journal.begin_sign_attempt(&changed, false).unwrap_err()),
            bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict,
            "{field}"
        );
    }
    let mut reused_attempt_id = retry.clone();
    reused_attempt_id.expires_at_ms = DecimalU64::new(1_900_000_029_000);
    reused_attempt_id.attempt_digest = digest("00");
    reused_attempt_id.attempt_digest = reused_attempt_id.computed_attempt_digest().unwrap();
    assert_eq!(
        protocol_code(
            journal
                .begin_sign_attempt(&reused_attempt_id, false)
                .unwrap_err()
        ),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );
    assert_eq!(
        protocol_code(journal.begin_sign_attempt(&retry, true).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );

    let mut conflict = first.clone();
    conflict.policy_version = DecimalU64::new(2);
    conflict.operation_digest = conflict.operation_identity().digest().unwrap();
    conflict.attempt_digest = digest("00");
    conflict.attempt_digest = conflict.computed_attempt_digest().unwrap();
    assert_eq!(
        protocol_code(journal.begin_sign_attempt(&conflict, false).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );

    journal.reserve(&reservation(1), &limits(2)).unwrap();
    advance_to_committed(&journal, &first.operation_id);
    let published = result(&first, "99");
    journal.publish_result(&digest("22"), &published).unwrap();
    journal.publish_result(&digest("22"), &published).unwrap();
    let mut different = published;
    different.signer_receipt_digest = digest("98");
    assert_eq!(
        protocol_code(
            journal
                .publish_result(&digest("22"), &different)
                .unwrap_err()
        ),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );
}

#[test]
fn ac10_concurrent_reservations_cannot_overspend_and_release_is_full() {
    let journal = memory_journal();
    install_reservation_approval(&journal);
    let journal = Arc::new(journal);
    let barrier = Arc::new(Barrier::new(21));
    let mut handles = Vec::new();
    for value in 1..=20 {
        let journal = Arc::clone(&journal);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            journal.reserve(&reservation(value), &limits(5))
        }));
    }
    barrier.wait();
    let successes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 5);

    let released = (1..=20)
        .find(|value| {
            journal
                .reservation_status(&digest("22"), &operation_id(*value))
                .unwrap()
                == Some(ReservationState::Reserved)
        })
        .unwrap();
    journal
        .finalize_reservation(
            &digest("22"),
            &operation_id(released),
            ReservationState::Released,
        )
        .unwrap();
    journal.reserve(&reservation(21), &limits(5)).unwrap();

    let mut same_operation_retry = reservation(21);
    same_operation_retry.reserved_at_ms += 1_000;
    same_operation_retry.observed_utc_ms = Some(same_operation_retry.reserved_at_ms);
    same_operation_retry.monotonic_anchor_ns += 1_000_000;
    same_operation_retry.clock_boot_epoch = BootEpoch::from_bytes([2; 16]);
    journal.reserve(&same_operation_retry, &limits(5)).unwrap();

    let mut changed_retry = reservation(21);
    changed_retry.signature_count = 2;
    assert_eq!(
        protocol_code(journal.reserve(&changed_retry, &limits(5)).unwrap_err()),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );
}

#[test]
fn clock_schema_migrates_an_existing_broker_database() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("broker.sqlite3");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "
            CREATE TABLE reservations (
                approval_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                operation_digest TEXT NOT NULL,
                signature_count TEXT NOT NULL,
                reserved_at_ms TEXT NOT NULL,
                state TEXT NOT NULL,
                PRIMARY KEY (approval_id, operation_id)
            );
            CREATE TABLE clock_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_effective_ms TEXT NOT NULL,
                condition TEXT NOT NULL
            );
            INSERT INTO clock_state(singleton, last_effective_ms, condition)
            VALUES (1, '1000', 'HEALTHY');
            ",
        )
        .unwrap();
    drop(connection);

    let journal = open_journal(&path);
    let decision = journal
        .observe_time(
            TimeReading {
                utc_ms: Some(1_001),
                monotonic_elapsed_ms: 1,
                monotonic_anchor_ns: 2_000_000,
                boot_epoch: BootEpoch::from_bytes([3; 16]),
            },
            3_600_000,
            false,
        )
        .unwrap();
    assert_eq!(decision.effective_now_ms, 1_001);

    let connection = Connection::open(path).unwrap();
    for table in ["reservations", "clock_state"] {
        let columns = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(columns.iter().any(|column| column == "observed_utc_ms"));
        assert!(columns.iter().any(|column| column == "monotonic_anchor_ns"));
    }
}

#[test]
fn approval_lifecycle_and_audit_chain_are_closed_and_durable() {
    let journal = memory_journal();
    let approval_id = digest("21");
    journal
        .create_approval(&approval_id, ApprovalLifecycleState::Prepared)
        .unwrap();
    journal
        .transition_approval(&approval_id, ApprovalLifecycleState::AwaitingCeremony)
        .unwrap();
    journal
        .transition_approval(&approval_id, ApprovalLifecycleState::Active)
        .unwrap();
    assert_eq!(
        journal.approval_state(&approval_id).unwrap(),
        Some(ApprovalLifecycleState::Active)
    );
    assert!(
        journal
            .transition_approval(&approval_id, ApprovalLifecycleState::Prepared)
            .is_err()
    );
    journal.verify_audit_chain().unwrap();
    let entries = journal.audit_entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert!(
        entries
            .iter()
            .all(|entry| entry.signature.decode().len() == 64)
    );
}

#[test]
fn audit_chain_rejects_a_valid_hash_with_a_forged_service_signature() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("audit.sqlite");
    let journal = open_journal(&path);
    journal
        .create_approval(&digest("22"), ApprovalLifecycleState::Prepared)
        .unwrap();
    drop(journal);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE audit_chain SET signature = 'AA' WHERE sequence = 0",
            [],
        )
        .unwrap();
    assert!(open_journal(&path).verify_audit_chain().is_err());
}

struct CrashAt(DurablePoint);

impl FaultHook for CrashAt {
    fn after_durable(&self, point: DurablePoint) -> Result<(), String> {
        if point == self.0 {
            Err("simulated process death".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn ac07_durable_operation_survives_crash_after_ack_boundary() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("broker.sqlite");
    let first = request(1);
    let journal =
        open_journal(&path).with_fault_hook(Arc::new(CrashAt(DurablePoint::OperationReceived)));
    assert!(matches!(
        journal.begin_sign_attempt(&first, false),
        Err(JournalError::InjectedCrash { .. })
    ));
    drop(journal);

    let recovered = open_journal(&path);
    assert_eq!(
        recovered
            .operation(&first.operation_id)
            .unwrap()
            .unwrap()
            .state,
        OperationState::Received
    );
    recovered.verify_audit_chain().unwrap();
}

#[test]
fn ac07_fault_matrix_recovers_every_non_batch_durable_transition() {
    let directory = TempDir::new().unwrap();

    let approval_path = directory.path().join("approval.sqlite");
    let approval_id = digest("22");
    let journal = open_journal(&approval_path)
        .with_fault_hook(Arc::new(CrashAt(DurablePoint::ApprovalTransition)));
    assert!(matches!(
        journal.create_approval(&approval_id, ApprovalLifecycleState::Prepared),
        Err(JournalError::InjectedCrash { .. })
    ));
    drop(journal);
    assert_eq!(
        open_journal(&approval_path)
            .approval_state(&approval_id)
            .unwrap(),
        Some(ApprovalLifecycleState::Prepared)
    );

    let operation_path = directory.path().join("operation.sqlite");
    let sign_request = request(4);
    open_journal(&operation_path)
        .begin_sign_attempt(&sign_request, false)
        .unwrap();
    let journal = open_journal(&operation_path)
        .with_fault_hook(Arc::new(CrashAt(DurablePoint::OperationTransition)));
    assert!(matches!(
        journal.transition_operation(&sign_request.operation_id, OperationState::Validated),
        Err(JournalError::InjectedCrash { .. })
    ));
    drop(journal);
    assert_eq!(
        open_journal(&operation_path)
            .operation(&sign_request.operation_id)
            .unwrap()
            .unwrap()
            .state,
        OperationState::Validated
    );

    let reserve_path = directory.path().join("reserve.sqlite");
    let reserve_request = reservation(5);
    let reserve_setup = open_journal(&reserve_path);
    install_reservation_approval(&reserve_setup);
    drop(reserve_setup);
    let journal = open_journal(&reserve_path)
        .with_fault_hook(Arc::new(CrashAt(DurablePoint::ReservationCreated)));
    assert!(matches!(
        journal.reserve(&reserve_request, &limits(2)),
        Err(JournalError::InjectedCrash { .. })
    ));
    drop(journal);
    assert_eq!(
        open_journal(&reserve_path)
            .reservation_status(&reserve_request.approval_id, &reserve_request.operation_id)
            .unwrap(),
        Some(ReservationState::Reserved)
    );

    let journal = open_journal(&reserve_path)
        .with_fault_hook(Arc::new(CrashAt(DurablePoint::ReservationFinalized)));
    assert!(matches!(
        journal.finalize_reservation(
            &reserve_request.approval_id,
            &reserve_request.operation_id,
            ReservationState::Quarantined,
        ),
        Err(JournalError::InjectedCrash { .. })
    ));
    drop(journal);
    let recovered = open_journal(&reserve_path);
    assert_eq!(
        recovered
            .reservation_status(&reserve_request.approval_id, &reserve_request.operation_id)
            .unwrap(),
        Some(ReservationState::Quarantined)
    );
    recovered.verify_audit_chain().unwrap();
}

#[test]
fn ac12_batch_parent_and_children_publish_in_one_transaction() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("broker.sqlite");
    let parent = request(1);
    let setup = open_journal(&path);
    install_reservation_approval(&setup);
    setup.begin_sign_attempt(&parent, true).unwrap();
    setup.reserve(&reservation(1), &limits(2)).unwrap();
    advance_to_committed(&setup, &parent.operation_id);
    drop(setup);

    let mut child_a = result(&request(2), "91");
    child_a.operation_id = derive_batch_child_operation_id(&parent.operation_id, 0).unwrap();
    let mut child_b = result(&request(3), "92");
    child_b.operation_id = derive_batch_child_operation_id(&parent.operation_id, 1).unwrap();
    let parent_result = result(&parent, "90");
    let crashing =
        open_journal(&path).with_fault_hook(Arc::new(CrashAt(DurablePoint::BatchPublished)));
    assert!(matches!(
        crashing.publish_batch(
            &digest("22"),
            &parent_result,
            &[child_a.clone(), child_b.clone()]
        ),
        Err(JournalError::InjectedCrash { .. })
    ));
    drop(crashing);

    let recovered = open_journal(&path);
    let snapshot = recovered.operation(&parent.operation_id).unwrap().unwrap();
    assert_eq!(snapshot.state, OperationState::Succeeded);
    assert_eq!(snapshot.result, Some(parent_result.clone()));
    assert_eq!(
        recovered
            .reservation_status(&digest("22"), &parent.operation_id)
            .unwrap(),
        Some(ReservationState::Committed)
    );
    assert_eq!(
        recovered.batch_children(&parent.operation_id).unwrap(),
        vec![child_a, child_b]
    );
    assert_eq!(
        recovered
            .batch_child(&derive_batch_child_operation_id(&parent.operation_id, 0).unwrap())
            .unwrap(),
        recovered
            .batch_children(&parent.operation_id)
            .unwrap()
            .first()
            .cloned()
    );
    recovered
        .publish_batch(
            &digest("22"),
            &parent_result,
            &recovered.batch_children(&parent.operation_id).unwrap(),
        )
        .unwrap();
    recovered.verify_audit_chain().unwrap();

    let another_parent = request(4);
    let wrong_child = result(&request(5), "93");
    assert_eq!(
        protocol_code(
            recovered
                .publish_batch(
                    &digest("22"),
                    &result(&another_parent, "94"),
                    &[wrong_child]
                )
                .unwrap_err()
        ),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );
    assert_eq!(
        protocol_code(
            recovered
                .publish_batch(
                    &digest("22"),
                    &parent_result,
                    &vec![recovered.batch_children(&parent.operation_id).unwrap()[0].clone(); 33],
                )
                .unwrap_err()
        ),
        bloom_triad_protocol::ProtocolErrorCode::BackendInvalidRequest
    );
}

#[test]
fn signature_encoding_contract_remains_recoverable_65() {
    assert_eq!(
        CryptoSuite::Secp256k1Sha256Recoverable.signature_encoding(),
        SignatureEncoding::Secp256k1Recoverable65
    );
}
