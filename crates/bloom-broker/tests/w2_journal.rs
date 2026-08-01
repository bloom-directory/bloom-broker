use bloom_audit_checkpoint::{AppendOutcome, CheckpointError, CheckpointSink};
use bloom_broker::journal::{
    AuditSigner, BrokerJournal, BudgetLimits, ClockCondition, DurablePoint, FaultHook,
    JournalError, ReservationRequest, ReservationState, SlidingBudgetLimit, SlidingValueLimit,
    TimeReading, derive_batch_child_operation_id,
};
use bloom_triad_local_transport::LocalIdentity;
use bloom_triad_protocol::{
    ApprovalLifecycleState, Base64UrlBytes, BootEpoch, BrokerValidationReceipt, CryptoSuite,
    DecimalU64, DecimalU256, DerivationRef, Digest32, KeyRef, KeySpec, NormalizedSignature,
    OperationId, OperationState, SelectorKind, SignOperationIdentity, SignatureEncoding,
    SigningResult, Token, UnsignedSignRequest,
};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use rusqlite::{Connection, params};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tempfile::TempDir;

struct TestAuditSigner(SigningKey);

#[derive(Default)]
struct RecordingSelfCheckpoint(Mutex<Vec<bloom_triad_protocol::SignedJournalHead>>);

impl CheckpointSink for RecordingSelfCheckpoint {
    fn append_peer_head(
        &self,
        peer_head: &bloom_triad_protocol::SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        self.0.lock().unwrap().push(peer_head.clone());
        Ok(AppendOutcome::Appended)
    }
}

struct FailingSelfCheckpoint;

impl CheckpointSink for FailingSelfCheckpoint {
    fn append_peer_head(
        &self,
        _peer_head: &bloom_triad_protocol::SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        Err(CheckpointError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "forced self-checkpoint failure",
        )))
    }
}

#[derive(Default)]
struct ReorderingCheckpoint {
    calls: AtomicUsize,
    sequences: Mutex<Vec<u64>>,
}

impl CheckpointSink for ReorderingCheckpoint {
    fn append_peer_head(
        &self,
        peer_head: &bloom_triad_protocol::SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            // Without journal/checkpoint serialization this lets a later
            // mutation publish first and deterministically exposes rollback.
            thread::sleep(Duration::from_millis(100));
        }
        let sequence = peer_head.sequence.get();
        let mut sequences = self.sequences.lock().unwrap();
        if sequences
            .last()
            .is_some_and(|previous| sequence < *previous)
        {
            return Err(CheckpointError::SequenceRollback);
        }
        sequences.push(sequence);
        Ok(AppendOutcome::Appended)
    }
}

fn broker_identity() -> LocalIdentity {
    LocalIdentity {
        service_id: Token::new("bloom-broker").unwrap(),
        boot_epoch: BootEpoch::from_bytes([0x41; 16]),
        application_key_id: Token::new("broker-app").unwrap(),
        signing_key: Arc::new(SigningKey::from_bytes(&[0x42; 32])),
    }
}

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
    request.validation_receipt_digest = validation_receipt(&request).digest().unwrap();
    request.attempt_digest = request.computed_attempt_digest().unwrap();
    request
}

fn validation_receipt(request: &UnsignedSignRequest) -> BrokerValidationReceipt {
    BrokerValidationReceipt {
        approval_id: request.approval_id.clone(),
        approval_digest: request.approval_id.clone(),
        operation_digest: request.operation_digest.clone(),
        policy_version: request.policy_version.clone(),
        policy_digest: request.policy_digest.clone(),
        claim_digest: request.petal_use_claim_digest.clone(),
        assurance_digest: request.claim_assurance_digest.clone(),
        reservation_ids: vec![digest("77")],
        effective_claim_assurance: None,
        broker_key_id: request.broker_signing_key_id.clone(),
        broker_signature: Base64UrlBytes::from_bytes(&[7; 64]),
    }
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
    journal
        .begin_sign_attempt(&first, false, &validation_receipt(&first))
        .unwrap();

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
            .begin_sign_attempt(&retry, false, &validation_receipt(&retry))
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
            protocol_code(
                journal
                    .begin_sign_attempt(&changed, false, &validation_receipt(&changed))
                    .unwrap_err(),
            ),
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
                .begin_sign_attempt(
                    &reused_attempt_id,
                    false,
                    &validation_receipt(&reused_attempt_id),
                )
                .unwrap_err()
        ),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );
    assert_eq!(
        protocol_code(
            journal
                .begin_sign_attempt(&retry, true, &validation_receipt(&retry))
                .unwrap_err(),
        ),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );

    let mut conflict = first.clone();
    conflict.policy_version = DecimalU64::new(2);
    conflict.operation_digest = conflict.operation_identity().digest().unwrap();
    conflict.attempt_digest = digest("00");
    conflict.attempt_digest = conflict.computed_attempt_digest().unwrap();
    assert_eq!(
        protocol_code(
            journal
                .begin_sign_attempt(&conflict, false, &validation_receipt(&conflict))
                .unwrap_err(),
        ),
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
fn ac18_validation_receipt_is_exactly_bound_and_retained_tamper_degrades_audit() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("broker.sqlite");
    let journal = BrokerJournal::open(
        &path,
        Arc::new(TestAuditSigner(SigningKey::from_bytes(&[42; 32]))),
    )
    .unwrap();
    install_reservation_approval(&journal);
    let request = request(14);
    let receipt = validation_receipt(&request);

    let mut changed = receipt.clone();
    changed.reservation_ids.push(digest("78"));
    assert_eq!(
        protocol_code(
            journal
                .begin_sign_attempt(&request, false, &changed)
                .unwrap_err()
        ),
        bloom_triad_protocol::ProtocolErrorCode::OperationIdConflict
    );
    journal
        .begin_sign_attempt(&request, false, &receipt)
        .unwrap();
    drop(journal);

    let mut retained: BrokerValidationReceipt = serde_json::from_str(
        &Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT validation_receipt_jcs FROM operations WHERE operation_id=?1",
                [request.operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    retained.reservation_ids.push(digest("79"));
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE operations SET validation_receipt_jcs=?1 WHERE operation_id=?2",
            params![
                serde_json::to_string(&retained).unwrap(),
                request.operation_id.as_str()
            ],
        )
        .unwrap();
    let reopened = BrokerJournal::open(
        &path,
        Arc::new(TestAuditSigner(SigningKey::from_bytes(&[42; 32]))),
    )
    .unwrap();
    assert!(reopened.audit_degraded());
    assert!(reopened.verify_audit_chain().is_err());
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

#[test]
fn ac18_every_internal_chain_tamper_latches_writes_but_preserves_reads() {
    let mutations: &[&str] = &[
        "UPDATE audit_chain SET payload_jcs = '{}' WHERE sequence = 1",
        "UPDATE audit_chain SET entry_hash = printf('%064x', 1) WHERE sequence = 1",
        "UPDATE audit_chain SET signature = 'AA' WHERE sequence = 1",
        "UPDATE audit_chain SET signing_key_id = 'foreign-audit-key' WHERE sequence = 1",
        "DELETE FROM audit_chain WHERE sequence = 1",
        "UPDATE audit_chain SET sequence = -1 WHERE sequence = 0;
         UPDATE audit_chain SET sequence = 0 WHERE sequence = 1;
         UPDATE audit_chain SET sequence = 1 WHERE sequence = -1;",
    ];
    for (index, mutation) in mutations.iter().enumerate() {
        let directory = TempDir::new().unwrap();
        let path = directory
            .path()
            .join(format!("audit-tamper-{index}.sqlite"));
        let journal = open_journal(&path);
        let approval_id = digest("31");
        journal
            .create_approval(&approval_id, ApprovalLifecycleState::Prepared)
            .unwrap();
        journal
            .transition_approval(&approval_id, ApprovalLifecycleState::AwaitingCeremony)
            .unwrap();
        journal
            .transition_approval(&approval_id, ApprovalLifecycleState::Active)
            .unwrap();
        drop(journal);
        Connection::open(&path)
            .unwrap()
            .execute_batch(mutation)
            .unwrap();

        let degraded = open_journal(&path);
        assert!(
            degraded.audit_degraded(),
            "tamper case {index} was not latched"
        );
        assert_eq!(
            degraded.approval_state(&approval_id).unwrap(),
            Some(ApprovalLifecycleState::Active),
            "read/status must remain available in tamper case {index}"
        );
        assert!(
            degraded
                .transition_approval(&approval_id, ApprovalLifecycleState::Revoked)
                .is_err(),
            "security mutation did not fail closed in tamper case {index}"
        );
    }
}

struct SwitchableAuditSigner {
    fail: Arc<AtomicBool>,
    signing_key: SigningKey,
}

struct RotatedAuditKeyring {
    old: SigningKey,
    new: SigningKey,
}

impl AuditSigner for RotatedAuditKeyring {
    fn key_id(&self) -> Token {
        Token::new("broker-audit-key-v2").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(
            &self.new.sign(message).to_bytes(),
        ))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        let key = match key_id.as_str() {
            "broker-audit-test-1" => &self.old,
            "broker-audit-key-v2" => &self.new,
            _ => return Err("unknown audit signing key".into()),
        };
        let bytes: [u8; 64] = signature
            .decode()
            .try_into()
            .map_err(|_| "invalid signature length")?;
        key.verifying_key()
            .verify(message, &ed25519_dalek::Signature::from_bytes(&bytes))
            .map_err(|error| error.to_string())
    }
}

#[test]
fn ac18_audit_key_rotation_is_cross_signed_and_continuous_across_reopen() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("broker.sqlite");
    let old = SigningKey::from_bytes(&[42; 32]);
    let new = SigningKey::from_bytes(&[44; 32]);
    let journal = BrokerJournal::open(&path, Arc::new(TestAuditSigner(old.clone()))).unwrap();
    journal
        .create_approval(&digest("71"), ApprovalLifecycleState::Prepared)
        .unwrap();
    journal
        .rotate_audit_key(Arc::new(RotatedAuditKeyring {
            old: old.clone(),
            new: new.clone(),
        }))
        .unwrap();
    journal
        .create_approval(&digest("72"), ApprovalLifecycleState::Prepared)
        .unwrap();
    let entries = journal.audit_entries().unwrap();
    assert_eq!(entries[1].event_type, "audit.key_rotated");
    assert_eq!(entries[2].event_type, "audit.key_rotation_completed");
    assert_eq!(entries[0].signing_key_id.as_str(), "broker-audit-test-1");
    assert_eq!(entries[1].signing_key_id.as_str(), "broker-audit-test-1");
    assert_eq!(entries[2].signing_key_id.as_str(), "broker-audit-key-v2");
    assert_eq!(entries[3].signing_key_id.as_str(), "broker-audit-key-v2");
    let completion: serde_json::Value = serde_json::from_str(&entries[2].payload_jcs).unwrap();
    assert_eq!(
        completion["final_old_head"],
        serde_json::json!(entries[1].entry_hash)
    );
    assert_eq!(entries[2].previous_hash, entries[1].entry_hash);
    drop(journal);

    let reopened = BrokerJournal::open(
        &path,
        Arc::new(RotatedAuditKeyring {
            old: old.clone(),
            new: new.clone(),
        }),
    )
    .unwrap();
    reopened.verify_audit_chain().unwrap();
    assert!(!reopened.audit_degraded());
    drop(reopened);

    // A crash or tamper that leaves only the old-key half of the transition is
    // a cryptographically valid prefix, but not a completed key rotation.
    Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM audit_chain WHERE sequence > 1", [])
        .unwrap();
    let incomplete =
        BrokerJournal::open(&path, Arc::new(RotatedAuditKeyring { old, new })).unwrap();
    assert!(incomplete.audit_degraded());
    assert!(incomplete.verify_audit_chain().is_err());
}

#[test]
fn ac18_every_security_mutation_synchronously_persists_its_self_head() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("broker.sqlite");
    let checkpoint = Arc::new(RecordingSelfCheckpoint::default());
    let journal = BrokerJournal::open(
        &path,
        Arc::new(TestAuditSigner(SigningKey::from_bytes(&[42; 32]))),
    )
    .unwrap();
    journal
        .install_self_checkpoint(broker_identity(), checkpoint.clone())
        .unwrap();
    journal
        .create_approval(&digest("73"), ApprovalLifecycleState::Prepared)
        .unwrap();
    let heads = checkpoint.0.lock().unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].sequence.get(), 1);
    assert_ne!(heads[0].head_hash, Digest32::from_bytes([0; 32]));
    drop(heads);
    drop(journal);

    // Corrupt immediately after the mutation, with no timer or subsequent
    // cross-service call available to advance the retained self-checkpoint.
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE audit_chain SET payload_jcs='{}' WHERE sequence=0",
            [],
        )
        .unwrap();
    let degraded = BrokerJournal::open(
        &path,
        Arc::new(TestAuditSigner(SigningKey::from_bytes(&[42; 32]))),
    )
    .unwrap();
    assert!(degraded.audit_degraded());
}

#[test]
fn ac18_postcommit_self_checkpoint_failure_suppresses_success_but_is_reconcilable() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("broker.sqlite");
    let journal = BrokerJournal::open(
        &path,
        Arc::new(TestAuditSigner(SigningKey::from_bytes(&[42; 32]))),
    )
    .unwrap();
    journal
        .install_self_checkpoint(broker_identity(), Arc::new(FailingSelfCheckpoint))
        .unwrap();
    let approval_id = digest("74");
    assert!(
        journal
            .create_approval(&approval_id, ApprovalLifecycleState::Prepared)
            .is_err()
    );
    assert!(journal.audit_degraded());
    assert_eq!(
        journal.approval_state(&approval_id).unwrap(),
        Some(ApprovalLifecycleState::Prepared)
    );
    assert_eq!(journal.audit_entries().unwrap().len(), 1);
    drop(journal);

    // Restart recovers the durable mutation. A fresh independently durable
    // sink accepts the following committed head without seeing a speculative
    // checkpoint from a rolled-back SQLite transaction.
    let checkpoint = Arc::new(RecordingSelfCheckpoint::default());
    let restarted = BrokerJournal::open(
        &path,
        Arc::new(TestAuditSigner(SigningKey::from_bytes(&[42; 32]))),
    )
    .unwrap();
    restarted
        .install_self_checkpoint(broker_identity(), checkpoint.clone())
        .unwrap();
    assert_eq!(
        restarted.approval_state(&approval_id).unwrap(),
        Some(ApprovalLifecycleState::Prepared)
    );
    let second = digest("75");
    restarted
        .create_approval(&second, ApprovalLifecycleState::Prepared)
        .unwrap();
    let heads = checkpoint.0.lock().unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].sequence.get(), 2);
}

#[test]
fn ac18_concurrent_commits_cannot_publish_self_checkpoints_out_of_order() {
    let journal = Arc::new(
        BrokerJournal::open_in_memory(Arc::new(TestAuditSigner(SigningKey::from_bytes(&[42; 32]))))
            .unwrap(),
    );
    let checkpoint = Arc::new(ReorderingCheckpoint::default());
    journal
        .install_self_checkpoint(broker_identity(), checkpoint.clone())
        .unwrap();
    let start = Arc::new(Barrier::new(3));
    let workers = [digest("76"), digest("77")]
        .into_iter()
        .map(|approval_id| {
            let journal = journal.clone();
            let start = start.clone();
            thread::spawn(move || {
                start.wait();
                journal.create_approval(&approval_id, ApprovalLifecycleState::Prepared)
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    for worker in workers {
        worker.join().unwrap().unwrap();
    }

    let sequences = checkpoint.sequences.lock().unwrap();
    assert_eq!(sequences.len(), 2);
    assert!(sequences.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(*sequences.last().unwrap(), 2);
}

impl AuditSigner for SwitchableAuditSigner {
    fn key_id(&self) -> Token {
        Token::new("switchable-audit-key").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("forced audit write failure".into());
        }
        Ok(Base64UrlBytes::from_bytes(
            &self.signing_key.sign(message).to_bytes(),
        ))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id != &self.key_id() {
            return Err("unexpected key ID".into());
        }
        let bytes: [u8; 64] = signature
            .decode()
            .try_into()
            .map_err(|_| "invalid signature length")?;
        self.signing_key
            .verifying_key()
            .verify(message, &ed25519_dalek::Signature::from_bytes(&bytes))
            .map_err(|error| error.to_string())
    }
}

#[test]
fn ac18_forced_journal_audit_write_failure_rolls_back_local_effect() {
    let fail = Arc::new(AtomicBool::new(true));
    let checkpoint = Arc::new(RecordingSelfCheckpoint::default());
    let journal = BrokerJournal::open_in_memory(Arc::new(SwitchableAuditSigner {
        fail: fail.clone(),
        signing_key: SigningKey::from_bytes(&[43; 32]),
    }))
    .unwrap();
    journal
        .install_self_checkpoint(broker_identity(), checkpoint.clone())
        .unwrap();
    let approval_id = digest("32");
    assert!(
        journal
            .create_approval(&approval_id, ApprovalLifecycleState::Prepared)
            .is_err()
    );
    assert_eq!(journal.approval_state(&approval_id).unwrap(), None);
    assert!(journal.audit_entries().unwrap().is_empty());
    assert!(checkpoint.0.lock().unwrap().is_empty());

    fail.store(false, Ordering::SeqCst);
    journal
        .create_approval(&approval_id, ApprovalLifecycleState::Prepared)
        .unwrap();
    assert_eq!(
        journal.approval_state(&approval_id).unwrap(),
        Some(ApprovalLifecycleState::Prepared)
    );
    let heads = checkpoint.0.lock().unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].sequence.get(), 1);
}

#[test]
fn ac18_audit_correlation_detects_persisted_receipt_and_result_tamper() {
    let directory = TempDir::new().unwrap();

    let approval_path = directory.path().join("approval-correlation.sqlite");
    let approval = open_journal(&approval_path);
    install_reservation_approval(&approval);
    let activation = approval
        .audit_entries()
        .unwrap()
        .into_iter()
        .find(|entry| {
            entry.event_type == "approval.transition"
                && entry
                    .payload_jcs
                    .contains("signer_activation_receipt_digest")
        })
        .expect("activation audit correlation");
    let activation_payload: serde_json::Value =
        serde_json::from_str(&activation.payload_jcs).unwrap();
    assert_eq!(activation_payload["correlation_schema"], "v1");
    assert_eq!(
        activation_payload["activation_operation_id"],
        serde_json::json!(operation_id(250))
    );
    drop(approval);
    Connection::open(&approval_path)
        .unwrap()
        .execute(
            "UPDATE approval_metadata SET ceremony_grant_jcs='{\"tampered\":true}'",
            [],
        )
        .unwrap();
    let degraded = open_journal(&approval_path);
    assert!(degraded.audit_degraded());
    assert_eq!(
        degraded.approval_state(&digest("22")).unwrap(),
        Some(ApprovalLifecycleState::Active)
    );

    let result_path = directory.path().join("result-correlation.sqlite");
    let single_request = request(41);
    let journal = open_journal(&result_path);
    install_reservation_approval(&journal);
    journal
        .begin_sign_attempt(&single_request, false, &validation_receipt(&single_request))
        .unwrap();
    let mut single_reservation = reservation(41);
    single_reservation.operation_id = single_request.operation_id.clone();
    single_reservation.operation_digest = single_request.operation_digest.clone();
    journal.reserve(&single_reservation, &limits(2)).unwrap();
    advance_to_committed(&journal, &single_request.operation_id);
    let published = result(&single_request, "b1");
    journal.publish_result(&digest("22"), &published).unwrap();
    let event = journal
        .audit_entries()
        .unwrap()
        .into_iter()
        .find(|entry| entry.event_type == "operation.published")
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&event.payload_jcs).unwrap();
    assert_eq!(
        payload["signer_receipt_digest"],
        serde_json::json!(published.signer_receipt_digest)
    );
    assert_eq!(
        payload["broker_receipt_digest"],
        serde_json::json!(published.broker_receipt_digest)
    );
    drop(journal);
    let mut tampered = published.clone();
    tampered.signer_receipt_digest = digest("b2");
    Connection::open(&result_path)
        .unwrap()
        .execute(
            "UPDATE operations SET result_jcs=?2 WHERE operation_id=?1",
            params![
                single_request.operation_id.as_str(),
                serde_jcs::to_string(&tampered).unwrap()
            ],
        )
        .unwrap();
    assert!(open_journal(&result_path).audit_degraded());

    let batch_path = directory.path().join("batch-correlation.sqlite");
    let parent = request(51);
    let journal = open_journal(&batch_path);
    install_reservation_approval(&journal);
    journal
        .begin_sign_attempt(&parent, true, &validation_receipt(&parent))
        .unwrap();
    let mut batch_reservation = reservation(51);
    batch_reservation.operation_id = parent.operation_id.clone();
    batch_reservation.operation_digest = parent.operation_digest.clone();
    journal.reserve(&batch_reservation, &limits(2)).unwrap();
    advance_to_committed(&journal, &parent.operation_id);
    let parent_result = result(&parent, "c1");
    let mut child = result(&request(52), "c2");
    child.operation_id = derive_batch_child_operation_id(&parent.operation_id, 0).unwrap();
    journal
        .publish_batch(&digest("22"), &parent_result, &[child.clone()])
        .unwrap();
    let event = journal
        .audit_entries()
        .unwrap()
        .into_iter()
        .find(|entry| entry.event_type == "batch.published")
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&event.payload_jcs).unwrap();
    assert_eq!(
        payload["children"][0]["operation_id"],
        serde_json::json!(child.operation_id)
    );
    assert_eq!(
        payload["children"][0]["signer_receipt_digest"],
        serde_json::json!(child.signer_receipt_digest)
    );
    drop(journal);
    child.broker_receipt_digest = digest("c3");
    Connection::open(&batch_path)
        .unwrap()
        .execute(
            "UPDATE batch_children SET result_jcs=?1 WHERE ordinal=0",
            [serde_jcs::to_string(&child).unwrap()],
        )
        .unwrap();
    assert!(open_journal(&batch_path).audit_degraded());
}

#[test]
fn verified_head_convention_and_checkpoint_failure_latch_preserve_reads() {
    let journal = memory_journal();
    assert_eq!(journal.verified_audit_head().unwrap(), (0, digest("00")));
    let approval_id = digest("34");
    journal
        .create_approval(&approval_id, ApprovalLifecycleState::Prepared)
        .unwrap();
    let (sequence, head_hash) = journal.verified_audit_head().unwrap();
    assert_eq!(sequence, 1);
    assert_ne!(head_hash, digest("00"));

    journal.latch_audit_degradation();
    assert_eq!(
        journal.approval_state(&approval_id).unwrap(),
        Some(ApprovalLifecycleState::Prepared)
    );
    assert!(
        journal
            .transition_approval(&approval_id, ApprovalLifecycleState::AwaitingCeremony)
            .is_err()
    );
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
        journal.begin_sign_attempt(&first, false, &validation_receipt(&first)),
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
        .begin_sign_attempt(&sign_request, false, &validation_receipt(&sign_request))
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
    setup
        .begin_sign_attempt(&parent, true, &validation_receipt(&parent))
        .unwrap();
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
