use super::*;
use crate::legacy_store::TestAuditSigner;
use bloom_broker_api::{CeremonyKind, DecimalU64};
use ed25519_dalek::{Signer as _, SigningKey};
use std::{sync::mpsc, thread, time::Duration};

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}
fn digest(byte: u8) -> Digest32 {
    Digest32::from_bytes([byte; 32])
}

fn authority(journal: Arc<BrokerJournal>) -> Arc<BrokerAuthority> {
    Arc::new(
        BrokerAuthority::open_in_memory(
            journal,
            BTreeMap::new(),
            token("installer"),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            token("ceremony"),
            SigningKey::from_bytes(&[3; 32]).verifying_key(),
            token("revocation"),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            AssuranceRegistry::compiled(vec![]).unwrap(),
        )
        .unwrap(),
    )
}

struct Fixture {
    authority: Arc<BrokerAuthority>,
    journal: Arc<BrokerJournal>,
}
impl Fixture {
    fn open(path: Option<&Path>) -> Self {
        let journal = Arc::new(match path {
            Some(path) => BrokerJournal::open(path, Arc::new(TestAuditSigner)).unwrap(),
            None => BrokerJournal::open_in_memory(Arc::new(TestAuditSigner)).unwrap(),
        });
        Self {
            authority: authority(journal.clone()),
            journal,
        }
    }
    fn initial(&self, kind: CeremonyKind, operation: u8, key: u8) -> CustodyResult {
        let receipt = receipt(kind, operation, Some(policy(key, 1)));
        self.authority
            .adopt_custody_receipt(&receipt, 1_000)
            .unwrap();
        receipt
    }
    fn delete(&self) -> CustodyResult {
        let receipt = receipt(CeremonyKind::WalletDelete, 20, None);
        self.authority
            .adopt_custody_receipt(&receipt, 2_000)
            .unwrap();
        receipt
    }
    fn released_late_read(&self, snapshot: &SignedPolicySnapshot, record_install: bool) {
        let mut connection = self.journal.lock_for_mutation().unwrap();
        let tx = connection.transaction().unwrap();
        tx.execute(
            "INSERT OR REPLACE INTO policies VALUES (?1,?2,?3,?4,?5)",
            params![
                snapshot.wallet_id.as_str(),
                snapshot.version.get().to_string(),
                snapshot.policy_digest.as_str(),
                serde_jcs::to_string(snapshot).unwrap(),
                String::from_utf8(snapshot.canonical_policy.decode()).unwrap(),
            ],
        )
        .unwrap();
        if record_install {
            self.journal
                .append_external_audit(
                    &tx,
                    "policy.installed",
                    &serde_json::json!({
                        "wallet_id": snapshot.wallet_id, "version": snapshot.version,
                        "policy_digest": snapshot.policy_digest, "ceremony_receipt_digest": null,
                        "validation_receipt_digest": null, "commit_receipt_digest": null,
                    }),
                )
                .unwrap();
        }
        tx.commit().unwrap();
        drop(connection);
        self.journal.checkpoint_committed_head().unwrap();
    }
}

fn policy(key: u8, version: u64) -> SignedPolicySnapshot {
    let key = SigningKey::from_bytes(&[key; 32]);
    let document = CanonicalWalletPolicy {
        wallet_id: token("reusable-name"),
        maximum_approval_lifetime_ms: 100_000,
        allowed_petal_packages: vec![],
        allowed_destinations: vec![],
        required_verifiers: vec![],
        clear_signing: None,
    };
    let encoded = serde_jcs::to_vec(&document).unwrap();
    let mut snapshot = SignedPolicySnapshot {
        wallet_id: document.wallet_id,
        version: DecimalU64::new(version),
        canonical_policy: Base64UrlBytes::from_bytes(&encoded),
        policy_digest: Digest32::from_bytes(Sha256::digest(&encoded).into()),
        policy_signing_key_id: token("policy-key"),
        policy_verifying_key: Base64UrlBytes::from_bytes(&key.verifying_key().to_bytes()),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    let mut message = POLICY_SIGNATURE_DOMAIN.to_vec();
    message.extend(serde_jcs::to_vec(&snapshot).unwrap());
    snapshot.signer_signature = Base64UrlBytes::from_bytes(&key.sign(&message).to_bytes());
    snapshot
}

fn receipt(
    kind: CeremonyKind,
    operation: u8,
    policy: Option<SignedPolicySnapshot>,
) -> CustodyResult {
    let mut result = CustodyResult {
        surface: None,
        credential_authority_generation: None,
        ceremony_kind: kind,
        custody_operation_id: OperationId::from_bytes([operation; 32]),
        public_status: kind.successful_terminal_state().unwrap(),
        wallet_id: Some(token("reusable-name")),
        public_key_refs: vec![],
        credential_summaries: vec![],
        initial_policy: policy,
        receipt_digest: digest(operation),
        encrypted_browser_result: None,
        signer_key_id: token("ceremony"),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    let mut message = SIGNER_CEREMONY_RECEIPT_DOMAIN.to_vec();
    message.extend(result.unsigned_canonical_bytes().unwrap());
    result.signer_signature =
        Base64UrlBytes::from_bytes(&SigningKey::from_bytes(&[3; 32]).sign(&message).to_bytes());
    result
}

#[test]
fn deletion_serializes_with_a_policy_read_paused_after_verification() {
    let fixture = Fixture::open(None);
    fixture.initial(CeremonyKind::WalletRegistration, 1, 1);
    #[derive(Debug, PartialEq)]
    enum Event {
        Verified,
        DeleteBlocked,
        Deleted,
    }
    let (events, receive) = mpsc::channel();
    let (resume, resume_receive) = mpsc::channel();
    let resume_receive = Mutex::new(resume_receive);
    let sender = events.clone();
    *fixture.authority.race_hooks.verified.lock().unwrap() = Some(Arc::new(move || {
        sender.send(Event::Verified).unwrap();
        resume_receive
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
    }));
    let sender = events.clone();
    *fixture
        .authority
        .race_hooks
        .barrier_contended
        .lock()
        .unwrap() = Some(Arc::new(move || {
        sender.send(Event::DeleteBlocked).unwrap();
    }));
    let installer = fixture.authority.clone();
    let install = thread::spawn(move || installer.install_policy(&policy(1, 2)));
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(10)).unwrap(),
        Event::Verified
    );
    let deleter = fixture.authority.clone();
    let delete = thread::spawn(move || {
        let result =
            deleter.adopt_custody_receipt(&receipt(CeremonyKind::WalletDelete, 20, None), 2_000);
        events.send(Event::Deleted).unwrap();
        result
    });
    // No scheduling sleep: the next event proves either real lock contention
    // or that deletion crossed the paused install. Always release/join both
    // workers before asserting, including when the barrier is mutated away.
    let ordering = receive.recv_timeout(Duration::from_secs(10)).unwrap();
    resume.send(()).unwrap();
    install.join().unwrap().unwrap();
    delete.join().unwrap().unwrap();
    assert_eq!(
        ordering,
        Event::DeleteBlocked,
        "deletion crossed verify/persist barrier"
    );
    assert!(fixture.authority.wallet_ids().unwrap().is_empty());
    assert!(
        fixture
            .authority
            .policy_snapshot(&token("reusable-name"))
            .is_err()
    );
}

#[test]
fn startup_removes_only_a_proven_released_late_read_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.sqlite");
    let fixture = Fixture::open(Some(&path));
    fixture.initial(CeremonyKind::WalletRegistration, 1, 1);
    fixture.delete();
    fixture.released_late_read(&policy(1, 2), true);
    drop(fixture);
    for _ in 0..2 {
        let reopened = Fixture::open(Some(&path));
        assert!(reopened.authority.wallet_ids().unwrap().is_empty());
        assert!(reopened.authority.install_policy(&policy(1, 2)).is_err());
        assert_eq!(
            reopened
                .journal
                .audit_entries()
                .unwrap()
                .iter()
                .filter(|entry| entry.event_type == "wallet.legacy_projection_removed")
                .count(),
            1
        );
        reopened.journal.verify_audit_chain().unwrap();
    }
}

#[test]
fn later_registration_and_import_survive_old_deletions_and_receipt_replays() {
    for kind in [CeremonyKind::WalletRegistration, CeremonyKind::WalletImport] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite");
        let fixture = Fixture::open(Some(&path));
        let old_registration = fixture.initial(CeremonyKind::WalletRegistration, 1, 1);
        let old_deletion = fixture.delete();
        // Replaying an already adopted registration is not new custody.
        fixture
            .authority
            .adopt_custody_receipt(&old_registration, 3_000)
            .unwrap();
        assert!(fixture.authority.wallet_ids().unwrap().is_empty());
        fixture.initial(kind, 2, 9);
        fixture
            .authority
            .adopt_custody_receipt(&old_deletion, 4_000)
            .unwrap();
        assert_eq!(
            fixture
                .authority
                .policy_snapshot(&token("reusable-name"))
                .unwrap(),
            policy(9, 1)
        );
        fixture.authority.install_policy(&policy(9, 2)).unwrap();
        drop(fixture);
        let reopened = Fixture::open(Some(&path));
        assert_eq!(
            reopened
                .authority
                .policy_snapshot(&token("reusable-name"))
                .unwrap(),
            policy(9, 2)
        );
        assert!(
            reopened.authority.install_policy(&policy(1, 3)).is_err(),
            "old incarnation key must not return"
        );
    }
}

#[test]
fn cleanup_preserves_rows_without_matching_audit_evidence() {
    for record_install in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite");
        let fixture = Fixture::open(Some(&path));
        fixture.initial(CeremonyKind::WalletRegistration, 1, 1);
        fixture.delete();
        fixture.released_late_read(&policy(1, 2), record_install);
        if record_install {
            // The row no longer matches the journal's version/digest proof.
            fixture.released_late_read(&policy(1, 3), false);
        }
        drop(fixture);
        let reopened = Fixture::open(Some(&path));
        assert_eq!(
            reopened.authority.wallet_ids().unwrap(),
            vec![token("reusable-name")]
        );
        assert!(
            !reopened
                .journal
                .audit_entries()
                .unwrap()
                .iter()
                .any(|entry| entry.event_type == "wallet.legacy_projection_removed")
        );
    }
}

#[test]
fn cleanup_does_not_mutate_a_degraded_journal() {
    let fixture = Fixture::open(None);
    fixture.initial(CeremonyKind::WalletRegistration, 1, 1);
    fixture.delete();
    fixture.released_late_read(&policy(1, 2), true);
    fixture.journal.latch_audit_degradation();
    let reopened = authority(fixture.journal.clone());
    assert_eq!(reopened.wallet_ids().unwrap(), vec![token("reusable-name")]);
    assert!(
        !fixture
            .journal
            .audit_entries()
            .unwrap()
            .iter()
            .any(|entry| entry.event_type == "wallet.legacy_projection_removed")
    );
}
