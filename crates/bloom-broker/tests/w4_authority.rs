use bloom_broker::{
    authority::{
        AssuranceRegistry, AssuranceVerifier, AuthorizationInput, BrokerAuthority,
        CanonicalWalletPolicy, CeremonyApprovalGrant, EpochReconciliation, PolicyAsset,
        PolicyDestination, ProvenanceOperationClass, ProvenanceRecord, ProvenanceSubject,
        VerifierCapability, canonical_policy_authority_diff,
    },
    journal::{AuditSigner, BrokerJournal},
};
use bloom_broker_api::{
    ActivationMode, ApprovalLimits, ApprovalSelector, ApprovalSubject, ApprovalTombstone, AssetId,
    Base64UrlBytes, BootEpoch, CeremonyKind, CeremonyState, ClaimAssurance, ClaimAssuranceLevel,
    CryptoSuite, CustodyResult, DecimalU64, DecimalU256, DeclaredDebit, DeclaredDestination,
    DeclaredFee, Digest32, KeyRef, KeySpec, MachineSignRequest, OperationId,
    PROVENANCE_CATALOG_SCHEMA, PetalKeyScope, PetalLineageMembership, PetalRouteGrant,
    PetalUseClaim, PolicyUpdateRequest, ProvenanceCatalog, RequestNonce, RevocationState,
    SealedApprovalTerms, SignedPolicySnapshot, SigningPayloads, Token, ValueLimit,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

const POLICY_DOMAIN: &[u8] = b"bloom-policy-snapshot/v1";
const PROVENANCE_DOMAIN: &[u8] = b"bloom-provenance-record/v1";
const CEREMONY_DOMAIN: &[u8] = b"bloom-broker-ceremony-grant/v1";
const REVOCATION_DOMAIN: &[u8] = b"bloom-revocation-state/v1";
const APPROVAL_TOMBSTONE_DOMAIN: &[u8] = b"bloom-approval-tombstone/v1";
const SIGNER_RECEIPT_DOMAIN: &[u8] = b"bloom-signer-ceremony-receipt/v1";
const SIGN_OPERATION_DOMAIN: &[u8] = b"bloom-sign-operation/v1";

#[derive(serde::Serialize)]
struct TestSignOperationIdentity {
    operation_id: OperationId,
    approval_id: Digest32,
    key_ref: KeyRef,
    crypto_suite: CryptoSuite,
    ordered_payload_digests: Vec<Digest32>,
    ordered_hashes: Vec<Digest32>,
    petal_use_claim_digest: Option<Digest32>,
    claim_assurance_digest: Option<Digest32>,
    policy_version: DecimalU64,
    policy_digest: Digest32,
}

impl TestSignOperationIdentity {
    fn digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(SIGN_OPERATION_DOMAIN);
        hasher.update(serde_jcs::to_vec(self).unwrap());
        Digest32::from_bytes(hasher.finalize().into())
    }
}

#[derive(Clone)]
struct TestAuditSigner;

impl AuditSigner for TestAuditSigner {
    fn key_id(&self) -> Token {
        token("audit-key")
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(&Sha256::digest(message)))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id == &self.key_id() && signature.decode() == Sha256::digest(message).as_slice() {
            Ok(())
        } else {
            Err("audit signature mismatch".into())
        }
    }
}

struct SwitchableAuditSigner(Arc<AtomicBool>);

impl AuditSigner for SwitchableAuditSigner {
    fn key_id(&self) -> Token {
        token("audit-key")
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        if self.0.load(Ordering::SeqCst) {
            Err("forced authority audit failure".into())
        } else {
            Ok(Base64UrlBytes::from_bytes(&Sha256::digest(message)))
        }
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id == &self.key_id() && signature.decode() == Sha256::digest(message).as_slice() {
            Ok(())
        } else {
            Err("audit signature mismatch".into())
        }
    }
}

struct TestProofVerifier {
    fields: Vec<Token>,
}

struct BlockingProofVerifier {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl AssuranceVerifier for BlockingProofVerifier {
    fn capability(&self) -> VerifierCapability {
        VerifierCapability {
            verifier_id: token("test-proof"),
            artifact_digest: digest(2),
            assurance: ClaimAssuranceLevel::ProofVerified,
            established_fields: authority_fields(),
        }
    }

    fn verify(&self, claim: &PetalUseClaim, _evidence: Option<&[u8]>) -> Result<(), String> {
        if !matches!(claim.claim_assurance, ClaimAssurance::ProofVerified { .. }) {
            return Err("proof required".into());
        }
        self.entered.wait();
        self.release.wait();
        Ok(())
    }
}

impl AssuranceVerifier for TestProofVerifier {
    fn capability(&self) -> VerifierCapability {
        VerifierCapability {
            verifier_id: token("test-proof"),
            artifact_digest: digest(2),
            assurance: ClaimAssuranceLevel::ProofVerified,
            established_fields: self.fields.clone(),
        }
    }

    fn verify(&self, claim: &PetalUseClaim, evidence: Option<&[u8]>) -> Result<(), String> {
        if evidence != Some(b"proof-evidence".as_slice()) {
            return Err("proof evidence was not forwarded intact".into());
        }
        match &claim.claim_assurance {
            ClaimAssurance::ProofVerified { proof_digest, .. } if proof_digest == &digest(3) => {
                Ok(())
            }
            _ => Err("proof does not bind the reviewed claim".into()),
        }
    }
}

fn authority_fields() -> Vec<Token> {
    [
        "package_hash",
        "route",
        "operation_class",
        "crypto_suite",
        "payload_digest",
        "ordered_hashes",
        "declared_debits",
        "declared_destinations",
        "declared_fee",
        "nonce",
    ]
    .into_iter()
    .map(token)
    .collect()
}

struct Harness {
    authority: BrokerAuthority,
    journal: Arc<BrokerJournal>,
    policy_key: SigningKey,
    installer_key: SigningKey,
    ceremony_key: SigningKey,
    revocation_key: SigningKey,
    wallet: Token,
}

impl Harness {
    fn new() -> Self {
        Self::new_with_verifiers(vec![])
    }

    fn new_with_verifiers(verifiers: Vec<Arc<dyn AssuranceVerifier>>) -> Self {
        let policy_key = SigningKey::from_bytes(&[1; 32]);
        let installer_key = SigningKey::from_bytes(&[2; 32]);
        let ceremony_key = SigningKey::from_bytes(&[3; 32]);
        let revocation_key = SigningKey::from_bytes(&[4; 32]);
        let wallet = token("wallet-1");
        let journal =
            Arc::new(BrokerJournal::open_in_memory(Arc::new(TestAuditSigner)).expect("journal"));
        let mut policy_keys = BTreeMap::new();
        policy_keys.insert(
            wallet.as_str().to_owned(),
            (token("policy-key"), policy_key.verifying_key()),
        );
        let authority = BrokerAuthority::open_in_memory(
            journal.clone(),
            policy_keys,
            token("installer-key"),
            installer_key.verifying_key(),
            token("ceremony-key"),
            ceremony_key.verifying_key(),
            token("revocation-key"),
            revocation_key.verifying_key(),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            AssuranceRegistry::compiled(verifiers).unwrap(),
        )
        .unwrap();
        let harness = Self {
            authority,
            journal,
            policy_key,
            installer_key,
            ceremony_key,
            revocation_key,
            wallet,
        };
        harness
            .authority
            .install_policy(&harness.policy_snapshot(1))
            .unwrap();
        harness
    }

    fn policy_snapshot(&self, version: u64) -> SignedPolicySnapshot {
        let policy = CanonicalWalletPolicy {
            wallet_id: self.wallet.clone(),
            maximum_approval_lifetime_ms: 100_000,
            allowed_petal_packages: vec![digest(9)],
            allowed_destinations: vec![PolicyDestination {
                chain: token("ethereum"),
                destination: "0xrecipient".into(),
            }],
            required_verifiers: vec![],
        };
        let canonical = serde_jcs::to_vec(&policy).unwrap();
        let mut snapshot = SignedPolicySnapshot {
            wallet_id: self.wallet.clone(),
            version: DecimalU64::new(version),
            canonical_policy: Base64UrlBytes::from_bytes(&canonical),
            policy_digest: Digest32::from_bytes(Sha256::digest(&canonical).into()),
            policy_signing_key_id: token("policy-key"),
            policy_verifying_key: Base64UrlBytes::from_bytes(
                &self.policy_key.verifying_key().to_bytes(),
            ),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        sign_zeroed(
            &mut snapshot,
            |value| &mut value.signer_signature,
            POLICY_DOMAIN,
            &self.policy_key,
        );
        snapshot
    }

    fn provenance(&self) -> ProvenanceRecord {
        let mut record = ProvenanceRecord {
            subject: ProvenanceSubject::Petal {
                package_hash: digest(9),
                route: "/sign".into(),
            },
            publisher: token("publisher"),
            petal_lineage: Some(PetalLineageMembership {
                lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                release_sequence: DecimalU64::new(1),
                predecessor_package_hashes: vec![],
                controller_key_id: token("controller-key"),
                controller_signature: Base64UrlBytes::from_bytes(&[1]),
                active: true,
            }),
            operation_classes: vec![
                ProvenanceOperationClass {
                    operation_class: token("transfer"),
                    fee_asset: Some(PolicyAsset {
                        chain: token("ethereum"),
                        asset: "eth".into(),
                    }),
                },
                ProvenanceOperationClass {
                    operation_class: token("authenticate"),
                    fee_asset: None,
                },
            ],
            installer_key_id: token("installer-key"),
            installer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        sign_zeroed(
            &mut record,
            |value| &mut value.installer_signature,
            PROVENANCE_DOMAIN,
            &self.installer_key,
        );
        record
    }

    fn system_provenance(&self) -> ProvenanceRecord {
        let mut record = ProvenanceRecord {
            subject: ProvenanceSubject::System {
                component_id: token("cli"),
                operation_class: token("sign"),
            },
            publisher: token("publisher"),
            petal_lineage: None,
            operation_classes: vec![ProvenanceOperationClass {
                operation_class: token("sign"),
                fee_asset: None,
            }],
            installer_key_id: token("installer-key"),
            installer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        sign_zeroed(
            &mut record,
            |value| &mut value.installer_signature,
            PROVENANCE_DOMAIN,
            &self.installer_key,
        );
        record
    }

    fn activate(&self, terms: &SealedApprovalTerms, provenance: Option<&ProvenanceRecord>) {
        let review = digest(7);
        self.authority
            .install_provenance(provenance.expect("test approval provenance"))
            .unwrap();
        let approval_id = self.authority.prepare_approval(terms, &review).unwrap();
        let grant = self.signed_grant(terms, approval_id, operation(3));
        self.authority.activate_approval(&grant, 1_500).unwrap();
        self.authority.activate_approval(&grant, 1_500).unwrap();
    }

    fn signed_grant(
        &self,
        terms: &SealedApprovalTerms,
        approval_id: Digest32,
        activation_operation_id: OperationId,
    ) -> CeremonyApprovalGrant {
        let mut grant = CeremonyApprovalGrant {
            activation_operation_id,
            approval_id: approval_id.clone(),
            approval_digest: approval_id,
            review_manifest_digest: digest(7),
            replacement_approval_id: terms.renewal_of.clone(),
            wallet_revocation_epoch: terms.wallet_revocation_epoch.get(),
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            ceremony_key_id: token("ceremony-key"),
            ceremony_signature: Base64UrlBytes::from_bytes(&[]),
        };
        sign_zeroed(
            &mut grant,
            |value| &mut value.ceremony_signature,
            CEREMONY_DOMAIN,
            &self.ceremony_key,
        );
        grant
    }
}

#[test]
fn ac18_wallet_delete_fails_closed_under_audit_degradation() {
    let harness = Harness::new();
    let baseline = harness
        .authority
        .policy_snapshot(&harness.wallet)
        .expect("baseline policy");
    let mut receipt = CustodyResult {
        petal_registration_terms_digest: None,
        ceremony_kind: CeremonyKind::WalletDelete,
        custody_operation_id: operation(90),
        public_status: CeremonyState::Completed,
        wallet_id: Some(harness.wallet.clone()),
        public_key_refs: Vec::new(),
        credential_summaries: Vec::new(),
        initial_policy: None,
        receipt_digest: digest(90),
        encrypted_browser_result: None,
        signer_key_id: token("ceremony-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    sign_custody_receipt(&mut receipt, &harness.ceremony_key);
    harness.journal.latch_audit_degradation();

    assert!(
        harness
            .authority
            .adopt_custody_receipt(&receipt, 1_000)
            .is_err()
    );
    assert_eq!(
        harness.authority.policy_snapshot(&harness.wallet).unwrap(),
        baseline,
        "audit degradation must not delete the public policy projection"
    );
}

#[test]
fn ac18_forced_authority_audit_write_failure_rolls_back_quota_effect() {
    let fail = Arc::new(AtomicBool::new(true));
    let journal = Arc::new(
        BrokerJournal::open_in_memory(Arc::new(SwitchableAuditSigner(fail.clone()))).unwrap(),
    );
    let authority = BrokerAuthority::open_in_memory(
        journal.clone(),
        BTreeMap::new(),
        token("installer-key"),
        SigningKey::from_bytes(&[2; 32]).verifying_key(),
        token("ceremony-key"),
        SigningKey::from_bytes(&[3; 32]).verifying_key(),
        token("revocation-key"),
        SigningKey::from_bytes(&[4; 32]).verifying_key(),
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]).verifying_key(),
        AssuranceRegistry::compiled(vec![]).unwrap(),
    )
    .unwrap();

    assert!(
        authority
            .consume_mutation_quota("machine-501", 1_000, 60_000, 1)
            .is_err()
    );
    assert!(journal.audit_entries().unwrap().is_empty());

    fail.store(false, Ordering::SeqCst);
    authority
        .consume_mutation_quota("machine-501", 1_000, 60_000, 1)
        .unwrap();
    assert_eq!(journal.audit_entries().unwrap().len(), 1);
    assert!(
        authority
            .consume_mutation_quota("machine-501", 1_001, 60_000, 1)
            .is_err(),
        "the failed audited mutation must not have consumed quota"
    );
}

#[test]
fn ac18_authority_reads_survive_latched_audit_tamper_while_mutations_fail() {
    let directory = tempfile::tempdir().unwrap();
    let journal_path = directory.path().join("journal.sqlite");
    let authority_path = directory.path().join("authority.sqlite");
    let open = || {
        let journal = Arc::new(
            BrokerJournal::open(&journal_path, Arc::new(TestAuditSigner)).expect("journal"),
        );
        let authority = BrokerAuthority::open(
            &authority_path,
            journal.clone(),
            BTreeMap::new(),
            token("installer-key"),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            token("ceremony-key"),
            SigningKey::from_bytes(&[3; 32]).verifying_key(),
            token("revocation-key"),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            AssuranceRegistry::compiled(vec![]).unwrap(),
        )
        .unwrap();
        (journal, authority)
    };
    let (journal, authority) = open();
    authority
        .consume_mutation_quota("machine-501", 1_000, 60_000, 2)
        .unwrap();
    drop(authority);
    drop(journal);

    rusqlite::Connection::open(&journal_path)
        .unwrap()
        .execute(
            "UPDATE audit_chain SET signing_key_id='foreign-key' WHERE sequence=0",
            [],
        )
        .unwrap();
    let (degraded_journal, degraded_authority) = open();
    assert!(degraded_journal.audit_degraded());
    assert_eq!(
        degraded_authority
            .wallet_epoch(&token("wallet-read-only"))
            .unwrap(),
        0
    );
    assert!(
        degraded_authority
            .consume_mutation_quota("machine-501", 1_001, 60_000, 2)
            .is_err()
    );
}

#[test]
fn ac18_populated_authority_migration_is_atomic_idempotent_and_retains_source() {
    let directory = tempfile::tempdir().unwrap();
    let legacy_path = directory.path().join("legacy-authority.sqlite");
    let journal_path = directory.path().join("journal.sqlite");
    let legacy = rusqlite::Connection::open(&legacy_path).unwrap();
    legacy
        .execute_batch(
            "CREATE TABLE policies(wallet_id TEXT PRIMARY KEY, version TEXT NOT NULL, digest TEXT NOT NULL, snapshot_jcs TEXT NOT NULL, policy_jcs TEXT NOT NULL);
             CREATE TABLE wallet_epochs(wallet_id TEXT PRIMARY KEY, epoch TEXT NOT NULL, reconciled INTEGER NOT NULL);
             CREATE TABLE provenance_catalog(subject_jcs TEXT PRIMARY KEY, record_digest TEXT NOT NULL, record_jcs TEXT NOT NULL);
             CREATE TABLE mutation_quota(principal TEXT PRIMARY KEY, window_started_ms TEXT NOT NULL, mutations TEXT NOT NULL);
             CREATE TABLE signer_approval_tombstones(approval_id TEXT PRIMARY KEY, wallet_id TEXT NOT NULL, tombstone_jcs TEXT NOT NULL);
             CREATE TABLE pending_petal_key_scopes(custody_operation_id TEXT PRIMARY KEY, scope_digest TEXT NOT NULL, scope_jcs TEXT NOT NULL);
             CREATE TABLE petal_key_scopes(key_ref_jcs TEXT PRIMARY KEY, scope_digest TEXT NOT NULL, scope_jcs TEXT NOT NULL, activated_at_ms TEXT NOT NULL, expires_at_ms TEXT NOT NULL, custody_receipt_digest TEXT NOT NULL);
             INSERT INTO mutation_quota VALUES ('legacy-principal', '100', '2');",
        )
        .unwrap();
    drop(legacy);
    let source_before = std::fs::read(&legacy_path).unwrap();

    let failed_target_path = directory.path().join("failed-journal.sqlite");
    let fail = Arc::new(AtomicBool::new(false));
    let failed_journal = Arc::new(
        BrokerJournal::open(
            &failed_target_path,
            Arc::new(SwitchableAuditSigner(fail.clone())),
        )
        .unwrap(),
    );
    fail.store(true, Ordering::SeqCst);
    assert!(
        BrokerAuthority::open(
            &legacy_path,
            failed_journal.clone(),
            BTreeMap::new(),
            token("installer-key"),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            token("ceremony-key"),
            SigningKey::from_bytes(&[3; 32]).verifying_key(),
            token("revocation-key"),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            AssuranceRegistry::compiled(vec![]).unwrap(),
        )
        .is_err()
    );
    let failed_target = rusqlite::Connection::open(&failed_target_path).unwrap();
    assert_eq!(
        failed_target
            .query_row("SELECT COUNT(*) FROM mutation_quota", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        failed_target
            .query_row("SELECT COUNT(*) FROM broker_store_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert!(failed_journal.audit_entries().unwrap().is_empty());
    assert_eq!(std::fs::read(&legacy_path).unwrap(), source_before);
    drop(failed_target);
    drop(failed_journal);

    let open = || {
        let journal =
            Arc::new(BrokerJournal::open(&journal_path, Arc::new(TestAuditSigner)).unwrap());
        let authority = BrokerAuthority::open(
            &legacy_path,
            journal.clone(),
            BTreeMap::new(),
            token("installer-key"),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            token("ceremony-key"),
            SigningKey::from_bytes(&[3; 32]).verifying_key(),
            token("revocation-key"),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            AssuranceRegistry::compiled(vec![]).unwrap(),
        )
        .unwrap();
        (journal, authority)
    };
    let (journal, authority) = open();
    assert!(
        authority
            .consume_mutation_quota("legacy-principal", 101, 1_000, 2)
            .is_err()
    );
    assert_eq!(std::fs::read(&legacy_path).unwrap(), source_before);
    let migration_events = journal
        .audit_entries()
        .unwrap()
        .into_iter()
        .filter(|entry| entry.event_type == "storage.authority_migrated")
        .count();
    assert_eq!(migration_events, 1);
    drop(authority);
    drop(journal);
    let (journal, _authority) = open();
    assert_eq!(
        journal
            .audit_entries()
            .unwrap()
            .into_iter()
            .filter(|entry| entry.event_type == "storage.authority_migrated")
            .count(),
        1
    );

    let conflict_legacy_path = directory.path().join("conflict-authority.sqlite");
    std::fs::copy(&legacy_path, &conflict_legacy_path).unwrap();
    let target = rusqlite::Connection::open(&journal_path).unwrap();
    target
        .execute(
            "INSERT OR REPLACE INTO mutation_quota VALUES ('legacy-principal', '999', '9')",
            [],
        )
        .unwrap();
    drop(target);
    let journal = Arc::new(BrokerJournal::open(&journal_path, Arc::new(TestAuditSigner)).unwrap());
    assert!(
        BrokerAuthority::open(
            &conflict_legacy_path,
            journal.clone(),
            BTreeMap::new(),
            token("installer-key"),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            token("ceremony-key"),
            SigningKey::from_bytes(&[3; 32]).verifying_key(),
            token("revocation-key"),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            AssuranceRegistry::compiled(vec![]).unwrap(),
        )
        .is_err()
    );
    let target = rusqlite::Connection::open(&journal_path).unwrap();
    let marker: i64 = target
        .query_row(
            "SELECT COUNT(*) FROM broker_store_migrations WHERE source_kind='authority' AND source_path=?1",
            [conflict_legacy_path.to_string_lossy().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, 0);
}

#[test]
fn active_approval_survives_broker_authority_and_journal_restart() {
    let fixture = Harness::new();
    let directory = tempfile::tempdir().unwrap();
    let authority_path = directory.path().join("authority.sqlite");
    let journal_path = directory.path().join("journal.sqlite");
    let policy_snapshot = fixture.policy_snapshot(1);
    let provenance = fixture.system_provenance();
    let terms = exact_terms(&fixture, b"restart-persistent approval");
    let approval_id = terms.approval_id().unwrap();

    let open = || {
        let journal = Arc::new(
            BrokerJournal::open(&journal_path, Arc::new(TestAuditSigner)).expect("journal"),
        );
        let mut policy_keys = BTreeMap::new();
        policy_keys.insert(
            fixture.wallet.as_str().to_owned(),
            (token("policy-key"), fixture.policy_key.verifying_key()),
        );
        BrokerAuthority::open(
            &authority_path,
            journal,
            policy_keys,
            token("installer-key"),
            fixture.installer_key.verifying_key(),
            token("ceremony-key"),
            fixture.ceremony_key.verifying_key(),
            token("revocation-key"),
            fixture.revocation_key.verifying_key(),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            AssuranceRegistry::compiled(vec![]).unwrap(),
        )
        .expect("authority")
    };

    {
        let authority = open();
        authority.install_policy(&policy_snapshot).unwrap();
        authority.install_provenance(&provenance).unwrap();
        authority.prepare_approval(&terms, &digest(7)).unwrap();
        authority
            .activate_approval(
                &fixture.signed_grant(&terms, approval_id.clone(), operation(3)),
                1_500,
            )
            .unwrap();
        assert_eq!(
            authority
                .approval_public_status(&approval_id)
                .unwrap()
                .state,
            bloom_broker_api::ApprovalLifecycleState::Active
        );
    }

    let restarted = open();
    assert_eq!(restarted.approval_terms(&approval_id).unwrap(), Some(terms));
    assert_eq!(
        restarted
            .approval_public_status(&approval_id)
            .unwrap()
            .state,
        bloom_broker_api::ApprovalLifecycleState::Active
    );
}

#[test]
fn signed_policy_is_canonical_monotonic_and_frozen() {
    let harness = Harness::new();
    harness
        .authority
        .install_policy(&harness.policy_snapshot(1))
        .expect("an identical authenticated policy reread is idempotent");
    let mut forged = harness.policy_snapshot(2);
    forged.policy_digest = digest(6);
    assert!(harness.authority.install_policy(&forged).is_err());

    let terms = exact_terms(&harness, b"approved");
    let provenance = harness.system_provenance();
    harness.activate(&terms, Some(&provenance));
    harness
        .authority
        .install_policy(&harness.policy_snapshot(2))
        .unwrap();
    let input = exact_input(&harness, &terms, operation(10), b"approved");
    assert!(
        error_code(harness.authority.authorize(&input).unwrap_err())
            .contains("POLICY_SNAPSHOT_MISMATCH")
    );
}

#[test]
fn initial_policy_adoption_requires_outer_receipt_and_does_not_poison_key_pin() {
    let harness = Harness::new();
    let wallet = token("new-wallet");
    let rejected_key = SigningKey::from_bytes(&[41; 32]);
    let accepted_key = SigningKey::from_bytes(&[42; 32]);

    let mut invalid_snapshot =
        initial_policy_snapshot(&wallet, &rejected_key, token("rejected-policy-key"));
    invalid_snapshot.signer_signature = Base64UrlBytes::from_bytes(&[0; 64]);
    assert!(
        harness
            .authority
            .install_initial_policy(&invalid_snapshot)
            .is_err()
    );

    let accepted_snapshot =
        initial_policy_snapshot(&wallet, &accepted_key, token("accepted-policy-key"));
    let mut receipt = CustodyResult {
        petal_registration_terms_digest: None,
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(91),
        public_status: CeremonyState::Completed,
        wallet_id: Some(wallet.clone()),
        public_key_refs: Vec::new(),
        credential_summaries: Vec::new(),
        initial_policy: Some(accepted_snapshot.clone()),
        receipt_digest: digest(92),
        encrypted_browser_result: None,
        signer_key_id: token("ceremony-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    sign_custody_receipt(&mut receipt, &harness.ceremony_key);

    let mut tampered = receipt.clone();
    tampered.receipt_digest = digest(93);
    assert!(
        harness
            .authority
            .adopt_custody_receipt(&tampered, 1_000)
            .is_err()
    );
    assert!(harness.authority.policy_snapshot(&wallet).is_err());

    let mut wrong_kind = receipt.clone();
    wrong_kind.ceremony_kind = CeremonyKind::CredentialAdd;
    sign_custody_receipt(&mut wrong_kind, &harness.ceremony_key);
    assert!(
        harness
            .authority
            .adopt_custody_receipt(&wrong_kind, 1_000)
            .is_err()
    );
    assert!(harness.authority.policy_snapshot(&wallet).is_err());

    harness
        .authority
        .adopt_custody_receipt(&receipt, 1_000)
        .unwrap();
    assert_eq!(
        harness.authority.policy_snapshot(&wallet).unwrap(),
        accepted_snapshot
    );
    harness
        .authority
        .adopt_custody_receipt(&receipt, 1_000)
        .unwrap();
}

#[test]
fn petal_scoped_key_is_frozen_to_installer_provenance_and_petal_approvals() {
    let harness = Harness::new();
    let provenance = harness.provenance();
    harness.authority.install_provenance(&provenance).unwrap();
    let scope = PetalKeyScope {
        wallet_id: harness.wallet.clone(),
        parent_key_ref: key_ref(),
        package_hash: digest(9),
        route: "/sign".into(),
        lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        key_slot: token("advisory"),
        allowed_routes: vec!["/other".into(), "/sign".into()],
        allowed_operation_classes: vec![token("transfer")],
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
        maximum_lifetime_ms: DecimalU64::new(10_000),
        custody_operation_id: operation(94),
    };
    harness.authority.prepare_petal_key_scope(&scope).unwrap();
    harness
        .authority
        .prepare_petal_key_scope(&scope)
        .expect("an exact custody retry is idempotent");

    let mut rebound = scope.clone();
    rebound.route = "/other".into();
    assert!(
        error_code(
            harness
                .authority
                .prepare_petal_key_scope(&rebound)
                .unwrap_err()
        )
        .contains("PROVENANCE")
    );
    let mut undeclared = scope.clone();
    undeclared.allowed_operation_classes = vec![token("undeclared-purpose")];
    assert!(
        error_code(
            harness
                .authority
                .prepare_petal_key_scope(&undeclared)
                .unwrap_err()
        )
        .contains("PROVENANCE_CLASS_MISMATCH")
    );

    let mut child = key_ref();
    child.locator = "petal-child-1".into();
    child.public_key_fingerprint = digest(95);
    let mut receipt = CustodyResult {
        petal_registration_terms_digest: None,
        ceremony_kind: CeremonyKind::KeyDerive,
        custody_operation_id: scope.custody_operation_id.clone(),
        public_status: CeremonyState::Succeeded,
        wallet_id: Some(harness.wallet.clone()),
        public_key_refs: vec![child.clone()],
        credential_summaries: vec![],
        initial_policy: None,
        receipt_digest: digest(96),
        encrypted_browser_result: None,
        signer_key_id: token("ceremony-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    sign_custody_receipt(&mut receipt, &harness.ceremony_key);
    harness
        .authority
        .adopt_custody_receipt(&receipt, 1_000)
        .unwrap();

    let mut non_petal = exact_terms(&harness, b"approved");
    non_petal.key_ref = child.clone();
    assert!(
        error_code(
            harness
                .authority
                .prepare_approval(&non_petal, &digest(7))
                .unwrap_err()
        )
        .contains("PETAL_KEY_SCOPE_MISMATCH")
    );

    let mut terms = petal_terms(&harness, &provenance);
    terms.key_ref = child.clone();
    terms.allowed_crypto_suites = vec![CryptoSuite::Secp256k1Sha256Recoverable];
    if let ApprovalSelector::Petal {
        allowed_operation_classes,
        ..
    } = &mut terms.selector
    {
        *allowed_operation_classes = vec![token("transfer")];
    }

    let mut secondary = provenance.clone();
    secondary.subject = ProvenanceSubject::Petal {
        package_hash: digest(9),
        route: "/other".into(),
    };
    secondary.operation_classes = vec![ProvenanceOperationClass {
        operation_class: token("transfer"),
        fee_asset: None,
    }];
    secondary.petal_lineage.as_mut().unwrap().active = false;
    sign_zeroed(
        &mut secondary,
        |value| &mut value.installer_signature,
        PROVENANCE_DOMAIN,
        &harness.installer_key,
    );
    harness.authority.install_provenance(&secondary).unwrap();

    let mut multi_route = terms.clone();
    let secondary_digest =
        Digest32::from_bytes(Sha256::digest(serde_jcs::to_vec(&secondary).unwrap()).into());
    if let ApprovalSelector::Petal { route_grants, .. } = &mut multi_route.selector {
        *route_grants = vec![
            PetalRouteGrant {
                route: "/other".into(),
                allowed_operation_classes: vec![token("transfer")],
                provenance_digest: secondary_digest,
            },
            PetalRouteGrant {
                route: "/sign".into(),
                allowed_operation_classes: vec![token("transfer")],
                provenance_digest: multi_route.provenance_digest.clone(),
            },
        ];
    }
    assert!(
        error_code(
            harness
                .authority
                .prepare_approval(&multi_route, &digest(7))
                .unwrap_err()
        )
        .contains("PROVENANCE_LINEAGE_MISMATCH"),
        "an inactive secondary grant must not inherit the origin route's lineage"
    );

    harness.activate(&terms, Some(&provenance));
    harness
        .authority
        .authorize(&petal_input(
            &terms,
            &provenance,
            operation(97),
            CryptoSuite::Secp256k1Sha256Recoverable,
        ))
        .unwrap();

    let mut wrong_provenance = petal_input(
        &terms,
        &provenance,
        operation(98),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    wrong_provenance.request.provenance = ProvenanceSubject::Petal {
        package_hash: digest(8),
        route: "/sign".into(),
    };
    assert!(
        error_code(harness.authority.authorize(&wrong_provenance).unwrap_err())
            .contains("PROVENANCE")
    );

    let mut invalid_replacement = harness.system_provenance();
    invalid_replacement.installer_signature = Base64UrlBytes::from_bytes(&[0; 64]);
    assert!(
        harness
            .authority
            .synchronize_provenance_catalog(&ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![invalid_replacement],
            })
            .is_err()
    );
    harness
        .authority
        .authorize(&petal_input(
            &terms,
            &provenance,
            operation(99),
            CryptoSuite::Secp256k1Sha256Recoverable,
        ))
        .expect("an invalid replacement must leave the current catalog intact");

    harness
        .authority
        .synchronize_provenance_catalog(&ProvenanceCatalog {
            schema: PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![harness.system_provenance()],
        })
        .unwrap();
    assert!(
        error_code(
            harness
                .authority
                .authorize(&petal_input(
                    &terms,
                    &provenance,
                    operation(100),
                    CryptoSuite::Secp256k1Sha256Recoverable,
                ))
                .unwrap_err()
        )
        .contains("PROVENANCE")
    );
}

#[test]
fn ac08_exact_selector_rejects_payload_hash_order_count_key_and_suite_changes() {
    let harness = Harness::new();
    let terms = exact_terms(&harness, b"approved");
    let provenance = harness.system_provenance();
    harness.activate(&terms, Some(&provenance));

    harness
        .authority
        .authorize(&exact_input(&harness, &terms, operation(11), b"approved"))
        .unwrap();
    let changed = exact_input(&harness, &terms, operation(12), b"changed");
    assert!(
        error_code(harness.authority.authorize(&changed).unwrap_err())
            .contains("SELECTOR_MISMATCH")
    );
    let mut wrong_suite = exact_input(&harness, &terms, operation(13), b"approved");
    wrong_suite.request.crypto_suite = CryptoSuite::Secp256k1Keccak256Recoverable;
    assert!(
        error_code(harness.authority.authorize(&wrong_suite).unwrap_err())
            .contains("SUITE_NOT_ALLOWED")
    );
    let mut wrong_key = exact_input(&harness, &terms, operation(14), b"approved");
    wrong_key.request.key_ref.locator = "other".into();
    assert!(
        error_code(harness.authority.authorize(&wrong_key).unwrap_err())
            .contains("KEYREF_MISMATCH")
    );

    let batch_harness = Harness::new();
    let provenance = batch_harness.system_provenance();
    let mut batch_terms = exact_terms(&batch_harness, b"first");
    let first = Digest32::from_bytes(Sha256::digest(b"first").into());
    let second = Digest32::from_bytes(Sha256::digest(b"second").into());
    batch_terms.selector = ApprovalSelector::Exact {
        ordered_payload_digests: vec![first.clone(), second.clone()],
        ordered_hashes: vec![first, second],
    };
    batch_terms.limits.max_signatures = DecimalU64::new(2);
    batch_harness.activate(&batch_terms, Some(&provenance));
    let valid_batch = exact_batch_input(
        &batch_harness,
        &batch_terms,
        operation(15),
        &[b"first".as_slice(), b"second".as_slice()],
    );
    batch_harness.authority.authorize(&valid_batch).unwrap();
    let reversed = exact_batch_input(
        &batch_harness,
        &batch_terms,
        operation(16),
        &[b"second".as_slice(), b"first".as_slice()],
    );
    assert!(batch_harness.authority.authorize(&reversed).is_err());
    let shortened = exact_batch_input(
        &batch_harness,
        &batch_terms,
        operation(17),
        &[b"first".as_slice()],
    );
    assert!(batch_harness.authority.authorize(&shortened).is_err());
}

#[test]
fn authorization_rechecks_broker_owned_current_provenance_catalog() {
    let harness = Harness::new();
    let provenance = harness.provenance();
    let terms = petal_terms(&harness, &provenance);
    harness.activate(&terms, Some(&provenance));

    let mut replacement = provenance.clone();
    replacement.publisher = token("replacement-publisher");
    replacement.installer_signature = Base64UrlBytes::from_bytes(&[]);
    sign_zeroed(
        &mut replacement,
        |value| &mut value.installer_signature,
        PROVENANCE_DOMAIN,
        &harness.installer_key,
    );
    harness.authority.install_provenance(&replacement).unwrap();

    let input = petal_input(
        &terms,
        &provenance,
        operation(20),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    assert!(
        error_code(harness.authority.authorize(&input).unwrap_err())
            .contains("PROVENANCE_MISMATCH")
    );
}

#[test]
fn provenance_rotation_linearizes_with_authorization_reservation() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let harness = Harness::new_with_verifiers(vec![Arc::new(BlockingProofVerifier {
        entered: entered.clone(),
        release: release.clone(),
    })]);
    let provenance = harness.provenance();
    let mut terms = petal_terms(&harness, &provenance);
    if let ApprovalSelector::Petal {
        required_claim_assurance,
        ..
    } = &mut terms.selector
    {
        *required_claim_assurance = ClaimAssuranceLevel::ProofVerified;
    }
    harness.activate(&terms, Some(&provenance));
    let mut input = petal_input(
        &terms,
        &provenance,
        operation(19),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    input
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .claim_assurance = ClaimAssurance::ProofVerified {
        verifier_id: token("test-proof"),
        verifier_digest: digest(2),
        proof_digest: digest(3),
    };
    bind_operation_digest(&mut input, &terms);

    let mut replacement = provenance.clone();
    replacement.publisher = token("replacement-publisher");
    replacement.installer_signature = Base64UrlBytes::from_bytes(&[]);
    sign_zeroed(
        &mut replacement,
        |value| &mut value.installer_signature,
        PROVENANCE_DOMAIN,
        &harness.installer_key,
    );
    let authority = Arc::new(harness.authority);
    let authorizing = {
        let authority = authority.clone();
        std::thread::spawn(move || authority.authorize(&input))
    };
    entered.wait();
    let (rotated_tx, rotated_rx) = mpsc::channel();
    let rotating = {
        let authority = authority.clone();
        std::thread::spawn(move || {
            let result = authority.install_provenance(&replacement);
            rotated_tx.send(()).unwrap();
            result
        })
    };
    assert!(
        rotated_rx.recv_timeout(Duration::from_millis(25)).is_err(),
        "catalog rotation must wait for the in-flight authorization reservation"
    );
    release.wait();
    authorizing.join().unwrap().unwrap();
    rotating.join().unwrap().unwrap();
    rotated_rx.recv().unwrap();

    let denied = petal_input(
        &terms,
        &provenance,
        operation(18),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    assert!(error_code(authority.authorize(&denied).unwrap_err()).contains("PROVENANCE_MISMATCH"));
}

#[test]
fn ac09_ac29_ac30_petal_claim_fee_and_multi_suite_are_fail_closed() {
    let harness = Harness::new();
    let provenance = harness.provenance();
    let terms = petal_terms(&harness, &provenance);
    harness.activate(&terms, Some(&provenance));
    let input = petal_input(
        &terms,
        &provenance,
        operation(21),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    let decision = harness.authority.authorize(&input).unwrap();
    assert_eq!(decision.reserved_values["ethereum:eth"].as_str(), "4");
    assert_eq!(decision.reserved_values["ethereum:token"].as_str(), "5");
    assert_eq!(
        decision.effective_assurance,
        Some(ClaimAssurance::MachineAsserted)
    );
    let mut conflicting_retry = input.clone();
    conflicting_retry
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .nonce = nonce(99);
    bind_operation_digest(&mut conflicting_retry, &terms);
    assert!(
        error_code(harness.authority.authorize(&conflicting_retry).unwrap_err())
            .contains("OPERATION_ID_CONFLICT")
    );

    let second_suite = petal_input(
        &terms,
        &provenance,
        operation(22),
        CryptoSuite::Secp256k1Keccak256Recoverable,
    );
    harness.authority.authorize(&second_suite).unwrap();
    let fee_exhausted = petal_input(
        &terms,
        &provenance,
        operation(26),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    assert!(
        error_code(harness.authority.authorize(&fee_exhausted).unwrap_err())
            .contains("FEE_LIMIT_EXCEEDED")
    );

    let mut wrong_route = petal_input(
        &terms,
        &provenance,
        operation(23),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    wrong_route.request.petal_use_claim.as_mut().unwrap().route = "/other".into();
    assert!(harness.authority.authorize(&wrong_route).is_err());

    let mut missing_fee = petal_input(
        &terms,
        &provenance,
        operation(24),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    missing_fee
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .declared_fee = DeclaredFee::None;
    assert!(
        error_code(harness.authority.authorize(&missing_fee).unwrap_err()).contains("FEE_REQUIRED")
    );

    let mut uncompiled_proof = petal_input(
        &terms,
        &provenance,
        operation(25),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    uncompiled_proof
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .claim_assurance = ClaimAssurance::ProofVerified {
        verifier_id: token("absent"),
        verifier_digest: digest(2),
        proof_digest: digest(3),
    };
    assert!(
        error_code(harness.authority.authorize(&uncompiled_proof).unwrap_err())
            .contains("ASSURANCE_UNAVAILABLE")
    );
    assert!(harness.authority.verifier_capabilities().is_empty());
}

#[test]
fn assurance_contract_fields_and_proof_evidence_are_enforced() {
    let incomplete = Harness::new_with_verifiers(vec![Arc::new(TestProofVerifier {
        fields: vec![token("payload_digest")],
    })]);
    let provenance = incomplete.provenance();
    let mut terms = petal_terms(&incomplete, &provenance);
    if let ApprovalSelector::Petal {
        required_claim_assurance,
        ..
    } = &mut terms.selector
    {
        *required_claim_assurance = ClaimAssuranceLevel::ProofVerified;
    }
    incomplete.activate(&terms, Some(&provenance));
    let mut input = petal_input(
        &terms,
        &provenance,
        operation(61),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    input
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .claim_assurance = ClaimAssurance::ProofVerified {
        verifier_id: token("test-proof"),
        verifier_digest: digest(2),
        proof_digest: digest(3),
    };
    input.request.claim_assurance_evidence = Some(Base64UrlBytes::from_bytes(b"proof-evidence"));
    bind_operation_digest(&mut input, &terms);
    assert!(
        error_code(incomplete.authority.authorize(&input).unwrap_err())
            .contains("ASSURANCE_CONTRACT_INCOMPLETE")
    );

    let complete = Harness::new_with_verifiers(vec![Arc::new(TestProofVerifier {
        fields: authority_fields(),
    })]);
    let provenance = complete.provenance();
    let mut terms = petal_terms(&complete, &provenance);
    if let ApprovalSelector::Petal {
        required_claim_assurance,
        ..
    } = &mut terms.selector
    {
        *required_claim_assurance = ClaimAssuranceLevel::ProofVerified;
    }
    complete.activate(&terms, Some(&provenance));
    let mut verified = petal_input(
        &terms,
        &provenance,
        operation(62),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    verified
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .claim_assurance = ClaimAssurance::ProofVerified {
        verifier_id: token("test-proof"),
        verifier_digest: digest(2),
        proof_digest: digest(3),
    };
    verified.request.claim_assurance_evidence = Some(Base64UrlBytes::from_bytes(b"proof-evidence"));
    bind_operation_digest(&mut verified, &terms);
    complete.authority.authorize(&verified).unwrap();
    let mut altered = petal_input(
        &terms,
        &provenance,
        operation(63),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    altered
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .claim_assurance = ClaimAssurance::ProofVerified {
        verifier_id: token("test-proof"),
        verifier_digest: digest(2),
        proof_digest: digest(4),
    };
    altered.request.claim_assurance_evidence = Some(Base64UrlBytes::from_bytes(b"proof-evidence"));
    bind_operation_digest(&mut altered, &terms);
    assert!(
        error_code(complete.authority.authorize(&altered).unwrap_err())
            .contains("ASSURANCE_VERIFICATION_FAILED")
    );
}

#[test]
fn concurrent_renewal_has_one_atomic_winner_and_never_reactivates_predecessor() {
    let harness = Harness::new();
    let provenance = harness.system_provenance();
    let original = exact_terms(&harness, b"original");
    harness.activate(&original, Some(&provenance));
    let original_id = original.approval_id().unwrap();

    let mut first = exact_terms(&harness, b"renewed");
    first.renewal_of = Some(original_id.clone());
    first.request_nonce = nonce(10);
    let mut second = first.clone();
    second.request_nonce = nonce(11);
    let first_id = harness
        .authority
        .prepare_approval(&first, &digest(7))
        .unwrap();
    let second_id = harness
        .authority
        .prepare_approval(&second, &digest(7))
        .unwrap();
    let first_grant = harness.signed_grant(&first, first_id, operation(70));
    let second_grant = harness.signed_grant(&second, second_id, operation(71));
    harness
        .authority
        .activate_approval(&first_grant, 1_500)
        .unwrap();
    assert!(
        harness
            .authority
            .activate_approval(&second_grant, 1_500)
            .is_err()
    );
    assert!(
        harness
            .authority
            .authorize(&exact_input(
                &harness,
                &original,
                operation(72),
                b"original"
            ))
            .is_err()
    );
    harness
        .authority
        .authorize(&exact_input(&harness, &first, operation(73), b"renewed"))
        .unwrap();
}

#[test]
fn revocation_and_authorization_linearize_without_post_revoke_reservation() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let harness = Harness::new_with_verifiers(vec![Arc::new(BlockingProofVerifier {
        entered: entered.clone(),
        release: release.clone(),
    })]);
    let provenance = harness.provenance();
    let mut terms = petal_terms(&harness, &provenance);
    if let ApprovalSelector::Petal {
        required_claim_assurance,
        ..
    } = &mut terms.selector
    {
        *required_claim_assurance = ClaimAssuranceLevel::ProofVerified;
    }
    harness.activate(&terms, Some(&provenance));
    let mut input = petal_input(
        &terms,
        &provenance,
        operation(90),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    input
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .claim_assurance = ClaimAssurance::ProofVerified {
        verifier_id: token("test-proof"),
        verifier_digest: digest(2),
        proof_digest: digest(3),
    };
    bind_operation_digest(&mut input, &terms);
    let tombstone = signed_approval_tombstone(&harness, terms.approval_id().unwrap());
    let state = signed_revocation_with_tombstones(&harness, 0, std::slice::from_ref(&tombstone));
    let mut denied_after = petal_input(
        &terms,
        &provenance,
        operation(91),
        CryptoSuite::Secp256k1Sha256Recoverable,
    );
    denied_after
        .request
        .petal_use_claim
        .as_mut()
        .unwrap()
        .claim_assurance = ClaimAssurance::ProofVerified {
        verifier_id: token("test-proof"),
        verifier_digest: digest(2),
        proof_digest: digest(3),
    };
    bind_operation_digest(&mut denied_after, &terms);

    let authority = Arc::new(harness.authority);
    let authorizing = {
        let authority = authority.clone();
        std::thread::spawn(move || authority.authorize(&input))
    };
    entered.wait();
    let reconciling = {
        let authority = authority.clone();
        std::thread::spawn(move || authority.reconcile_revocation(&state, &[tombstone]))
    };
    release.wait();
    authorizing.join().unwrap().unwrap();
    assert_eq!(
        reconciling.join().unwrap().unwrap(),
        EpochReconciliation::Converged
    );
    assert!(authority.authorize(&denied_after).is_err());
}

#[test]
fn quotas_leave_reads_available_and_revocation_reconciliation_is_monotonic() {
    let harness = Harness::new();
    let terms = exact_terms(&harness, b"approved");
    let provenance = harness.system_provenance();
    harness.activate(&terms, Some(&provenance));
    harness
        .authority
        .consume_mutation_quota("machine", 1_000, 1_000, 1)
        .unwrap();
    assert!(
        harness
            .authority
            .consume_mutation_quota("machine", 1_001, 1_000, 1)
            .is_err()
    );
    assert_eq!(
        harness
            .authority
            .approval_terms(&terms.approval_id().unwrap())
            .unwrap(),
        Some(terms.clone())
    );
    let tombstone = signed_approval_tombstone(&harness, terms.approval_id().unwrap());
    let same_epoch =
        signed_revocation_with_tombstones(&harness, 0, std::slice::from_ref(&tombstone));
    assert_eq!(
        harness
            .authority
            .reconcile_revocation(&same_epoch, std::slice::from_ref(&tombstone))
            .unwrap(),
        EpochReconciliation::Converged
    );
    assert!(
        harness
            .authority
            .authorize(&exact_input(&harness, &terms, operation(30), b"approved"))
            .is_err()
    );

    let higher = signed_revocation_with_tombstones(&harness, 2, std::slice::from_ref(&tombstone));
    assert_eq!(
        harness
            .authority
            .reconcile_revocation(&higher, std::slice::from_ref(&tombstone))
            .unwrap(),
        EpochReconciliation::AdoptedSignerEpoch
    );
    assert!(
        harness
            .authority
            .authorize(&exact_input(&harness, &terms, operation(31), b"approved"))
            .is_err()
    );
    assert_eq!(
        harness
            .authority
            .reconcile_revocation(&higher, std::slice::from_ref(&tombstone))
            .unwrap(),
        EpochReconciliation::Converged
    );
    assert_eq!(
        harness
            .authority
            .reconcile_revocation(
                &signed_revocation_with_tombstones(&harness, 1, std::slice::from_ref(&tombstone),),
                std::slice::from_ref(&tombstone),
            )
            .unwrap(),
        EpochReconciliation::PushLocalEpoch
    );
    let mut epoch_two_terms = exact_terms(&harness, b"next");
    epoch_two_terms.wallet_revocation_epoch = DecimalU64::new(2);
    epoch_two_terms.request_nonce = nonce(9);
    assert!(
        error_code(
            harness
                .authority
                .prepare_approval(&epoch_two_terms, &digest(7))
                .unwrap_err()
        )
        .contains("REVOCATION_EPOCH_UNRECONCILED")
    );
    assert_eq!(
        harness
            .authority
            .reconcile_revocation(&higher, std::slice::from_ref(&tombstone))
            .unwrap(),
        EpochReconciliation::Converged
    );
    harness
        .authority
        .prepare_approval(&epoch_two_terms, &digest(7))
        .unwrap();
    let mut forged =
        signed_revocation_with_tombstones(&harness, 3, std::slice::from_ref(&tombstone));
    forged.signature = Base64UrlBytes::from_bytes(&[0; 64]);
    assert!(
        harness
            .authority
            .reconcile_revocation(&forged, std::slice::from_ref(&tombstone))
            .is_err()
    );

    let reverse = Harness::new();
    reverse
        .authority
        .advance_local_epoch(&reverse.wallet, 0, 1)
        .unwrap();
    let mut epoch_one_terms = exact_terms(&reverse, b"reverse");
    epoch_one_terms.wallet_revocation_epoch = DecimalU64::new(1);
    assert!(
        reverse
            .authority
            .prepare_approval(&epoch_one_terms, &digest(7))
            .is_err()
    );
    assert_eq!(
        reverse
            .authority
            .reconcile_revocation(&signed_revocation(&reverse, 1), &[])
            .unwrap(),
        EpochReconciliation::Converged
    );
    reverse
        .authority
        .prepare_approval(&epoch_one_terms, &digest(7))
        .unwrap();

    let stale = Harness::new();
    let stale_terms = exact_terms(&stale, b"stale");
    let stale_id = stale
        .authority
        .prepare_approval(&stale_terms, &digest(7))
        .unwrap();
    let stale_grant = stale.signed_grant(&stale_terms, stale_id, operation(77));
    stale
        .authority
        .advance_local_epoch(&stale.wallet, 0, 1)
        .unwrap();
    assert!(
        stale
            .authority
            .activate_approval(&stale_grant, 1_500)
            .is_err()
    );

    let preempted = Harness::new();
    let preempted_terms = exact_terms(&preempted, b"preempted");
    let preemptive_tombstone =
        signed_approval_tombstone(&preempted, preempted_terms.approval_id().unwrap());
    let preemptive_state = signed_revocation_with_tombstones(
        &preempted,
        0,
        std::slice::from_ref(&preemptive_tombstone),
    );
    preempted
        .authority
        .reconcile_revocation(
            &preemptive_state,
            std::slice::from_ref(&preemptive_tombstone),
        )
        .unwrap();
    assert!(
        preempted
            .authority
            .prepare_approval(&preempted_terms, &digest(7))
            .is_err()
    );
}

#[test]
fn policy_update_rejects_a_machine_claimed_diff_that_broker_did_not_derive() {
    let harness = Harness::new();
    let baseline_snapshot = harness.policy_snapshot(1);
    let baseline: CanonicalWalletPolicy =
        serde_json::from_slice(&baseline_snapshot.canonical_policy.decode()).unwrap();
    let mut proposed = baseline.clone();
    proposed.maximum_approval_lifetime_ms += 1;
    proposed.allowed_destinations.push(PolicyDestination {
        chain: token("ethereum"),
        destination: "0xexpanded-authority".into(),
    });
    let proposed_bytes = serde_jcs::to_vec(&proposed).unwrap();

    let stale_benign_diff = canonical_policy_authority_diff(&baseline, &baseline);
    let mut request = PolicyUpdateRequest {
        operation_id: operation(90),
        wallet_id: harness.wallet.clone(),
        baseline_version: baseline_snapshot.version,
        baseline_digest: baseline_snapshot.policy_digest,
        proposed_canonical_policy: Base64UrlBytes::from_bytes(&proposed_bytes),
        proposed_policy_digest: Digest32::from_bytes(Sha256::digest(&proposed_bytes).into()),
        authority_diff_digest: stale_benign_diff.digest().unwrap(),
        assurance_level: token("user_verified"),
    };
    assert!(
        error_code(
            harness
                .authority
                .validate_policy_update(&request)
                .unwrap_err()
        )
        .contains("authority diff digest")
    );

    let exact_diff = canonical_policy_authority_diff(&baseline, &proposed);
    request.authority_diff_digest = exact_diff.digest().unwrap();
    assert_eq!(
        harness.authority.validate_policy_update(&request).unwrap(),
        exact_diff
    );
}

fn exact_terms(harness: &Harness, payload: &[u8]) -> SealedApprovalTerms {
    harness
        .authority
        .install_provenance(&harness.system_provenance())
        .unwrap();
    let hash = Digest32::from_bytes(Sha256::digest(payload).into());
    SealedApprovalTerms {
        subject: ApprovalSubject::System {
            component_id: token("cli"),
            operation_class: token("sign"),
        },
        wallet_id: harness.wallet.clone(),
        key_ref: key_ref(),
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
        selector: ApprovalSelector::Exact {
            ordered_payload_digests: vec![hash.clone()],
            ordered_hashes: vec![hash],
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(0),
        policy_version: DecimalU64::new(1),
        policy_digest: harness.policy_snapshot(1).policy_digest,
        provenance_digest: Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(&harness.system_provenance()).unwrap()).into(),
        ),
        request_nonce: nonce(1),
        issued_at_ms: DecimalU64::new(900),
        not_before_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(2_000),
        renewal_of: None,
    }
}

fn petal_terms(harness: &Harness, provenance: &ProvenanceRecord) -> SealedApprovalTerms {
    harness.authority.install_provenance(provenance).unwrap();
    let (package_hash, route) = match &provenance.subject {
        ProvenanceSubject::Petal {
            package_hash,
            route,
        } => (package_hash.clone(), route.clone()),
        _ => panic!("expected Petal provenance"),
    };
    SealedApprovalTerms {
        subject: ApprovalSubject::Petal {
            package_hash: package_hash.clone(),
            route: route.clone(),
            agent_id: Some("advisory".into()),
        },
        wallet_id: harness.wallet.clone(),
        key_ref: key_ref(),
        allowed_crypto_suites: vec![
            CryptoSuite::Secp256k1Sha256Recoverable,
            CryptoSuite::Secp256k1Keccak256Recoverable,
        ],
        selector: ApprovalSelector::Petal {
            package_hash,
            route,
            allowed_operation_classes: vec![token("authenticate"), token("transfer")],
            route_grants: Vec::new(),
            required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(4),
            max_signatures: DecimalU64::new(4),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![
                value_limit("ethereum", "token", "100"),
                value_limit("ethereum", "eth", "10"),
            ],
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(0),
        policy_version: DecimalU64::new(1),
        policy_digest: harness.policy_snapshot(1).policy_digest,
        provenance_digest: Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(provenance).unwrap()).into(),
        ),
        request_nonce: nonce(2),
        issued_at_ms: DecimalU64::new(900),
        not_before_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(2_000),
        renewal_of: None,
    }
}

fn exact_input(
    harness: &Harness,
    terms: &SealedApprovalTerms,
    operation_id: OperationId,
    payload: &[u8],
) -> AuthorizationInput {
    let mut input = AuthorizationInput {
        request: MachineSignRequest {
            operation_id,
            operation_digest: digest(5),
            approval_id: terms.approval_id().unwrap(),
            key_ref: terms.key_ref.clone(),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            payloads: SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(payload),
            },
            petal_use_claim: None,
            claim_assurance_evidence: None,
            provenance: harness.system_provenance().subject,
        },
        reserved_at_ms: 1_500,
        observed_utc_ms: Some(1_500),
        monotonic_anchor_ns: 1_000_000,
        clock_boot_epoch: BootEpoch::from_bytes([1; 16]),
    };
    bind_operation_digest(&mut input, terms);
    input
}

fn exact_batch_input(
    harness: &Harness,
    terms: &SealedApprovalTerms,
    operation_id: OperationId,
    payloads: &[&[u8]],
) -> AuthorizationInput {
    let mut input = AuthorizationInput {
        request: MachineSignRequest {
            operation_id,
            operation_digest: digest(5),
            approval_id: terms.approval_id().unwrap(),
            key_ref: terms.key_ref.clone(),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            payloads: SigningPayloads::Batch {
                children: payloads
                    .iter()
                    .map(|payload| Base64UrlBytes::from_bytes(payload))
                    .collect(),
            },
            petal_use_claim: None,
            claim_assurance_evidence: None,
            provenance: harness.system_provenance().subject,
        },
        reserved_at_ms: 1_500,
        observed_utc_ms: Some(1_500),
        monotonic_anchor_ns: 1_000_000,
        clock_boot_epoch: BootEpoch::from_bytes([1; 16]),
    };
    bind_operation_digest(&mut input, terms);
    input
}

fn petal_input(
    terms: &SealedApprovalTerms,
    provenance: &ProvenanceRecord,
    operation_id: OperationId,
    suite: CryptoSuite,
) -> AuthorizationInput {
    let (package_hash, route) = match &provenance.subject {
        ProvenanceSubject::Petal {
            package_hash,
            route,
        } => (package_hash.clone(), route.clone()),
        _ => panic!("expected Petal provenance"),
    };
    let payload = b"transfer";
    let mut claim_digest = Sha256::new();
    claim_digest.update(b"bloom.petal.payload-batch.v1\0");
    claim_digest.update(1u64.to_be_bytes());
    claim_digest.update((payload.len() as u64).to_be_bytes());
    claim_digest.update(payload);
    let payload_digest = Digest32::from_bytes(claim_digest.finalize().into());
    let payload_hash = Digest32::from_bytes(Sha256::digest(payload).into());
    let ordered_hash = match suite {
        CryptoSuite::Secp256k1Keccak256Recoverable => {
            use sha3::Keccak256;
            Digest32::from_bytes(Keccak256::digest(payload).into())
        }
        _ => payload_hash,
    };
    let claim_nonce = nonce(operation_id.to_bytes()[31]);
    let mut input = AuthorizationInput {
        request: MachineSignRequest {
            operation_id,
            operation_digest: digest(5),
            approval_id: terms.approval_id().unwrap(),
            key_ref: terms.key_ref.clone(),
            crypto_suite: suite,
            payloads: SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(payload),
            },
            petal_use_claim: Some(PetalUseClaim {
                package_hash,
                route,
                operation_class: token("transfer"),
                crypto_suite: suite,
                payload_digest,
                ordered_hashes: vec![ordered_hash],
                declared_debits: vec![
                    DeclaredDebit {
                        asset: AssetId {
                            chain: token("ethereum"),
                            asset: "token".into(),
                        },
                        amount: DecimalU256::parse("5").unwrap(),
                    },
                    DeclaredDebit {
                        asset: AssetId {
                            chain: token("ethereum"),
                            asset: "eth".into(),
                        },
                        amount: DecimalU256::parse("1").unwrap(),
                    },
                ],
                declared_destinations: vec![DeclaredDestination {
                    chain: token("ethereum"),
                    destination: "0xrecipient".into(),
                }],
                declared_fee: DeclaredFee::Fee {
                    chain: token("ethereum"),
                    asset: "eth".into(),
                    amount: DecimalU256::parse("3").unwrap(),
                },
                nonce: claim_nonce.clone(),
                claim_assurance: ClaimAssurance::MachineAsserted,
            }),
            claim_assurance_evidence: None,
            provenance: provenance.subject.clone(),
        },
        reserved_at_ms: 1_500,
        observed_utc_ms: Some(1_500),
        monotonic_anchor_ns: 1_000_000,
        clock_boot_epoch: BootEpoch::from_bytes([1; 16]),
    };
    bind_operation_digest(&mut input, terms);
    input
}

fn bind_operation_digest(input: &mut AuthorizationInput, terms: &SealedApprovalTerms) {
    let payloads = match &input.request.payloads {
        SigningPayloads::Single { payload } => vec![payload.decode()],
        SigningPayloads::Batch { children } => {
            children.iter().map(Base64UrlBytes::decode).collect()
        }
    };
    let payload_digests: Vec<_> = payloads
        .iter()
        .map(|payload| Digest32::from_bytes(Sha256::digest(payload).into()))
        .collect();
    let ordered_hashes: Vec<_> = payloads
        .iter()
        .map(|payload| match input.request.crypto_suite {
            CryptoSuite::Secp256k1Keccak256Recoverable => {
                use sha3::Keccak256;
                Digest32::from_bytes(Keccak256::digest(payload).into())
            }
            _ => Digest32::from_bytes(Sha256::digest(payload).into()),
        })
        .collect();
    let claim_digest = input.request.petal_use_claim.as_ref().map(|claim| {
        Digest32::from_bytes(Sha256::digest(serde_jcs::to_vec(claim).unwrap()).into())
    });
    let assurance_digest = input.request.petal_use_claim.as_ref().map(|claim| {
        Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(&claim.claim_assurance).unwrap()).into(),
        )
    });
    input.request.operation_digest = TestSignOperationIdentity {
        operation_id: input.request.operation_id.clone(),
        approval_id: input.request.approval_id.clone(),
        key_ref: input.request.key_ref.clone(),
        crypto_suite: input.request.crypto_suite,
        ordered_payload_digests: payload_digests,
        ordered_hashes,
        petal_use_claim_digest: claim_digest,
        claim_assurance_digest: assurance_digest,
        policy_version: terms.policy_version.clone(),
        policy_digest: terms.policy_digest.clone(),
    }
    .digest();
}

fn signed_revocation(harness: &Harness, epoch: u64) -> RevocationState {
    signed_revocation_with_tombstones(harness, epoch, &[])
}

fn signed_revocation_with_tombstones(
    harness: &Harness,
    epoch: u64,
    tombstones: &[ApprovalTombstone],
) -> RevocationState {
    let mut sorted = tombstones.to_vec();
    sorted.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
    let mut state = RevocationState {
        wallet_id: harness.wallet.clone(),
        wallet_revocation_epoch: DecimalU64::new(epoch),
        wallet_tombstone: None,
        approval_tombstone_digest: Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(&sorted).unwrap()).into(),
        ),
        approval_tombstone_count: DecimalU64::new(sorted.len() as u64),
        observed_at_ms: DecimalU64::new(1_500),
        issuer_service_id: token("bloom-signer"),
        key_id: token("revocation-key"),
        signature: Base64UrlBytes::from_bytes(&[]),
    };
    sign_zeroed(
        &mut state,
        |value| &mut value.signature,
        REVOCATION_DOMAIN,
        &harness.revocation_key,
    );
    state
}

fn signed_approval_tombstone(harness: &Harness, approval_id: Digest32) -> ApprovalTombstone {
    let mut tombstone = ApprovalTombstone {
        approval_id,
        wallet_id: harness.wallet.clone(),
        wallet_revocation_epoch: DecimalU64::new(0),
        reason: "panic revoke".into(),
        operation_id: operation(88),
        revoked_at_ms: DecimalU64::new(1_500),
        issuer_service_id: token("bloom-signer"),
        key_id: token("revocation-key"),
        signature: Base64UrlBytes::from_bytes(&[]),
    };
    sign_zeroed(
        &mut tombstone,
        |value| &mut value.signature,
        APPROVAL_TOMBSTONE_DOMAIN,
        &harness.revocation_key,
    );
    tombstone
}

fn sign_zeroed<T: Clone + serde::Serialize>(
    value: &mut T,
    signature: fn(&mut T) -> &mut Base64UrlBytes,
    domain: &[u8],
    key: &SigningKey,
) {
    *signature(value) = Base64UrlBytes::from_bytes(&[]);
    let mut message = domain.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(value).unwrap());
    *signature(value) = Base64UrlBytes::from_bytes(&key.sign(&message).to_bytes());
}

fn initial_policy_snapshot(
    wallet: &Token,
    key: &SigningKey,
    key_id: Token,
) -> SignedPolicySnapshot {
    let policy = CanonicalWalletPolicy {
        wallet_id: wallet.clone(),
        maximum_approval_lifetime_ms: 86_400_000,
        allowed_petal_packages: Vec::new(),
        allowed_destinations: Vec::new(),
        required_verifiers: Vec::new(),
    };
    let canonical = serde_jcs::to_vec(&policy).unwrap();
    let mut snapshot = SignedPolicySnapshot {
        wallet_id: wallet.clone(),
        version: DecimalU64::new(1),
        canonical_policy: Base64UrlBytes::from_bytes(&canonical),
        policy_digest: Digest32::from_bytes(Sha256::digest(&canonical).into()),
        policy_signing_key_id: key_id,
        policy_verifying_key: Base64UrlBytes::from_bytes(&key.verifying_key().to_bytes()),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    sign_zeroed(
        &mut snapshot,
        |value| &mut value.signer_signature,
        POLICY_DOMAIN,
        key,
    );
    snapshot
}

fn sign_custody_receipt(receipt: &mut CustodyResult, key: &SigningKey) {
    receipt.signer_signature = Base64UrlBytes::from_bytes(&[]);
    let mut message = SIGNER_RECEIPT_DOMAIN.to_vec();
    message.extend_from_slice(&receipt.unsigned_canonical_bytes().unwrap());
    receipt.signer_signature = Base64UrlBytes::from_bytes(&key.sign(&message).to_bytes());
}

fn value_limit(chain: &str, asset: &str, lifetime: &str) -> ValueLimit {
    ValueLimit {
        asset: AssetId {
            chain: token(chain),
            asset: asset.into(),
        },
        lifetime: DecimalU256::parse(lifetime).unwrap(),
        rolling_windows: vec![],
    }
}

fn key_ref() -> KeyRef {
    KeyRef {
        backend: token("local"),
        backend_instance: token("primary"),
        locator: "key-1".into(),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: digest(4),
        derivation: None,
    }
}

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}

fn digest(byte: u8) -> Digest32 {
    Digest32::from_bytes([byte; 32])
}

fn operation(byte: u8) -> OperationId {
    OperationId::from_bytes([byte; 32])
}

fn nonce(byte: u8) -> RequestNonce {
    RequestNonce::from_bytes([byte; 16])
}

fn error_code(error: impl ToString) -> String {
    error.to_string()
}

#[path = "support/petal_registration.rs"]
mod registration_fixture;

fn registration_receipt(
    h: &Harness,
    terms: &bloom_broker_api::PetalRegistrationTerms,
) -> CustodyResult {
    let mut receipt: CustodyResult = serde_json::from_value(serde_json::json!({
        "ceremony_kind": "petal_registration", "custody_operation_id": terms.operation_id,
        "public_status": "SUCCEEDED", "wallet_id": terms.owner_wallet_id,
        "public_key_refs": [], "credential_summaries": [], "initial_policy": null,
        "receipt_digest": "66".repeat(32), "petal_registration_terms_digest": terms.digest().unwrap(),
        "encrypted_browser_result": null, "signer_key_id": "ceremony-key", "signer_signature": ""
    })).unwrap();
    receipt.signer_signature = Base64UrlBytes::from_bytes(
        &h.ceremony_key
            .sign(
                &[
                    SIGNER_RECEIPT_DOMAIN,
                    &receipt.unsigned_canonical_bytes().unwrap(),
                ]
                .concat(),
            )
            .to_bytes(),
    );
    receipt
}

#[test]
fn petal_registration_commits_complete_exact_routes_only_after_a_valid_receipt() {
    let h = Harness::new();
    let request =
        registration_fixture::proposal(OperationId::from_bytes([81; 32]), h.wallet.clone());
    let terms = h.authority.prepare_petal_registration(&request).unwrap();
    assert!(
        h.authority
            .petal_registration(&terms.package_hash)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        h.authority.prepare_petal_registration(&request).unwrap(),
        terms
    );
    let mut equivalent = request.clone();
    equivalent.requested_routes.reverse();
    equivalent.requested_routes[0]
        .capabilities
        .push("bloom:sign".into());
    equivalent.evidence.file_pages[0].reverse();
    assert_eq!(
        h.authority.prepare_petal_registration(&equivalent).unwrap(),
        terms,
        "equivalent sets must be canonicalized before consent"
    );
    let mut same_package = request.clone();
    same_package.operation_id = OperationId::from_bytes([82; 32]);
    assert_eq!(
        h.authority
            .prepare_petal_registration(&same_package)
            .unwrap(),
        terms
    );
    let receipt = registration_receipt(&h, &terms);
    for mutated in 0..5 {
        let mut forged = receipt.clone();
        match mutated {
            0 => forged.signer_signature = Base64UrlBytes::from_bytes(&[0; 64]),
            1 => forged.custody_operation_id = OperationId::from_bytes([83; 32]),
            2 => {
                forged.ceremony_kind = CeremonyKind::PolicyUpdate;
                forged.petal_registration_terms_digest = None;
            }
            3 => forged.petal_registration_terms_digest = Some(digest(1)),
            _ => forged.wallet_id = Some(token("different-owner")),
        }
        if mutated != 0 {
            // These are valid Signer signatures for different terms/kinds. Only
            // exact registration binding, rather than signature alone, rejects them.
            forged.signer_signature = Base64UrlBytes::from_bytes(
                &h.ceremony_key
                    .sign(
                        &[
                            SIGNER_RECEIPT_DOMAIN,
                            &forged.unsigned_canonical_bytes().unwrap(),
                        ]
                        .concat(),
                    )
                    .to_bytes(),
            );
        }
        assert!(
            h.authority
                .commit_petal_registration(&bloom_broker_api::PetalRegistrationCommitRequest {
                    operation_id: terms.operation_id.clone(),
                    ceremony_receipt: forged
                })
                .is_err()
        );
        assert!(
            h.authority
                .petal_registration(&terms.package_hash)
                .unwrap()
                .is_none()
        );
    }
    let commit = bloom_broker_api::PetalRegistrationCommitRequest {
        operation_id: terms.operation_id.clone(),
        ceremony_receipt: receipt,
    };
    let record = h.authority.commit_petal_registration(&commit).unwrap();
    assert_eq!(record.approved_routes, request.requested_routes);
    assert_eq!(record.approved_routes.len(), 2);
    assert_eq!(
        h.authority.commit_petal_registration(&commit).unwrap(),
        record
    );
    assert_eq!(
        h.authority.petal_registration(&terms.package_hash).unwrap(),
        Some(record.clone())
    );
    same_package.requested_routes[0].capabilities.clear();
    assert!(
        h.authority
            .prepare_petal_registration(&same_package)
            .is_err()
    );
    h.authority
        .synchronize_provenance_catalog(&ProvenanceCatalog {
            schema: PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![h.system_provenance()],
        })
        .unwrap();
    assert_eq!(
        h.authority.petal_registration(&terms.package_hash).unwrap(),
        Some(record)
    );
    assert_eq!(
        h.authority.policy_snapshot(&h.wallet).unwrap(),
        h.policy_snapshot(1)
    );
}

#[test]
fn petal_registration_rejects_static_scope_and_incomplete_routes_before_reserving_identity() {
    let h = Harness::new();
    let request =
        registration_fixture::proposal(OperationId::from_bytes([84; 32]), h.wallet.clone());
    let mut invalid = request.clone();
    invalid.requested_routes.pop();
    assert!(h.authority.prepare_petal_registration(&invalid).is_err());
    invalid = request.clone();
    invalid.requested_routes[0]
        .signing_operations
        .push("transaction.confirm".into());
    assert!(h.authority.prepare_petal_registration(&invalid).is_err());
    invalid = request.clone();
    invalid.evidence.package_hash = digest(1).to_string();
    assert!(h.authority.prepare_petal_registration(&invalid).is_err());
    assert!(h.authority.prepare_petal_registration(&request).is_ok());
}

#[test]
fn petal_registration_concurrent_prepares_reserve_one_lineage_and_operation() {
    let h = Harness::new();
    let mut request =
        registration_fixture::proposal(OperationId::from_bytes([85; 32]), h.wallet.clone());
    let authority = Arc::new(h.authority);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = vec![];
    for tag in [85, 86] {
        request.operation_id = OperationId::from_bytes([tag; 32]);
        let request = request.clone();
        let authority = authority.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            authority.prepare_petal_registration(&request).unwrap()
        }));
    }
    barrier.wait();
    let first = handles.remove(0).join().unwrap();
    let second = handles.remove(0).join().unwrap();
    assert_eq!(first, second);
    assert_eq!(
        h.journal
            .audit_entries()
            .unwrap()
            .iter()
            .filter(|entry| entry.event_type == "petal.registration_prepared")
            .count(),
        1
    );
}

fn reopen_registration_authority(journal: Arc<BrokerJournal>, broker_seed: u8) -> BrokerAuthority {
    BrokerAuthority::open_in_memory(
        journal,
        BTreeMap::new(),
        token("installer-key"),
        SigningKey::from_bytes(&[2; 32]).verifying_key(),
        token("ceremony-key"),
        SigningKey::from_bytes(&[3; 32]).verifying_key(),
        token("revocation-key"),
        SigningKey::from_bytes(&[4; 32]).verifying_key(),
        token("broker-app-1"),
        SigningKey::from_bytes(&[broker_seed; 32]).verifying_key(),
        AssuranceRegistry::compiled(vec![]).unwrap(),
    )
    .unwrap()
}

#[test]
fn petal_registration_reads_reject_transplanted_database_identity_and_changed_custody_pin() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.sqlite");
    let journal = Arc::new(BrokerJournal::open(&path, Arc::new(TestAuditSigner)).unwrap());
    let authority = reopen_registration_authority(journal.clone(), 7);
    let h = Harness::new();
    let request =
        registration_fixture::proposal(OperationId::from_bytes([87; 32]), h.wallet.clone());
    let terms = authority.prepare_petal_registration(&request).unwrap();
    let commit = bloom_broker_api::PetalRegistrationCommitRequest {
        operation_id: terms.operation_id.clone(),
        ceremony_receipt: registration_receipt(&h, &terms),
    };
    let record = authority.commit_petal_registration(&commit).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection
        .execute(
            "UPDATE petal_registration_attempts SET package_hash=?1",
            [digest(1).as_str()],
        )
        .unwrap();
    assert!(
        authority.petal_registration(&digest(1)).is_err(),
        "a record cannot be transplanted under another package lookup key"
    );
    connection
        .execute(
            "UPDATE petal_registration_attempts SET package_hash=?1",
            [terms.package_hash.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE petal_registration_attempts SET operation_id=?1",
            [OperationId::from_bytes([88; 32]).as_str()],
        )
        .unwrap();
    let mut wrong_lookup = commit.clone();
    wrong_lookup.operation_id = OperationId::from_bytes([88; 32]);
    assert!(authority.commit_petal_registration(&wrong_lookup).is_err());
    connection
        .execute(
            "UPDATE petal_registration_attempts SET operation_id=?1",
            [terms.operation_id.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE petal_registration_identities SET lineage_id=?1",
            [format!("pln1_{}", "b".repeat(52))],
        )
        .unwrap();
    assert!(
        authority.petal_registration(&terms.package_hash).is_err(),
        "reserved lineage must remain consistent with signed terms"
    );
    connection
        .execute(
            "UPDATE petal_registration_identities SET lineage_id=?1",
            [&terms.lineage_id],
        )
        .unwrap();
    let original_request: String = connection
        .query_row(
            "SELECT request_jcs FROM petal_registration_attempts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut reordered: serde_json::Value = serde_json::from_str(&original_request).unwrap();
    reordered["requested_routes"]
        .as_array_mut()
        .unwrap()
        .reverse();
    connection
        .execute(
            "UPDATE petal_registration_attempts SET request_jcs=?1",
            [serde_json::to_string(&reordered).unwrap()],
        )
        .unwrap();
    assert!(
        authority.petal_registration(&terms.package_hash).is_err(),
        "stored reviewed arrays must never be normalized during verification"
    );
    connection
        .execute(
            "UPDATE petal_registration_attempts SET request_jcs=?1",
            [&original_request],
        )
        .unwrap();
    assert_eq!(
        authority.petal_registration(&terms.package_hash).unwrap(),
        Some(record)
    );
    let rotated = reopen_registration_authority(journal, 8);
    assert!(
        rotated
            .petal_registration(&terms.package_hash)
            .unwrap()
            .is_none()
    );
    assert!(rotated.commit_petal_registration(&commit).is_err());
}

#[test]
fn petal_registration_audit_failure_rolls_back_the_entire_route_commit() {
    let fails = Arc::new(AtomicBool::new(false));
    let journal = Arc::new(
        BrokerJournal::open_in_memory(Arc::new(SwitchableAuditSigner(fails.clone()))).unwrap(),
    );
    let authority = reopen_registration_authority(journal, 7);
    let h = Harness::new();
    let request =
        registration_fixture::proposal(OperationId::from_bytes([89; 32]), h.wallet.clone());
    let terms = authority.prepare_petal_registration(&request).unwrap();
    let commit = bloom_broker_api::PetalRegistrationCommitRequest {
        operation_id: terms.operation_id.clone(),
        ceremony_receipt: registration_receipt(&h, &terms),
    };
    fails.store(true, Ordering::SeqCst);
    assert!(authority.commit_petal_registration(&commit).is_err());
    assert!(
        authority
            .petal_registration(&terms.package_hash)
            .unwrap()
            .is_none()
    );
    fails.store(false, Ordering::SeqCst);
    assert_eq!(
        authority
            .commit_petal_registration(&commit)
            .unwrap()
            .approved_routes,
        request.requested_routes
    );
}

fn register_for_authorization(h: &Harness) -> bloom_broker_api::PetalRegistration {
    let proposal = registration_fixture::proposal(operation(201), token("registration-owner"));
    let terms = h.authority.prepare_petal_registration(&proposal).unwrap();
    h.authority
        .commit_petal_registration(&bloom_broker_api::PetalRegistrationCommitRequest {
            operation_id: terms.operation_id.clone(),
            ceremony_receipt: registration_receipt(h, &terms),
        })
        .unwrap()
}

fn registered_digest(registration: &bloom_broker_api::PetalRegistration, route: &str) -> Digest32 {
    let bytes = serde_jcs::to_vec(&serde_json::json!({
        "registration_digest": registration.registration_digest,
        "route_id": route,
    }))
    .unwrap();
    Digest32::from_bytes(
        Sha256::digest([b"bloom.owner-petal-route/v1".as_slice(), &bytes].concat()).into(),
    )
}

fn allow_registered_package(h: &Harness, registration: &bloom_broker_api::PetalRegistration) {
    let mut snapshot = h.policy_snapshot(2);
    let mut policy: CanonicalWalletPolicy =
        serde_json::from_slice(&snapshot.canonical_policy.decode()).unwrap();
    policy.allowed_petal_packages = vec![registration.terms.package_hash.clone()];
    let canonical = serde_jcs::to_vec(&policy).unwrap();
    snapshot.policy_digest = Digest32::from_bytes(Sha256::digest(&canonical).into());
    snapshot.canonical_policy = Base64UrlBytes::from_bytes(&canonical);
    sign_zeroed(
        &mut snapshot,
        |value| &mut value.signer_signature,
        POLICY_DOMAIN,
        &h.policy_key,
    );
    h.authority.install_policy(&snapshot).unwrap();
}

fn registered_approval(
    h: &Harness,
    registration: &bloom_broker_api::PetalRegistration,
) -> SealedApprovalTerms {
    let mut terms = exact_terms(h, b"transfer");
    let snapshot = h.authority.policy_snapshot(&h.wallet).unwrap();
    terms.policy_digest = snapshot.policy_digest;
    terms.policy_version = snapshot.version;
    terms.subject = ApprovalSubject::Petal {
        package_hash: registration.terms.package_hash.clone(),
        route: "r000002".into(),
        agent_id: None,
    };
    terms.provenance_digest = registered_digest(registration, "r000002");
    terms.selector = ApprovalSelector::Petal {
        package_hash: registration.terms.package_hash.clone(),
        route: "r000002".into(),
        allowed_operation_classes: vec![token("example.sign")],
        route_grants: vec![
            PetalRouteGrant {
                route: "r000001".into(),
                allowed_operation_classes: vec![token("transaction.confirm")],
                provenance_digest: registered_digest(registration, "r000001"),
            },
            PetalRouteGrant {
                route: "r000002".into(),
                allowed_operation_classes: vec![token("example.sign")],
                provenance_digest: registered_digest(registration, "r000002"),
            },
        ],
        required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
    };
    terms.limits.max_operations = DecimalU64::new(2);
    terms.limits.max_signatures = DecimalU64::new(2);
    terms
}

fn registered_input(
    h: &Harness,
    terms: &SealedApprovalTerms,
    route: &str,
    class: &str,
    op: u8,
) -> AuthorizationInput {
    let mut input = petal_input(
        terms,
        &h.provenance(),
        operation(op),
        terms.allowed_crypto_suites[0],
    );
    let ApprovalSubject::Petal { package_hash, .. } = &terms.subject else {
        panic!("Petal terms required")
    };
    input.request.provenance = ProvenanceSubject::Petal {
        package_hash: package_hash.clone(),
        route: route.into(),
    };
    let claim = input.request.petal_use_claim.as_mut().unwrap();
    claim.package_hash = package_hash.clone();
    claim.route = route.into();
    claim.operation_class = token(class);
    claim.declared_fee = DeclaredFee::None;
    claim.declared_debits.clear();
    bind_operation_digest(&mut input, terms);
    input
}

#[test]
fn owner_registered_routes_require_exact_policy_and_scoped_approval() {
    let h = Harness::new();
    let registration = register_for_authorization(&h);
    let without_policy = registered_approval(&h, &registration);
    assert!(
        h.authority
            .prepare_approval(&without_policy, &digest(7))
            .is_err(),
        "registration owner authentication is not wallet eligibility"
    );
    allow_registered_package(&h, &registration);
    let terms = registered_approval(&h, &registration);
    let mut bad_digest = terms.clone();
    bad_digest.provenance_digest = digest(255);
    assert!(
        h.authority
            .prepare_approval(&bad_digest, &digest(7))
            .is_err()
    );
    let mut bad_grant = terms.clone();
    if let ApprovalSelector::Petal { route_grants, .. } = &mut bad_grant.selector {
        route_grants[0].allowed_operation_classes = vec![token("example.sign")];
    }
    assert!(
        h.authority
            .prepare_approval(&bad_grant, &digest(7))
            .is_err()
    );
    let approval_id = h.authority.prepare_approval(&terms, &digest(7)).unwrap();
    let input = registered_input(&h, &terms, "r000002", "example.sign", 202);
    assert!(
        h.authority.authorize(&input).is_err(),
        "registration receipt cannot sign without approved terms"
    );
    h.authority
        .activate_approval(&h.signed_grant(&terms, approval_id, operation(202)), 1500)
        .unwrap();
    for (route, class, op) in [
        ("missing", "example.sign", 210),
        ("r000001", "example.sign", 211),
        ("r000002", "transaction.confirm", 212),
    ] {
        assert!(
            h.authority
                .authorize(&registered_input(&h, &terms, route, class, op))
                .is_err()
        );
    }
    let mut wrong_hash = input.clone();
    if let ProvenanceSubject::Petal { package_hash, .. } = &mut wrong_hash.request.provenance {
        *package_hash = digest(255);
    }
    assert!(h.authority.authorize(&wrong_hash).is_err());
    let mut expired = input.clone();
    expired.reserved_at_ms = 2001;
    assert!(h.authority.authorize(&expired).is_err());
    let mut renewal = terms.clone();
    renewal.request_nonce = nonce(222);
    renewal.renewal_of = Some(terms.approval_id().unwrap());
    h.authority.prepare_approval(&renewal, &digest(7)).unwrap();
    h.authority.authorize(&input).unwrap();
    h.authority
        .authorize(&registered_input(
            &h,
            &terms,
            "r000001",
            "transaction.confirm",
            203,
        ))
        .unwrap();
    assert!(
        h.authority
            .authorize(&registered_input(
                &h,
                &terms,
                "r000002",
                "example.sign",
                204
            ))
            .is_err(),
        "count exhaustion remains enforced"
    );
}
