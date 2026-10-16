//! Clear signing at the authority boundary: the downgrade floor, and what a
//! frozen review still needs to be true when a signature is actually
//! authorized.

use bloom_broker::{
    authority::{
        AssuranceRegistry, AuthorizationInput, BrokerAuthority, CanonicalWalletPolicy,
        CeremonyApprovalGrant, ProvenanceOperationClass, ProvenanceRecord, ProvenanceSubject,
    },
    journal::{AuditSigner, BrokerJournal, FrozenReview, ReviewKind},
};
use bloom_broker_api::{
    ActivationMode, ApprovalLimits, ApprovalSelector, ApprovalSubject, Base64UrlBytes, BootEpoch,
    ClearSigningPolicy, CryptoSuite, DecimalU64, Digest32, KeyRef, KeySpec, MachineSignRequest,
    OperationId, RequestNonce, SealedApprovalTerms, SignedPolicySnapshot, SigningPayloads, Token,
};
use bloom_evm_clear_signing::*;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::{collections::BTreeMap, sync::Arc};

const POLICY_DOMAIN: &[u8] = b"bloom-policy-snapshot/v1";
const PROVENANCE_DOMAIN: &[u8] = b"bloom-provenance-record/v1";
const SIGN_OPERATION_DOMAIN: &[u8] = b"bloom-sign-operation/v1";

/// How Broker derives a signing operation's identity digest. Mirrored here so
/// the tests exercise real authorization instead of a relaxed path.
#[derive(serde::Serialize)]
struct SignOperationIdentity {
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

impl SignOperationIdentity {
    fn digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(SIGN_OPERATION_DOMAIN);
        hasher.update(serde_jcs::to_vec(self).unwrap());
        Digest32::from_bytes(hasher.finalize().into())
    }
}
const CEREMONY_DOMAIN: &[u8] = b"bloom-broker-ceremony-grant/v1";
const TOKEN_ADDRESS: &str = "0x1111111111111111111111111111111111111111";
const NOW_MS: u64 = 1_750_000_000_000;

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

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}

struct Harness {
    authority: BrokerAuthority,
    policy_key: SigningKey,
    installer_key: SigningKey,
    ceremony_key: SigningKey,
    wallet: Token,
}

impl Harness {
    fn open(directory: Option<&std::path::Path>) -> Self {
        let policy_key = SigningKey::from_bytes(&[1; 32]);
        let journal = Arc::new(match directory {
            None => BrokerJournal::open_in_memory(Arc::new(TestAuditSigner)).unwrap(),
            Some(directory) => {
                BrokerJournal::open(directory.join("journal.sqlite"), Arc::new(TestAuditSigner))
                    .unwrap()
            }
        });
        let installer = SigningKey::from_bytes(&[2; 32]);
        let wallet = token("wallet-1");
        let mut policy_keys = BTreeMap::new();
        policy_keys.insert(
            wallet.as_str().to_owned(),
            (token("policy-key"), policy_key.verifying_key()),
        );
        let build = move |path: Option<std::path::PathBuf>| match path {
            None => BrokerAuthority::open_in_memory(
                journal.clone(),
                policy_keys,
                token("installer-key"),
                installer.verifying_key(),
                token("ceremony-key"),
                SigningKey::from_bytes(&[3; 32]).verifying_key(),
                token("revocation-key"),
                SigningKey::from_bytes(&[4; 32]).verifying_key(),
                AssuranceRegistry::compiled(vec![]).unwrap(),
            ),
            Some(path) => BrokerAuthority::open(
                path,
                journal.clone(),
                policy_keys,
                token("installer-key"),
                installer.verifying_key(),
                token("ceremony-key"),
                SigningKey::from_bytes(&[3; 32]).verifying_key(),
                token("revocation-key"),
                SigningKey::from_bytes(&[4; 32]).verifying_key(),
                AssuranceRegistry::compiled(vec![]).unwrap(),
            ),
        };
        Self {
            authority: build(directory.map(|directory| directory.join("authority.sqlite")))
                .unwrap(),
            policy_key,
            installer_key: SigningKey::from_bytes(&[2; 32]),
            ceremony_key: SigningKey::from_bytes(&[3; 32]),
            wallet,
        }
    }

    fn install_policy(&self, version: u64, clear_signing: Option<ClearSigningPolicy>) {
        let policy = CanonicalWalletPolicy {
            wallet_id: self.wallet.clone(),
            maximum_approval_lifetime_ms: 100_000,
            allowed_petal_packages: Vec::new(),
            allowed_destinations: Vec::new(),
            required_verifiers: Vec::new(),
            clear_signing,
        };
        self.authority
            .install_policy(&self.sign_policy(version, &policy))
            .unwrap();
    }

    fn sign_policy(&self, version: u64, policy: &CanonicalWalletPolicy) -> SignedPolicySnapshot {
        let canonical = serde_jcs::to_vec(policy).unwrap();
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
        let mut unsigned = snapshot.clone();
        unsigned.signer_signature = Base64UrlBytes::from_bytes(&[]);
        let mut message = POLICY_DOMAIN.to_vec();
        message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
        snapshot.signer_signature =
            Base64UrlBytes::from_bytes(&self.policy_key.sign(&message).to_bytes());
        snapshot
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

    /// Terms for one exact EVM payload under the wallet's current policy.
    fn exact_terms(&self, policy_version: u64, payload: &[u8]) -> SealedApprovalTerms {
        self.authority
            .install_provenance(&self.system_provenance())
            .unwrap();
        let digest = Digest32::from_bytes(Sha256::digest(payload).into());
        SealedApprovalTerms {
            subject: ApprovalSubject::System {
                component_id: token("cli"),
                operation_class: token("sign"),
            },
            wallet_id: self.wallet.clone(),
            key_ref: KeyRef {
                backend: token("local"),
                backend_instance: token("primary"),
                locator: "key-1".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: Digest32::from_bytes([4; 32]),
                derivation: None,
            },
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: ApprovalSelector::Exact {
                ordered_payload_digests: vec![digest],
                ordered_hashes: vec![Digest32::from_bytes(Keccak256::digest(payload).into())],
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
            policy_version: DecimalU64::new(policy_version),
            policy_digest: self
                .authority
                .policy_snapshot(&self.wallet)
                .unwrap()
                .policy_digest,
            provenance_digest: Digest32::from_bytes(
                Sha256::digest(serde_jcs::to_vec(&self.system_provenance()).unwrap()).into(),
            ),
            request_nonce: RequestNonce::from_bytes([9; 16]),
            issued_at_ms: DecimalU64::new(NOW_MS - 100),
            expires_at_ms: DecimalU64::new(NOW_MS + 50_000),
            not_before_ms: DecimalU64::new(NOW_MS - 10),
            renewal_of: None,
        }
    }

    fn prepare(
        &self,
        terms: &SealedApprovalTerms,
        review: &FrozenReview,
    ) -> Result<Digest32, String> {
        self.authority
            .prepare_approval_with_claim(terms, &REVIEW_MANIFEST_DIGEST(), None, review)
            .map_err(|error| error.to_string())
    }

    fn activate(&self, terms: &SealedApprovalTerms, approval_id: &Digest32) -> Result<(), String> {
        let mut grant = CeremonyApprovalGrant {
            activation_operation_id: OperationId::from_bytes(
                Sha256::digest(format!("activate:{}", approval_id.as_str())).into(),
            ),
            approval_id: approval_id.clone(),
            approval_digest: approval_id.clone(),
            review_manifest_digest: REVIEW_MANIFEST_DIGEST(),
            replacement_approval_id: terms.renewal_of.clone(),
            wallet_revocation_epoch: terms.wallet_revocation_epoch.get(),
            issued_at_ms: NOW_MS - 10,
            expires_at_ms: NOW_MS + 50_000,
            ceremony_key_id: token("ceremony-key"),
            ceremony_signature: Base64UrlBytes::from_bytes(&[]),
        };
        sign_zeroed(
            &mut grant,
            |value| &mut value.ceremony_signature,
            CEREMONY_DOMAIN,
            &self.ceremony_key,
        );
        self.authority
            .activate_approval(&grant, NOW_MS)
            .map_err(|error| error.to_string())
    }

    fn authorize(&self, terms: &SealedApprovalTerms, payload: &[u8]) -> Result<(), String> {
        self.authorize_at(terms, payload, NOW_MS)
    }

    fn authorize_at(
        &self,
        terms: &SealedApprovalTerms,
        payload: &[u8],
        reserved_at_ms: u64,
    ) -> Result<(), String> {
        let approval_id = terms.approval_id().unwrap();
        let operation_id = OperationId::from_bytes(
            Sha256::digest(format!("sign:{}", approval_id.as_str())).into(),
        );
        let mut input = AuthorizationInput {
            expected_signer_public_key: None,
            request: MachineSignRequest {
                operation_id: operation_id.clone(),
                operation_digest: Digest32::from_bytes([0; 32]),
                approval_id: terms.approval_id().unwrap(),
                key_ref: terms.key_ref.clone(),
                crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
                payloads: SigningPayloads::Single {
                    payload: Base64UrlBytes::from_bytes(payload),
                },
                petal_use_claim: None,
                system_use_claim: None,
                claim_assurance_evidence: None,
                provenance: self.system_provenance().subject,
            },
            reserved_at_ms,
            observed_utc_ms: Some(reserved_at_ms),
            monotonic_anchor_ns: 1_000_000,
            clock_boot_epoch: BootEpoch::from_bytes([1; 16]),
        };
        input.request.operation_digest = SignOperationIdentity {
            operation_id,
            approval_id,
            key_ref: terms.key_ref.clone(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            ordered_payload_digests: vec![Digest32::from_bytes(Sha256::digest(payload).into())],
            ordered_hashes: vec![Digest32::from_bytes(Keccak256::digest(payload).into())],
            petal_use_claim_digest: None,
            claim_assurance_digest: None,
            policy_version: terms.policy_version.clone(),
            policy_digest: terms.policy_digest.clone(),
        }
        .digest();
        self.authority
            .authorize_for_clock_profile(&input, false)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// The frozen review Broker would have produced for a clear reading of
    /// the catalog entry this suite installs.
    fn clear_review(&self) -> FrozenReview {
        FrozenReview::with_evidence(
            ReviewKind::Clear,
            &ClearSigningEvidence::new(artifact::digest(), vec![token_entry()], false),
        )
        .unwrap()
    }

    /// Reach into durable state the way a lost row, a truncated backup or a
    /// tampering operator would: the approval record stays, its evidence
    /// does not.
    fn corrupt_stored_evidence(
        &self,
        path: &Path,
        approval_id: &Digest32,
        replacement: Option<&str>,
    ) {
        let connection = rusqlite::Connection::open(path.join("journal.sqlite")).unwrap();
        connection
            .execute(
                "UPDATE approval_metadata SET clear_signing_evidence_jcs = ?2
                 WHERE approval_id = ?1",
                rusqlite::params![approval_id.as_str(), replacement],
            )
            .unwrap();
    }
}

fn token_entry() -> SelectedEntry {
    SelectedEntry {
        chain_id: "1".into(),
        contract_address: TOKEN_ADDRESS.into(),
        upgradeable: false,
        token: None,
        applies_to_instances: false,
        instance: None,
    }
}

#[allow(non_snake_case)]
fn REVIEW_MANIFEST_DIGEST() -> Digest32 {
    Digest32::from_bytes([0x33; 32])
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

use std::path::Path;

fn clear_signing_policy() -> ClearSigningPolicy {
    ClearSigningPolicy::default()
}

#[test]
fn enabling_clear_signing_raises_the_downgrade_floor_before_the_policy_is_visible() {
    let directory = tempfile::tempdir().unwrap();
    {
        let harness = Harness::open(Some(directory.path()));
        harness.install_policy(1, None);
        assert_eq!(state_floor(directory.path()), None);
        harness.install_policy(2, Some(clear_signing_policy()));
        assert_eq!(state_floor(directory.path()), Some(2));
    }
    // Reopening with a build that understands the floor succeeds.
    drop(Harness::open(Some(directory.path())));

    // A build whose durable-state version is below the recorded floor refuses
    // to open the store at all, before it can mutate anything.
    raise_floor_beyond_this_build(directory.path());
    let journal = Arc::new(
        BrokerJournal::open(
            directory.path().join("journal.sqlite"),
            Arc::new(TestAuditSigner),
        )
        .unwrap(),
    );
    let error = BrokerAuthority::open(
        directory.path().join("authority.sqlite"),
        journal,
        BTreeMap::new(),
        token("installer-key"),
        SigningKey::from_bytes(&[2; 32]).verifying_key(),
        token("ceremony-key"),
        SigningKey::from_bytes(&[3; 32]).verifying_key(),
        token("revocation-key"),
        SigningKey::from_bytes(&[4; 32]).verifying_key(),
        AssuranceRegistry::compiled(vec![]).unwrap(),
    )
    .err()
    .expect("a store above this build's state version must not open")
    .to_string();
    assert!(error.contains("durable state version"), "{error}");
    assert!(error.contains("instead of downgrading"), "{error}");
}

fn state_floor(directory: &Path) -> Option<i64> {
    let connection = rusqlite::Connection::open(directory.join("journal.sqlite")).unwrap();
    connection
        .query_row(
            "SELECT minimum_state_version FROM store_compatibility WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .ok()
}

fn raise_floor_beyond_this_build(directory: &Path) {
    let connection = rusqlite::Connection::open(directory.join("journal.sqlite")).unwrap();
    connection
        .execute(
            "INSERT INTO store_compatibility(id, minimum_state_version) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET minimum_state_version = excluded.minimum_state_version",
            [bloom_broker::authority::BROKER_STATE_VERSION + 1],
        )
        .unwrap();
}

/// A clear approval and a legacy one, prepared and activated the same way,
/// so what follows compares the two under identical conditions.
fn prepared_clear_approval(harness: &Harness, payload: &[u8]) -> (SealedApprovalTerms, Digest32) {
    let terms = harness.exact_terms(1, payload);
    let approval = harness.prepare(&terms, &harness.clear_review()).unwrap();
    (terms, approval)
}

#[test]
fn a_clear_approval_cannot_activate_or_sign_once_its_frozen_evidence_is_gone() {
    let directory = tempfile::tempdir().unwrap();
    let payload = b"clear-payload";
    let harness = Harness::open(Some(directory.path()));
    harness.install_policy(1, Some(clear_signing_policy()));
    let (terms, approval) = prepared_clear_approval(&harness, payload);

    // Losing the evidence row must not read as "this approval never had any".
    harness.corrupt_stored_evidence(directory.path(), &approval, None);
    let error = harness.activate(&terms, &approval).unwrap_err();
    assert!(error.contains("frozen evidence is gone"), "{error}");

    // The same is true after activation: signing rechecks, so an approval
    // activated while its evidence was intact still cannot sign without it.
    let restored = harness.clear_review();
    harness.corrupt_stored_evidence(
        directory.path(),
        &approval,
        Some(restored.evidence_jcs().unwrap()),
    );
    harness.activate(&terms, &approval).unwrap();
    harness.corrupt_stored_evidence(directory.path(), &approval, None);
    let error = harness.authorize(&terms, payload).unwrap_err();
    assert!(error.contains("frozen evidence is gone"), "{error}");
}

#[test]
fn corrupt_evidence_is_refused_rather_than_read_as_absent() {
    let directory = tempfile::tempdir().unwrap();
    let harness = Harness::open(Some(directory.path()));
    harness.install_policy(1, Some(clear_signing_policy()));
    let (terms, approval) = prepared_clear_approval(&harness, b"clear-payload");

    harness.corrupt_stored_evidence(directory.path(), &approval, Some("{\"not\":\"evidence\"}"));
    let error = harness.activate(&terms, &approval).unwrap_err();
    assert!(error.contains("corrupt"), "{error}");
}

#[test]
fn evidence_cannot_be_swapped_for_another_readings() {
    let directory = tempfile::tempdir().unwrap();
    let harness = Harness::open(Some(directory.path()));
    harness.install_policy(1, Some(clear_signing_policy()));
    let (terms, approval) = prepared_clear_approval(&harness, b"clear-payload");

    // Evidence naming a verifier this build is not is refused, so replacing
    // one approval's reading with another's cannot pass the recheck.
    let foreign = ClearSigningEvidence::new(
        &Digest32::from_bytes([0x11; 32]),
        vec![token_entry()],
        false,
    );
    harness.corrupt_stored_evidence(
        directory.path(),
        &approval,
        Some(&serde_jcs::to_string(&foreign).unwrap()),
    );
    let error = harness.activate(&terms, &approval).unwrap_err();
    assert!(error.contains("verifier or catalog changed"), "{error}");
}

#[test]
fn reviews_without_catalog_evidence_still_activate_and_sign() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy()));

    for kind in [
        ReviewKind::Legacy,
        ReviewKind::Native,
        ReviewKind::OpaqueExact,
        ReviewKind::Structural,
    ] {
        let payload = format!("payload-{}", kind.as_str());
        let terms = harness.exact_terms(1, payload.as_bytes());
        let approval = harness
            .prepare(&terms, &FrozenReview::without_evidence(kind).unwrap())
            .unwrap();
        harness
            .activate(&terms, &approval)
            .unwrap_or_else(|error| panic!("{} must activate: {error}", kind.as_str()));
        harness
            .authorize(&terms, payload.as_bytes())
            .unwrap_or_else(|error| panic!("{} must sign: {error}", kind.as_str()));
    }
}

#[test]
fn a_review_whose_kind_and_evidence_disagree_cannot_be_constructed() {
    // The frozen review is the only way evidence reaches an approval record,
    // and it refuses both halves of the confusion: a catalog-backed review
    // with no evidence, and evidence attached to a review that does not need
    // it.
    let error = FrozenReview::without_evidence(ReviewKind::Clear).unwrap_err();
    assert!(error.contains("disagree"), "{error}");
    let error = FrozenReview::without_evidence(ReviewKind::Mixed).unwrap_err();
    assert!(error.contains("disagree"), "{error}");
    let error =
        FrozenReview::with_evidence(ReviewKind::OpaqueExact, &serde_json::json!({})).unwrap_err();
    assert!(error.contains("disagree"), "{error}");
}

#[test]
fn an_identical_retry_is_idempotent_and_a_changed_review_is_a_conflict() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy()));
    let terms = harness.exact_terms(1, b"clear-payload");
    let approval = harness.prepare(&terms, &harness.clear_review()).unwrap();

    // The same preparation repeated, byte for byte, is the same approval.
    assert_eq!(
        harness.prepare(&terms, &harness.clear_review()).unwrap(),
        approval
    );

    // Re-preparing the same terms under a different review would change what
    // the owner is being asked to approve. It is a conflict, not an update.
    let error = harness
        .prepare(
            &terms,
            &FrozenReview::without_evidence(ReviewKind::OpaqueExact).unwrap(),
        )
        .unwrap_err();
    assert!(
        error.contains("already bound to different prepared bytes"),
        "{error}"
    );

    let mut different = ClearSigningEvidence::new(artifact::digest(), vec![token_entry()], false);
    different.entries[0].upgradeable = true;
    let error = harness
        .prepare(
            &terms,
            &FrozenReview::with_evidence(ReviewKind::Clear, &different).unwrap(),
        )
        .unwrap_err();
    assert!(
        error.contains("already bound to different prepared bytes"),
        "{error}"
    );

    // The original review is untouched by either refusal.
    let (kind, evidence) = harness.authority.frozen_review(&approval).unwrap().unwrap();
    assert_eq!(kind, ReviewKind::Clear);
    assert!(!evidence.unwrap().entries[0].upgradeable);
}

#[test]
fn an_interrupted_preparation_leaves_nothing_that_can_activate() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy()));

    // Preparation that never reached the approval record — a crash between
    // the ceremony and the record — leaves no record at all, so the identity
    // it would have had cannot be activated or signed.
    let terms = harness.exact_terms(1, b"never-prepared");
    let approval = terms.approval_id().unwrap();
    assert!(
        harness
            .authority
            .frozen_review(&approval)
            .unwrap()
            .is_none()
    );
    assert!(harness.activate(&terms, &approval).is_err());
    assert!(harness.authorize(&terms, b"never-prepared").is_err());
}

#[test]
fn a_verifier_upgrade_invalidates_a_review_frozen_under_the_old_one() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy()));

    let superseded = ClearSigningEvidence::new(
        &Digest32::from_bytes([0x11; 32]),
        vec![token_entry()],
        false,
    );
    let terms = harness.exact_terms(1, b"clear-payload");
    let approval = harness
        .prepare(
            &terms,
            &FrozenReview::with_evidence(ReviewKind::Clear, &superseded).unwrap(),
        )
        .unwrap();
    let error = harness.activate(&terms, &approval).unwrap_err();
    assert!(error.contains("verifier or catalog changed"), "{error}");
}

const UNLIMITED_ALLOWANCE_DIFF_JCS: &str = concat!(
    r#"{"added_destinations":[],"added_petal_packages":[],"added_required_verifiers":[],"#,
    r#""clear_signing":{"after":{"opaque_exact_allowed":false,"unlimited_allowance_allowed":true},"#,
    r#""before":{"opaque_exact_allowed":false,"unlimited_allowance_allowed":false}},"#,
    r#""maximum_approval_lifetime_ms_after":"100000","maximum_approval_lifetime_ms_before":"100000","#,
    r#""removed_destinations":[],"removed_petal_packages":[],"removed_required_verifiers":[]}"#,
);

#[test]
fn enabling_unlimited_allowances_is_a_visible_authority_change() {
    let mut before = clear_signing_policy();
    before.unlimited_allowance_allowed = false;
    let mut after = before.clone();
    after.unlimited_allowance_allowed = true;

    let unchanged = bloom_broker::authority::canonical_policy_authority_diff(
        &wallet_policy(Some(before.clone())),
        &wallet_policy(Some(before.clone())),
    );
    assert!(
        unchanged.clear_signing.is_none(),
        "an unchanged policy must not claim a clear-signing change"
    );

    let changed = bloom_broker::authority::canonical_policy_authority_diff(
        &wallet_policy(Some(before)),
        &wallet_policy(Some(after)),
    );
    let change = changed
        .clear_signing
        .as_ref()
        .expect("enabling unlimited allowances is an authority change the owner must see");
    assert!(!change.before.as_ref().unwrap().unlimited_allowance_allowed);
    assert!(change.after.as_ref().unwrap().unlimited_allowance_allowed);

    assert_eq!(
        serde_jcs::to_string(&changed).unwrap(),
        UNLIMITED_ALLOWANCE_DIFF_JCS,
        "Bloom's machine client asserts these same bytes; a change here must be made on both sides"
    );
}

/// A policy update that never mentions clear signing produces the diff it
/// always produced, so the digest a released Machine computes still matches.
#[test]
fn a_policy_update_without_clear_signing_keeps_its_exact_diff_bytes() {
    let diff = bloom_broker::authority::canonical_policy_authority_diff(
        &wallet_policy(None),
        &wallet_policy(None),
    );
    assert_eq!(
        serde_jcs::to_string(&diff).unwrap(),
        concat!(
            r#"{"added_destinations":[],"added_petal_packages":[],"added_required_verifiers":[],"#,
            r#""maximum_approval_lifetime_ms_after":"100000","#,
            r#""maximum_approval_lifetime_ms_before":"100000","#,
            r#""removed_destinations":[],"removed_petal_packages":[],"removed_required_verifiers":[]}"#,
        )
    );
}

fn wallet_policy(clear_signing: Option<ClearSigningPolicy>) -> CanonicalWalletPolicy {
    CanonicalWalletPolicy {
        wallet_id: token("wallet-1"),
        maximum_approval_lifetime_ms: 100_000,
        allowed_petal_packages: Vec::new(),
        allowed_destinations: Vec::new(),
        required_verifiers: Vec::new(),
        clear_signing,
    }
}
