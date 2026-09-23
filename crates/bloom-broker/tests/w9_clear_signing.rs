//! Clear signing at the authority boundary: catalog trust, sequence rules,
//! withdrawal, the downgrade floor, and what a frozen review still needs to
//! be true when a signature is actually authorized.

use bloom_broker::{
    authority::{
        AssuranceRegistry, AuthorizationInput, BrokerAuthority, CanonicalWalletPolicy,
        CeremonyApprovalGrant, ProvenanceOperationClass, ProvenanceRecord, ProvenanceSubject,
    },
    journal::{AuditSigner, BrokerJournal, FrozenReview, ReviewKind},
};
use bloom_broker_api::{
    ActivationMode, ApprovalLimits, ApprovalSelector, ApprovalSubject, Base64UrlBytes, BootEpoch,
    CatalogTrustedKey, ClearSigningPolicy, CryptoSuite, DecimalU64, Digest32,
    EVM_CLEAR_SIGNING_VERIFIER_DIGEST_BYTES, EVM_CLEAR_SIGNING_VERIFIER_ID, KeyRef, KeySpec,
    MachineSignRequest, OperationId, RequestNonce, RequiredVerifier, SealedApprovalTerms,
    SignedPolicySnapshot, SigningPayloads, Token,
};
use bloom_evm_clear_signing::*;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
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

    fn try_install_policy(
        &self,
        version: u64,
        clear_signing: Option<ClearSigningPolicy>,
    ) -> Result<(), String> {
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
            .map_err(|error| error.to_string())
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

    fn current_policy(&self) -> CanonicalWalletPolicy {
        let snapshot = self.authority.policy_snapshot(&self.wallet).unwrap();
        serde_json::from_slice(&snapshot.canonical_policy.decode()).unwrap()
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
            reserved_at_ms: NOW_MS,
            observed_utc_ms: Some(NOW_MS),
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
        let accepted = stored(self).unwrap();
        FrozenReview::with_evidence(
            ReviewKind::Clear,
            &ClearSigningEvidence::new(
                &accepted,
                &Digest32::from_bytes(EVM_CLEAR_SIGNING_VERIFIER_DIGEST_BYTES),
                vec![SelectedEntry::of(accepted.entry(1, TOKEN_ADDRESS).unwrap())],
            ),
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

fn publisher(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn clear_signing_policy(seed: u8) -> ClearSigningPolicy {
    ClearSigningPolicy {
        catalog_id: token("bloom-tokens"),
        trusted_keys: vec![CatalogTrustedKey {
            key_id: token("publisher-1"),
            verifying_key: Base64UrlBytes::from_bytes(&publisher(seed).verifying_key().to_bytes()),
        }],
        signature_threshold: 1,
        maximum_observation_age_ms: 86_400_000,
        opaque_exact_allowed: false,
        unlimited_allowance_allowed: false,
        verifier: RequiredVerifier {
            verifier_id: token(EVM_CLEAR_SIGNING_VERIFIER_ID),
            verifier_digest: Digest32::from_bytes(EVM_CLEAR_SIGNING_VERIFIER_DIGEST_BYTES),
        },
    }
}

fn entry() -> CatalogEntry {
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": 1, "address": TOKEN_ADDRESS}]}},
        "display": {"formats": {"transfer(address _to, uint256 _value)": {
            "fields": [
                {"path": "_to", "label": "To", "format": "addressName", "visible": "always"},
                {"path": "_value", "label": "Amount", "format": "tokenAmount",
                 "params": {"tokenPath": "@.to"}, "visible": "always"}
            ]
        }}}
    });
    CatalogEntry {
        chain_id: DecimalU64::new(1),
        contract_address: TOKEN_ADDRESS.into(),
        admitted_functions: vec![AdmittedFunction {
            signature: "transfer(address _to, uint256 _value)".into(),
            action_class: ActionClass::Transfer,
        }],
        descriptor_digest: Some(descriptor_digest(&descriptor).unwrap()),
        flattened_descriptor: Some(descriptor),
        runtime_code_hash: None,
        token_metadata: Some(TokenMetadata {
            decimals: 6,
            symbol: "EXA".into(),
            name: "Example Token".into(),
        }),
        upgradeable: false,
        implementation_hash: None,
        observed_at_ms: DecimalU64::new(NOW_MS - 1000),
    }
}

fn catalog(sequence: u64, entries: Vec<CatalogEntry>, seed: u8) -> ClearSigningCatalog {
    let mut catalog = ClearSigningCatalog {
        schema: CATALOG_SCHEMA.into(),
        catalog_id: token("bloom-tokens"),
        sequence: DecimalU64::new(sequence),
        issued_at_ms: DecimalU64::new(NOW_MS - 10_000),
        expires_at_ms: DecimalU64::new(NOW_MS + 86_400_000),
        entries,
        signatures: Vec::new(),
    };
    let mut message = CATALOG_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&catalog.unsigned_canonical_bytes().unwrap());
    catalog.signatures = vec![CatalogSignature {
        key_id: token("publisher-1"),
        signature: Base64UrlBytes::from_bytes(&publisher(seed).sign(&message).to_bytes()),
    }];
    catalog
}

fn install(harness: &Harness, catalog: &ClearSigningCatalog) -> Result<bool, String> {
    let bytes = serde_jcs::to_vec(catalog).unwrap().len();
    harness
        .authority
        .install_clear_signing_catalog_for_enrolled_wallets(catalog, bytes)
        .map_err(|error| error.to_string())
}

fn stored(harness: &Harness) -> Option<AcceptedCatalog> {
    let policy = harness.current_policy();
    let settings = policy.clear_signing.as_ref().unwrap();
    let trusted = bloom_broker::authority::trusted_catalog_keys(settings).unwrap();
    harness
        .authority
        .clear_signing_catalog(&trusted, usize::from(settings.signature_threshold))
        .unwrap()
}

#[test]
fn a_catalog_installs_only_for_a_wallet_that_already_trusts_its_publisher() {
    let harness = Harness::open(None);
    harness.install_policy(1, None);
    // No wallet has enabled clear signing: nothing to install against.
    assert!(!install(&harness, &catalog(1, vec![entry()], 5)).unwrap());
    assert!(harness.authority.clear_signing_status().unwrap().is_none());

    harness.install_policy(2, Some(clear_signing_policy(5)));
    assert!(install(&harness, &catalog(1, vec![entry()], 5)).unwrap());
    assert!(stored(&harness).unwrap().entry(1, TOKEN_ADDRESS).is_some());

    // A snapshot signed by someone the wallet does not trust is refused, and
    // does not replace what is stored.
    assert!(install(&harness, &catalog(2, vec![], 9)).is_err());
    assert!(stored(&harness).unwrap().entry(1, TOKEN_ADDRESS).is_some());
}

#[test]
fn sequence_moves_forward_only_and_equal_sequences_must_be_identical() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(7, vec![entry()], 5)).unwrap();

    // The same sequence with the same content is an idempotent retry.
    install(&harness, &catalog(7, vec![entry()], 5)).unwrap();

    // The same sequence with different content is a conflict, not a newer
    // truth to prefer.
    let mut conflicting = entry();
    conflicting.observed_at_ms = DecimalU64::new(NOW_MS - 2000);
    let error = install(&harness, &catalog(7, vec![conflicting], 5)).unwrap_err();
    assert!(error.contains("sequence"), "{error}");

    // A rollback is refused.
    assert!(install(&harness, &catalog(6, vec![entry()], 5)).is_err());

    // A newer complete snapshot that omits the entry withdraws it.
    install(&harness, &catalog(8, vec![], 5)).unwrap();
    assert!(stored(&harness).unwrap().entry(1, TOKEN_ADDRESS).is_none());
    assert_eq!(
        harness
            .authority
            .clear_signing_status()
            .unwrap()
            .unwrap()
            .sequence,
        "8"
    );
}

#[test]
fn stored_bytes_stop_authorizing_when_the_wallet_rotates_its_trust() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();
    assert!(stored(&harness).is_some());

    // The owner rotates the publisher key in a policy ceremony. Nothing was
    // deleted, and the same bytes now authorize nothing.
    harness.install_policy(2, Some(clear_signing_policy(6)));
    assert!(stored(&harness).is_none());
    // The operator can still see what is stored, which is how they notice.
    assert!(harness.authority.clear_signing_status().unwrap().is_some());
}

#[test]
fn a_policy_pinning_a_verifier_this_build_does_not_contain_is_refused() {
    let harness = Harness::open(None);
    let mut wrong_digest = clear_signing_policy(5);
    wrong_digest.verifier.verifier_digest = Digest32::from_bytes([0xaa; 32]);
    let error = harness
        .try_install_policy(1, Some(wrong_digest))
        .unwrap_err();
    assert!(error.contains("POLICY_VERIFIER_UNAVAILABLE"), "{error}");

    let mut impossible_threshold = clear_signing_policy(5);
    impossible_threshold.signature_threshold = 2;
    assert!(
        harness
            .try_install_policy(1, Some(impossible_threshold))
            .is_err()
    );
}

#[test]
fn enabling_clear_signing_raises_the_downgrade_floor_before_the_policy_is_visible() {
    let directory = tempfile::tempdir().unwrap();
    {
        let harness = Harness::open(Some(directory.path()));
        harness.install_policy(1, None);
        assert_eq!(state_floor(directory.path()), None);
        harness.install_policy(2, Some(clear_signing_policy(5)));
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
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();
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
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();
    let (terms, approval) = prepared_clear_approval(&harness, b"clear-payload");

    harness.corrupt_stored_evidence(directory.path(), &approval, Some("{\"not\":\"evidence\"}"));
    let error = harness.activate(&terms, &approval).unwrap_err();
    assert!(error.contains("corrupt"), "{error}");
}

#[test]
fn evidence_cannot_be_swapped_for_another_readings() {
    let directory = tempfile::tempdir().unwrap();
    let harness = Harness::open(Some(directory.path()));
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();
    let (terms, approval) = prepared_clear_approval(&harness, b"clear-payload");

    // Evidence naming a verifier this build is not is refused, so replacing
    // one approval's reading with another's cannot pass the recheck.
    let accepted = stored(&harness).unwrap();
    let foreign = ClearSigningEvidence::new(
        &accepted,
        &Digest32::from_bytes([0x11; 32]),
        vec![SelectedEntry::of(accepted.entry(1, TOKEN_ADDRESS).unwrap())],
    );
    harness.corrupt_stored_evidence(
        directory.path(),
        &approval,
        Some(&serde_jcs::to_string(&foreign).unwrap()),
    );
    let error = harness.activate(&terms, &approval).unwrap_err();
    assert!(error.contains("verifier changed"), "{error}");
}

#[test]
fn legacy_and_opaque_approvals_still_activate_and_sign_without_evidence() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();

    for kind in [
        ReviewKind::Legacy,
        ReviewKind::Native,
        ReviewKind::OpaqueExact,
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
    // and it refuses both halves of the confusion: a clear review with no
    // evidence, and evidence attached to a review that does not need it.
    let error = FrozenReview::without_evidence(ReviewKind::Clear).unwrap_err();
    assert!(error.contains("disagree"), "{error}");
    let error =
        FrozenReview::with_evidence(ReviewKind::OpaqueExact, &serde_json::json!({})).unwrap_err();
    assert!(error.contains("disagree"), "{error}");
}

#[test]
fn an_identical_retry_is_idempotent_and_a_changed_review_is_a_conflict() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();
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

    let accepted = stored(&harness).unwrap();
    let mut different = ClearSigningEvidence::new(
        &accepted,
        &Digest32::from_bytes(EVM_CLEAR_SIGNING_VERIFIER_DIGEST_BYTES),
        vec![SelectedEntry::of(accepted.entry(1, TOKEN_ADDRESS).unwrap())],
    );
    different.catalog_sequence = "99".into();
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
    assert_eq!(evidence.unwrap().catalog_sequence, "1");
}

#[test]
fn an_interrupted_preparation_leaves_nothing_that_can_activate() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();

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
fn a_withdrawal_committed_before_the_decision_blocks_the_frozen_review() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();

    let payload = b"clear-payload";
    let (terms, approval) = prepared_clear_approval(&harness, payload);
    harness
        .activate(&terms, &approval)
        .expect("nothing has changed yet");

    // A newer complete snapshot that omits the entry withdraws it, and the
    // signature that would still have been authorized a moment ago is not.
    install(&harness, &catalog(2, vec![], 5)).unwrap();
    let error = harness.authorize(&terms, payload).unwrap_err();
    assert!(error.contains("withdrawn"), "{error}");

    // An approval prepared without a clear reading is unaffected.
    let opaque_terms = harness.exact_terms(1, b"opaque-payload");
    let opaque = harness
        .prepare(
            &opaque_terms,
            &FrozenReview::without_evidence(ReviewKind::OpaqueExact).unwrap(),
        )
        .unwrap();
    harness.activate(&opaque_terms, &opaque).unwrap();
    harness.authorize(&opaque_terms, b"opaque-payload").unwrap();
}

#[test]
fn a_verifier_upgrade_invalidates_a_review_frozen_under_the_old_one() {
    let harness = Harness::open(None);
    harness.install_policy(1, Some(clear_signing_policy(5)));
    install(&harness, &catalog(1, vec![entry()], 5)).unwrap();

    let accepted = stored(&harness).unwrap();
    let superseded = ClearSigningEvidence::new(
        &accepted,
        &Digest32::from_bytes([0x11; 32]),
        vec![SelectedEntry::of(accepted.entry(1, TOKEN_ADDRESS).unwrap())],
    );
    let terms = harness.exact_terms(1, b"clear-payload");
    let approval = harness
        .prepare(
            &terms,
            &FrozenReview::with_evidence(ReviewKind::Clear, &superseded).unwrap(),
        )
        .unwrap();
    let error = harness.activate(&terms, &approval).unwrap_err();
    assert!(error.contains("verifier changed"), "{error}");
}

#[test]
fn a_restart_keeps_the_sequence_watermark_and_the_frozen_review() {
    let directory = tempfile::tempdir().unwrap();
    let payload = b"clear-payload";
    let terms;
    let approval;
    {
        let harness = Harness::open(Some(directory.path()));
        harness.install_policy(1, Some(clear_signing_policy(5)));
        install(&harness, &catalog(4, vec![entry()], 5)).unwrap();
        (terms, approval) = prepared_clear_approval(&harness, payload);
        harness.activate(&terms, &approval).unwrap();
    }
    let harness = Harness::open(Some(directory.path()));
    assert_eq!(
        harness
            .authority
            .clear_signing_status()
            .unwrap()
            .unwrap()
            .sequence,
        "4"
    );
    // The frozen review survived the restart, so the approval still signs.
    let (kind, evidence) = harness.authority.frozen_review(&approval).unwrap().unwrap();
    assert_eq!(kind, ReviewKind::Clear);
    assert_eq!(evidence.unwrap().catalog_sequence, "4");
    harness.authorize(&terms, payload).unwrap();

    // The watermark survived, so a rollback is still refused after a restart.
    assert!(install(&harness, &catalog(3, vec![entry()], 5)).is_err());

    // And a withdrawal after the restart still blocks it.
    install(&harness, &catalog(5, vec![], 5)).unwrap();
    assert!(harness.authorize(&terms, payload).is_err());
}

/// The exact canonical bytes of the authority diff for enabling unlimited
/// allowances. Bloom's machine client computes a claimed diff that Broker
/// refuses if it differs, so the two shapes must agree byte for byte.
/// `bloom-machine-client` asserts this same literal.
const UNLIMITED_ALLOWANCE_DIFF_JCS: &str = concat!(
    r#"{"added_destinations":[],"added_petal_packages":[],"added_required_verifiers":[],"#,
    r#""clear_signing":{"after":{"catalog_id":"bloom-tokens","maximum_observation_age_ms":86400000,"#,
    r#""opaque_exact_allowed":false,"signature_threshold":1,"#,
    r#""trusted_keys":[{"key_id":"publisher-1","verifying_key":"bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E"}],"#,
    r#""unlimited_allowance_allowed":true,"#,
    r#""verifier":{"verifier_digest":"VERIFIER","verifier_id":"evm-clear-signing-v1"}},"#,
    r#""before":{"catalog_id":"bloom-tokens","maximum_observation_age_ms":86400000,"#,
    r#""opaque_exact_allowed":false,"signature_threshold":1,"#,
    r#""trusted_keys":[{"key_id":"publisher-1","verifying_key":"bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E"}],"#,
    r#""unlimited_allowance_allowed":false,"#,
    r#""verifier":{"verifier_digest":"VERIFIER","verifier_id":"evm-clear-signing-v1"}}},"#,
    r#""maximum_approval_lifetime_ms_after":"100000","maximum_approval_lifetime_ms_before":"100000","#,
    r#""removed_destinations":[],"removed_petal_packages":[],"removed_required_verifiers":[]}"#,
);

#[test]
fn enabling_unlimited_allowances_is_a_visible_authority_change() {
    let mut before = clear_signing_policy(5);
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
        UNLIMITED_ALLOWANCE_DIFF_JCS.replace(
            "VERIFIER",
            Digest32::from_bytes(EVM_CLEAR_SIGNING_VERIFIER_DIGEST_BYTES).as_str()
        ),
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

/// A verifier that moves must not strand the wallet that pinned the old one.
/// Installing an unknown pin stays refused, and re-presenting the snapshot
/// already stored stays readable — otherwise the owner could not approve the
/// policy update that re-pins it, and there would be no way out at all. The
/// pin is still spent: `clear_signing_context` refuses to produce a review
/// from a verifier the policy does not name.
#[test]
fn an_outdated_verifier_pin_does_not_strand_the_wallet() {
    let harness = Harness::open(None);
    let mut stale = clear_signing_policy(7);
    stale.verifier.verifier_digest = Digest32::from_bytes([0x5a; 32]);

    // Installing a policy pinning a verifier this build lacks is refused.
    let refused = harness.try_install_policy(2, Some(stale));
    assert!(
        refused
            .as_ref()
            .err()
            .is_some_and(|message| message.contains("absent from this build")),
        "installing an unknown verifier pin must be refused, got {refused:?}"
    );

    // A policy installed while its verifier was current stays installable
    // from the identical stored snapshot — the read path a client takes on
    // every call.
    harness.install_policy(3, Some(clear_signing_policy(7)));
    let snapshot = harness.sign_policy(3, &harness.current_policy());
    harness
        .authority
        .install_policy(&snapshot)
        .expect("re-presenting the stored snapshot must stay readable");
}
