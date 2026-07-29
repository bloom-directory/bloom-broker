use bloom_broker::{
    authority::{
        AssuranceRegistry, AssuranceVerifier, AuthorizationInput, BrokerAuthority,
        CanonicalWalletPolicy, CeremonyApprovalGrant, EpochReconciliation, PolicyAsset,
        PolicyDestination, ProvenanceOperationClass, ProvenanceRecord, ProvenanceSubject,
        VerifierCapability, canonical_policy_authority_diff,
    },
    journal::{AuditSigner, BrokerJournal},
};
use bloom_triad_protocol::{
    ActivationMode, ApprovalLimits, ApprovalSelector, ApprovalSubject, ApprovalTombstone, AssetId,
    Base64UrlBytes, CeremonyKind, CeremonyState, ClaimAssurance, ClaimAssuranceLevel, CryptoSuite,
    CustodyResult, DecimalU64, DecimalU256, DeclaredDebit, DeclaredDestination, DeclaredFee,
    Digest32, KeyRef, KeySpec, MachineSignRequest, OperationId, PetalUseClaim, PolicyUpdateRequest,
    RequestNonce, RevocationState, SealedApprovalTerms, SignOperationIdentity,
    SignedPolicySnapshot, SigningPayloads, Token, ValueLimit,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier, mpsc},
    time::Duration,
};

const POLICY_DOMAIN: &[u8] = b"bloom-policy-snapshot/v1";
const PROVENANCE_DOMAIN: &[u8] = b"bloom-provenance-record/v1";
const CEREMONY_DOMAIN: &[u8] = b"bloom-broker-ceremony-grant/v1";
const REVOCATION_DOMAIN: &[u8] = b"bloom-revocation-state/v1";
const APPROVAL_TOMBSTONE_DOMAIN: &[u8] = b"bloom-approval-tombstone/v1";
const SIGNER_RECEIPT_DOMAIN: &[u8] = b"bloom-signer-ceremony-receipt/v1";

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
            journal,
            policy_keys,
            token("installer-key"),
            installer_key.verifying_key(),
            token("ceremony-key"),
            ceremony_key.verifying_key(),
            token("revocation-key"),
            revocation_key.verifying_key(),
            AssuranceRegistry::compiled(verifiers).unwrap(),
        )
        .unwrap();
        let harness = Self {
            authority,
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
    assert!(harness.authority.adopt_custody_receipt(&tampered).is_err());
    assert!(harness.authority.policy_snapshot(&wallet).is_err());

    let mut wrong_kind = receipt.clone();
    wrong_kind.ceremony_kind = CeremonyKind::CredentialAdd;
    sign_custody_receipt(&mut wrong_kind, &harness.ceremony_key);
    assert!(
        harness
            .authority
            .adopt_custody_receipt(&wrong_kind)
            .is_err()
    );
    assert!(harness.authority.policy_snapshot(&wallet).is_err());

    harness.authority.adopt_custody_receipt(&receipt).unwrap();
    assert_eq!(
        harness.authority.policy_snapshot(&wallet).unwrap(),
        accepted_snapshot
    );
    harness.authority.adopt_custody_receipt(&receipt).unwrap();
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
            allowed_operation_classes: vec![token("transfer"), token("authenticate")],
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
    let payload_digest = Digest32::from_bytes(Sha256::digest(payload).into());
    let ordered_hash = match suite {
        CryptoSuite::Secp256k1Keccak256Recoverable => {
            use sha3::Keccak256;
            Digest32::from_bytes(Keccak256::digest(payload).into())
        }
        _ => payload_digest.clone(),
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
    input.request.operation_digest = SignOperationIdentity {
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
    .digest()
    .unwrap();
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
