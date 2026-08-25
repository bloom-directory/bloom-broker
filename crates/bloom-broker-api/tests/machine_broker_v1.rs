use bloom_broker_api::*;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::fmt::Debug;

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn operation(value: u8) -> OperationId {
    OperationId::from_bytes([value; 32])
}

fn key_ref() -> KeyRef {
    KeyRef {
        backend: token("local"),
        backend_instance: token("default"),
        locator: "key-1".into(),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: digest(1),
        derivation: None,
    }
}

fn approval_terms() -> SealedApprovalTerms {
    SealedApprovalTerms {
        subject: ApprovalSubject::Cli {
            client_id: token("cli"),
            command_class: token("wallet.sign"),
        },
        wallet_id: token("wallet"),
        key_ref: key_ref(),
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        selector: ApprovalSelector::Exact {
            ordered_payload_digests: vec![digest(2)],
            ordered_hashes: vec![digest(3)],
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: Vec::new(),
            signature_rate_limits: Vec::new(),
            value_limits: Vec::new(),
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(0),
        policy_version: DecimalU64::new(1),
        policy_digest: digest(4),
        provenance_digest: digest(5),
        request_nonce: RequestNonce::from_bytes([6; 16]),
        issued_at_ms: DecimalU64::new(10),
        not_before_ms: DecimalU64::new(10),
        expires_at_ms: DecimalU64::new(20),
        renewal_of: None,
    }
}

fn hello() -> HelloChallenge {
    HelloChallenge {
        service_id: token("bloom-machine"),
        boot_epoch: BootEpoch::from_bytes([7; 16]),
        protocol: BROKER_API_CURRENT,
        challenge: digest(8),
        application_key_id: token("app-key"),
        signature: Base64UrlBytes::from_bytes(&[9; 64]),
    }
}

fn readiness() -> Readiness {
    Readiness {
        service_id: token("bloom-broker"),
        service_version: "0.1.0".into(),
        build_digest: digest(10),
        boot_epoch: BootEpoch::from_bytes([11; 16]),
        state: ReadinessState::Ready,
        conditions: Vec::new(),
    }
}

fn capabilities() -> ServiceCapabilities {
    ServiceCapabilities {
        service_id: token("bloom-broker"),
        service_version: "0.1.0".into(),
        build_digest: digest(12),
        protocol_major: BROKER_API_MAJOR,
        protocol_minor_min: BROKER_API_MINOR_MIN,
        protocol_minor_max: BROKER_API_MINOR_MAX,
        methods: vec![token("system.hello")],
        schemas: vec![token("bloom.rpc-envelope.1")],
        backends: vec![BackendPublicCapability {
            backend_id: token("local"),
            backend_instance_id: token("default"),
            crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            derivation_schemes: vec![token("bip32")],
            networked: false,
        }],
        assurance_verifiers: vec![VerifierPublicCapability {
            verifier_id: token("webauthn"),
            verifier_digest: digest(13),
        }],
        frame_max_bytes: DecimalU64::new(FRAME_MAX_BYTES as u64),
    }
}

fn custody_prepare() -> CustodyPrepareRequest {
    CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(14),
        wallet_id: Some(token("wallet")),
        key_ref: Some(key_ref()),
        exact_terms_digest: digest(15),
        expected_input_class: token("none"),
        browser_output_recipient_key: None,
        petal_key_scope: None,
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_request: None,
        account_terms: None,
    }
}

fn policy_snapshot() -> SignedPolicySnapshot {
    SignedPolicySnapshot {
        wallet_id: token("wallet"),
        version: DecimalU64::new(1),
        canonical_policy: Base64UrlBytes::from_bytes(b"{}"),
        policy_digest: digest(16),
        policy_signing_key_id: token("policy-key"),
        policy_verifying_key: Base64UrlBytes::from_bytes(&[17; 32]),
        signer_signature: Base64UrlBytes::from_bytes(&[18; 64]),
    }
}

fn custody_result() -> CustodyResult {
    CustodyResult {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(14),
        public_status: CeremonyState::Completed,
        wallet_id: Some(token("wallet")),
        public_key_refs: vec![key_ref()],
        credential_summaries: vec![CredentialSummary {
            credential_id: Base64UrlBytes::from_bytes(&[19]),
            rp_id: token("localhost"),
            active: true,
        }],
        initial_policy: Some(policy_snapshot()),
        receipt_digest: digest(20),
        encrypted_browser_result: None,
        signer_key_id: token("signer-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[21; 64]),
    }
}

fn policy_update() -> PolicyUpdateRequest {
    PolicyUpdateRequest {
        operation_id: operation(22),
        wallet_id: token("wallet"),
        baseline_version: DecimalU64::new(1),
        baseline_digest: digest(23),
        proposed_canonical_policy: Base64UrlBytes::from_bytes(b"{}"),
        proposed_policy_digest: digest(24),
        authority_diff_digest: digest(25),
        assurance_level: token("hardened"),
    }
}

fn policy_commit_receipt() -> PolicyCommitReceipt {
    PolicyCommitReceipt {
        operation_id: operation(22),
        wallet_id: token("wallet"),
        previous_version: DecimalU64::new(1),
        committed: policy_snapshot(),
        authority_diff_digest: digest(25),
        signer_key_id: token("signer-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[29; 64]),
    }
}

fn signing_result() -> SigningResult {
    SigningResult {
        operation_id: operation(30),
        operation_digest: digest(31),
        signatures: vec![NormalizedSignature {
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            bytes: Base64UrlBytes::from_bytes(&[32; 65]),
        }],
        signer_receipt_digest: digest(33),
        broker_receipt_digest: digest(34),
    }
}

fn machine_sign() -> MachineSignRequest {
    MachineSignRequest {
        operation_id: operation(30),
        operation_digest: digest(31),
        approval_id: digest(35),
        key_ref: key_ref(),
        crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
        payloads: SigningPayloads::Single {
            payload: Base64UrlBytes::from_bytes(&[36]),
        },
        petal_use_claim: None,
        system_use_claim: None,
        claim_assurance_evidence: None,
        provenance: ProvenanceSubject::Cli {
            client_id: token("cli"),
            command_class: token("wallet.sign"),
        },
    }
}
fn approval_status() -> ApprovalPublicStatus {
    ApprovalPublicStatus {
        approval_id: digest(35),
        wallet_id: token("wallet"),
        state: ApprovalLifecycleState::Active,
        effective_claim_assurance: Some(ClaimAssuranceLevel::MachineAsserted),
        ceremony_url: None,
        ceremony_expires_at_ms: None,
    }
}

fn revocation_state() -> RevocationState {
    RevocationState {
        wallet_id: token("wallet"),
        wallet_revocation_epoch: DecimalU64::new(1),
        wallet_tombstone: None,
        approval_tombstone_digest: digest(44),
        approval_tombstone_count: DecimalU64::new(0),
        observed_at_ms: DecimalU64::new(10),
        issuer_service_id: token("bloom-signer"),
        key_id: token("signer-key"),
        signature: Base64UrlBytes::from_bytes(&[45; 64]),
    }
}

fn ceremony_status() -> CeremonyPublicStatus {
    CeremonyPublicStatus {
        ceremony_id: digest(46),
        ceremony_kind: CeremonyKind::WalletRegistration,
        operation_id: operation(14),
        state: CeremonyState::AwaitingUser,
        expires_at_ms: DecimalU64::new(20),
        ceremony_url: Some("http://localhost:18734/ceremony/token".into()),
        receipt_digest: None,
    }
}
fn machine_requests() -> Vec<MachineBrokerRequest> {
    let id = IdRequest { id: digest(35) };
    let wallet = WalletRequest {
        wallet_id: token("wallet"),
    };
    let operation_request = OperationRequest {
        operation_id: operation(30),
    };
    vec![
        MachineBrokerRequest::SystemHello(hello()),
        MachineBrokerRequest::BrokerReadiness(Empty {}),
        MachineBrokerRequest::BrokerCapabilities(Empty {}),
        MachineBrokerRequest::ActionValidate(digest(58)),
        MachineBrokerRequest::SealedApprovalPrepare(ApprovalPrepareRequest {
            operation_id: operation(54),
            terms: approval_terms(),
            canonical_plan_facts_digest: digest(59),
            petal_use_claim: None,
            system_use_claim: None,
        }),
        MachineBrokerRequest::SealedApprovalStatus(id.clone()),
        MachineBrokerRequest::SealedApprovalList(wallet.clone()),
        MachineBrokerRequest::SealedApprovalLimitState(id.clone()),
        MachineBrokerRequest::SealedApprovalRevoke(RevokeRequest {
            operation_id: operation(60),
            approval_id: digest(35),
            wallet_id: token("wallet"),
            reason: "reviewed".into(),
        }),
        MachineBrokerRequest::SealedApprovalRevokeAll(WalletOperationRequest {
            operation_id: operation(61),
            wallet_id: token("wallet"),
        }),
        MachineBrokerRequest::SealedApprovalRenew(ApprovalRenewRequest {
            operation_id: operation(62),
            old_approval_id: digest(35),
            replacement_terms: approval_terms(),
        }),
        MachineBrokerRequest::SigningSign(machine_sign()),
        MachineBrokerRequest::SigningSignBatch(machine_sign()),
        MachineBrokerRequest::OperationStatus(operation_request.clone()),
        MachineBrokerRequest::OperationCancel(operation_request.clone()),
        MachineBrokerRequest::PolicyRead(wallet.clone()),
        MachineBrokerRequest::PolicyValidateUpdate(policy_update()),
        MachineBrokerRequest::PolicyCommitUpdate(PolicyCommitUpdateRequest {
            operation_id: operation(22),
            ceremony_receipt: custody_result(),
        }),
        MachineBrokerRequest::WalletListPublic(Empty {}),
        MachineBrokerRequest::WalletGetPublic(wallet.clone()),
        MachineBrokerRequest::WalletRegistrationPrepare(custody_prepare()),
        MachineBrokerRequest::WalletUnlockPrepare(custody_prepare()),
        MachineBrokerRequest::WalletImportPrepare(custody_prepare()),
        MachineBrokerRequest::WalletExportPrepare(custody_prepare()),
        MachineBrokerRequest::WalletDeletePrepare(custody_prepare()),
        MachineBrokerRequest::WalletAccounts(wallet.clone()),
        MachineBrokerRequest::KeyListPublic(wallet.clone()),
        MachineBrokerRequest::KeyGetPublic(KeyRequest { key_ref: key_ref() }),
        MachineBrokerRequest::KeyDerivationCapabilities(KeyRequest { key_ref: key_ref() }),
        MachineBrokerRequest::KeyDerivePrepare(custody_prepare()),
        MachineBrokerRequest::KeyListDerived(KeyRequest { key_ref: key_ref() }),
        MachineBrokerRequest::KeyEnrollPrepare(custody_prepare()),
        MachineBrokerRequest::AccountAllocatePrepare(account_allocate_prepare()),
        MachineBrokerRequest::AccountRetirePrepare(account_retire_prepare()),
        MachineBrokerRequest::CredentialListPublic(wallet),
        MachineBrokerRequest::CredentialAddPrepare(custody_prepare()),
        MachineBrokerRequest::CredentialReplacePrepare(custody_prepare()),
        MachineBrokerRequest::CredentialRemovePrepare(custody_prepare()),
        MachineBrokerRequest::RecoveryPrepare(custody_prepare()),
        MachineBrokerRequest::CeremonyStatus(id.clone()),
        MachineBrokerRequest::CeremonyCancel(id),
        MachineBrokerRequest::CustodyResult(operation_request),
    ]
}

fn wallet_public() -> WalletPublic {
    WalletPublic {
        wallet_id: token("wallet"),
        wallet_kind: token("local"),
        root_key_ref: Some(key_ref()),
        key_refs: vec![key_ref()],
        policy_version: DecimalU64::new(1),
        policy_digest: digest(16),
        wallet_revocation_epoch: DecimalU64::new(0),
    }
}

fn key_public() -> KeyPublic {
    KeyPublic {
        key_ref: key_ref(),
        role: KeyRole::WalletRoot,
        canonical_public_key: Base64UrlBytes::from_bytes(&[63; 33]),
        addresses: vec!["0x1".into()],
        supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
    }
}

fn credential_public() -> CredentialPublic {
    CredentialPublic {
        credential_id: Base64UrlBytes::from_bytes(&[64]),
        wallet_id: token("wallet"),
        created_at_ms: DecimalU64::new(10),
        state: CredentialState::Active,
    }
}

fn account_allocate_terms() -> AccountTerms {
    AccountTerms {
        schema: token("bloom.account_terms.v1"),
        wallet_id: token("wallet"),
        seed_profile: WalletSeedProfile::Bip39MulticurveV1,
        derivation: Some(DerivedAccountRequest {
            derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
            requested_role: token("primary-evm"),
            account: Some(0),
        }),
        retire_key_fingerprint: None,
        path_template: DerivationProfile::Bip44EvmSecp256k1V1
            .path_template()
            .to_owned(),
        key_spec: KeySpec::Secp256k1,
        allowed_crypto_suites: DerivationProfile::Bip44EvmSecp256k1V1
            .frozen_crypto_suites()
            .to_vec(),
        policy_version: DecimalU64::new(1),
        revocation_epoch: DecimalU64::new(1),
        replay_id: operation(70),
        expires_at_ms: DecimalU64::new(120),
        audit_purpose: token("allocate-derived-account"),
    }
}

fn account_allocate_prepare() -> CustodyPrepareRequest {
    let terms = account_allocate_terms();
    CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::AccountAllocate,
        custody_operation_id: operation(70),
        wallet_id: Some(token("wallet")),
        key_ref: None,
        exact_terms_digest: terms.request_digest().unwrap(),
        expected_input_class: token("generic-custody-v1"),
        browser_output_recipient_key: None,
        petal_key_scope: None,
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_request: terms.derivation.clone(),
        account_terms: Some(terms),
    }
}

fn account_retire_prepare() -> CustodyPrepareRequest {
    let mut terms = account_allocate_terms();
    terms.derivation = None;
    terms.retire_key_fingerprint = Some(digest(74));
    CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::AccountRetire,
        custody_operation_id: operation(72),
        wallet_id: Some(token("wallet")),
        key_ref: Some(key_ref()),
        exact_terms_digest: terms.request_digest().unwrap(),
        expected_input_class: token("generic-custody-v1"),
        browser_output_recipient_key: None,
        petal_key_scope: None,
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_request: None,
        account_terms: Some(terms),
    }
}

fn wallet_accounts() -> WalletAccountsPublic {
    WalletAccountsPublic {
        wallet_id: token("wallet"),
        seed_profile: WalletSeedProfile::Bip39MulticurveV1,
        accounts: vec![],
    }
}

fn machine_responses() -> Vec<MachineBrokerResponse> {
    let operation_status = OperationPublicStatus {
        operation_id: operation(30),
        operation_digest: digest(31),
        state: OperationState::Succeeded,
        result: Some(signing_result()),
        error: None,
    };
    let custody_prepared = CustodyPrepareResponse {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(14),
        state: CustodyPrepareState::AwaitingUser,
        ceremony_url: "http://localhost:18734/ceremony/token".into(),
        ceremony_expires_at_ms: DecimalU64::new(20),
        signer_contribution_digest: digest(55),
    };
    vec![
        MachineBrokerResponse::SystemHello(hello()),
        MachineBrokerResponse::BrokerReadiness(readiness()),
        MachineBrokerResponse::BrokerCapabilities(capabilities()),
        MachineBrokerResponse::ActionValidate(digest(58)),
        MachineBrokerResponse::SealedApprovalPrepare(SealedApprovalPrepareResponse {
            approval_id: digest(35),
            state: ApprovalPrepareState::AwaitingCeremony,
            ceremony_url: "http://localhost:18734/ceremony/token".into(),
            ceremony_expires_at_ms: DecimalU64::new(20),
            review_manifest_digest: digest(27),
        }),
        MachineBrokerResponse::SealedApprovalStatus(approval_status()),
        MachineBrokerResponse::SealedApprovalList(vec![approval_status()]),
        MachineBrokerResponse::SealedApprovalLimitState(ApprovalLimitState {
            approval_id: digest(35),
            committed_operations: DecimalU64::new(0),
            reserved_operations: DecimalU64::new(0),
            quarantined_operations: DecimalU64::new(0),
            committed_signatures: DecimalU64::new(0),
            reserved_signatures: DecimalU64::new(0),
            quarantined_signatures: DecimalU64::new(0),
        }),
        MachineBrokerResponse::SealedApprovalRevoke(approval_status()),
        MachineBrokerResponse::SealedApprovalRevokeAll(revocation_state()),
        MachineBrokerResponse::SealedApprovalRenew(SealedApprovalPrepareResponse {
            approval_id: digest(35),
            state: ApprovalPrepareState::AwaitingCeremony,
            ceremony_url: "http://localhost:18734/ceremony/token".into(),
            ceremony_expires_at_ms: DecimalU64::new(20),
            review_manifest_digest: digest(27),
        }),
        MachineBrokerResponse::SigningSign(signing_result()),
        MachineBrokerResponse::SigningSignBatch(signing_result()),
        MachineBrokerResponse::OperationStatus(operation_status.clone()),
        MachineBrokerResponse::OperationCancel(operation_status),
        MachineBrokerResponse::PolicyRead(policy_snapshot()),
        MachineBrokerResponse::PolicyValidateUpdate(PolicyUpdatePrepareResponse {
            operation_id: operation(22),
            ceremony_kind: CeremonyKind::PolicyUpdate,
            ceremony_url: "http://localhost:18734/ceremony/token".into(),
            ceremony_expires_at_ms: DecimalU64::new(20),
            review_manifest_digest: digest(27),
        }),
        MachineBrokerResponse::PolicyCommitUpdate(policy_commit_receipt()),
        MachineBrokerResponse::WalletListPublic(vec![wallet_public()]),
        MachineBrokerResponse::WalletGetPublic(wallet_public()),
        MachineBrokerResponse::WalletRegistrationPrepare(custody_prepared.clone()),
        MachineBrokerResponse::WalletUnlockPrepare(custody_prepared.clone()),
        MachineBrokerResponse::WalletImportPrepare(custody_prepared.clone()),
        MachineBrokerResponse::WalletExportPrepare(custody_prepared.clone()),
        MachineBrokerResponse::WalletDeletePrepare(custody_prepared.clone()),
        MachineBrokerResponse::WalletAccounts(wallet_accounts()),
        MachineBrokerResponse::KeyListPublic(vec![key_public()]),
        MachineBrokerResponse::KeyGetPublic(key_public()),
        MachineBrokerResponse::KeyDerivationCapabilities(vec![token("bip32")]),
        MachineBrokerResponse::KeyListDerived(vec![key_public()]),
        MachineBrokerResponse::KeyDerivePrepare(custody_prepared.clone()),
        MachineBrokerResponse::KeyEnrollPrepare(custody_prepared.clone()),
        MachineBrokerResponse::AccountAllocatePrepare(custody_prepared.clone()),
        MachineBrokerResponse::AccountRetirePrepare(custody_prepared.clone()),
        MachineBrokerResponse::CredentialListPublic(vec![credential_public()]),
        MachineBrokerResponse::CredentialAddPrepare(custody_prepared.clone()),
        MachineBrokerResponse::CredentialReplacePrepare(custody_prepared.clone()),
        MachineBrokerResponse::CredentialRemovePrepare(custody_prepared.clone()),
        MachineBrokerResponse::RecoveryPrepare(custody_prepared),
        MachineBrokerResponse::CeremonyStatus(ceremony_status()),
        MachineBrokerResponse::CeremonyCancel(ceremony_status()),
        MachineBrokerResponse::CustodyResult(custody_result()),
    ]
}

fn assert_wire_digest<T>(name: &str, values: Vec<T>, expected: &str)
where
    T: Clone + Debug + DeserializeOwned + Eq + Serialize,
{
    let mut aggregate = Sha256::new();
    for value in values {
        let frame = encode_frame(&value).unwrap();
        assert_eq!(decode_frame::<T>(&frame).unwrap(), value, "{name}");
        aggregate.update(frame);
    }
    assert_eq!(hex::encode(aggregate.finalize()), expected, "{name}");
}

#[test]
fn every_machine_broker_variant_matches_frozen_v1_frames() {
    assert_eq!(MachineBrokerMethod::ALL.len(), 42);
    assert_wire_digest(
        "machine requests",
        machine_requests(),
        "bcb648dce4e11c5f38bc8555fd325299a2bdeb0f256345696ecb76b6c9d15030",
    );
    assert_wire_digest(
        "machine responses",
        machine_responses(),
        "2386da024a2fdfcf6b8bf57d4e4e52f938ef04b1e26d3ec9b43328e6eede8cb1",
    );
}

#[test]
fn fake_machine_peer_is_compatible_and_unknown_fields_fail_closed() {
    fn framed(json: &[u8]) -> Vec<u8> {
        let mut frame = (json.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(json);
        frame
    }
    let json = br#"{"body":{"wallet_id":"wallet"},"method":"wallet.get_public"}"#;
    let frame = framed(json);
    let request: MachineBrokerRequest = decode_frame(&frame).unwrap();
    assert_eq!(
        request,
        MachineBrokerRequest::WalletGetPublic(WalletRequest {
            wallet_id: token("wallet")
        })
    );
    assert_eq!(encode_frame(&request).unwrap(), frame);
    assert!(
        decode_frame::<MachineBrokerRequest>(&framed(
            br#"{"body":{"extra":true,"wallet_id":"wallet"},"method":"wallet.get_public"}"#
        ))
        .is_err()
    );
    assert!(MachineBrokerMethod::parse("signer.sign").is_err());
}

#[test]
fn capabilities_advertise_only_the_broker_owned_api_range() {
    let advertised = capabilities();
    assert_eq!(advertised.protocol_major, BROKER_API_RANGE.major);
    assert_eq!(advertised.protocol_minor_min, BROKER_API_RANGE.minor_min);
    assert_eq!(advertised.protocol_minor_max, BROKER_API_RANGE.minor_max);
    assert_eq!(advertised.protocol_major, BROKER_API_CURRENT.major);
    assert_eq!(advertised.protocol_minor_max, BROKER_API_CURRENT.minor);
}
