use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use bloom_broker::{
    authority::{
        AssuranceRegistry, BrokerAuthority, CanonicalWalletPolicy, canonical_policy_authority_diff,
    },
    ceremony::{
        CEREMONY_ADDR, CeremonyBroker, CeremonyCompletionObserver, CeremonySigner,
        ReviewManifestContext,
    },
    journal::{AuditSigner, BrokerJournal},
    service::BrokerRpcService,
    signer_client::BrokerSignerClient,
};
use bloom_broker_debug_driver::{VirtualAuthenticator, seal_hpke};
use bloom_signer::{
    ceremony::SignerCeremonyService,
    engine::SignerEngine,
    hpke::{CUSTODY_OUTPUT_INFO, HpkeRecipient},
    registry::BackendRegistry,
    service::SignerRpcService,
};
use bloom_triad_local_transport::{EndpointQuota, LocalIdentity, PeerAcl};
use bloom_triad_protocol::*;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use sha2::Digest as _;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt as _;

#[derive(Clone)]
struct ServiceTestAuditSigner;

impl AuditSigner for ServiceTestAuditSigner {
    fn key_id(&self) -> Token {
        Token::new("broker-audit-key").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(&sha2::Sha256::digest(message)))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id == &self.key_id()
            && signature.decode() == sha2::Sha256::digest(message).as_slice()
        {
            Ok(())
        } else {
            Err("audit signature mismatch".into())
        }
    }
}

#[test]
fn browser_crypto_self_test_executes_the_shipped_asset() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let script = format!(
        r#"
globalThis.crypto = require("node:crypto").webcrypto;
globalThis.document = {{getElementById: () => ({{}})}};
globalThis.location = {{hash: "", search: "", pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
{executable}
cryptoSelfTest().then(
  () => process.stdout.write("browser-crypto-ok"),
  error => {{ console.error(error); process.exit(1); }}
);
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate the shipped ceremony asset");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "browser-crypto-ok");
}

fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

fn operation(byte: &str) -> OperationId {
    OperationId::new(byte.repeat(32)).unwrap()
}

fn approval_request() -> CeremonyPrepareRequest {
    let key_ref = KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("local-default").unwrap(),
        key_spec: KeySpec::Secp256k1,
        locator: "root-key".into(),
        derivation: None,
        public_key_fingerprint: digest("11"),
    };
    let terms = SealedApprovalTerms {
        subject: ApprovalSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet-sign").unwrap(),
        },
        wallet_id: Token::new("wallet-review").unwrap(),
        key_ref,
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
        selector: ApprovalSelector::Exact {
            ordered_payload_digests: vec![digest("12")],
            ordered_hashes: vec![digest("13")],
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: ActivationMode::BackendManaged,
        wallet_revocation_epoch: DecimalU64::new(1),
        policy_version: DecimalU64::new(1),
        policy_digest: digest("14"),
        provenance_digest: digest("15"),
        request_nonce: RequestNonce::new("16".repeat(16)).unwrap(),
        issued_at_ms: DecimalU64::new(1_000),
        not_before_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(u64::MAX - 1),
        renewal_of: None,
    };
    CeremonyPrepareRequest {
        activation_operation_id: operation("17"),
        terms,
        review_manifest_digest: digest("00"),
        exact_ordered_payload_digests: vec![digest("12")],
        exact_ordered_hashes: vec![digest("13")],
        replacement_approval_id: None,
    }
}

struct MockSigner {
    completions: AtomicUsize,
    cancellations: AtomicUsize,
    pending: parking_lot::Mutex<HashSet<OperationId>>,
}

struct RealSigner {
    service: Arc<SignerCeremonyService>,
}

struct FailOnceAdoptionObserver {
    authority: Arc<BrokerAuthority>,
    custody_attempts: AtomicUsize,
}

impl CeremonyCompletionObserver for FailOnceAdoptionObserver {
    fn approval_completed(
        &self,
        receipt: &SignerActivationReceipt,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.authority
            .activate_signer_receipt(receipt, now_ms)
            .map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, error.to_string())
            })
    }

    fn custody_completed(&self, receipt: &CustodyResult) -> Result<(), ProtocolError> {
        if self.custody_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "injected transient initial-policy storage failure",
            ));
        }
        self.authority
            .adopt_custody_receipt(receipt)
            .map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, error.to_string())
            })
    }
}

impl CeremonySigner for RealSigner {
    fn prepare_approval(
        &self,
        request: CeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedApproval, ProtocolError> {
        let wallet_id = request.terms.wallet_id.clone();
        let prepared = self.service.prepare_approval(request, now_ms)?;
        let verification_credentials = prepared
            .webauthn_options
            .allowed_credentials
            .iter()
            .map(|allowed| self.service.credential(&wallet_id, &allowed.credential_id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SignerPreparedApproval {
            contribution: prepared.contribution,
            challenges: prepared.challenges,
            webauthn_options: prepared.webauthn_options,
            verification_credentials,
        })
    }

    fn complete_approval(
        &self,
        request: CeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<SignerActivationReceipt, ProtocolError> {
        futures::executor::block_on(self.service.complete_approval(request, now_ms))
    }

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        let prepared = self.service.prepare_custody(request, now_ms)?;
        let verification_credentials = prepared
            .contribution
            .wallet_id
            .as_ref()
            .map(|wallet_id| {
                prepared
                    .webauthn_options
                    .allowed_credentials
                    .iter()
                    .map(|allowed| self.service.credential(wallet_id, &allowed.credential_id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(SignerPreparedCustody {
            contribution: prepared.contribution,
            challenges: prepared.challenges,
            webauthn_options: prepared.webauthn_options,
            verification_credentials,
        })
    }

    fn complete_custody(
        &self,
        request: CustodyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        self.service.complete_custody(request, now_ms)
    }

    fn cancel(&self, operation_id: &OperationId) -> Result<(), ProtocolError> {
        self.service.cancel(operation_id)
    }

    fn bind_custody_output_recipient(
        &self,
        operation_id: &OperationId,
        recipient_key: Base64UrlBytes,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        let prepared =
            self.service
                .bind_custody_output_recipient(operation_id, recipient_key, now_ms)?;
        let verification_credentials = prepared
            .contribution
            .wallet_id
            .as_ref()
            .map(|wallet_id| {
                prepared
                    .webauthn_options
                    .allowed_credentials
                    .iter()
                    .map(|allowed| self.service.credential(wallet_id, &allowed.credential_id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(SignerPreparedCustody {
            contribution: prepared.contribution,
            challenges: prepared.challenges,
            webauthn_options: prepared.webauthn_options,
            verification_credentials,
        })
    }

    fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        let prepared = self.service.prepare_policy_update(request, now_ms)?;
        let verification_credentials = prepared
            .contribution
            .wallet_id
            .as_ref()
            .map(|wallet_id| {
                prepared
                    .webauthn_options
                    .allowed_credentials
                    .iter()
                    .map(|allowed| self.service.credential(wallet_id, &allowed.credential_id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(SignerPreparedCustody {
            contribution: prepared.contribution,
            challenges: prepared.challenges,
            webauthn_options: prepared.webauthn_options,
            verification_credentials,
        })
    }

    fn complete_policy_update(
        &self,
        request: PolicyUpdateCeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        self.service.complete_policy_update(request, now_ms)
    }

    fn status(&self, operation_id: &OperationId) -> Result<SignerCeremonyStatus, ProtocolError> {
        Ok(match self.service.status(operation_id)? {
            bloom_signer::ceremony::SignerCeremonyStatus::Pending => SignerCeremonyStatus::Pending,
            bloom_signer::ceremony::SignerCeremonyStatus::CompletedApproval(receipt) => {
                SignerCeremonyStatus::CompletedApproval(receipt)
            }
            bloom_signer::ceremony::SignerCeremonyStatus::CompletedCustody(result) => {
                SignerCeremonyStatus::CompletedCustody(result)
            }
            bloom_signer::ceremony::SignerCeremonyStatus::Missing => SignerCeremonyStatus::Missing,
        })
    }
}

impl MockSigner {
    fn new() -> Self {
        Self {
            completions: AtomicUsize::new(0),
            cancellations: AtomicUsize::new(0),
            pending: parking_lot::Mutex::new(HashSet::new()),
        }
    }
}

impl CeremonySigner for MockSigner {
    fn prepare_approval(
        &self,
        request: CeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedApproval, ProtocolError> {
        self.pending
            .lock()
            .insert(request.activation_operation_id.clone());
        let mut contribution = SignerCeremonyContribution {
            ceremony_id: Digest32::from_bytes(
                sha2::Sha256::digest(request.activation_operation_id.to_bytes()).into(),
            ),
            signer_nonce: digest("21"),
            approval_digest: request.terms.approval_digest()?,
            review_manifest_digest: request.review_manifest_digest.clone(),
            key_ref: request.terms.key_ref.clone(),
            allowed_crypto_suites: request.terms.allowed_crypto_suites.clone(),
            activation_mode: request.terms.activation_mode.clone(),
            wallet_revocation_epoch: request.terms.wallet_revocation_epoch.clone(),
            required_user_verification: true,
            ephemeral_encryption_public_key: None,
            expires_at_ms: DecimalU64::new(now_ms + 10_000),
            signer_key_id: Token::new("mock-signer").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        contribution.signer_signature = Base64UrlBytes::from_bytes(&[8; 64]);
        let challenge = CeremonyChallenge {
            schema: Token::new("bloom.ceremony.challenge.v1").unwrap(),
            ceremony_id: contribution.ceremony_id.clone(),
            ceremony_kind: CeremonyKind::SealedApproval,
            operation_id: request.activation_operation_id,
            signer_nonce: contribution.signer_nonce.clone(),
            review_manifest_digest: request.review_manifest_digest,
            signer_contribution_digest: contribution.digest()?,
            exact_terms_digest: request.terms.approval_digest()?,
            phase: CeremonyPhase::Approve,
        };
        Ok(SignerPreparedApproval {
            contribution,
            challenges: vec![challenge],
            webauthn_options: CeremonyWebAuthnOptions {
                allowed_credentials: vec![],
                registration_user_handle: None,
                registration_prf_salt: None,
            },
            verification_credentials: Vec::new(),
        })
    }

    fn complete_approval(
        &self,
        _request: CeremonyCompleteRequest,
        _now_ms: u64,
    ) -> Result<SignerActivationReceipt, ProtocolError> {
        Err(ProtocolError::new(
            ProtocolErrorCode::BackendUnsupported,
            "mock exposes only the custody path used by this test",
        ))
    }

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        self.pending
            .lock()
            .insert(request.custody_operation_id.clone());
        let ceremony_id = Digest32::from_bytes(
            sha2::Sha256::digest(request.custody_operation_id.to_bytes()).into(),
        );
        let mut contribution = CustodySignerContribution {
            ceremony_id: ceremony_id.clone(),
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id.clone(),
            signer_nonce: digest("22"),
            review_manifest_digest: request.exact_terms_digest.clone(),
            wallet_id: request.wallet_id.clone(),
            key_ref: request.key_ref,
            expected_input_class: request.expected_input_class,
            required_user_verification: true,
            hpke_recipient_key: Base64UrlBytes::from_bytes(&[7; 32]),
            browser_output_recipient_key: request.browser_output_recipient_key,
            expires_at_ms: DecimalU64::new(now_ms + 10_000),
            signer_key_id: Token::new("mock-signer").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        // A signature is opaque to Broker. Non-empty bytes make accidental
        // dropping or reconstruction observable in the relay test.
        contribution.signer_signature = Base64UrlBytes::from_bytes(&[9; 64]);
        let challenge = CeremonyChallenge {
            schema: Token::new("bloom.ceremony.challenge.v1").unwrap(),
            ceremony_id,
            ceremony_kind: request.ceremony_kind,
            operation_id: request.custody_operation_id,
            signer_nonce: digest("22"),
            review_manifest_digest: request.exact_terms_digest.clone(),
            signer_contribution_digest: contribution.digest().unwrap(),
            exact_terms_digest: request.exact_terms_digest,
            phase: CeremonyPhase::Approve,
        };
        Ok(SignerPreparedCustody {
            contribution,
            challenges: vec![challenge],
            webauthn_options: CeremonyWebAuthnOptions {
                allowed_credentials: vec![],
                registration_user_handle: None,
                registration_prf_salt: None,
            },
            verification_credentials: Vec::new(),
        })
    }

    fn complete_custody(
        &self,
        request: CustodyCompleteRequest,
        _now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        self.completions.fetch_add(1, Ordering::SeqCst);
        Ok(CustodyResult {
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id,
            public_status: CeremonyState::Completed,
            wallet_id: None,
            public_key_refs: Vec::new(),
            credential_summaries: Vec::new(),
            initial_policy: None,
            receipt_digest: digest("44"),
            encrypted_browser_result: None,
            signer_key_id: Token::new("mock-signer-key").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[0; 64]),
        })
    }

    fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        let review_manifest_digest = request
            .broker_validation_receipt
            .review_manifest_digest
            .clone();
        let mut prepared = self.prepare_custody(request.custody, now_ms)?;
        prepared.contribution.review_manifest_digest = review_manifest_digest.clone();
        prepared.contribution.signer_signature = Base64UrlBytes::from_bytes(&[9; 64]);
        let contribution_digest = prepared.contribution.digest()?;
        for challenge in &mut prepared.challenges {
            challenge.review_manifest_digest = review_manifest_digest.clone();
            challenge.signer_contribution_digest = contribution_digest.clone();
        }
        Ok(prepared)
    }

    fn complete_policy_update(
        &self,
        request: PolicyUpdateCeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        self.complete_custody(request.custody, now_ms)
    }

    fn cancel(&self, operation_id: &OperationId) -> Result<(), ProtocolError> {
        self.pending.lock().remove(operation_id);
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn bind_custody_output_recipient(
        &self,
        _operation_id: &OperationId,
        _recipient_key: Base64UrlBytes,
        _now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        Err(ProtocolError::new(
            ProtocolErrorCode::BackendUnsupported,
            "mock does not expose output-key binding",
        ))
    }

    fn status(&self, operation_id: &OperationId) -> Result<SignerCeremonyStatus, ProtocolError> {
        Ok(if self.pending.lock().contains(operation_id) {
            SignerCeremonyStatus::Pending
        } else {
            SignerCeremonyStatus::Missing
        })
    }
}

#[test]
fn policy_validate_update_returns_the_standard_launch_projection_without_a_new_method() {
    let broker = CeremonyBroker::new(Arc::new(MockSigner::new()));
    let proposed = Base64UrlBytes::from_bytes(br#"{"wallet_id":"wallet-review"}"#);
    let update = PolicyUpdateRequest {
        operation_id: operation("c1"),
        wallet_id: Token::new("wallet-review").unwrap(),
        baseline_version: DecimalU64::new(1),
        baseline_digest: digest("c2"),
        proposed_policy_digest: Digest32::from_bytes(
            sha2::Sha256::digest(proposed.decode()).into(),
        ),
        proposed_canonical_policy: proposed,
        authority_diff_digest: digest("c3"),
        assurance_level: Token::new("user_verified").unwrap(),
    };
    let mut review = PolicyUpdateReviewManifest {
        schema: Token::new("bloom.policy-update-review/1").unwrap(),
        operation_id: update.operation_id.clone(),
        wallet_id: update.wallet_id.clone(),
        baseline_version: update.baseline_version.clone(),
        baseline_digest: update.baseline_digest.clone(),
        proposed_policy_digest: update.proposed_policy_digest.clone(),
        authority_diff_digest: update.authority_diff_digest.clone(),
        authority_diff: PolicyAuthorityDiff {
            maximum_approval_lifetime_ms_before: DecimalU64::new(100),
            maximum_approval_lifetime_ms_after: DecimalU64::new(200),
            added_petal_packages: vec![],
            removed_petal_packages: vec![],
            added_destinations: vec![],
            removed_destinations: vec![],
            added_required_verifiers: vec![],
            removed_required_verifiers: vec![],
        },
        assurance_level: update.assurance_level.clone(),
        issued_at_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(11_000),
        broker_key_id: Token::new("broker-app-1").unwrap(),
        broker_signature: Base64UrlBytes::from_bytes(&[1; 64]),
    };
    let review_digest = review.digest().unwrap();
    let request = PolicyUpdateCeremonyPrepareRequest {
        custody: CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::PolicyUpdate,
            custody_operation_id: update.operation_id.clone(),
            wallet_id: Some(update.wallet_id.clone()),
            key_ref: None,
            exact_terms_digest: update.terms_digest().unwrap(),
            expected_input_class: Token::new("policy_update_credential_prf").unwrap(),
            browser_output_recipient_key: None,
        },
        broker_validation_receipt: PolicyValidationReceipt {
            update_terms_digest: update.terms_digest().unwrap(),
            review_manifest_digest: review_digest.clone(),
            broker_key_id: Token::new("broker-app-1").unwrap(),
            broker_signature: Base64UrlBytes::from_bytes(&[2; 64]),
        },
        update,
    };
    let response = broker
        .prepare_policy_update(request.clone(), review.clone(), 1_000)
        .unwrap();
    assert_eq!(response.ceremony_kind, CeremonyKind::PolicyUpdate);
    assert_eq!(response.operation_id, request.update.operation_id);
    assert_eq!(response.review_manifest_digest, review_digest);
    assert!(response.ceremony_url.starts_with("http://localhost:18734/"));
    assert_eq!(
        broker
            .prepare_policy_update(request.clone(), review.clone(), 1_001)
            .unwrap()
            .ceremony_url,
        response.ceremony_url
    );
    assert_eq!(
        broker
            .prepare_custody(request.custody.clone(), 1_002)
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyKindMismatch
    );
    review.authority_diff_digest = digest("c4");
    assert_eq!(
        broker
            .prepare_policy_update(request, review, 1_003)
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyKindMismatch
    );
}

fn prepare(
    broker: &CeremonyBroker,
    operation_id: OperationId,
    wallet_id: Option<Token>,
    now_ms: u64,
) -> CustodyPrepareResponse {
    broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation_id,
                wallet_id,
                key_ref: None,
                exact_terms_digest: digest("33"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
            },
            now_ms,
        )
        .unwrap()
}

fn url_token(url: &str) -> String {
    url.strip_prefix("http://localhost:18734/ceremony/")
        .unwrap()
        .to_owned()
}

fn local_identity(service_id: &str, seed: [u8; 32], epoch: &str) -> LocalIdentity {
    LocalIdentity {
        service_id: Token::new(service_id).unwrap(),
        boot_epoch: BootEpoch::new(epoch.repeat(16)).unwrap(),
        application_key_id: Token::new(format!("{service_id}-app")).unwrap(),
        signing_key: Arc::new(SigningKey::from_bytes(&seed)),
    }
}

fn peer_acl(identity: &LocalIdentity, effective_uid: u32) -> PeerAcl {
    PeerAcl {
        effective_uid,
        service_id: identity.service_id.clone(),
        boot_epoch: identity.boot_epoch.clone(),
        application_key_id: identity.application_key_id.clone(),
        application_public_key: identity.signing_key.verifying_key().to_bytes(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_service_requires_completion_then_commits_and_replays_over_authenticated_rpc() {
    let authenticator = VirtualAuthenticator::generate();
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    let signer_engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            registry,
        )
        .unwrap(),
    );
    let signer_ceremony = Arc::new(
        SignerCeremonyService::new(
            signer_engine.clone(),
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("signer.sock");
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let effective_uid = fs::metadata(directory.path()).unwrap().uid();
    let broker_identity = local_identity("bloom-broker", [0x31; 32], "31");
    let signer_identity = local_identity("bloom-signer", [0x32; 32], "32");
    let signer_acl = peer_acl(&signer_identity, effective_uid);
    let broker_acl = peer_acl(&broker_identity, effective_uid);
    let signer_rpc = Arc::new(SignerRpcService::new(
        signer_engine.clone(),
        signer_ceremony.clone(),
        signer_identity.boot_epoch.clone(),
        digest("e2"),
        "test",
    ));
    let signer_server = tokio::spawn({
        let signer_identity = signer_identity.clone();
        async move {
            let quota = EndpointQuota::new(16, 1_000, 60_000, 1_000, 60_000).unwrap();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                bloom_triad_local_transport::dispatch_broker_signer_connection(
                    &mut stream,
                    &signer_identity,
                    &broker_acl,
                    &quota,
                    signer_rpc.as_ref(),
                )
                .await
                .unwrap();
            }
        }
    });
    let signer_client =
        BrokerSignerClient::connect_unix(&socket_path, broker_identity.clone(), signer_acl)
            .unwrap();

    let journal =
        Arc::new(BrokerJournal::open_in_memory(Arc::new(ServiceTestAuditSigner)).unwrap());
    let authority = Arc::new(
        BrokerAuthority::open_in_memory(
            journal.clone(),
            BTreeMap::new(),
            Token::new("installer-key").unwrap(),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            AssuranceRegistry::compiled(Vec::new()).unwrap(),
        )
        .unwrap(),
    );
    let ceremony = CeremonyBroker::open(
        directory.path().join("ceremony.sqlite"),
        Arc::new(signer_client.clone()),
    )
    .unwrap();
    let broker = BrokerRpcService::new(
        authority.clone(),
        journal,
        ceremony,
        signer_client.clone(),
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        broker_identity.boot_epoch,
        digest("e3"),
        "test",
    )
    .unwrap();
    let adoption_observer = Arc::new(FailOnceAdoptionObserver {
        authority: authority.clone(),
        custody_attempts: AtomicUsize::new(0),
    });
    broker
        .ceremony()
        .set_completion_observer(adoption_observer.clone(), now_ms)
        .unwrap();

    let registration_operation = operation("e1");
    let registration = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::WalletRegistrationPrepare(CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::WalletRegistration,
            custody_operation_id: registration_operation.clone(),
            wallet_id: None,
            key_ref: None,
            exact_terms_digest: digest("a1"),
            expected_input_class: Token::new("passkey-prf").unwrap(),
            browser_output_recipient_key: None,
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::WalletRegistrationPrepare(prepared) => prepared,
        response => panic!("unexpected response: {response:?}"),
    };
    let registration_token = url_token(&registration.ceremony_url);
    let registration_id = broker
        .ceremony()
        .public_status(&registration_operation)
        .unwrap()
        .ceremony_id
        .to_string();
    let registration_app = broker.ceremony().router();
    let session_response = registration_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &registration_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session: serde_json::Value = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let first_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let second_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][1]["binding"].clone()).unwrap();
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let attestation = authenticator.attestation(&first_challenge.canonical_bytes().unwrap());
    let assertion = authenticator.assertion(&second_challenge.canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: registration_operation,
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("passkey-prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_input = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let registration_request = || {
        Request::builder()
            .method("POST")
            .uri(format!("/api/session/{registration_id}/complete"))
            .header(header::HOST, "localhost:18734")
            .header(header::ORIGIN, "http://localhost:18734")
            .header("x-bloom-ceremony-token", &registration_token)
            .header(header::CONTENT_TYPE, "application/json")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "proof": {
                        "kind": "registration",
                        "attestation": attestation,
                        "prf_assertion": assertion
                    },
                    "encrypted_input": encrypted_input,
                    "public_binding_digest": digest("a1")
                }))
                .unwrap(),
            ))
            .unwrap()
    };
    let first_registration_response = registration_app
        .clone()
        .oneshot(registration_request())
        .await
        .unwrap();
    assert_eq!(
        first_registration_response.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        broker.ceremony().status(&operation("e1")),
        Some(CeremonyState::WalletCommitted)
    );
    assert_eq!(adoption_observer.custody_attempts.load(Ordering::SeqCst), 1);

    let restarted_ceremony = CeremonyBroker::open(
        directory.path().join("ceremony.sqlite"),
        Arc::new(signer_client),
    )
    .unwrap();
    restarted_ceremony
        .set_completion_observer(adoption_observer.clone(), now_ms)
        .unwrap();
    assert_eq!(
        restarted_ceremony.status(&operation("e1")),
        Some(CeremonyState::Completed)
    );
    assert_eq!(adoption_observer.custody_attempts.load(Ordering::SeqCst), 2);

    let registration_response = registration_app
        .oneshot(registration_request())
        .await
        .unwrap();
    assert_eq!(registration_response.status(), StatusCode::OK);
    assert_eq!(adoption_observer.custody_attempts.load(Ordering::SeqCst), 3);
    let registration_result: CustodyResult = serde_json::from_slice(
        &registration_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let wallet_id = registration_result.wallet_id.clone().unwrap();
    let baseline = registration_result.initial_policy.clone().unwrap();
    assert_eq!(authority.policy_snapshot(&wallet_id).unwrap(), baseline);

    let baseline_policy: CanonicalWalletPolicy =
        serde_json::from_slice(&baseline.canonical_policy.decode()).unwrap();
    let mut proposed_policy = baseline_policy.clone();
    proposed_policy.maximum_approval_lifetime_ms += 1;
    proposed_policy
        .allowed_destinations
        .push(PolicyDestination {
            chain: Token::new("ethereum").unwrap(),
            destination: "0xexpanded-authority".into(),
        });
    let proposed_bytes = serde_jcs::to_vec(&proposed_policy).unwrap();
    let authority_diff = canonical_policy_authority_diff(&baseline_policy, &proposed_policy);
    let update = PolicyUpdateRequest {
        operation_id: operation("e4"),
        wallet_id: wallet_id.clone(),
        baseline_version: baseline.version.clone(),
        baseline_digest: baseline.policy_digest.clone(),
        proposed_canonical_policy: Base64UrlBytes::from_bytes(&proposed_bytes),
        proposed_policy_digest: Digest32::from_bytes(sha2::Sha256::digest(&proposed_bytes).into()),
        authority_diff_digest: authority_diff.digest().unwrap(),
        assurance_level: Token::new("user_verified").unwrap(),
    };
    let prepared = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::PolicyValidateUpdate(update.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::PolicyValidateUpdate(prepared) => prepared,
        response => panic!("unexpected response: {response:?}"),
    };
    let premature = CustodyResult {
        ceremony_kind: CeremonyKind::PolicyUpdate,
        custody_operation_id: update.operation_id.clone(),
        public_status: CeremonyState::Succeeded,
        wallet_id: Some(wallet_id.clone()),
        public_key_refs: Vec::new(),
        credential_summaries: Vec::new(),
        initial_policy: None,
        receipt_digest: digest("e5"),
        encrypted_browser_result: None,
        signer_key_id: Token::new("signer-ceremony-key").unwrap(),
        signer_signature: Base64UrlBytes::from_bytes(&[0; 64]),
    };
    assert!(
        MachineBrokerService::dispatch(
            &broker,
            MachineBrokerRequest::PolicyCommitUpdate(PolicyCommitUpdateRequest {
                operation_id: update.operation_id.clone(),
                ceremony_receipt: premature,
            }),
        )
        .await
        .is_err()
    );

    let token = url_token(&prepared.ceremony_url);
    let session_response = broker
        .ceremony()
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session: serde_json::Value = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(
        session["review_manifest"]["authority_diff"],
        serde_json::to_value(&authority_diff).unwrap()
    );
    let challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let assertion = authenticator.assertion(&challenge.canonical_bytes().unwrap(), 2);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::PolicyUpdate,
        custody_operation_id: update.operation_id.clone(),
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: Some(wallet_id.clone()),
        key_ref: None,
        credential_id: Some(assertion.credential_id.clone()),
        expected_input_class: Token::new("policy_update_credential_prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let plaintext = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "effect": {"kind": "policy_update"},
    }))
    .unwrap();
    let encrypted_input = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &plaintext,
    )
    .unwrap();
    let completed = signer_ceremony
        .complete_policy_update(
            PolicyUpdateCeremonyCompleteRequest {
                custody: CustodyCompleteRequest {
                    ceremony_kind: CeremonyKind::PolicyUpdate,
                    custody_operation_id: update.operation_id.clone(),
                    ceremony_id: contribution.ceremony_id,
                    proof: WebAuthnCeremonyProof::Assertion { assertion },
                    encrypted_input: Some(encrypted_input),
                    public_binding_digest: update.terms_digest().unwrap(),
                },
            },
            now_ms + 1_000,
        )
        .unwrap();
    broker
        .ceremony()
        .expire_sessions(contribution.expires_at_ms.get() + 1)
        .unwrap();
    let commit_request = PolicyCommitUpdateRequest {
        operation_id: update.operation_id,
        ceremony_receipt: completed,
    };
    let committed = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::PolicyCommitUpdate(commit_request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::PolicyCommitUpdate(receipt) => receipt,
        response => panic!("unexpected response: {response:?}"),
    };
    let replay = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::PolicyCommitUpdate(commit_request),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::PolicyCommitUpdate(receipt) => receipt,
        response => panic!("unexpected response: {response:?}"),
    };
    assert_eq!(replay, committed);
    assert_eq!(committed.committed.version.get(), 2);
    assert_eq!(
        authority.policy_snapshot(&wallet_id).unwrap(),
        committed.committed
    );
    signer_server.abort();
}

#[test]
fn stable_url_single_live_wallet_and_cancellation_backoff_hold() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let first = prepare(
        &broker,
        operation("01"),
        Some(Token::new("wallet-1").unwrap()),
        1_000,
    );
    let retry = prepare(
        &broker,
        operation("01"),
        Some(Token::new("wallet-1").unwrap()),
        1_001,
    );
    assert_eq!(first, retry);
    let conflicting = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("01"),
                wallet_id: Some(Token::new("wallet-1").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("99"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
            },
            1_001,
        )
        .unwrap_err();
    assert_eq!(conflicting.code, ProtocolErrorCode::OperationIdConflict);
    assert_eq!(
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletDelete,
                    custody_operation_id: operation("02"),
                    wallet_id: Some(Token::new("wallet-1").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("33"),
                    expected_input_class: Token::new("policy-document").unwrap(),
                    browser_output_recipient_key: None,
                },
                1_001,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::QuotaExceeded
    );
    assert_eq!(
        broker.status(&operation("01")),
        Some(CeremonyState::AwaitingUser)
    );
    broker.cancel(&operation("01"), 1_100).unwrap();
    assert_eq!(
        broker.status(&operation("01")),
        Some(CeremonyState::Cancelled)
    );
    assert_eq!(
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletDelete,
                    custody_operation_id: operation("03"),
                    wallet_id: Some(Token::new("wallet-1").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("33"),
                    expected_input_class: Token::new("policy-document").unwrap(),
                    browser_output_recipient_key: None,
                },
                1_101,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyRateLimited
    );
}

#[tokio::test]
async fn broker_constructs_and_signs_the_review_plan_from_immutable_terms() {
    let signer = Arc::new(MockSigner::new());
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let broker = CeremonyBroker::new_with_manifest_signer(
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[31; 32]),
    );
    let response = broker
        .prepare_approval(
            approval_request(),
            ReviewManifestContext {
                attributed_advisory_items: vec![
                    "machine supplied descriptions are advisory".into(),
                ],
                ..ReviewManifestContext::default()
            },
            now_ms,
        )
        .unwrap();
    assert_ne!(response.review_manifest_digest, digest("00"));
    let token = url_token(&response.ceremony_url);
    let session = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let projection: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let manifest: ReviewManifest =
        serde_json::from_value(projection["review_manifest"].clone()).unwrap();
    assert!(manifest.canonical_plan.to_lowercase().contains("sha256"));
    assert!(manifest.canonical_plan.contains("max_operations"));
    assert!(manifest.canonical_plan.contains("root-key"));
    assert!(
        manifest
            .canonical_plan
            .contains("Bloom has not established the execution effects")
    );
    assert_eq!(manifest.broker_signature.decode().len(), 64);
    assert_eq!(
        Digest32::from_bytes(sha2::Sha256::digest(serde_jcs::to_vec(&manifest).unwrap()).into()),
        response.review_manifest_digest
    );
}

#[tokio::test]
async fn machine_asserted_reusable_plan_carries_primary_surface_warning() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new_with_manifest_signer(
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[31; 32]),
    );
    let mut request = approval_request();
    request.activation_operation_id = operation("18");
    request.terms.subject = ApprovalSubject::Petal {
        package_hash: digest("19"),
        route: "wallet/send".into(),
        agent_id: None,
    };
    request.terms.selector = ApprovalSelector::Petal {
        package_hash: digest("19"),
        route: "wallet/send".into(),
        allowed_operation_classes: vec![Token::new("transfer").unwrap()],
        required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
    };
    request.exact_ordered_payload_digests.clear();
    request.exact_ordered_hashes.clear();
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let response = broker
        .prepare_approval(
            request,
            ReviewManifestContext {
                claim_assurance: Some(ClaimAssurance::MachineAsserted),
                ..ReviewManifestContext::default()
            },
            now_ms,
        )
        .unwrap();
    let token = url_token(&response.ceremony_url);
    let session = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let projection: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let plan = projection["review_manifest"]["canonical_plan"]
        .as_str()
        .unwrap();
    assert!(plan.contains("limits are asserted by the named Petal"));
    assert!(plan.contains("compromised Petal or Machine"));
    assert!(plan.contains("full remaining capacity"));
}

#[tokio::test]
async fn assets_headers_host_origin_token_and_opaque_relay_are_enforced() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer.clone());
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let prepared = prepare(
        &broker,
        operation("11"),
        Some(Token::new("wallet-2").unwrap()),
        now_ms,
    );
    let ceremony_id = broker
        .public_status(&operation("11"))
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&prepared.ceremony_url);
    assert_eq!(token.len(), 43);
    assert!(!prepared.ceremony_url.contains(['?', '#']));
    let app = broker.router();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ceremony/{token}"))
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY)
    );

    let wrong_host = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::HOST, "127.0.0.1:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_host.status(), StatusCode::FORBIDDEN);

    let no_token = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{ceremony_id}"))
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_token.status(), StatusCode::FORBIDDEN);

    let session_by_launch_token = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_by_launch_token.status(), StatusCode::OK);

    let session = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{ceremony_id}"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    let session_json: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(session_json["ceremony_kind"], "wallet_delete");
    assert!(session_json["challenges"][0]["challenge"].is_string());

    let body = serde_json::json!({
        "proof": {
            "kind": "assertion",
            "assertion": {
                "credential_id": "Y3JlZGVudGlhbA",
                "authenticator_data": "YXV0aA",
                "client_data_json": "e30",
                "signature": "c2ln",
                "user_handle": null
            }
        },
        "encrypted_input": {
            "kem_output": "a2Vt",
            "ciphertext": "Y2lwaGVydGV4dA"
        },
        "public_binding_digest": digest("33")
    });
    let missing_origin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

    let completed = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(signer.completions.load(Ordering::SeqCst), 0);
    assert_eq!(signer.cancellations.load(Ordering::SeqCst), 1);
}

#[test]
fn prebound_canonical_listener_is_a_fatal_no_fallback_failure() {
    let listener = std::net::TcpListener::bind(CEREMONY_ADDR).unwrap();
    let error = CeremonyBroker::bind_canonical().unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);
    assert!(error.message.contains("18734"));
    drop(listener);
}

#[tokio::test]
async fn inherited_listener_handover_rejects_every_noncanonical_socket() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    assert_eq!(
        broker.serve_listener(listener).await.unwrap_err().code,
        ProtocolErrorCode::ServiceUnavailable
    );
}

#[test]
fn restart_expires_nonterminal_session_and_persists_only_token_hash() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ceremonies.sqlite");
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::open(&path, signer.clone()).unwrap();
    let prepared = prepare(
        &broker,
        operation("31"),
        Some(Token::new("wallet-restart").unwrap()),
        50_000,
    );
    let token = url_token(&prepared.ceremony_url);
    drop(broker);

    let bytes = std::fs::read(&path).unwrap();
    assert!(
        !bytes
            .windows(token.len())
            .any(|window| window == token.as_bytes()),
        "launch token plaintext must not be durable"
    );

    let restarted = CeremonyBroker::open(&path, signer.clone()).unwrap();
    assert_eq!(signer.cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(
        restarted.status(&operation("31")),
        Some(CeremonyState::Expired)
    );
    let error = restarted
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("31"),
                wallet_id: Some(Token::new("wallet-restart").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("33"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
            },
            50_001,
        )
        .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::CeremonyReplay);
}

#[test]
fn rolling_creation_limits_survive_terminal_sessions_and_bound_anonymous_registration() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let wallet = Token::new("wallet-rate-bound").unwrap();
    for index in 0..6_u8 {
        let now_ms = 1_000 + u64::from(index) * 70_000;
        let operation_id = operation(&format!("{index:02x}"));
        prepare(&broker, operation_id.clone(), Some(wallet.clone()), now_ms);
        broker.cancel(&operation_id, now_ms).unwrap();
    }
    let error = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("f1"),
                wallet_id: Some(wallet),
                key_ref: None,
                exact_terms_digest: digest("33"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
            },
            355_000,
        )
        .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::CeremonyRateLimited);

    for index in 0..4_u8 {
        let operation_id = operation(&format!("a{index}"));
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletRegistration,
                    custody_operation_id: operation_id.clone(),
                    wallet_id: None,
                    key_ref: None,
                    exact_terms_digest: digest("34"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                },
                500_000 + u64::from(index),
            )
            .unwrap();
        broker
            .cancel(&operation_id, 500_000 + u64::from(index))
            .unwrap();
    }
    assert_eq!(
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletRegistration,
                    custody_operation_id: operation("af"),
                    wallet_id: None,
                    key_ref: None,
                    exact_terms_digest: digest("34"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                },
                500_010,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyRateLimited
    );
}

#[test]
fn real_signer_generated_wallet_ids_still_count_as_anonymous_registration_attempts() {
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    let engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            registry,
        )
        .unwrap(),
    );
    let service = Arc::new(
        SignerCeremonyService::new(
            engine,
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    let broker = CeremonyBroker::new(Arc::new(RealSigner { service }));
    for index in 0..4_u8 {
        let operation_id = operation(&format!("d{index}"));
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletRegistration,
                    custody_operation_id: operation_id.clone(),
                    wallet_id: None,
                    key_ref: None,
                    exact_terms_digest: digest("d8"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                },
                100_000 + u64::from(index),
            )
            .unwrap();
        broker
            .cancel(&operation_id, 100_000 + u64::from(index))
            .unwrap();
    }
    assert_eq!(
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletRegistration,
                    custody_operation_id: operation("df"),
                    wallet_id: None,
                    key_ref: None,
                    exact_terms_digest: digest("d8"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                },
                100_010,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyRateLimited
    );
}

#[tokio::test]
async fn browser_to_broker_to_signer_registration_keeps_prf_ciphertext_opaque() {
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    let engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            registry,
        )
        .unwrap(),
    );
    let service = Arc::new(
        SignerCeremonyService::new(
            engine,
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    let broker = CeremonyBroker::new(Arc::new(RealSigner { service }));
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let operation_id = operation("41");
    let prepared = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletRegistration,
                custody_operation_id: operation_id.clone(),
                wallet_id: None,
                key_ref: None,
                exact_terms_digest: digest("51"),
                expected_input_class: Token::new("passkey-prf").unwrap(),
                browser_output_recipient_key: None,
            },
            now_ms,
        )
        .unwrap();
    let ceremony_id = broker
        .public_status(&operation_id)
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&prepared.ceremony_url);
    let app = broker.router();
    let session_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{ceremony_id}"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session: serde_json::Value = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let first_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let second_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][1]["binding"].clone()).unwrap();
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let authenticator = VirtualAuthenticator::generate();
    let attestation = authenticator.attestation(&first_challenge.canonical_bytes().unwrap());
    let assertion = authenticator.assertion(&second_challenge.canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation_id,
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("passkey-prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let prf = authenticator.deterministic_prf();
    let envelope = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &prf,
    )
    .unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "proof": {
            "kind": "registration",
            "attestation": attestation,
            "prf_assertion": assertion
        },
        "encrypted_input": envelope,
        "public_binding_digest": digest("51")
    }))
    .unwrap();
    assert!(
        !body
            .windows(prf.len())
            .any(|window| window == prf.as_slice()),
        "Broker request body must never contain plaintext PRF"
    );
    let completed = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);

    let export_operation = operation("42");
    let export = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletExport,
                custody_operation_id: export_operation.clone(),
                wallet_id: contribution.wallet_id.clone(),
                key_ref: None,
                exact_terms_digest: digest("52"),
                expected_input_class: Token::new("generic-custody-v1").unwrap(),
                browser_output_recipient_key: None,
            },
            now_ms + 1_000,
        )
        .unwrap();
    let export_id = broker
        .public_status(&export_operation)
        .unwrap()
        .ceremony_id
        .to_string();
    let export_token = url_token(&export.ceremony_url);
    let output_recipient = HpkeRecipient::generate();
    let export_app = broker.router();
    let bound = export_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{export_id}/output-key"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &export_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "recipient_key": output_recipient.public_key()
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bound.status(), StatusCode::OK);
    let projection: serde_json::Value =
        serde_json::from_slice(&bound.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let export_contribution: CustodySignerContribution =
        serde_json::from_value(projection["signer_contribution"].clone()).unwrap();
    assert_eq!(
        export_contribution.browser_output_recipient_key.as_ref(),
        Some(output_recipient.public_key())
    );
    let export_challenge: CeremonyChallenge =
        serde_json::from_value(projection["challenges"][0]["binding"].clone()).unwrap();
    let export_assertion = authenticator.assertion(&export_challenge.canonical_bytes().unwrap(), 2);
    let export_aad = CustodyHpkeAad {
        ceremony_id: export_contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletExport,
        custody_operation_id: export_operation.clone(),
        signer_nonce: export_contribution.signer_nonce.clone(),
        signer_contribution_digest: export_contribution.digest().unwrap(),
        wallet_id: export_contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(export_assertion.credential_id.clone()),
        expected_input_class: Token::new("generic-custody-v1").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let export_input = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&prf),
        "effect": {"kind": "wallet_export"}
    }))
    .unwrap();
    let export_envelope = seal_hpke(
        &export_contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &export_aad,
        &export_input,
    )
    .unwrap();
    let exported = export_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{export_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &export_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "proof": {
                            "kind": "assertion",
                            "assertion": export_assertion
                        },
                        "encrypted_input": export_envelope,
                        "public_binding_digest": digest("52")
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exported.status(), StatusCode::OK);
    let export_result: CustodyResult =
        serde_json::from_slice(&exported.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let recovered = export_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{export_id}/result"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &export_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered_result: CustodyResult =
        serde_json::from_slice(&recovered.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(recovered_result, export_result);
    let export_contribution_digest = export_contribution.digest().unwrap();
    let output_aad = CustodyOutputHpkeAad {
        ceremony_id: export_contribution.ceremony_id,
        ceremony_kind: CeremonyKind::WalletExport,
        custody_operation_id: export_operation,
        signer_contribution_digest: export_contribution_digest,
        public_binding_digest: digest("52"),
    }
    .canonical_bytes()
    .unwrap();
    let plaintext = output_recipient
        .open(
            export_result.encrypted_browser_result.as_ref().unwrap(),
            CUSTODY_OUTPUT_INFO,
            &output_aad,
        )
        .unwrap();
    let export_json: serde_json::Value =
        serde_json::from_slice(plaintext.expose_to_backend()).unwrap();
    assert_eq!(export_json["credentials"].as_array().unwrap().len(), 1);
    let acknowledged = export_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{export_id}/ack"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &export_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::NO_CONTENT);
    let replay_after_ack = export_app
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{export_id}/result"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", export_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_after_ack.status(), StatusCode::FORBIDDEN);
}
