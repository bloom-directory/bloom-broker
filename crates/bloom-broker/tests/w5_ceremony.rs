use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use bloom_broker::{
    ceremony::{
        CEREMONY_ADDR, CEREMONY_OWNER_HEADER, CEREMONY_OWNER_VALUE, CeremonyBroker, CeremonySigner,
        ReviewManifestContext,
    },
    journal::{AuditSigner, BrokerJournal},
};
use bloom_broker_api::{
    Base64UrlBytes, CeremonyState, ClaimAssurance, CustodyPrepareResponse, DecimalU64, Digest32,
    OperationId, ProtocolErrorCode, RequestNonce, Token,
};
use bloom_broker_debug_driver::{VirtualAuthenticator, seal_hpke};
use bloom_signer::{
    ceremony::SignerCeremonyService,
    engine::{SignerAuditKeys, SignerEngine},
    hpke::{CUSTODY_OUTPUT_INFO, HpkeRecipient},
    registry::BackendRegistry,
};
use bloom_signer_api::{
    CeremonyChallenge, CeremonyCompleteRequest, CeremonyKind, CeremonyPhase,
    CeremonyPrepareRequest, CeremonyWebAuthnOptions, CustodyCompleteRequest, CustodyHpkeAad,
    CustodyOutputHpkeAad, CustodyPrepareRequest, CustodyResult, CustodySignerContribution,
    LegacyPasskeyMigrationPublic, PolicyUpdateCeremonyCompleteRequest,
    PolicyUpdateCeremonyPrepareRequest, SignerActivationReceipt, SignerCeremonyContribution,
    SignerCeremonyStatus, SignerPreparedApproval, SignerPreparedCustody, WalletSeedProfile,
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use sha2::Digest as _;
use std::collections::{BTreeMap, HashSet};
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
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

struct SwitchableAuditSigner(Arc<AtomicBool>);

impl AuditSigner for SwitchableAuditSigner {
    fn key_id(&self) -> Token {
        Token::new("broker-audit-key").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        if self.0.load(Ordering::SeqCst) {
            Err("forced ceremony audit failure".into())
        } else {
            Ok(Base64UrlBytes::from_bytes(&sha2::Sha256::digest(message)))
        }
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

#[test]
fn browser_ceremony_state_survives_reload_and_reuses_one_output_key() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    for required in [
        "tokenFromPath || readSessionToken()",
        "writeSessionToken(tokenFromPath)",
        "bloom-ceremony-browser-state-v1",
        "database.transaction(browserStateStore, \"readwrite\")",
        "store.get(session.ceremony_id)",
        "{name: \"X25519\"}, false, [\"deriveBits\"]",
        "await purgeExpiredBrowserState()",
        "await clearBrowserState(ceremonyId)",
    ] {
        assert!(
            asset.contains(required),
            "browser state flow omitted {required}"
        );
    }
    let persisted_key_flow = asset
        .split_once("async function outputRecipientFor(session)")
        .expect("asset must define persisted browser output-key state")
        .1
        .split_once("async function clearBrowserState(id)")
        .expect("asset must bound persisted browser output-key state")
        .0;
    assert!(
        !persisted_key_flow.contains("{name: \"X25519\"}, true, [\"deriveBits\"]"),
        "the persisted browser private key must be non-extractable"
    );
}

#[test]
fn browser_reload_recovers_the_ceremony_token_from_tab_storage() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let encoded_token = serde_json::to_value(Base64UrlBytes::from_bytes(&[31; 32])).unwrap();
    let token = encoded_token.as_str().unwrap();
    let script = format!(
        r#"
globalThis.crypto = require("node:crypto").webcrypto;
globalThis.document = {{getElementById: () => ({{}})}};
globalThis.location = {{pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
const stored = new Map([["bloom.ceremony.token.v1", {token:?}]]);
globalThis.sessionStorage = {{
  getItem: key => stored.get(key) || null,
  setItem: (key, value) => stored.set(key, value),
  removeItem: key => stored.delete(key)
}};
{executable}
if (token !== {token:?} || authHeaders["x-bloom-ceremony-token"] !== {token:?}) {{
  throw new Error("reload did not recover the ceremony token");
}}
process.stdout.write("browser-reload-ok");
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate ceremony reload state");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "browser-reload-ok");
}

#[test]
fn browser_approval_failure_is_logged_displayed_and_retryable() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let script = format!(
        r#"
globalThis.crypto = require("node:crypto").webcrypto;
const elements = new Map();
globalThis.document = {{getElementById: id => {{
  if (!elements.has(id)) elements.set(id, {{disabled: true}});
  return elements.get(id);
}}}};
globalThis.location = {{pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
const logged = [];
globalThis.console = {{error: (...args) => logged.push(args)}};
{executable}
const failure = new Error("Signer rejected completion");
reportApprovalFailure(failure);
if (statusNode.textContent !== "Passkey verification failed. Please try again.") {{
  throw new Error(`failure was not displayed: ${{statusNode.textContent}}`);
}}
if (approve.disabled) throw new Error("approval retry was not enabled");
if (logged.length !== 1 || logged[0][0] !== "Bloom ceremony failed" ||
    logged[0][1] !== failure) {{
  throw new Error("full ceremony failure was not logged");
}}
const cancellationFailure = new Error("internal cancellation detail");
reportCeremonyError(cancellationFailure, "Cancellation failed. Please try again.");
if (statusNode.textContent !== "Cancellation failed. Please try again.") {{
  throw new Error("safe cancellation failure was not displayed");
}}
if (logged.length !== 2 || logged[1][1] !== cancellationFailure) {{
  throw new Error("full cancellation failure was not logged");
}}
process.stdout.write("browser-error-feedback-ok");
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate ceremony error feedback");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "browser-error-feedback-ok"
    );
    assert!(asset.contains("approve.onclick = () => run(session).catch(reportApprovalFailure)"));
    assert!(asset.contains("Cancellation failed. Please try again."));
    assert!(asset.contains("Ceremony failed to load. Please refresh and try again."));
}

#[test]
fn ceremony_shell_preserves_bloom_review_layout_and_required_controls() {
    let shell = include_str!("../src/ceremony_assets/index.html");
    for required in [
        "href=\"/assets/style.css\"",
        "href=\"/assets/bloom-primary.svg\"",
        "src=\"/assets/bloom-primary.svg\"",
        "Signed local review",
        "Review before continuing",
        "id=\"status\"",
        "id=\"review\"",
        "id=\"approve\"",
        "id=\"cancel\"",
        "id=\"recovery-fields\"",
        "id=\"generic-fields\"",
    ] {
        assert!(
            shell.contains(required),
            "ceremony shell omitted {required}"
        );
    }

    let stylesheet = include_str!("../src/ceremony_assets/style.css");
    for required in [
        "--paper:#f4efe6",
        ".layout{display:grid",
        "@media(max-width:560px)",
    ] {
        assert!(
            stylesheet.contains(required),
            "ceremony stylesheet omitted {required}"
        );
    }

    let logo = include_str!("../src/ceremony_assets/bloom-primary.svg");
    assert_eq!(logo.matches("<path ").count(), 7);
    assert!(logo.contains("fill=\"#9d2d3f\""));
    assert!(logo.contains("stroke=\"#7a2230\""));
}

#[test]
fn scoped_petal_key_browser_flow_never_collects_a_namespace_grant() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    assert!(asset.contains("session.signer_contribution?.petal_key_scope"));
    assert!(asset.contains("&& !scopedPetalKey"));
    assert!(asset.contains("Boolean(scopedPetalKey)"));
    assert!(asset.contains("if (!scopedPetalKey && !genericFields.hidden)"));
    let run = asset
        .split_once("async function run(session)")
        .expect("asset must define the ceremony runner")
        .1;
    let definition = run
        .find("const scopedPetalKey")
        .expect("the runner must derive its own scoped-petal-key state");
    let use_site = run
        .find("if (!scopedPetalKey && !genericFields.hidden)")
        .expect("the runner must guard generic input");
    assert!(
        definition < use_site,
        "runner state must be defined before use"
    );
}

#[test]
fn legacy_passkey_browser_flow_uses_assertion_prf_and_hides_raw_key_input() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    assert!(asset.contains("legacy_passkey_v1_prf"));
    assert!(asset.contains("const assertion = await getCredential(session, 0)"));
    assert!(asset.contains("credential_prf: encodeUrl(credentialPrf)"));
    assert!(asset.contains("Boolean(scopedPetalKey) || legacyPasskeyImport"));
    assert!(asset.contains("wallet_import\" && !legacyPasskeyImport"));
}

fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

fn signer_audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: Token::new("signer-audit-key").unwrap(),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

fn operation(byte: &str) -> OperationId {
    OperationId::new(byte.repeat(32)).unwrap()
}

fn approval_request() -> CeremonyPrepareRequest {
    let key_ref = bloom_signer_api::KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("local-default").unwrap(),
        key_spec: bloom_signer_api::KeySpec::Secp256k1,
        locator: "root-key".into(),
        derivation: None,
        public_key_fingerprint: digest("11"),
    };
    let terms = bloom_signer_api::SealedApprovalTerms {
        subject: bloom_signer_api::ApprovalSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet-sign").unwrap(),
        },
        wallet_id: Token::new("wallet-review").unwrap(),
        key_ref,
        allowed_crypto_suites: vec![bloom_signer_api::CryptoSuite::Secp256k1Sha256Recoverable],
        selector: bloom_signer_api::ApprovalSelector::Exact {
            ordered_payload_digests: vec![digest("12")],
            ordered_hashes: vec![digest("13")],
        },
        limits: bloom_signer_api::ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: bloom_signer_api::ActivationMode::BackendManaged,
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

impl CeremonySigner for RealSigner {
    fn prepare_approval(
        &self,
        request: CeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedApproval, bloom_signer_api::ProtocolError> {
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
    ) -> Result<SignerActivationReceipt, bloom_signer_api::ProtocolError> {
        futures::executor::block_on(self.service.complete_approval(request, now_ms))
    }

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
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
    ) -> Result<CustodyResult, bloom_signer_api::ProtocolError> {
        self.service.complete_custody(request, now_ms)
    }

    fn cancel(&self, operation_id: &OperationId) -> Result<(), bloom_signer_api::ProtocolError> {
        self.service.cancel(operation_id)
    }

    fn bind_custody_output_recipient(
        &self,
        operation_id: &OperationId,
        recipient_key: Base64UrlBytes,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
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
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
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
    ) -> Result<CustodyResult, bloom_signer_api::ProtocolError> {
        self.service.complete_policy_update(request, now_ms)
    }

    fn status(
        &self,
        operation_id: &OperationId,
    ) -> Result<SignerCeremonyStatus, bloom_signer_api::ProtocolError> {
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
    ) -> Result<SignerPreparedApproval, bloom_signer_api::ProtocolError> {
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
            ceremony_kind: bloom_signer_api::CeremonyKind::SealedApproval,
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
    ) -> Result<SignerActivationReceipt, bloom_signer_api::ProtocolError> {
        Err(bloom_signer_api::ProtocolError::new(
            bloom_signer_api::ProtocolErrorCode::BackendUnsupported,
            "mock exposes only the custody path used by this test",
        ))
    }

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
        let effective_wallet_id = request.wallet_id.clone().or_else(|| {
            request
                .legacy_passkey_migration
                .as_ref()
                .map(|migration| migration.wallet_name.clone())
        });
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
            wallet_id: effective_wallet_id,
            key_ref: request.key_ref,
            expected_input_class: request.expected_input_class,
            required_user_verification: true,
            hpke_recipient_key: Base64UrlBytes::from_bytes(&[7; 32]),
            browser_output_recipient_key: request.browser_output_recipient_key,
            petal_key_scope: request.petal_key_scope,
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
    ) -> Result<CustodyResult, bloom_signer_api::ProtocolError> {
        self.completions.fetch_add(1, Ordering::SeqCst);
        Ok(CustodyResult {
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id,
            public_status: request.ceremony_kind.successful_terminal_state().unwrap(),
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
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
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
    ) -> Result<CustodyResult, bloom_signer_api::ProtocolError> {
        self.complete_custody(request.custody, now_ms)
    }

    fn cancel(&self, operation_id: &OperationId) -> Result<(), bloom_signer_api::ProtocolError> {
        self.pending.lock().remove(operation_id);
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn bind_custody_output_recipient(
        &self,
        _operation_id: &OperationId,
        _recipient_key: Base64UrlBytes,
        _now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
        Err(bloom_signer_api::ProtocolError::new(
            bloom_signer_api::ProtocolErrorCode::BackendUnsupported,
            "mock does not expose output-key binding",
        ))
    }

    fn status(
        &self,
        operation_id: &OperationId,
    ) -> Result<SignerCeremonyStatus, bloom_signer_api::ProtocolError> {
        Ok(if self.pending.lock().contains(operation_id) {
            SignerCeremonyStatus::Pending
        } else {
            SignerCeremonyStatus::Missing
        })
    }
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
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
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
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
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
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
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
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
                },
                1_101,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyRateLimited
    );
}

#[tokio::test]
async fn legacy_passkey_prepare_renders_only_digest_bound_public_migration_terms() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let operation_id = operation("81");
    let migration = LegacyPasskeyMigrationPublic {
        schema: Token::new("bloom.legacy_passkey_migration_receipt.v1").unwrap(),
        wallet_name: Token::new("wallet").unwrap(),
        address: "0x1111111111111111111111111111111111111111".into(),
        public_key_fingerprint: digest("82"),
        credential_id_fingerprint: digest("83"),
        legacy_format_version: 1,
        bundle_digest: digest("84"),
        policy_mode: Token::new("restrictive_current_policy").unwrap(),
    };
    let exact_terms_digest = migration.terms_digest(&operation_id).unwrap();
    let response = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletImport,
                custody_operation_id: operation_id,
                wallet_id: None,
                key_ref: None,
                exact_terms_digest,
                expected_input_class: Token::new("legacy_passkey_v1_prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: Some(migration),
                wallet_seed_profile: None,
                derivation_request: None,
            },
            now_ms,
        )
        .unwrap();
    let session = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", url_token(&response.ceremony_url))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let projection: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        projection["review_manifest"]["schema"],
        "bloom.legacy_passkey_migration_review.v1"
    );
    assert_eq!(projection["review_manifest"]["wallet_name"], "wallet");
    assert_eq!(
        projection["review_manifest"]["creates_current_wkek_custody"],
        true
    );
    assert!(
        projection["review_manifest"]
            .get("raw_private_key")
            .is_none()
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
    let manifest = projection["review_manifest"].clone();
    let canonical_plan = manifest["canonical_plan"].as_str().unwrap();
    assert!(canonical_plan.to_lowercase().contains("sha256"));
    assert!(canonical_plan.contains("max_operations"));
    assert!(canonical_plan.contains("root-key"));
    assert!(canonical_plan.contains("Bloom has not established the execution effects"));
    let broker_signature: Base64UrlBytes =
        serde_json::from_value(manifest["broker_signature"].clone()).unwrap();
    assert_eq!(broker_signature.decode().len(), 64);
    assert_eq!(
        Digest32::from_bytes(sha2::Sha256::digest(serde_jcs::to_vec(&manifest).unwrap()).into()),
        response.review_manifest_digest
    );
}

#[tokio::test]
async fn petal_key_scope_is_the_exact_human_review_and_tampering_fails_closed() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let parent = approval_request().terms.key_ref;
    let scope = bloom_signer_api::PetalKeyScope {
        wallet_id: Token::new("wallet-review").unwrap(),
        parent_key_ref: parent.clone(),
        package_hash: digest("91"),
        route: "/petals/exchange/sign".into(),
        lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        key_slot: Token::new("account-a").unwrap(),
        allowed_routes: vec!["/petals/exchange/sign".into()],
        allowed_operation_classes: vec![Token::new("exchange-order").unwrap()],
        allowed_crypto_suites: vec![bloom_signer_api::CryptoSuite::Secp256k1Sha256Recoverable],
        maximum_lifetime_ms: DecimalU64::new(60_000),
        custody_operation_id: operation("92"),
    };
    let request = CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::KeyDerive,
        custody_operation_id: scope.custody_operation_id.clone(),
        wallet_id: Some(scope.wallet_id.clone()),
        key_ref: Some(parent),
        exact_terms_digest: scope.request_digest().unwrap(),
        expected_input_class: Token::new("petal-key-scope-v1").unwrap(),
        browser_output_recipient_key: None,
        petal_key_scope: Some(scope.clone()),
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_request: None,
    };
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let prepared = broker.prepare_custody(request.clone(), now_ms).unwrap();
    let token = url_token(&prepared.ceremony_url);
    let response = broker
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
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        projection["review_manifest"],
        serde_json::to_value(&scope).unwrap()
    );
    assert_eq!(
        projection["signer_contribution"]["petal_key_scope"],
        serde_json::to_value(&scope).unwrap()
    );
    assert!(projection["signer_contribution"]["browser_output_recipient_key"].is_null());

    let mut tampered = request.clone();
    tampered.custody_operation_id = operation("93");
    assert_eq!(
        broker
            .prepare_custody(tampered, now_ms + 1)
            .unwrap_err()
            .code,
        ProtocolErrorCode::OperationIdConflict
    );

    let mut wrong_kind = request;
    wrong_kind.custody_operation_id = operation("94");
    wrong_kind.ceremony_kind = CeremonyKind::WalletDelete;
    assert_eq!(
        broker
            .prepare_custody(wrong_kind, now_ms + 2)
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyKindMismatch
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
    request.terms.subject = bloom_signer_api::ApprovalSubject::Petal {
        package_hash: digest("19"),
        route: "wallet/send".into(),
        agent_id: None,
    };
    request.terms.selector = bloom_signer_api::ApprovalSelector::Petal {
        package_hash: digest("19"),
        route: "wallet/send".into(),
        allowed_operation_classes: vec![Token::new("transfer").unwrap()],
        required_claim_assurance: bloom_signer_api::ClaimAssuranceLevel::MachineAsserted,
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
    assert_eq!(
        response.headers()[CEREMONY_OWNER_HEADER],
        CEREMONY_OWNER_VALUE
    );
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY)
    );
    let stylesheet = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/style.css")
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stylesheet.status(), StatusCode::OK);
    assert_eq!(
        stylesheet.headers()[header::CONTENT_TYPE],
        "text/css; charset=utf-8"
    );
    let stylesheet_body = stylesheet.into_body().collect().await.unwrap().to_bytes();
    assert!(stylesheet_body.starts_with(b":root{"));
    let logo = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/bloom-primary.svg")
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logo.status(), StatusCode::OK);
    assert_eq!(
        logo.headers()[header::CONTENT_TYPE],
        "image/svg+xml; charset=utf-8"
    );
    let logo_body = logo.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        logo_body.as_ref(),
        include_bytes!("../src/ceremony_assets/bloom-primary.svg")
    );
    let unknown_token = Base64UrlBytes::from_bytes(&[99; 32]);
    let unknown = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ceremony/{}", unknown_token.encoded()))
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        unknown.status(),
        StatusCode::NOT_FOUND,
        "another local user cannot discover a ceremony without its 256-bit token"
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
    assert_eq!(completed.status(), StatusCode::OK);
    assert_eq!(signer.completions.load(Ordering::SeqCst), 1);
    assert_eq!(signer.cancellations.load(Ordering::SeqCst), 0);
}

#[test]
fn prebound_canonical_listener_is_a_fatal_no_fallback_failure() {
    let listener = match std::net::TcpListener::bind(CEREMONY_ADDR) {
        Ok(listener) => Some(listener),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => None,
        Err(error) => panic!("cannot establish canonical-listener precondition: {error}"),
    };
    let error = CeremonyBroker::bind_canonical().unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);
    assert!(error.message.contains("18734"));
    drop(listener);
}

#[test]
fn login_session_disconnect_terminalizes_every_live_browser_session() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer.clone());
    let operation_id = operation("af");
    prepare(
        &broker,
        operation_id.clone(),
        Some(Token::new("wallet-logout").unwrap()),
        10_000,
    );

    broker.terminate_live_sessions(10_001).unwrap();

    let status = broker.public_status(&operation_id).unwrap();
    assert_eq!(status.state, CeremonyState::Cancelled);
    assert!(status.ceremony_url.is_none());
    assert_eq!(signer.cancellations.load(Ordering::SeqCst), 1);
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
fn ac18_forced_ceremony_audit_write_failure_rolls_back_session() {
    let directory = tempfile::tempdir().unwrap();
    let fail = Arc::new(AtomicBool::new(false));
    let journal = Arc::new(
        BrokerJournal::open(
            directory.path().join("journal.sqlite"),
            Arc::new(SwitchableAuditSigner(fail.clone())),
        )
        .unwrap(),
    );
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::open_with_manifest_signer_audited(
        directory.path().join("ceremonies.sqlite"),
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        journal.clone(),
    )
    .unwrap();
    let operation_id = operation("30");
    let request = CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::WalletDelete,
        custody_operation_id: operation_id.clone(),
        wallet_id: Some(Token::new("wallet-audit-rollback").unwrap()),
        key_ref: None,
        exact_terms_digest: digest("33"),
        expected_input_class: Token::new("policy-document").unwrap(),
        browser_output_recipient_key: None,
        petal_key_scope: None,
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_request: None,
    };

    fail.store(true, Ordering::SeqCst);
    assert!(broker.prepare_custody(request.clone(), 40_000).is_err());
    assert_eq!(broker.status(&operation_id), None);
    assert!(journal.audit_entries().unwrap().is_empty());

    fail.store(false, Ordering::SeqCst);
    broker.prepare_custody(request, 40_001).unwrap();
    assert_eq!(
        broker.status(&operation_id),
        Some(CeremonyState::AwaitingUser)
    );
    assert_eq!(journal.audit_entries().unwrap().len(), 1);

    fail.store(true, Ordering::SeqCst);
    assert!(broker.cancel(&operation_id, 40_002).is_err());
    assert_eq!(
        broker.status(&operation_id),
        Some(CeremonyState::AwaitingUser),
        "a failed session+journal transaction must not publish cancellation in memory"
    );
    assert_eq!(journal.audit_entries().unwrap().len(), 1);
}

#[test]
fn ac18_populated_ceremony_migration_is_atomic_idempotent_and_retains_source() {
    let directory = tempfile::tempdir().unwrap();
    let legacy_path = directory.path().join("legacy-ceremony.sqlite");
    let legacy_journal =
        Arc::new(BrokerJournal::open(&legacy_path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let operation_id = operation("39");
    let legacy_broker = CeremonyBroker::open_with_manifest_signer_audited(
        &legacy_path,
        Arc::new(MockSigner::new()),
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        legacy_journal,
    )
    .unwrap();
    legacy_broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation_id.clone(),
                wallet_id: Some(Token::new("wallet-migrated").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("39"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            50_000,
        )
        .unwrap();
    legacy_broker.cancel(&operation_id, 50_001).unwrap();
    drop(legacy_broker);
    let source = rusqlite::Connection::open(&legacy_path).unwrap();
    let source_jcs: String = source
        .query_row(
            "SELECT session_jcs FROM ceremony_sessions WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    drop(source);

    let failed_target_path = directory.path().join("failed-target-journal.sqlite");
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
        CeremonyBroker::open(
            &legacy_path,
            Arc::new(MockSigner::new()),
            failed_journal.clone(),
        )
        .is_err()
    );
    let failed_target = rusqlite::Connection::open(&failed_target_path).unwrap();
    assert_eq!(
        failed_target
            .query_row("SELECT COUNT(*) FROM ceremony_sessions", [], |row| {
                row.get::<_, i64>(0)
            })
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
    let source = rusqlite::Connection::open(&legacy_path).unwrap();
    assert_eq!(
        source
            .query_row(
                "SELECT session_jcs FROM ceremony_sessions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        source_jcs
    );
    drop(source);
    drop(failed_target);
    drop(failed_journal);

    let target_path = directory.path().join("target-journal.sqlite");
    let target_journal =
        Arc::new(BrokerJournal::open(&target_path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let migrated = CeremonyBroker::open(
        &legacy_path,
        Arc::new(MockSigner::new()),
        target_journal.clone(),
    )
    .unwrap();
    assert_eq!(
        migrated.status(&operation_id),
        Some(CeremonyState::Cancelled)
    );
    assert_eq!(
        target_journal
            .audit_entries()
            .unwrap()
            .iter()
            .filter(|entry| entry.event_type == "storage.ceremony_migrated")
            .count(),
        1
    );
    drop(migrated);
    let reopened = CeremonyBroker::open(
        &legacy_path,
        Arc::new(MockSigner::new()),
        target_journal.clone(),
    )
    .unwrap();
    assert_eq!(
        reopened.status(&operation_id),
        Some(CeremonyState::Cancelled)
    );
    assert_eq!(
        target_journal
            .audit_entries()
            .unwrap()
            .iter()
            .filter(|entry| entry.event_type == "storage.ceremony_migrated")
            .count(),
        1
    );
    let source = rusqlite::Connection::open(&legacy_path).unwrap();
    assert_eq!(
        source
            .query_row(
                "SELECT session_jcs FROM ceremony_sessions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        source_jcs
    );
    drop(source);

    let conflict_path = directory.path().join("conflict-ceremony.sqlite");
    std::fs::copy(&legacy_path, &conflict_path).unwrap();
    assert!(
        CeremonyBroker::open(
            &conflict_path,
            Arc::new(MockSigner::new()),
            target_journal.clone(),
        )
        .is_err()
    );
    let target = rusqlite::Connection::open(&target_path).unwrap();
    let marker: i64 = target
        .query_row(
            "SELECT COUNT(*) FROM broker_store_migrations WHERE source_kind='ceremony' AND source_path=?1",
            [conflict_path.to_string_lossy().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, 0);
}

#[test]
fn ac18_ceremony_status_survives_latched_audit_tamper_while_new_sessions_fail() {
    let directory = tempfile::tempdir().unwrap();
    let journal_path = directory.path().join("journal.sqlite");
    let ceremony_path = directory.path().join("ceremonies.sqlite");
    let journal =
        Arc::new(BrokerJournal::open(&journal_path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let broker = CeremonyBroker::open_with_manifest_signer_audited(
        &ceremony_path,
        Arc::new(MockSigner::new()),
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        journal,
    )
    .unwrap();
    let existing_operation = operation("39");
    prepare(
        &broker,
        existing_operation.clone(),
        Some(Token::new("wallet-audit-status").unwrap()),
        41_000,
    );
    drop(broker);

    rusqlite::Connection::open(&journal_path)
        .unwrap()
        .execute(
            "UPDATE audit_chain SET payload_jcs='{}' WHERE sequence=0",
            [],
        )
        .unwrap();
    let degraded_journal =
        Arc::new(BrokerJournal::open(&journal_path, Arc::new(ServiceTestAuditSigner)).unwrap());
    assert!(degraded_journal.audit_degraded());
    let restarted = CeremonyBroker::open_with_manifest_signer_audited(
        &ceremony_path,
        Arc::new(MockSigner::new()),
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        degraded_journal,
    )
    .unwrap();
    assert_eq!(
        restarted.status(&existing_operation),
        Some(CeremonyState::AwaitingUser)
    );
    assert!(
        restarted
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletDelete,
                    custody_operation_id: operation("3a"),
                    wallet_id: Some(Token::new("wallet-audit-new").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("33"),
                    expected_input_class: Token::new("policy-document").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
                },
                41_001,
            )
            .is_err()
    );
}

#[test]
fn restart_expires_nonterminal_session_and_persists_only_token_hash() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ceremonies.sqlite");
    let signer = Arc::new(MockSigner::new());
    let journal = Arc::new(BrokerJournal::open(&path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let broker = CeremonyBroker::open(&path, signer.clone(), journal.clone()).unwrap();
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

    let restarted = CeremonyBroker::open(&path, signer.clone(), journal).unwrap();
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
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
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
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
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
                    wallet_id: Some(Token::new(format!("wallet-a{index}")).unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("34"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
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
                    wallet_id: Some(Token::new("wallet-af").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("34"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
                },
                500_010,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyRateLimited
    );
}

#[test]
fn zero_effective_time_fails_closed_before_anonymous_creation_quota() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    for index in 0..4_u8 {
        let operation_id = operation(&format!("b{index}"));
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletRegistration,
                    custody_operation_id: operation_id.clone(),
                    wallet_id: Some(Token::new(format!("wallet-b{index}")).unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("34"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
                },
                1 + u64::from(index),
            )
            .unwrap();
        broker.cancel(&operation_id, 1 + u64::from(index)).unwrap();
    }

    let error = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletRegistration,
                custody_operation_id: operation("bf"),
                wallet_id: Some(Token::new("wallet-bf").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("34"),
                expected_input_class: Token::new("passkey-prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            0,
        )
        .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::ClockUntrusted);
    assert_eq!(
        error.message,
        "trusted platform time is required to create a ceremony"
    );
}

#[test]
fn cancellation_backoff_reports_remaining_cooldown_and_resets_after_expiry() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let wallet = Token::new("wallet-cancellation-backoff").unwrap();
    let first_operation = operation("c1");
    prepare(
        &broker,
        first_operation.clone(),
        Some(wallet.clone()),
        10_000,
    );
    broker.cancel(&first_operation, 10_000).unwrap();

    let error = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("c2"),
                wallet_id: Some(wallet.clone()),
                key_ref: None,
                exact_terms_digest: digest("35"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            10_001,
        )
        .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::CeremonyRateLimited);
    assert_eq!(
        error.message,
        "wallet ceremony is in cancellation backoff; retry after 1999 ms"
    );

    prepare(&broker, operation("c3"), Some(wallet), 12_000);
}

#[test]
fn requested_wallet_ids_still_count_as_new_registration_attempts() {
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    let engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            signer_audit_keys(),
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
                    wallet_id: Some(Token::new(format!("wallet-d{index}")).unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("d8"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: Some(WalletSeedProfile::Bip39MulticurveV1),
                    derivation_request: None,
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
                    wallet_id: Some(Token::new("wallet-df").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("d8"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: Some(WalletSeedProfile::Bip39MulticurveV1),
                    derivation_request: None,
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
            signer_audit_keys(),
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
                wallet_id: Some(Token::new("quiet-lilac").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("51"),
                expected_input_class: Token::new("passkey-prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: Some(WalletSeedProfile::Bip39MulticurveV1),
                derivation_request: None,
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
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
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
