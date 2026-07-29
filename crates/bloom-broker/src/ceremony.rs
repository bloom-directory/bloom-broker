use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use bloom_triad_protocol::{
    ApprovalPrepareState, Base64UrlBytes, CeremonyChallenge, CeremonyCompleteRequest, CeremonyKind,
    CeremonyPrepareRequest, CeremonyState, CeremonyWebAuthnOptions, CustodyCompleteRequest,
    CustodyPrepareRequest, CustodyPrepareResponse, CustodyPrepareState, CustodyResult,
    CustodySignerContribution, Digest32, OperationId, PolicyUpdateCeremonyCompleteRequest,
    PolicyUpdateCeremonyPrepareRequest, PolicyUpdatePrepareResponse, PolicyUpdateReviewManifest,
    ProtocolError, ProtocolErrorCode, ReviewManifest, SealedApprovalPrepareResponse,
    SignerActivationReceipt, SignerCeremonyContribution, SignerCeremonyStatus,
    SignerPreparedApproval, SignerPreparedCustody, Token, WebAuthnCeremonyProof,
    WebAuthnCredential, verify_webauthn_assertion, verify_webauthn_attestation,
};
use ed25519_dalek::{Signer as _, SigningKey};
use parking_lot::Mutex;
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    path::Path as FsPath,
    sync::Arc,
};

pub const CEREMONY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_734);
pub const CEREMONY_ORIGIN: &str = "http://localhost:18734";
pub const MAX_CEREMONY_BODY_BYTES: usize = 16 * 1024;
pub const CEREMONY_OWNER_HEADER: &str = "x-bloom-ceremony-owner";
pub const CEREMONY_OWNER_VALUE: &str = "bloom-broker-v1";
pub const MAX_CONCURRENT_SESSIONS: usize = 16;
const INVALID_ATTEMPT_LIMIT: u32 = 8;
const CANCELLATION_BACKOFF_MS: u64 = 2_000;
const REVIEW_MANIFEST_DOMAIN: &[u8] = b"bloom-broker-review-manifest/v1";
const CREATION_WINDOW_MS: u64 = 10 * 60 * 1_000;
const MAX_CREATIONS_PER_WALLET: usize = 6;
const MAX_ANONYMOUS_REGISTRATIONS: usize = 4;
const OUTPUT_ACK_TTL_MS: u64 = 5 * 60 * 1_000;

const SHELL_HTML: &str = include_str!("ceremony_assets/index.html");
const APP_JS: &str = include_str!("ceremony_assets/app.js");

#[derive(Clone, Debug, Default)]
pub struct ReviewManifestContext {
    pub petal_use_claim: Option<bloom_triad_protocol::PetalUseClaim>,
    pub claim_assurance: Option<bloom_triad_protocol::ClaimAssurance>,
    pub attributed_advisory_items: Vec<String>,
}

/// Typed Broker-to-Signer seam. Broker only forwards raw proof and opaque HPKE
/// envelopes; no method accepts plaintext PRF or custody input.
pub trait CeremonySigner: Send + Sync {
    fn prepare_approval(
        &self,
        request: CeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedApproval, ProtocolError>;

    fn complete_approval(
        &self,
        request: CeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<SignerActivationReceipt, ProtocolError>;

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError>;

    fn complete_custody(
        &self,
        request: CustodyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError>;

    fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        let _ = (request, now_ms);
        Err(protocol(
            ProtocolErrorCode::BackendUnsupported,
            "policy-update ceremony preparation is not implemented by this Signer seam",
        ))
    }

    fn complete_policy_update(
        &self,
        request: PolicyUpdateCeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        let _ = (request, now_ms);
        Err(protocol(
            ProtocolErrorCode::BackendUnsupported,
            "policy-update ceremony completion is not implemented by this Signer seam",
        ))
    }

    fn bind_custody_output_recipient(
        &self,
        operation_id: &OperationId,
        recipient_key: Base64UrlBytes,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError>;

    fn cancel(&self, operation_id: &OperationId) -> Result<(), ProtocolError>;

    fn status(&self, operation_id: &OperationId) -> Result<SignerCeremonyStatus, ProtocolError>;
}

pub trait CeremonyCompletionObserver: Send + Sync {
    fn approval_completed(
        &self,
        receipt: &SignerActivationReceipt,
        now_ms: u64,
    ) -> Result<(), ProtocolError>;

    fn custody_completed(&self, _receipt: &CustodyResult) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct CeremonyBroker {
    inner: Arc<BrokerInner>,
}

struct BrokerInner {
    signer: Arc<dyn CeremonySigner>,
    sessions: Mutex<HashMap<String, BrowserSession>>,
    operations: Mutex<HashMap<OperationId, String>>,
    cancellation_backoff: Mutex<HashMap<Token, (u32, u64)>>,
    invalid_attempts: Mutex<HashMap<IpAddr, u32>>,
    database: Option<Mutex<Connection>>,
    manifest_signer: Option<(Token, SigningKey)>,
    completion_observer: Mutex<Option<Arc<dyn CeremonyCompletionObserver>>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrowserSession {
    operation_id: OperationId,
    request_digest: Digest32,
    wallet_id: Option<Token>,
    #[serde(default)]
    anonymous_registration: bool,
    ceremony_kind: CeremonyKind,
    #[serde(skip)]
    token: Option<Base64UrlBytes>,
    token_hash: [u8; 32],
    expires_at_ms: u64,
    created_at_ms: u64,
    terminal_at_ms: Option<u64>,
    state: CeremonyState,
    terminal_result: Option<serde_json::Value>,
    #[serde(default)]
    verification_credentials: Vec<WebAuthnCredential>,
    #[serde(default)]
    policy_update: Option<PolicyUpdateCeremonyPrepareRequest>,
    projection: BrowserProjection,
}

struct NewBrowserSession {
    operation_id: OperationId,
    request_digest: Digest32,
    wallet_id: Option<Token>,
    anonymous_registration: bool,
    ceremony_kind: CeremonyKind,
    ceremony_id: Digest32,
    review_manifest: Option<serde_json::Value>,
    challenges: Vec<CeremonyChallenge>,
    signer_contribution: serde_json::Value,
    webauthn_options: CeremonyWebAuthnOptions,
    verification_credentials: Vec<WebAuthnCredential>,
    policy_update: Option<PolicyUpdateCeremonyPrepareRequest>,
    expires_at_ms: u64,
    created_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrowserProjection {
    ceremony_id: Digest32,
    ceremony_kind: CeremonyKind,
    operation_id: OperationId,
    review_manifest: Option<serde_json::Value>,
    challenges: Vec<BrowserChallenge>,
    signer_contribution: serde_json::Value,
    webauthn_options: CeremonyWebAuthnOptions,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrowserChallenge {
    binding: CeremonyChallenge,
    challenge: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserComplete {
    proof: WebAuthnCeremonyProof,
    encrypted_input: Option<bloom_triad_protocol::HpkeEnvelope>,
    public_binding_digest: Digest32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserOutputKey {
    recipient_key: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserAck {}

impl CeremonyBroker {
    pub fn new(signer: Arc<dyn CeremonySigner>) -> Self {
        Self::from_parts(signer, None, None)
    }

    pub fn new_with_manifest_signer(
        signer: Arc<dyn CeremonySigner>,
        broker_key_id: Token,
        signing_key: SigningKey,
    ) -> Self {
        Self::from_parts(signer, None, Some((broker_key_id, signing_key)))
    }

    pub fn open(
        path: impl AsRef<FsPath>,
        signer: Arc<dyn CeremonySigner>,
    ) -> Result<Self, ProtocolError> {
        let connection = Connection::open(path).map_err(storage)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS ceremony_sessions (
                    ceremony_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    session_jcs TEXT NOT NULL
                );",
            )
            .map_err(storage)?;
        let broker = Self::from_parts(signer, Some(connection), None);
        broker.reload_and_reconcile_nonterminal()?;
        Ok(broker)
    }

    pub fn open_with_manifest_signer(
        path: impl AsRef<FsPath>,
        signer: Arc<dyn CeremonySigner>,
        broker_key_id: Token,
        signing_key: SigningKey,
    ) -> Result<Self, ProtocolError> {
        let connection = Connection::open(path).map_err(storage)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS ceremony_sessions (
                    ceremony_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    session_jcs TEXT NOT NULL
                );",
            )
            .map_err(storage)?;
        let broker = Self::from_parts(signer, Some(connection), Some((broker_key_id, signing_key)));
        broker.reload_and_reconcile_nonterminal()?;
        Ok(broker)
    }

    fn from_parts(
        signer: Arc<dyn CeremonySigner>,
        database: Option<Connection>,
        manifest_signer: Option<(Token, SigningKey)>,
    ) -> Self {
        Self {
            inner: Arc::new(BrokerInner {
                signer,
                sessions: Mutex::new(HashMap::new()),
                operations: Mutex::new(HashMap::new()),
                cancellation_backoff: Mutex::new(HashMap::new()),
                invalid_attempts: Mutex::new(HashMap::new()),
                database: database.map(Mutex::new),
                manifest_signer,
                completion_observer: Mutex::new(None),
            }),
        }
    }

    pub fn set_completion_observer(
        &self,
        observer: Arc<dyn CeremonyCompletionObserver>,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        *self.inner.completion_observer.lock() = Some(observer.clone());
        let sessions = self
            .inner
            .sessions
            .lock()
            .values()
            .filter_map(|session| {
                session.terminal_result.as_ref().map(|receipt| {
                    (
                        session.projection.ceremony_id.as_str().to_owned(),
                        session.state,
                        session.ceremony_kind,
                        receipt.clone(),
                    )
                })
            })
            .collect::<Vec<_>>();
        for (ceremony_id, state, kind, receipt) in sessions {
            if state == CeremonyState::WalletCommitted {
                self.finalize_committed_session(&ceremony_id, now_ms)?;
            } else {
                self.notify_completion(kind, &receipt, now_ms)?;
            }
        }
        Ok(())
    }

    pub fn prepare_approval(
        &self,
        mut request: CeremonyPrepareRequest,
        context: ReviewManifestContext,
        now_ms: u64,
    ) -> Result<SealedApprovalPrepareResponse, ProtocolError> {
        self.expire_sessions(now_ms)?;
        let manifest = self.build_review_manifest(&request, context, now_ms)?;
        request.review_manifest_digest = digest(&manifest)?;
        self.validate_review_manifest(&request, &manifest, now_ms)?;
        let request_digest = digest(&(request.clone(), manifest.clone()))?;
        if let Some(response) =
            self.stable_approval_response(&request.activation_operation_id, &request_digest)
        {
            return response;
        }
        self.enforce_creation_bounds(Some(&request.terms.wallet_id), false, now_ms)?;
        let prepared = self
            .inner
            .signer
            .prepare_approval(request.clone(), now_ms)?;
        let ceremony_id = prepared.contribution.ceremony_id.clone();
        let expires_at_ms = prepared.contribution.expires_at_ms.get();
        let session = self.new_session(NewBrowserSession {
            operation_id: request.activation_operation_id.clone(),
            request_digest,
            wallet_id: Some(request.terms.wallet_id.clone()),
            anonymous_registration: false,
            ceremony_kind: CeremonyKind::SealedApproval,
            ceremony_id: ceremony_id.clone(),
            review_manifest: Some(serde_json::to_value(&manifest).map_err(malformed)?),
            challenges: prepared.challenges,
            signer_contribution: serde_json::to_value(prepared.contribution).map_err(malformed)?,
            webauthn_options: prepared.webauthn_options,
            verification_credentials: prepared.verification_credentials,
            policy_update: None,
            expires_at_ms,
            created_at_ms: now_ms,
        })?;
        let url = session_url(&token_for(&session));
        self.insert_session(ceremony_id.clone(), session)?;
        Ok(SealedApprovalPrepareResponse {
            approval_id: request.terms.approval_id()?,
            state: ApprovalPrepareState::AwaitingCeremony,
            ceremony_url: url,
            ceremony_expires_at_ms: bloom_triad_protocol::DecimalU64::new(expires_at_ms),
            review_manifest_digest: request.review_manifest_digest,
        })
    }

    pub fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<CustodyPrepareResponse, ProtocolError> {
        self.expire_sessions(now_ms)?;
        if matches!(
            request.ceremony_kind,
            CeremonyKind::SealedApproval | CeremonyKind::PolicyUpdate
        ) {
            return Err(kind_mismatch());
        }
        let request_digest = digest(&request)?;
        if let Some(response) =
            self.stable_custody_response(&request.custody_operation_id, &request_digest)
        {
            return response;
        }
        let anonymous_registration = request.ceremony_kind == CeremonyKind::WalletRegistration
            && request.wallet_id.is_none();
        self.enforce_creation_bounds(request.wallet_id.as_ref(), anonymous_registration, now_ms)?;
        let prepared = self.inner.signer.prepare_custody(request.clone(), now_ms)?;
        let ceremony_id = prepared.contribution.ceremony_id.clone();
        let contribution_digest = prepared.contribution.digest()?;
        let expires_at_ms = prepared.contribution.expires_at_ms.get();
        let session = self.new_session(NewBrowserSession {
            operation_id: request.custody_operation_id.clone(),
            request_digest,
            wallet_id: prepared.contribution.wallet_id.clone(),
            anonymous_registration,
            ceremony_kind: request.ceremony_kind,
            ceremony_id: ceremony_id.clone(),
            review_manifest: None,
            challenges: prepared.challenges,
            signer_contribution: serde_json::to_value(prepared.contribution).map_err(malformed)?,
            webauthn_options: prepared.webauthn_options,
            verification_credentials: prepared.verification_credentials,
            policy_update: None,
            expires_at_ms,
            created_at_ms: now_ms,
        })?;
        let url = session_url(&token_for(&session));
        self.insert_session(ceremony_id, session)?;
        Ok(CustodyPrepareResponse {
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id,
            state: CustodyPrepareState::AwaitingUser,
            ceremony_url: url,
            ceremony_expires_at_ms: bloom_triad_protocol::DecimalU64::new(expires_at_ms),
            signer_contribution_digest: contribution_digest,
        })
    }

    pub fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        review_manifest: PolicyUpdateReviewManifest,
        now_ms: u64,
    ) -> Result<PolicyUpdatePrepareResponse, ProtocolError> {
        self.expire_sessions(now_ms)?;
        if request.custody.ceremony_kind != CeremonyKind::PolicyUpdate
            || request.custody.custody_operation_id != request.update.operation_id
            || request.custody.wallet_id.as_ref() != Some(&request.update.wallet_id)
            || request.custody.key_ref.is_some()
            || request.custody.exact_terms_digest != request.update.terms_digest()?
            || request.broker_validation_receipt.update_terms_digest
                != request.custody.exact_terms_digest
            || request.broker_validation_receipt.review_manifest_digest
                != review_manifest.digest()?
            || review_manifest.operation_id != request.update.operation_id
            || review_manifest.wallet_id != request.update.wallet_id
        {
            return Err(kind_mismatch());
        }
        let request_digest = digest(&(request.clone(), review_manifest.clone()))?;
        if let Some(response) = self.stable_policy_update_response(
            &request.update.operation_id,
            &request_digest,
            &request.broker_validation_receipt.review_manifest_digest,
        ) {
            return response;
        }
        self.enforce_creation_bounds(Some(&request.update.wallet_id), false, now_ms)?;
        let prepared = self
            .inner
            .signer
            .prepare_policy_update(request.clone(), now_ms)?;
        let ceremony_id = prepared.contribution.ceremony_id.clone();
        let expires_at_ms = prepared.contribution.expires_at_ms.get();
        let session = self.new_session(NewBrowserSession {
            operation_id: request.update.operation_id.clone(),
            request_digest,
            wallet_id: Some(request.update.wallet_id.clone()),
            anonymous_registration: false,
            ceremony_kind: CeremonyKind::PolicyUpdate,
            ceremony_id: ceremony_id.clone(),
            review_manifest: Some(serde_json::to_value(review_manifest).map_err(malformed)?),
            challenges: prepared.challenges,
            signer_contribution: serde_json::to_value(prepared.contribution).map_err(malformed)?,
            webauthn_options: prepared.webauthn_options,
            verification_credentials: prepared.verification_credentials,
            policy_update: Some(request.clone()),
            expires_at_ms,
            created_at_ms: now_ms,
        })?;
        let response = PolicyUpdatePrepareResponse {
            operation_id: request.update.operation_id,
            ceremony_kind: CeremonyKind::PolicyUpdate,
            ceremony_url: session_url(&token_for(&session)),
            ceremony_expires_at_ms: bloom_triad_protocol::DecimalU64::new(expires_at_ms),
            review_manifest_digest: request.broker_validation_receipt.review_manifest_digest,
        };
        self.insert_session(ceremony_id, session)?;
        Ok(response)
    }

    pub fn status(&self, operation_id: &OperationId) -> Option<CeremonyState> {
        let ceremony_id = self.inner.operations.lock().get(operation_id)?.clone();
        self.inner
            .sessions
            .lock()
            .get(&ceremony_id)
            .map(|session| session.state)
    }

    pub fn public_status(
        &self,
        operation_id: &OperationId,
    ) -> Result<bloom_triad_protocol::CeremonyPublicStatus, ProtocolError> {
        let ceremony_id = self
            .inner
            .operations
            .lock()
            .get(operation_id)
            .cloned()
            .ok_or_else(not_found)?;
        let sessions = self.inner.sessions.lock();
        let session = sessions.get(&ceremony_id).ok_or_else(not_found)?;
        let receipt_digest = session.terminal_result.as_ref().map(digest).transpose()?;
        let ceremony_url = if session.state == CeremonyState::AwaitingUser {
            session.token.as_ref().map(session_url)
        } else {
            None
        };
        Ok(bloom_triad_protocol::CeremonyPublicStatus {
            ceremony_id: session.projection.ceremony_id.clone(),
            ceremony_kind: session.ceremony_kind,
            operation_id: operation_id.clone(),
            state: session.state,
            expires_at_ms: bloom_triad_protocol::DecimalU64::new(session.expires_at_ms),
            ceremony_url,
            receipt_digest,
        })
    }

    pub fn completed_policy_update(
        &self,
        operation_id: &OperationId,
        receipt: &CustodyResult,
    ) -> Result<PolicyUpdateCeremonyPrepareRequest, ProtocolError> {
        let ceremony_id = self
            .inner
            .operations
            .lock()
            .get(operation_id)
            .cloned()
            .ok_or_else(not_found)?;
        let sessions = self.inner.sessions.lock();
        let session = sessions.get(&ceremony_id).ok_or_else(not_found)?;
        if session.ceremony_kind != CeremonyKind::PolicyUpdate
            || session.state != CeremonyState::Succeeded
            || receipt.ceremony_kind != CeremonyKind::PolicyUpdate
            || &receipt.custody_operation_id != operation_id
        {
            return Err(kind_mismatch());
        }
        let stored: CustodyResult =
            serde_json::from_value(session.terminal_result.clone().ok_or_else(not_found)?)
                .map_err(malformed)?;
        if &stored != receipt {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "policy commit receipt differs from completed ceremony",
            ));
        }
        session.policy_update.clone().ok_or_else(kind_mismatch)
    }

    pub fn cancel(&self, operation_id: &OperationId, now_ms: u64) -> Result<(), ProtocolError> {
        let ceremony_id = self
            .inner
            .operations
            .lock()
            .get(operation_id)
            .cloned()
            .ok_or_else(not_found)?;
        let wallet_id = {
            let mut sessions = self.inner.sessions.lock();
            let session = sessions.get_mut(&ceremony_id).ok_or_else(not_found)?;
            if session.state != CeremonyState::AwaitingUser {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "terminal ceremony cannot be cancelled",
                ));
            }
            session.wallet_id.clone()
        };
        self.inner.signer.cancel(operation_id)?;
        if let Some(session) = self.inner.sessions.lock().get_mut(&ceremony_id) {
            session.state = CeremonyState::Cancelled;
            session.terminal_at_ms = Some(now_ms);
            session.token = None;
            session.token_hash = [0_u8; 32];
            let snapshot = session.clone();
            self.persist_session(&snapshot)?;
        }
        if let Some(wallet_id) = &wallet_id {
            self.record_backoff(wallet_id, now_ms);
        }
        Ok(())
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(shell))
            .route("/ceremony/{token}", get(ceremony_shell))
            .route("/assets/app.js", get(app_js))
            .route("/api/session", get(read_session_by_token))
            .route("/api/session/{ceremony_id}", get(read_session))
            .route("/api/session/{ceremony_id}/result", get(read_result))
            .route(
                "/api/session/{ceremony_id}/complete",
                post(complete_session),
            )
            .route(
                "/api/session/{ceremony_id}/output-key",
                post(bind_output_key),
            )
            .route("/api/session/{ceremony_id}/ack", post(acknowledge_result))
            .route("/api/session/{ceremony_id}/cancel", post(cancel_session))
            .layer(DefaultBodyLimit::max(MAX_CEREMONY_BODY_BYTES))
            .layer(middleware::from_fn(security_headers))
            .with_state(self.clone())
    }

    pub fn expire_sessions(&self, now_ms: u64) -> Result<(), ProtocolError> {
        let expired = self
            .inner
            .sessions
            .lock()
            .iter()
            .filter(|(_, session)| !is_terminal(session.state) && session.expires_at_ms <= now_ms)
            .map(|(id, session)| (id.clone(), session.operation_id.clone()))
            .collect::<Vec<_>>();
        for (ceremony_id, operation_id) in expired {
            if self
                .inner
                .sessions
                .lock()
                .get(&ceremony_id)
                .is_some_and(|session| session.state == CeremonyState::WalletCommitted)
            {
                self.finalize_committed_session(&ceremony_id, now_ms)?;
                continue;
            }
            if self
                .inner
                .sessions
                .lock()
                .get(&ceremony_id)
                .is_some_and(|session| session.state == CeremonyState::AwaitingRecoveryAck)
            {
                let snapshot = {
                    let sessions = self.inner.sessions.lock();
                    let mut snapshot = sessions.get(&ceremony_id).cloned().ok_or_else(not_found)?;
                    snapshot.state = CeremonyState::Failed;
                    snapshot.terminal_at_ms = Some(now_ms);
                    snapshot.token = None;
                    snapshot.token_hash = [0_u8; 32];
                    snapshot
                };
                self.persist_session(&snapshot)?;
                self.inner
                    .sessions
                    .lock()
                    .insert(ceremony_id.clone(), snapshot);
                continue;
            }
            let signer_status = self.inner.signer.status(&operation_id)?;
            let (state, terminal_result) = match signer_status {
                SignerCeremonyStatus::CompletedApproval(receipt) => (
                    CeremonyState::WalletCommitted,
                    Some(serde_json::to_value(receipt).map_err(malformed)?),
                ),
                SignerCeremonyStatus::CompletedCustody(result) => (
                    CeremonyState::WalletCommitted,
                    Some(serde_json::to_value(result).map_err(malformed)?),
                ),
                SignerCeremonyStatus::Pending => {
                    self.inner.signer.cancel(&operation_id)?;
                    (CeremonyState::Expired, None)
                }
                SignerCeremonyStatus::Missing => (CeremonyState::Expired, None),
            };
            let snapshot = {
                let mut sessions = self.inner.sessions.lock();
                let session = sessions.get_mut(&ceremony_id).ok_or_else(not_found)?;
                session.state = state;
                session.terminal_result = terminal_result;
                if state == CeremonyState::Expired {
                    session.terminal_at_ms = Some(now_ms);
                    session.token = None;
                    session.token_hash = [0_u8; 32];
                }
                session.clone()
            };
            if state == CeremonyState::Expired {
                if let Some(wallet_id) = &snapshot.wallet_id {
                    self.record_backoff(wallet_id, now_ms);
                }
            } else if state == CeremonyState::WalletCommitted {
                validate_completion_identity(
                    snapshot.ceremony_kind,
                    &snapshot.operation_id,
                    &snapshot.projection.ceremony_id,
                    snapshot.terminal_result.as_ref().ok_or_else(not_found)?,
                )?;
            }
            self.persist_session(&snapshot)?;
            if state == CeremonyState::WalletCommitted {
                self.finalize_committed_session(&ceremony_id, now_ms)?;
            }
        }
        Ok(())
    }

    /// Exclusively acquire the canonical socket. There is deliberately no
    /// fallback address or port.
    pub fn bind_canonical() -> Result<StdTcpListener, ProtocolError> {
        let listener = StdTcpListener::bind(CEREMONY_ADDR).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!(
                    "fatal canonical ceremony listener ownership conflict at {CEREMONY_ADDR}; no fallback port will be used: {error}"
                ),
            )
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!("canonical ceremony listener setup failed: {error}"),
            )
        })?;
        Ok(listener)
    }

    pub async fn serve_canonical(self) -> Result<(), ProtocolError> {
        let listener = Self::bind_canonical()?;
        self.serve_listener(listener).await
    }

    /// Accept a canonical listener inherited from a launch/socket activation
    /// manager. A listener for any other address is rejected.
    pub async fn serve_listener(self, listener: StdTcpListener) -> Result<(), ProtocolError> {
        if listener
            .local_addr()
            .map_err(|error| protocol(ProtocolErrorCode::ServiceUnavailable, error.to_string()))?
            != CEREMONY_ADDR
        {
            return Err(protocol(
                ProtocolErrorCode::ServiceUnavailable,
                "inherited ceremony listener is not the canonical listener",
            ));
        }
        listener
            .set_nonblocking(true)
            .map_err(|error| protocol(ProtocolErrorCode::ServiceUnavailable, error.to_string()))?;
        let listener = tokio::net::TcpListener::from_std(listener).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!("canonical ceremony listener handoff failed: {error}"),
            )
        })?;
        axum::serve(listener, self.router())
            .await
            .map_err(|error| protocol(ProtocolErrorCode::ServiceUnavailable, error.to_string()))
    }

    fn new_session(&self, new: NewBrowserSession) -> Result<BrowserSession, ProtocolError> {
        let mut token_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        Ok(BrowserSession {
            operation_id: new.operation_id.clone(),
            request_digest: new.request_digest,
            wallet_id: new.wallet_id,
            anonymous_registration: new.anonymous_registration,
            ceremony_kind: new.ceremony_kind,
            token: Some(Base64UrlBytes::from_bytes(&token_bytes)),
            token_hash: Sha256::digest(token_bytes).into(),
            expires_at_ms: new.expires_at_ms,
            created_at_ms: new.created_at_ms,
            terminal_at_ms: None,
            state: CeremonyState::AwaitingUser,
            terminal_result: None,
            verification_credentials: new.verification_credentials,
            policy_update: new.policy_update,
            projection: BrowserProjection {
                ceremony_id: new.ceremony_id,
                ceremony_kind: new.ceremony_kind,
                operation_id: new.operation_id,
                review_manifest: new.review_manifest,
                challenges: new
                    .challenges
                    .into_iter()
                    .map(|binding| {
                        let challenge = binding.webauthn_challenge()?;
                        Ok(BrowserChallenge { binding, challenge })
                    })
                    .collect::<Result<Vec<_>, ProtocolError>>()?,
                signer_contribution: new.signer_contribution,
                webauthn_options: new.webauthn_options,
                expires_at_ms: new.expires_at_ms,
            },
        })
    }

    fn insert_session(
        &self,
        ceremony_id: Digest32,
        session: BrowserSession,
    ) -> Result<(), ProtocolError> {
        let id = ceremony_id.as_str().to_owned();
        if self.inner.sessions.lock().contains_key(&id) {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "Signer reused a ceremony ID",
            ));
        }
        self.persist_session(&session)?;
        self.inner
            .operations
            .lock()
            .insert(session.operation_id.clone(), id.clone());
        self.inner.sessions.lock().insert(id, session);
        Ok(())
    }

    fn enforce_creation_bounds(
        &self,
        wallet_id: Option<&Token>,
        anonymous_registration: bool,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        let sessions = self.inner.sessions.lock();
        let live = sessions
            .values()
            .filter(|session| !is_terminal(session.state) && session.expires_at_ms > now_ms)
            .count();
        if live >= MAX_CONCURRENT_SESSIONS {
            return Err(protocol(
                ProtocolErrorCode::QuotaExceeded,
                "Broker ceremony concurrency quota is exhausted",
            ));
        }
        if let Some(wallet_id) = wallet_id {
            let recent = sessions
                .values()
                .filter(|session| {
                    session.wallet_id.as_ref() == Some(wallet_id)
                        && session.created_at_ms.saturating_add(CREATION_WINDOW_MS) > now_ms
                })
                .count();
            if recent >= MAX_CREATIONS_PER_WALLET {
                return Err(protocol(
                    ProtocolErrorCode::CeremonyRateLimited,
                    "wallet ceremony rolling creation quota is exhausted",
                ));
            }
            if sessions.values().any(|session| {
                session.wallet_id.as_ref() == Some(wallet_id)
                    && !is_terminal(session.state)
                    && session.expires_at_ms > now_ms
            }) {
                return Err(protocol(
                    ProtocolErrorCode::QuotaExceeded,
                    "wallet already has a live ceremony",
                ));
            }
            if self
                .inner
                .cancellation_backoff
                .lock()
                .get(wallet_id)
                .is_some_and(|(_, until)| *until > now_ms)
            {
                return Err(protocol(
                    ProtocolErrorCode::CeremonyRateLimited,
                    "wallet ceremony is in cancellation backoff",
                ));
            }
        } else if anonymous_registration {
            let recent = sessions
                .values()
                .filter(|session| {
                    session.anonymous_registration
                        && session.created_at_ms.saturating_add(CREATION_WINDOW_MS) > now_ms
                })
                .count();
            if recent >= MAX_ANONYMOUS_REGISTRATIONS {
                return Err(protocol(
                    ProtocolErrorCode::CeremonyRateLimited,
                    "anonymous registration rolling creation quota is exhausted",
                ));
            }
        }
        Ok(())
    }

    fn stable_approval_response(
        &self,
        operation_id: &OperationId,
        request_digest: &Digest32,
    ) -> Option<Result<SealedApprovalPrepareResponse, ProtocolError>> {
        let id = self.inner.operations.lock().get(operation_id)?.clone();
        let sessions = self.inner.sessions.lock();
        let session = sessions.get(&id)?;
        if &session.request_digest != request_digest {
            return Some(Err(operation_conflict()));
        }
        if session.state != CeremonyState::AwaitingUser {
            return Some(Err(replay()));
        }
        let manifest: ReviewManifest =
            serde_json::from_value(session.projection.review_manifest.clone()?).ok()?;
        Some(Ok(SealedApprovalPrepareResponse {
            approval_id: manifest.approval_id.clone(),
            state: ApprovalPrepareState::AwaitingCeremony,
            ceremony_url: session_url(&token_for(session)),
            ceremony_expires_at_ms: bloom_triad_protocol::DecimalU64::new(session.expires_at_ms),
            review_manifest_digest: digest(&manifest).ok()?,
        }))
    }

    fn stable_custody_response(
        &self,
        operation_id: &OperationId,
        request_digest: &Digest32,
    ) -> Option<Result<CustodyPrepareResponse, ProtocolError>> {
        let id = self.inner.operations.lock().get(operation_id)?.clone();
        let sessions = self.inner.sessions.lock();
        let session = sessions.get(&id)?;
        if &session.request_digest != request_digest {
            return Some(Err(operation_conflict()));
        }
        if is_terminal(session.state) {
            return Some(Err(replay()));
        }
        let contribution: CustodySignerContribution =
            serde_json::from_value(session.projection.signer_contribution.clone()).ok()?;
        Some(Ok(CustodyPrepareResponse {
            ceremony_kind: session.ceremony_kind,
            custody_operation_id: operation_id.clone(),
            state: CustodyPrepareState::AwaitingUser,
            ceremony_url: session_url(&token_for(session)),
            ceremony_expires_at_ms: bloom_triad_protocol::DecimalU64::new(session.expires_at_ms),
            signer_contribution_digest: contribution.digest().ok()?,
        }))
    }

    fn stable_policy_update_response(
        &self,
        operation_id: &OperationId,
        request_digest: &Digest32,
        review_manifest_digest: &Digest32,
    ) -> Option<Result<PolicyUpdatePrepareResponse, ProtocolError>> {
        let id = self.inner.operations.lock().get(operation_id)?.clone();
        let sessions = self.inner.sessions.lock();
        let session = sessions.get(&id)?;
        if &session.request_digest != request_digest {
            return Some(Err(operation_conflict()));
        }
        if is_terminal(session.state) {
            return Some(Err(replay()));
        }
        Some(Ok(PolicyUpdatePrepareResponse {
            operation_id: operation_id.clone(),
            ceremony_kind: CeremonyKind::PolicyUpdate,
            ceremony_url: session_url(&token_for(session)),
            ceremony_expires_at_ms: bloom_triad_protocol::DecimalU64::new(session.expires_at_ms),
            review_manifest_digest: review_manifest_digest.clone(),
        }))
    }

    fn record_backoff(&self, wallet_id: &Token, now_ms: u64) {
        let mut backoffs = self.inner.cancellation_backoff.lock();
        let (count, _) = backoffs.get(wallet_id).copied().unwrap_or((0, 0));
        let next_count = count.saturating_add(1);
        let multiplier = 1_u64
            .checked_shl(next_count.saturating_sub(1).min(5))
            .unwrap_or(32);
        backoffs.insert(
            wallet_id.clone(),
            (
                next_count,
                now_ms.saturating_add(CANCELLATION_BACKOFF_MS.saturating_mul(multiplier)),
            ),
        );
    }

    fn reload_and_reconcile_nonterminal(&self) -> Result<(), ProtocolError> {
        let database = self
            .inner
            .database
            .as_ref()
            .expect("open installs a ceremony database")
            .lock();
        let mut statement = database
            .prepare(
                "SELECT ceremony_id, operation_id, session_jcs
                 FROM ceremony_sessions",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        drop(statement);
        drop(database);

        for (ceremony_id, operation_id, encoded) in rows {
            let mut session: BrowserSession = serde_json::from_str(&encoded).map_err(malformed)?;
            let preserve_awaiting = session.state == CeremonyState::AwaitingRecoveryAck
                && session.expires_at_ms > unix_time_ms();
            if session.state == CeremonyState::AwaitingRecoveryAck && !preserve_awaiting {
                session.state = CeremonyState::Failed;
                session.terminal_at_ms = Some(unix_time_ms());
                session.token = None;
                session.token_hash = [0_u8; 32];
                self.persist_session(&session)?;
            } else if !preserve_awaiting
                && session.state != CeremonyState::WalletCommitted
                && !is_terminal(session.state)
            {
                match self.inner.signer.status(&session.operation_id)? {
                    SignerCeremonyStatus::CompletedApproval(receipt) => {
                        session.state = CeremonyState::WalletCommitted;
                        session.terminal_result =
                            Some(serde_json::to_value(receipt).map_err(malformed)?);
                    }
                    SignerCeremonyStatus::CompletedCustody(result) => {
                        session.state = CeremonyState::WalletCommitted;
                        session.terminal_result =
                            Some(serde_json::to_value(result).map_err(malformed)?);
                    }
                    SignerCeremonyStatus::Pending => {
                        self.inner.signer.cancel(&session.operation_id)?;
                        session.state = CeremonyState::Expired;
                    }
                    SignerCeremonyStatus::Missing => {
                        session.state = CeremonyState::Expired;
                    }
                }
                if session.state == CeremonyState::Expired {
                    session.terminal_at_ms = Some(unix_time_ms());
                    session.token = None;
                    session.token_hash = [0_u8; 32];
                } else if session.state == CeremonyState::WalletCommitted {
                    validate_completion_identity(
                        session.ceremony_kind,
                        &session.operation_id,
                        &session.projection.ceremony_id,
                        session.terminal_result.as_ref().ok_or_else(not_found)?,
                    )?;
                }
                self.persist_session(&session)?;
            }
            let parsed_operation = OperationId::new(operation_id)?;
            if parsed_operation != session.operation_id
                || ceremony_id != session.projection.ceremony_id.as_str()
            {
                return Err(protocol(
                    ProtocolErrorCode::MalformedFrame,
                    "durable ceremony index does not match its signed session",
                ));
            }
            self.inner
                .operations
                .lock()
                .insert(parsed_operation, ceremony_id.clone());
            self.inner.sessions.lock().insert(ceremony_id, session);
        }
        Ok(())
    }

    fn validate_review_manifest(
        &self,
        request: &CeremonyPrepareRequest,
        manifest: &ReviewManifest,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        let approval_id = request.terms.approval_id()?;
        let approval_digest = request.terms.approval_digest()?;
        let disclosures = review_disclosures(
            request,
            manifest.claim_assurance.as_ref(),
            manifest.petal_use_claim.as_ref(),
        );
        let canonical_plan = canonical_review_plan(request, &disclosures)?;
        if manifest.approval_id != approval_id
            || manifest.approval_digest != approval_digest
            || manifest.exact_payload_digests != request.exact_ordered_payload_digests
            || manifest.exact_hashes != request.exact_ordered_hashes
            || manifest.canonical_plan != canonical_plan
            || manifest.canonical_plan_digest
                != Digest32::from_bytes(Sha256::digest(canonical_plan.as_bytes()).into())
            || manifest.issued_at_ms.get() > now_ms
            || manifest.expires_at_ms.get() <= now_ms
            || manifest.expires_at_ms.get() > request.terms.expires_at_ms.get()
        {
            return Err(protocol(
                ProtocolErrorCode::SelectorMismatch,
                "review manifest is inconsistent with immutable approval terms",
            ));
        }
        Ok(())
    }

    fn build_review_manifest(
        &self,
        request: &CeremonyPrepareRequest,
        context: ReviewManifestContext,
        now_ms: u64,
    ) -> Result<ReviewManifest, ProtocolError> {
        let (broker_key_id, signing_key) =
            self.inner.manifest_signer.as_ref().ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    "Broker review-manifest signing key is unavailable",
                )
            })?;
        let disclosures = review_disclosures(
            request,
            context.claim_assurance.as_ref(),
            context.petal_use_claim.as_ref(),
        );
        let canonical_plan = canonical_review_plan(request, &disclosures)?;
        let mut manifest = ReviewManifest {
            schema: Token::new("bloom.review-manifest.v1")?,
            approval_id: request.terms.approval_id()?,
            approval_digest: request.terms.approval_digest()?,
            canonical_plan_digest: Digest32::from_bytes(
                Sha256::digest(canonical_plan.as_bytes()).into(),
            ),
            canonical_plan,
            exact_payload_digests: request.exact_ordered_payload_digests.clone(),
            exact_hashes: request.exact_ordered_hashes.clone(),
            petal_use_claim: context.petal_use_claim,
            claim_assurance: context.claim_assurance,
            attributed_advisory_items: context.attributed_advisory_items,
            issued_at_ms: bloom_triad_protocol::DecimalU64::new(now_ms),
            expires_at_ms: request.terms.expires_at_ms.clone(),
            broker_key_id: broker_key_id.clone(),
            broker_signature: Base64UrlBytes::from_bytes(&[]),
        };
        manifest.broker_signature = Base64UrlBytes::from_bytes(
            &signing_key
                .sign(
                    &[
                        REVIEW_MANIFEST_DOMAIN,
                        manifest.unsigned_canonical_bytes()?.as_slice(),
                    ]
                    .concat(),
                )
                .to_bytes(),
        );
        Ok(manifest)
    }

    fn verify_browser_proof(
        &self,
        wallet_id: Option<&Token>,
        projection: &BrowserProjection,
        verification_credentials: &[WebAuthnCredential],
        proof: &WebAuthnCeremonyProof,
    ) -> Result<(), ProtocolError> {
        let challenge = |index: usize| {
            projection
                .challenges
                .get(index)
                .ok_or_else(kind_mismatch)?
                .binding
                .canonical_bytes()
        };
        let verify_assertion = |assertion: &bloom_triad_protocol::WebAuthnAssertion,
                                index: usize|
         -> Result<(), ProtocolError> {
            wallet_id.ok_or_else(kind_mismatch)?;
            let credential = verification_credentials
                .iter()
                .find(|credential| credential.credential_id == assertion.credential_id)
                .ok_or_else(kind_mismatch)?;
            if projection
                .webauthn_options
                .allowed_credentials
                .iter()
                .all(|allowed| allowed.credential_id != credential.credential_id)
            {
                return Err(kind_mismatch());
            }
            verify_webauthn_assertion(assertion, credential, &challenge(index)?, true)?;
            Ok(())
        };
        let verify_attestation = |attestation: &bloom_triad_protocol::WebAuthnAttestation,
                                  index: usize|
         -> Result<WebAuthnCredential, ProtocolError> {
            verify_webauthn_attestation(
                attestation,
                &challenge(index)?,
                projection
                    .webauthn_options
                    .registration_user_handle
                    .clone()
                    .ok_or_else(kind_mismatch)?,
                projection
                    .webauthn_options
                    .registration_prf_salt
                    .clone()
                    .ok_or_else(kind_mismatch)?,
            )
        };
        match proof {
            WebAuthnCeremonyProof::Assertion { assertion } => verify_assertion(assertion, 0),
            WebAuthnCeremonyProof::Registration {
                attestation,
                prf_assertion,
            } => {
                let credential = verify_attestation(attestation, 0)?;
                if let Some(assertion) = prf_assertion {
                    verify_webauthn_assertion(assertion, &credential, &challenge(1)?, true)?;
                }
                Ok(())
            }
            WebAuthnCeremonyProof::AuthorityCredentialChange {
                authority_assertion,
                new_credential_attestation,
                new_credential_prf_assertion,
            } => {
                verify_assertion(authority_assertion, 0)?;
                let credential = verify_attestation(new_credential_attestation, 1)?;
                if let Some(assertion) = new_credential_prf_assertion {
                    verify_webauthn_assertion(assertion, &credential, &challenge(2)?, true)?;
                }
                Ok(())
            }
            WebAuthnCeremonyProof::RecoveryCredentialChange {
                new_credential_attestation,
                new_credential_prf_assertion,
            } => {
                let credential = verify_attestation(new_credential_attestation, 0)?;
                if let Some(assertion) = new_credential_prf_assertion {
                    verify_webauthn_assertion(assertion, &credential, &challenge(1)?, true)?;
                }
                Ok(())
            }
        }
    }

    fn persist_session(&self, session: &BrowserSession) -> Result<(), ProtocolError> {
        let Some(database) = &self.inner.database else {
            return Ok(());
        };
        let encoded =
            String::from_utf8(serde_jcs::to_vec(session).map_err(malformed)?).map_err(malformed)?;
        database
            .lock()
            .execute(
                "INSERT INTO ceremony_sessions(ceremony_id, operation_id, session_jcs)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(ceremony_id) DO UPDATE SET
                    operation_id = excluded.operation_id,
                    session_jcs = excluded.session_jcs",
                params![
                    session.projection.ceremony_id.as_str(),
                    session.operation_id.as_str(),
                    encoded
                ],
            )
            .map_err(storage)?;
        Ok(())
    }

    fn notify_completion(
        &self,
        ceremony_kind: CeremonyKind,
        receipt: &serde_json::Value,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        let Some(observer) = self.inner.completion_observer.lock().clone() else {
            return Ok(());
        };
        if ceremony_kind == CeremonyKind::SealedApproval {
            let receipt: SignerActivationReceipt =
                serde_json::from_value(receipt.clone()).map_err(malformed)?;
            observer.approval_completed(&receipt, now_ms)
        } else {
            let receipt: CustodyResult =
                serde_json::from_value(receipt.clone()).map_err(malformed)?;
            observer.custody_completed(&receipt)
        }
    }

    fn finalize_committed_session(
        &self,
        ceremony_id: &str,
        now_ms: u64,
    ) -> Result<serde_json::Value, ProtocolError> {
        let committed = {
            let sessions = self.inner.sessions.lock();
            let session = sessions.get(ceremony_id).ok_or_else(not_found)?;
            if session.state != CeremonyState::WalletCommitted {
                return Err(protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    "ceremony receipt is not awaiting Broker adoption",
                ));
            }
            session.clone()
        };
        let receipt = committed.terminal_result.clone().ok_or_else(|| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                "committed ceremony omitted its durable Signer receipt",
            )
        })?;

        // Adoption is deliberately after the signed receipt is durable. Every
        // observer operation is idempotent, so a failure leaves WALLET_COMMITTED
        // retryable across the same request and process restart.
        self.notify_completion(committed.ceremony_kind, &receipt, now_ms)?;

        let has_sensitive_output = receipt
            .get("encrypted_browser_result")
            .is_some_and(|value| !value.is_null());
        let mut finalized = committed;
        if has_sensitive_output {
            finalized.state = CeremonyState::AwaitingRecoveryAck;
            finalized.expires_at_ms = now_ms.saturating_add(OUTPUT_ACK_TTL_MS);
        } else {
            finalized.state = finalized
                .ceremony_kind
                .successful_terminal_state()
                .unwrap_or(CeremonyState::Completed);
            finalized.terminal_at_ms = Some(now_ms);
            finalized.token = None;
            finalized.token_hash = [0_u8; 32];
        }
        self.persist_session(&finalized)?;
        self.inner
            .sessions
            .lock()
            .insert(ceremony_id.to_owned(), finalized);
        Ok(receipt)
    }
}

async fn shell(headers: HeaderMap) -> Response {
    if validate_host(&headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    Html(SHELL_HTML).into_response()
}

async fn ceremony_shell(
    State(broker): State<CeremonyBroker>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    if validate_host(&headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if broker.expire_sessions(unix_time_ms()).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if broker.ceremony_for_encoded_token(&token).is_none() {
        broker.record_invalid_browser_token();
        return StatusCode::NOT_FOUND.into_response();
    }
    Html(SHELL_HTML).into_response()
}

async fn app_js(headers: HeaderMap) -> Response {
    if validate_host(&headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        APP_JS,
    )
        .into_response()
}

async fn read_session(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if validate_host(&headers).is_err()
        || broker
            .authorize_browser(&ceremony_id, &headers, false)
            .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let sessions = broker.inner.sessions.lock();
    let Some(session) = sessions.get(&ceremony_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(&session.projection).into_response()
}

async fn read_session_by_token(
    State(broker): State<CeremonyBroker>,
    headers: HeaderMap,
) -> Response {
    let ceremony_id = match broker.authorize_browser_token(&headers) {
        Ok(ceremony_id) => ceremony_id,
        Err(_) => return StatusCode::FORBIDDEN.into_response(),
    };
    let sessions = broker.inner.sessions.lock();
    let Some(session) = sessions.get(&ceremony_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(&session.projection).into_response()
}

async fn read_result(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if validate_host(&headers).is_err()
        || broker
            .authorize_browser(&ceremony_id, &headers, false)
            .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let sessions = broker.inner.sessions.lock();
    let Some(session) = sessions.get(&ceremony_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !matches!(
        session.state,
        CeremonyState::WalletCommitted | CeremonyState::AwaitingRecoveryAck
    ) {
        return StatusCode::CONFLICT.into_response();
    }
    session
        .terminal_result
        .as_ref()
        .map(|result| Json(result).into_response())
        .unwrap_or_else(|| StatusCode::CONFLICT.into_response())
}

async fn acknowledge_result(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(_body): Json<BrowserAck>,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, true)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let snapshot = {
        let sessions = broker.inner.sessions.lock();
        let Some(session) = sessions.get(&ceremony_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if session.state != CeremonyState::AwaitingRecoveryAck {
            return StatusCode::CONFLICT.into_response();
        }
        let mut snapshot = session.clone();
        snapshot.state = snapshot
            .ceremony_kind
            .successful_terminal_state()
            .unwrap_or(CeremonyState::Completed);
        snapshot.terminal_at_ms = Some(unix_time_ms());
        snapshot.token = None;
        snapshot.token_hash = [0_u8; 32];
        snapshot
    };
    if broker.persist_session(&snapshot).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    broker.inner.sessions.lock().insert(ceremony_id, snapshot);
    StatusCode::NO_CONTENT.into_response()
}

async fn complete_session(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<BrowserComplete>,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, true)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let (ceremony_kind, operation_id, wallet_id, projection, verifying_snapshot) = {
        let mut sessions = broker.inner.sessions.lock();
        let Some(session) = sessions.get_mut(&ceremony_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if session.state == CeremonyState::AwaitingRecoveryAck {
            return session
                .terminal_result
                .as_ref()
                .map(|result| Json(result).into_response())
                .unwrap_or_else(|| StatusCode::CONFLICT.into_response());
        }
        if session.state == CeremonyState::WalletCommitted {
            drop(sessions);
            return match broker.finalize_committed_session(&ceremony_id, unix_time_ms()) {
                Ok(result) => Json(result).into_response(),
                Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response(),
            };
        }
        if is_terminal(session.state) {
            return StatusCode::CONFLICT.into_response();
        }
        session.state = CeremonyState::Verifying;
        (
            session.ceremony_kind,
            session.operation_id.clone(),
            session.wallet_id.clone(),
            session.projection.clone(),
            session.clone(),
        )
    };
    if broker.persist_session(&verifying_snapshot).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(error) = broker.verify_browser_proof(
        wallet_id.as_ref(),
        &projection,
        &verifying_snapshot.verification_credentials,
        &body.proof,
    ) {
        if broker.inner.signer.cancel(&operation_id).is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        if let Some(session) = broker.inner.sessions.lock().get_mut(&ceremony_id) {
            session.state = CeremonyState::Failed;
            session.terminal_at_ms = Some(unix_time_ms());
            session.token = None;
            session.token_hash = [0_u8; 32];
            let snapshot = session.clone();
            let _ = broker.persist_session(&snapshot);
        }
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }
    let result = if ceremony_kind == CeremonyKind::SealedApproval {
        let contribution: SignerCeremonyContribution =
            match serde_json::from_value(projection.signer_contribution.clone()) {
                Ok(value) => value,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
        broker
            .inner
            .signer
            .complete_approval(
                CeremonyCompleteRequest {
                    activation_operation_id: operation_id.clone(),
                    proof: body.proof,
                    contribution,
                    encrypted_local_prf: body.encrypted_input,
                },
                unix_time_ms(),
            )
            .and_then(|receipt| serde_json::to_value(receipt).map_err(malformed))
    } else if ceremony_kind == CeremonyKind::PolicyUpdate {
        broker
            .inner
            .signer
            .complete_policy_update(
                PolicyUpdateCeremonyCompleteRequest {
                    custody: CustodyCompleteRequest {
                        ceremony_kind,
                        custody_operation_id: operation_id.clone(),
                        ceremony_id: projection.ceremony_id.clone(),
                        proof: body.proof,
                        encrypted_input: body.encrypted_input,
                        public_binding_digest: body.public_binding_digest,
                    },
                },
                unix_time_ms(),
            )
            .and_then(|receipt| serde_json::to_value(receipt).map_err(malformed))
    } else {
        broker
            .inner
            .signer
            .complete_custody(
                CustodyCompleteRequest {
                    ceremony_kind,
                    custody_operation_id: operation_id.clone(),
                    ceremony_id: projection.ceremony_id.clone(),
                    proof: body.proof,
                    encrypted_input: body.encrypted_input,
                    public_binding_digest: body.public_binding_digest,
                },
                unix_time_ms(),
            )
            .and_then(|receipt| serde_json::to_value(receipt).map_err(malformed))
    };
    match result {
        Ok(receipt) => {
            if let Err(error) = validate_completion_identity(
                ceremony_kind,
                &operation_id,
                &projection.ceremony_id,
                &receipt,
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
            }
            let committed = {
                let sessions = broker.inner.sessions.lock();
                let Some(session) = sessions.get(&ceremony_id) else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                };
                let mut committed = session.clone();
                committed.state = CeremonyState::WalletCommitted;
                committed.terminal_result = Some(receipt);
                committed
            };
            if broker.persist_session(&committed).is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            broker
                .inner
                .sessions
                .lock()
                .insert(ceremony_id.clone(), committed);
            match broker.finalize_committed_session(&ceremony_id, unix_time_ms()) {
                Ok(receipt) => Json(receipt).into_response(),
                Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response(),
            }
        }
        Err(error) => {
            let mut sessions = broker.inner.sessions.lock();
            let Some(session) = sessions.get_mut(&ceremony_id) else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            session.state = CeremonyState::Failed;
            session.terminal_at_ms = Some(unix_time_ms());
            session.token = None;
            session.token_hash = [0_u8; 32];
            let snapshot = session.clone();
            if broker.persist_session(&snapshot).is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            (StatusCode::BAD_REQUEST, Json(error)).into_response()
        }
    }
}

async fn bind_output_key(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<BrowserOutputKey>,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, true)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let operation_id = {
        let sessions = broker.inner.sessions.lock();
        let Some(session) = sessions.get(&ceremony_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if session.state != CeremonyState::AwaitingUser {
            return StatusCode::CONFLICT.into_response();
        }
        session.operation_id.clone()
    };
    let prepared = match broker.inner.signer.bind_custody_output_recipient(
        &operation_id,
        body.recipient_key,
        unix_time_ms(),
    ) {
        Ok(prepared) => prepared,
        Err(error) => return (StatusCode::BAD_REQUEST, Json(error)).into_response(),
    };
    let projection = {
        let mut sessions = broker.inner.sessions.lock();
        let Some(session) = sessions.get_mut(&ceremony_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if prepared.contribution.ceremony_id != session.projection.ceremony_id {
            return StatusCode::CONFLICT.into_response();
        }
        session.projection.signer_contribution = match serde_json::to_value(prepared.contribution) {
            Ok(value) => value,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        session.projection.challenges = match prepared
            .challenges
            .into_iter()
            .map(|binding| {
                let challenge = binding.webauthn_challenge()?;
                Ok(BrowserChallenge { binding, challenge })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()
        {
            Ok(challenges) => challenges,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        session.projection.webauthn_options = prepared.webauthn_options;
        let snapshot = session.clone();
        if broker.persist_session(&snapshot).is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        session.projection.clone()
    };
    Json(projection).into_response()
}

async fn cancel_session(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, true)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let operation = broker
        .inner
        .sessions
        .lock()
        .get(&ceremony_id)
        .map(|session| session.operation_id.clone());
    match operation {
        Some(operation) if broker.cancel(&operation, unix_time_ms()).is_ok() => {
            StatusCode::NO_CONTENT.into_response()
        }
        Some(_) => StatusCode::CONFLICT.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

impl CeremonyBroker {
    fn ceremony_for_encoded_token(&self, encoded: &str) -> Option<String> {
        let supplied = Base64UrlBytes::parse(encoded.to_owned())
            .ok()
            .filter(|value| value.decode().len() == 32)?;
        let hash = <[u8; 32]>::from(Sha256::digest(supplied.decode()));
        self.inner
            .sessions
            .lock()
            .iter()
            .find_map(|(ceremony_id, session)| {
                (session.token_hash == hash).then(|| ceremony_id.clone())
            })
    }

    fn authorize_browser_token(&self, headers: &HeaderMap) -> Result<String, ProtocolError> {
        self.expire_sessions(unix_time_ms())?;
        validate_host(headers)?;
        let ceremony_id = headers
            .get("x-bloom-ceremony-token")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| self.ceremony_for_encoded_token(value));
        if let Some(ceremony_id) = ceremony_id {
            return Ok(ceremony_id);
        }
        let rate_limited = self.record_invalid_browser_token();
        Err(protocol(
            if rate_limited {
                ProtocolErrorCode::CeremonyRateLimited
            } else {
                ProtocolErrorCode::UnauthenticatedPeer
            },
            "invalid ceremony session token",
        ))
    }

    fn authorize_browser(
        &self,
        ceremony_id: &str,
        headers: &HeaderMap,
        mutation: bool,
    ) -> Result<(), ProtocolError> {
        self.expire_sessions(unix_time_ms())?;
        validate_host(headers)?;
        if mutation {
            require_exact_header(headers, header::ORIGIN, CEREMONY_ORIGIN)?;
            require_exact_header(headers, header::CONTENT_TYPE, "application/json")?;
            require_exact_header_name(headers, "sec-fetch-site", "same-origin")?;
        }
        let supplied = headers
            .get("x-bloom-ceremony-token")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Base64UrlBytes::parse(value.to_owned()).ok())
            .filter(|value| value.decode().len() == 32);
        let sessions = self.inner.sessions.lock();
        let expected = sessions.get(ceremony_id).map(|session| session.token_hash);
        let valid = supplied
            .map(|token| {
                Sha256::digest(token.decode()).as_slice()
                    == expected.as_ref().map(<[u8; 32]>::as_slice).unwrap_or(&[])
            })
            .unwrap_or(false);
        drop(sessions);
        if !valid {
            let rate_limited = self.record_invalid_browser_token();
            return Err(protocol(
                if rate_limited {
                    ProtocolErrorCode::CeremonyRateLimited
                } else {
                    ProtocolErrorCode::UnauthenticatedPeer
                },
                "invalid ceremony session token",
            ));
        }
        Ok(())
    }

    fn record_invalid_browser_token(&self) -> bool {
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut attempts = self.inner.invalid_attempts.lock();
        let count = attempts.entry(source).or_default();
        *count = count.saturating_add(1);
        *count > INVALID_ATTEMPT_LIMIT
    }
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // This marker is diagnostic only. It lets a Machine whose authenticated
    // Unix edge is unavailable report that a Bloom-shaped listener appears to
    // occupy the canonical port. It conveys no authority, can be imitated by
    // a foreign process, and never substitutes for the session token.
    headers.insert(
        HeaderName::from_static(CEREMONY_OWNER_HEADER),
        HeaderValue::from_static(CEREMONY_OWNER_VALUE),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn validate_host(headers: &HeaderMap) -> Result<(), ProtocolError> {
    require_exact_header(headers, header::HOST, "localhost:18734")
}

fn require_exact_header(
    headers: &HeaderMap,
    name: header::HeaderName,
    expected: &str,
) -> Result<(), ProtocolError> {
    if headers.get(name).and_then(|value| value.to_str().ok()) == Some(expected) {
        Ok(())
    } else {
        Err(protocol(
            ProtocolErrorCode::UnauthenticatedPeer,
            "ceremony request has an invalid security header",
        ))
    }
}

fn require_exact_header_name(
    headers: &HeaderMap,
    name: &'static str,
    expected: &str,
) -> Result<(), ProtocolError> {
    require_exact_header(headers, HeaderName::from_static(name), expected)
}

fn session_url(token: &Base64UrlBytes) -> String {
    format!("{CEREMONY_ORIGIN}/ceremony/{}", token.encoded())
}

fn token_for(session: &BrowserSession) -> Base64UrlBytes {
    session
        .token
        .clone()
        .unwrap_or_else(|| Base64UrlBytes::from_bytes(&[]))
}

fn is_terminal(state: CeremonyState) -> bool {
    matches!(
        state,
        CeremonyState::Completed
            | CeremonyState::Succeeded
            | CeremonyState::Cancelled
            | CeremonyState::Expired
            | CeremonyState::Failed
    )
}

fn validate_completion_identity(
    ceremony_kind: CeremonyKind,
    operation_id: &OperationId,
    ceremony_id: &Digest32,
    value: &serde_json::Value,
) -> Result<(), ProtocolError> {
    if ceremony_kind == CeremonyKind::SealedApproval {
        let receipt: SignerActivationReceipt =
            serde_json::from_value(value.clone()).map_err(malformed)?;
        if &receipt.activation_operation_id != operation_id || &receipt.ceremony_id != ceremony_id {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "Signer approval receipt changed the prepared ceremony identity",
            ));
        }
    } else {
        let receipt: CustodyResult = serde_json::from_value(value.clone()).map_err(malformed)?;
        if receipt.ceremony_kind != ceremony_kind {
            return Err(protocol(
                ProtocolErrorCode::CeremonyKindMismatch,
                "Signer custody receipt changed the prepared ceremony kind",
            ));
        }
        if &receipt.custody_operation_id != operation_id
            || Some(receipt.public_status) != ceremony_kind.successful_terminal_state()
        {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "Signer custody receipt changed the prepared operation or completion state",
            ));
        }
    }
    Ok(())
}

fn digest(value: &impl Serialize) -> Result<Digest32, ProtocolError> {
    Ok(Digest32::from_bytes(
        Sha256::digest(serde_jcs::to_vec(value).map_err(malformed)?).into(),
    ))
}

fn canonical_review_plan(
    request: &CeremonyPrepareRequest,
    security_disclosures: &[String],
) -> Result<String, ProtocolError> {
    #[derive(Serialize)]
    struct Plan<'a> {
        schema: &'static str,
        terms: &'a bloom_triad_protocol::SealedApprovalTerms,
        exact_ordered_payload_digests: &'a [Digest32],
        exact_ordered_hashes: &'a [Digest32],
        replacement_approval_id: &'a Option<Digest32>,
        security_disclosures: &'a [String],
    }
    serde_jcs::to_string(&Plan {
        schema: "bloom-review-plan/v1",
        terms: &request.terms,
        exact_ordered_payload_digests: &request.exact_ordered_payload_digests,
        exact_ordered_hashes: &request.exact_ordered_hashes,
        replacement_approval_id: &request.replacement_approval_id,
        security_disclosures,
    })
    .map_err(malformed)
}

fn review_disclosures(
    request: &CeremonyPrepareRequest,
    assurance: Option<&bloom_triad_protocol::ClaimAssurance>,
    claim: Option<&bloom_triad_protocol::PetalUseClaim>,
) -> Vec<String> {
    let mut disclosures = Vec::new();
    if !request.exact_ordered_payload_digests.is_empty() || !request.exact_ordered_hashes.is_empty()
    {
        disclosures.push(
            "Bloom has not established the execution effects of these opaque payload digests and hashes."
                .to_owned(),
        );
    }
    let machine_asserted = matches!(
        assurance,
        Some(bloom_triad_protocol::ClaimAssurance::MachineAsserted)
    ) || claim.is_some_and(|claim| {
        matches!(
            claim.claim_assurance,
            bloom_triad_protocol::ClaimAssurance::MachineAsserted
        )
    }) || matches!(
        request.terms.selector,
        bloom_triad_protocol::ApprovalSelector::Petal { .. }
    ) && assurance.is_none();
    if machine_asserted {
        disclosures.push(
            "The displayed limits are asserted by the named Petal. Bloom does not verify them against the payload, and a compromised Petal or Machine can consume the full remaining capacity."
                .to_owned(),
        );
    }
    disclosures
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn not_found() -> ProtocolError {
    protocol(ProtocolErrorCode::ApprovalNotFound, "ceremony not found")
}

fn kind_mismatch() -> ProtocolError {
    protocol(
        ProtocolErrorCode::CeremonyKindMismatch,
        "sealed approval and custody ceremony kinds cannot be interchanged",
    )
}

fn operation_conflict() -> ProtocolError {
    protocol(
        ProtocolErrorCode::OperationIdConflict,
        "ceremony operation ID was reused with different stable input",
    )
}

fn replay() -> ProtocolError {
    protocol(
        ProtocolErrorCode::CeremonyReplay,
        "ceremony is terminal and its launch URL cannot be revived",
    )
}

fn malformed(error: impl std::fmt::Display) -> ProtocolError {
    protocol(ProtocolErrorCode::MalformedFrame, error.to_string())
}

fn storage(error: impl std::fmt::Display) -> ProtocolError {
    protocol(
        ProtocolErrorCode::ServiceUnavailable,
        format!("ceremony durability failure: {error}"),
    )
}

fn protocol(code: ProtocolErrorCode, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}
