use crate::{
    authority::PolicyAuthorityDiff,
    journal::BrokerJournal,
    translation::{
        ceremony::{kind_to_machine, state_to_machine},
        error::signer_error_to_machine,
    },
};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use bloom_broker_api::{
    ApprovalPrepareState, CeremonyKind as BrokerCeremonyKind,
    CeremonyPublicStatus as BrokerCeremonyPublicStatus, CeremonyState as BrokerCeremonyState,
    ClaimAssurance, CustodyPrepareResponse, CustodyPrepareState, PetalUseClaim,
    PolicyUpdatePrepareResponse, ProtocolError, ProtocolErrorCode, RateLimitDetails,
    SealedApprovalPrepareResponse, SystemUseClaim,
};
use bloom_signer_api::{
    Base64UrlBytes, CeremonyChallenge, CeremonyCompleteRequest, CeremonyKind,
    CeremonyPrepareRequest, CeremonyState, CeremonyWebAuthnOptions, CustodyCompleteRequest,
    CustodyPrepareRequest, CustodyResult, CustodySignerContribution, DecimalU64, Digest32,
    HpkeEnvelope, OperationId, PolicyUpdateCeremonyCompleteRequest,
    PolicyUpdateCeremonyPrepareRequest, ProtocolError as SignerProtocolError,
    ProtocolErrorCode as SignerProtocolErrorCode, SignerActivationReceipt,
    SignerCeremonyContribution, SignerCeremonyStatus, SignerPreparedApproval,
    SignerPreparedCustody, Token, WebAuthnCeremonyProof, WebAuthnCredential,
};
use ed25519_dalek::{Signer as _, SigningKey};
use parking_lot::Mutex;
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    path::Path as FsPath,
    sync::Arc,
};

pub const CEREMONY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_734);
pub const CEREMONY_ORIGIN: &str = "http://localhost:18734";
pub const MAX_CEREMONY_BODY_BYTES: usize = 16 * 1024;
pub const CEREMONY_OWNER_HEADER: &str = "x-bloom-ceremony-owner";
pub const CEREMONY_OWNER_VALUE: &str = "bloom-broker-v1";
const INVALID_ATTEMPT_LIMIT: u32 = 8;
const CANCELLATION_BACKOFF_MS: u64 = 2_000;
const REVIEW_MANIFEST_DOMAIN: &[u8] = b"bloom-broker-review-manifest/v1";
const OUTPUT_ACK_TTL_MS: u64 = 5 * 60 * 1_000;

/// Compiled default bound on simultaneously live ceremony sessions. This is
/// the independent limit on concurrent resource usage; the rolling creation
/// quotas below bound sustained throughput instead.
pub const DEFAULT_MAXIMUM_CONCURRENT_SESSIONS: usize = 16;
/// Compiled default rolling creation window, shared by both creation quotas.
pub const DEFAULT_CREATION_WINDOW_MS: u64 = 5 * 60 * 1_000;
/// Compiled default authenticated wallet creations per rolling window: 12 per
/// five minutes, a sustained 2.4 creations per minute.
pub const DEFAULT_MAXIMUM_CREATIONS_PER_WALLET: usize = 12;
/// Compiled default anonymous registrations per rolling window. Anonymous
/// creation is unauthenticated, so it stays deliberately tighter than the
/// per-wallet quota.
pub const DEFAULT_MAXIMUM_ANONYMOUS_REGISTRATIONS: usize = 4;

/// Ceilings that keep a configured value inside what the admission
/// calculations can represent and what one Broker process can actually hold
/// open. They are not policy: policy is the configured value below them.
const MAXIMUM_SESSIONS_CEILING: usize = 1_024;
const MAXIMUM_CREATIONS_CEILING: usize = 1_024;
const CREATION_WINDOW_CEILING_MS: u64 = 24 * 60 * 60 * 1_000;

/// The four global ceremony admission limits.
///
/// One policy for the whole Broker: nothing here is selected per wallet or per
/// ceremony kind, so no request can widen the quota that judges it.
///
/// The fields are private and every way in validates, so a `CeremonyLimits`
/// value is in range by construction: there is no zero window for the retry
/// arithmetic to divide a caller out of, and no zero quota to silently close
/// the Broker. [`Self::new`] is the only literal constructor,
/// [`Self::default`] is the compiled policy, and the [`Deserialize`] impl —
/// the path [`crate::config`] merges through — runs the same checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CeremonyLimits {
    maximum_concurrent_sessions: usize,
    creation_window_ms: u64,
    maximum_creations_per_wallet: usize,
    maximum_anonymous_registrations: usize,
}

impl Default for CeremonyLimits {
    fn default() -> Self {
        Self {
            maximum_concurrent_sessions: DEFAULT_MAXIMUM_CONCURRENT_SESSIONS,
            creation_window_ms: DEFAULT_CREATION_WINDOW_MS,
            maximum_creations_per_wallet: DEFAULT_MAXIMUM_CREATIONS_PER_WALLET,
            maximum_anonymous_registrations: DEFAULT_MAXIMUM_ANONYMOUS_REGISTRATIONS,
        }
    }
}

impl<'de> Deserialize<'de> for CeremonyLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            maximum_concurrent_sessions: usize,
            creation_window_ms: u64,
            maximum_creations_per_wallet: usize,
            maximum_anonymous_registrations: usize,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        Self::new(
            unchecked.maximum_concurrent_sessions,
            unchecked.creation_window_ms,
            unchecked.maximum_creations_per_wallet,
            unchecked.maximum_anonymous_registrations,
        )
        .map_err(|error| serde::de::Error::custom(error.message))
    }
}

impl CeremonyLimits {
    /// Build a policy, rejecting any value that would disable admission
    /// control or overflow the window arithmetic. The error names the field
    /// and its environment override so an operator can fix the deployment
    /// rather than read Broker's source.
    pub fn new(
        maximum_concurrent_sessions: usize,
        creation_window_ms: u64,
        maximum_creations_per_wallet: usize,
        maximum_anonymous_registrations: usize,
    ) -> Result<Self, ProtocolError> {
        bounded(
            "maximum_concurrent_sessions",
            maximum_concurrent_sessions as u64,
            MAXIMUM_SESSIONS_CEILING as u64,
        )?;
        bounded(
            "creation_window_ms",
            creation_window_ms,
            CREATION_WINDOW_CEILING_MS,
        )?;
        bounded(
            "maximum_creations_per_wallet",
            maximum_creations_per_wallet as u64,
            MAXIMUM_CREATIONS_CEILING as u64,
        )?;
        bounded(
            "maximum_anonymous_registrations",
            maximum_anonymous_registrations as u64,
            MAXIMUM_CREATIONS_CEILING as u64,
        )?;
        Ok(Self {
            maximum_concurrent_sessions,
            creation_window_ms,
            maximum_creations_per_wallet,
            maximum_anonymous_registrations,
        })
    }

    pub fn maximum_concurrent_sessions(&self) -> usize {
        self.maximum_concurrent_sessions
    }

    pub fn creation_window_ms(&self) -> u64 {
        self.creation_window_ms
    }

    pub fn maximum_creations_per_wallet(&self) -> usize {
        self.maximum_creations_per_wallet
    }

    pub fn maximum_anonymous_registrations(&self) -> usize {
        self.maximum_anonymous_registrations
    }

    /// The four effective values, and nothing else. Safe to log: none of them
    /// identifies a wallet, and none of them is secret.
    pub fn effective_summary(&self) -> String {
        format!(
            "maximum_concurrent_sessions={} creation_window_ms={} \
             maximum_creations_per_wallet={} maximum_anonymous_registrations={}",
            self.maximum_concurrent_sessions,
            self.creation_window_ms,
            self.maximum_creations_per_wallet,
            self.maximum_anonymous_registrations,
        )
    }
}

fn bounded(field: &str, value: u64, ceiling: u64) -> Result<(), ProtocolError> {
    if value == 0 || value > ceiling {
        // Zero would admit nothing at all for concurrency and everything at
        // once for a window, so it is a configuration error either way.
        return Err(protocol(
            ProtocolErrorCode::MalformedFrame,
            format!(
                "ceremony_limits.{field} must be between 1 and {ceiling}, but is {value}; \
                 correct it in the Broker configuration file or set {}_CEREMONY_LIMITS{}{}",
                crate::config::ENVIRONMENT_PREFIX,
                crate::config::ENVIRONMENT_SEPARATOR,
                field.to_uppercase(),
            ),
        ));
    }
    Ok(())
}

const SHELL_HTML: &str = include_str!("ceremony_assets/index.html");
const APP_JS: &str = include_str!("ceremony_assets/app.js");
const STYLE_CSS: &str = include_str!("ceremony_assets/style.css");
const BLOOM_PRIMARY_SVG: &str = include_str!("ceremony_assets/bloom-primary.svg");

#[derive(Clone, Debug, Default)]
pub struct ReviewManifestContext {
    pub petal_use_claim: Option<PetalUseClaim>,
    pub system_use_claim: Option<SystemUseClaim>,
    pub claim_assurance: Option<ClaimAssurance>,
    pub attributed_advisory_items: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewManifest {
    pub schema: Token,
    pub approval_id: Digest32,
    pub approval_digest: Digest32,
    pub canonical_plan: String,
    pub canonical_plan_digest: Digest32,
    pub exact_payload_digests: Vec<Digest32>,
    pub exact_hashes: Vec<Digest32>,
    pub petal_use_claim: Option<PetalUseClaim>,
    pub system_use_claim: Option<SystemUseClaim>,
    pub claim_assurance: Option<ClaimAssurance>,
    pub attributed_advisory_items: Vec<String>,
    pub issued_at_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub broker_key_id: Token,
    pub broker_signature: Base64UrlBytes,
}

impl ReviewManifest {
    fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            schema: &'a Token,
            approval_id: &'a Digest32,
            approval_digest: &'a Digest32,
            canonical_plan: &'a str,
            canonical_plan_digest: &'a Digest32,
            exact_payload_digests: &'a [Digest32],
            exact_hashes: &'a [Digest32],
            petal_use_claim: &'a Option<PetalUseClaim>,
            system_use_claim: &'a Option<SystemUseClaim>,
            claim_assurance: &'a Option<ClaimAssurance>,
            attributed_advisory_items: &'a [String],
            issued_at_ms: &'a DecimalU64,
            expires_at_ms: &'a DecimalU64,
            broker_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            schema: &self.schema,
            approval_id: &self.approval_id,
            approval_digest: &self.approval_digest,
            canonical_plan: &self.canonical_plan,
            canonical_plan_digest: &self.canonical_plan_digest,
            exact_payload_digests: &self.exact_payload_digests,
            exact_hashes: &self.exact_hashes,
            petal_use_claim: &self.petal_use_claim,
            system_use_claim: &self.system_use_claim,
            claim_assurance: &self.claim_assurance,
            attributed_advisory_items: &self.attributed_advisory_items,
            issued_at_ms: &self.issued_at_ms,
            expires_at_ms: &self.expires_at_ms,
            broker_key_id: &self.broker_key_id,
        })
        .map_err(malformed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyUpdateReviewManifest {
    pub schema: Token,
    pub operation_id: OperationId,
    pub wallet_id: Token,
    pub baseline_version: DecimalU64,
    pub baseline_digest: Digest32,
    pub proposed_policy_digest: Digest32,
    pub authority_diff_digest: Digest32,
    pub authority_diff: PolicyAuthorityDiff,
    pub assurance_level: Token,
    pub issued_at_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub broker_key_id: Token,
    pub broker_signature: Base64UrlBytes,
}

impl PolicyUpdateReviewManifest {
    pub(crate) fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            schema: &'a Token,
            operation_id: &'a OperationId,
            wallet_id: &'a Token,
            baseline_version: &'a DecimalU64,
            baseline_digest: &'a Digest32,
            proposed_policy_digest: &'a Digest32,
            authority_diff_digest: &'a Digest32,
            authority_diff: &'a PolicyAuthorityDiff,
            assurance_level: &'a Token,
            issued_at_ms: &'a DecimalU64,
            expires_at_ms: &'a DecimalU64,
            broker_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            schema: &self.schema,
            operation_id: &self.operation_id,
            wallet_id: &self.wallet_id,
            baseline_version: &self.baseline_version,
            baseline_digest: &self.baseline_digest,
            proposed_policy_digest: &self.proposed_policy_digest,
            authority_diff_digest: &self.authority_diff_digest,
            authority_diff: &self.authority_diff,
            assurance_level: &self.assurance_level,
            issued_at_ms: &self.issued_at_ms,
            expires_at_ms: &self.expires_at_ms,
            broker_key_id: &self.broker_key_id,
        })
        .map_err(malformed)
    }

    pub(crate) fn digest(&self) -> Result<Digest32, ProtocolError> {
        digest(self)
    }
}

/// Typed Broker-to-Signer seam. Broker only forwards raw proof and opaque HPKE
/// envelopes; no method accepts plaintext PRF or custody input.
pub trait CeremonySigner: Send + Sync {
    fn prepare_approval(
        &self,
        request: CeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedApproval, SignerProtocolError>;

    fn complete_approval(
        &self,
        request: CeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<SignerActivationReceipt, SignerProtocolError>;

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, SignerProtocolError>;

    fn complete_custody(
        &self,
        request: CustodyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, SignerProtocolError>;

    fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, SignerProtocolError> {
        let _ = (request, now_ms);
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::BackendUnsupported,
            "policy-update ceremony preparation is not implemented by this Signer seam",
        ))
    }

    fn complete_policy_update(
        &self,
        request: PolicyUpdateCeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, SignerProtocolError> {
        let _ = (request, now_ms);
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::BackendUnsupported,
            "policy-update ceremony completion is not implemented by this Signer seam",
        ))
    }

    fn bind_custody_output_recipient(
        &self,
        operation_id: &OperationId,
        recipient_key: Base64UrlBytes,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, SignerProtocolError>;

    fn cancel(&self, operation_id: &OperationId) -> Result<(), SignerProtocolError>;

    fn status(
        &self,
        operation_id: &OperationId,
    ) -> Result<SignerCeremonyStatus, SignerProtocolError>;
}

pub trait CeremonyCompletionObserver: Send + Sync {
    fn approval_completed(
        &self,
        receipt: &SignerActivationReceipt,
        now_ms: u64,
    ) -> Result<(), ProtocolError>;

    fn custody_completed(
        &self,
        _receipt: &CustodyResult,
        _now_ms: u64,
    ) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct CeremonyBroker {
    inner: Arc<BrokerInner>,
}

struct BrokerInner {
    signer: Arc<dyn CeremonySigner>,
    limits: CeremonyLimits,
    /// Serializes the admission decision through durable session insertion so
    /// concurrent prepares cannot all reserve the same remaining capacity.
    creation_admission: Mutex<()>,
    sessions: Mutex<HashMap<String, BrowserSession>>,
    operations: Mutex<HashMap<OperationId, String>>,
    cancellation_backoff: Mutex<HashMap<Token, (u32, u64)>>,
    invalid_attempts: Mutex<HashMap<IpAddr, u32>>,
    database: Option<Arc<std::sync::Mutex<Connection>>>,
    journal: Option<Arc<BrokerJournal>>,
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
    encrypted_input: Option<HpkeEnvelope>,
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
        Self::new_with_limits(signer, CeremonyLimits::default())
    }

    /// Construct with an explicit admission policy. Deployments configure the
    /// policy at startup; this constructor is how a non-default policy reaches
    /// an in-memory Broker.
    pub fn new_with_limits(signer: Arc<dyn CeremonySigner>, limits: CeremonyLimits) -> Self {
        Self::from_parts(signer, limits, None, None, None)
    }

    pub fn new_with_manifest_signer(
        signer: Arc<dyn CeremonySigner>,
        broker_key_id: Token,
        signing_key: SigningKey,
    ) -> Self {
        Self::from_parts(
            signer,
            CeremonyLimits::default(),
            None,
            Some((broker_key_id, signing_key)),
            None,
        )
    }

    pub fn open(
        legacy_path: impl AsRef<FsPath>,
        signer: Arc<dyn CeremonySigner>,
        journal: Arc<BrokerJournal>,
    ) -> Result<Self, ProtocolError> {
        let database = open_audited_ceremony_store(legacy_path, &journal)?;
        let broker = Self::from_parts(
            signer,
            CeremonyLimits::default(),
            Some(database),
            None,
            Some(journal),
        );
        broker.reload_and_reconcile_nonterminal()?;
        Ok(broker)
    }

    pub fn open_with_manifest_signer(
        path: impl AsRef<FsPath>,
        signer: Arc<dyn CeremonySigner>,
        broker_key_id: Token,
        signing_key: SigningKey,
        journal: Arc<BrokerJournal>,
    ) -> Result<Self, ProtocolError> {
        Self::open_with_manifest_signer_audited(
            path,
            signer,
            broker_key_id,
            signing_key,
            journal,
            CeremonyLimits::default(),
        )
    }

    pub fn open_with_manifest_signer_audited(
        legacy_path: impl AsRef<FsPath>,
        signer: Arc<dyn CeremonySigner>,
        broker_key_id: Token,
        signing_key: SigningKey,
        journal: Arc<BrokerJournal>,
        limits: CeremonyLimits,
    ) -> Result<Self, ProtocolError> {
        let database = open_audited_ceremony_store(legacy_path, &journal)?;
        let broker = Self::from_parts(
            signer,
            limits,
            Some(database),
            Some((broker_key_id, signing_key)),
            Some(journal),
        );
        broker.reload_and_reconcile_nonterminal()?;
        Ok(broker)
    }

    /// The effective global admission policy, for startup reporting.
    pub fn limits(&self) -> CeremonyLimits {
        self.inner.limits
    }

    fn from_parts(
        signer: Arc<dyn CeremonySigner>,
        limits: CeremonyLimits,
        database: Option<Arc<std::sync::Mutex<Connection>>>,
        manifest_signer: Option<(Token, SigningKey)>,
        journal: Option<Arc<BrokerJournal>>,
    ) -> Self {
        Self {
            inner: Arc::new(BrokerInner {
                signer,
                limits,
                creation_admission: Mutex::new(()),
                sessions: Mutex::new(HashMap::new()),
                operations: Mutex::new(HashMap::new()),
                cancellation_backoff: Mutex::new(HashMap::new()),
                invalid_attempts: Mutex::new(HashMap::new()),
                database,
                journal,
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
            .filter(|session| session.state == CeremonyState::WalletCommitted)
            .map(|session| {
                (
                    session.projection.ceremony_id.as_str().to_owned(),
                    session.terminal_at_ms.unwrap_or(now_ms),
                )
            })
            .collect::<Vec<_>>();
        for (ceremony_id, completed_at_ms) in sessions {
            self.sweep_committed_session(&ceremony_id, completed_at_ms)?;
        }
        Ok(())
    }

    /// Install the observer without replaying durable completion effects.
    /// Used only while the Broker audit journal is latched read-only; replay
    /// would be a security mutation and is deferred until a clean restart.
    pub fn set_completion_observer_read_only(&self, observer: Arc<dyn CeremonyCompletionObserver>) {
        *self.inner.completion_observer.lock() = Some(observer);
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
        let _admission_guard = self.inner.creation_admission.lock();
        if let Some(response) =
            self.stable_approval_response(&request.activation_operation_id, &request_digest)
        {
            return response;
        }
        self.enforce_creation_bounds(Some(&request.terms.wallet_id), false, now_ms)?;
        let prepared = self
            .inner
            .signer
            .prepare_approval(request.clone(), now_ms)
            .map_err(signer_error_to_machine)?;
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
            approval_id: request
                .terms
                .approval_id()
                .map_err(signer_error_to_machine)?,
            state: ApprovalPrepareState::AwaitingCeremony,
            ceremony_url: url,
            ceremony_expires_at_ms: DecimalU64::new(expires_at_ms),
            review_manifest_digest: request.review_manifest_digest,
        })
    }

    pub fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<CustodyPrepareResponse, ProtocolError> {
        self.expire_sessions(now_ms)?;
        request
            .validate_legacy_passkey_migration_binding()
            .map_err(signer_error_to_machine)?;
        request
            .validate_petal_key_scope_binding()
            .map_err(signer_error_to_machine)?;
        if matches!(
            request.ceremony_kind,
            CeremonyKind::SealedApproval | CeremonyKind::PolicyUpdate
        ) {
            return Err(kind_mismatch());
        }
        let request_digest = digest(&request)?;
        let _admission_guard = self.inner.creation_admission.lock();
        if let Some(response) =
            self.stable_custody_response(&request.custody_operation_id, &request_digest)
        {
            return response;
        }
        // This quota class means a brand-new wallet registration. The caller
        // now supplies its authoritative ID, but it is still unauthenticated
        // by an existing wallet credential and must retain the global bound.
        let anonymous_registration = request.ceremony_kind == CeremonyKind::WalletRegistration;
        self.enforce_creation_bounds(request.wallet_id.as_ref(), anonymous_registration, now_ms)?;
        let prepared = self
            .inner
            .signer
            .prepare_custody(request.clone(), now_ms)
            .map_err(signer_error_to_machine)?;
        if matches!(
            request.ceremony_kind,
            CeremonyKind::WalletRegistration | CeremonyKind::WalletImport
        ) {
            let expected_wallet_id = request.wallet_id.as_ref().or_else(|| {
                request
                    .legacy_passkey_migration
                    .as_ref()
                    .map(|migration| &migration.wallet_name)
            });
            if expected_wallet_id.is_some()
                && prepared.contribution.wallet_id.as_ref() != expected_wallet_id
            {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "Signer contribution changed the requested wallet ID",
                ));
            }
        }
        prepared
            .contribution
            .validate_petal_key_scope_binding(&request)
            .map_err(signer_error_to_machine)?;
        let ceremony_id = prepared.contribution.ceremony_id.clone();
        let contribution_digest = prepared
            .contribution
            .digest()
            .map_err(signer_error_to_machine)?;
        let expires_at_ms = prepared.contribution.expires_at_ms.get();
        let session = self.new_session(NewBrowserSession {
            operation_id: request.custody_operation_id.clone(),
            request_digest,
            wallet_id: prepared.contribution.wallet_id.clone(),
            anonymous_registration,
            ceremony_kind: request.ceremony_kind,
            ceremony_id: ceremony_id.clone(),
            review_manifest: if let Some(migration) = &request.legacy_passkey_migration {
                Some(serde_json::json!({
                    "schema": "bloom.legacy_passkey_migration_review.v1",
                    "title": "Import existing passkey wallet into Triad custody",
                    "wallet_name": migration.wallet_name,
                    "address": migration.address,
                    "public_key_fingerprint": migration.public_key_fingerprint,
                    "credential_id_fingerprint": migration.credential_id_fingerprint,
                    "legacy_format_version": migration.legacy_format_version,
                    "bundle_digest": migration.bundle_digest,
                    "policy_mode": migration.policy_mode,
                    "existing_passkey_remains_authority": true,
                    "creates_current_wkek_custody": true,
                    "legacy_policy_is_not_imported": true
                }))
            } else {
                request
                    .petal_key_scope
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(malformed)?
            },
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
            ceremony_kind: kind_to_machine(request.ceremony_kind),
            custody_operation_id: request.custody_operation_id,
            state: CustodyPrepareState::AwaitingUser,
            ceremony_url: url,
            ceremony_expires_at_ms: DecimalU64::new(expires_at_ms),
            signer_contribution_digest: contribution_digest,
        })
    }

    pub(crate) fn prepare_policy_update(
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
            || request.custody.exact_terms_digest
                != request
                    .update
                    .terms_digest()
                    .map_err(signer_error_to_machine)?
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
        let _admission_guard = self.inner.creation_admission.lock();
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
            .prepare_policy_update(request.clone(), now_ms)
            .map_err(signer_error_to_machine)?;
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
            ceremony_kind: BrokerCeremonyKind::PolicyUpdate,
            ceremony_url: session_url(&token_for(&session)),
            ceremony_expires_at_ms: DecimalU64::new(expires_at_ms),
            review_manifest_digest: request.broker_validation_receipt.review_manifest_digest,
        };
        self.insert_session(ceremony_id, session)?;
        Ok(response)
    }

    /// Recover the stable prepare response for an exact policy-update retry.
    ///
    /// The review manifest contains Broker-issued timestamps, so rebuilding it
    /// after a lost response would change the request digest. Compare the
    /// immutable update terms first and return the already-durable response.
    pub(crate) fn recover_policy_update_prepare(
        &self,
        update: &bloom_signer_api::PolicyUpdateRequest,
    ) -> Option<Result<PolicyUpdatePrepareResponse, ProtocolError>> {
        let id = self
            .inner
            .operations
            .lock()
            .get(&update.operation_id)?
            .clone();
        let sessions = self.inner.sessions.lock();
        let session = sessions.get(&id)?;
        let Some(stored) = session.policy_update.as_ref() else {
            return Some(Err(operation_conflict()));
        };
        if &stored.update != update {
            return Some(Err(operation_conflict()));
        }
        if is_terminal(session.state) {
            return Some(Err(replay()));
        }
        let manifest: PolicyUpdateReviewManifest =
            serde_json::from_value(session.projection.review_manifest.clone()?).ok()?;
        Some(Ok(PolicyUpdatePrepareResponse {
            operation_id: update.operation_id.clone(),
            ceremony_kind: BrokerCeremonyKind::PolicyUpdate,
            ceremony_url: session_url(&token_for(session)),
            ceremony_expires_at_ms: DecimalU64::new(session.expires_at_ms),
            review_manifest_digest: manifest.digest().ok()?,
        }))
    }

    pub fn status(&self, operation_id: &OperationId) -> Option<BrokerCeremonyState> {
        let ceremony_id = self.inner.operations.lock().get(operation_id)?.clone();
        self.inner
            .sessions
            .lock()
            .get(&ceremony_id)
            .map(|session| state_to_machine(session.state))
    }

    pub fn public_status(
        &self,
        operation_id: &OperationId,
    ) -> Result<BrokerCeremonyPublicStatus, ProtocolError> {
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
        Ok(BrokerCeremonyPublicStatus {
            ceremony_id: session.projection.ceremony_id.clone(),
            ceremony_kind: kind_to_machine(session.ceremony_kind),
            operation_id: operation_id.clone(),
            state: state_to_machine(session.state),
            expires_at_ms: DecimalU64::new(session.expires_at_ms),
            ceremony_url,
            receipt_digest,
        })
    }

    /// Return the owner-visible URL for an approval ceremony while it is
    /// awaiting the user. Approval status is keyed by the approval digest,
    /// whereas the ceremony store is keyed by activation operation ID, so the
    /// association is recovered from the signed review manifest.
    pub fn pending_approval_ceremony(
        &self,
        approval_id: &Digest32,
    ) -> Option<(String, DecimalU64)> {
        self.inner.sessions.lock().values().find_map(|session| {
            if session.ceremony_kind != CeremonyKind::SealedApproval
                || session.state != CeremonyState::AwaitingUser
            {
                return None;
            }
            let manifest_approval_id = session
                .projection
                .review_manifest
                .as_ref()?
                .get("approval_id")?
                .as_str()?;
            if manifest_approval_id != approval_id.as_str() {
                return None;
            }
            session
                .token
                .as_ref()
                .map(|token| (session_url(token), DecimalU64::new(session.expires_at_ms)))
        })
    }

    pub fn completed_policy_update(
        &self,
        operation_id: &OperationId,
        receipt: &bloom_broker_api::CustodyResult,
    ) -> Result<(PolicyUpdateCeremonyPrepareRequest, CustodyResult), ProtocolError> {
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
            || receipt.ceremony_kind != BrokerCeremonyKind::PolicyUpdate
            || &receipt.custody_operation_id != operation_id
        {
            return Err(kind_mismatch());
        }
        let stored: CustodyResult =
            serde_json::from_value(session.terminal_result.clone().ok_or_else(not_found)?)
                .map_err(malformed)?;
        if crate::translation::custody::result_to_machine(stored.clone()) != *receipt {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "policy commit receipt differs from completed ceremony",
            ));
        }
        Ok((
            session.policy_update.clone().ok_or_else(kind_mismatch)?,
            stored,
        ))
    }

    pub fn cancel(&self, operation_id: &OperationId, now_ms: u64) -> Result<(), ProtocolError> {
        let ceremony_id = self
            .inner
            .operations
            .lock()
            .get(operation_id)
            .cloned()
            .ok_or_else(not_found)?;
        let (wallet_id, snapshot) = {
            let sessions = self.inner.sessions.lock();
            let session = sessions.get(&ceremony_id).ok_or_else(not_found)?;
            if session.state != CeremonyState::AwaitingUser {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "terminal ceremony cannot be cancelled",
                ));
            }
            let mut snapshot = session.clone();
            snapshot.state = CeremonyState::Cancelled;
            latch_terminal(&mut snapshot, now_ms);
            (session.wallet_id.clone(), snapshot)
        };
        self.inner
            .signer
            .cancel(operation_id)
            .map_err(signer_error_to_machine)?;
        self.persist_session(&snapshot)?;
        self.inner.sessions.lock().insert(ceremony_id, snapshot);
        if let Some(wallet_id) = &wallet_id {
            self.record_backoff(wallet_id, now_ms);
        }
        Ok(())
    }

    /// Make every browser-facing session terminal after the authenticated
    /// login sentinel disappears. The HTTP listener is stopped and drained
    /// before this is called, so no new browser transition can race the
    /// snapshots below.
    pub fn terminate_live_sessions(&self, now_ms: u64) -> Result<(), ProtocolError> {
        let live = self
            .inner
            .sessions
            .lock()
            .iter()
            .filter(|(_, session)| !is_terminal(session.state))
            .map(|(id, session)| {
                (
                    id.clone(),
                    session.operation_id.clone(),
                    session.state,
                    session.wallet_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (ceremony_id, operation_id, state, wallet_id) in live {
            if state == CeremonyState::WalletCommitted {
                self.sweep_committed_session(&ceremony_id, now_ms)?;
                continue;
            }
            if state == CeremonyState::AwaitingUser {
                self.inner
                    .signer
                    .cancel(&operation_id)
                    .map_err(signer_error_to_machine)?;
            }
            let snapshot = {
                let sessions = self.inner.sessions.lock();
                let Some(session) = sessions.get(&ceremony_id) else {
                    continue;
                };
                if is_terminal(session.state) {
                    continue;
                }
                let mut snapshot = session.clone();
                snapshot.state = if state == CeremonyState::AwaitingUser {
                    CeremonyState::Cancelled
                } else {
                    CeremonyState::Failed
                };
                latch_terminal(&mut snapshot, now_ms);
                snapshot
            };
            self.persist_session(&snapshot)?;
            self.inner.sessions.lock().insert(ceremony_id, snapshot);
            if state == CeremonyState::AwaitingUser
                && let Some(wallet_id) = &wallet_id
            {
                self.record_backoff(wallet_id, now_ms);
            }
        }
        Ok(())
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(shell))
            .route("/ceremony/{token}", get(ceremony_shell))
            .route("/assets/app.js", get(app_js))
            .route("/assets/style.css", get(style_css))
            .route("/assets/bloom-primary.svg", get(bloom_primary_svg))
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
                self.sweep_committed_session(&ceremony_id, now_ms)?;
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
                    latch_terminal(&mut snapshot, now_ms);
                    snapshot
                };
                self.persist_session(&snapshot)?;
                self.inner
                    .sessions
                    .lock()
                    .insert(ceremony_id.clone(), snapshot);
                continue;
            }
            let signer_status = self
                .inner
                .signer
                .status(&operation_id)
                .map_err(signer_error_to_machine)?;
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
                    self.inner
                        .signer
                        .cancel(&operation_id)
                        .map_err(signer_error_to_machine)?;
                    (CeremonyState::Expired, None)
                }
                SignerCeremonyStatus::Terminal(state) => (state, None),
                SignerCeremonyStatus::Missing => (CeremonyState::Expired, None),
            };
            let snapshot = {
                let sessions = self.inner.sessions.lock();
                let session = sessions.get(&ceremony_id).ok_or_else(not_found)?;
                let mut snapshot = session.clone();
                snapshot.state = state;
                snapshot.terminal_result = terminal_result;
                // A Signer-reported terminal state is as final as an expiry:
                // `Cancelled` and `Failed` have to burn the token too.
                if is_terminal(state) {
                    latch_terminal(&mut snapshot, now_ms);
                }
                snapshot
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
            self.inner
                .sessions
                .lock()
                .insert(ceremony_id.clone(), snapshot);
            if state == CeremonyState::WalletCommitted {
                self.sweep_committed_session(&ceremony_id, now_ms)?;
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

    pub async fn serve_canonical_until<F>(self, shutdown: F) -> Result<(), ProtocolError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = Self::bind_canonical()?;
        self.serve_listener_until(listener, shutdown).await
    }

    /// Accept a canonical listener inherited from a launch/socket activation
    /// manager. A listener for any other address is rejected.
    pub async fn serve_listener(self, listener: StdTcpListener) -> Result<(), ProtocolError> {
        self.serve_listener_until(listener, std::future::pending())
            .await
    }

    pub async fn serve_listener_until<F>(
        self,
        listener: StdTcpListener,
        shutdown: F,
    ) -> Result<(), ProtocolError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
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
            .with_graceful_shutdown(shutdown)
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
                        let challenge = binding
                            .webauthn_challenge()
                            .map_err(signer_error_to_machine)?;
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
        if now_ms == 0 {
            return Err(protocol(
                ProtocolErrorCode::ClockUntrusted,
                "trusted platform time is required to create a ceremony",
            ));
        }
        let limits = self.inner.limits;
        let sessions = self.inner.sessions.lock();
        let live = sessions
            .values()
            .filter(|session| !is_terminal(session.state) && session.expires_at_ms > now_ms)
            .count();
        if live >= limits.maximum_concurrent_sessions() {
            // Concurrency exhaustion is a different class from rolling rate
            // limiting: it carries no retry hint because nothing ages out on a
            // schedule, only when a live ceremony ends.
            return Err(protocol(
                ProtocolErrorCode::QuotaExceeded,
                "Broker ceremony concurrency quota is exhausted",
            ));
        }
        if let Some(wallet_id) = wallet_id {
            let recent = creations_in_window(
                sessions
                    .values()
                    .filter(|session| session.wallet_id.as_ref() == Some(wallet_id)),
                limits.creation_window_ms(),
                now_ms,
            );
            if recent.len() >= limits.maximum_creations_per_wallet() {
                return Err(rolling_quota_exhausted(
                    "wallet",
                    "wallet ceremony rolling creation quota is exhausted",
                    recent,
                    limits.maximum_creations_per_wallet(),
                    limits.creation_window_ms(),
                    now_ms,
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
            let mut backoffs = self.inner.cancellation_backoff.lock();
            if backoffs
                .get(wallet_id)
                .is_some_and(|(_, until)| *until <= now_ms)
            {
                // Backoff is a cooldown, not durable strike history.  Leaving
                // the old count here made every later cancellation escalate
                // forever until the Broker process restarted.
                backoffs.remove(wallet_id);
            }
            if let Some((strikes, until)) = backoffs
                .get(wallet_id)
                .copied()
                .filter(|(_, until)| *until > now_ms)
            {
                // Same code, same structured contract as the rolling quotas: a
                // caller acts on the metadata, never on the message. The
                // cooldown admits one creation once it elapses, so its limit
                // is 1 over a window of the current backoff.
                let remaining_ms = until.saturating_sub(now_ms);
                let message = format!(
                    "wallet ceremony is in cancellation backoff; retry after {remaining_ms} ms"
                );
                return Err(
                    match RateLimitDetails::new(remaining_ms, 1, backoff_window_ms(strikes)) {
                        Some(details) => ProtocolError::rate_limited(message, details),
                        None => protocol(ProtocolErrorCode::CeremonyRateLimited, message),
                    },
                );
            }
        }
        if anonymous_registration {
            let recent = creations_in_window(
                sessions
                    .values()
                    .filter(|session| session.anonymous_registration),
                limits.creation_window_ms(),
                now_ms,
            );
            if recent.len() >= limits.maximum_anonymous_registrations() {
                return Err(rolling_quota_exhausted(
                    "anonymous-registration",
                    "anonymous registration rolling creation quota is exhausted",
                    recent,
                    limits.maximum_anonymous_registrations(),
                    limits.creation_window_ms(),
                    now_ms,
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
            ceremony_expires_at_ms: DecimalU64::new(session.expires_at_ms),
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
            ceremony_kind: kind_to_machine(session.ceremony_kind),
            custody_operation_id: operation_id.clone(),
            state: CustodyPrepareState::AwaitingUser,
            ceremony_url: session_url(&token_for(session)),
            ceremony_expires_at_ms: DecimalU64::new(session.expires_at_ms),
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
            ceremony_kind: BrokerCeremonyKind::PolicyUpdate,
            ceremony_url: session_url(&token_for(session)),
            ceremony_expires_at_ms: DecimalU64::new(session.expires_at_ms),
            review_manifest_digest: review_manifest_digest.clone(),
        }))
    }

    fn record_backoff(&self, wallet_id: &Token, now_ms: u64) {
        let mut backoffs = self.inner.cancellation_backoff.lock();
        let (count, _) = backoffs.get(wallet_id).copied().unwrap_or((0, 0));
        let next_count = count.saturating_add(1);
        backoffs.insert(
            wallet_id.clone(),
            (
                next_count,
                now_ms.saturating_add(backoff_window_ms(next_count)),
            ),
        );
    }

    fn reload_and_reconcile_nonterminal(&self) -> Result<(), ProtocolError> {
        let database = self
            .inner
            .database
            .as_ref()
            .expect("open installs a ceremony database")
            .lock()
            .map_err(|_| storage("ceremony database mutex poisoned"))?;
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
        let audit_degraded = self
            .inner
            .journal
            .as_ref()
            .is_some_and(|journal| journal.audit_degraded());

        for (ceremony_id, operation_id, encoded) in rows {
            let mut session: BrowserSession = serde_json::from_str(&encoded).map_err(malformed)?;
            let preserve_awaiting = session.state == CeremonyState::AwaitingRecoveryAck
                && session.expires_at_ms > unix_time_ms();
            if audit_degraded {
                // AC-18 keeps the exact durable read/status projection
                // available while every security mutation remains latched.
            } else if session.state == CeremonyState::AwaitingRecoveryAck && !preserve_awaiting {
                session.state = CeremonyState::Failed;
                latch_terminal(&mut session, unix_time_ms());
                self.persist_session(&session)?;
            } else if !preserve_awaiting
                && session.state != CeremonyState::WalletCommitted
                && !is_terminal(session.state)
            {
                match self
                    .inner
                    .signer
                    .status(&session.operation_id)
                    .map_err(signer_error_to_machine)?
                {
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
                        self.inner
                            .signer
                            .cancel(&session.operation_id)
                            .map_err(signer_error_to_machine)?;
                        session.state = CeremonyState::Expired;
                    }
                    SignerCeremonyStatus::Terminal(state) => {
                        session.state = state;
                    }
                    SignerCeremonyStatus::Missing => {
                        session.state = CeremonyState::Expired;
                    }
                }
                if is_terminal(session.state) {
                    latch_terminal(&mut session, unix_time_ms());
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
        let approval_id = request
            .terms
            .approval_id()
            .map_err(signer_error_to_machine)?;
        let approval_digest = request
            .terms
            .approval_digest()
            .map_err(signer_error_to_machine)?;
        let disclosures = review_disclosures(
            request,
            manifest.claim_assurance.as_ref(),
            manifest.petal_use_claim.as_ref(),
            manifest.system_use_claim.as_ref(),
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
            context.system_use_claim.as_ref(),
        );
        let canonical_plan = canonical_review_plan(request, &disclosures)?;
        let mut manifest = ReviewManifest {
            schema: Token::new("bloom.review-manifest.v1")?,
            approval_id: request
                .terms
                .approval_id()
                .map_err(signer_error_to_machine)?,
            approval_digest: request
                .terms
                .approval_digest()
                .map_err(signer_error_to_machine)?,
            canonical_plan_digest: Digest32::from_bytes(
                Sha256::digest(canonical_plan.as_bytes()).into(),
            ),
            canonical_plan,
            exact_payload_digests: request.exact_ordered_payload_digests.clone(),
            exact_hashes: request.exact_ordered_hashes.clone(),
            petal_use_claim: context.petal_use_claim,
            system_use_claim: context.system_use_claim,
            claim_assurance: context.claim_assurance,
            attributed_advisory_items: context.attributed_advisory_items,
            issued_at_ms: DecimalU64::new(now_ms),
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

    fn persist_session(&self, session: &BrowserSession) -> Result<(), ProtocolError> {
        let Some(database) = &self.inner.database else {
            return Ok(());
        };
        let encoded =
            String::from_utf8(serde_jcs::to_vec(session).map_err(malformed)?).map_err(malformed)?;
        let mut database = if let Some(journal) = &self.inner.journal {
            journal.lock_for_mutation().map_err(storage)?
        } else {
            database
                .lock()
                .map_err(|_| storage("ceremony database mutex poisoned"))?
        };
        let transaction = database.transaction().map_err(storage)?;
        transaction
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
        if let Some(journal) = &self.inner.journal {
            journal
                .append_external_audit(
                    &transaction,
                    "ceremony.session_persisted",
                    &serde_json::json!({
                        "ceremony_id": session.projection.ceremony_id,
                        "operation_id": session.operation_id,
                        "ceremony_kind": session.ceremony_kind,
                        "state": session.state,
                        "request_digest": session.request_digest,
                        "receipt_digest": session
                            .terminal_result
                            .as_ref()
                            .and_then(|receipt| receipt.get("receipt_digest"))
                    }),
                )
                .map_err(storage)?;
        }
        transaction.commit().map_err(storage)?;
        drop(database);
        if let Some(journal) = &self.inner.journal {
            journal.checkpoint_committed_head().map_err(storage)?;
        }
        tracing::info!(
            event = "ceremony.state_persisted",
            ceremony_id = session.projection.ceremony_id.as_str(),
            operation_id = session.operation_id.as_str(),
            ceremony_kind = ceremony_kind_name(session.ceremony_kind),
            state = ceremony_state_name(session.state),
            terminal = is_terminal(session.state),
            "Broker ceremony state persisted"
        );
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
            observer.custody_completed(&receipt, now_ms)
        }
    }

    /// Sweep-side adoption: a permanently rejected session has already been
    /// terminalized by `finalize_committed_session`, so the sweep continues;
    /// transient failures still surface so the caller retries later.
    fn sweep_committed_session(&self, ceremony_id: &str, now_ms: u64) -> Result<(), ProtocolError> {
        match self.finalize_committed_session(ceremony_id, now_ms) {
            Ok(_) => Ok(()),
            Err(error) if error.retry == bloom_broker_api::RetryClass::Never => Ok(()),
            Err(error) => Err(error),
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
        // observer operation is idempotent, so a transient failure leaves
        // WALLET_COMMITTED retryable across the same request and process
        // restart. A permanent rejection (`retry: never`, e.g. an activation
        // receipt whose validity interval already closed) can never succeed
        // on retry; leaving it WALLET_COMMITTED would re-fire on every sweep
        // and every restart, so it is terminalized as FAILED instead.
        if let Err(error) = self.notify_completion(committed.ceremony_kind, &receipt, now_ms) {
            if error.retry == bloom_broker_api::RetryClass::Never {
                eprintln!(
                    "Broker ceremony {ceremony_id} adoption permanently rejected; marking FAILED: {error}"
                );
                let mut failed = committed;
                failed.state = CeremonyState::Failed;
                failed.terminal_at_ms = Some(now_ms);
                failed.token = None;
                failed.token_hash = [0_u8; 32];
                self.persist_session(&failed)?;
                self.inner
                    .sessions
                    .lock()
                    .insert(ceremony_id.to_owned(), failed);
            }
            return Err(error);
        }

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
            latch_terminal(&mut finalized, now_ms);
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

async fn style_css(headers: HeaderMap) -> Response {
    if validate_host(&headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLE_CSS,
    )
        .into_response()
}

async fn bloom_primary_svg(headers: HeaderMap) -> Response {
    if validate_host(&headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        BLOOM_PRIMARY_SVG,
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
        latch_terminal(&mut snapshot, unix_time_ms());
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
    let (ceremony_kind, operation_id, projection, verifying_snapshot) = {
        let sessions = broker.inner.sessions.lock();
        let Some(session) = sessions.get(&ceremony_id) else {
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
        let mut verifying_snapshot = session.clone();
        verifying_snapshot.state = CeremonyState::Verifying;
        (
            session.ceremony_kind,
            session.operation_id.clone(),
            session.projection.clone(),
            verifying_snapshot,
        )
    };
    if broker.persist_session(&verifying_snapshot).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    broker
        .inner
        .sessions
        .lock()
        .insert(ceremony_id.clone(), verifying_snapshot.clone());
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
            .map_err(signer_error_to_machine)
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
            .map_err(signer_error_to_machine)
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
            .map_err(signer_error_to_machine)
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
            // A stale WebAuthn signature counter reports `UnauthenticatedPeer`
            // while the Signer leaves the operation pending, so the Signer-side
            // operation has to be released or it holds the wallet's concurrency
            // quota forever. Every other rejection already terminalises the
            // Signer operation, so there is nothing to cancel.
            let released = error.code != ProtocolErrorCode::UnauthenticatedPeer
                || broker.inner.signer.cancel(&operation_id).is_ok();
            // The Broker session is only terminalised once the Signer side is
            // known to be released. If cancellation failed the session stays
            // `Verifying` so the expiry sweep retries the cancel; terminalising
            // here would strand the Signer operation permanently.
            //
            // Terminalising regardless would also be safe against the older
            // Signer, which reported `ApprovalNotFound` for a ceremony it had
            // already failed closed and so made a benign outcome look like a
            // failed cancel. That is fixed: cancel is now idempotent for a
            // ceremony in a durable non-successful terminal, so a cancel that
            // still fails here is a real unreleased operation and must not be
            // abandoned. Retry is not blocked in the meantime — the sweep
            // releases the wallet's quota once the cancel succeeds.
            if released {
                let snapshot = {
                    let sessions = broker.inner.sessions.lock();
                    let Some(session) = sessions.get(&ceremony_id) else {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    };
                    let mut snapshot = session.clone();
                    snapshot.state = CeremonyState::Failed;
                    latch_terminal(&mut snapshot, unix_time_ms());
                    snapshot
                };
                if broker.persist_session(&snapshot).is_err() {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                broker.inner.sessions.lock().insert(ceremony_id, snapshot);
            }
            // The browser needs the structured rejection either way: a failed
            // best-effort cancel must never replace it with an empty 500.
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
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(signer_error_to_machine(error)),
            )
                .into_response();
        }
    };
    let snapshot = {
        let sessions = broker.inner.sessions.lock();
        let Some(session) = sessions.get(&ceremony_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if prepared.contribution.ceremony_id != session.projection.ceremony_id {
            return StatusCode::CONFLICT.into_response();
        }
        let mut snapshot = session.clone();
        snapshot.projection.signer_contribution = match serde_json::to_value(prepared.contribution)
        {
            Ok(value) => value,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        snapshot.projection.challenges = match prepared
            .challenges
            .into_iter()
            .map(|binding| {
                let challenge = binding
                    .webauthn_challenge()
                    .map_err(signer_error_to_machine)?;
                Ok(BrowserChallenge { binding, challenge })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()
        {
            Ok(challenges) => challenges,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        snapshot.projection.webauthn_options = prepared.webauthn_options;
        snapshot
    };
    if broker.persist_session(&snapshot).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let projection = snapshot.projection.clone();
    broker.inner.sessions.lock().insert(ceremony_id, snapshot);
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

/// Stamp when a session reached its terminal state and destroy the launch
/// token material. Every terminal state latches identically: no terminal
/// session may keep a usable bearer token, whichever state ended it.
fn latch_terminal(session: &mut BrowserSession, now_ms: u64) {
    session.terminal_at_ms = Some(now_ms);
    session.token = None;
    session.token_hash = [0_u8; 32];
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

fn ceremony_kind_name(kind: CeremonyKind) -> &'static str {
    match kind {
        CeremonyKind::SealedApproval => "sealed_approval",
        CeremonyKind::WalletRegistration => "wallet_registration",
        CeremonyKind::WalletImport => "wallet_import",
        CeremonyKind::WalletExport => "wallet_export",
        CeremonyKind::WalletDelete => "wallet_delete",
        CeremonyKind::WalletRecovery => "wallet_recovery",
        CeremonyKind::CredentialAdd => "credential_add",
        CeremonyKind::CredentialReplace => "credential_replace",
        CeremonyKind::CredentialRemove => "credential_remove",
        CeremonyKind::BackendEnrollment => "backend_enrollment",
        CeremonyKind::KeyDerive => "key_derive",
        CeremonyKind::PolicyUpdate => "policy_update",
        CeremonyKind::AccountAllocate => "account_allocate",
        CeremonyKind::AccountRetire => "account_retire",
    }
}

fn ceremony_state_name(state: CeremonyState) -> &'static str {
    match state {
        CeremonyState::Prepared => "prepared",
        CeremonyState::AwaitingUser => "awaiting_user",
        CeremonyState::Verifying => "verifying",
        CeremonyState::WalletCommitted => "wallet_committed",
        CeremonyState::AwaitingRecoveryAck => "awaiting_recovery_ack",
        CeremonyState::Completed => "completed",
        CeremonyState::ApprovingRootChange => "approving_root_change",
        CeremonyState::CreatingCredential => "creating_credential",
        CeremonyState::Committing => "committing",
        CeremonyState::Succeeded => "succeeded",
        CeremonyState::Cancelled => "cancelled",
        CeremonyState::Expired => "expired",
        CeremonyState::Failed => "failed",
    }
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
        terms: &'a bloom_signer_api::SealedApprovalTerms,
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
    assurance: Option<&ClaimAssurance>,
    claim: Option<&PetalUseClaim>,
    system_claim: Option<&SystemUseClaim>,
) -> Vec<String> {
    let mut disclosures = Vec::new();
    if !request.exact_ordered_payload_digests.is_empty() || !request.exact_ordered_hashes.is_empty()
    {
        disclosures.push(
            "Bloom has not established the execution effects of these opaque payload digests and hashes."
                .to_owned(),
        );
    }
    let machine_asserted = matches!(assurance, Some(ClaimAssurance::MachineAsserted))
        || claim
            .is_some_and(|claim| matches!(claim.claim_assurance, ClaimAssurance::MachineAsserted))
        || system_claim
            .is_some_and(|claim| matches!(claim.claim_assurance, ClaimAssurance::MachineAsserted))
        || matches!(
            request.terms.selector,
            bloom_signer_api::ApprovalSelector::Petal { .. }
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

// See the authority migration: ceremony state formerly lived in a separate
// SQLite file, which cannot commit atomically with the Broker audit chain.
// Import it once into the consolidated journal database and retain the source
// file untouched as a rollback artifact.
fn open_audited_ceremony_store(
    legacy_path: impl AsRef<FsPath>,
    journal: &Arc<BrokerJournal>,
) -> Result<Arc<std::sync::Mutex<Connection>>, ProtocolError> {
    let legacy = Connection::open(legacy_path).map_err(storage)?;
    legacy
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS ceremony_sessions (
                ceremony_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL UNIQUE,
                session_jcs TEXT NOT NULL
            );",
        )
        .map_err(storage)?;
    let database = journal.shared_connection();
    {
        let mut connection = database.lock().map_err(|_| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                "ceremony database mutex poisoned",
            )
        })?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS ceremony_sessions (
                    ceremony_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    session_jcs TEXT NOT NULL
                );",
            )
            .map_err(storage)?;
        migrate_legacy_ceremonies(&mut connection, &legacy, journal)?;
    }
    Ok(database)
}

fn migrate_legacy_ceremonies(
    target: &mut Connection,
    legacy: &Connection,
    journal: &BrokerJournal,
) -> Result<(), ProtocolError> {
    let legacy_path: String = legacy
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    let legacy_session_count: i64 = legacy
        .query_row("SELECT COUNT(*) FROM ceremony_sessions", [], |row| {
            row.get(0)
        })
        .map_err(storage)?;
    let target_path: String = target
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if legacy_path.is_empty() || legacy_path == target_path || legacy_session_count == 0 {
        return Ok(());
    }
    target
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS broker_store_migrations (
                source_kind TEXT NOT NULL,
                source_path TEXT NOT NULL,
                PRIMARY KEY(source_kind, source_path)
            );",
        )
        .map_err(storage)?;
    let migrated: bool = target
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM broker_store_migrations
                WHERE source_kind='ceremony' AND source_path=?1
            )",
            [&legacy_path],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if migrated {
        return Ok(());
    }
    target
        .execute("ATTACH DATABASE ?1 AS ceremony_legacy", [&legacy_path])
        .map_err(storage)?;
    journal.verify_migration_target(target).map_err(storage)?;
    let migration = (|| -> Result<(), ProtocolError> {
        let transaction = target.transaction().map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO ceremony_sessions
                 SELECT * FROM ceremony_legacy.ceremony_sessions",
                [],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO broker_store_migrations(source_kind, source_path)
                 VALUES ('ceremony', ?1)",
                [&legacy_path],
            )
            .map_err(storage)?;
        journal
            .append_external_audit(
                &transaction,
                "storage.ceremony_migrated",
                &serde_json::json!({"legacy_path": legacy_path}),
            )
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        Ok(())
    })();
    let detach = target.execute_batch("DETACH DATABASE ceremony_legacy;");
    migration?;
    detach.map_err(storage)?;
    Ok(())
}

fn protocol(code: ProtocolErrorCode, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}

/// Creation times of the already-counted sessions still inside the rolling
/// window. Admission and the retry hint read the same set, so a caller can
/// never be told to retry at a time that would be rejected again.
fn creations_in_window<'a>(
    sessions: impl Iterator<Item = &'a BrowserSession>,
    window_ms: u64,
    now_ms: u64,
) -> Vec<u64> {
    sessions
        .filter_map(|session| {
            (session.created_at_ms.saturating_add(window_ms) > now_ms)
                .then_some(session.created_at_ms)
        })
        .collect()
}

/// The cancellation cooldown a wallet is held for after `strikes` consecutive
/// cancellations, doubling up to a ceiling. This is the window the rejection's
/// retry hint is measured against, so both sides read one definition.
fn backoff_window_ms(strikes: u32) -> u64 {
    let multiplier = 1_u64
        .checked_shl(strikes.saturating_sub(1).min(5))
        .unwrap_or(32);
    CANCELLATION_BACKOFF_MS.saturating_mul(multiplier)
}

/// Reject a creation whose rolling quota is at capacity, carrying the retry
/// contract callers act on.
///
/// The hint is the wait until enough of the counted creations have left the
/// window to free one slot — the creation whose expiry frees that slot, which
/// is the oldest only when the quota sits exactly at capacity. Under a quota
/// lowered beneath an existing population it is a later creation: the last one
/// that must age out. The quota class is logged; the wallet that hit it is
/// not, since the class is what an operator tunes.
fn rolling_quota_exhausted(
    quota: &str,
    message: &str,
    mut created_at_ms: Vec<u64>,
    limit: usize,
    window_ms: u64,
    now_ms: u64,
) -> ProtocolError {
    tracing::warn!(
        event = "ceremony.quota_rejected",
        quota,
        limit,
        window_ms,
        "Broker ceremony rolling creation quota exhausted"
    );
    created_at_ms.sort_unstable();
    let blocking = created_at_ms
        .len()
        .checked_sub(limit)
        .and_then(|index| created_at_ms.get(index).copied());
    let Some(blocking) = blocking else {
        // Only reachable if the quota rejected without a counted creation
        // behind it, which no configured limit permits. Report the refusal
        // without a hint rather than invent one.
        return protocol(ProtocolErrorCode::CeremonyRateLimited, message);
    };
    let retry_after_ms = blocking
        .saturating_add(window_ms)
        .saturating_sub(now_ms)
        .clamp(1, window_ms);
    match RateLimitDetails::new(retry_after_ms, limit as u64, window_ms) {
        Some(details) => ProtocolError::rate_limited(message, details),
        None => protocol(ProtocolErrorCode::CeremonyRateLimited, message),
    }
}
