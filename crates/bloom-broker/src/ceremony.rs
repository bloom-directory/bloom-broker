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
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Version, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use bloom_broker_api::{
    ApprovalPrepareState, CeremonyCrossSurfacePrepareRequest, CeremonyCrossSurfacePrepareResponse,
    CeremonyExposureMode, CeremonyExposureStage, CeremonyExposureStatus,
    CeremonyKind as BrokerCeremonyKind, CeremonyPublicStatus as BrokerCeremonyPublicStatus,
    CeremonyState as BrokerCeremonyState, CeremonySurfaceSelection, ClaimAssurance,
    CustodyPrepareResponse, CustodyPrepareState, PetalUseClaim, PolicyUpdatePrepareResponse,
    ProtocolError, ProtocolErrorCode, RateLimitDetails, SealedApprovalPrepareResponse,
    SystemUseClaim,
};
use bloom_signer_api::{
    Base64UrlBytes, CeremonyChallenge, CeremonyCompleteRequest, CeremonyKind,
    CeremonyPrepareRequest, CeremonyState, CeremonyWebAuthnOptions,
    CrossSurfaceAlreadyRegisteredRequest, CrossSurfaceCompleteDestinationRequest,
    CrossSurfaceCompleteSourceRequest, CrossSurfaceHandoff, CrossSurfacePairStartRequest,
    CrossSurfacePairing, CrossSurfacePrepareSourceRequest, CrossSurfaceSourcePrepared,
    CustodyCompleteRequest, CustodyPrepareRequest, CustodyResult, CustodySignerContribution,
    DecimalU64, Digest32, ExposureMode, HpkeEnvelope, OperationId,
    PolicyUpdateCeremonyCompleteRequest, PolicyUpdateCeremonyPrepareRequest,
    ProtocolError as SignerProtocolError, ProtocolErrorCode as SignerProtocolErrorCode,
    SignerActivationReceipt, SignerCeremonyContribution, SignerCeremonyStatus,
    SignerPreparedApproval, SignerPreparedCustody, SurfaceDescriptor, SurfaceEffectiveReport,
    SurfaceLifecycle, SurfaceRef, SurfaceStatus, Token, WebAuthnCeremonyProof, WebAuthnCredential,
};
use ed25519_dalek::{Signer as _, SigningKey};
use parking_lot::Mutex;
use rand::{TryRng as _, rngs::SysRng};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    future::{Future, IntoFuture},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener},
    path::Path as FsPath,
    sync::Arc,
    time::Duration,
};

/// Canonical IPv4 loopback ceremony listener address.
pub const CEREMONY_ADDR_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_734);
/// Canonical IPv6 loopback ceremony listener address. Chromium and many
/// other modern browsers resolve `localhost` to `::1` before `127.0.0.1`,
/// so the canonical ceremony origin is reachable only when the Broker also
/// binds the IPv6 loopback family explicitly.
pub const CEREMONY_ADDR_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 18_734);
/// Every address on which the canonical ceremony listener may be reached.
/// A listener on any address outside this set is refused at acquisition.
pub const CEREMONY_LOOPBACK_ADDRS: [SocketAddr; 2] = [CEREMONY_ADDR_V4, CEREMONY_ADDR_V6];
pub const CEREMONY_ORIGIN: &str = "http://localhost:18734";
/// Compiled default loopback port for the hosted-relay upstream. Used when
/// the protected configuration omits `remote_upstream_port`.
pub const DEFAULT_REMOTE_UPSTREAM_PORT: u16 = 18_735;
pub const REMOTE_CEREMONY_UPSTREAM: SocketAddr = SocketAddr::new(
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    DEFAULT_REMOTE_UPSTREAM_PORT,
);
/// Compiled default ceremony port. Used when the protected configuration
/// omits `ceremony_port`.
pub const DEFAULT_CEREMONY_PORT: u16 = 18_734;

/// Small immutable ceremony endpoint value. Port, IPv4/IPv6 bind addresses,
/// Host, origin, and URL construction live together so they cannot disagree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CeremonyEndpoint {
    port: u16,
    /// Loopback port where the relay tunnel delivers hosted-surface streams.
    remote_upstream_port: u16,
}

impl CeremonyEndpoint {
    /// Resolve and validate a configured port. Accepts 1 through 65535 in
    /// every build; rejects zero before listeners or ceremony state open.
    pub fn new(port: u16) -> Result<Self, ProtocolError> {
        if port == 0 {
            return Err(protocol(
                ProtocolErrorCode::MalformedFrame,
                "ceremony_port must be between 1 and 65535; correct it in the Broker configuration file",
            ));
        }
        Ok(Self {
            port,
            remote_upstream_port: DEFAULT_REMOTE_UPSTREAM_PORT,
        })
    }

    pub fn default_endpoint() -> Self {
        Self {
            port: DEFAULT_CEREMONY_PORT,
            remote_upstream_port: DEFAULT_REMOTE_UPSTREAM_PORT,
        }
    }

    /// Use a configured relay upstream port. Accepts 1 through 65535 in every
    /// build and rejects the ceremony port itself, so the two loopback
    /// listeners can never contend for one address.
    pub fn with_remote_upstream_port(self, port: u16) -> Result<Self, ProtocolError> {
        if port == 0 {
            return Err(protocol(
                ProtocolErrorCode::MalformedFrame,
                "remote_upstream_port must be between 1 and 65535; correct it in the Broker configuration file",
            ));
        }
        if port == self.port {
            return Err(protocol(
                ProtocolErrorCode::MalformedFrame,
                "remote_upstream_port must differ from ceremony_port; correct it in the Broker configuration file",
            ));
        }
        Ok(Self {
            remote_upstream_port: port,
            ..self
        })
    }

    pub fn port(self) -> u16 {
        self.port
    }

    pub fn remote_upstream_port(self) -> u16 {
        self.remote_upstream_port
    }

    /// IPv4 loopback address the hosted-surface listener binds and the relay
    /// tunnel forwards to.
    pub fn remote_upstream_addr(self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.remote_upstream_port)
    }

    pub fn addr_v4(self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)
    }

    pub fn addr_v6(self) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.port)
    }

    pub fn addrs(self) -> [SocketAddr; 2] {
        [self.addr_v4(), self.addr_v6()]
    }

    /// Host header value, serialized as browsers do: bare `localhost` for
    /// HTTP port 80, otherwise `localhost:<port>`.
    pub fn host(self) -> String {
        if self.port == 80 {
            "localhost".to_owned()
        } else {
            format!("localhost:{}", self.port)
        }
    }

    /// Ceremony origin, serialized as browsers do.
    pub fn origin(self) -> String {
        format!("http://{}", self.host())
    }

    pub fn session_url(self, token: &Base64UrlBytes) -> String {
        format!("{}/ceremony/{}", self.origin(), token.encoded())
    }

    /// `localhost:<port>` diagnostic form used in startup failure reports.
    pub fn address_string(self) -> String {
        format!("localhost:{}", self.port)
    }
}

impl Default for CeremonyEndpoint {
    fn default() -> Self {
        Self::default_endpoint()
    }
}
pub const MAX_CEREMONY_BODY_BYTES: usize = 16 * 1024;
pub const CEREMONY_OWNER_HEADER: &str = "x-bloom-ceremony-owner";
pub const CEREMONY_OWNER_VALUE: &str = "bloom-broker-v1";
const INVALID_ATTEMPT_LIMIT: u32 = 8;
const CANCELLATION_BACKOFF_MS: u64 = 2_000;
const REVIEW_MANIFEST_DOMAIN: &[u8] = b"bloom-broker-review-manifest/v1";
const OUTPUT_ACK_TTL_MS: u64 = 15 * 60 * 1_000;
const REMOTE_PRECOMMIT_SESSION_MS: u64 = 5 * 60 * 1_000;
const REMOTE_COOKIE_MAX_MS: u64 = 25 * 60 * 1_000;
const CROSS_SURFACE_DEADLINE_MS: u64 = 10 * 60 * 1_000;
const CEREMONY_STORAGE_VERSION: i64 = 2;

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
    fn surface_status(&self) -> Result<SurfaceStatus, SignerProtocolError>;

    fn report_surface_effective(
        &self,
        _report: SurfaceEffectiveReport,
    ) -> Result<SurfaceStatus, SignerProtocolError> {
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::ServiceUnavailable,
            "surface readiness reporting unavailable",
        ))
    }

    fn cross_surface_pair_start(
        &self,
        _request: CrossSurfacePairStartRequest,
    ) -> Result<CrossSurfacePairing, SignerProtocolError> {
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::ServiceUnavailable,
            "cross-surface pairing unavailable",
        ))
    }

    fn cross_surface_prepare_source(
        &self,
        _request: CrossSurfacePrepareSourceRequest,
    ) -> Result<CrossSurfaceSourcePrepared, SignerProtocolError> {
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::ServiceUnavailable,
            "cross-surface preparation unavailable",
        ))
    }

    fn cross_surface_complete_source(
        &self,
        _request: CrossSurfaceCompleteSourceRequest,
    ) -> Result<CrossSurfaceHandoff, SignerProtocolError> {
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::ServiceUnavailable,
            "cross-surface authorization unavailable",
        ))
    }

    fn cross_surface_complete_destination(
        &self,
        _request: CrossSurfaceCompleteDestinationRequest,
    ) -> Result<CustodyResult, SignerProtocolError> {
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::ServiceUnavailable,
            "cross-surface completion unavailable",
        ))
    }

    fn cross_surface_already_registered(
        &self,
        _request: CrossSurfaceAlreadyRegisteredRequest,
    ) -> Result<bloom_signer_api::CeremonyPublicStatus, SignerProtocolError> {
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::ServiceUnavailable,
            "cross-surface existing-passkey outcome unavailable",
        ))
    }

    /// Public credential projection for one wallet. Broker uses it only to
    /// choose which surface can approve a passkey addition; Signer still
    /// enforces eligibility when it prepares the approving leg.
    fn credential_list_public(
        &self,
        _request: bloom_signer_api::WalletRequest,
    ) -> Result<Vec<bloom_signer_api::CredentialPublic>, SignerProtocolError> {
        Err(SignerProtocolError::new(
            SignerProtocolErrorCode::ServiceUnavailable,
            "credential listing unavailable",
        ))
    }

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
    served_origin: String,
}

#[derive(Clone, Copy)]
enum BackoffClock {
    Trusted,
    Monotonic,
}

#[derive(Clone, Copy)]
enum BackoffDeadline {
    Trusted(u64),
    Monotonic(std::time::Instant),
}

impl BackoffDeadline {
    fn remaining_ms(self, trusted_now_ms: u64) -> u64 {
        match self {
            Self::Trusted(until_ms) => until_ms.saturating_sub(trusted_now_ms),
            Self::Monotonic(until) => until
                .checked_duration_since(std::time::Instant::now())
                .map(|remaining| {
                    u64::try_from(remaining.as_millis())
                        .unwrap_or(u64::MAX)
                        .saturating_add(u64::from(remaining.subsec_nanos() % 1_000_000 != 0))
                })
                .unwrap_or(0),
        }
    }
}

struct BrokerInner {
    signer: Arc<dyn CeremonySigner>,
    endpoint: CeremonyEndpoint,
    limits: CeremonyLimits,
    /// Serializes the admission decision through durable session insertion so
    /// concurrent prepares cannot all reserve the same remaining capacity.
    creation_admission: Mutex<()>,
    sessions: Mutex<HashMap<String, BrowserSession>>,
    operations: Mutex<HashMap<OperationId, String>>,
    cancellation_backoff: Mutex<HashMap<Token, (u32, BackoffDeadline)>>,
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
    #[serde(default)]
    remote_auth: Option<RemoteBrowserAuth>,
    #[serde(default = "local_ceremony_origin")]
    origin: String,
    expires_at_ms: u64,
    created_at_ms: u64,
    terminal_at_ms: Option<u64>,
    state: CeremonyState,
    terminal_result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_retain_until_ms: Option<u64>,
    #[serde(default)]
    verification_credentials: Vec<WebAuthnCredential>,
    #[serde(default)]
    policy_update: Option<PolicyUpdateCeremonyPrepareRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cross_surface: Option<CrossSurfaceFlow>,
    #[serde(default)]
    auxiliary: bool,
    projection: BrowserProjection,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CrossSurfaceFlow {
    role: CrossSurfaceRole,
    source_surface: SurfaceRef,
    destination_surface: SurfaceRef,
    exact_terms_digest: Digest32,
    destination_ceremony_id: Digest32,
    source_ceremony_id: Option<Digest32>,
    pairing: Option<CrossSurfacePairing>,
    source_prepared: Option<CrossSurfaceSourcePrepared>,
    handoff: Option<CrossSurfaceHandoff>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CrossSurfaceRole {
    Destination,
    Source,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CrossSurfaceBrowserProjection {
    role: CrossSurfaceRole,
    wallet_id: Token,
    source_origin: String,
    destination_origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pairing: Option<CrossSurfacePairing>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_prepared: Option<CrossSurfaceSourcePrepared>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteBrowserAuth {
    cookie_hash: [u8; 32],
    csrf_hash: [u8; 32],
    #[serde(default)]
    precommit_expires_at_ms: u64,
    expires_at_ms: u64,
}

impl RemoteBrowserAuth {
    fn allows(&self, state: CeremonyState, result_until_ms: Option<u64>, now_ms: u64) -> bool {
        let deadline = if matches!(
            state,
            CeremonyState::WalletCommitted | CeremonyState::AwaitingRecoveryAck
        ) {
            self.expires_at_ms
        } else if state == CeremonyState::Succeeded {
            result_until_ms.unwrap_or(0).min(self.expires_at_ms)
        } else {
            self.precommit_expires_at_ms
        };
        now_ms < deadline
    }
}

fn local_ceremony_origin() -> String {
    CEREMONY_ORIGIN.to_owned()
}

/// Decode the released schema-1 projection. Surface identity and credential
/// authority generation were added after that release; their only valid
/// predecessor meaning is the compiled localhost identity at generation zero.
fn decode_stored_browser_session(encoded: &str) -> Result<BrowserSession, serde_json::Error> {
    let mut value: serde_json::Value = serde_json::from_str(encoded)?;
    let legacy_surface = serde_json::to_value(bloom_signer_api::legacy_local_surface())
        .expect("the compiled legacy surface must serialize");
    if let Some(session) = value.as_object_mut() {
        if let Some(policy_custody) = session
            .get_mut("policy_update")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|policy| policy.get_mut("custody"))
            .and_then(serde_json::Value::as_object_mut)
        {
            if !policy_custody.contains_key("surface") {
                policy_custody.insert("surface".to_owned(), legacy_surface.clone());
            }
        }
        if let Some(projection) = session
            .get_mut("projection")
            .and_then(serde_json::Value::as_object_mut)
        {
            if let Some(contribution) = projection
                .get_mut("signer_contribution")
                .and_then(serde_json::Value::as_object_mut)
            {
                if !contribution.contains_key("surface") {
                    contribution.insert("surface".to_owned(), legacy_surface.clone());
                }
                if !contribution.contains_key("credential_authority_generation") {
                    contribution.insert(
                        "credential_authority_generation".to_owned(),
                        serde_json::Value::String("0".to_owned()),
                    );
                }
            }
            if let Some(challenges) = projection
                .get_mut("challenges")
                .and_then(serde_json::Value::as_array_mut)
            {
                for challenge in challenges {
                    if let Some(binding) = challenge
                        .get_mut("binding")
                        .and_then(serde_json::Value::as_object_mut)
                    {
                        if !binding.contains_key("surface") {
                            binding.insert("surface".to_owned(), legacy_surface.clone());
                        }
                    }
                }
            }
        }
    }
    serde_json::from_value(value)
}

#[derive(Deserialize)]
struct StoredSessionIndex {
    operation_id: OperationId,
    state: CeremonyState,
    projection: StoredProjectionIndex,
}

#[derive(Deserialize)]
struct StoredProjectionIndex {
    ceremony_id: Digest32,
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
    origin: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cross_surface: Option<CrossSurfaceBrowserProjection>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteFragmentExchange {
    capability: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossPairBody {
    destination_hpke_public_key: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossAuthorizeBody {
    authority_assertion: bloom_signer_api::WebAuthnAssertion,
    encrypted_authority_prf: HpkeEnvelope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossAlreadyRegisteredBody {
    capability: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossFinishBody {
    capability: Base64UrlBytes,
    attestation: bloom_signer_api::WebAuthnAttestation,
    prf_assertion: bloom_signer_api::WebAuthnAssertion,
    encrypted_new_prf: HpkeEnvelope,
}

impl CeremonyBroker {
    pub fn signer_surface_status(&self) -> Result<SurfaceStatus, ProtocolError> {
        self.inner
            .signer
            .surface_status()
            .map_err(signer_error_to_machine)
    }

    pub fn report_surface_effective(
        &self,
        report: SurfaceEffectiveReport,
    ) -> Result<SurfaceStatus, ProtocolError> {
        self.inner
            .signer
            .report_surface_effective(report)
            .map_err(signer_error_to_machine)
    }

    pub fn new(signer: Arc<dyn CeremonySigner>) -> Self {
        Self::new_with_limits(signer, CeremonyLimits::default())
    }

    /// Construct with an explicit admission policy. Deployments configure the
    /// policy at startup; this constructor is how a non-default policy reaches
    /// an in-memory Broker.
    pub fn new_with_limits(signer: Arc<dyn CeremonySigner>, limits: CeremonyLimits) -> Self {
        Self::from_parts(
            signer,
            CeremonyEndpoint::default(),
            limits,
            None,
            None,
            None,
        )
    }

    pub fn new_with_endpoint(signer: Arc<dyn CeremonySigner>, endpoint: CeremonyEndpoint) -> Self {
        Self::from_parts(
            signer,
            endpoint,
            CeremonyLimits::default(),
            None,
            None,
            None,
        )
    }

    pub fn new_with_manifest_signer(
        signer: Arc<dyn CeremonySigner>,
        broker_key_id: Token,
        signing_key: SigningKey,
    ) -> Self {
        Self::from_parts(
            signer,
            CeremonyEndpoint::default(),
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
        Self::open_with_endpoint(legacy_path, signer, journal, CeremonyEndpoint::default())
    }

    pub fn open_with_endpoint(
        legacy_path: impl AsRef<FsPath>,
        signer: Arc<dyn CeremonySigner>,
        journal: Arc<BrokerJournal>,
        endpoint: CeremonyEndpoint,
    ) -> Result<Self, ProtocolError> {
        let database = open_audited_ceremony_store(legacy_path, &journal)?;
        let broker = Self::from_parts(
            signer,
            endpoint,
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
        Self::open_with_manifest_signer_audited_and_endpoint(
            legacy_path,
            signer,
            broker_key_id,
            signing_key,
            journal,
            limits,
            CeremonyEndpoint::default(),
        )
    }

    pub fn open_with_manifest_signer_audited_and_endpoint(
        legacy_path: impl AsRef<FsPath>,
        signer: Arc<dyn CeremonySigner>,
        broker_key_id: Token,
        signing_key: SigningKey,
        journal: Arc<BrokerJournal>,
        limits: CeremonyLimits,
        endpoint: CeremonyEndpoint,
    ) -> Result<Self, ProtocolError> {
        let database = open_audited_ceremony_store(legacy_path, &journal)?;
        let broker = Self::from_parts(
            signer,
            endpoint,
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

    /// Resolve a caller's bounded preference against authenticated Signer
    /// state. Only Signer descriptors can authorize an origin or RP ID.
    pub fn select_surface(
        &self,
        selection: CeremonySurfaceSelection,
    ) -> Result<SurfaceDescriptor, ProtocolError> {
        let status = self
            .inner
            .signer
            .surface_status()
            .map_err(signer_error_to_machine)?;
        let mut local = None;
        let mut remote = None;
        for descriptor in status.surfaces {
            descriptor.validate().map_err(signer_error_to_machine)?;
            if descriptor.identity.surface_id.as_str() == "local" && local.is_none() {
                local = Some(descriptor);
            } else if descriptor.identity.surface_id.as_str() == "remote" && remote.is_none() {
                remote = Some(descriptor);
            } else {
                return Err(protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    "invalid Signer surface inventory",
                ));
            }
        }
        let local = local.ok_or_else(|| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer local surface missing",
            )
        })?;
        if local.lifecycle != SurfaceLifecycle::Active {
            return Err(protocol(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer local surface inactive",
            ));
        }
        match selection {
            CeremonySurfaceSelection::Local => Ok(local),
            CeremonySurfaceSelection::Default
                if status.desired_mode == ExposureMode::LocalhostOnly =>
            {
                Ok(local)
            }
            CeremonySurfaceSelection::Default | CeremonySurfaceSelection::Remote => {
                if selection == CeremonySurfaceSelection::Default && remote.is_none() {
                    // A fresh legacy installation has not received a hosted
                    // identity yet. Preserve explicit pending status while
                    // keeping its existing local ceremony entrypoints usable.
                    return Ok(local);
                }
                if status.desired_mode != ExposureMode::RemoteEnabled
                    || status.effective_mode != ExposureMode::RemoteEnabled
                    || status.desired_revision != status.effective_revision
                    || !status.remote_tls_ready
                    || !status.remote_routing_ready
                    || !remote
                        .as_ref()
                        .is_some_and(|surface| surface.lifecycle == SurfaceLifecycle::Active)
                {
                    return Err(protocol(
                        ProtocolErrorCode::ServiceUnavailable,
                        "hosted ceremony surface is pending; explicitly select local for a localhost ceremony",
                    ));
                }
                remote.ok_or_else(|| {
                    protocol(
                        ProtocolErrorCode::ServiceUnavailable,
                        "Signer remote surface missing",
                    )
                })
            }
        }
    }

    pub fn exposure_status(&self) -> Result<CeremonyExposureStatus, ProtocolError> {
        let status = self
            .inner
            .signer
            .surface_status()
            .map_err(signer_error_to_machine)?;
        let remote = status
            .surfaces
            .iter()
            .find(|surface| surface.identity.surface_id.as_str() == "remote")
            .map(|surface| {
                surface.validate().map_err(signer_error_to_machine)?;
                Ok::<_, ProtocolError>(surface.identity.origin.clone())
            })
            .transpose()?;
        let mode = |mode| match mode {
            ExposureMode::RemoteEnabled => CeremonyExposureMode::RemoteEnabled,
            ExposureMode::LocalhostOnly => CeremonyExposureMode::LocalhostOnly,
        };
        let stage = if status.desired_mode == ExposureMode::LocalhostOnly {
            if status.effective_mode == ExposureMode::LocalhostOnly
                && status.desired_revision == status.effective_revision
            {
                CeremonyExposureStage::LocalhostOnly
            } else {
                CeremonyExposureStage::Degraded
            }
        } else if remote.is_none() {
            CeremonyExposureStage::Unprovisioned
        } else if !status.remote_tls_ready {
            CeremonyExposureStage::CertificatePending
        } else if !status.remote_routing_ready {
            CeremonyExposureStage::RoutingPending
        } else if status.effective_mode == ExposureMode::RemoteEnabled
            && status.desired_revision == status.effective_revision
        {
            CeremonyExposureStage::Enabled
        } else {
            CeremonyExposureStage::Degraded
        };
        Ok(CeremonyExposureStatus {
            desired_mode: mode(status.desired_mode),
            desired_revision: status.desired_revision,
            effective_mode: mode(status.effective_mode),
            effective_revision: status.effective_revision,
            local_origin: self.inner.endpoint.origin(),
            remote_origin: remote,
            remote_tls_ready: status.remote_tls_ready,
            remote_routing_ready: status.remote_routing_ready,
            stage,
        })
    }

    fn origin_for_surface(&self, surface: &SurfaceRef) -> Result<String, ProtocolError> {
        let status = self
            .inner
            .signer
            .surface_status()
            .map_err(signer_error_to_machine)?;
        let descriptor = status
            .surfaces
            .into_iter()
            .find(|candidate| candidate.reference() == *surface)
            .ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    "Signer surface changed",
                )
            })?;
        descriptor.validate().map_err(signer_error_to_machine)?;
        if descriptor.lifecycle != SurfaceLifecycle::Active {
            return Err(protocol(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer surface inactive",
            ));
        }
        // The local surface is served on this Broker's configured ceremony
        // port; its persisted Signer identity stays at the shipping origin.
        if descriptor.identity.surface_id.as_str() == "local" {
            return Ok(self.inner.endpoint.origin());
        }
        Ok(descriptor.identity.origin)
    }

    /// The instance ceremony endpoint (port, addrs, Host, origin, URLs).
    pub fn endpoint(&self) -> CeremonyEndpoint {
        self.inner.endpoint
    }

    pub fn ceremony_session_url(&self, token: &Base64UrlBytes) -> String {
        self.inner.endpoint.session_url(token)
    }

    fn from_parts(
        signer: Arc<dyn CeremonySigner>,
        endpoint: CeremonyEndpoint,
        limits: CeremonyLimits,
        database: Option<Arc<std::sync::Mutex<Connection>>>,
        manifest_signer: Option<(Token, SigningKey)>,
        journal: Option<Arc<BrokerJournal>>,
    ) -> Self {
        Self {
            served_origin: endpoint.origin(),
            inner: Arc::new(BrokerInner {
                signer,
                endpoint,
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
        let origin = self.origin_for_surface(&prepared.contribution.surface)?;
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
            origin,
        })?;
        let url = session_url(&session);
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
        self.prepare_custody_reviewed(request, None, now_ms)
    }

    pub fn prepare_cross_surface(
        &self,
        request: CeremonyCrossSurfacePrepareRequest,
        now_ms: u64,
    ) -> Result<CeremonyCrossSurfacePrepareResponse, ProtocolError> {
        self.expire_sessions(now_ms)?;
        // `Default` resolves like every other ceremony: the hosted surface
        // when it is effective, otherwise localhost.
        let destination = self.select_surface(request.destination)?;
        let request_digest = digest(&request)?;
        let _guard = self.inner.creation_admission.lock();
        if let Some(ceremony_id) = self
            .inner
            .operations
            .lock()
            .get(&request.operation_id)
            .cloned()
        {
            let sessions = self.inner.sessions.lock();
            let session = sessions.get(&ceremony_id).ok_or_else(not_found)?;
            if session.request_digest != request_digest || session.cross_surface.is_none() {
                return Err(operation_conflict());
            }
            if session.state != CeremonyState::AwaitingUser || session.token.is_none() {
                return Err(replay());
            }
            return Ok(CeremonyCrossSurfacePrepareResponse {
                operation_id: request.operation_id,
                ceremony_id: session.projection.ceremony_id.clone(),
                state: BrokerCeremonyState::AwaitingUser,
                destination_url: session_url(session),
                expires_at_ms: DecimalU64::new(session.expires_at_ms),
            });
        }
        let source = self.select_approving_surface(&request.wallet_id, &destination)?;
        self.enforce_creation_bounds(Some(&request.wallet_id), false, now_ms)?;
        let destination_surface = destination.reference();
        let source_surface = source.reference();
        let terms_digest = digest(&(
            "bloom.cross_surface_credential_add.v1",
            &request.operation_id,
            &request.wallet_id,
            &source_surface,
            &destination_surface,
        ))?;
        let mut id_bytes = [0_u8; 32];
        SysRng.try_fill_bytes(&mut id_bytes).map_err(malformed)?;
        let ceremony_id = Digest32::from_bytes(id_bytes);
        let expires_at_ms = now_ms.saturating_add(CROSS_SURFACE_DEADLINE_MS);
        let mut session = self.new_session(NewBrowserSession {
            operation_id: request.operation_id.clone(),
            request_digest,
            wallet_id: Some(request.wallet_id.clone()),
            anonymous_registration: false,
            ceremony_kind: CeremonyKind::CredentialAdd,
            ceremony_id: ceremony_id.clone(),
            review_manifest: Some(serde_json::json!({
                "schema": "bloom.cross_surface_add_review.v1",
                "title": "Add a wallet passkey",
                "wallet_name": request.wallet_id,
                "source_origin": source.identity.origin.clone(),
                "destination_origin": destination.identity.origin.clone(),
                "exact_terms_digest": terms_digest,
            })),
            challenges: Vec::new(),
            signer_contribution: serde_json::Value::Null,
            webauthn_options: CeremonyWebAuthnOptions {
                allowed_credentials: Vec::new(),
                registration_user_handle: None,
                registration_prf_salt: None,
            },
            verification_credentials: Vec::new(),
            policy_update: None,
            expires_at_ms,
            created_at_ms: now_ms,
            origin: destination.identity.origin.clone(),
        })?;
        session.projection.cross_surface = Some(CrossSurfaceBrowserProjection {
            role: CrossSurfaceRole::Destination,
            wallet_id: request.wallet_id,
            source_origin: source.identity.origin,
            destination_origin: destination.identity.origin,
            pairing: None,
            source_prepared: None,
        });
        session.cross_surface = Some(CrossSurfaceFlow {
            role: CrossSurfaceRole::Destination,
            source_surface,
            destination_surface,
            exact_terms_digest: terms_digest,
            destination_ceremony_id: ceremony_id.clone(),
            source_ceremony_id: None,
            pairing: None,
            source_prepared: None,
            handoff: None,
        });
        let url = session_url(&session);
        self.insert_session(ceremony_id.clone(), session)?;
        Ok(CeremonyCrossSurfacePrepareResponse {
            operation_id: request.operation_id,
            ceremony_id,
            state: BrokerCeremonyState::AwaitingUser,
            destination_url: url,
            expires_at_ms: DecimalU64::new(expires_at_ms),
        })
    }

    /// Choose the surface whose existing passkey approves a new one.
    ///
    /// A wallet passkey on the destination's own surface is preferred: that
    /// approval link opens on any device holding one, whereas a localhost
    /// link only opens on the Bloom host. Otherwise the other surface
    /// approves, which is the original cross-surface addition. With neither,
    /// no approval can ever succeed, so the ceremony is refused here instead
    /// of reaching `AWAITING_USER` and failing on the user's device.
    fn select_approving_surface(
        &self,
        wallet_id: &Token,
        destination: &SurfaceDescriptor,
    ) -> Result<SurfaceDescriptor, ProtocolError> {
        let credentials = self
            .inner
            .signer
            .credential_list_public(bloom_signer_api::WalletRequest {
                wallet_id: wallet_id.clone(),
            })
            .map_err(signer_error_to_machine)?;
        let other = if destination.identity.surface_id.as_str() == "local" {
            CeremonySurfaceSelection::Remote
        } else {
            CeremonySurfaceSelection::Local
        };
        approving_surface(&credentials, destination, self.select_surface(other).ok()).ok_or_else(
            || {
                protocol(
                    ProtocolErrorCode::ApprovalNotFound,
                    format!(
                        "wallet {} has no active passkey that can approve adding another",
                        wallet_id.as_str()
                    ),
                )
            },
        )
    }

    fn pair_cross_surface(
        &self,
        ceremony_id: &str,
        body: CrossPairBody,
        now_ms: u64,
    ) -> Result<serde_json::Value, ProtocolError> {
        let _guard = self.inner.creation_admission.lock();
        let destination = self
            .inner
            .sessions
            .lock()
            .get(ceremony_id)
            .cloned()
            .ok_or_else(not_found)?;
        let flow = destination
            .cross_surface
            .as_ref()
            .filter(|flow| flow.role == CrossSurfaceRole::Destination)
            .ok_or_else(kind_mismatch)?;
        if destination.state != CeremonyState::AwaitingUser || destination.expires_at_ms <= now_ms {
            return Err(replay());
        }
        if let (Some(source_id), Some(pairing)) = (&flow.source_ceremony_id, &flow.pairing) {
            let source = self
                .inner
                .sessions
                .lock()
                .get(source_id.as_str())
                .cloned()
                .ok_or_else(not_found)?;
            if pairing.destination_hpke_public_key != body.destination_hpke_public_key
                || source.token.is_none()
            {
                return Err(operation_conflict());
            }
            return Ok(serde_json::json!({
                "source_url": session_url(&source),
                "confirmation_code": pairing.confirmation_code,
                "pairing_id": pairing.pairing_id,
                "expires_at_ms": pairing.expires_at_ms,
            }));
        }
        if body.destination_hpke_public_key.decode().len() != 32 {
            return Err(protocol(
                ProtocolErrorCode::MalformedFrame,
                "destination HPKE key must be 32 bytes",
            ));
        }
        let pairing = self
            .inner
            .signer
            .cross_surface_pair_start(CrossSurfacePairStartRequest {
                destination_surface: flow.destination_surface.clone(),
                operation_id: destination.operation_id.clone(),
                exact_terms_digest: flow.exact_terms_digest.clone(),
                destination_hpke_public_key: body.destination_hpke_public_key,
                expires_at_ms: DecimalU64::new(destination.expires_at_ms),
            })
            .map_err(signer_error_to_machine)?;
        if pairing.destination_surface != flow.destination_surface
            || pairing.operation_id != destination.operation_id
            || pairing.exact_terms_digest != flow.exact_terms_digest
            || pairing.expires_at_ms.get() > destination.expires_at_ms
        {
            return Err(operation_conflict());
        }
        let wallet_id = destination.wallet_id.clone().ok_or_else(not_found)?;
        let prepared = self
            .inner
            .signer
            .cross_surface_prepare_source(CrossSurfacePrepareSourceRequest {
                pairing_id: pairing.pairing_id.clone(),
                operation_id: destination.operation_id.clone(),
                source_surface: flow.source_surface.clone(),
                wallet_id: wallet_id.clone(),
                exact_terms_digest: flow.exact_terms_digest.clone(),
            })
            .map_err(signer_error_to_machine)?;
        if prepared.pairing != pairing
            || prepared.source_surface != flow.source_surface
            || prepared.wallet_id != wallet_id
        {
            return Err(operation_conflict());
        }
        let mut id_bytes = [0_u8; 32];
        SysRng.try_fill_bytes(&mut id_bytes).map_err(malformed)?;
        let source_id = Digest32::from_bytes(id_bytes);
        let source_origin = self.origin_for_surface(&flow.source_surface)?;
        let destination_origin = destination.origin.clone();
        let mut source = self.new_session(NewBrowserSession {
            operation_id: destination.operation_id.clone(),
            request_digest: destination.request_digest.clone(),
            wallet_id: Some(wallet_id.clone()),
            anonymous_registration: false,
            ceremony_kind: CeremonyKind::CredentialAdd,
            ceremony_id: source_id.clone(),
            review_manifest: destination.projection.review_manifest.clone(),
            challenges: vec![prepared.source_challenge.clone()],
            signer_contribution: serde_json::to_value(&prepared).map_err(malformed)?,
            webauthn_options: CeremonyWebAuthnOptions {
                allowed_credentials: prepared.source_prf_inputs.clone(),
                registration_user_handle: None,
                registration_prf_salt: None,
            },
            verification_credentials: prepared.source_credentials.clone(),
            policy_update: None,
            expires_at_ms: pairing.expires_at_ms.get(),
            created_at_ms: now_ms,
            origin: source_origin.clone(),
        })?;
        source.auxiliary = true;
        source.cross_surface = Some(CrossSurfaceFlow {
            role: CrossSurfaceRole::Source,
            source_surface: flow.source_surface.clone(),
            destination_surface: flow.destination_surface.clone(),
            exact_terms_digest: flow.exact_terms_digest.clone(),
            destination_ceremony_id: flow.destination_ceremony_id.clone(),
            source_ceremony_id: Some(source_id.clone()),
            pairing: Some(pairing.clone()),
            source_prepared: Some(prepared.clone()),
            handoff: None,
        });
        source.projection.cross_surface = Some(CrossSurfaceBrowserProjection {
            role: CrossSurfaceRole::Source,
            wallet_id,
            source_origin,
            destination_origin,
            pairing: Some(pairing.clone()),
            source_prepared: Some(prepared.clone()),
        });
        let source_url = session_url(&source);
        let mut next_destination = destination.clone();
        let next_flow = next_destination
            .cross_surface
            .as_mut()
            .ok_or_else(not_found)?;
        next_flow.pairing = Some(pairing.clone());
        next_flow.source_prepared = Some(prepared);
        next_flow.source_ceremony_id = Some(source_id.clone());
        if let Some(projection) = next_destination.projection.cross_surface.as_mut() {
            projection.pairing = Some(pairing.clone());
        }
        self.persist_session(&source)?;
        self.persist_session(&next_destination)?;
        let mut sessions = self.inner.sessions.lock();
        sessions.insert(source_id.as_str().to_owned(), source);
        sessions.insert(ceremony_id.to_owned(), next_destination);
        Ok(serde_json::json!({
            "source_url": source_url,
            "confirmation_code": pairing.confirmation_code,
            "pairing_id": pairing.pairing_id,
            "expires_at_ms": pairing.expires_at_ms,
        }))
    }

    fn authorize_cross_surface(
        &self,
        ceremony_id: &str,
        body: CrossAuthorizeBody,
        now_ms: u64,
    ) -> Result<serde_json::Value, ProtocolError> {
        let _guard = self.inner.creation_admission.lock();
        let source = self
            .inner
            .sessions
            .lock()
            .get(ceremony_id)
            .cloned()
            .ok_or_else(not_found)?;
        let flow = source
            .cross_surface
            .as_ref()
            .filter(|flow| flow.role == CrossSurfaceRole::Source)
            .ok_or_else(kind_mismatch)?;
        if source.state != CeremonyState::AwaitingUser || source.expires_at_ms <= now_ms {
            return Err(replay());
        }
        let pairing = flow.pairing.as_ref().ok_or_else(not_found)?;
        let handoff = self
            .inner
            .signer
            .cross_surface_complete_source(CrossSurfaceCompleteSourceRequest {
                pairing_id: pairing.pairing_id.clone(),
                operation_id: source.operation_id.clone(),
                authority_assertion: body.authority_assertion,
                encrypted_authority_prf: body.encrypted_authority_prf,
            })
            .map_err(signer_error_to_machine)?;
        if handoff.pairing_id != pairing.pairing_id
            || handoff.expires_at_ms.get() > pairing.expires_at_ms.get()
        {
            return Err(operation_conflict());
        }
        let destination_id = flow.destination_ceremony_id.as_str().to_owned();
        let mut destination = self
            .inner
            .sessions
            .lock()
            .get(&destination_id)
            .cloned()
            .ok_or_else(not_found)?;
        let destination_flow = destination
            .cross_surface
            .as_mut()
            .ok_or_else(kind_mismatch)?;
        if destination_flow.role != CrossSurfaceRole::Destination
            || destination_flow.pairing.as_ref() != Some(pairing)
        {
            return Err(operation_conflict());
        }
        destination_flow.handoff = Some(handoff);
        let mut source_done = source;
        source_done.state = CeremonyState::Completed;
        latch_terminal(&mut source_done, now_ms);
        self.persist_session(&destination)?;
        self.persist_session(&source_done)?;
        let mut sessions = self.inner.sessions.lock();
        sessions.insert(destination_id, destination.clone());
        sessions.insert(ceremony_id.to_owned(), source_done);
        Ok(serde_json::json!({"destination_origin": destination.origin}))
    }

    fn cross_surface_handoff(
        &self,
        ceremony_id: &str,
        now_ms: u64,
    ) -> Result<serde_json::Value, ProtocolError> {
        let destination = self
            .inner
            .sessions
            .lock()
            .get(ceremony_id)
            .cloned()
            .ok_or_else(not_found)?;
        let flow = destination
            .cross_surface
            .as_ref()
            .filter(|flow| flow.role == CrossSurfaceRole::Destination)
            .ok_or_else(kind_mismatch)?;
        if destination.expires_at_ms <= now_ms || is_terminal(destination.state) {
            return Err(replay());
        }
        if let (Some(handoff), Some(prepared)) = (&flow.handoff, &flow.source_prepared) {
            Ok(
                serde_json::json!({"state":"ready", "encrypted_capability": handoff.encrypted_capability,
                "source_prepared": prepared}),
            )
        } else {
            Ok(serde_json::json!({"state":"waiting"}))
        }
    }

    fn finish_cross_surface(
        &self,
        ceremony_id: &str,
        body: CrossFinishBody,
        now_ms: u64,
    ) -> Result<serde_json::Value, ProtocolError> {
        let _guard = self.inner.creation_admission.lock();
        let destination = self
            .inner
            .sessions
            .lock()
            .get(ceremony_id)
            .cloned()
            .ok_or_else(not_found)?;
        let flow = destination
            .cross_surface
            .as_ref()
            .filter(|flow| flow.role == CrossSurfaceRole::Destination)
            .ok_or_else(kind_mismatch)?;
        if destination.state == CeremonyState::WalletCommitted {
            return self.finalize_committed_session(ceremony_id, now_ms);
        }
        if destination.state == CeremonyState::Succeeded
            && destination
                .result_retain_until_ms
                .is_some_and(|deadline| deadline > now_ms)
        {
            return destination.terminal_result.ok_or_else(not_found);
        }
        if destination.state != CeremonyState::AwaitingUser
            || destination.expires_at_ms <= now_ms
            || flow.handoff.is_none()
        {
            return Err(replay());
        }
        let pairing = flow.pairing.as_ref().ok_or_else(not_found)?;
        let result = self
            .inner
            .signer
            .cross_surface_complete_destination(CrossSurfaceCompleteDestinationRequest {
                pairing_id: pairing.pairing_id.clone(),
                operation_id: destination.operation_id.clone(),
                capability: body.capability,
                attestation: body.attestation,
                prf_assertion: body.prf_assertion,
                encrypted_new_prf: body.encrypted_new_prf,
            })
            .map_err(signer_error_to_machine)?;
        if result.surface.as_ref() != Some(&flow.destination_surface)
            || result.credential_authority_generation.is_none()
            || result.wallet_id.as_ref() != destination.wallet_id.as_ref()
        {
            return Err(operation_conflict());
        }
        let receipt = serde_json::to_value(result).map_err(malformed)?;
        validate_completion_identity(
            CeremonyKind::CredentialAdd,
            &destination.operation_id,
            &destination.projection.ceremony_id,
            &receipt,
        )?;
        let mut committed = destination;
        committed.state = CeremonyState::WalletCommitted;
        committed.terminal_result = Some(receipt);
        self.persist_session(&committed)?;
        self.inner
            .sessions
            .lock()
            .insert(ceremony_id.to_owned(), committed);
        self.finalize_committed_session(ceremony_id, now_ms)
    }

    /// The destination's passkey provider already holds one of the wallet's
    /// passkeys for this surface, so WebAuthn refused to create another.
    /// Signer verifies the handoff capability and records the terminal
    /// outcome; the destination session ends as `ALREADY_REGISTERED` with no
    /// credential change.
    fn already_registered_cross_surface(
        &self,
        ceremony_id: &str,
        body: CrossAlreadyRegisteredBody,
        now_ms: u64,
    ) -> Result<serde_json::Value, ProtocolError> {
        let _guard = self.inner.creation_admission.lock();
        let destination = self
            .inner
            .sessions
            .lock()
            .get(ceremony_id)
            .cloned()
            .ok_or_else(not_found)?;
        let flow = destination
            .cross_surface
            .as_ref()
            .filter(|flow| flow.role == CrossSurfaceRole::Destination)
            .ok_or_else(kind_mismatch)?;
        if destination.state != CeremonyState::AwaitingUser
            || destination.expires_at_ms <= now_ms
            || flow.handoff.is_none()
        {
            return Err(replay());
        }
        let pairing = flow.pairing.as_ref().ok_or_else(not_found)?;
        let status = self
            .inner
            .signer
            .cross_surface_already_registered(CrossSurfaceAlreadyRegisteredRequest {
                pairing_id: pairing.pairing_id.clone(),
                operation_id: destination.operation_id.clone(),
                capability: body.capability,
            })
            .map_err(signer_error_to_machine)?;
        if status.state != CeremonyState::AlreadyRegistered
            || status.operation_id != destination.operation_id
            || status.ceremony_id != pairing.pairing_id
        {
            return Err(operation_conflict());
        }
        let mut done = destination;
        done.state = CeremonyState::AlreadyRegistered;
        latch_terminal(&mut done, now_ms);
        self.persist_session(&done)?;
        self.inner
            .sessions
            .lock()
            .insert(ceremony_id.to_owned(), done);
        Ok(serde_json::json!({"state": "already_registered"}))
    }

    /// [`Self::prepare_custody`] with a broker-authored review JSON the
    /// browser shows for account ceremonies: the owner approves the exact
    /// families, roles and frozen path templates before any key exists.
    pub fn prepare_custody_reviewed(
        &self,
        request: CustodyPrepareRequest,
        account_review: Option<serde_json::Value>,
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
        let origin = self.origin_for_surface(&prepared.contribution.surface)?;
        let session = self.new_session(NewBrowserSession {
            operation_id: request.custody_operation_id.clone(),
            request_digest,
            wallet_id: prepared.contribution.wallet_id.clone(),
            anonymous_registration,
            ceremony_kind: request.ceremony_kind,
            ceremony_id: ceremony_id.clone(),
            review_manifest: custody_review_manifest(
                &request,
                prepared.contribution.wallet_id.as_ref(),
                anonymous_registration,
                account_review,
            )?,
            challenges: prepared.challenges,
            signer_contribution: serde_json::to_value(prepared.contribution).map_err(malformed)?,
            webauthn_options: prepared.webauthn_options,
            verification_credentials: prepared.verification_credentials,
            policy_update: None,
            expires_at_ms,
            created_at_ms: now_ms,
            origin,
        })?;
        let url = session_url(&session);
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
        let origin = self.origin_for_surface(&prepared.contribution.surface)?;
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
            origin,
        })?;
        let response = PolicyUpdatePrepareResponse {
            operation_id: request.update.operation_id,
            ceremony_kind: BrokerCeremonyKind::PolicyUpdate,
            ceremony_url: session_url(&session),
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
            ceremony_url: session_url(session),
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
        let receipt_digest = match session.terminal_result.as_ref() {
            Some(result) if session.ceremony_kind == CeremonyKind::SealedApproval => {
                Some(digest(result)?)
            }
            Some(result) => Some(
                serde_json::from_value::<CustodyResult>(result.clone())
                    .map_err(malformed)?
                    .receipt_digest,
            ),
            None => None,
        };
        let ceremony_url = if session.state == CeremonyState::AwaitingUser {
            session.token.as_ref().map(|_| session_url(session))
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

    /// Public status as of `now_ms`. Status requests are a lifecycle boundary
    /// just like opening the browser: sweep first so an elapsed AwaitingUser
    /// session is reported as expired rather than as still awaiting the user.
    pub fn current_public_status(
        &self,
        operation_id: &OperationId,
        now_ms: u64,
    ) -> Result<BrokerCeremonyPublicStatus, ProtocolError> {
        self.expire_sessions(now_ms)?;
        self.public_status(operation_id)
    }

    /// Return the owner-visible URL for an approval ceremony while it is
    /// awaiting the user. Approval status is keyed by the approval digest,
    /// whereas the ceremony store is keyed by activation operation ID, so the
    /// association is recovered from the signed review manifest.
    pub fn pending_approval_ceremony(
        &self,
        approval_id: &Digest32,
        now_ms: u64,
    ) -> Result<Option<(String, DecimalU64)>, ProtocolError> {
        // Status/list requests are a lifecycle boundary just like opening the
        // browser. Sweep first so an owner who never opened the page cannot
        // leave an expired AwaitingUser row masquerading as a live URL.
        self.expire_sessions(now_ms)?;
        Ok(self.inner.sessions.lock().values().find_map(|session| {
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
                .map(|_| (session_url(session), DecimalU64::new(session.expires_at_ms)))
        }))
    }

    /// True when every owner ceremony minted for this approval died without
    /// activating it. No URL exists for the owner and none can appear, so a
    /// caller waiting on this approval is waiting on nothing.
    ///
    /// A completed ceremony is deliberately not counted: that approval is on
    /// its way to `Active`, and reporting it dead would strand a signature the
    /// owner already authorised.
    pub fn approval_ceremony_unreachable(&self, approval_id: &Digest32) -> bool {
        let mut saw_ceremony = false;
        for session in self.inner.sessions.lock().values() {
            if session.ceremony_kind != CeremonyKind::SealedApproval {
                continue;
            }
            let manifest_approval_id = session
                .projection
                .review_manifest
                .as_ref()
                .and_then(|manifest| manifest.get("approval_id"))
                .and_then(|value| value.as_str());
            if manifest_approval_id != Some(approval_id.as_str()) {
                continue;
            }
            if !matches!(
                session.state,
                CeremonyState::Cancelled | CeremonyState::Expired | CeremonyState::Failed
            ) {
                return false;
            }
            saw_ceremony = true;
        }
        saw_ceremony
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
        self.cancel_with_backoff(operation_id, now_ms, BackoffClock::Trusted)
    }

    fn cancel_from_browser(
        &self,
        operation_id: &OperationId,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.cancel_with_backoff(operation_id, now_ms, BackoffClock::Monotonic)
    }

    fn cancel_with_backoff(
        &self,
        operation_id: &OperationId,
        now_ms: u64,
        backoff_clock: BackoffClock,
    ) -> Result<(), ProtocolError> {
        let _guard = self.inner.creation_admission.lock();
        self.expire_sessions(now_ms)?;
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
            // A ceremony that died without ever committing is already what a
            // caller asking to cancel wants it to be, so report success rather
            // than an error it cannot act on. Refusing here strands the caller:
            // the operation can no longer be completed *or* abandoned, and the
            // only way out is editing durable state by hand.
            if matches!(
                session.state,
                CeremonyState::Cancelled | CeremonyState::Expired | CeremonyState::Failed
            ) && session.terminal_result.is_none()
            {
                return Ok(());
            }
            // Anything that reached the wallet is a different matter: it may
            // have taken effect, and reporting it cancelled would misdescribe
            // what happened.
            if session.state != CeremonyState::AwaitingUser {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "ceremony is past the point where it can be cancelled",
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
        // Both tabs belong to one operation. Leaving its auxiliary source live
        // would strand the wallet's admission slot after a successful cancel.
        let auxiliary = self
            .inner
            .sessions
            .lock()
            .iter()
            .filter(|(_, session)| {
                session.auxiliary
                    && &session.operation_id == operation_id
                    && !is_terminal(session.state)
            })
            .map(|(id, session)| (id.clone(), session.clone()))
            .collect::<Vec<_>>();
        for (id, mut source) in auxiliary {
            source.state = CeremonyState::Cancelled;
            latch_terminal(&mut source, now_ms);
            self.persist_session(&source)?;
            self.inner.sessions.lock().insert(id, source);
        }
        self.persist_session(&snapshot)?;
        self.inner.sessions.lock().insert(ceremony_id, snapshot);
        if let Some(wallet_id) = &wallet_id {
            self.record_backoff(wallet_id, now_ms, backoff_clock);
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
            .map(|(id, session)| (id.clone(), session.operation_id.clone(), session.state))
            .collect::<Vec<_>>();
        for (ceremony_id, operation_id, state) in live {
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
            // Losing the authenticated Machine session is infrastructure
            // cleanup, not an owner cancellation. Counting it as one lets
            // routine restarts exponentially lock a wallet out of ceremonies.
        }
        Ok(())
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(shell))
            .route("/.well-known/bloom/relay-health", get(remote_health))
            .route("/ceremony/{token}", get(ceremony_shell))
            .route("/api/session/exchange", post(exchange_remote_fragment))
            .route("/ceremony/", get(ceremony_resume_shell))
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
            .route("/api/cross/{ceremony_id}/pair", post(cross_surface_pair))
            .route(
                "/api/cross/{ceremony_id}/authorize",
                post(cross_surface_authorize),
            )
            .route(
                "/api/cross/{ceremony_id}/handoff",
                get(cross_surface_handoff),
            )
            .route(
                "/api/cross/{ceremony_id}/finish",
                post(cross_surface_finish),
            )
            .route(
                "/api/cross/{ceremony_id}/already-registered",
                post(cross_surface_already_registered),
            )
            .layer(DefaultBodyLimit::max(MAX_CEREMONY_BODY_BYTES))
            .layer(middleware::from_fn(security_headers))
            .with_state(self.clone())
    }

    /// Use the same ceremony state and handlers on a Broker-owned TLS listener.
    /// The caller must obtain this exact assigned origin from authenticated
    /// Signer state and must attach the router only to that TLS listener.
    pub fn for_remote_origin(&self, origin: &str) -> Result<Self, ProtocolError> {
        let hostname = origin.strip_prefix("https://").ok_or_else(|| {
            protocol(
                ProtocolErrorCode::MalformedFrame,
                "invalid remote ceremony origin",
            )
        })?;
        bloom_signer_api::SurfaceIdentity::remote(hostname, 0).map_err(signer_error_to_machine)?;
        Ok(Self {
            inner: self.inner.clone(),
            served_origin: origin.to_owned(),
        })
    }

    /// Serve the exact Signer-assigned origin through Broker-owned TLS. The
    /// relay client is separately pinned to this loopback socket; neither
    /// caller nor gateway supplies a forwarding destination.
    pub async fn serve_remote_tls_until<F>(
        self,
        origin: &str,
        certificate_pem: Vec<u8>,
        private_key_pem: Vec<u8>,
        shutdown: F,
    ) -> Result<(), ProtocolError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let remote = self.for_remote_origin(origin)?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(certificate_pem, private_key_pem)
            .await
            .map_err(|error| {
                protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("remote TLS material invalid: {error}"),
                )
            })?;
        let listener =
            StdTcpListener::bind(self.inner.endpoint.remote_upstream_addr()).map_err(|error| {
                protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("remote ceremony listener unavailable: {error}"),
                )
            })?;
        listener.set_nonblocking(true).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!("remote ceremony listener setup failed: {error}"),
            )
        })?;
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
        axum_server::from_tcp_rustls(listener, tls)
            .map_err(|error| {
                protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("remote TLS listener handoff failed: {error}"),
                )
            })?
            .handle(handle)
            .serve(remote.router().into_make_service())
            .await
            .map_err(|error| {
                protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("remote TLS service failed: {error}"),
                )
            })
    }

    pub fn expire_sessions(&self, now_ms: u64) -> Result<(), ProtocolError> {
        let expired = self
            .inner
            .sessions
            .lock()
            .iter()
            .filter(|(_, session)| {
                session.expires_at_ms <= now_ms
                    && (!is_terminal(session.state) || session.result_retain_until_ms.is_some())
            })
            .map(|(id, session)| (id.clone(), session.operation_id.clone()))
            .collect::<Vec<_>>();
        for (ceremony_id, operation_id) in expired {
            if self
                .inner
                .sessions
                .lock()
                .get(&ceremony_id)
                .is_some_and(|session| session.result_retain_until_ms.is_some())
            {
                let mut result = self
                    .inner
                    .sessions
                    .lock()
                    .get(&ceremony_id)
                    .cloned()
                    .ok_or_else(not_found)?;
                result.result_retain_until_ms = None;
                latch_terminal(&mut result, now_ms);
                self.persist_session(&result)?;
                self.inner.sessions.lock().insert(ceremony_id, result);
                continue;
            }
            if self
                .inner
                .sessions
                .lock()
                .get(&ceremony_id)
                .is_some_and(|session| session.auxiliary)
            {
                let mut source = self
                    .inner
                    .sessions
                    .lock()
                    .get(&ceremony_id)
                    .cloned()
                    .ok_or_else(not_found)?;
                source.state = CeremonyState::Expired;
                latch_terminal(&mut source, now_ms);
                self.persist_session(&source)?;
                self.inner.sessions.lock().insert(ceremony_id, source);
                continue;
            }
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
            if state == CeremonyState::WalletCommitted {
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

    /// Acquire the configured ceremony listener pair for this platform.
    ///
    /// The ceremony origin is `http://localhost:<port>`, and Chromium
    /// resolves `localhost` to `::1` before `127.0.0.1`, so the Broker must
    /// own both the IPv4 and the IPv6 loopback socket on the configured port.
    /// macOS binds them directly. Linux always consumes the listeners its
    /// launch manager inherited, including under `triad-dev-harness`: that
    /// feature selects which identity and manifest are loaded, not how a
    /// Linux service acquires its sockets. This lives in the library rather
    /// than the binary so the inherited-listener path is directly testable.
    ///
    /// The pair is returned in canonical order: IPv4 first, IPv6 second.
    /// Callers must serve both listeners concurrently; the ceremony origin
    /// resolves to whichever family the browser chose.
    #[cfg(target_os = "macos")]
    pub fn acquire_canonical_loopback_listeners(
        _v4_activation_name: &str,
        _v6_activation_name: &str,
        endpoint: CeremonyEndpoint,
    ) -> Result<(StdTcpListener, StdTcpListener), ProtocolError> {
        Self::bind_canonical_loopback_for(endpoint)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn acquire_canonical_loopback_listeners(
        v4_activation_name: &str,
        v6_activation_name: &str,
        endpoint: CeremonyEndpoint,
    ) -> Result<(StdTcpListener, StdTcpListener), ProtocolError> {
        let v4 = bloom_service_activation::take_tcp_listener(v4_activation_name).map_err(
            |error| {
                protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!(
                        "no inherited IPv4 ceremony listener named {v4_activation_name:?}; this service is socket-activated and will not bind a listener itself: {error}"
                    ),
                )
            },
        )?;
        let v6 = bloom_service_activation::take_tcp_listener(v6_activation_name).map_err(
            |error| {
                protocol(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!(
                        "no inherited IPv6 ceremony listener named {v6_activation_name:?}; this service is socket-activated and will not bind a listener itself: {error}"
                    ),
                )
            },
        )?;
        let v4 = Self::require_canonical_loopback_listener(v4, endpoint.addr_v4())?;
        let v6 = Self::require_canonical_loopback_listener(v6, endpoint.addr_v6())?;
        Ok((v4, v6))
    }

    /// Verify that an already-acquired listener is the configured ceremony
    /// socket for `expected_family`.
    ///
    /// An inherited listener is supplied by the launch manager rather than
    /// chosen by this process, so its address is an input to be checked, not
    /// an invariant to be assumed. A descriptor bound to any other address
    /// is refused outright: the ceremony origin, the `Host` header check,
    /// and the browser's same-origin expectations are all pinned to the
    /// configured endpoint, so serving on a different address would
    /// silently break them rather than fail closed. Wildcards, wrong ports,
    /// swapped families, and missing descriptors are all refused.
    pub fn require_canonical_loopback_listener(
        listener: StdTcpListener,
        expected_family: SocketAddr,
    ) -> Result<StdTcpListener, ProtocolError> {
        let observed = listener.local_addr().map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!("inherited ceremony listener has no readable address: {error}"),
            )
        })?;
        if observed != expected_family {
            return Err(protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!(
                    "inherited ceremony listener for {expected_family} is bound to {observed}; addresses cannot be cross-paired across loopback families"
                ),
            ));
        }
        listener.set_nonblocking(true).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!("canonical ceremony listener setup failed: {error}"),
            )
        })?;
        Ok(listener)
    }

    /// Exclusively acquire both canonical loopback sockets. There is
    /// deliberately no fallback address or port.
    pub fn bind_canonical_loopback() -> Result<(StdTcpListener, StdTcpListener), ProtocolError> {
        Self::bind_canonical_loopback_for(CeremonyEndpoint::default())
    }

    /// Exclusively acquire both loopback sockets for `endpoint`. There is
    /// deliberately no fallback address or port.
    pub fn bind_canonical_loopback_for(
        endpoint: CeremonyEndpoint,
    ) -> Result<(StdTcpListener, StdTcpListener), ProtocolError> {
        let v4 = Self::bind_loopback_one(endpoint.addr_v4())?;
        let v6 = Self::bind_loopback_one(endpoint.addr_v6())?;
        Ok((v4, v6))
    }

    fn bind_loopback_one(addr: SocketAddr) -> Result<StdTcpListener, ProtocolError> {
        let listener = StdTcpListener::bind(addr).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!(
                    "cannot bind canonical ceremony listener at {addr}; no fallback port will be used: {error}"
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

    /// Bind and serve both configured loopback listeners until `shutdown`
    /// resolves. macOS-only.
    pub async fn serve_canonical_loopback_until<F>(self, shutdown: F) -> Result<(), ProtocolError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let endpoint = self.inner.endpoint;
        let (v4, v6) = Self::bind_canonical_loopback_for(endpoint)?;
        self.serve_loopback_listeners_until(v4, v6, shutdown).await
    }

    /// Serve an already-acquired pair of configured loopback listeners until
    /// `shutdown` resolves. Linux uses this with descriptors inherited from
    /// the launch manager; tests use it with synthesized listeners. Both
    /// listeners run under one graceful shutdown. If either server exits,
    /// its peer is also asked to stop so the pair cannot strand shutdown.
    /// Each descriptor must match the instance endpoint exactly.
    pub async fn serve_loopback_listeners_until<F>(
        self,
        v4: StdTcpListener,
        v6: StdTcpListener,
        shutdown: F,
    ) -> Result<(), ProtocolError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let endpoint = self.inner.endpoint;
        let v4 = Self::require_canonical_loopback_listener(v4, endpoint.addr_v4())?;
        let v6 = Self::require_canonical_loopback_listener(v6, endpoint.addr_v6())?;
        let router = self.router();
        let v4 = tokio::net::TcpListener::from_std(v4).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!("canonical IPv4 ceremony listener handoff failed: {error}"),
            )
        })?;
        let v6 = tokio::net::TcpListener::from_std(v6).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!("canonical IPv6 ceremony listener handoff failed: {error}"),
            )
        })?;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let wait_for_stop = |mut stop: tokio::sync::watch::Receiver<bool>| async move {
            while !*stop.borrow() && stop.changed().await.is_ok() {}
        };
        let v4_router = router.clone();
        let v6_router = router;
        let v4_server = axum::serve(v4, v4_router)
            .with_graceful_shutdown(wait_for_stop(stop_rx.clone()))
            .into_future();
        let v6_server = axum::serve(v6, v6_router)
            .with_graceful_shutdown(wait_for_stop(stop_rx))
            .into_future();
        tokio::pin!(v4_server, v6_server, shutdown);

        let (v4_result, v6_result) = tokio::select! {
            () = &mut shutdown => {
                let _ = stop_tx.send(true);
                tokio::join!(&mut v4_server, &mut v6_server)
            }
            result = &mut v4_server => {
                let _ = stop_tx.send(true);
                (result, v6_server.await)
            }
            result = &mut v6_server => {
                let _ = stop_tx.send(true);
                (v4_server.await, result)
            }
        };
        v4_result
            .and(v6_result)
            .map_err(|error| protocol(ProtocolErrorCode::ServiceUnavailable, error.to_string()))
    }

    fn new_session(&self, new: NewBrowserSession) -> Result<BrowserSession, ProtocolError> {
        let mut token_bytes = [0_u8; 32];
        SysRng
            .try_fill_bytes(&mut token_bytes)
            .expect("OS randomness unavailable");
        Ok(BrowserSession {
            operation_id: new.operation_id.clone(),
            request_digest: new.request_digest,
            wallet_id: new.wallet_id,
            anonymous_registration: new.anonymous_registration,
            ceremony_kind: new.ceremony_kind,
            token: Some(Base64UrlBytes::from_bytes(&token_bytes)),
            token_hash: Sha256::digest(token_bytes).into(),
            remote_auth: None,
            origin: new.origin,
            expires_at_ms: new.expires_at_ms,
            created_at_ms: new.created_at_ms,
            terminal_at_ms: None,
            state: CeremonyState::AwaitingUser,
            terminal_result: None,
            result_retain_until_ms: None,
            verification_credentials: new.verification_credentials,
            policy_update: new.policy_update,
            cross_surface: None,
            auxiliary: false,
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
                cross_surface: None,
            },
        })
    }

    fn insert_session(
        &self,
        ceremony_id: Digest32,
        session: BrowserSession,
    ) -> Result<(), ProtocolError> {
        let id = ceremony_id.as_str().to_owned();
        let mut operations = self.inner.operations.lock();
        let mut sessions = self.inner.sessions.lock();
        if sessions.contains_key(&id) || operations.contains_key(&session.operation_id) {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "ceremony ID or operation ID is already in use",
            ));
        }
        self.persist_session(&session)?;
        operations.insert(session.operation_id.clone(), id.clone());
        sessions.insert(id, session);
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
                .is_some_and(|(_, deadline)| deadline.remaining_ms(now_ms) == 0)
            {
                // Backoff is a cooldown, not durable strike history.  Leaving
                // the old count here made every later cancellation escalate
                // forever until the Broker process restarted.
                backoffs.remove(wallet_id);
            }
            if let Some((strikes, deadline)) = backoffs
                .get(wallet_id)
                .copied()
                .filter(|(_, deadline)| deadline.remaining_ms(now_ms) > 0)
            {
                // Same code, same structured contract as the rolling quotas: a
                // caller acts on the metadata, never on the message. The
                // cooldown admits one creation once it elapses, so its limit
                // is 1 over a window of the current backoff.
                let remaining_ms = deadline.remaining_ms(now_ms);
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
            ceremony_url: session_url(session),
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
            ceremony_url: session_url(session),
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
            ceremony_url: session_url(session),
            ceremony_expires_at_ms: DecimalU64::new(session.expires_at_ms),
            review_manifest_digest: review_manifest_digest.clone(),
        }))
    }

    fn record_backoff(&self, wallet_id: &Token, now_ms: u64, clock: BackoffClock) {
        let mut backoffs = self.inner.cancellation_backoff.lock();
        let (count, _) = backoffs
            .get(wallet_id)
            .copied()
            .unwrap_or((0, BackoffDeadline::Trusted(0)));
        let next_count = count.saturating_add(1);
        let window_ms = backoff_window_ms(next_count);
        let deadline = match clock {
            BackoffClock::Trusted => BackoffDeadline::Trusted(now_ms.saturating_add(window_ms)),
            BackoffClock::Monotonic => BackoffDeadline::Monotonic(
                std::time::Instant::now() + std::time::Duration::from_millis(window_ms),
            ),
        };
        backoffs.insert(wallet_id.clone(), (next_count, deadline));
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
            let mut session = match decode_stored_browser_session(&encoded) {
                Ok(session) => session,
                Err(error) => {
                    let decode_error = error.to_string();
                    let index: StoredSessionIndex =
                        serde_json::from_str(&encoded).map_err(|_| malformed(&decode_error))?;
                    if !is_terminal(index.state)
                        || operation_id != index.operation_id.as_str()
                        || ceremony_id != index.projection.ceremony_id.as_str()
                    {
                        return Err(malformed(decode_error));
                    }
                    self.inner
                        .operations
                        .lock()
                        .insert(index.operation_id, ceremony_id);
                    tracing::warn!(
                        event = "ceremony.unsupported_terminal_projection",
                        "Broker retained replay protection for an unsupported terminal ceremony"
                    );
                    continue;
                }
            };
            let parsed_operation = OperationId::new(operation_id)?;
            if parsed_operation != session.operation_id
                || ceremony_id != session.projection.ceremony_id.as_str()
            {
                return Err(protocol(
                    ProtocolErrorCode::MalformedFrame,
                    "durable ceremony index does not match its signed session",
                ));
            }
            if matches!(
                session.state,
                CeremonyState::WalletCommitted | CeremonyState::AwaitingRecoveryAck
            ) {
                validate_completion_identity(
                    session.ceremony_kind,
                    &session.operation_id,
                    &session.projection.ceremony_id,
                    session.terminal_result.as_ref().ok_or_else(not_found)?,
                )?;
            }
            let preserve_awaiting = session.state == CeremonyState::AwaitingRecoveryAck
                && session.expires_at_ms > unix_time_ms();
            if session.auxiliary {
                // Cross-surface source unlock material lives only in Signer
                // memory. A process restart can never resume that authority.
                if !is_terminal(session.state) {
                    session.state = CeremonyState::Expired;
                    latch_terminal(&mut session, unix_time_ms());
                    self.persist_session(&session)?;
                }
                self.inner.sessions.lock().insert(ceremony_id, session);
                continue;
            }
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
        let canonical_plan = canonical_review_plan(
            request,
            &disclosures,
            manifest.petal_use_claim.as_ref(),
            manifest.system_use_claim.as_ref(),
        )?;
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
        let canonical_plan = canonical_review_plan(
            request,
            &disclosures,
            context.petal_use_claim.as_ref(),
            context.system_use_claim.as_ref(),
        )?;
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
                latch_terminal(&mut failed, now_ms);
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
        } else if finalized
            .cross_surface
            .as_ref()
            .is_some_and(|flow| flow.role == CrossSurfaceRole::Destination)
        {
            finalized.state = CeremonyState::Succeeded;
            finalized.terminal_at_ms = Some(now_ms);
            finalized.result_retain_until_ms = Some(now_ms.saturating_add(OUTPUT_ACK_TTL_MS));
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

async fn shell(State(broker): State<CeremonyBroker>, headers: HeaderMap) -> Response {
    if broker.validate_served_host(&headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Explicit empty fragment prevents browsers inheriting any capability
    // fragment from an old bare-root launch URL during the redirect.
    Redirect::to("https://bloom.directory/#").into_response()
}

async fn ceremony_resume_shell(
    State(broker): State<CeremonyBroker>,
    headers: HeaderMap,
) -> Response {
    if broker.validate_served_host(&headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    Html(SHELL_HTML).into_response()
}

async fn remote_health(State(broker): State<CeremonyBroker>, headers: HeaderMap) -> Response {
    if broker.serves_local() || broker.validate_served_host(&headers).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn exchange_remote_fragment(
    State(broker): State<CeremonyBroker>,
    headers: HeaderMap,
    Json(body): Json<RemoteFragmentExchange>,
) -> Response {
    if broker.serves_local()
        || broker.validate_served_host(&headers).is_err()
        || require_exact_header(&headers, header::ORIGIN, &broker.served_origin).is_err()
        || require_exact_header(&headers, header::CONTENT_TYPE, "application/json").is_err()
        || require_exact_header_name(&headers, "sec-fetch-site", "same-origin").is_err()
        || body.capability.decode().len() != 32
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if broker.expire_sessions(unix_time_ms()).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let _exchange_guard = broker.inner.creation_admission.lock();
    let token_hash = <[u8; 32]>::from(Sha256::digest(body.capability.decode()));
    let (ceremony_id, mut snapshot) = {
        let sessions = broker.inner.sessions.lock();
        let Some((id, session)) = sessions.iter().find(|(_, session)| {
            session.token_hash == token_hash
                && session.origin == broker.served_origin
                && session.state == CeremonyState::AwaitingUser
                && session.expires_at_ms > unix_time_ms()
        }) else {
            broker.record_invalid_browser_token();
            return StatusCode::FORBIDDEN.into_response();
        };
        let mut snapshot = session.clone();
        snapshot.token = None;
        snapshot.token_hash = [0; 32];
        (id.clone(), snapshot)
    };
    let mut cookie = [0_u8; 32];
    let mut csrf = [0_u8; 32];
    if SysRng.try_fill_bytes(&mut cookie).is_err() || SysRng.try_fill_bytes(&mut csrf).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    snapshot.remote_auth = Some(RemoteBrowserAuth {
        cookie_hash: Sha256::digest(cookie).into(),
        csrf_hash: Sha256::digest(csrf).into(),
        precommit_expires_at_ms: snapshot
            .expires_at_ms
            .min(unix_time_ms().saturating_add(REMOTE_PRECOMMIT_SESSION_MS)),
        expires_at_ms: unix_time_ms().saturating_add(REMOTE_COOKIE_MAX_MS),
    });
    if broker.persist_session(&snapshot).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    broker
        .inner
        .sessions
        .lock()
        .insert(ceremony_id.clone(), snapshot.clone());
    let cookie_value = Base64UrlBytes::from_bytes(&cookie);
    let csrf_value = Base64UrlBytes::from_bytes(&csrf);
    let mut response = Json(serde_json::json!({
        "ceremony_id": ceremony_id,
        "csrf": csrf_value,
    }))
    .into_response();
    let set_cookie = format!(
        "__Host-bloom-ceremony-{ceremony_id}={}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=1500",
        cookie_value.encoded(),
    );
    if let Ok(value) = HeaderValue::from_str(&set_cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    } else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    response
}

async fn ceremony_shell(
    State(broker): State<CeremonyBroker>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    if broker.validate_served_host(&headers).is_err() || !broker.serves_local() {
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

async fn app_js(State(broker): State<CeremonyBroker>, headers: HeaderMap) -> Response {
    if broker.validate_served_host(&headers).is_err() {
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

async fn style_css(State(broker): State<CeremonyBroker>, headers: HeaderMap) -> Response {
    if broker.validate_served_host(&headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLE_CSS,
    )
        .into_response()
}

async fn bloom_primary_svg(State(broker): State<CeremonyBroker>, headers: HeaderMap) -> Response {
    if broker.validate_served_host(&headers).is_err() {
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
    if broker.validate_served_host(&headers).is_err()
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
    if broker.validate_served_host(&headers).is_err()
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
    let cross_result = session
        .cross_surface
        .as_ref()
        .is_some_and(|flow| flow.role == CrossSurfaceRole::Destination)
        && session.state == CeremonyState::Succeeded
        && session
            .result_retain_until_ms
            .is_some_and(|deadline| deadline > unix_time_ms());
    if !cross_result
        && !matches!(
            session.state,
            CeremonyState::WalletCommitted | CeremonyState::AwaitingRecoveryAck
        )
    {
        return StatusCode::CONFLICT.into_response();
    }
    session
        .terminal_result
        .as_ref()
        .map(|result| Json(result).into_response())
        .unwrap_or_else(|| StatusCode::CONFLICT.into_response())
}

async fn cross_surface_pair(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CrossPairBody>,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, true)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = broker.pair_cross_surface(&ceremony_id, body, unix_time_ms());
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(error)).into_response(),
    }
}

async fn cross_surface_authorize(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CrossAuthorizeBody>,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, true)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    match broker.authorize_cross_surface(&ceremony_id, body, unix_time_ms()) {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(error)).into_response(),
    }
}

async fn cross_surface_handoff(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, false)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    match broker.cross_surface_handoff(&ceremony_id, unix_time_ms()) {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(error)).into_response(),
    }
}

async fn cross_surface_finish(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CrossFinishBody>,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, true)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    match broker.finish_cross_surface(&ceremony_id, body, unix_time_ms()) {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(error)).into_response(),
    }
}

async fn cross_surface_already_registered(
    State(broker): State<CeremonyBroker>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CrossAlreadyRegisteredBody>,
) -> Response {
    if broker
        .authorize_browser(&ceremony_id, &headers, true)
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    match broker.already_registered_cross_surface(&ceremony_id, body, unix_time_ms()) {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::CONFLICT, Json(error)).into_response(),
    }
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
    let recovery_error_floor = (ceremony_kind == CeremonyKind::WalletRecovery)
        .then(|| tokio::time::Instant::now() + Duration::from_millis(750));
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
            if let Some(floor) = recovery_error_floor {
                // The browser recovery ceremony must not distinguish an
                // unknown wallet/recovery ID from a wrong factor or proof.
                // The Signer keeps its typed internal audit error.
                tokio::time::sleep_until(floor).await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(protocol(
                        ProtocolErrorCode::BackendInvalidRequest,
                        "Recovery could not be completed",
                    )),
                )
                    .into_response();
            }
            // Ordinary browser ceremonies retain their structured rejection.
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
        // Browser wall time and the Broker's trusted clock can diverge while
        // the latter is being repaired. The in-memory cancellation throttle
        // therefore uses elapsed monotonic time; the terminal audit timestamp
        // remains ordinary wall time like the other browser transitions.
        Some(operation)
            if broker
                .cancel_from_browser(&operation, unix_time_ms())
                .is_ok() =>
        {
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
        self.validate_served_host(headers)?;
        if !self.serves_local() {
            return Err(protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "remote sessions require fragment exchange",
            ));
        }
        let ceremony_id = headers
            .get("x-bloom-ceremony-token")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| self.ceremony_for_encoded_token(value))
            .filter(|id| {
                self.inner
                    .sessions
                    .lock()
                    .get(id)
                    .is_some_and(|session| session.origin == self.served_origin)
            });
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
        self.validate_served_host(headers)?;
        if mutation {
            self.validate_served_origin(headers)?;
            require_exact_header(headers, header::CONTENT_TYPE, "application/json")?;
            require_exact_header_name(headers, "sec-fetch-site", "same-origin")?;
        }
        if !self.serves_local() {
            return self.authorize_remote_cookie(ceremony_id, headers, mutation);
        }
        let supplied = headers
            .get("x-bloom-ceremony-token")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Base64UrlBytes::parse(value.to_owned()).ok())
            .filter(|value| value.decode().len() == 32);
        let sessions = self.inner.sessions.lock();
        let expected = sessions
            .get(ceremony_id)
            .filter(|session| session.origin == self.served_origin)
            .map(|session| session.token_hash);
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

    /// Whether this handle serves the local listener on the configured port.
    fn serves_local(&self) -> bool {
        self.served_origin == self.inner.endpoint.origin()
    }

    fn validate_served_host(&self, headers: &HeaderMap) -> Result<(), ProtocolError> {
        if self.serves_local() {
            return require_exact_header(headers, header::HOST, &self.inner.endpoint.host());
        }
        let expected = self.served_origin.strip_prefix("https://").ok_or_else(|| {
            protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "invalid served origin",
            )
        })?;
        require_exact_header(headers, header::HOST, expected)
    }

    /// Exact `Origin` check against the served origin; a mismatch names the
    /// expected origin in the log while the HTTP response stays a bare 403.
    fn validate_served_origin(&self, headers: &HeaderMap) -> Result<(), ProtocolError> {
        let observed = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok());
        check_origin(observed, &self.served_origin)
    }

    fn authorize_remote_cookie(
        &self,
        ceremony_id: &str,
        headers: &HeaderMap,
        mutation: bool,
    ) -> Result<(), ProtocolError> {
        let cookie_name = format!("__Host-bloom-ceremony-{ceremony_id}=");
        // HTTP/2 permits a browser to split its Cookie header into multiple
        // fields. Earlier ceremonies leave other scoped cookies behind, so
        // the requested ceremony's cookie may not be in the first field.
        // Ambiguous duplicates of this exact name are never accepted.
        let mut cookie_value = None;
        for field in headers.get_all(header::COOKIE) {
            let field = field.to_str().map_err(|_| {
                protocol(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "invalid remote ceremony cookie header",
                )
            })?;
            for part in field.split(';').map(str::trim) {
                if let Some(value) = part.strip_prefix(&cookie_name) {
                    if cookie_value.replace(value).is_some() {
                        return Err(protocol(
                            ProtocolErrorCode::UnauthenticatedPeer,
                            "duplicate remote ceremony cookie",
                        ));
                    }
                }
            }
        }
        let cookie = cookie_value
            .and_then(|value| Base64UrlBytes::parse(value.to_owned()).ok())
            .filter(|value| value.decode().len() == 32);
        let hash = cookie
            .map(|value| <[u8; 32]>::from(Sha256::digest(value.decode())))
            .ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "missing remote ceremony session",
                )
            })?;
        let sessions = self.inner.sessions.lock();
        let session = sessions.get(ceremony_id).ok_or_else(|| {
            protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "unknown remote ceremony session",
            )
        })?;
        let remote = session.remote_auth.as_ref().ok_or_else(|| {
            protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "unknown remote ceremony session",
            )
        })?;
        if remote.cookie_hash != hash
            || !remote.allows(
                session.state,
                session.result_retain_until_ms,
                unix_time_ms(),
            )
        {
            return Err(protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "remote ceremony session expired",
            ));
        }
        if mutation {
            let csrf = headers
                .get("x-bloom-csrf")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| Base64UrlBytes::parse(value.to_owned()).ok())
                .filter(|value| value.decode().len() == 32)
                .ok_or_else(|| {
                    protocol(ProtocolErrorCode::UnauthenticatedPeer, "missing CSRF proof")
                })?;
            if <[u8; 32]>::from(Sha256::digest(csrf.decode())) != remote.csrf_hash {
                return Err(protocol(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "invalid CSRF proof",
                ));
            }
        }
        if session.origin != self.served_origin {
            return Err(protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "ceremony surface mismatch",
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

async fn security_headers(mut request: Request<Body>, next: Next) -> Response {
    let mut response = if normalize_http2_authority(&mut request).is_ok() {
        next.run(request).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    };
    apply_security_headers(&mut response);
    response
}

/// Hyper exposes HTTP/2 `:authority` through the request URI, while the
/// ceremony handlers deliberately consume one strict `Host` value. Normalize
/// that transport representation once for every route. HTTP/1 remains
/// unchanged, and a client cannot override the authority with a conflicting or
/// duplicate Host header.
fn normalize_http2_authority(request: &mut Request<Body>) -> Result<(), ()> {
    if request.version() != Version::HTTP_2 {
        return Ok(());
    }

    let authority = request.uri().authority().ok_or(())?.as_str();
    let mut hosts = request.headers().get_all(header::HOST).iter();
    if let Some(host) = hosts.next() {
        if hosts.next().is_some() || host.as_bytes() != authority.as_bytes() {
            return Err(());
        }
        return Ok(());
    }

    let host = HeaderValue::from_str(authority).map_err(|_| ())?;
    request.headers_mut().insert(header::HOST, host);
    Ok(())
}

fn apply_security_headers(response: &mut Response) {
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
}

/// Reject a ceremony `Origin` that is not this Broker's endpoint origin. The
/// mismatch error names the expected origin so a page served by one Triad
/// posting to another is recognizable in Broker logs. The check itself is
/// unchanged: anything but an exact match fails, and HTTP responses stay a
/// bare 403 — only the log carries the diagnostic.
fn check_origin(observed: Option<&str>, expected: &str) -> Result<(), ProtocolError> {
    if observed == Some(expected) {
        return Ok(());
    }
    Err(protocol(
        ProtocolErrorCode::UnauthenticatedPeer,
        match observed {
            Some(observed) => format!(
                "ceremony request origin {observed} does not match the expected ceremony origin {expected}"
            ),
            None => format!("ceremony request is missing the expected ceremony origin {expected}"),
        },
    ))
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

/// Launch URL for a session on its own origin. Local surfaces are plain
/// HTTP on this Broker's ceremony port and carry the token in the path; the
/// hosted relay is HTTPS and carries a one-use capability in the fragment.
fn session_url(session: &BrowserSession) -> String {
    let token = token_for(session);
    if session.origin.starts_with("http://") {
        format!("{}/ceremony/{}", session.origin, token.encoded())
    } else {
        format!("{}/ceremony/#cap={}", session.origin, token.encoded())
    }
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
/// The destination's own surface approves when the wallet has an active
/// passkey there; otherwise the other usable surface does, if it has one.
fn approving_surface(
    credentials: &[bloom_signer_api::CredentialPublic],
    destination: &SurfaceDescriptor,
    other: Option<SurfaceDescriptor>,
) -> Option<SurfaceDescriptor> {
    let has_passkey_on = |surface: &SurfaceRef| {
        credentials.iter().any(|credential| {
            credential.state == bloom_signer_api::CredentialState::Active
                && &credential.surface == surface
        })
    };
    if has_passkey_on(&destination.reference()) {
        return Some(destination.clone());
    }
    other.filter(|other| has_passkey_on(&other.reference()))
}

fn latch_terminal(session: &mut BrowserSession, now_ms: u64) {
    session.terminal_at_ms = Some(now_ms);
    session.token = None;
    session.token_hash = [0_u8; 32];
    session.remote_auth = None;
}

fn is_terminal(state: CeremonyState) -> bool {
    matches!(
        state,
        CeremonyState::Completed
            | CeremonyState::Succeeded
            | CeremonyState::Cancelled
            | CeremonyState::Expired
            | CeremonyState::Failed
            | CeremonyState::AlreadyRegistered
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
        CeremonyState::AlreadyRegistered => "already_registered",
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

/// The browser-visible review of one account ceremony: every requested
/// family with its role, frozen path template, and key material shape. Signer
/// chooses the account number.
pub(crate) fn account_terms_review(
    kind: &bloom_broker_api::CeremonyKind,
    terms: &bloom_broker_api::AccountTerms,
) -> serde_json::Value {
    let families: Vec<serde_json::Value> = terms
        .derivations
        .iter()
        .map(|request| {
            let profile = request.derivation_profile;
            serde_json::json!({
                "derivation_profile": profile,
                "requested_role": request.requested_role,
                "pinned_account": request.account,
                "path_template": profile.path_template(),
                "key_spec": profile.key_spec(),
                "allowed_crypto_suites": profile.frozen_crypto_suites(),
            })
        })
        .collect();
    let title = match kind {
        bloom_broker_api::CeremonyKind::AccountRetire => "Retire one derived account key",
        _ => "Allocate account key(s)",
    };
    serde_json::json!({
        "schema": "bloom.account_terms_review.v1",
        "title": title,
        "wallet_id": terms.wallet_id,
        "seed_profile": terms.seed_profile,
        "families": families,
        "retire_key_fingerprint": terms.retire_key_fingerprint,
        "policy_version": terms.policy_version,
        "revocation_epoch": terms.revocation_epoch,
    })
}

fn canonical_review_plan(
    request: &CeremonyPrepareRequest,
    security_disclosures: &[String],
    claim: Option<&PetalUseClaim>,
    system_claim: Option<&SystemUseClaim>,
) -> Result<String, ProtocolError> {
    #[derive(Serialize)]
    struct AssetAmountReview {
        kind: &'static str,
        chain: String,
        asset: String,
        display: String,
        base_units: String,
        decimals: Option<u8>,
    }

    #[derive(Serialize)]
    struct Plan<'a> {
        schema: &'static str,
        asset_amounts: Vec<AssetAmountReview>,
        terms: &'a bloom_signer_api::SealedApprovalTerms,
        exact_ordered_payload_digests: &'a [Digest32],
        exact_ordered_hashes: &'a [Digest32],
        replacement_approval_id: &'a Option<Digest32>,
        security_disclosures: &'a [String],
    }
    let mut asset_amounts = Vec::new();
    // A system claim declares the same amounts a Petal claim does. Reading
    // only the Petal claim left system operations — an ordinary transaction
    // confirmation among them — rendering as bare digests, so the owner was
    // asked to approve a transfer without being shown its value or
    // destination.
    if let Some(system) = system_claim {
        asset_amounts.extend(system.declared_debits.iter().map(|debit| {
            review_asset_amount(
                "declared_debit",
                debit.asset.chain.as_str(),
                &debit.asset.asset,
                debit.amount.as_str(),
            )
        }));
        if let bloom_broker_api::DeclaredFee::Fee {
            chain,
            asset,
            amount,
        } = &system.declared_fee
        {
            asset_amounts.push(review_asset_amount(
                "declared_fee",
                chain.as_str(),
                asset,
                amount.as_str(),
            ));
        }
    }
    if let Some(claim) = claim {
        asset_amounts.extend(claim.declared_debits.iter().map(|debit| {
            review_asset_amount(
                "declared_debit",
                debit.asset.chain.as_str(),
                &debit.asset.asset,
                debit.amount.as_str(),
            )
        }));
        if let bloom_broker_api::DeclaredFee::Fee {
            chain,
            asset,
            amount,
        } = &claim.declared_fee
        {
            asset_amounts.push(review_asset_amount(
                "declared_fee",
                chain.as_str(),
                asset,
                amount.as_str(),
            ));
        }
    }
    // A reusable approval's value limits are its spending ceiling: the Broker
    // sums every debit and fee per asset against them and refuses any asset
    // without one. The owner must see that ceiling, not only the raw terms.
    asset_amounts.extend(request.terms.limits.value_limits.iter().map(|limit| {
        review_asset_amount(
            "value_limit",
            limit.asset.chain.as_str(),
            &limit.asset.asset,
            limit.lifetime.as_str(),
        )
    }));

    fn review_asset_amount(
        kind: &'static str,
        chain: &str,
        asset: &str,
        base_units: &str,
    ) -> AssetAmountReview {
        let metadata = match (chain, asset) {
            ("hyperliquid", "usdc") => Some((6, "USDC")),
            ("solana", "native") | ("solana-mainnet", "native") => Some((9, "SOL")),
            ("ethereum", "native") | ("base", "native") | ("arbitrum", "native") => {
                Some((18, "ETH"))
            }
            ("polygon", "native") => Some((18, "POL")),
            _ => None,
        };
        let (display, decimals) = metadata.map_or_else(
            || {
                (
                    format!(
                        "{base_units} raw units of {asset} on {chain} (token decimals unknown)"
                    ),
                    None,
                )
            },
            |(decimals, symbol)| {
                (
                    format!("{} {symbol}", format_base_units(base_units, decimals)),
                    Some(decimals),
                )
            },
        );
        AssetAmountReview {
            kind,
            chain: chain.to_owned(),
            asset: asset.to_owned(),
            display,
            base_units: base_units.to_owned(),
            decimals,
        }
    }

    fn format_base_units(base_units: &str, decimals: u8) -> String {
        if decimals == 0 {
            return base_units.to_owned();
        }
        let decimals = usize::from(decimals);
        let padded = format!("{:0>width$}", base_units, width = decimals + 1);
        let split = padded.len() - decimals;
        let fractional = padded[split..].trim_end_matches('0');
        if fractional.is_empty() {
            padded[..split].to_owned()
        } else {
            format!("{}.{}", &padded[..split], fractional)
        }
    }

    serde_jcs::to_string(&Plan {
        schema: "bloom-review-plan/v1",
        asset_amounts,
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
        let source = if system_claim.is_some() {
            "the named system component"
        } else {
            "the named Petal"
        };
        disclosures.push(format!(
            "The displayed limits are asserted by {source}. Bloom does not verify them against the payload, and a compromised Petal or Machine can consume the full remaining capacity."
        ));
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
        guard_ceremony_storage_version(&connection)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS ceremony_sessions (
                    ceremony_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    session_jcs TEXT NOT NULL
                );",
            )
            .map_err(storage)?;
        migrate_legacy_ceremonies(&mut connection, &legacy, journal)?;
        let transaction = connection.transaction().map_err(storage)?;
        if migrate_pairing_session_index(&transaction)? {
            journal
                .append_external_audit(
                    &transaction,
                    "storage.ceremony_pairing_index_migrated",
                    &serde_json::json!({"primary_operation_uniqueness": true}),
                )
                .map_err(storage)?;
        }
        transaction.commit().map_err(storage)?;
        connection
            .pragma_update(None, "user_version", CEREMONY_STORAGE_VERSION)
            .map_err(storage)?;
    }
    Ok(database)
}

// A pairing has one primary destination session and an auxiliary source session
// with the same logical operation. Preserve the primary uniqueness constraint
// while permitting the source to be stored under its own ceremony ID.
fn migrate_pairing_session_index(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<bool, ProtocolError> {
    let old_unique: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_index_list('ceremony_sessions') AS idx
         JOIN pragma_index_info(idx.name) AS col
         WHERE idx.\"unique\" = 1 AND idx.partial = 0 AND col.name = 'operation_id')",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if !old_unique {
        transaction
            .execute_batch(
                "CREATE UNIQUE INDEX IF NOT EXISTS ceremony_primary_operation
             ON ceremony_sessions(operation_id)
             WHERE COALESCE(json_extract(session_jcs, '$.auxiliary'), 0) = 0;",
            )
            .map_err(storage)?;
        return Ok(false);
    }
    transaction
        .execute_batch(
            "ALTER TABLE ceremony_sessions RENAME TO ceremony_sessions_before_pairing;
         CREATE TABLE ceremony_sessions (
             ceremony_id TEXT PRIMARY KEY,
             operation_id TEXT NOT NULL,
             session_jcs TEXT NOT NULL
         );
         INSERT INTO ceremony_sessions SELECT * FROM ceremony_sessions_before_pairing;
         DROP TABLE ceremony_sessions_before_pairing;
         CREATE UNIQUE INDEX ceremony_primary_operation ON ceremony_sessions(operation_id)
             WHERE COALESCE(json_extract(session_jcs, '$.auxiliary'), 0) = 0;",
        )
        .map_err(storage)?;
    Ok(true)
}

/// The consolidated Broker database owns ceremony session persistence. A
/// future schema cannot be interpreted by this binary; existing v0/v1 rows
/// are decoded by the normal legacy session migration path before this gate
/// advances the marker.
fn guard_ceremony_storage_version(connection: &Connection) -> Result<(), ProtocolError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(storage)?;
    if !(0..=CEREMONY_STORAGE_VERSION).contains(&version) {
        return Err(storage("unsupported ceremony storage version"));
    }
    Ok(())
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

/// One line naming the operation, and one line stating its consequence.
///
/// Deliberately plain: the owner is being asked to authorize custody with a
/// hardware credential, and the only honest basis for that is a sentence they
/// can actually read.
fn custody_review_text(kind: CeremonyKind) -> (&'static str, &'static str) {
    match kind {
        CeremonyKind::WalletRegistration => (
            "Create a new wallet",
            "Signer creates custody for a new wallet and binds the passkey you are about to \
             use as its authority. No existing wallet is changed.",
        ),
        CeremonyKind::WalletImport => (
            "Import an existing wallet",
            "Signer takes custody of a private key you supply in this browser. The key is \
             entered here and never passes through the Machine process.",
        ),
        CeremonyKind::WalletExport => (
            "Export wallet secret material",
            "Signer releases this wallet's secret material to this browser. Anyone who \
             obtains it controls the wallet.",
        ),
        CeremonyKind::WalletDelete => (
            "Permanently delete a wallet",
            "Signer destroys this wallet's custody. This cannot be undone, and Bloom cannot \
             recover the wallet or anything it holds afterwards.",
        ),
        CeremonyKind::WalletRecovery => (
            "Recover a wallet",
            "Signer restores custody for this wallet from recovery material you supply in \
             this browser.",
        ),
        CeremonyKind::CredentialAdd => (
            "Add a passkey to a wallet",
            "The passkey you are about to use becomes an additional authority for this \
             wallet. Existing credentials keep working.",
        ),
        CeremonyKind::CredentialReplace => (
            "Replace a wallet's passkey",
            "The passkey you are about to use replaces the current credential for this \
             wallet. The wallet address does not change.",
        ),
        CeremonyKind::CredentialRemove => (
            "Remove a passkey from a wallet",
            "This credential stops being an authority for this wallet. Removing your only \
             credential leaves the wallet unusable.",
        ),
        CeremonyKind::BackendEnrollment => (
            "Enroll a signing backend",
            "Signer enrolls a signing backend for this wallet.",
        ),
        CeremonyKind::AccountAllocate => (
            "Allocate a derived account",
            "Signer derives a new account under this wallet's root and publishes its public \
             key. The wallet's existing accounts are unaffected.",
        ),
        CeremonyKind::AccountRetire => (
            "Retire a derived account",
            "Signer retires the account named below. Bloom stops projecting it and will not \
             select it for signing.",
        ),
        CeremonyKind::KeyDerive => (
            "Create a temporary Petal key",
            "Allow an installed Petal to use a temporary child key for only the listed actions \
             and time. No funds move now, and the wallet's main key remains in Signer.",
        ),
        // Rejected earlier in custody preparation and reviewed by their own
        // paths; named so this match stays exhaustive.
        CeremonyKind::SealedApproval => (
            "Approve an action",
            "Authorize the exact action described below.",
        ),
        CeremonyKind::PolicyUpdate => (
            "Update wallet policy",
            "Replace this wallet's spending policy with the one described below.",
        ),
    }
}

/// Build the human-readable review a custody ceremony page renders.
///
/// The browser shows `review_manifest` when the session carries one and
/// otherwise falls back to dumping the raw Signer contribution. Returning
/// `None` therefore asks an owner to authorize custody against a page of
/// base64, which is not consent in any meaningful sense, so every kind gets a
/// manifest. Legacy passkey migration keeps its more specific review.
///
/// This is what the page displays. The value the passkey binds is the Signer
/// contribution's own `review_manifest_digest`, so this text must describe
/// that operation faithfully rather than stand in for it.
fn custody_review_manifest(
    request: &CustodyPrepareRequest,
    wallet_id: Option<&Token>,
    anonymous_registration: bool,
    account_review: Option<serde_json::Value>,
) -> Result<Option<serde_json::Value>, ProtocolError> {
    if let Some(migration) = &request.legacy_passkey_migration {
        return Ok(Some(serde_json::json!({
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
        })));
    }

    // An account ceremony already has a review the Broker authored from the
    // frozen account terms: every requested family with its role and path
    // template. That is a more exact description than anything derivable from
    // the custody request here, so it stands as written.
    if account_review.is_some()
        && matches!(
            request.ceremony_kind,
            CeremonyKind::AccountAllocate | CeremonyKind::AccountRetire
        )
    {
        return Ok(account_review);
    }

    let (title, summary) = custody_review_text(request.ceremony_kind);

    // The page renders `canonical_plan` as plain text and only falls back to
    // dumping this object as JSON, so the prose form is what an owner
    // actually reads. Identifiers are shown in full so they can be compared
    // against what the CLI printed before the browser was opened.
    let mut plan = format!("{title}\n\n{summary}\n\n");
    if let Some(wallet) = wallet_id {
        plan.push_str(&format!("Wallet name   {}\n", wallet.as_str()));
    }
    plan.push_str(&format!(
        "Operation     {}\nCredential    {}\n",
        request.custody_operation_id,
        request.expected_input_class.as_str(),
    ));
    if request.key_ref.is_some() {
        plan.push_str("Key           shown in full below\n");
    }
    if request.petal_key_scope.is_some() {
        plan.push_str("Petal scope   shown in full below\n");
    }

    let mut manifest = serde_json::json!({
        "schema": "bloom.custody_ceremony_review.v1",
        "canonical_plan": plan,
        "title": title,
        "summary": summary,
        "ceremony_kind": kind_to_machine(request.ceremony_kind),
        "wallet_name": wallet_id.map(Token::as_str),
        "operation_id": serde_json::to_value(&request.custody_operation_id).map_err(malformed)?,
        "credential_input": request.expected_input_class.as_str(),
        "creates_new_wallet": anonymous_registration,
    });
    if let Some(scope) = &request.petal_key_scope {
        manifest["petal_key_scope"] = serde_json::to_value(scope).map_err(malformed)?;
    }
    if let Some(key_ref) = &request.key_ref {
        manifest["key_ref"] = serde_json::to_value(key_ref).map_err(malformed)?;
    }
    Ok(Some(manifest))
}

#[cfg(test)]
mod remote_storage_tests {
    use super::*;

    #[test]
    fn pairing_storage_migration_retains_primary_uniqueness_and_auxiliary_rows() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut connection = Connection::open(file.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ceremony_sessions (
                ceremony_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
                session_jcs TEXT NOT NULL);
             INSERT INTO ceremony_sessions VALUES ('destination', 'operation', '{}');",
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        assert!(migrate_pairing_session_index(&transaction).unwrap());
        transaction.commit().unwrap();
        connection
            .execute(
                "INSERT INTO ceremony_sessions VALUES ('source', 'operation', ?1)",
                [r#"{"auxiliary":true}"#],
            )
            .unwrap();
        assert!(
            connection
                .execute(
                    "INSERT INTO ceremony_sessions VALUES ('duplicate', 'operation', '{}')",
                    [],
                )
                .is_err()
        );
        drop(connection);
        let mut reopened = Connection::open(file.path()).unwrap();
        assert_eq!(
            reopened
                .query_row("SELECT COUNT(*) FROM ceremony_sessions", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        let transaction = reopened.transaction().unwrap();
        assert!(!migrate_pairing_session_index(&transaction).unwrap());
        transaction.commit().unwrap();
    }

    #[test]
    fn precommit_cookie_expires_even_while_browser_cookie_remains_present() {
        let auth = RemoteBrowserAuth {
            cookie_hash: [1; 32],
            csrf_hash: [2; 32],
            precommit_expires_at_ms: 5 * 60_000,
            expires_at_ms: 25 * 60_000,
        };
        assert!(auth.allows(CeremonyState::AwaitingUser, None, 5 * 60_000 - 1));
        assert!(!auth.allows(CeremonyState::AwaitingUser, None, 5 * 60_000));
        assert!(auth.allows(CeremonyState::AwaitingRecoveryAck, None, 15 * 60_000));
        assert!(!auth.allows(CeremonyState::AwaitingRecoveryAck, None, 25 * 60_000));
        assert!(auth.allows(CeremonyState::Succeeded, Some(20 * 60_000), 19 * 60_000));
        assert!(!auth.allows(CeremonyState::Succeeded, Some(20 * 60_000), 20 * 60_000));
        let persisted = serde_json::to_string(&auth).unwrap();
        let restored: RemoteBrowserAuth = serde_json::from_str(&persisted).unwrap();
        assert_eq!(restored, auth);
    }

    #[test]
    fn ceremony_store_rejects_future_schema() {
        let connection = Connection::open_in_memory().unwrap();
        guard_ceremony_storage_version(&connection).unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        guard_ceremony_storage_version(&connection).unwrap();
        connection.pragma_update(None, "user_version", 3).unwrap();
        assert!(guard_ceremony_storage_version(&connection).is_err());
    }
}

#[cfg(test)]
mod approving_surface_tests {
    use super::*;

    fn descriptor(identity: bloom_signer_api::SurfaceIdentity) -> SurfaceDescriptor {
        let reference = identity.reference().unwrap();
        SurfaceDescriptor {
            identity,
            identity_digest: reference.identity_digest,
            lifecycle: SurfaceLifecycle::Active,
            lifecycle_revision: DecimalU64::new(0),
        }
    }

    fn passkey(
        surface: &SurfaceDescriptor,
        state: bloom_signer_api::CredentialState,
    ) -> bloom_signer_api::CredentialPublic {
        bloom_signer_api::CredentialPublic {
            credential_id: Base64UrlBytes::from_bytes(&[1; 16]),
            wallet_id: Token::new("main").unwrap(),
            surface: surface.reference(),
            created_at_ms: DecimalU64::new(1),
            state,
        }
    }

    #[test]
    fn same_surface_is_preferred_then_the_other_surface_then_nothing() {
        use bloom_signer_api::CredentialState::{Active, Revoked};
        let local = descriptor(bloom_signer_api::SurfaceIdentity::local(0));
        let remote = descriptor(
            bloom_signer_api::SurfaceIdentity::remote(
                "abcdefghijklmnopqrstuv2345.relay.bloom.directory",
                1,
            )
            .unwrap(),
        );
        let chosen = |credentials: &[bloom_signer_api::CredentialPublic],
                      other: Option<&SurfaceDescriptor>| {
            approving_surface(credentials, &remote, other.cloned())
                .map(|surface| surface.identity.surface_id.as_str().to_owned())
        };
        // A phone joining a wallet whose passkeys are remote.
        assert_eq!(
            chosen(
                &[passkey(&remote, Active), passkey(&local, Active)],
                Some(&local)
            )
            .as_deref(),
            Some("remote")
        );
        // Only a localhost passkey: the original cross-surface addition.
        assert_eq!(
            chosen(&[passkey(&local, Active)], Some(&local)).as_deref(),
            Some("local")
        );
        // Revoked passkeys and an unusable other surface approve nothing.
        assert_eq!(chosen(&[passkey(&remote, Revoked)], Some(&local)), None);
        assert_eq!(chosen(&[passkey(&local, Active)], None), None);
        assert_eq!(chosen(&[], Some(&local)), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_mismatch_names_expected_origin() {
        let error =
            check_origin(Some("http://localhost:28735"), "http://localhost:28736").unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::UnauthenticatedPeer);
        assert!(
            error.message.contains("http://localhost:28736"),
            "origin mismatch must name the expected origin: {}",
            error.message
        );
    }

    #[test]
    fn missing_origin_names_expected_origin() {
        let error = check_origin(None, "http://localhost:28736").unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::UnauthenticatedPeer);
        assert!(
            error.message.contains("http://localhost:28736"),
            "missing origin must name the expected origin: {}",
            error.message
        );
    }

    #[test]
    fn matching_origin_passes() {
        check_origin(Some("http://localhost:28736"), "http://localhost:28736")
            .expect("exact origin match must pass");
    }
}
