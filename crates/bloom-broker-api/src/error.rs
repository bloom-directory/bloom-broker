use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Retry contract attached to every protocol error.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    Never,
    SameOperation,
    AfterReconciliation,
    AfterBackoff,
    AfterReread,
    AfterRepair,
    UserAction,
}

/// Whether the failed request may have caused a durable effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableEffect {
    None,
    PriorOperationStands,
    ReservationReleased,
    PossibleProviderEffect,
    UnknownResolveByStatus,
}

/// Closed v1 error-code registry from architecture section 18.1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolErrorCode {
    UnauthenticatedPeer,
    UnsupportedVersion,
    MalformedFrame,
    LimitExceededFrame,
    UnknownField,
    UnknownMethod,
    OperationIdConflict,
    ApprovalNotFound,
    ApprovalExpired,
    ApprovalRevoked,
    ApprovalRearmRequired,
    RevocationEpochUnreconciled,
    SelectorMismatch,
    SuiteNotAllowed,
    KeyrefMismatch,
    LimitExceededOperations,
    LimitExceededSignatures,
    LimitExceededValue,
    LimitExceededRate,
    SignerRateBackstopDenied,
    ClaimInvalid,
    AssuranceUnavailable,
    ProvenanceMismatch,
    PolicyBaselineStale,
    CeremonyRateLimited,
    CeremonyReplay,
    CeremonyKindMismatch,
    QuotaExceeded,
    ClockUntrusted,
    ClockRollback,
    BackendUnsupported,
    BackendInvalidRequest,
    AmbiguousProviderEffect,
    ServiceUnavailable,
}

impl ProtocolErrorCode {
    pub const ALL: [Self; 34] = [
        Self::UnauthenticatedPeer,
        Self::UnsupportedVersion,
        Self::MalformedFrame,
        Self::LimitExceededFrame,
        Self::UnknownField,
        Self::UnknownMethod,
        Self::OperationIdConflict,
        Self::ApprovalNotFound,
        Self::ApprovalExpired,
        Self::ApprovalRevoked,
        Self::ApprovalRearmRequired,
        Self::RevocationEpochUnreconciled,
        Self::SelectorMismatch,
        Self::SuiteNotAllowed,
        Self::KeyrefMismatch,
        Self::LimitExceededOperations,
        Self::LimitExceededSignatures,
        Self::LimitExceededValue,
        Self::LimitExceededRate,
        Self::SignerRateBackstopDenied,
        Self::ClaimInvalid,
        Self::AssuranceUnavailable,
        Self::ProvenanceMismatch,
        Self::PolicyBaselineStale,
        Self::CeremonyRateLimited,
        Self::CeremonyReplay,
        Self::CeremonyKindMismatch,
        Self::QuotaExceeded,
        Self::ClockUntrusted,
        Self::ClockRollback,
        Self::BackendUnsupported,
        Self::BackendInvalidRequest,
        Self::AmbiguousProviderEffect,
        Self::ServiceUnavailable,
    ];

    pub fn contract(self) -> ErrorContract {
        use DurableEffect as Effect;
        use ProtocolErrorCode as Code;
        use RetryClass as Retry;

        match self {
            Code::OperationIdConflict => {
                ErrorContract::new(Retry::Never, Effect::PriorOperationStands)
            }
            Code::RevocationEpochUnreconciled => {
                ErrorContract::new(Retry::AfterReconciliation, Effect::None)
            }
            Code::ApprovalRearmRequired => ErrorContract::new(Retry::UserAction, Effect::None),
            Code::PolicyBaselineStale => ErrorContract::new(Retry::AfterReread, Effect::None),
            Code::CeremonyRateLimited | Code::QuotaExceeded => {
                ErrorContract::new(Retry::AfterBackoff, Effect::None)
            }
            Code::ClockUntrusted | Code::ClockRollback => {
                ErrorContract::new(Retry::AfterRepair, Effect::None)
            }
            Code::LimitExceededOperations
            | Code::LimitExceededSignatures
            | Code::LimitExceededValue
            | Code::LimitExceededRate
            | Code::SignerRateBackstopDenied => {
                ErrorContract::new(Retry::Never, Effect::ReservationReleased)
            }
            Code::AmbiguousProviderEffect => {
                ErrorContract::new(Retry::Never, Effect::PossibleProviderEffect)
            }
            Code::ServiceUnavailable => {
                ErrorContract::new(Retry::SameOperation, Effect::UnknownResolveByStatus)
            }
            _ => ErrorContract::new(Retry::Never, Effect::None),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnauthenticatedPeer => "UNAUTHENTICATED_PEER",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::MalformedFrame => "MALFORMED_FRAME",
            Self::LimitExceededFrame => "LIMIT_EXCEEDED_FRAME",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::UnknownMethod => "UNKNOWN_METHOD",
            Self::OperationIdConflict => "OPERATION_ID_CONFLICT",
            Self::ApprovalNotFound => "APPROVAL_NOT_FOUND",
            Self::ApprovalExpired => "APPROVAL_EXPIRED",
            Self::ApprovalRevoked => "APPROVAL_REVOKED",
            Self::ApprovalRearmRequired => "APPROVAL_REARM_REQUIRED",
            Self::RevocationEpochUnreconciled => "REVOCATION_EPOCH_UNRECONCILED",
            Self::SelectorMismatch => "SELECTOR_MISMATCH",
            Self::SuiteNotAllowed => "SUITE_NOT_ALLOWED",
            Self::KeyrefMismatch => "KEYREF_MISMATCH",
            Self::LimitExceededOperations => "LIMIT_EXCEEDED_OPERATIONS",
            Self::LimitExceededSignatures => "LIMIT_EXCEEDED_SIGNATURES",
            Self::LimitExceededValue => "LIMIT_EXCEEDED_VALUE",
            Self::LimitExceededRate => "LIMIT_EXCEEDED_RATE",
            Self::SignerRateBackstopDenied => "SIGNER_RATE_BACKSTOP_DENIED",
            Self::ClaimInvalid => "CLAIM_INVALID",
            Self::AssuranceUnavailable => "ASSURANCE_UNAVAILABLE",
            Self::ProvenanceMismatch => "PROVENANCE_MISMATCH",
            Self::PolicyBaselineStale => "POLICY_BASELINE_STALE",
            Self::CeremonyRateLimited => "CEREMONY_RATE_LIMITED",
            Self::CeremonyReplay => "CEREMONY_REPLAY",
            Self::CeremonyKindMismatch => "CEREMONY_KIND_MISMATCH",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::ClockUntrusted => "CLOCK_UNTRUSTED",
            Self::ClockRollback => "CLOCK_ROLLBACK",
            Self::BackendUnsupported => "BACKEND_UNSUPPORTED",
            Self::BackendInvalidRequest => "BACKEND_INVALID_REQUEST",
            Self::AmbiguousProviderEffect => "AMBIGUOUS_PROVIDER_EFFECT",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
        }
    }
}

impl FromStr for ProtocolErrorCode {
    type Err = UnknownPeerErrorCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        for code in Self::ALL {
            if code.as_str() == value {
                return Ok(code);
            }
        }
        Err(UnknownPeerErrorCode(value.to_owned()))
    }
}

impl Serialize for ProtocolErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtocolErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Structured metadata attached to `CEREMONY_RATE_LIMITED`, introduced in
/// protocol minor [`crate::RATE_LIMIT_DETAILS_MINOR`].
///
/// Callers wait `retry_after_ms` and retry the *same* operation identity; they
/// must never parse the human-readable message or invent a replacement
/// operation. The values describe the quota class that rejected the request,
/// never the wallet that hit it.
///
/// Both time-based classes of `CEREMONY_RATE_LIMITED` report through this
/// shape: a rolling creation quota (`limit` creations per `window_ms`) and a
/// per-wallet cancellation cooldown (`limit` of 1 creation once the current
/// `window_ms` cooldown has elapsed).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitDetails {
    /// Milliseconds until the rejected creation can succeed: for a rolling
    /// quota, the wait until the counted creation whose expiry frees the next
    /// slot leaves the window; for a cooldown, the wait remaining on it.
    pub retry_after_ms: u64,
    /// Effective number of creations the quota class allows inside one
    /// `window_ms`.
    pub limit: u64,
    /// Length of the window the limit is measured over, in milliseconds.
    pub window_ms: u64,
}

impl RateLimitDetails {
    /// Build details, returning `None` when the values cannot describe a real
    /// rolling quota. Callers fall back to an error without details rather
    /// than publishing a retry hint a caller could not act on.
    pub fn new(retry_after_ms: u64, limit: u64, window_ms: u64) -> Option<Self> {
        let details = Self {
            retry_after_ms,
            limit,
            window_ms,
        };
        details.is_well_formed().then_some(details)
    }

    /// A retry hint is only actionable when it is positive and lands inside
    /// the window it was derived from; anything else is a forged or corrupt
    /// projection and is refused at the boundary.
    pub fn is_well_formed(&self) -> bool {
        self.limit > 0
            && self.window_ms > 0
            && self.retry_after_ms > 0
            && self.retry_after_ms <= self.window_ms
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorContract {
    pub retry: RetryClass,
    pub durable_effect: DurableEffect,
}

impl ErrorContract {
    const fn new(retry: RetryClass, durable_effect: DurableEffect) -> Self {
        Self {
            retry,
            durable_effect,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    pub code: ProtocolErrorCode,
    pub retry: RetryClass,
    pub durable_effect: DurableEffect,
    pub message: String,
    /// Present only on time-based `CEREMONY_RATE_LIMITED` rejections, and
    /// never serialized when absent. Decoders that predate
    /// [`crate::RATE_LIMIT_DETAILS_MINOR`] refuse it as an unknown field, so
    /// the Broker never negotiates a minor below that one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitDetails>,
}

impl<'de> Deserialize<'de> for ProtocolError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireError {
            code: ProtocolErrorCode,
            retry: RetryClass,
            durable_effect: DurableEffect,
            message: String,
            #[serde(default)]
            rate_limit: Option<RateLimitDetails>,
        }

        let wire = WireError::deserialize(deserializer)?;
        let contract = wire.code.contract();
        if wire.retry != contract.retry || wire.durable_effect != contract.durable_effect {
            return Err(serde::de::Error::custom(format!(
                "{} carries a forged retry or durable-effect contract",
                wire.code.as_str()
            )));
        }
        if let Some(details) = wire.rate_limit
            && (wire.code != ProtocolErrorCode::CeremonyRateLimited || !details.is_well_formed())
        {
            return Err(serde::de::Error::custom(format!(
                "{} carries unusable rate-limit details",
                wire.code.as_str()
            )));
        }
        Ok(Self {
            code: wire.code,
            retry: wire.retry,
            durable_effect: wire.durable_effect,
            message: wire.message,
            rate_limit: wire.rate_limit,
        })
    }
}

impl ProtocolError {
    pub fn new(code: ProtocolErrorCode, message: impl Into<String>) -> Self {
        let contract = code.contract();
        Self {
            code,
            retry: contract.retry,
            durable_effect: contract.durable_effect,
            message: message.into(),
            rate_limit: None,
        }
    }

    pub fn fatal(code: ProtocolErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message)
    }

    /// A time-based rate-limit rejection carrying the retry contract callers
    /// act on.
    pub fn rate_limited(message: impl Into<String>, details: RateLimitDetails) -> Self {
        let mut error = Self::new(ProtocolErrorCode::CeremonyRateLimited, message);
        if details.is_well_formed() {
            error.rate_limit = Some(details);
        }
        error
    }

    pub fn has_valid_contract(&self) -> bool {
        self.code.contract()
            == ErrorContract {
                retry: self.retry,
                durable_effect: self.durable_effect,
            }
            && self.rate_limit.is_none_or(|details| {
                self.code == ProtocolErrorCode::CeremonyRateLimited && details.is_well_formed()
            })
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ProtocolError {}

impl From<bloom_rpc_wire::WireError> for ProtocolError {
    fn from(error: bloom_rpc_wire::WireError) -> Self {
        use bloom_rpc_wire::WireErrorCode as Wire;
        let code = match error.code {
            Wire::MalformedFrame => ProtocolErrorCode::MalformedFrame,
            Wire::UnknownField => ProtocolErrorCode::UnknownField,
            Wire::LimitExceededFrame => ProtocolErrorCode::LimitExceededFrame,
            Wire::UnauthenticatedPeer => ProtocolErrorCode::UnauthenticatedPeer,
            Wire::UnsupportedVersion => ProtocolErrorCode::UnsupportedVersion,
            Wire::OperationIdConflict => ProtocolErrorCode::OperationIdConflict,
            Wire::QuotaExceeded => ProtocolErrorCode::QuotaExceeded,
            Wire::ServiceUnavailable => ProtocolErrorCode::ServiceUnavailable,
            Wire::ClockRollback => ProtocolErrorCode::ClockRollback,
            Wire::ClockUntrusted => ProtocolErrorCode::ClockUntrusted,
        };
        Self::new(code, error.message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownPeerErrorCode(pub String);

impl fmt::Display for UnknownPeerErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown peer error code {}; fail closed", self.0)
    }
}

impl std::error::Error for UnknownPeerErrorCode {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_peer_code_fails_closed_and_is_not_retryable() {
        let error = "NEW_AND_UNKNOWN".parse::<ProtocolErrorCode>().unwrap_err();
        assert_eq!(error.0, "NEW_AND_UNKNOWN");
    }

    #[test]
    fn serialized_error_contract_cannot_lie() {
        let mut error = ProtocolError::new(
            ProtocolErrorCode::AmbiguousProviderEffect,
            "provider acceptance unknown",
        );
        assert!(error.has_valid_contract());
        error.retry = RetryClass::SameOperation;
        assert!(!error.has_valid_contract());

        let wire = r#"{
            "code":"AMBIGUOUS_PROVIDER_EFFECT",
            "retry":"same_operation",
            "durable_effect":"possible_provider_effect",
            "message":"forged"
        }"#;
        assert!(serde_json::from_str::<ProtocolError>(wire).is_err());
    }

    #[test]
    fn rate_limit_details_survive_a_wire_round_trip() {
        let details = RateLimitDetails::new(84_231, 12, 300_000).unwrap();
        let error = ProtocolError::rate_limited("wallet quota is exhausted", details);
        assert!(error.has_valid_contract());

        let encoded = serde_json::to_value(&error).unwrap();
        assert_eq!(encoded["rate_limit"]["retry_after_ms"], 84_231);
        assert_eq!(encoded["rate_limit"]["limit"], 12);
        assert_eq!(encoded["rate_limit"]["window_ms"], 300_000);

        let decoded: ProtocolError = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, error);
        assert_eq!(decoded.rate_limit, Some(details));
    }

    #[test]
    fn errors_without_rate_limit_details_still_decode_and_omit_the_field() {
        let plain = ProtocolError::new(ProtocolErrorCode::CeremonyRateLimited, "no hint");
        let encoded = serde_json::to_value(&plain).unwrap();
        assert!(encoded.get("rate_limit").is_none());

        let legacy = r#"{
            "code":"CEREMONY_RATE_LIMITED",
            "retry":"after_backoff",
            "durable_effect":"none",
            "message":"no hint"
        }"#;
        let decoded: ProtocolError = serde_json::from_str(legacy).unwrap();
        assert_eq!(decoded, plain);
        assert!(decoded.rate_limit.is_none());
    }

    /// `ProtocolError` exactly as a peer one minor older decodes it: strict,
    /// with no field able to absorb `rate_limit`. This is the decoder the
    /// negotiated range exists to keep away from a rate-limited error.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PreRateLimitProtocolError {
        #[allow(dead_code)]
        code: ProtocolErrorCode,
        #[allow(dead_code)]
        retry: RetryClass,
        #[allow(dead_code)]
        durable_effect: DurableEffect,
        #[allow(dead_code)]
        message: String,
    }

    #[test]
    fn a_decoder_predating_the_rate_limit_minor_refuses_the_field() {
        let details = RateLimitDetails::new(61_000, 12, 300_000).unwrap();
        let encoded = serde_json::to_string(&ProtocolError::rate_limited(
            "wallet ceremony rolling creation quota is exhausted",
            details,
        ))
        .unwrap();
        assert!(
            serde_json::from_str::<PreRateLimitProtocolError>(&encoded).is_err(),
            "an older strict decoder must fail on rate_limit, which is why the \
             negotiated range excludes every minor below it"
        );

        // The same decoder still reads every error that omits the field, so
        // the field is the whole of the incompatibility.
        let plain = serde_json::to_string(&ProtocolError::new(
            ProtocolErrorCode::QuotaExceeded,
            "full",
        ))
        .unwrap();
        assert!(serde_json::from_str::<PreRateLimitProtocolError>(&plain).is_ok());
        const {
            assert!(crate::BROKER_API_MINOR_MIN >= crate::RATE_LIMIT_DETAILS_MINOR);
        }
    }

    #[test]
    fn unusable_or_misplaced_rate_limit_details_are_refused() {
        assert!(RateLimitDetails::new(0, 12, 300_000).is_none());
        assert!(RateLimitDetails::new(300_001, 12, 300_000).is_none());
        assert!(RateLimitDetails::new(1, 0, 300_000).is_none());
        assert!(RateLimitDetails::new(1, 12, 0).is_none());

        // A retry hint longer than its own window, and a hint bolted onto an
        // unrelated code, are both rejected instead of trusted.
        for wire in [
            r#"{
                "code":"CEREMONY_RATE_LIMITED",
                "retry":"after_backoff",
                "durable_effect":"none",
                "message":"forged",
                "rate_limit":{"retry_after_ms":300001,"limit":12,"window_ms":300000}
            }"#,
            r#"{
                "code":"QUOTA_EXCEEDED",
                "retry":"after_backoff",
                "durable_effect":"none",
                "message":"concurrency",
                "rate_limit":{"retry_after_ms":10,"limit":12,"window_ms":300000}
            }"#,
        ] {
            assert!(serde_json::from_str::<ProtocolError>(wire).is_err());
        }
    }
}
