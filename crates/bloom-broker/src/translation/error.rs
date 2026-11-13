//! Closed Signer error projection onto the Machine-facing error registry.

use bloom_broker_api as north;
use bloom_signer_api as south;

unit_enum_translation!(ProtocolErrorCode: (code_to_signer), (code_to_machine) {
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
});

pub(crate) fn signer_error_to_machine(value: south::ProtocolError) -> north::ProtocolError {
    // Re-derive retry and durable-effect contracts from the northbound code;
    // never forward peer-supplied contract fields independently.
    north::ProtocolError::new(code_to_machine(value.code), value.message)
}

pub(crate) fn machine_error_to_signer(value: north::ProtocolError) -> south::ProtocolError {
    south::ProtocolError::new(code_to_signer(value.code), value.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signer_error_code_preserves_its_contract() {
        for code in south::ProtocolErrorCode::ALL {
            let mapped = signer_error_to_machine(south::ProtocolError::new(code, code.as_str()));
            assert!(mapped.has_valid_contract());
            assert_eq!(mapped.code.as_str(), code.as_str());
        }
        for code in north::ProtocolErrorCode::ALL {
            let mapped = machine_error_to_signer(north::ProtocolError::new(code, code.as_str()));
            assert!(mapped.has_valid_contract());
            assert_eq!(mapped.code.as_str(), code.as_str());
        }
    }
}
