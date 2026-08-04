//! Closed Signer error projection onto the Machine-facing error registry.

use bloom_broker_api as north;
use bloom_signer_api as south;

fn code_to_machine(value: south::ProtocolErrorCode) -> north::ProtocolErrorCode {
    match value {
        south::ProtocolErrorCode::UnauthenticatedPeer => {
            north::ProtocolErrorCode::UnauthenticatedPeer
        }
        south::ProtocolErrorCode::UnsupportedVersion => {
            north::ProtocolErrorCode::UnsupportedVersion
        }
        south::ProtocolErrorCode::MalformedFrame => north::ProtocolErrorCode::MalformedFrame,
        south::ProtocolErrorCode::LimitExceededFrame => {
            north::ProtocolErrorCode::LimitExceededFrame
        }
        south::ProtocolErrorCode::UnknownField => north::ProtocolErrorCode::UnknownField,
        south::ProtocolErrorCode::UnknownMethod => north::ProtocolErrorCode::UnknownMethod,
        south::ProtocolErrorCode::OperationIdConflict => {
            north::ProtocolErrorCode::OperationIdConflict
        }
        south::ProtocolErrorCode::ApprovalNotFound => north::ProtocolErrorCode::ApprovalNotFound,
        south::ProtocolErrorCode::ApprovalExpired => north::ProtocolErrorCode::ApprovalExpired,
        south::ProtocolErrorCode::ApprovalRevoked => north::ProtocolErrorCode::ApprovalRevoked,
        south::ProtocolErrorCode::ApprovalRearmRequired => {
            north::ProtocolErrorCode::ApprovalRearmRequired
        }
        south::ProtocolErrorCode::RevocationEpochUnreconciled => {
            north::ProtocolErrorCode::RevocationEpochUnreconciled
        }
        south::ProtocolErrorCode::SelectorMismatch => north::ProtocolErrorCode::SelectorMismatch,
        south::ProtocolErrorCode::SuiteNotAllowed => north::ProtocolErrorCode::SuiteNotAllowed,
        south::ProtocolErrorCode::KeyrefMismatch => north::ProtocolErrorCode::KeyrefMismatch,
        south::ProtocolErrorCode::LimitExceededOperations => {
            north::ProtocolErrorCode::LimitExceededOperations
        }
        south::ProtocolErrorCode::LimitExceededSignatures => {
            north::ProtocolErrorCode::LimitExceededSignatures
        }
        south::ProtocolErrorCode::LimitExceededValue => {
            north::ProtocolErrorCode::LimitExceededValue
        }
        south::ProtocolErrorCode::LimitExceededRate => north::ProtocolErrorCode::LimitExceededRate,
        south::ProtocolErrorCode::SignerRateBackstopDenied => {
            north::ProtocolErrorCode::SignerRateBackstopDenied
        }
        south::ProtocolErrorCode::ClaimInvalid => north::ProtocolErrorCode::ClaimInvalid,
        south::ProtocolErrorCode::AssuranceUnavailable => {
            north::ProtocolErrorCode::AssuranceUnavailable
        }
        south::ProtocolErrorCode::ProvenanceMismatch => {
            north::ProtocolErrorCode::ProvenanceMismatch
        }
        south::ProtocolErrorCode::PolicyBaselineStale => {
            north::ProtocolErrorCode::PolicyBaselineStale
        }
        south::ProtocolErrorCode::CeremonyRateLimited => {
            north::ProtocolErrorCode::CeremonyRateLimited
        }
        south::ProtocolErrorCode::CeremonyReplay => north::ProtocolErrorCode::CeremonyReplay,
        south::ProtocolErrorCode::CeremonyKindMismatch => {
            north::ProtocolErrorCode::CeremonyKindMismatch
        }
        south::ProtocolErrorCode::QuotaExceeded => north::ProtocolErrorCode::QuotaExceeded,
        south::ProtocolErrorCode::ClockUntrusted => north::ProtocolErrorCode::ClockUntrusted,
        south::ProtocolErrorCode::ClockRollback => north::ProtocolErrorCode::ClockRollback,
        south::ProtocolErrorCode::BackendUnsupported => {
            north::ProtocolErrorCode::BackendUnsupported
        }
        south::ProtocolErrorCode::BackendInvalidRequest => {
            north::ProtocolErrorCode::BackendInvalidRequest
        }
        south::ProtocolErrorCode::AmbiguousProviderEffect => {
            north::ProtocolErrorCode::AmbiguousProviderEffect
        }
        south::ProtocolErrorCode::ServiceUnavailable => {
            north::ProtocolErrorCode::ServiceUnavailable
        }
    }
}

fn code_to_signer(value: north::ProtocolErrorCode) -> south::ProtocolErrorCode {
    match value {
        north::ProtocolErrorCode::UnauthenticatedPeer => {
            south::ProtocolErrorCode::UnauthenticatedPeer
        }
        north::ProtocolErrorCode::UnsupportedVersion => {
            south::ProtocolErrorCode::UnsupportedVersion
        }
        north::ProtocolErrorCode::MalformedFrame => south::ProtocolErrorCode::MalformedFrame,
        north::ProtocolErrorCode::LimitExceededFrame => {
            south::ProtocolErrorCode::LimitExceededFrame
        }
        north::ProtocolErrorCode::UnknownField => south::ProtocolErrorCode::UnknownField,
        north::ProtocolErrorCode::UnknownMethod => south::ProtocolErrorCode::UnknownMethod,
        north::ProtocolErrorCode::OperationIdConflict => {
            south::ProtocolErrorCode::OperationIdConflict
        }
        north::ProtocolErrorCode::ApprovalNotFound => south::ProtocolErrorCode::ApprovalNotFound,
        north::ProtocolErrorCode::ApprovalExpired => south::ProtocolErrorCode::ApprovalExpired,
        north::ProtocolErrorCode::ApprovalRevoked => south::ProtocolErrorCode::ApprovalRevoked,
        north::ProtocolErrorCode::ApprovalRearmRequired => {
            south::ProtocolErrorCode::ApprovalRearmRequired
        }
        north::ProtocolErrorCode::RevocationEpochUnreconciled => {
            south::ProtocolErrorCode::RevocationEpochUnreconciled
        }
        north::ProtocolErrorCode::SelectorMismatch => south::ProtocolErrorCode::SelectorMismatch,
        north::ProtocolErrorCode::SuiteNotAllowed => south::ProtocolErrorCode::SuiteNotAllowed,
        north::ProtocolErrorCode::KeyrefMismatch => south::ProtocolErrorCode::KeyrefMismatch,
        north::ProtocolErrorCode::LimitExceededOperations => {
            south::ProtocolErrorCode::LimitExceededOperations
        }
        north::ProtocolErrorCode::LimitExceededSignatures => {
            south::ProtocolErrorCode::LimitExceededSignatures
        }
        north::ProtocolErrorCode::LimitExceededValue => {
            south::ProtocolErrorCode::LimitExceededValue
        }
        north::ProtocolErrorCode::LimitExceededRate => south::ProtocolErrorCode::LimitExceededRate,
        north::ProtocolErrorCode::SignerRateBackstopDenied => {
            south::ProtocolErrorCode::SignerRateBackstopDenied
        }
        north::ProtocolErrorCode::ClaimInvalid => south::ProtocolErrorCode::ClaimInvalid,
        north::ProtocolErrorCode::AssuranceUnavailable => {
            south::ProtocolErrorCode::AssuranceUnavailable
        }
        north::ProtocolErrorCode::ProvenanceMismatch => {
            south::ProtocolErrorCode::ProvenanceMismatch
        }
        north::ProtocolErrorCode::PolicyBaselineStale => {
            south::ProtocolErrorCode::PolicyBaselineStale
        }
        north::ProtocolErrorCode::CeremonyRateLimited => {
            south::ProtocolErrorCode::CeremonyRateLimited
        }
        north::ProtocolErrorCode::CeremonyReplay => south::ProtocolErrorCode::CeremonyReplay,
        north::ProtocolErrorCode::CeremonyKindMismatch => {
            south::ProtocolErrorCode::CeremonyKindMismatch
        }
        north::ProtocolErrorCode::QuotaExceeded => south::ProtocolErrorCode::QuotaExceeded,
        north::ProtocolErrorCode::ClockUntrusted => south::ProtocolErrorCode::ClockUntrusted,
        north::ProtocolErrorCode::ClockRollback => south::ProtocolErrorCode::ClockRollback,
        north::ProtocolErrorCode::BackendUnsupported => {
            south::ProtocolErrorCode::BackendUnsupported
        }
        north::ProtocolErrorCode::BackendInvalidRequest => {
            south::ProtocolErrorCode::BackendInvalidRequest
        }
        north::ProtocolErrorCode::AmbiguousProviderEffect => {
            south::ProtocolErrorCode::AmbiguousProviderEffect
        }
        north::ProtocolErrorCode::ServiceUnavailable => {
            south::ProtocolErrorCode::ServiceUnavailable
        }
    }
}

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
