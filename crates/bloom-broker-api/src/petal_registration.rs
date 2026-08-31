//! Exact owner-consent terms for a package registration. These terms confer no
//! wallet, key-derivation, or signing authority.
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Base64UrlBytes, CeremonyKind, CeremonyState, CustodyPrepareResponse, CustodyResult, Digest32,
    OperationId, ProtocolError, ProtocolErrorCode, Token,
};

pub const PETAL_REGISTRATION_SCHEMA: &str = "bloom.petal-registration/1";
pub use bloom_petal_package::{PackageEvidence, RequestedRoutePermission};
const RECORD_DOMAIN: &[u8] = b"bloom.petal-registration-record/v1";
const TERMS_DOMAIN: &[u8] = b"bloom.petal-registration-terms/v1\0";
const ENROLLMENT_DOMAIN: &[u8] = b"bloom.petal-registration-enrollment/v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistrationTerms {
    #[serde(deserialize_with = "deserialize_schema")]
    pub schema: Token,
    pub operation_id: OperationId,
    pub enrollment_digest: Digest32,
    pub owner_wallet_id: Token,
    pub package_hash: Digest32,
    pub manifest_digest: Digest32,
    pub permissions_digest: Digest32,
    pub lineage_id: String,
}

impl PetalRegistrationTerms {
    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        if self.schema.as_str() != PETAL_REGISTRATION_SCHEMA {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnsupportedVersion,
                "unsupported Petal registration schema",
            ));
        }
        crate::validate_lineage_id(&self.lineage_id)
    }

    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        self.validate_shape()?;
        digest(TERMS_DOMAIN, self)
    }
}

/// Identifies the locally configured persistent custody pair, independent of
/// boot epochs, transport rotation, or release versions. Callers must use their
/// actual local key and configured peer verification pin, never request input.
pub fn petal_registration_enrollment_digest(
    broker_key_id: &Token,
    broker_public_key: &VerifyingKey,
    signer_key_id: &Token,
    signer_public_key: &VerifyingKey,
) -> Result<Digest32, ProtocolError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        service_id: &'static str,
        key_role: &'static str,
        key_id: &'a Token,
        public_key: Base64UrlBytes,
    }
    #[derive(Serialize)]
    struct Enrollment<'a> {
        broker: Identity<'a>,
        signer: Identity<'a>,
    }
    digest(
        ENROLLMENT_DOMAIN,
        &Enrollment {
            broker: Identity {
                service_id: "bloom-broker",
                key_role: "broker_signing",
                key_id: broker_key_id,
                public_key: Base64UrlBytes::from_bytes(&broker_public_key.to_bytes()),
            },
            signer: Identity {
                service_id: "bloom-signer",
                key_role: "signer_ceremony",
                key_id: signer_key_id,
                public_key: Base64UrlBytes::from_bytes(&signer_public_key.to_bytes()),
            },
        },
    )
}

impl CustodyResult {
    /// Enforce the registration-specific signed field on all receipt kinds.
    /// Existing receipt kinds keep their canonical bytes with an absent field.
    pub fn validate_petal_registration_shape(&self) -> Result<(), ProtocolError> {
        if self.ceremony_kind == CeremonyKind::PetalRegistration {
            if self.petal_registration_terms_digest.is_none()
                || self.public_status != CeremonyState::Succeeded
                || self.wallet_id.is_none()
                || !self.public_key_refs.is_empty()
                || !self.credential_summaries.is_empty()
                || self.initial_policy.is_some()
                || self.encrypted_browser_result.is_some()
            {
                return Err(binding_error());
            }
        } else if self.petal_registration_terms_digest.is_some() {
            return Err(binding_error());
        }
        Ok(())
    }

    /// Exact public terms binding; signature and local enrollment verification
    /// remain mandatory for any consumer adopting this receipt as authority.
    pub fn validate_petal_registration_binding(
        &self,
        terms: &PetalRegistrationTerms,
    ) -> Result<(), ProtocolError> {
        self.validate_petal_registration_shape()?;
        if self.ceremony_kind != CeremonyKind::PetalRegistration
            || self.custody_operation_id != terms.operation_id
            || self.wallet_id.as_ref() != Some(&terms.owner_wallet_id)
            || self.petal_registration_terms_digest.as_ref() != Some(&terms.digest()?)
        {
            return Err(binding_error());
        }
        Ok(())
    }
}

fn binding_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::CeremonyKindMismatch,
        "Petal registration binding mismatch",
    )
}
fn deserialize_schema<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Token, D::Error> {
    let schema = Token::deserialize(deserializer)?;
    if schema.as_str() != PETAL_REGISTRATION_SCHEMA {
        return Err(serde::de::Error::custom(
            "unsupported Petal registration schema",
        ));
    }
    Ok(schema)
}
fn digest(domain: &[u8], value: &impl Serialize) -> Result<Digest32, ProtocolError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistrationPrepareRequest {
    pub operation_id: OperationId,
    pub owner_wallet_id: Token,
    pub evidence: PackageEvidence,
    pub requested_routes: Vec<RequestedRoutePermission>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PetalRegistrationPrepareResponse {
    AwaitingApproval {
        terms: PetalRegistrationTerms,
        ceremony: CustodyPrepareResponse,
    },
    Registered {
        registration: PetalRegistration,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistrationCommitRequest {
    pub operation_id: OperationId,
    pub ceremony_receipt: CustodyResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistration {
    pub terms: PetalRegistrationTerms,
    pub approved_routes: Vec<RequestedRoutePermission>,
    pub ceremony_receipt: CustodyResult,
    pub registration_digest: Digest32,
}

impl PetalRegistration {
    /// Recompute the record commitment without sorting or deduplicating any
    /// reviewed array. This hash is not signature or enrollment verification.
    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        self.terms.validate_shape()?;
        #[derive(Serialize)]
        struct Record<'a> {
            terms: &'a PetalRegistrationTerms,
            approved_routes: &'a [RequestedRoutePermission],
            ceremony_receipt: &'a CustodyResult,
        }
        digest(
            RECORD_DOMAIN,
            &Record {
                terms: &self.terms,
                approved_routes: &self.approved_routes,
                ceremony_receipt: &self.ceremony_receipt,
            },
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistrationReadRequest {
    pub package_hash: Digest32,
}

/// Check the complete static proposal, then canonicalize sets before review.
/// This does not execute artifacts or certify Machine's metadata claims.
pub fn canonical_petal_registration_request(
    request: &PetalRegistrationPrepareRequest,
) -> Result<PetalRegistrationPrepareRequest, ProtocolError> {
    let checked = bloom_petal_package::check_package_request(
        request.evidence.clone(),
        request.requested_routes.clone(),
    )
    .map_err(|error| ProtocolError::new(ProtocolErrorCode::ClaimInvalid, error.to_string()))?;
    let mut canonical = request.clone();
    canonical.requested_routes = checked.routes;
    canonical
        .requested_routes
        .sort_by(|a, b| a.route_id.cmp(&b.route_id));
    for route in &mut canonical.requested_routes {
        for set in [
            &mut route.capabilities,
            &mut route.signing_operations,
            &mut route.key_derive_operations,
        ] {
            set.sort();
            set.dedup();
        }
    }
    let mut entries = checked
        .evidence
        .file_pages
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    canonical.evidence.file_pages = entries
        .chunks(bloom_petal_package::evidence::MAX_PAGE_ENTRIES)
        .map(|page| page.to_vec())
        .collect();
    Ok(canonical)
}

/// Exact UTF-8 manifest string, JCS encoded, including unverified source claims.
pub fn petal_registration_manifest_digest(manifest_utf8: &str) -> Result<Digest32, ProtocolError> {
    digest(b"bloom.petal-registration-manifest/v1\0", &manifest_utf8)
}

/// Exact reviewed array. Call canonical_petal_registration_request before review;
/// never normalize a completed record while checking its commitment.
pub fn petal_registration_permissions_digest(
    routes: &[RequestedRoutePermission],
) -> Result<Digest32, ProtocolError> {
    digest(b"bloom.petal-registration-permissions/v1\0", &routes)
}
