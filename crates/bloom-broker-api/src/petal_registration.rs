//! Exact owner-consent terms for a package registration. These terms confer no
//! wallet, key-derivation, or signing authority.
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Base64UrlBytes, CustodyPrepareResponse, Digest32, OperationId, ProtocolError,
    ProtocolErrorCode, Token,
};

pub const PETAL_REGISTRATION_SCHEMA: &str = "bloom.petal-registration/1";
pub use bloom_petal_contract::{PackageEvidence, RequestedRoutePermission};
const RECORD_DOMAIN: &[u8] = b"bloom.petal-registration-record/v1";
const TERMS_DOMAIN: &[u8] = b"bloom.petal-registration-terms/v1\0";
const ENROLLMENT_DOMAIN: &[u8] = b"bloom.petal-registration-enrollment/v1\0";
const OWNER_ATTESTATION_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"bloom-owner-attestation-receipt/v1\0";
const REGISTRATION_CONTEXT_DOMAIN: &[u8] = b"bloom-petal-registration-context/v1\0";

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistrationReceipt {
    pub operation_id: OperationId,
    pub ceremony_id: Digest32,
    pub owner_wallet_id: Token,
    pub authority_edge_digest: Digest32,
    pub context_digest: Digest32,
    pub subject_digest: Digest32,
    pub receipt_digest: Digest32,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

impl PetalRegistrationReceipt {
    pub fn validate_binding(
        &self,
        terms: &PetalRegistrationTerms,
        authority_edge_digest: &Digest32,
    ) -> Result<(), ProtocolError> {
        if self.operation_id != terms.operation_id
            || self.owner_wallet_id != terms.owner_wallet_id
            || &self.authority_edge_digest != authority_edge_digest
            || self.context_digest != petal_registration_context_digest()
            || self.subject_digest != terms.digest()?
        {
            return Err(binding_error());
        }
        Ok(())
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            operation_id: &'a OperationId,
            ceremony_id: &'a Digest32,
            owner_wallet_id: &'a Token,
            authority_edge_digest: &'a Digest32,
            context_digest: &'a Digest32,
            subject_digest: &'a Digest32,
            receipt_digest: &'a Digest32,
            signer_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            operation_id: &self.operation_id,
            ceremony_id: &self.ceremony_id,
            owner_wallet_id: &self.owner_wallet_id,
            authority_edge_digest: &self.authority_edge_digest,
            context_digest: &self.context_digest,
            subject_digest: &self.subject_digest,
            receipt_digest: &self.receipt_digest,
            signer_key_id: &self.signer_key_id,
        })
        .map_err(|error| ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string()))
    }

    pub fn signature_message(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok([
            OWNER_ATTESTATION_RECEIPT_SIGNATURE_DOMAIN,
            self.unsigned_canonical_bytes()?.as_slice(),
        ]
        .concat())
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
    pub ceremony_receipt: PetalRegistrationReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistration {
    pub terms: PetalRegistrationTerms,
    pub approved_routes: Vec<RequestedRoutePermission>,
    pub ceremony_receipt: PetalRegistrationReceipt,
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
            ceremony_receipt: &'a PetalRegistrationReceipt,
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

pub fn petal_registration_context_digest() -> Digest32 {
    Digest32::from_bytes(Sha256::digest(REGISTRATION_CONTEXT_DOMAIN).into())
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
    let checked = bloom_petal_contract::check_package_request(
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
        .chunks(bloom_petal_contract::evidence::MAX_PAGE_ENTRIES)
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
