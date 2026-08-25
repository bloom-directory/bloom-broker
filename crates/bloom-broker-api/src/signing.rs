use crate::{
    Base64UrlBytes, CryptoSuite, Digest32, KeyRef, OperationId, PetalUseClaim, ProvenanceSubject,
    SigningPayloads, SystemUseClaim,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSignRequest {
    pub operation_id: OperationId,
    pub operation_digest: Digest32,
    pub approval_id: Digest32,
    pub key_ref: KeyRef,
    pub crypto_suite: CryptoSuite,
    pub payloads: SigningPayloads,
    pub petal_use_claim: Option<PetalUseClaim>,
    #[serde(default)]
    pub system_use_claim: Option<SystemUseClaim>,
    pub claim_assurance_evidence: Option<Base64UrlBytes>,
    pub provenance: ProvenanceSubject,
}

/// This is intentionally distinct from the Broker's wire-level
/// selector: `Reusable` maps to the Petal selector while `Exact` maps to the
/// payload-digest selector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PetalSignSelector {
    Exact,
    Reusable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedSignature {
    pub crypto_suite: CryptoSuite,
    pub bytes: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningResult {
    pub operation_id: OperationId,
    pub operation_digest: Digest32,
    pub signatures: Vec<NormalizedSignature>,
    pub signer_receipt_digest: Digest32,
    pub broker_receipt_digest: Digest32,
}
