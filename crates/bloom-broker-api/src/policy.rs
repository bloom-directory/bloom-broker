use crate::{
    Base64UrlBytes, CeremonyKind, CustodyResult, DecimalU64, Digest32, OperationId, ProtocolError,
    ProtocolErrorCode, Token,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
const POLICY_UPDATE_TERMS_DOMAIN: &[u8] = b"bloom-policy-update-terms/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWalletPolicy {
    pub wallet_id: Token,
    pub maximum_approval_lifetime_ms: u64,
    pub allowed_petal_packages: Vec<Digest32>,
    pub allowed_destinations: Vec<PolicyDestination>,
    pub required_verifiers: Vec<RequiredVerifier>,
}
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDestination {
    pub chain: Token,
    pub destination: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredVerifier {
    pub verifier_id: Token,
    pub verifier_digest: Digest32,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicySnapshot {
    pub wallet_id: Token,
    pub version: DecimalU64,
    pub canonical_policy: Base64UrlBytes,
    pub policy_digest: Digest32,
    pub policy_signing_key_id: Token,
    pub policy_verifying_key: Base64UrlBytes,
    pub signer_signature: Base64UrlBytes,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdateRequest {
    pub operation_id: OperationId,
    pub wallet_id: Token,
    pub baseline_version: DecimalU64,
    pub baseline_digest: Digest32,
    pub proposed_canonical_policy: Base64UrlBytes,
    pub proposed_policy_digest: Digest32,
    pub authority_diff_digest: Digest32,
    pub assurance_level: Token,
}
impl PolicyUpdateRequest {
    pub fn terms_digest(&self) -> Result<Digest32, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_UPDATE_TERMS_DOMAIN);
        hasher.update(serde_jcs::to_vec(self).map_err(canonical_error)?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdatePrepareResponse {
    pub operation_id: OperationId,
    pub ceremony_kind: CeremonyKind,
    pub ceremony_url: String,
    pub ceremony_expires_at_ms: DecimalU64,
    pub review_manifest_digest: Digest32,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCommitUpdateRequest {
    pub operation_id: OperationId,
    pub ceremony_receipt: CustodyResult,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCommitReceipt {
    pub operation_id: OperationId,
    pub wallet_id: Token,
    pub previous_version: DecimalU64,
    pub committed: SignedPolicySnapshot,
    pub authority_diff_digest: Digest32,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}
fn canonical_error(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        format!("policy canonicalization failed: {error}"),
    )
}
