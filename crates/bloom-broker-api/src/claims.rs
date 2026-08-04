use serde::{Deserialize, Serialize};

use crate::{
    AssetId, ClaimAssuranceLevel, CryptoSuite, DecimalU256, Digest32, RequestNonce, Token,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredDebit {
    pub asset: AssetId,
    pub amount: DecimalU256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredDestination {
    pub chain: Token,
    pub destination: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeclaredFee {
    None,
    Fee {
        chain: Token,
        asset: String,
        amount: DecimalU256,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimAssurance {
    MachineAsserted,
    ProofVerified {
        verifier_id: Token,
        verifier_digest: Digest32,
        proof_digest: Digest32,
    },
    InvariantAttested {
        attestor_id: Token,
        attestation_digest: Digest32,
    },
}

impl ClaimAssurance {
    pub const fn level(&self) -> ClaimAssuranceLevel {
        match self {
            Self::MachineAsserted => ClaimAssuranceLevel::MachineAsserted,
            Self::ProofVerified { .. } => ClaimAssuranceLevel::ProofVerified,
            Self::InvariantAttested { .. } => ClaimAssuranceLevel::InvariantAttested,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalUseClaim {
    pub package_hash: Digest32,
    pub route: String,
    pub operation_class: Token,
    pub crypto_suite: CryptoSuite,
    pub payload_digest: Digest32,
    pub ordered_hashes: Vec<Digest32>,
    pub declared_debits: Vec<DeclaredDebit>,
    pub declared_destinations: Vec<DeclaredDestination>,
    pub declared_fee: DeclaredFee,
    pub nonce: RequestNonce,
    pub claim_assurance: ClaimAssurance,
}
