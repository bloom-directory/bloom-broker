use serde::{Deserialize, Serialize};

use crate::{
    AssetId, ClaimAssuranceLevel, CryptoSuite, DecimalU64, DecimalU256, Digest32, RequestNonce,
    Token,
};

pub const SOLANA_SYSTEM_TRANSFER_VERIFIER_ID: &str = "solana-system-transfer-v1";
pub const SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES: [u8; 32] = [
    0x8e, 0x33, 0x06, 0x7a, 0x59, 0x30, 0x1e, 0x84, 0x49, 0x5f, 0x0b, 0xb5, 0x82, 0xbd, 0x8a, 0xaa,
    0x00, 0xa0, 0x5f, 0xb0, 0xc0, 0xbd, 0x18, 0x87, 0x9f, 0xc7, 0x11, 0xa4, 0x67, 0xf3, 0xe4, 0x56,
];

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

/// Cluster facts bound into a native chain operation. The semantic verifier
/// establishes the recent blockhash from the exact signed message; a separate
/// trusted observation/attestation gate is required to establish live genesis
/// and freshness before a release may enable mainnet.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemChainContext {
    pub chain_family: Token,
    pub genesis_hash: String,
    pub recent_blockhash: String,
    pub last_valid_block_height: DecimalU64,
}

/// Economic and chain-context claim for an installer-authorized native system
/// operation. This is deliberately distinct from [`PetalUseClaim`]: native
/// execution must not impersonate a Petal package merely to reach assurance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemUseClaim {
    pub component_id: Token,
    pub action_class: Token,
    pub operation_class: Token,
    pub crypto_suite: CryptoSuite,
    pub payload_digest: Digest32,
    pub ordered_hashes: Vec<Digest32>,
    pub declared_debits: Vec<DeclaredDebit>,
    pub declared_destinations: Vec<DeclaredDestination>,
    pub declared_fee: DeclaredFee,
    pub nonce: RequestNonce,
    pub chain_context: SystemChainContext,
    pub claim_assurance: ClaimAssurance,
}
