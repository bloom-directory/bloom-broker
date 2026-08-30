use serde::{Deserialize, Serialize};

use crate::{
    AssetId, ClaimAssuranceLevel, CryptoSuite, DecimalU64, DecimalU256, Digest32, RequestNonce,
    Token,
};

pub const SOLANA_SYSTEM_TRANSFER_VERIFIER_ID: &str = "solana-system-transfer-v1";
pub const SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES: [u8; 32] = [
    0x93, 0x0b, 0xad, 0x9a, 0xb1, 0x21, 0x78, 0xae, 0xd2, 0x09, 0x77, 0x6d, 0xe9, 0x39, 0x1d, 0xd6,
    0x1b, 0xfb, 0x45, 0x25, 0xdf, 0x03, 0x1d, 0x60, 0x3b, 0xd2, 0xb6, 0xd5, 0x22, 0x98, 0x7c, 0x3b,
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
