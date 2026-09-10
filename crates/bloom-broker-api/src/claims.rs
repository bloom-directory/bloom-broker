use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    AssetId, ClaimAssuranceLevel, CryptoSuite, DecimalU64, DecimalU256, Digest32, ProtocolError,
    ProtocolErrorCode, RequestNonce, Token,
};

pub const SOLANA_SYSTEM_TRANSFER_VERIFIER_ID: &str = "solana-system-transfer-v1";
pub const SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES: [u8; 32] = [
    0x74, 0x9e, 0x18, 0x79, 0xc8, 0x3d, 0x2c, 0x53, 0x93, 0x75, 0xaf, 0x1d, 0xff, 0xd2, 0x73, 0x0c,
    0xe0, 0x3c, 0xfd, 0xa0, 0x1c, 0x6b, 0xf0, 0x96, 0x1d, 0x2e, 0x86, 0x26, 0x09, 0x96, 0xb1, 0x1c,
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

impl SystemUseClaim {
    /// Digest of the reviewed economic and chain identity, excluding only
    /// payload freshness fields that a semantic verifier re-establishes.
    pub fn approval_intent_digest(&self) -> Result<Digest32, ProtocolError> {
        #[derive(Serialize)]
        struct Intent<'a> {
            component_id: &'a Token,
            action_class: &'a Token,
            operation_class: &'a Token,
            crypto_suite: CryptoSuite,
            declared_debits: &'a [DeclaredDebit],
            declared_destinations: &'a [DeclaredDestination],
            declared_fee: &'a DeclaredFee,
            chain_family: &'a Token,
            genesis_hash: &'a str,
        }
        let intent = Intent {
            component_id: &self.component_id,
            action_class: &self.action_class,
            operation_class: &self.operation_class,
            crypto_suite: self.crypto_suite,
            declared_debits: &self.declared_debits,
            declared_destinations: &self.declared_destinations,
            declared_fee: &self.declared_fee,
            chain_family: &self.chain_context.chain_family,
            genesis_hash: &self.chain_context.genesis_hash,
        };
        let mut hasher = Sha256::new();
        hasher.update(b"bloom-system-approval-intent/v1");
        hasher.update(serde_jcs::to_vec(&intent).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("system approval intent encoding failed: {error}"),
            )
        })?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}
