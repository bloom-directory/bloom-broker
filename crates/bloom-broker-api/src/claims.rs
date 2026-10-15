use serde::{Deserialize, Serialize};

use crate::{
    AssetId, ClaimAssuranceLevel, CryptoSuite, DecimalU64, DecimalU256, Digest32, RequestNonce,
    Token,
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

/// Plain-text lines a Petal supplies to describe the operation it is asking
/// the owner to approve. They are presentation only: nothing here is verified,
/// nothing here changes what the approval permits, and Broker renders them
/// attributed to the Petal rather than as its own findings.
///
/// This is deliberately not part of [`PetalUseClaim`]. The claim is the
/// economic assertion Broker enforces value limits against; adding display
/// text to it would make a presentation change alter an enforcement input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttributedAdvisory {
    pub schema: Token,
    pub items: Vec<String>,
}

impl AttributedAdvisory {
    pub const SCHEMA: &'static str = "bloom.petal.review.v1";
    /// Enough lines for a trade's account, assets, floor and costs, and no
    /// more. A Petal that needs an essay is describing the wrong thing.
    pub const MAX_ITEMS: usize = 16;
    pub const MAX_ITEM_CHARS: usize = 200;

    /// The lines, or why they cannot be shown. A rejected advisory fails the
    /// preparation rather than being silently dropped: an owner must not be
    /// asked to approve an operation whose description Broker discarded.
    pub fn validated(&self) -> Result<Vec<String>, String> {
        if self.schema.as_str() != Self::SCHEMA {
            return Err(format!(
                "unsupported advisory schema {:?}; expected {:?}",
                self.schema.as_str(),
                Self::SCHEMA
            ));
        }
        if self.items.is_empty() || self.items.len() > Self::MAX_ITEMS {
            return Err(format!(
                "an advisory carries 1..={} items, but this one carries {}",
                Self::MAX_ITEMS,
                self.items.len()
            ));
        }
        for item in &self.items {
            let characters = item.chars().count();
            if characters == 0 || characters > Self::MAX_ITEM_CHARS {
                return Err(format!(
                    "each advisory item is 1..={} characters, but one is {characters}",
                    Self::MAX_ITEM_CHARS
                ));
            }
            // Control characters would let a Petal forge line structure in a
            // rendered review. The page escapes markup already; this closes
            // the other half.
            if item.chars().any(char::is_control) {
                return Err("an advisory item contains a control character".to_owned());
            }
        }
        Ok(self.items.clone())
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

#[cfg(test)]
mod attributed_advisory_tests {
    use super::*;

    fn advisory(items: Vec<String>) -> AttributedAdvisory {
        AttributedAdvisory {
            schema: Token::new(AttributedAdvisory::SCHEMA).unwrap(),
            items,
        }
    }

    #[test]
    fn a_well_formed_advisory_passes_its_lines_through_unchanged() {
        let items = vec![
            "Buy on Pump.fun".to_owned(),
            "Guaranteed minimum received: 1000 raw units of C8CM…pump".to_owned(),
        ];
        assert_eq!(advisory(items.clone()).validated().unwrap(), items);
    }

    /// Every rejection here is a rejection, not a silent drop: the owner must
    /// never be asked to approve an operation whose description was discarded.
    #[test]
    fn an_advisory_that_cannot_be_rendered_honestly_is_refused() {
        let long = "x".repeat(AttributedAdvisory::MAX_ITEM_CHARS + 1);
        let cases = [
            (advisory(Vec::new()), "no items"),
            (
                advisory(vec!["x".to_owned(); AttributedAdvisory::MAX_ITEMS + 1]),
                "too many items",
            ),
            (advisory(vec![String::new()]), "an empty item"),
            (advisory(vec![long]), "an over-long item"),
            // A newline would let a Petal forge line structure inside one
            // rendered item.
            (advisory(vec!["first\nsecond".to_owned()]), "a newline"),
            (
                advisory(vec!["ring\u{7}".to_owned()]),
                "a control character",
            ),
            (
                AttributedAdvisory {
                    schema: Token::new("bloom.petal.review.v99").unwrap(),
                    items: vec!["Buy".to_owned()],
                },
                "an unknown schema",
            ),
        ];
        for (candidate, reason) in cases {
            assert!(candidate.validated().is_err(), "{reason} must be refused");
        }
    }

    /// A character counts once, however many bytes it takes. A byte-length
    /// bound would reject a legitimate non-ASCII review.
    #[test]
    fn the_item_bound_counts_characters_not_bytes() {
        let item = "é".repeat(AttributedAdvisory::MAX_ITEM_CHARS);
        assert!(item.len() > AttributedAdvisory::MAX_ITEM_CHARS);
        assert!(advisory(vec![item]).validated().is_ok());
    }
}
