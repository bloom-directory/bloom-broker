//! Chain-aware decoding for wallet policy destinations.
//!
//! `allowed_destinations` is matched by comparing *decoded bytes*, never
//! strings. The same account is spelled differently by different tooling —
//! EIP-55 encodes a checksum in letter case, bech32 accepts either case — so a
//! string comparison answers a question about spelling when the question is
//! about identity.
//!
//! Stored entries are never rewritten. A policy is JCS-canonicalised and
//! signed, and its bytes feed the digests a ceremony binds, so canonicalising
//! on write would invalidate every existing signature. Only interpretation
//! changes here.
//!
//! This crate carries its own decoders rather than borrowing
//! `bloom-solana-verify`'s `Pubkey`: that crate's sources are hashed into the
//! `ProofVerified` identity wallets pin, so its file set is deliberately
//! frozen. The two look alike today and are free to diverge.

use std::fmt;

use bloom_rpc_wire::Token;
use thiserror::Error;

/// How a chain spells an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    Evm,
    Solana,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DestinationError {
    #[error("chain \"{0}\" is not a chain this build can decode addresses for")]
    UnknownChain(String),
    #[error("{family:?} address is malformed: {reason}")]
    Malformed {
        family: AddressFamily,
        reason: String,
    },
}

/// A destination decoded into its chain's native address bytes.
///
/// Equality is over the variant *and* the bytes, so two families can never
/// compare equal even when their payloads coincide.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainAddress {
    Evm([u8; 20]),
    /// Exactly 32 bytes, and **not** necessarily a curve point: program
    /// derived addresses are deliberately off-curve, and Petals declare them
    /// as destinations. Validating ed25519 membership here would refuse every
    /// PDA and every associated token account.
    Solana([u8; 32]),
}

/// An entry in `allowed_destinations`. Not every entry is an address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyTarget {
    Address(ChainAddress),
    /// `petal:<name>` — a destination chosen by the named Petal rather than a
    /// fixed account. Matched case-insensitively, and carried lowercased here
    /// so equality is byte-wise like every other variant.
    PetalClass(String),
}

impl fmt::Display for PolicyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PetalClass(name) => write!(f, "petal:{name}"),
            Self::Address(ChainAddress::Evm(bytes)) => write!(f, "0x{}", hex::encode(bytes)),
            Self::Address(ChainAddress::Solana(bytes)) => {
                f.write_str(&bs58::encode(bytes).into_string())
            }
        }
    }
}

/// The prefix marking a Petal-chosen destination rather than a fixed account.
pub const PETAL_DESTINATION_PREFIX: &str = "petal:";

/// Which spelling rules a chain uses.
///
/// Chains are named rather than identified by CAIP-2 today. Under CAIP-2 this
/// function would collapse into reading the namespace (`eip155:*` is EVM,
/// `solana:*` is Solana), so the mapping is isolated here: adopting CAIP-2
/// changes this body and nothing that calls it.
pub fn address_family(chain: &Token) -> Option<AddressFamily> {
    match chain.as_str() {
        "solana" => Some(AddressFamily::Solana),
        // Every other chain Bloom transacts on today is EVM. An unknown name
        // returns None and fails closed at the call site rather than guessing.
        "arbitrum" | "arc" | "avalanche" | "base" | "bsc" | "ethereum" | "gnosis"
        | "hyperliquid" | "linea" | "optimism" | "polygon" | "robinhood" | "tempo" => {
            Some(AddressFamily::Evm)
        }
        _ => None,
    }
}

/// Decodes one `allowed_destinations` entry for comparison.
pub fn parse_destination(
    chain: &Token,
    destination: &str,
) -> Result<PolicyTarget, DestinationError> {
    if let Some(name) = destination.strip_prefix(PETAL_DESTINATION_PREFIX) {
        return Ok(PolicyTarget::PetalClass(name.to_ascii_lowercase()));
    }
    let family =
        address_family(chain).ok_or_else(|| DestinationError::UnknownChain(chain.to_string()))?;
    let address = match family {
        AddressFamily::Evm => ChainAddress::Evm(evm_address(destination)?),
        AddressFamily::Solana => ChainAddress::Solana(solana_address(destination)?),
    };
    Ok(PolicyTarget::Address(address))
}

fn malformed(family: AddressFamily, reason: impl Into<String>) -> DestinationError {
    DestinationError::Malformed {
        family,
        reason: reason.into(),
    }
}

/// 20 bytes of hex. Case is EIP-55's checksum, not part of the address, so
/// both spellings decode identically and neither is preferred.
///
/// The checksum is deliberately not verified: it would need keccak, which this
/// crate does not carry, and it cannot change which account the bytes name.
/// Verifying it is typo protection and belongs where a policy is written.
fn evm_address(value: &str) -> Result<[u8; 20], DestinationError> {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| malformed(AddressFamily::Evm, "expected a 0x-prefixed address"))?;
    let bytes = hex::decode(body).map_err(|e| malformed(AddressFamily::Evm, e.to_string()))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        malformed(
            AddressFamily::Evm,
            format!("expected 20 bytes, got {}", b.len()),
        )
    })
}

/// 32 bytes of base58. Case carries data here, unlike EVM, so the string is
/// decoded exactly as written.
fn solana_address(value: &str) -> Result<[u8; 32], DestinationError> {
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|e| malformed(AddressFamily::Solana, e.to_string()))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        malformed(
            AddressFamily::Solana,
            format!("expected 32 bytes, got {}", b.len()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(name: &str) -> Token {
        Token::new(name).expect("valid chain token")
    }

    fn parse(name: &str, destination: &str) -> PolicyTarget {
        parse_destination(&chain(name), destination).expect("destination decodes")
    }

    /// The whole point. EIP-55 encodes a checksum in letter case, so tooling
    /// emits the mixed-case form while policies are often written lowercase.
    /// Comparing strings makes those two different destinations.
    #[test]
    fn evm_spellings_of_one_account_are_one_destination() {
        let checksummed = parse("base", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        let lowercase = parse("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
        let uppercase = parse("base", "0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913");
        assert_eq!(checksummed, lowercase);
        assert_eq!(checksummed, uppercase);
    }

    #[test]
    fn evm_rejects_wrong_length_and_non_hex() {
        for bad in [
            "0xdeadbeef",
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda0291",
            "not-an-address",
        ] {
            assert!(
                parse_destination(&chain("base"), bad).is_err(),
                "{bad} must not decode"
            );
        }
    }

    /// Case is data in base58, not a checksum, so two spellings are two
    /// different accounts — the opposite of the EVM rule above.
    #[test]
    fn solana_case_is_not_interchangeable() {
        let a = parse("solana", "11111111111111111111111111111111");
        let b = parse_destination(&chain("solana"), "1111111111111111111111111111111z");
        assert!(b.is_err() || PolicyTarget::Address(ChainAddress::Solana([0; 32])) != b.unwrap());
        assert_eq!(a, PolicyTarget::Address(ChainAddress::Solana([0; 32])));
    }

    /// Solana destinations include program IDs and program derived addresses.
    /// PDAs are constructed to be *off* the ed25519 curve, so a validity check
    /// stronger than "32 bytes" would refuse every one of them — and every
    /// associated token account with them. This test exists to make that
    /// deliberate: do not add curve validation here.
    #[test]
    fn solana_accepts_any_thirty_two_bytes_without_curve_validation() {
        // The System Program, which Petals genuinely declare as a destination.
        parse("solana", "11111111111111111111111111111111");
        // The SPL Associated Token Account program.
        parse("solana", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
        assert!(
            parse_destination(&chain("solana"), "111").is_err(),
            "length is still enforced"
        );
    }

    /// 32 bytes on one chain must never equal 32 bytes on another.
    #[test]
    fn families_cannot_collide() {
        let solana = ChainAddress::Solana([7; 32]);
        let evm = ChainAddress::Evm([7; 20]);
        assert_ne!(PolicyTarget::Address(solana), PolicyTarget::Address(evm));
    }

    /// `allowed_destinations` is a union: concrete accounts and Petal classes.
    /// A `petal:` entry is not an address and must survive decoding rather
    /// than erroring or being silently dropped.
    #[test]
    fn petal_classes_round_trip_on_every_chain() {
        assert_eq!(
            parse("solana", "petal:near-intents"),
            PolicyTarget::PetalClass("near-intents".into())
        );
        assert_eq!(
            parse("base", "petal:NEAR-Intents"),
            PolicyTarget::PetalClass("near-intents".into()),
            "petal classes match case-insensitively"
        );
        // Even on a chain this build cannot decode addresses for.
        assert_eq!(
            parse("some-future-chain", "petal:near-intents"),
            PolicyTarget::PetalClass("near-intents".into())
        );
    }

    /// An unrecognised chain must not be guessed at. Refusing to decode is
    /// what makes a typo'd chain name visible instead of inert.
    #[test]
    fn an_unknown_chain_fails_closed() {
        assert!(matches!(
            parse_destination(&chain("bsae"), "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
            Err(DestinationError::UnknownChain(_))
        ));
    }

    #[test]
    fn display_round_trips_each_variant() {
        for (chain_name, text) in [
            ("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
            ("solana", "11111111111111111111111111111111"),
            ("base", "petal:near-intents"),
        ] {
            assert_eq!(parse(chain_name, text).to_string(), text);
        }
    }
}
