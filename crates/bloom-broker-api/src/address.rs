//! Chain-aware decoding for wallet policy destinations.
//!
//! `allowed_destinations` is matched by comparing *decoded bytes*, never
//! strings. The same account is spelled differently by different tooling —
//! EIP-55 encodes a checksum in letter case, bech32 accepts either case — so a
//! string comparison answers a question about spelling when the question is
//! about identity.
//!
//! Decoding is equally what keeps distinct accounts *apart*. A Cosmos HRP and
//! a Bitcoin output script carry identity, not decoration: `cosmos1…` and
//! `cosmosvaloper1…` over one key are different destinations, and so are the
//! P2PKH and P2WPKH addresses over one hash160. Comparing payloads alone would
//! quietly merge them, which is the more dangerous direction of the same bug.
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

use bech32::{Bech32, Hrp, primitives::decode::CheckedHrpstring};
use bloom_rpc_wire::Token;
use thiserror::Error;

/// How a chain spells an address.
///
/// This is narrower than the `chain_family` on [`crate::wallet_account`],
/// which names a *key* family (`evm` is secp256k1, `solana` is ed25519). Two
/// chains can share a key family and still encode addresses nothing alike —
/// EVM and Cosmos are both secp256k1 — so the two stay separate concepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    Evm,
    Solana,
    Cosmos,
    Bitcoin,
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
    /// bech32, compared as `(hrp, payload)` because the prefix is part of the
    /// identity: `cosmos1…` is an account and `cosmosvaloper1…` is a validator
    /// operator, over the very same key.
    Cosmos {
        hrp: String,
        payload: Vec<u8>,
    },
    /// The output script the address pays to, not the hash inside it. One
    /// hash160 has both a P2PKH and a P2WPKH spelling that spend under
    /// different rules, so they must not compare equal.
    Bitcoin {
        script_pubkey: Vec<u8>,
    },
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
            Self::Address(ChainAddress::Cosmos { hrp, payload }) => {
                let hrp = Hrp::parse(hrp).map_err(|_| fmt::Error)?;
                f.write_str(&bech32::encode::<Bech32>(hrp, payload).map_err(|_| fmt::Error)?)
            }
            // Deliberately not re-encoded as an address. The script *is* the
            // decoded identity, and a reverse mapping would be a second
            // implementation of the forward one, free to drift from it, for
            // the sake of a diagnostic string.
            Self::Address(ChainAddress::Bitcoin { script_pubkey }) => {
                write!(f, "script:{}", hex::encode(script_pubkey))
            }
        }
    }
}

/// The prefix marking a Petal-chosen destination rather than a fixed account.
pub const PETAL_DESTINATION_PREFIX: &str = "petal:";

/// Cosmos payloads are 20 bytes for a secp256k1 account and 32 for module and
/// interchain accounts. The bound is a sanity limit rather than either of
/// those: a length no chain uses simply never matches a real destination, so
/// pinning the set here would only refuse chains before they arrive.
const COSMOS_MAX_PAYLOAD_BYTES: usize = 64;

/// Bitcoin mainnet only. Testnet and regtest are different chains and belong
/// under their own `chain` names — accepting `tb1…` here would let a testnet
/// address sit in a mainnet policy and read as allowed.
const BITCOIN_MAINNET_HRP: &str = "bc";
const BITCOIN_P2PKH_VERSION: u8 = 0x00;
const BITCOIN_P2SH_VERSION: u8 = 0x05;

/// Which spelling rules a chain uses.
///
/// A plain name rather than a CAIP-2 identifier, because `Token` cannot hold
/// one: its alphabet is `[a-z0-9._/-]`, with no `:`. CAIP-2 already lives in
/// this crate as the `caip2: String` on `ChainAccountProjection`, which is the
/// shape adopting it here would take too — a wire-visible type change to a
/// field inside the signed policy snapshot. It would also not remove this
/// table, only add to it: existing signatures cover the spelling `base`, so
/// the mapping would have to stay for as long as any policy signed today does.
pub fn address_family(chain: &Token) -> Option<AddressFamily> {
    match chain.as_str() {
        "bitcoin" => Some(AddressFamily::Bitcoin),
        "solana" => Some(AddressFamily::Solana),
        // Bech32 chains are listed by name even though the HRP identifies the
        // chain, because HRPs are reused across a chain's own testnets.
        "celestia" | "cosmos" | "dydx" | "injective" | "neutron" | "noble" | "osmosis" => {
            Some(AddressFamily::Cosmos)
        }
        // Every other chain Bloom transacts on today is EVM. An unknown name
        // returns None and fails closed at the call site rather than guessing.
        // Machine's shipped chain list, plus `robinhood`, which policies name.
        // `anvil` is the local development node and is EVM like the rest: a
        // destination there should follow the same case rule, not fall back to
        // exact spelling because the name was missing here.
        "anvil" | "arbitrum" | "arc" | "avalanche" | "base" | "bsc" | "ethereum" | "gnosis"
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
        AddressFamily::Cosmos => {
            let (hrp, payload) = cosmos_address(destination)?;
            ChainAddress::Cosmos { hrp, payload }
        }
        AddressFamily::Bitcoin => ChainAddress::Bitcoin {
            script_pubkey: bitcoin_script_pubkey(destination)?,
        },
    };
    Ok(PolicyTarget::Address(address))
}

/// The value a destination is compared by.
///
/// Decoding only ever *adds* matches. Where the chain is unknown to this build,
/// or the spelling does not decode, the entry compares verbatim — which is what
/// every chain did before this module existed — so nothing that was allowed
/// yesterday is refused today. A policy naming `localnet`, or carrying a
/// placeholder like `0xrecipient`, keeps behaving exactly as it did.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Comparable {
    Decoded(PolicyTarget),
    Literal(String),
}

/// Reduces one `(chain, destination)` pair to the value it is compared by.
///
/// A pure function of its inputs, so two identical spellings always reduce
/// alike: exact-match behaviour survives by construction rather than through a
/// fallback branch repeated at each call site.
pub fn comparable(chain: &Token, destination: &str) -> Comparable {
    match parse_destination(chain, destination) {
        Ok(target) => Comparable::Decoded(target),
        Err(_) => Comparable::Literal(destination.to_owned()),
    }
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

/// bech32 with the original checksum, which is what the Cosmos SDK emits.
/// bech32m is rejected rather than tolerated: it is a different encoding, and
/// a string carrying it is not an address any Cosmos chain issued.
///
/// The HRP is returned lowercased. bech32 forbids mixed case, so an all-upper
/// string is the same address as its lowercase form, but the *prefix itself*
/// distinguishes roles on one key and is therefore part of what is compared.
fn cosmos_address(value: &str) -> Result<(String, Vec<u8>), DestinationError> {
    let parsed = CheckedHrpstring::new::<Bech32>(value)
        .map_err(|e| malformed(AddressFamily::Cosmos, e.to_string()))?;
    let payload: Vec<u8> = parsed.byte_iter().collect();
    if payload.is_empty() || payload.len() > COSMOS_MAX_PAYLOAD_BYTES {
        return Err(malformed(
            AddressFamily::Cosmos,
            format!(
                "expected 1-{COSMOS_MAX_PAYLOAD_BYTES} bytes, got {}",
                payload.len()
            ),
        ));
    }
    Ok((parsed.hrp().to_lowercase(), payload))
}

/// The output script the address pays to.
///
/// Bitcoin has no single address encoding: base58check covers P2PKH and P2SH,
/// bech32 covers segwit v0, and bech32m covers v1 taproot. They are not
/// interchangeable spellings of one identity the way EIP-55 case is — each
/// names a different script with different spending rules — so the script is
/// what gets compared and the address form is merely how it was written down.
fn bitcoin_script_pubkey(value: &str) -> Result<Vec<u8>, DestinationError> {
    // `segwit::decode` applies BIP-350 itself: v0 must carry a bech32
    // checksum, v1 and later bech32m, and the program length is checked
    // against the version. Falling through on failure keeps the base58 forms
    // reachable without having to sniff the encoding first.
    if let Ok((hrp, version, program)) = bech32::segwit::decode(value) {
        if hrp.to_lowercase() != BITCOIN_MAINNET_HRP {
            return Err(malformed(
                AddressFamily::Bitcoin,
                format!(
                    "expected a mainnet address (hrp \"{BITCOIN_MAINNET_HRP}\"), got \"{}\"",
                    hrp.to_lowercase()
                ),
            ));
        }
        // OP_0 is 0x00; versions 1..=16 are OP_1..OP_16 at 0x51..=0x60.
        let opcode = match version.to_u8() {
            0 => 0x00,
            v => 0x50 + v,
        };
        let mut script = Vec::with_capacity(2 + program.len());
        script.push(opcode);
        script.push(program.len() as u8);
        script.extend_from_slice(&program);
        return Ok(script);
    }

    let decoded = bs58::decode(value)
        .with_check(None)
        .into_vec()
        .map_err(|_| {
            malformed(
                AddressFamily::Bitcoin,
                "expected a mainnet bech32 (bc1…) or base58check address",
            )
        })?;
    let (version, hash) = decoded
        .split_first()
        .ok_or_else(|| malformed(AddressFamily::Bitcoin, "address payload is empty"))?;
    if hash.len() != 20 {
        return Err(malformed(
            AddressFamily::Bitcoin,
            format!("expected a 20-byte hash, got {}", hash.len()),
        ));
    }
    match *version {
        // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        BITCOIN_P2PKH_VERSION => Ok([&[0x76, 0xa9, 0x14], hash, &[0x88, 0xac]].concat()),
        // OP_HASH160 <20> OP_EQUAL
        BITCOIN_P2SH_VERSION => Ok([&[0xa9, 0x14], hash, &[0x87]].concat()),
        other => Err(malformed(
            AddressFamily::Bitcoin,
            format!("unknown mainnet address version byte {other:#04x}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// hash160 of the secp256k1 generator point, the BIP-173 test vector.
    const HASH160: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";

    fn chain(name: &str) -> Token {
        Token::new(name).expect("valid chain token")
    }

    fn parse(name: &str, destination: &str) -> PolicyTarget {
        parse_destination(&chain(name), destination).expect("destination decodes")
    }

    fn script(name: &str, destination: &str) -> String {
        match parse(name, destination) {
            PolicyTarget::Address(ChainAddress::Bitcoin { script_pubkey }) => {
                hex::encode(script_pubkey)
            }
            other => panic!("expected a Bitcoin script, got {other:?}"),
        }
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

    /// The Cosmos counterpart of the EVM case rule: bech32 forbids mixed case,
    /// so an all-uppercase string is the same address written differently.
    #[test]
    fn cosmos_case_is_only_spelling() {
        assert_eq!(
            parse("cosmos", "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c"),
            parse("cosmos", "COSMOS1W508D6QEJXTDG4Y5R3ZARVARY0C5XW7K6AH60C"),
        );
    }

    /// ...and the rule that pulls the other way. One key yields an account
    /// address and a validator operator address that differ *only* in prefix.
    /// They authorise different things, so comparing the payload alone would
    /// let a policy naming the account also permit the operator.
    #[test]
    fn cosmos_prefix_is_part_of_the_identity() {
        let account = parse("cosmos", "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c");
        let operator = parse(
            "cosmos",
            "cosmosvaloper1w508d6qejxtdg4y5r3zarvary0c5xw7klfr0rt",
        );
        assert_ne!(account, operator, "prefix distinguishes the two roles");
        let (
            PolicyTarget::Address(ChainAddress::Cosmos { payload: a, .. }),
            PolicyTarget::Address(ChainAddress::Cosmos { payload: b, .. }),
        ) = (&account, &operator)
        else {
            panic!("expected Cosmos addresses");
        };
        assert_eq!(a, b, "and they really are the same 20 bytes underneath");
    }

    /// Module and interchain accounts are 32 bytes rather than 20. Pinning the
    /// length to 20 would refuse them.
    #[test]
    fn cosmos_accepts_both_account_widths() {
        parse("osmosis", "osmo1w508d6qejxtdg4y5r3zarvary0c5xw7kjxy2e2");
        parse(
            "cosmos",
            "cosmos1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs5u086e",
        );
    }

    /// bech32m is a different encoding, not a lenient spelling of bech32. A
    /// Cosmos chain never issues one, and a corrupted checksum must not decode
    /// to *some* address.
    #[test]
    fn cosmos_rejects_bech32m_and_broken_checksums() {
        for bad in [
            // Valid bech32m, which no Cosmos chain emits.
            "abc14w46h2at4w46h2at4w46h2at4w46h2at958ngu",
            // One character of the payload changed.
            "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60d",
            "cosmos1",
            "not-bech32",
        ] {
            assert!(
                parse_destination(&chain("cosmos"), bad).is_err(),
                "{bad} must not decode"
            );
        }
    }

    /// The Bitcoin counterpart of the Cosmos prefix rule, and the reason this
    /// family compares scripts. One hash160 has a P2PKH spelling and a P2WPKH
    /// spelling; they spend under different rules and are not one destination.
    #[test]
    fn bitcoin_address_forms_over_one_hash_are_different_destinations() {
        let p2pkh = script("bitcoin", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        let p2wpkh = script("bitcoin", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(p2pkh, format!("76a914{HASH160}88ac"));
        assert_eq!(p2wpkh, format!("0014{HASH160}"));
        assert_ne!(p2pkh, p2wpkh);
    }

    #[test]
    fn bitcoin_covers_p2sh_and_taproot() {
        assert_eq!(
            script("bitcoin", "3CNHUhP3uyB9EUtRLsmvFUmvGdjGdkTxJw"),
            format!("a914{HASH160}87"),
        );
        assert_eq!(
            script(
                "bitcoin",
                "bc1py3m7vwnghyne9gnvcjw82j7gqt2rafgdmlmwmqnn3hvcmdm09rjqcgrtxs"
            ),
            "51202477e63a68b92792a26cc49c754bc802d43ea50ddff6ed82738dd98db76f28e4",
        );
    }

    /// A testnet address decodes perfectly well — that is exactly why it has
    /// to be refused here rather than left to look like a mainnet one.
    #[test]
    fn bitcoin_refuses_other_networks_on_the_mainnet_chain() {
        for bad in [
            // Same witness program as the mainnet vector above, on testnet.
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            // Same hash160 as the P2PKH vector above, testnet version byte.
            "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r",
        ] {
            assert!(
                parse_destination(&chain("bitcoin"), bad).is_err(),
                "{bad} must not decode on mainnet"
            );
        }
    }

    /// Bytes on one chain must never equal bytes on another.
    #[test]
    fn families_cannot_collide() {
        let targets = [
            ChainAddress::Solana([7; 32]),
            ChainAddress::Evm([7; 20]),
            ChainAddress::Cosmos {
                hrp: "cosmos".into(),
                payload: vec![7; 20],
            },
            ChainAddress::Bitcoin {
                script_pubkey: vec![7; 20],
            },
        ];
        for (i, a) in targets.iter().enumerate() {
            for b in &targets[i + 1..] {
                assert_ne!(
                    PolicyTarget::Address(a.clone()),
                    PolicyTarget::Address(b.clone())
                );
            }
        }
    }

    /// Two bech32 chains are two destinations even though the HRP alone would
    /// already tell them apart — `chain` stays the scoping key because HRPs
    /// are reused between a chain and its testnets.
    #[test]
    fn cosmos_chains_do_not_share_destinations() {
        assert_ne!(
            parse("osmosis", "osmo1w508d6qejxtdg4y5r3zarvary0c5xw7kjxy2e2"),
            parse(
                "celestia",
                "celestia1w508d6qejxtdg4y5r3zarvary0c5xw7kthx244"
            ),
        );
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

    /// Decoding widens what matches; it must never narrow it. Chains this
    /// build cannot decode, and placeholder spellings that are not addresses
    /// at all, have to keep comparing exactly as they did before.
    #[test]
    fn undecodable_entries_still_compare_by_exact_spelling() {
        for (chain_name, text) in [
            ("localnet", "whatever-this-is"),
            ("ethereum", "0xrecipient"),
        ] {
            let c = chain(chain_name);
            assert!(matches!(comparable(&c, text), Comparable::Literal(_)));
            assert_eq!(comparable(&c, text), comparable(&c, text));
            assert_ne!(comparable(&c, text), comparable(&c, "something-else"));
        }
    }

    /// The two rules that pull opposite ways, stated against the value the
    /// Broker actually compares.
    #[test]
    fn comparable_follows_each_chain_case_rule() {
        let eth = chain("ethereum");
        assert_eq!(
            comparable(&eth, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            comparable(&eth, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
            "EIP-55 case is a checksum, not an address"
        );

        // Both of these are valid 32-byte Solana addresses; they differ only
        // in case, and they are two different accounts.
        let sol = chain("solana");
        let mixed = "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8";
        let lower = "cktruq2mttgrgkxjtyksdkhjudc2c4tgdzyb98oezy8";
        assert!(matches!(comparable(&sol, mixed), Comparable::Decoded(_)));
        assert!(matches!(comparable(&sol, lower), Comparable::Decoded(_)));
        assert_ne!(
            comparable(&sol, mixed),
            comparable(&sol, lower),
            "base58 case is data, so lowercasing names a different account"
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
    fn display_round_trips_each_decodable_spelling() {
        for (chain_name, text) in [
            ("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
            ("solana", "11111111111111111111111111111111"),
            ("cosmos", "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c"),
            ("base", "petal:near-intents"),
        ] {
            assert_eq!(parse(chain_name, text).to_string(), text);
        }
    }

    /// Bitcoin is the exception: the decoded identity is a script, and showing
    /// it is more use in a diagnostic than echoing back whichever of the four
    /// address forms happened to be written.
    #[test]
    fn display_shows_the_bitcoin_script() {
        assert_eq!(
            parse("bitcoin", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").to_string(),
            format!("script:0014{HASH160}"),
        );
    }
}
