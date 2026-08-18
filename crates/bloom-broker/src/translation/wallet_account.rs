//! Wallet-seed and derived-account translations at the Broker boundary.
//!
//! Two invariants are enforced here and must survive every change:
//!
//! 1. **Path templates are descriptive only.** Machine callers select a
//!    registered derivation profile and account role; no function in this
//!    module accepts a derivation path from the north edge. The `path` on
//!    `DerivedAccountPublic` is a projection cloned from the Signer-owned
//!    registry descriptor and is never caller input.
//! 2. **Broker constructs chain projections from key bytes.** Addresses and
//!    CAIP-10 identifiers are recomputed from the descriptor's canonical
//!    public-key bytes. Supplied strings are never trusted:
//!    [`verify_chain_projection`] recomputes the address and requires that
//!    CAIP-10 embeds the exact CAIP-2 and the exact encoded address.
//!
//! No Signer type is re-exported across this boundary; every value is
//! translated explicitly in both directions.

use bloom_broker_api as north;
use bloom_signer_api as south;

use sha2::Digest as _;
use sha3::Keccak256;

/// Canonical SPKI DER prefix for an uncompressed secp256k1 public key
/// (`id-ecPublicKey` / `secp256k1`, 65-byte `0x04 || x || y` point).
const SECP256K1_SPKI_PREFIX: [u8; 23] = [
    0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
];

/// Canonical SPKI DER prefix for a raw Ed25519 public key (RFC 8410
/// `id-Ed25519`, 32-byte key).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// One configured chain projection target. `caip2` and the accepted
/// derivation profile come from Broker's configured network profile, never
/// from Machine input. A descriptor whose profile differs from the target
/// fails closed instead of projecting a mismatched address onto the chain.
#[derive(Clone)]
pub(crate) struct ChainProjectionTarget<'a> {
    pub chain_family: north::Token,
    pub caip2: &'a str,
    pub accepted_profile: south::DerivationProfile,
}

pub(crate) fn wallet_seed_profile_to_machine(
    value: south::WalletSeedProfile,
) -> north::WalletSeedProfile {
    match value {
        south::WalletSeedProfile::Bip39MulticurveV1 => north::WalletSeedProfile::Bip39MulticurveV1,
        south::WalletSeedProfile::ImportedSecp256k1Scalar => {
            north::WalletSeedProfile::ImportedSecp256k1Scalar
        }
    }
}

// The three north→south helpers below complete the translation surface but
// have no production caller in Broker yet: Machine never sends descriptors
// or address projections south. They are exercised by the round-trip and
// tamper tests and become live with the deferred import/recovery Broker
// ceremonies.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn derivation_profile_to_signer(
    value: north::DerivationProfile,
) -> south::DerivationProfile {
    match value {
        north::DerivationProfile::Bip44EvmSecp256k1V1 => {
            south::DerivationProfile::Bip44EvmSecp256k1V1
        }
        north::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
            south::DerivationProfile::Bip44SolanaSlip10Ed25519V1
        }
    }
}

pub(crate) fn derivation_profile_to_machine(
    value: south::DerivationProfile,
) -> north::DerivationProfile {
    match value {
        south::DerivationProfile::Bip44EvmSecp256k1V1 => {
            north::DerivationProfile::Bip44EvmSecp256k1V1
        }
        south::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
            north::DerivationProfile::Bip44SolanaSlip10Ed25519V1
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn public_key_encoding_to_signer(
    value: north::PublicKeyEncoding,
) -> south::PublicKeyEncoding {
    match value {
        north::PublicKeyEncoding::Secp256k1SpkiDer => south::PublicKeyEncoding::Secp256k1SpkiDer,
        north::PublicKeyEncoding::Ed25519SpkiDer => south::PublicKeyEncoding::Ed25519SpkiDer,
    }
}

pub(crate) fn public_key_encoding_to_machine(
    value: south::PublicKeyEncoding,
) -> north::PublicKeyEncoding {
    match value {
        south::PublicKeyEncoding::Secp256k1SpkiDer => north::PublicKeyEncoding::Secp256k1SpkiDer,
        south::PublicKeyEncoding::Ed25519SpkiDer => north::PublicKeyEncoding::Ed25519SpkiDer,
    }
}

/// Strictly parse canonical uncompressed secp256k1 SPKI DER (88 bytes).
pub(crate) fn secp256k1_uncompressed_point(spki: &[u8]) -> Result<[u8; 65], north::ProtocolError> {
    if spki.len() != 88 || spki[..SECP256K1_SPKI_PREFIX.len()] != SECP256K1_SPKI_PREFIX {
        return Err(invalid("public key is not canonical secp256k1 SPKI DER"));
    }
    let mut point = [0u8; 65];
    point.copy_from_slice(&spki[23..88]);
    if point[0] != 0x04 {
        return Err(invalid(
            "secp256k1 point must be uncompressed 0x04 || x || y",
        ));
    }
    Ok(point)
}

/// Strictly parse canonical Ed25519 SPKI DER (44 bytes).
pub(crate) fn ed25519_raw_key(spki: &[u8]) -> Result<[u8; 32], north::ProtocolError> {
    if spki.len() != 44 || spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(invalid("public key is not canonical Ed25519 SPKI DER"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&spki[12..44]);
    Ok(key)
}

/// EVM address: the low 20 bytes of keccak256(x || y), lowercase `0x` hex.
fn derive_evm_address(spki: &[u8]) -> Result<String, north::ProtocolError> {
    let point = secp256k1_uncompressed_point(spki)?;
    let mut hasher = Keccak256::new();
    hasher.update(&point[1..33]);
    hasher.update(&point[33..65]);
    let digest = hasher.finalize();
    Ok(format!("0x{}", hex::encode(&digest[12..32])))
}

/// Solana address: base58 (Bitcoin alphabet) of the raw 32-byte Ed25519 key.
fn derive_solana_address(spki: &[u8]) -> Result<String, north::ProtocolError> {
    let key = ed25519_raw_key(spki)?;
    Ok(base58_encode(&key))
}

pub(crate) fn base58_encode(input: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 2);
    for &byte in input {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut encoded = String::with_capacity(digits.len() + input.len());
    for &byte in input {
        if byte == 0 {
            encoded.push('1');
        } else {
            break;
        }
    }
    for &digit in digits.iter().rev() {
        encoded.push(BASE58_ALPHABET[usize::from(digit)] as char);
    }
    encoded
}

/// Recompute an address and encoding for a derivation profile from the
/// canonical public-key bytes.
fn recompute_address(
    profile: south::DerivationProfile,
    canonical_public_key: &[u8],
) -> Result<(String, north::AddressEncoding), north::ProtocolError> {
    match profile {
        south::DerivationProfile::Bip44EvmSecp256k1V1 => Ok((
            derive_evm_address(canonical_public_key)?,
            north::AddressEncoding::Hex0x,
        )),
        south::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => Ok((
            derive_solana_address(canonical_public_key)?,
            north::AddressEncoding::Base58,
        )),
    }
}

/// Construct one chain projection by recomputing the address from key bytes.
/// The CAIP-10 identifier is assembled as `caip2:address`, never accepted.
pub(crate) fn chain_projection_from_key_bytes(
    profile: south::DerivationProfile,
    canonical_public_key: &[u8],
    chain_family: north::Token,
    caip2: &str,
) -> Result<north::ChainAccountProjection, north::ProtocolError> {
    let (address, address_encoding) = recompute_address(profile, canonical_public_key)?;
    let projection = north::ChainAccountProjection {
        chain_family,
        caip2: caip2.to_owned(),
        caip10: format!("{caip2}:{address}"),
        address,
        address_encoding,
    };
    projection.validate()?;
    Ok(projection)
}

/// Verify a supplied projection against the canonical public-key bytes:
/// recompute the address, require the exact encoding, and require that
/// CAIP-10 embeds the exact CAIP-2 and encoded address.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_chain_projection(
    projection: &north::ChainAccountProjection,
    profile: south::DerivationProfile,
    canonical_public_key: &[u8],
) -> Result<(), north::ProtocolError> {
    let (address, encoding) = recompute_address(profile, canonical_public_key)?;
    if projection.address != address {
        return Err(invalid(
            "chain projection address does not match the public key",
        ));
    }
    if projection.address_encoding != encoding {
        return Err(invalid(
            "chain projection address encoding is wrong for the profile",
        ));
    }
    if projection.caip10 != format!("{}:{}", projection.caip2, address) {
        return Err(invalid(
            "caip10 must embed the exact caip2 and encoded address",
        ));
    }
    projection.validate()
}

/// Translate a Signer registry descriptor into the Machine-facing projection.
///
/// Chain projections are constructed from key bytes for each configured
/// target whose accepted profile matches the descriptor; a mismatched target
/// is a hard error. The descriptor fingerprint is verified against SHA-256
/// of the canonical public key before anything is projected.
pub(crate) fn derived_account_to_machine(
    descriptor: &south::DerivedAccountDescriptor,
    targets: &[ChainProjectionTarget<'_>],
) -> Result<north::DerivedAccountPublic, north::ProtocolError> {
    for target in targets {
        if target.accepted_profile != descriptor.derivation_profile {
            return Err(invalid(
                "chain target derivation profile does not match the account",
            ));
        }
    }
    let canonical_public_key = descriptor.canonical_public_key.decode();
    let computed_fingerprint =
        north::Digest32::from_bytes(sha2::Sha256::digest(&canonical_public_key).into());
    if computed_fingerprint != descriptor.public_key_fingerprint {
        return Err(invalid(
            "descriptor public key fingerprint does not match its canonical bytes",
        ));
    }
    let mut chain_projections = Vec::with_capacity(targets.len());
    for target in targets {
        chain_projections.push(chain_projection_from_key_bytes(
            descriptor.derivation_profile,
            &canonical_public_key,
            target.chain_family.clone(),
            target.caip2,
        )?);
    }
    let account = north::DerivedAccountPublic {
        key_ref: super::key::key_ref_to_machine(descriptor.key_ref.clone()),
        wallet_seed_profile: wallet_seed_profile_to_machine(descriptor.wallet_seed_ref.profile),
        derivation_profile: derivation_profile_to_machine(descriptor.derivation_profile),
        path: descriptor.path.clone(),
        canonical_public_key: descriptor.canonical_public_key.clone(),
        public_key_encoding: public_key_encoding_to_machine(descriptor.public_key_encoding),
        public_key_fingerprint: descriptor.public_key_fingerprint.clone(),
        supported_crypto_suites: descriptor
            .supported_crypto_suites
            .iter()
            .map(|suite| super::key::crypto_suite_to_machine(*suite))
            .collect(),
        chain_projections,
        // The descriptor carries no lifecycle yet; retire operations extend
        // this mapping when they are implemented.
        lifecycle: north::AccountLifecycleState::Active,
    };
    account.validate()?;
    Ok(account)
}

/// Assemble the Machine-facing wallet account collection from Signer
/// descriptors. Each descriptor projects onto the targets whose declared
/// profile matches it; no account is ever projected onto a mismatched chain.
pub(crate) fn wallet_accounts_to_machine(
    wallet_id: north::Token,
    profile: south::WalletSeedProfile,
    descriptors: &[south::DerivedAccountDescriptor],
    targets: &[ChainProjectionTarget<'_>],
) -> Result<north::WalletAccountsPublic, north::ProtocolError> {
    let accounts = descriptors
        .iter()
        .map(|descriptor| {
            let matching: Vec<ChainProjectionTarget<'_>> = targets
                .iter()
                .filter(|target| target.accepted_profile == descriptor.derivation_profile)
                .cloned()
                .collect();
            derived_account_to_machine(descriptor, &matching)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let collection = north::WalletAccountsPublic {
        wallet_id,
        seed_profile: wallet_seed_profile_to_machine(profile),
        accounts,
    };
    collection.validate()?;
    Ok(collection)
}

/// The production chain projection targets. EVM mainnet and Solana mainnet
/// are the only configured families for `bip39-multicurve-v1`; a descriptor
/// of any other profile fails closed at projection time.
pub(crate) fn production_chain_targets() -> [ChainProjectionTarget<'static>; 2] {
    [
        ChainProjectionTarget {
            chain_family: north::Token::new("evm").expect("static token"),
            caip2: "eip155:1",
            accepted_profile: south::DerivationProfile::Bip44EvmSecp256k1V1,
        },
        ChainProjectionTarget {
            chain_family: north::Token::new("solana").expect("static token"),
            caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            accepted_profile: south::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
        },
    ]
}

fn invalid(message: impl Into<String>) -> north::ProtocolError {
    north::ProtocolError::new(north::ProtocolErrorCode::KeyrefMismatch, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_signer_vectors as vectors;

    fn token(value: &str) -> north::Token {
        north::Token::new(value).unwrap()
    }

    fn digest32(hex_value: &str) -> south::Digest32 {
        south::Digest32::from_bytes(hex::decode(hex_value).unwrap().try_into().unwrap())
    }

    fn spki(hex_value: &str) -> north::Base64UrlBytes {
        let bytes = hex::decode(hex_value).unwrap();
        north::Base64UrlBytes::from_bytes(&bytes)
    }

    fn evm_descriptor() -> south::DerivedAccountDescriptor {
        south::DerivedAccountDescriptor {
            key_ref: south::KeyRef {
                backend: south::Token::new("local").unwrap(),
                backend_instance: south::Token::new("local-default").unwrap(),
                locator: "wallet/primary/child-evm-0".into(),
                key_spec: south::KeySpec::Secp256k1,
                public_key_fingerprint: digest32(
                    vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
                ),
                derivation: Some(south::DerivationRef::Bip32Secp256k1 {
                    root_key_id: south::Token::new("primary-root").unwrap(),
                    path: vectors::BIP32_EVM_PATH.into(),
                }),
            },
            wallet_seed_ref: south::WalletSeedRef {
                wallet_id: south::Token::new("primary").unwrap(),
                profile: south::WalletSeedProfile::Bip39MulticurveV1,
                entropy_bits: 256,
            },
            derivation_profile: south::DerivationProfile::Bip44EvmSecp256k1V1,
            path: vectors::BIP32_EVM_PATH.into(),
            canonical_public_key: spki(vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX),
            public_key_encoding: south::PublicKeyEncoding::Secp256k1SpkiDer,
            public_key_fingerprint: digest32(
                vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
            ),
            supported_crypto_suites: vec![south::CryptoSuite::Secp256k1Keccak256Recoverable],
            lifecycle: south::AccountLifecycleState::Active,
        }
    }

    fn solana_descriptor() -> south::DerivedAccountDescriptor {
        south::DerivedAccountDescriptor {
            key_ref: south::KeyRef {
                backend: south::Token::new("local").unwrap(),
                backend_instance: south::Token::new("local-default").unwrap(),
                locator: "wallet/primary/child-sol-0".into(),
                key_spec: south::KeySpec::Ed25519,
                public_key_fingerprint: digest32(
                    vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
                ),
                derivation: None,
            },
            wallet_seed_ref: south::WalletSeedRef {
                wallet_id: south::Token::new("primary").unwrap(),
                profile: south::WalletSeedProfile::Bip39MulticurveV1,
                entropy_bits: 256,
            },
            derivation_profile: south::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            path: vectors::SLIP10_SOLANA_PATH.into(),
            canonical_public_key: spki(vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX),
            public_key_encoding: south::PublicKeyEncoding::Ed25519SpkiDer,
            public_key_fingerprint: digest32(
                vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
            ),
            supported_crypto_suites: vec![south::CryptoSuite::Ed25519Message],
            lifecycle: south::AccountLifecycleState::Active,
        }
    }

    const EVM_MAINNET_CAIP2: &str = "eip155:1";
    const SOLANA_MAINNET_CAIP2: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    const EVM_MAINNET_ADDRESS: &str = "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb";
    const SOLANA_MAINNET_ADDRESS: &str = "3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx";

    fn evm_target() -> ChainProjectionTarget<'static> {
        ChainProjectionTarget {
            chain_family: token("evm"),
            caip2: EVM_MAINNET_CAIP2,
            accepted_profile: south::DerivationProfile::Bip44EvmSecp256k1V1,
        }
    }

    fn solana_target() -> ChainProjectionTarget<'static> {
        ChainProjectionTarget {
            chain_family: token("solana"),
            caip2: SOLANA_MAINNET_CAIP2,
            accepted_profile: south::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
        }
    }

    #[test]
    fn enum_translations_are_exhaustive_round_trips() {
        for profile in north::DerivationProfile::ALL {
            assert_eq!(
                derivation_profile_to_machine(derivation_profile_to_signer(profile)),
                profile
            );
        }
        // The south edge carries exactly one seed profile; the legacy root
        // exists only on the north edge and maps to a `None` south selection
        // (asserted in the custody translation tests).
        assert_eq!(
            wallet_seed_profile_to_machine(south::WalletSeedProfile::Bip39MulticurveV1),
            north::WalletSeedProfile::Bip39MulticurveV1
        );
        for encoding in [
            north::PublicKeyEncoding::Secp256k1SpkiDer,
            north::PublicKeyEncoding::Ed25519SpkiDer,
        ] {
            assert_eq!(
                public_key_encoding_to_machine(public_key_encoding_to_signer(encoding)),
                encoding
            );
        }
    }

    #[test]
    fn frozen_vectors_project_to_exact_addresses() {
        let evm = derived_account_to_machine(&evm_descriptor(), &[evm_target()]).unwrap();
        assert_eq!(evm.chain_projections.len(), 1);
        let projection = &evm.chain_projections[0];
        assert_eq!(projection.caip2, EVM_MAINNET_CAIP2);
        assert_eq!(projection.address, EVM_MAINNET_ADDRESS);
        assert_eq!(projection.address_encoding, north::AddressEncoding::Hex0x);
        assert_eq!(
            projection.caip10,
            format!("{EVM_MAINNET_CAIP2}:{EVM_MAINNET_ADDRESS}")
        );

        let solana = derived_account_to_machine(&solana_descriptor(), &[solana_target()]).unwrap();
        let projection = &solana.chain_projections[0];
        assert_eq!(projection.address, SOLANA_MAINNET_ADDRESS);
        assert_eq!(projection.address_encoding, north::AddressEncoding::Base58);
        assert_eq!(
            projection.caip10,
            format!("{SOLANA_MAINNET_CAIP2}:{SOLANA_MAINNET_ADDRESS}")
        );

        let collection = wallet_accounts_to_machine(
            token("primary"),
            south::WalletSeedProfile::Bip39MulticurveV1,
            &[evm_descriptor(), solana_descriptor()],
            &[evm_target(), solana_target()],
        )
        .unwrap();
        assert_eq!(collection.accounts.len(), 2);
        assert_eq!(collection.accounts[0].chain_projections.len(), 1);
        assert_eq!(collection.accounts[1].chain_projections.len(), 1);
    }

    #[test]
    fn cross_family_targets_fail_closed() {
        // An EVM descriptor can never project onto the Solana chain family.
        assert!(derived_account_to_machine(&evm_descriptor(), &[solana_target()]).is_err());
        // And the symmetric case.
        assert!(derived_account_to_machine(&solana_descriptor(), &[evm_target()]).is_err());
    }

    #[test]
    fn supplied_projections_are_verified_not_trusted() {
        let descriptor = evm_descriptor();
        let key = descriptor.canonical_public_key.decode();
        let good = chain_projection_from_key_bytes(
            south::DerivationProfile::Bip44EvmSecp256k1V1,
            &key,
            token("evm"),
            EVM_MAINNET_CAIP2,
        )
        .unwrap();
        assert!(
            verify_chain_projection(&good, south::DerivationProfile::Bip44EvmSecp256k1V1, &key)
                .is_ok()
        );

        let mut tampered_address = good.clone();
        tampered_address.address = "0x0000000000000000000000000000000000000000".into();
        assert!(
            verify_chain_projection(
                &tampered_address,
                south::DerivationProfile::Bip44EvmSecp256k1V1,
                &key
            )
            .is_err()
        );

        let mut tampered_caip10 = good.clone();
        tampered_caip10.caip10 = format!("eip155:137:{}", tampered_caip10.address);
        assert!(
            verify_chain_projection(
                &tampered_caip10,
                south::DerivationProfile::Bip44EvmSecp256k1V1,
                &key
            )
            .is_err()
        );

        let mut wrong_encoding = good.clone();
        wrong_encoding.address_encoding = north::AddressEncoding::Base58;
        assert!(
            verify_chain_projection(
                &wrong_encoding,
                south::DerivationProfile::Bip44EvmSecp256k1V1,
                &key
            )
            .is_err()
        );
    }

    #[test]
    fn descriptor_fingerprint_mismatch_is_rejected() {
        let mut descriptor = evm_descriptor();
        descriptor.public_key_fingerprint = south::Digest32::from_bytes([0x11; 32]);
        assert!(derived_account_to_machine(&descriptor, &[]).is_err());
    }

    #[test]
    fn noncanonical_spki_is_rejected() {
        // Wrong length: compressed-point splice cannot pass the 88-byte form.
        let compressed = [&SECP256K1_SPKI_PREFIX[..], &[0x02], &[0u8; 32]].concat();
        assert!(secp256k1_uncompressed_point(&compressed).is_err());

        // Trailing byte appended to valid Ed25519 SPKI.
        let mut ed = hex::decode(vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX).unwrap();
        ed.push(0x00);
        assert!(ed25519_raw_key(&ed).is_err());

        // Empty bytes never parse.
        assert!(secp256k1_uncompressed_point(&[]).is_err());
        assert!(ed25519_raw_key(&[]).is_err());
    }

    #[test]
    fn base58_matches_reference_vectors() {
        assert_eq!(base58_encode(&[0]), "1");
        assert_eq!(base58_encode(&[0, 0]), "11");
        assert_eq!(base58_encode(&[1]), "2");
        assert_eq!(base58_encode(&[255]), "5Q");
        assert_eq!(base58_encode(b"hello world"), "StV1DL6CwTryKyV");
    }

    /// Differential gate: the hand-rolled encoder must agree with the
    /// independent `bs58` crate across edge shapes — empty input, every
    /// leading-zero pattern up to a full all-zero Ed25519 key, and random
    /// payloads of random lengths. Self-consistent vectors are not
    /// sufficient evidence for a hand-rolled encoder.
    #[test]
    fn base58_differentials_against_independent_bs58() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0],
            vec![0, 0],
            vec![0, 0, 0],
            vec![1],
            vec![255],
            b"hello world".to_vec(),
            vec![0, 1, 2, 3, 250, 251, 252],
            vec![7, 0, 1, 2],
            [0u8; 32].to_vec(),
            [[0u8; 31].as_slice(), &[7u8]].concat(),
        ];
        for _ in 0..512 {
            let len = rng.gen_range(0..64);
            cases.push((0..len).map(|_| rng.r#gen::<u8>()).collect());
        }
        for _ in 0..128 {
            let zeros = rng.gen_range(0..12);
            let tail: Vec<u8> = (0..rng.gen_range(0..40))
                .map(|_| rng.r#gen::<u8>())
                .collect();
            cases.push([vec![0u8; zeros], tail].concat());
        }
        for case in &cases {
            assert_eq!(
                base58_encode(case),
                bs58::encode(case).into_string(),
                "encoder disagreement for input {case:?}"
            );
        }
    }
}
