//! Machine-facing derived-account projections.
//!
//! These DTOs are the north-side edge contract. Broker derives them from
//! Signer's chain-agnostic `DerivedAccountDescriptor` and adds the chain
//! projections — addresses, CAIP identifiers, network families — that Signer
//! deliberately does not own. Signer types are never re-exported across this
//! boundary; Broker translates explicitly.

use serde::{Deserialize, Serialize};

use crate::{
    Base64UrlBytes, CryptoSuite, Digest32, KeyRef, ProtocolError, ProtocolErrorCode, Token,
};

/// Root seed profile mirrored for Machine presentation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletSeedProfile {
    Bip39MulticurveV1,
}

/// Derivation profile mirrored for Machine presentation. The path template is
/// frozen per profile and never changes silently.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DerivationProfile {
    Bip44EvmSecp256k1V1,
    Bip44SolanaSlip10Ed25519V1,
}

impl DerivationProfile {
    pub const ALL: [Self; 2] = [Self::Bip44EvmSecp256k1V1, Self::Bip44SolanaSlip10Ed25519V1];

    pub const fn path_template(self) -> &'static str {
        match self {
            Self::Bip44EvmSecp256k1V1 => "m/44'/60'/<account>'/0/<index>",
            Self::Bip44SolanaSlip10Ed25519V1 => "m/44'/501'/<account>'/0'",
        }
    }

    pub const fn key_spec(self) -> crate::KeySpec {
        match self {
            Self::Bip44EvmSecp256k1V1 => crate::KeySpec::Secp256k1,
            Self::Bip44SolanaSlip10Ed25519V1 => crate::KeySpec::Ed25519,
        }
    }
}

/// Explicit encoding of `canonical_public_key` bytes, mirrored from the
/// Signer-owned registry entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicKeyEncoding {
    Secp256k1SpkiDer,
    Ed25519SpkiDer,
}

impl PublicKeyEncoding {
    pub const fn key_spec(self) -> crate::KeySpec {
        match self {
            Self::Secp256k1SpkiDer => crate::KeySpec::Secp256k1,
            Self::Ed25519SpkiDer => crate::KeySpec::Ed25519,
        }
    }
}

/// Explicit encoding of a projected chain address. Consumers must never
/// infer the encoding from the address string.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressEncoding {
    Hex0x,
    Base58,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AccountLifecycleState {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "RETIRED")]
    Retired,
}

const CAIP2_MAX_BYTES: usize = 64;
const CAIP10_MAX_BYTES: usize = 128;
const ADDRESS_MAX_BYTES: usize = 128;
const CHAIN_PROJECTION_MAX_COUNT: usize = 16;
const ACCOUNT_MAX_COUNT: usize = 256;

/// One chain projection of a derived account. `caip2` names the chain (for
/// example `eip155:1` or `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`), `caip10`
/// is the full CAIP-10 account identifier, and `address` is the human-readable
/// form in the stated encoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainAccountProjection {
    pub chain_family: Token,
    pub caip2: String,
    pub caip10: String,
    pub address: String,
    pub address_encoding: AddressEncoding,
}

impl<'de> Deserialize<'de> for ChainAccountProjection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            chain_family: Token,
            caip2: String,
            caip10: String,
            address: String,
            address_encoding: AddressEncoding,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        let projection = Self {
            chain_family: unchecked.chain_family,
            caip2: unchecked.caip2,
            caip10: unchecked.caip10,
            address: unchecked.address,
            address_encoding: unchecked.address_encoding,
        };
        projection.validate().map_err(serde::de::Error::custom)?;
        Ok(projection)
    }
}

impl ChainAccountProjection {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_caip2(&self.caip2)?;
        validate_bounded("caip10", &self.caip10, CAIP10_MAX_BYTES)?;
        validate_bounded("address", &self.address, ADDRESS_MAX_BYTES)?;
        Ok(())
    }
}

/// Machine-facing projection of one registered derived account. The chain
/// projections are Broker-derived facts; Signer supplies only the
/// chain-agnostic key material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedAccountPublic {
    pub key_ref: KeyRef,
    pub wallet_seed_profile: WalletSeedProfile,
    pub derivation_profile: DerivationProfile,
    pub path: String,
    pub canonical_public_key: Base64UrlBytes,
    pub public_key_encoding: PublicKeyEncoding,
    pub public_key_fingerprint: Digest32,
    pub supported_crypto_suites: Vec<CryptoSuite>,
    pub chain_projections: Vec<ChainAccountProjection>,
    pub lifecycle: AccountLifecycleState,
}

impl<'de> Deserialize<'de> for DerivedAccountPublic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            key_ref: KeyRef,
            wallet_seed_profile: WalletSeedProfile,
            derivation_profile: DerivationProfile,
            path: String,
            canonical_public_key: Base64UrlBytes,
            public_key_encoding: PublicKeyEncoding,
            public_key_fingerprint: Digest32,
            supported_crypto_suites: Vec<CryptoSuite>,
            chain_projections: Vec<ChainAccountProjection>,
            lifecycle: AccountLifecycleState,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        let account = Self {
            key_ref: unchecked.key_ref,
            wallet_seed_profile: unchecked.wallet_seed_profile,
            derivation_profile: unchecked.derivation_profile,
            path: unchecked.path,
            canonical_public_key: unchecked.canonical_public_key,
            public_key_encoding: unchecked.public_key_encoding,
            public_key_fingerprint: unchecked.public_key_fingerprint,
            supported_crypto_suites: unchecked.supported_crypto_suites,
            chain_projections: unchecked.chain_projections,
            lifecycle: unchecked.lifecycle,
        };
        account.validate().map_err(serde::de::Error::custom)?;
        Ok(account)
    }
}

impl DerivedAccountPublic {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.key_ref.validate()?;
        if self.key_ref.key_spec != self.derivation_profile.key_spec() {
            return Err(invalid("derivation profile curve does not match the KeyRef"));
        }
        if self.public_key_encoding.key_spec() != self.key_ref.key_spec {
            return Err(invalid("public-key encoding does not match the KeyRef"));
        }
        if self.canonical_public_key.decode().is_empty() {
            return Err(invalid("canonical public key must not be empty"));
        }
        let unique_suites: std::collections::HashSet<_> =
            self.supported_crypto_suites.iter().copied().collect();
        if self.supported_crypto_suites.is_empty()
            || self.supported_crypto_suites.len() > CryptoSuite::ALL.len()
            || unique_suites.len() != self.supported_crypto_suites.len()
            || self
                .supported_crypto_suites
                .iter()
                .any(|suite| suite.key_spec() != self.key_ref.key_spec)
        {
            return Err(invalid(
                "supported crypto suites must be unique and match the KeyRef",
            ));
        }
        if self.chain_projections.len() > CHAIN_PROJECTION_MAX_COUNT {
            return Err(invalid("too many chain projections"));
        }
        let mut seen = std::collections::HashSet::new();
        for projection in &self.chain_projections {
            projection.validate()?;
            if !seen.insert((
                projection.chain_family.as_str().to_owned(),
                projection.caip2.clone(),
            )) {
                return Err(invalid("chain projections must be unique per chain"));
            }
        }
        Ok(())
    }
}

/// The public account collection Machine sees for one wallet. The seed root
/// itself is not signable and is never listed as an account.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAccountsPublic {
    pub wallet_id: Token,
    pub seed_profile: WalletSeedProfile,
    pub accounts: Vec<DerivedAccountPublic>,
}

impl<'de> Deserialize<'de> for WalletAccountsPublic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            wallet_id: Token,
            seed_profile: WalletSeedProfile,
            accounts: Vec<DerivedAccountPublic>,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        let collection = Self {
            wallet_id: unchecked.wallet_id,
            seed_profile: unchecked.seed_profile,
            accounts: unchecked.accounts,
        };
        collection.validate().map_err(serde::de::Error::custom)?;
        Ok(collection)
    }
}

impl WalletAccountsPublic {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.accounts.len() > ACCOUNT_MAX_COUNT {
            return Err(invalid("too many accounts"));
        }
        let mut locators = std::collections::HashSet::new();
        for account in &self.accounts {
            account.validate()?;
            if account.wallet_seed_profile != self.seed_profile {
                return Err(invalid("account seed profile does not match the wallet"));
            }
            if !locators.insert(account.key_ref.locator.clone()) {
                return Err(invalid("account KeyRef locators must be unique"));
            }
        }
        Ok(())
    }
}

fn validate_caip2(value: &str) -> Result<(), ProtocolError> {
    validate_bounded("caip2", value, CAIP2_MAX_BYTES)?;
    let (namespace, reference) = value
        .split_once(':')
        .ok_or_else(|| invalid("caip2 must be namespace:reference"))?;
    if namespace.is_empty()
        || reference.is_empty()
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(invalid("caip2 namespace must be lowercase ascii"));
    }
    Ok(())
}

fn validate_bounded(field: &str, value: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(|character| character.is_control())
    {
        return Err(invalid(format!(
            "{field} must contain 1-{maximum} UTF-8 bytes without control characters"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::KeyrefMismatch, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DerivationRef;

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn key_ref(key_spec: crate::KeySpec, locator: &str) -> KeyRef {
        KeyRef {
            backend: token("local"),
            backend_instance: token("local-default"),
            locator: locator.into(),
            key_spec,
            public_key_fingerprint: digest(7),
            derivation: match key_spec {
                crate::KeySpec::Secp256k1 => Some(DerivationRef::Bip32Secp256k1 {
                    root_key_id: token("primary-root"),
                    path: "m/44'/60'/0'/0/0".into(),
                }),
                crate::KeySpec::Ed25519 => None,
            },
        }
    }

    fn projection(chain_family: &str, caip2: &str, caip10: &str, address: &str) -> ChainAccountProjection {
        ChainAccountProjection {
            chain_family: token(chain_family),
            caip2: caip2.into(),
            caip10: caip10.into(),
            address: address.into(),
            address_encoding: AddressEncoding::Hex0x,
        }
    }

    fn account(
        profile: DerivationProfile,
        key_spec: crate::KeySpec,
        path: &str,
        projections: Vec<ChainAccountProjection>,
    ) -> DerivedAccountPublic {
        let locator = match key_spec {
            crate::KeySpec::Secp256k1 => "wallet/primary/child-evm-0",
            crate::KeySpec::Ed25519 => "wallet/primary/child-sol-0",
        };
        let (encoding, public_key) = match key_spec {
            crate::KeySpec::Secp256k1 => (PublicKeyEncoding::Secp256k1SpkiDer, vec![2u8; 88]),
            crate::KeySpec::Ed25519 => (PublicKeyEncoding::Ed25519SpkiDer, vec![3u8; 44]),
        };
        DerivedAccountPublic {
            key_ref: key_ref(key_spec, locator),
            wallet_seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            derivation_profile: profile,
            path: path.into(),
            canonical_public_key: Base64UrlBytes::from_bytes(&public_key),
            public_key_encoding: encoding,
            public_key_fingerprint: digest(9),
            supported_crypto_suites: match key_spec {
                crate::KeySpec::Secp256k1 => vec![CryptoSuite::Secp256k1Keccak256Recoverable],
                crate::KeySpec::Ed25519 => vec![CryptoSuite::Ed25519Message],
            },
            chain_projections: projections,
            lifecycle: AccountLifecycleState::Active,
        }
    }

    #[test]
    fn canonical_accounts_validate() {
        let evm = account(
            DerivationProfile::Bip44EvmSecp256k1V1,
            crate::KeySpec::Secp256k1,
            "m/44'/60'/0'/0/0",
            vec![projection(
                "evm",
                "eip155:1",
                "eip155:1:0x8320a0e0a3e4c1e6e8ee2ee2ee2ee2ee2ee2ee2e",
                "0x8320a0e0a3e4c1e6e8ee2ee2ee2ee2ee2ee2ee2e",
            )],
        );
        assert!(evm.validate().is_ok());

        let solana = account(
            DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            crate::KeySpec::Ed25519,
            "m/44'/501'/0'/0'",
            vec![projection(
                "solana",
                "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:EVjSDh7ZcybLGMhEQxCzLz4hdNQWkT8tPFjHCLAbNBYd",
                "EVjSDh7ZcybLGMhEQxCzLz4hdNQWkT8tPFjHCLAbNBYd",
            )],
        );
        let mut solana = solana;
        if let Some(first) = solana.chain_projections.first_mut() {
            first.address_encoding = AddressEncoding::Base58;
        }
        assert!(solana.validate().is_ok());

        let collection = WalletAccountsPublic {
            wallet_id: token("primary"),
            seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            accounts: vec![evm, solana],
        };
        assert!(collection.validate().is_ok());
    }

    #[test]
    fn rejects_curve_mismatch_and_bad_caip2() {
        let mismatched = account(
            DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            crate::KeySpec::Secp256k1,
            "m/44'/501'/0'/0'",
            vec![],
        );
        assert!(mismatched.validate().is_err());

        let bad_caip2 = account(
            DerivationProfile::Bip44EvmSecp256k1V1,
            crate::KeySpec::Secp256k1,
            "m/44'/60'/0'/0/0",
            vec![projection("evm", "EIP155:1", "eip155:1:0xabc", "0xabc")],
        );
        assert!(bad_caip2.validate().is_err());

        let no_colon = account(
            DerivationProfile::Bip44EvmSecp256k1V1,
            crate::KeySpec::Secp256k1,
            "m/44'/60'/0'/0/0",
            vec![projection("evm", "eip1551", "eip155:1:0xabc", "0xabc")],
        );
        assert!(no_colon.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_chain_projections() {
        let duplicate = account(
            DerivationProfile::Bip44EvmSecp256k1V1,
            crate::KeySpec::Secp256k1,
            "m/44'/60'/0'/0/0",
            vec![
                projection("evm", "eip155:1", "eip155:1:0xaaa", "0xaaa"),
                projection("evm", "eip155:1", "eip155:1:0xbbb", "0xbbb"),
            ],
        );
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn rejects_empty_collection_accounts_only_when_malformed() {
        // An empty account list is legal: a freshly created wallet may not
        // have allocated a child yet. Validation still applies per account.
        let collection = WalletAccountsPublic {
            wallet_id: token("primary"),
            seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            accounts: vec![],
        };
        assert!(collection.validate().is_ok());
    }

    #[test]
    fn serde_round_trips_and_fails_closed() {
        let value = account(
            DerivationProfile::Bip44EvmSecp256k1V1,
            crate::KeySpec::Secp256k1,
            "m/44'/60'/0'/0/0",
            vec![projection("evm", "eip155:1", "eip155:1:0xabc", "0xabc")],
        );
        let encoded = serde_json::to_string(&value).unwrap();
        let decoded: DerivedAccountPublic = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value, decoded);

        let mut json = serde_json::to_value(&value).unwrap();
        json["chain_projections"][0]["caip2"] = serde_json::json!("not-a-caip2");
        assert!(serde_json::from_value::<DerivedAccountPublic>(json).is_err());
    }
}
