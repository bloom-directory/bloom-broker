//! A 32-byte Solana public key with base58 projection.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Number of bytes in a Solana public key.
pub const PUBKEY_BYTES: usize = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PubkeyError {
    #[error("invalid base58 public key: {0}")]
    Base58(String),
    #[error("public key must be exactly {PUBKEY_BYTES} bytes, got {0}")]
    BadLength(usize),
}

/// A Solana public key (a 32-byte Ed25519 verification key).
///
/// Serializes to and from its canonical base58 string representation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey([u8; PUBKEY_BYTES]);

impl Serialize for Pubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Pubkey {
    pub const fn from_bytes(bytes: [u8; PUBKEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PUBKEY_BYTES] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; PUBKEY_BYTES] {
        self.0
    }
}

impl FromStr for Pubkey {
    type Err = PubkeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| PubkeyError::Base58(e.to_string()))?;
        let arr: [u8; PUBKEY_BYTES] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| PubkeyError::BadLength(v.len()))?;
        Ok(Self(arr))
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_program_roundtrips() {
        let sys = Pubkey::from_str("11111111111111111111111111111111").unwrap();
        assert_eq!(sys.to_string(), "11111111111111111111111111111111");
        assert_eq!(sys.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn rejects_bad_length() {
        // "111" decodes to three zero bytes, not a 32-byte key.
        assert!(matches!(
            Pubkey::from_str("111").unwrap_err(),
            PubkeyError::BadLength(3)
        ));
    }

    #[test]
    fn serde_transparent() {
        let sys = Pubkey::from_str("11111111111111111111111111111111").unwrap();
        let s = serde_json::to_string(&sys).unwrap();
        assert_eq!(s, "\"11111111111111111111111111111111\"");
        let back: Pubkey = serde_json::from_str(&s).unwrap();
        assert_eq!(back, sys);
    }
}
