//! The wallet-policy extension that turns clear signing on.
//!
//! Clear signing is authority, not display: it names the catalog whose
//! descriptions this wallet accepts, the keys that may sign it, and the two
//! refusals the owner can lift. So it lives in the canonical policy document
//! and changes only through the existing policy ceremony.
//!
//! The extension is optional. Omitting it preserves the previous
//! serialization exactly and leaves the wallet on the existing envelope
//! review, which is not advertised as clear signing.

use serde::{Deserialize, Serialize};

use crate::{
    Base64UrlBytes, ProtocolError, ProtocolErrorCode, RequiredVerifier, Token,
    validation::all_unique,
};

/// The compiled verifier a wallet may pin. Its digest is recomputed from the
/// verifier's sources; see `bloom_evm_clear_signing::artifact`.
pub const EVM_CLEAR_SIGNING_VERIFIER_ID: &str = "evm-clear-signing-v1";
/// SHA-256 over the verifier's semantic sources, recomputed by
/// `bloom_evm_clear_signing::artifact::compute` and asserted equal in Broker.
/// A changed verifier is a changed identity, so a wallet that pinned this
/// digest stops accepting reviews from a build whose sources moved.
pub const EVM_CLEAR_SIGNING_VERIFIER_DIGEST_BYTES: [u8; 32] = [
    0xf5, 0x57, 0xa4, 0xc8, 0x0f, 0x70, 0x64, 0x14, 0xe8, 0x70, 0x78, 0x5d, 0xef, 0x23, 0xe4, 0x7a,
    0xbb, 0x34, 0x4f, 0x3c, 0x20, 0xcb, 0x58, 0x22, 0x27, 0x38, 0x0a, 0x5b, 0x08, 0x2c, 0x30, 0x89,
];

pub const DEFAULT_MAXIMUM_OBSERVATION_AGE_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAXIMUM_OBSERVATION_AGE_CEILING_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const MAX_TRUSTED_CATALOG_KEYS: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogTrustedKey {
    pub key_id: Token,
    /// A raw 32-byte Ed25519 verifying key.
    pub verifying_key: Base64UrlBytes,
}

/// The operator-visible status of the stored catalog. Advertised beside the
/// assurance verifiers so an operator can tell, without a new command family,
/// what Broker would read a contract call against.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSigningStatus {
    pub catalog_id: String,
    pub sequence: String,
    pub content_digest: String,
    pub expires_at_ms: String,
    pub entries: u64,
    /// The oldest publisher observation in the snapshot, so staleness is
    /// visible before a ceremony refuses one.
    pub oldest_observation_ms: String,
    pub verifier_id: String,
    pub verifier_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSigningPolicy {
    /// The one catalog identity this wallet accepts descriptions from.
    pub catalog_id: Token,
    pub trusted_keys: Vec<CatalogTrustedKey>,
    /// How many distinct trusted keys must sign a snapshot. One by default:
    /// a second maintainer is a real operational commitment, not a setting.
    pub signature_threshold: u8,
    /// How stale a publisher's observation of a deployment may be before its
    /// entry stops authorizing anything.
    pub maximum_observation_age_ms: u64,
    /// Whether this wallet may approve exact payloads Bloom cannot explain.
    pub opaque_exact_allowed: bool,
    /// Whether a maximum-U256 allowance may be requested at all. Enabling it
    /// still requires a separate exact approval for each allowance.
    pub unlimited_allowance_allowed: bool,
    /// The verifier source identity, pinned the same way `required_verifiers`
    /// pins a claim verifier.
    pub verifier: RequiredVerifier,
}

impl ClearSigningPolicy {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let invalid = |message: &str| {
            Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("clear-signing policy is invalid: {message}"),
            ))
        };
        if self.trusted_keys.is_empty() || self.trusted_keys.len() > MAX_TRUSTED_CATALOG_KEYS {
            return invalid("trusted key count must be 1-8");
        }
        let key_ids: Vec<_> = self
            .trusted_keys
            .iter()
            .map(|key| key.key_id.clone())
            .collect();
        if !all_unique(&key_ids) {
            return invalid("trusted key identities must be distinct");
        }
        if self
            .trusted_keys
            .iter()
            .any(|key| key.verifying_key.decode().len() != 32)
        {
            return invalid("each trusted verifying key must contain 32 bytes");
        }
        if self.signature_threshold == 0
            || usize::from(self.signature_threshold) > self.trusted_keys.len()
        {
            return invalid("signature threshold must be 1..=trusted key count");
        }
        if self.maximum_observation_age_ms == 0
            || self.maximum_observation_age_ms > MAXIMUM_OBSERVATION_AGE_CEILING_MS
        {
            return invalid("maximum observation age must be 1ms..=30 days");
        }
        if self.verifier.verifier_id.as_str() != EVM_CLEAR_SIGNING_VERIFIER_ID {
            return invalid("the pinned verifier is not the clear-signing verifier");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest32;

    fn policy() -> ClearSigningPolicy {
        ClearSigningPolicy {
            catalog_id: Token::new("bloom-tokens").unwrap(),
            trusted_keys: vec![CatalogTrustedKey {
                key_id: Token::new("publisher-1").unwrap(),
                verifying_key: Base64UrlBytes::from_bytes(&[7; 32]),
            }],
            signature_threshold: 1,
            maximum_observation_age_ms: DEFAULT_MAXIMUM_OBSERVATION_AGE_MS,
            opaque_exact_allowed: false,
            unlimited_allowance_allowed: false,
            verifier: RequiredVerifier {
                verifier_id: Token::new(EVM_CLEAR_SIGNING_VERIFIER_ID).unwrap(),
                verifier_digest: Digest32::from_bytes([9; 32]),
            },
        }
    }

    #[test]
    fn the_defaults_are_the_closed_ones() {
        let policy = policy();
        policy.validate().unwrap();
        assert!(!policy.opaque_exact_allowed);
        assert!(!policy.unlimited_allowance_allowed);
        assert_eq!(policy.signature_threshold, 1);
    }

    #[test]
    fn a_threshold_no_key_set_can_satisfy_is_refused() {
        let mut policy = policy();
        policy.signature_threshold = 2;
        assert!(policy.validate().is_err());
        policy.signature_threshold = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn duplicate_or_malformed_trusted_keys_are_refused() {
        let mut duplicated = policy();
        duplicated
            .trusted_keys
            .push(duplicated.trusted_keys[0].clone());
        assert!(duplicated.validate().is_err());

        let mut short_key = policy();
        short_key.trusted_keys[0].verifying_key = Base64UrlBytes::from_bytes(&[7; 31]);
        assert!(short_key.validate().is_err());
    }

    #[test]
    fn an_unbounded_observation_age_is_refused() {
        let mut policy = policy();
        policy.maximum_observation_age_ms = MAXIMUM_OBSERVATION_AGE_CEILING_MS + 1;
        assert!(policy.validate().is_err());
        policy.maximum_observation_age_ms = 0;
        assert!(policy.validate().is_err());
    }
}
