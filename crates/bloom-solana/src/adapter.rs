//! The `solana-system-transfer-v1` adapter surface for Broker integration.
//!
//! Broker compiles the verifier behind a versioned input/result schema. Until
//! the BIP-39 Signer contracts stabilize, this module runs the same verifier
//! behind a **fixture `KeyRef`** — an opaque token plus a pinned Ed25519
//! public key, standing in for the future `DerivationRef` /
//! `DerivedAccountDescriptor` types. When bloom#163 lands, the bloom-broker
//! branch replaces [`FixtureKeyRef`] with the real types without touching the
//! verifier itself.

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::str::FromStr;

use crate::pubkey::Pubkey;
use crate::verifier::{RejectionReason, VerifiedTransfer, verify_native_transfer};

/// The versioned adapter schema.
pub const ADAPTER_SCHEMA: &str = "bloom.solana-system-transfer-verifier/1";

/// The exact crypto suite this verifier accepts.
pub const REQUIRED_SUITE: &str = "ed25519-message";

/// The exact operation class this verifier accepts.
pub const REQUIRED_OPERATION_CLASS: &str = "solana.native-transfer";

/// Fixture stand-in for the Broker's backend-qualified `KeyRef`: an opaque
/// locator plus the pinned Ed25519 public key the child must sign with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureKeyRef {
    pub backend: String,
    pub locator: String,
    /// 64 lowercase hex characters: the selected child's Ed25519 public key.
    pub public_key_hex: String,
}

impl FixtureKeyRef {
    pub fn public_key(&self) -> Result<Pubkey, AdapterError> {
        let bytes = hex::decode(&self.public_key_hex)
            .map_err(|e| AdapterError::InvalidKeyRef(format!("public_key_hex: {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            AdapterError::InvalidKeyRef(format!("key must be 32 bytes, got {}", v.len()))
        })?;
        Ok(Pubkey::from_bytes(arr))
    }
}

/// The versioned verifier input carried across the Broker boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierInputV1 {
    pub schema: String,
    pub operation_class: String,
    pub crypto_suite: String,
    /// The exact serialized legacy message bytes (hex).
    pub message_hex: String,
    /// SHA-256 of the message bytes — Bloom's payload commitment (hex).
    pub payload_digest_hex: String,
    /// The driver's economic claim, compared field-by-field against the
    /// verifier's independent extraction.
    pub claim: TransferClaimV1,
    pub key_ref: FixtureKeyRef,
    /// Driver-supplied evidence in the verifier's versioned schema. v1
    /// accepts `None` or any object; no evidence field is verifier-proven
    /// beyond what the message itself encodes.
    pub evidence: Option<serde_json::Value>,
}

/// The economic facts the driver claims; every field must equal the
/// verifier's extraction exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferClaimV1 {
    pub fee_payer_base58: String,
    pub destination_base58: String,
    pub lamports: u64,
}

/// The versioned verifier result: canonical verified facts plus the result
/// digest Broker binds into approvals, uses, and receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierResultV1 {
    pub verifier_id: String,
    pub verified: VerifiedTransfer,
    /// SHA-256 over the canonical JSON of the verified facts.
    pub result_digest_hex: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AdapterError {
    #[error("schema '{0}' is not {ADAPTER_SCHEMA}")]
    BadSchema(String),
    #[error("operation class '{0}' is not {REQUIRED_OPERATION_CLASS}")]
    BadOperationClass(String),
    #[error("crypto suite '{0}' is not {REQUIRED_SUITE}")]
    BadSuite(String),
    #[error("invalid key ref: {0}")]
    InvalidKeyRef(String),
    #[error("claim fee payer is not valid base58: {0}")]
    BadClaimFeePayer(String),
    #[error("claim destination is not valid base58: {0}")]
    BadClaimDestination(String),
    #[error("payload digest must be 64 lowercase hex characters")]
    BadDigest,
}

/// Run the verifier over the versioned input. On success the result digest is
/// derived from the verified facts, never from driver-supplied bytes.
pub fn run_verifier(input: &VerifierInputV1) -> Result<VerifierResultV1, RejectionReason> {
    let key = input
        .key_ref
        .public_key()
        .map_err(|e| RejectionReason::Malformed {
            detail: e.to_string(),
        })?;

    // The claimed fee payer must equal the selected KeyRef's pinned public
    // key: the claim cannot substitute a different signer.
    let claimed_payer = Pubkey::from_str(&input.claim.fee_payer_base58).map_err(|_| {
        RejectionReason::Malformed {
            detail: format!(
                "claim fee_payer_base58 invalid: {}",
                input.claim.fee_payer_base58
            ),
        }
    })?;
    let destination = Pubkey::from_str(&input.claim.destination_base58).map_err(|_| {
        RejectionReason::Malformed {
            detail: format!(
                "claim destination_base58 invalid: {}",
                input.claim.destination_base58
            ),
        }
    })?;
    if claimed_payer != key {
        return Err(RejectionReason::FeePayerMismatch {
            expected: key.to_string(),
            actual: claimed_payer.to_string(),
        });
    }

    let message_bytes =
        hex::decode(&input.message_hex).map_err(|e| RejectionReason::Malformed {
            detail: format!("message_hex: {e}"),
        })?;
    let mut digest = [0u8; 32];
    let digest_hex =
        hex::decode(&input.payload_digest_hex).map_err(|_| RejectionReason::DigestMismatch)?;
    let digest_bytes: &[u8] = digest_hex.as_slice();
    if digest_bytes.len() != 32 {
        return Err(RejectionReason::DigestMismatch);
    }
    digest.copy_from_slice(digest_bytes);

    let verified = verify_native_transfer(
        &message_bytes,
        key,
        destination,
        input.claim.lamports,
        Some(digest),
    )?;

    let canonical = serde_json::to_vec(&verified).map_err(|e| RejectionReason::Malformed {
        detail: format!("canonical result: {e}"),
    })?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&canonical);
    let result_digest_hex = hex::encode(hasher.finalize());

    Ok(VerifierResultV1 {
        verifier_id: crate::VERIFIER_ID.to_string(),
        verified,
        result_digest_hex,
    })
}

impl VerifierInputV1 {
    /// Validate the schema-level invariants before running the verifier.
    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema != ADAPTER_SCHEMA {
            return Err(AdapterError::BadSchema(self.schema.clone()));
        }
        if self.operation_class != REQUIRED_OPERATION_CLASS {
            return Err(AdapterError::BadOperationClass(
                self.operation_class.clone(),
            ));
        }
        if self.crypto_suite != REQUIRED_SUITE {
            return Err(AdapterError::BadSuite(self.crypto_suite.clone()));
        }
        self.key_ref.public_key()?;
        Pubkey::from_str(&self.claim.fee_payer_base58)
            .map_err(|e| AdapterError::BadClaimFeePayer(e.to_string()))?;
        Pubkey::from_str(&self.claim.destination_base58)
            .map_err(|e| AdapterError::BadClaimDestination(e.to_string()))?;
        if self.payload_digest_hex.len() != 64
            || !self
                .payload_digest_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(AdapterError::BadDigest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden;

    fn input() -> VerifierInputV1 {
        VerifierInputV1 {
            schema: ADAPTER_SCHEMA.to_string(),
            operation_class: REQUIRED_OPERATION_CLASS.to_string(),
            crypto_suite: REQUIRED_SUITE.to_string(),
            message_hex: golden::MESSAGE_HEX.to_string(),
            payload_digest_hex: golden::MESSAGE_DIGEST_HEX.to_string(),
            claim: TransferClaimV1 {
                fee_payer_base58: golden::FEE_PAYER.to_string(),
                destination_base58: golden::DESTINATION.to_string(),
                lamports: golden::LAMPORTS,
            },
            key_ref: FixtureKeyRef {
                backend: "local".to_string(),
                locator: "fixture-child-0".to_string(),
                public_key_hex: hex::encode(golden::fee_payer().as_bytes()),
            },
            evidence: None,
        }
    }

    #[test]
    fn golden_input_verifies_and_digest_is_stable() {
        let input = input();
        input.validate().unwrap();
        let result = run_verifier(&input).unwrap();
        assert_eq!(result.verifier_id, "solana-system-transfer-v1");
        assert_eq!(result.verified.destination, golden::DESTINATION);
        assert_eq!(result.verified.lamports, golden::LAMPORTS);
        // Deterministic: same input, same result digest.
        let again = run_verifier(&input).unwrap();
        assert_eq!(result.result_digest_hex, again.result_digest_hex);
        assert_eq!(result.result_digest_hex.len(), 64);
    }

    #[test]
    fn claim_cannot_substitute_a_different_signer() {
        let mut input = input();
        input.claim.fee_payer_base58 = golden::DESTINATION.to_string();
        assert!(matches!(
            run_verifier(&input).unwrap_err(),
            RejectionReason::FeePayerMismatch { .. }
        ));
    }

    #[test]
    fn wrong_suite_is_rejected_at_validation() {
        let mut input = input();
        input.crypto_suite = "ed25519-digest".into();
        assert!(matches!(
            input.validate().unwrap_err(),
            AdapterError::BadSuite(_)
        ));
    }

    #[test]
    fn wrong_length_digest_is_rejected_not_panicking() {
        let mut input = input();
        input.payload_digest_hex = "ab".to_string();
        assert!(matches!(
            run_verifier(&input).unwrap_err(),
            RejectionReason::DigestMismatch
        ));
    }

    #[test]
    fn tampered_digest_is_rejected() {
        let mut input = input();
        input.payload_digest_hex = "f".repeat(64);
        assert!(matches!(
            run_verifier(&input).unwrap_err(),
            RejectionReason::DigestMismatch
        ));
    }

    #[test]
    fn result_digest_derives_from_facts_not_driver_bytes() {
        // Same facts via a structurally different but equivalent input
        // (evidence differs) produce the same digest.
        let mut a = input();
        a.evidence = Some(serde_json::json!({ "driver": "note" }));
        let b = input();
        assert_eq!(
            run_verifier(&a).unwrap().result_digest_hex,
            run_verifier(&b).unwrap().result_digest_hex
        );
    }
}
