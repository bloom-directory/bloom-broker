//! Compiled-in assurance verifiers.
//!
//! Verifiers are deliberately *compiled into* Broker — there is no path,
//! library name, or runtime loading API (see [`crate::authority`]). This
//! module holds the `solana-system-transfer-v1` semantic verifier, the first
//! `ProofVerified` assurance implementation: it independently re-parses the
//! exact message bytes and establishes destination and lamports, so a bug in
//! Solana's own construction code cannot redefine what is being signed.

use bloom_broker_api::{ClaimAssuranceLevel, CryptoSuite, Digest32, PetalUseClaim, Token};
use bloom_solana::Pubkey;
use std::str::FromStr;

use crate::authority::{AssuranceVerifier, VerifierCapability};

/// SHA-256 over the verifier crate's core sources (`lib.rs`, `message.rs`,
/// `verifier.rs`, `pubkey.rs`, `short_vec.rs`, `system_transfer.rs`) — the
/// compiled-verifier artifact digest that pins this exact implementation to
/// its source, so a changed verifier is a changed digest and therefore a
/// changed `ProofVerified` identity.
const SOLANA_VERIFIER_ARTIFACT_DIGEST: [u8; 32] = [
    0xeb, 0x3d, 0x9a, 0x08, 0x4d, 0x60, 0xcd, 0x73, 0xd2, 0xb2, 0x31, 0xb4, 0x27, 0x5f, 0x28, 0x4d,
    0x8a, 0x33, 0x52, 0x68, 0x29, 0x57, 0xba, 0x85, 0xc4, 0x49, 0x2f, 0x6f, 0xe1, 0x6c, 0x63, 0x3a,
];

/// The `solana-system-transfer-v1` semantic verifier.
pub struct SolanaSystemTransferVerifier;

impl SolanaSystemTransferVerifier {
    pub fn compiled() -> std::sync::Arc<dyn AssuranceVerifier> {
        std::sync::Arc::new(Self)
    }
}

impl AssuranceVerifier for SolanaSystemTransferVerifier {
    fn capability(&self) -> VerifierCapability {
        VerifierCapability {
            verifier_id: Token::new("solana-system-transfer-v1").expect("valid token"),
            artifact_digest: Digest32::from_bytes(SOLANA_VERIFIER_ARTIFACT_DIGEST),
            assurance: ClaimAssuranceLevel::ProofVerified,
            // The fields this verifier independently establishes from the
            // message evidence. Provenance/identity fields (package_hash,
            // route, operation_class, crypto_suite, ordered_hashes, nonce)
            // are bound by Broker's own claim-mismatch checks, and Solana's
            // fee is machine-asserted — neither is verifier-proven.
            established_fields: vec![
                Token::new("declared_destinations").expect("valid token"),
                Token::new("declared_debits").expect("valid token"),
                Token::new("payload_digest").expect("valid token"),
            ],
        }
    }

    fn verify(&self, claim: &PetalUseClaim, evidence: Option<&[u8]>) -> Result<(), String> {
        let message = evidence.ok_or("solana transfer requires message evidence")?;
        if claim.crypto_suite != CryptoSuite::Ed25519Message {
            return Err(format!(
                "crypto suite must be ed25519-message, got {:?}",
                claim.crypto_suite
            ));
        }
        let [destination] = claim.declared_destinations.as_slice() else {
            return Err("expected exactly one declared destination".to_string());
        };
        let [debit] = claim.declared_debits.as_slice() else {
            return Err("expected exactly one declared debit".to_string());
        };
        let destination_key = Pubkey::from_str(&destination.destination)
            .map_err(|e| format!("declared destination is not base58: {e}"))?;
        let lamports: u64 = debit
            .amount
            .as_str()
            .parse()
            .map_err(|_| "declared lamports do not fit u64".to_string())?;
        let digest = claim.payload_digest.to_bytes();
        bloom_solana::verify_transfer(message, destination_key, lamports, Some(digest))
            .map(|_| ())
            .map_err(|reason| format!("{reason:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::CryptoSuite;
    use bloom_broker_api::{
        AssetId, ClaimAssurance, DeclaredDebit, DeclaredDestination, DeclaredFee,
    };
    use bloom_solana::system_transfer::transfer_message;

    fn solana_claim(destination: &str, lamports: u64, digest: [u8; 32]) -> PetalUseClaim {
        PetalUseClaim {
            package_hash: Digest32::from_bytes([0x11; 32]),
            route: "transfer.stage.json".to_string(),
            operation_class: Token::new("solana.native-transfer").unwrap(),
            crypto_suite: CryptoSuite::Ed25519Message,
            payload_digest: Digest32::from_bytes(digest),
            ordered_hashes: vec![],
            declared_debits: vec![DeclaredDebit {
                asset: AssetId {
                    chain: Token::new("solana").unwrap(),
                    asset: "native".to_string(),
                },
                amount: bloom_broker_api::DecimalU256::parse(lamports.to_string()).unwrap(),
            }],
            declared_destinations: vec![DeclaredDestination {
                chain: Token::new("solana").unwrap(),
                destination: destination.to_string(),
            }],
            declared_fee: DeclaredFee::None,
            nonce: bloom_broker_api::RequestNonce::new("00".repeat(16)).unwrap(),
            claim_assurance: ClaimAssurance::ProofVerified {
                verifier_id: Token::new("solana-system-transfer-v1").unwrap(),
                verifier_digest: Digest32::from_bytes(SOLANA_VERIFIER_ARTIFACT_DIGEST),
                proof_digest: Digest32::from_bytes([0x22; 32]),
            },
        }
    }

    #[test]
    fn verifies_golden_shaped_transfer() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let lamports = 1_000_000_000u64;
        let message = transfer_message(payer, dest, lamports, [7u8; 32]).unwrap();
        let bytes = message.serialize();
        let digest = bloom_solana::message_digest(&bytes);

        let verifier = SolanaSystemTransferVerifier;
        let claim = solana_claim(&dest.to_string(), lamports, digest);
        verifier.verify(&claim, Some(&bytes)).unwrap();
    }

    #[test]
    fn rejects_lying_destination() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let lamports = 1_000_000_000u64;
        let message = transfer_message(payer, dest, lamports, [7u8; 32]).unwrap();
        let bytes = message.serialize();
        let digest = bloom_solana::message_digest(&bytes);

        let lying = Pubkey::from_bytes([9u8; 32]);
        let claim = solana_claim(&lying.to_string(), lamports, digest);
        let err = SolanaSystemTransferVerifier
            .verify(&claim, Some(&bytes))
            .unwrap_err();
        assert!(err.contains("DestinationMismatch"), "{err}");
    }

    #[test]
    fn rejects_lying_amount() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let lamports = 1_000_000_000u64;
        let message = transfer_message(payer, dest, lamports, [7u8; 32]).unwrap();
        let bytes = message.serialize();
        let digest = bloom_solana::message_digest(&bytes);

        let claim = solana_claim(&dest.to_string(), lamports + 1, digest);
        let err = SolanaSystemTransferVerifier
            .verify(&claim, Some(&bytes))
            .unwrap_err();
        assert!(err.contains("LamportsMismatch"), "{err}");
    }

    #[test]
    fn requires_evidence_and_ed25519_suite() {
        let dest = Pubkey::from_bytes([2u8; 32]);
        let claim = solana_claim(&dest.to_string(), 1, [0u8; 32]);
        assert!(SolanaSystemTransferVerifier.verify(&claim, None).is_err());

        let mut wrong_suite = claim;
        wrong_suite.crypto_suite = CryptoSuite::Secp256k1Keccak256Recoverable;
        assert!(
            SolanaSystemTransferVerifier
                .verify(&wrong_suite, Some(b"x"))
                .is_err()
        );
    }
}
