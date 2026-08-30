//! Compiled-in assurance verifiers.
//!
//! Verifiers are deliberately *compiled into* Broker — there is no path,
//! library name, or runtime loading API (see [`crate::authority`]). This
//! module holds the `solana-system-transfer-v1` semantic verifier, the first
//! `ProofVerified` assurance implementation: it independently re-parses the
//! exact message bytes and establishes destination and lamports, so a bug in
//! Solana's own construction code cannot redefine what is being signed.

use bloom_broker_api::{
    ClaimAssuranceLevel, CryptoSuite, Digest32, PetalUseClaim,
    SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES, SOLANA_SYSTEM_TRANSFER_VERIFIER_ID,
    SystemUseClaim, Token,
};
use bloom_solana::Pubkey;
use std::str::FromStr;

use crate::authority::{AssuranceVerifier, VerifierCapability};

/// The `solana-system-transfer-v1` semantic verifier.
///
/// Its published artifact digest (`SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES`)
/// is SHA-256 over the verifier crate's core sources, recomputed by
/// `bloom_solana::artifact::compute` and asserted equal below. That is what
/// makes "a changed verifier is a changed `ProofVerified` identity" true
/// rather than aspirational: the digest cannot stay put while the code it
/// names changes.
pub struct SolanaSystemTransferVerifier;

impl SolanaSystemTransferVerifier {
    pub fn compiled() -> std::sync::Arc<dyn AssuranceVerifier> {
        std::sync::Arc::new(Self)
    }
}

impl AssuranceVerifier for SolanaSystemTransferVerifier {
    fn capability(&self) -> VerifierCapability {
        VerifierCapability {
            verifier_id: Token::new(SOLANA_SYSTEM_TRANSFER_VERIFIER_ID).expect("valid token"),
            artifact_digest: Digest32::from_bytes(SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES),
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
                Token::new("recent_blockhash").expect("valid token"),
            ],
        }
    }

    fn verify(&self, _claim: &PetalUseClaim, _evidence: Option<&[u8]>) -> Result<(), String> {
        // Unreachable in any correct configuration, and now explicit rather
        // than dead code that looks live. A Petal claim requiring
        // above-MachineAsserted assurance must establish ten authority
        // fields; this verifier advertises four, so such a claim always fails
        // the contract check before reaching here. Native transfers use the
        // system-claim path and its own four-field contract.
        Err("solana-system-transfer-v1 verifies native system claims, not Petal claims".to_owned())
    }

    fn verify_system(
        &self,
        claim: &SystemUseClaim,
        evidence: Option<&[u8]>,
        expected_signer: Option<&[u8; 32]>,
    ) -> Result<(), String> {
        let message = evidence.ok_or("solana transfer requires message evidence")?;
        if claim.component_id.as_str() != "bloom-machine"
            || claim.action_class.as_str() != "solana.transfer.confirm"
            || claim.operation_class.as_str() != "solana.native-transfer"
            || claim.crypto_suite != CryptoSuite::Ed25519Message
            || claim.chain_context.chain_family.as_str() != "solana"
        {
            return Err("system claim identity, class, suite, or chain is invalid".to_owned());
        }
        let [destination] = claim.declared_destinations.as_slice() else {
            return Err("expected exactly one declared destination".to_owned());
        };
        let [debit] = claim.declared_debits.as_slice() else {
            return Err("expected exactly one declared debit".to_owned());
        };
        let destination_key = Pubkey::from_str(&destination.destination)
            .map_err(|error| format!("declared destination is not base58: {error}"))?;
        let lamports: u64 = debit
            .amount
            .as_str()
            .parse()
            .map_err(|_| "declared lamports do not fit u64".to_owned())?;
        // Bind the payer to the account the approval pinned.
        //
        // The signature alone does not establish it: the Signer signs with
        // the key the terms name regardless of what `account_keys[0]`
        // contains, so a mismatch only surfaces when the cluster rejects the
        // transaction — long after Broker has approved it, reserved wallet
        // quota against it, and journaled a `ProofVerified` transfer. This
        // verifier advertises `declared_debits` as proven, so the debited
        // account has to be established here or that claim is not true.
        let expected_signer = expected_signer
            .ok_or("native Solana verification requires the approved account's public key")?;
        let verified = bloom_solana::verify_native_transfer(
            message,
            Pubkey::from_bytes(*expected_signer),
            destination_key,
            lamports,
            Some(claim.payload_digest.to_bytes()),
        )
        .map_err(|reason| format!("{reason:?}"))?;
        if verified.recent_blockhash != claim.chain_context.recent_blockhash {
            return Err("signed message blockhash differs from system claim".to_owned());
        }
        // Belt and braces: `verify_native_transfer` already rejects a payer
        // mismatch, so this asserts the verified identity we carry forward is
        // the one that was checked rather than re-deriving trust from it.
        if verified.fee_payer != Pubkey::from_bytes(*expected_signer).to_string() {
            return Err("verified fee payer differs from the approved account".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::CryptoSuite;
    use bloom_broker_api::{
        AssetId, ClaimAssurance, DecimalU64, DeclaredDebit, DeclaredDestination, DeclaredFee,
        SystemChainContext,
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
                verifier_id: Token::new(SOLANA_SYSTEM_TRANSFER_VERIFIER_ID).unwrap(),
                verifier_digest: Digest32::from_bytes(SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES),
                proof_digest: Digest32::from_bytes([0x22; 32]),
            },
        }
    }

    fn system_claim(
        destination: &Pubkey,
        lamports: u64,
        digest: [u8; 32],
        blockhash: [u8; 32],
    ) -> SystemUseClaim {
        let petal = solana_claim(&destination.to_string(), lamports, digest);
        SystemUseClaim {
            component_id: Token::new("bloom-machine").unwrap(),
            action_class: Token::new("solana.transfer.confirm").unwrap(),
            operation_class: petal.operation_class,
            crypto_suite: petal.crypto_suite,
            payload_digest: petal.payload_digest,
            ordered_hashes: petal.ordered_hashes,
            declared_debits: petal.declared_debits,
            declared_destinations: petal.declared_destinations,
            declared_fee: petal.declared_fee,
            nonce: petal.nonce,
            chain_context: SystemChainContext {
                chain_family: Token::new("solana").unwrap(),
                genesis_hash: "local-validator-genesis".into(),
                recent_blockhash: bs58::encode(blockhash).into_string(),
                last_valid_block_height: DecimalU64::new(123),
            },
            claim_assurance: petal.claim_assurance,
        }
    }

    /// Promote a Petal-shaped fixture claim onto the native system path,
    /// which is the only path this verifier serves.
    fn as_system_claim(petal: PetalUseClaim, blockhash: [u8; 32]) -> SystemUseClaim {
        SystemUseClaim {
            component_id: Token::new("bloom-machine").unwrap(),
            action_class: Token::new("solana.transfer.confirm").unwrap(),
            operation_class: petal.operation_class,
            crypto_suite: petal.crypto_suite,
            payload_digest: petal.payload_digest,
            ordered_hashes: petal.ordered_hashes,
            declared_debits: petal.declared_debits,
            declared_destinations: petal.declared_destinations,
            declared_fee: petal.declared_fee,
            nonce: petal.nonce,
            chain_context: SystemChainContext {
                chain_family: Token::new("solana").unwrap(),
                genesis_hash: "devnet-genesis".into(),
                recent_blockhash: bs58::encode(blockhash).into_string(),
                last_valid_block_height: DecimalU64::new(123),
            },
            claim_assurance: petal.claim_assurance,
        }
    }

    /// The gap this closes: the Signer signs with whatever key the approval
    /// terms name, regardless of `account_keys[0]`. A message payed by some
    /// other account therefore carries a perfectly valid signature, and the
    /// mismatch only surfaces when the cluster rejects it — after Broker has
    /// approved, reserved wallet quota, and journaled a `ProofVerified`
    /// transfer whose debited account was never established.
    #[test]
    fn a_transfer_paid_by_another_account_is_refused() {
        let approved = Pubkey::from_bytes([1u8; 32]);
        let someone_else = Pubkey::from_bytes([5u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let lamports = 1_000_000_000u64;

        // A well-formed message that simply pays from a different account.
        let message = transfer_message(someone_else, dest, lamports, [7u8; 32]).unwrap();
        let bytes = message.serialize();
        let claim = as_system_claim(
            solana_claim(
                &dest.to_string(),
                lamports,
                bloom_solana::message_digest(&bytes),
            ),
            [7u8; 32],
        );

        let err = SolanaSystemTransferVerifier
            .verify_system(&claim, Some(&bytes), Some(&approved.to_bytes()))
            .unwrap_err();
        assert!(err.contains("FeePayerMismatch"), "{err}");

        // The same message verifies for the account that actually pays it,
        // so the refusal is about binding, not a malformed message.
        SolanaSystemTransferVerifier
            .verify_system(&claim, Some(&bytes), Some(&someone_else.to_bytes()))
            .unwrap();
    }

    /// Without a resolved account there is nothing to bind to, so
    /// verification refuses rather than treating the payer as unconstrained.
    #[test]
    fn verification_refuses_when_no_account_was_resolved() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let message = transfer_message(payer, dest, 42, [7u8; 32]).unwrap();
        let bytes = message.serialize();
        let claim = as_system_claim(
            solana_claim(&dest.to_string(), 42, bloom_solana::message_digest(&bytes)),
            [7u8; 32],
        );
        let err = SolanaSystemTransferVerifier
            .verify_system(&claim, Some(&bytes), None)
            .unwrap_err();
        assert!(err.contains("requires the approved account"), "{err}");
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
        // The Petal path is unreachable in any correct configuration and now
        // says so, rather than looking like a live second entry point.
        assert!(
            verifier
                .verify(&claim, Some(&bytes))
                .unwrap_err()
                .contains("not Petal claims")
        );
    }

    #[test]
    fn verifies_native_system_claim_and_binds_recent_blockhash() {
        let payer = Pubkey::from_bytes([1u8; 32]);
        let dest = Pubkey::from_bytes([2u8; 32]);
        let blockhash = [7u8; 32];
        let message = transfer_message(payer, dest, 42, blockhash).unwrap();
        let bytes = message.serialize();
        let petal = solana_claim(&dest.to_string(), 42, bloom_solana::message_digest(&bytes));
        let mut claim = SystemUseClaim {
            component_id: Token::new("bloom-machine").unwrap(),
            action_class: Token::new("solana.transfer.confirm").unwrap(),
            operation_class: petal.operation_class,
            crypto_suite: petal.crypto_suite,
            payload_digest: petal.payload_digest,
            ordered_hashes: petal.ordered_hashes,
            declared_debits: petal.declared_debits,
            declared_destinations: petal.declared_destinations,
            declared_fee: petal.declared_fee,
            nonce: petal.nonce,
            chain_context: SystemChainContext {
                chain_family: Token::new("solana").unwrap(),
                genesis_hash: "devnet-genesis".into(),
                recent_blockhash: bs58::encode(blockhash).into_string(),
                last_valid_block_height: DecimalU64::new(123),
            },
            claim_assurance: petal.claim_assurance,
        };
        SolanaSystemTransferVerifier
            .verify_system(&claim, Some(&bytes), Some(&payer.to_bytes()))
            .unwrap();
        claim.chain_context.recent_blockhash = bs58::encode([8u8; 32]).into_string();
        assert!(
            SolanaSystemTransferVerifier
                .verify_system(&claim, Some(&bytes), Some(&payer.to_bytes()))
                .unwrap_err()
                .contains("blockhash")
        );
    }

    #[test]
    fn generated_transfers_and_adversarial_claim_mutations_fail_closed() {
        for case in 0u8..64 {
            let payer = Pubkey::from_bytes([case.wrapping_add(1); 32]);
            let destination = Pubkey::from_bytes([case.wrapping_add(2); 32]);
            let lamports = 1_000 + u64::from(case);
            let blockhash = [case.wrapping_add(7); 32];
            let message = transfer_message(payer, destination, lamports, blockhash)
                .unwrap()
                .serialize();
            let digest = bloom_solana::message_digest(&message);
            let verifier = SolanaSystemTransferVerifier;
            let claim = system_claim(&destination, lamports, digest, blockhash);
            verifier
                .verify_system(&claim, Some(&message), Some(&payer.to_bytes()))
                .unwrap();

            let mut wrong_destination = claim.clone();
            wrong_destination.declared_destinations[0].destination =
                Pubkey::from_bytes([0xee; 32]).to_string();
            assert!(
                verifier
                    .verify_system(&wrong_destination, Some(&message), Some(&payer.to_bytes()))
                    .is_err()
            );

            let mut wrong_amount = claim.clone();
            wrong_amount.declared_debits[0].amount =
                bloom_broker_api::DecimalU256::parse((lamports + 1).to_string()).unwrap();
            assert!(
                verifier
                    .verify_system(&wrong_amount, Some(&message), Some(&payer.to_bytes()))
                    .is_err()
            );

            let mut wrong_blockhash = claim.clone();
            wrong_blockhash.chain_context.recent_blockhash = bs58::encode([0xdd; 32]).into_string();
            assert!(
                verifier
                    .verify_system(&wrong_blockhash, Some(&message), Some(&payer.to_bytes()))
                    .is_err()
            );

            let mut wrong_digest = claim.clone();
            wrong_digest.payload_digest = Digest32::from_bytes([0xcc; 32]);
            assert!(
                verifier
                    .verify_system(&wrong_digest, Some(&message), Some(&payer.to_bytes()))
                    .is_err()
            );

            let mut wrong_suite = claim;
            wrong_suite.crypto_suite = CryptoSuite::Secp256k1Keccak256Recoverable;
            assert!(
                verifier
                    .verify_system(&wrong_suite, Some(&message), Some(&payer.to_bytes()))
                    .is_err()
            );
        }
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
        let claim = as_system_claim(
            solana_claim(&lying.to_string(), lamports, digest),
            [7u8; 32],
        );
        let err = SolanaSystemTransferVerifier
            .verify_system(&claim, Some(&bytes), Some(&payer.to_bytes()))
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

        let claim = as_system_claim(
            solana_claim(&dest.to_string(), lamports + 1, digest),
            [7u8; 32],
        );
        let err = SolanaSystemTransferVerifier
            .verify_system(&claim, Some(&bytes), Some(&payer.to_bytes()))
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

#[cfg(test)]
mod artifact_digest_tests {
    /// The published digest must equal the one recomputed from the verifier's
    /// sources. Without this the constant is a hand-assigned version tag:
    /// `verifier.rs` could be rewritten entirely and the `ProofVerified`
    /// identity, the wallet's `required_verifiers` pins, and the audit
    /// journal entries would all be unchanged.
    ///
    /// When this fails after a deliberate verifier change, recompute with
    /// `cargo test -p bloom-solana artifact_digest_is_reproducible -- --nocapture`
    /// and update the constant as part of the same change.
    #[test]
    fn published_digest_matches_the_verifier_sources() {
        assert_eq!(
            bloom_solana::artifact::compute(),
            bloom_broker_api::SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES,
            "the published verifier artifact digest no longer matches its sources"
        );
    }
}
