//! Golden vector and differential tests against the pinned Anza reference.
//!
//! The differential tests construct the identical transfer message using the
//! real `solana-message` and `solana-system-interface` crates and assert that
//! our independent codec produces byte-identical serialization. The reference
//! verification test constructs an actual Anza `Transaction` and confirms its
//! signature — over the raw message bytes — verifies.

use bloom_solana::golden;
use bloom_solana::message_digest;
use bloom_solana::system_transfer::transfer_message;
use bloom_solana::{Pubkey, verify_native_transfer};

#[test]
fn golden_message_reproduced_by_our_codec() {
    let msg = transfer_message(
        golden::fee_payer(),
        golden::destination(),
        golden::LAMPORTS,
        golden::blockhash(),
    )
    .unwrap();
    let bytes = msg.serialize();
    assert_eq!(hex::encode(&bytes), golden::MESSAGE_HEX);
    assert_eq!(bytes.len(), 150);
}

#[test]
fn golden_message_digest_is_sha256_of_message() {
    assert_eq!(
        message_digest(&golden::message_bytes()),
        golden::message_digest(),
        "payload commitment must be SHA-256 of the serialized message"
    );
}

#[test]
fn golden_signature_verifies_over_raw_message_bytes() {
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(golden::fee_payer().as_bytes()).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&golden::signature());
    // Solana signs the raw serialized message bytes.
    verifying_key
        .verify_strict(&golden::message_bytes(), &sig)
        .expect("signature must verify against the raw message bytes");
}

#[test]
fn golden_signature_fails_against_sha256_digest() {
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(golden::fee_payer().as_bytes()).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&golden::signature());
    // The SHA-256 digest is only a payload commitment, not the signing input.
    assert!(
        verifying_key
            .verify_strict(&golden::message_digest(), &sig)
            .is_err(),
        "signature must not verify against the SHA-256 digest"
    );
}

/// Reference verification: build a real Anza `Transaction` containing the
/// golden message and signature, and confirm it passes `Transaction::verify`.
#[test]
fn golden_signature_passes_anza_transaction_verification() {
    use solana_message::{Address, Hash, Message};
    use solana_system_interface::instruction::transfer;
    use solana_transaction::{Signature, Transaction};

    let from = Address::from(*golden::fee_payer().as_bytes());
    let to = Address::from(*golden::destination().as_bytes());
    let blockhash = Hash::new_from_array(golden::blockhash());

    let ix = transfer(&from, &to, golden::LAMPORTS);
    let message = Message::new_with_blockhash(&[ix], Some(&from), &blockhash);

    let tx = Transaction {
        signatures: vec![Signature::from(golden::signature())],
        message,
    };
    tx.verify()
        .expect("golden signature must verify against the Anza reference");
}

#[test]
fn golden_verifier_accepts() {
    let verified = verify_native_transfer(
        &golden::message_bytes(),
        golden::fee_payer(),
        golden::destination(),
        golden::LAMPORTS,
        Some(golden::message_digest()),
    )
    .unwrap();
    assert_eq!(verified.fee_payer, golden::FEE_PAYER);
    assert_eq!(verified.destination, golden::DESTINATION);
    assert_eq!(verified.lamports, golden::LAMPORTS);
    assert_eq!(verified.message_digest, golden::message_digest());
}

/// Differential: build the same transfer through the Anza crates and confirm
/// byte-identical message serialization.
#[test]
fn differential_matches_anza_reference() {
    use solana_message::{Address, Hash, Message};
    use solana_system_interface::instruction::transfer;

    let from = Address::from(*golden::fee_payer().as_bytes());
    let to = Address::from(*golden::destination().as_bytes());
    let blockhash = Hash::new_from_array(golden::blockhash());

    let ix = transfer(&from, &to, golden::LAMPORTS);
    let message = Message::new_with_blockhash(&[ix], Some(&from), &blockhash);
    let bytes = message.serialize();

    assert_eq!(hex::encode(&bytes), golden::MESSAGE_HEX);
}

/// Exact digest binding: with the original payload digest held fixed, flip
/// every byte of the golden message one bit at a time and confirm the verifier
/// rejects each mutation via digest mismatch. This proves the digest commitment
/// binds the exact bytes; it does not itself classify each mutation's semantic
/// effect.
#[test]
fn every_single_byte_mutation_breaks_digest_binding() {
    let original = golden::message_bytes();
    let digest = golden::message_digest();
    let mut accepted = Vec::new();

    for i in 0..original.len() {
        for bit in 0..8u8 {
            let mut mutated = original.clone();
            mutated[i] ^= 1 << bit;
            let result = verify_native_transfer(
                &mutated,
                golden::fee_payer(),
                golden::destination(),
                golden::LAMPORTS,
                Some(digest),
            );
            if result.is_ok() {
                accepted.push((i, bit));
            }
        }
    }

    assert!(
        accepted.is_empty(),
        "mutations that still satisfy the digest binding: {accepted:?}"
    );
}

/// Semantic mutation with the digest recomputed: an economic-field change
/// (destination, amount, fee payer) must fail even when the payload digest is
/// recomputed to match the altered bytes.
#[test]
fn economic_mutations_fail_even_with_recomputed_digest() {
    let payer = Pubkey::from_bytes([1u8; 32]);
    let dest = Pubkey::from_bytes([2u8; 32]);
    let lamports = 1_000_000_000u64;

    // Destination changed: verifier must reject the (now internally consistent)
    // message against the original claim.
    let altered = Pubkey::from_bytes([3u8; 32]);
    let msg = transfer_message(payer, altered, lamports, [7u8; 32]).unwrap();
    let bytes = msg.serialize();
    assert!(
        verify_native_transfer(
            &bytes,
            payer,
            dest, // original claim destination
            lamports,
            Some(message_digest(&bytes)),
        )
        .is_err()
    );

    // Amount changed.
    let msg = transfer_message(payer, dest, lamports + 1, [7u8; 32]).unwrap();
    let bytes = msg.serialize();
    assert!(
        verify_native_transfer(
            &bytes,
            payer,
            dest,
            lamports, // original claim amount
            Some(message_digest(&bytes)),
        )
        .is_err()
    );

    // Fee payer changed.
    let other_payer = Pubkey::from_bytes([4u8; 32]);
    let msg = transfer_message(other_payer, dest, lamports, [7u8; 32]).unwrap();
    let bytes = msg.serialize();
    assert!(
        verify_native_transfer(
            &bytes,
            payer, // original claim payer
            dest,
            lamports,
            Some(message_digest(&bytes)),
        )
        .is_err()
    );
}

/// Blockhash is a network-liveness fact, not an economic fact: a message with
/// a different blockhash remains structurally valid and must pass the verifier
/// (with a recomputed digest).
#[test]
fn blockhash_change_remains_structurally_valid() {
    let payer = Pubkey::from_bytes([1u8; 32]);
    let dest = Pubkey::from_bytes([2u8; 32]);
    let lamports = 1_000_000_000u64;

    let msg = transfer_message(payer, dest, lamports, [0xAAu8; 32]).unwrap();
    let bytes = msg.serialize();
    verify_native_transfer(&bytes, payer, dest, lamports, Some(message_digest(&bytes)))
        .expect("blockhash changes are machine_asserted, not verifier-rejected");
}

/// A different valid transfer with a matching claim and recomputed digest must
/// pass — the verifier distinguishes it from an economic-field lie.
#[test]
fn different_valid_transfer_with_matching_claim_passes() {
    let payer = Pubkey::from_bytes([9u8; 32]);
    let dest = Pubkey::from_bytes([8u8; 32]);
    let lamports = 42_000_000u64;
    let blockhash = [0x11u8; 32];

    let msg = transfer_message(payer, dest, lamports, blockhash).unwrap();
    let bytes = msg.serialize();

    let verified =
        verify_native_transfer(&bytes, payer, dest, lamports, Some(message_digest(&bytes)))
            .unwrap();
    assert_eq!(verified.fee_payer, payer.to_string());
    assert_eq!(verified.destination, dest.to_string());
    assert_eq!(verified.lamports, lamports);
}

/// The classic attack: the claim says one destination/amount while the message
/// encodes another. The verifier must reject even before the digest is checked.
#[test]
fn claim_message_divergence_is_rejected() {
    let bytes = golden::message_bytes();
    let digest = golden::message_digest();

    let alice = Pubkey::from_bytes([0xcdu8; 32]);
    assert!(verify_native_transfer(&bytes, golden::fee_payer(), alice, 42, Some(digest)).is_err());
    assert!(
        verify_native_transfer(
            &bytes,
            golden::fee_payer(),
            golden::destination(),
            5 * golden::LAMPORTS,
            Some(digest)
        )
        .is_err()
    );
    let other_payer = Pubkey::from_bytes([0xdeu8; 32]);
    assert!(
        verify_native_transfer(
            &bytes,
            other_payer,
            golden::destination(),
            golden::LAMPORTS,
            Some(digest)
        )
        .is_err()
    );
}

#[test]
fn oversized_message_rejected_before_parse() {
    // 1200 bytes of garbage, none of which is a valid message, but larger than
    // MAX_MESSAGE_SIZE. The verifier must reject as Oversized without
    // attempting to parse.
    let bytes = vec![0u8; 1200];
    assert!(matches!(
        verify_native_transfer(&bytes, golden::fee_payer(), golden::destination(), 1, None)
            .unwrap_err(),
        bloom_solana::RejectionReason::Oversized { message_len: 1200 }
    ));
}
