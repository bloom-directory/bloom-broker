//! Frozen golden vectors for the canonical legacy native-transfer message.
//!
//! These vectors are the shared contract across Petal/Machine/Broker/Signer.
//! They were produced from a fixed Ed25519 seed, a fixed destination, a fixed
//! lamport amount, and a fixed recent blockhash, and are independently
//! reproduced by [`crate::message`] and checked against the pinned Anza
//! reference crates in `tests/golden_vectors.rs`.
//!
//! The message is a canonical single-signer System Program transfer:
//! `account_keys = [fee_payer, destination, system_program]`, one instruction
//! `{ program_id_index: 2, accounts: [0, 1], data: transfer(lamports) }`,
//! header `{ 1, 0, 1 }`.
//!
//! The signature is Ed25519 over the **raw serialized message bytes** (the
//! Solana convention — there is no SHA-256 pre-hash). The SHA-256 value is
//! Bloom's payload commitment only.

use crate::pubkey::Pubkey;
pub use bloom_broker_api::solana_vectors::{
    BLOCKHASH_HEX, DESTINATION, FEE_PAYER, FEE_PAYER_SEED, LAMPORTS, MESSAGE_DIGEST_HEX,
    MESSAGE_HEX, SIGNATURE_HEX,
};

/// The golden fee-payer public key.
pub fn fee_payer() -> Pubkey {
    FEE_PAYER.parse().expect("golden fee payer is valid base58")
}

/// The golden destination public key.
pub fn destination() -> Pubkey {
    DESTINATION
        .parse()
        .expect("golden destination is valid base58")
}

/// The golden recent blockhash.
pub fn blockhash() -> [u8; 32] {
    let bytes = hex::decode(BLOCKHASH_HEX).expect("golden blockhash is valid hex");
    bytes.try_into().expect("golden blockhash is 32 bytes")
}

/// The golden serialized message bytes.
pub fn message_bytes() -> Vec<u8> {
    hex::decode(MESSAGE_HEX).expect("golden message is valid hex")
}

/// The golden payload commitment (SHA-256 of the message).
pub fn message_digest() -> [u8; 32] {
    let bytes = hex::decode(MESSAGE_DIGEST_HEX).expect("golden digest is valid hex");
    bytes.try_into().expect("golden digest is 32 bytes")
}

/// The golden signature over the raw message bytes.
pub fn signature() -> [u8; 64] {
    let bytes = hex::decode(SIGNATURE_HEX).expect("golden signature is valid hex");
    bytes.try_into().expect("golden signature is 64 bytes")
}
