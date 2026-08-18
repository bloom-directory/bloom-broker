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

/// The fee payer (and transfer source) public key.
pub const FEE_PAYER: &str = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF";
/// The destination public key.
pub const DESTINATION: &str = "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t";
/// The lamport amount (1 SOL).
pub const LAMPORTS: u64 = 1_000_000_000;

/// The recent blockhash used in the golden message.
pub const BLOCKHASH_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";

/// The canonical serialized message bytes.
pub const MESSAGE_HEX: &str = "0100010303a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8abababababababababababababababababababababababababababababababab0000000000000000000000000000000000000000000000000000000000000000424242424242424242424242424242424242424242424242424242424242424201020200010c0200000000ca9a3b00000000";

/// SHA-256 of the serialized message — Bloom's payload commitment, **not** the
/// Ed25519 signing input.
pub const MESSAGE_DIGEST_HEX: &str =
    "d7770e6c7f805e94d5ed24b4b0d8ca93bdd7de4081ccb230fa257096b7dc5ec5";

/// The deterministic Ed25519 signature over the **raw serialized message
/// bytes**, produced by the fixed golden seed.
pub const SIGNATURE_HEX: &str = "cb7ccec4699662f08de156e8322e71e00abcf88506055ecdd849e5749f15b8590a65883e433069bad539fc8206781f4d9ec56c2bbd15c061cbf5570ce9ebbf0e";

/// The fixed 32-byte Ed25519 seed that derives [`FEE_PAYER`]. `0x00..=0x1f`.
pub const FEE_PAYER_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

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
