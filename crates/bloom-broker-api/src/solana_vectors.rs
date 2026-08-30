//! Frozen cross-repository vectors for `solana-system-transfer-v1`.
//!
//! Both the independent Broker verifier and the Machine-side constructor
//! consume these exact constants. Keeping one authoritative copy makes a
//! constructor/verifier drift fail at compile or test time instead of during
//! a production signing attempt.

/// The fee payer (and transfer source) public key.
pub const FEE_PAYER: &str = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF";
/// The destination public key.
pub const DESTINATION: &str = "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t";
/// The lamport amount (1 SOL).
pub const LAMPORTS: u64 = 1_000_000_000;
/// The recent blockhash used in the golden message.
pub const BLOCKHASH_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";
/// The canonical serialized legacy-message bytes.
pub const MESSAGE_HEX: &str = "0100010303a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8abababababababababababababababababababababababababababababababab0000000000000000000000000000000000000000000000000000000000000000424242424242424242424242424242424242424242424242424242424242424201020200010c0200000000ca9a3b00000000";
/// SHA-256 of [`MESSAGE_HEX`], used as Bloom's payload commitment.
pub const MESSAGE_DIGEST_HEX: &str =
    "d7770e6c7f805e94d5ed24b4b0d8ca93bdd7de4081ccb230fa257096b7dc5ec5";
/// Deterministic Ed25519 signature over the raw serialized message bytes.
pub const SIGNATURE_HEX: &str = "cb7ccec4699662f08de156e8322e71e00abcf88506055ecdd849e5749f15b8590a65883e433069bad539fc8206781f4d9ec56c2bbd15c061cbf5570ce9ebbf0e";
/// Fixed test-only Ed25519 seed that derives [`FEE_PAYER`].
pub const FEE_PAYER_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
