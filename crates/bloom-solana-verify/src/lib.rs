//! Canonical Solana legacy-message codec and strict semantic verifier.
//!
//! This crate is the content-addressed, dependency-light foundation for
//! Bloom's `solana-system-transfer-v1` native system claim. It contains two
//! deliberately separate concerns:
//!
//! * [`message`] — a strict, canonical encoder/decoder for the Solana legacy
//!   transaction message format, together with [`system_transfer`] for the
//!   System Program native transfer instruction. This is the *verifier's*
//!   implementation-independent parser: it must never share code with the
//!   Machine's construction parser (which uses the Anza `solana-message`
//!   and `solana-system-interface` crates).
//! * [`verifier`] — the `solana-system-transfer-v1` semantic verifier. Given
//!   exact message bytes and the expected economic facts, it establishes the
//!   destination, lamport debit, fee payer/source, program, signer count, and
//!   message commitment, or returns a precise rejection reason.
//!
//! The wire format facts this crate relies on are frozen by golden vectors
//! (see [`golden`]) and by differential tests against the pinned Anza
//! reference crates. No unsafe code is permitted.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod artifact;
pub mod golden;
pub mod message;
pub mod pubkey;
pub mod short_vec;
pub mod system_transfer;
pub mod verifier;

pub use message::{CompiledInstruction, LegacyMessage, MessageHeader, ParseError};
pub use pubkey::{PUBKEY_BYTES, Pubkey};
pub use short_vec::{ShortVecError, read_short_vec, write_short_vec};
pub use system_transfer::{
    SYSTEM_PROGRAM_ID, SystemTransferError, transfer_data, transfer_instruction,
};
pub use verifier::{RejectionReason, VerifiedTransfer, verify_native_transfer};

/// The `solana-system-transfer-v1` verifier identifier, as advertised by
/// Broker capabilities and required by wallet policy.
pub const VERIFIER_ID: &str = "solana-system-transfer-v1";

/// The SHA-256 payload commitment for a serialized message.
///
/// Solana signatures are Ed25519 over the **raw serialized message bytes** —
/// there is no pre-hash. This SHA-256 value is Bloom's `payload_digest` /
/// ordered-hash commitment used for operation identity, review, and audit; it
/// must never be used as the Ed25519 signing input.
pub fn message_digest(message_bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(message_bytes);
    h.finalize().into()
}
