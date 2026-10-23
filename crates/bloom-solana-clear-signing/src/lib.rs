//! Network-free structural readings for signed Solana messages. Kept separate
//! from the policy-pinned native-transfer verifier: a display catalog update
//! must not change that proof verifier's source identity or accepted language.
#![forbid(unsafe_code)]

pub use bloom_solana_verify::{Pubkey, message_digest, pubkey, read_short_vec, short_vec};
pub mod inspection;
pub mod message;
