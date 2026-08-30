//! Compiled-verifier artifact digest.
//!
//! The `ProofVerified` identity a wallet pins names this verifier by digest.
//! For that identity to mean anything, the digest has to be *derived* from
//! the verifier's source rather than assigned by hand: a hand-assigned
//! constant can stay put while the code beneath it changes, which is the one
//! thing the digest exists to prevent.
//!
//! [`compute`] recomputes it from the sources embedded at compile time, and
//! the test below asserts it equals the constant the Broker publishes. A
//! change to any covered file fails that test until the constant is updated
//! deliberately — which is the intended workflow, because a changed verifier
//! *is* a changed identity.

use sha2::{Digest, Sha256};

/// The verifier's core sources, in a fixed order. Embedded at compile time so
/// the digest does not depend on the working directory or on files present at
/// run time.
const COVERED_SOURCES: [(&str, &str); 6] = [
    ("lib.rs", include_str!("lib.rs")),
    ("message.rs", include_str!("message.rs")),
    ("verifier.rs", include_str!("verifier.rs")),
    ("pubkey.rs", include_str!("pubkey.rs")),
    ("short_vec.rs", include_str!("short_vec.rs")),
    ("system_transfer.rs", include_str!("system_transfer.rs")),
];

/// SHA-256 over the covered sources.
///
/// Each file contributes its name and byte length before its contents, so
/// moving text between files changes the digest rather than cancelling out.
pub fn compute() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bloom.solana_system_transfer_verifier.v1");
    for (name, source) in COVERED_SOURCES {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((source.len() as u64).to_be_bytes());
        hasher.update(source.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    /// Printed on mismatch so the constant can be updated deliberately.
    #[test]
    fn artifact_digest_is_reproducible() {
        let first = super::compute();
        assert_eq!(first, super::compute(), "the digest must be deterministic");
        println!("verifier artifact digest = {}", hex::encode(first));
    }
}
