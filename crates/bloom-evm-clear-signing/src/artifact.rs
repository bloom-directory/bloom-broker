//! Verifier source digest.
//!
//! Wallet policy pins the clear-signing verifier by digest. For that pin to
//! mean anything the digest has to be *derived* from the sources rather than
//! assigned by hand, so an upgrade that changes parsing, an admitted format
//! or a safety rule cannot keep the identity a wallet already approved.
//!
//! [`compute`] recomputes it from the sources embedded at compile time; the
//! test in Broker asserts it equals the published constant.

use sha2::{Digest, Sha256};

/// The semantic sources, in a fixed order. Formatting lives here rather than
/// in a date or units library precisely so this digest covers it.
const COVERED_SOURCES: [(&str, &str); 4] = [
    ("lib.rs", include_str!("lib.rs")),
    ("catalog.rs", include_str!("catalog.rs")),
    ("descriptor.rs", include_str!("descriptor.rs")),
    ("render.rs", include_str!("render.rs")),
];

/// SHA-256 over the covered sources. Each file contributes its name and byte
/// length before its contents, so moving text between files changes the
/// digest rather than cancelling out.
pub fn compute() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bloom.evm_clear_signing_verifier.v1");
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
    /// Printed on mismatch so the published constant can be updated in the
    /// same change that altered the verifier.
    #[test]
    fn artifact_digest_is_reproducible() {
        let first = super::compute();
        assert_eq!(first, super::compute(), "the digest must be deterministic");
        println!(
            "clear-signing verifier artifact digest = {}",
            hex::encode(first)
        );
    }
}
