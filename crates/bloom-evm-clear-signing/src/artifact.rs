//! Verifier source digest.
//!
//! Wallet policy pins the clear-signing verifier by digest. For that pin to
//! mean anything the digest has to be *derived* from the sources rather than
//! assigned by hand, so an upgrade that changes parsing, an admitted format
//! or a safety rule cannot keep the identity a wallet already approved.
//!
//! [`compute`] recomputes it from the sources embedded at compile time; the
//! test in Broker asserts it equals the published constant.
//!
//! # What the pin does not cover
//!
//! This digest covers catalog-driven clear signing: this crate's sources and
//! the ABI decoder underneath them. It does not cover Broker's own renderings
//! -- `evm_review.rs` and `safe_review.rs` -- which read a native EVM
//! transaction or a Safe transaction from the exact bytes rather than from a
//! publisher's catalog. Those produce security-bearing ceremony text too, and
//! a wallet that pins this digest is not pinning them.
//!
//! That is deliberate: a catalog reading is a third party's description, which
//! is what a wallet needs to pin, while Broker's own reading changes with
//! Broker. Anyone adding a decoder should know which side of the line they
//! are on. Extending the pin to cover Broker's renderings would mean a second
//! digest with its own recompute-in-the-same-change test.

use sha2::{Digest, Sha256};

/// The semantic sources, in a fixed order. Formatting lives here rather than
/// in a date or units library precisely so this digest covers it.
const COVERED_SOURCES: [(&str, &str); 4] = [
    ("lib.rs", include_str!("lib.rs")),
    ("catalog.rs", include_str!("catalog.rs")),
    ("descriptor.rs", include_str!("descriptor.rs")),
    ("render.rs", include_str!("render.rs")),
];

/// The versions of the crates that do the actual ABI decoding.
///
/// The sources above state the rules, but they delegate the decode and the
/// re-encode that enforces canonical calldata to alloy. A change there can
/// change what the same bytes decode to without touching a line of this
/// crate, so the pin has to cover it or it does not cover the decoder at all.
/// `dependency_versions_match_the_lockfile` keeps this honest: a bump that
/// leaves this list alone fails, and updating the list moves this digest,
/// which is what forces the published constant to move with it.
const COVERED_DEPENDENCIES: [(&str, &str); 4] = [
    ("alloy-dyn-abi", "1.7.3"),
    ("alloy-json-abi", "1.7.3"),
    ("alloy-primitives", "1.7.3"),
    ("alloy-sol-types", "1.7.3"),
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
    hasher.update(b"dependencies");
    for (name, version) in COVERED_DEPENDENCIES {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((version.len() as u64).to_be_bytes());
        hasher.update(version.as_bytes());
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

    /// The digest claims to cover the decoder's version, so the claim is
    /// checked against the resolved lockfile rather than trusted.
    #[test]
    fn dependency_versions_match_the_lockfile() {
        let lock = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock"),
        )
        .expect("the workspace lockfile is committed and resolves this crate's dependencies");
        for (name, version) in super::COVERED_DEPENDENCIES {
            let package = lock
                .split("[[package]]")
                .find(|block| block.contains(&format!("name = \"{name}\"\n")))
                .unwrap_or_else(|| panic!("{name} is not in the lockfile"));
            assert!(
                package.contains(&format!("version = \"{version}\"\n")),
                "the verifier digest pins {name} {version}, but the lockfile resolves something \
                 else; update COVERED_DEPENDENCIES and the published verifier digest together"
            );
        }
    }
}
