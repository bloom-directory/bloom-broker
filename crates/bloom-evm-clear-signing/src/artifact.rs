//! Verifier digest: SHA-256 over this crate's semantic sources and the
//! compiled-in catalog.
//!
//! Clear-signing evidence records it, and activation and signing compare it
//! with the running build's. A Broker upgrade that changes how the same bytes
//! read, or what the catalog says, therefore invalidates an approval prepared
//! under the old build instead of carrying it forward.
//!
//! It covers catalog-driven clear signing only, not Broker's own renderings in
//! `evm_review.rs`, which read a native transaction from the exact bytes.

use std::sync::LazyLock;

use bloom_broker_api::Digest32;
use sha2::{Digest, Sha256};

/// The semantic sources, in a fixed order. Formatting lives here rather than
/// in a date or units library precisely so this digest covers it.
const COVERED_SOURCES: [(&str, &str); 4] = [
    ("lib.rs", include_str!("lib.rs")),
    ("catalog.rs", include_str!("catalog.rs")),
    ("descriptor.rs", include_str!("descriptor.rs")),
    ("render.rs", include_str!("render.rs")),
];

static DIGEST: LazyLock<Digest32> = LazyLock::new(|| {
    let mut hasher = Sha256::new();
    hasher.update(b"bloom.evm_clear_signing_verifier.v2");
    let catalog = crate::DESCRIPTORS
        .iter()
        .map(|(path, text, _)| (*path, *text))
        .chain([("tokens.json", crate::TOKENS)]);
    // Each file contributes its name and byte length before its contents, so
    // moving text between files changes the digest rather than cancelling out.
    for (name, text) in COVERED_SOURCES.into_iter().chain(catalog) {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((text.len() as u64).to_be_bytes());
        hasher.update(text.as_bytes());
    }
    Digest32::from_bytes(hasher.finalize().into())
});

pub fn digest() -> &'static Digest32 {
    &DIGEST
}
