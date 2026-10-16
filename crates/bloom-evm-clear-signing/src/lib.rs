//! Bounded ERC-7730 clear signing for EVM contract calls.
//!
//! Broker is the only semantic authority here. This crate is compiled into
//! it: there is no path, library name or runtime loading API, and no
//! JavaScript runtime. It reads a signed local catalog and the flattened
//! ERC-7730 descriptors inside it, decodes exact calldata with one strict
//! generic ABI path, and produces the typed facts an owner reviews.
//!
//! What it does *not* do: fetch anything, read the chain, resolve a proxy,
//! resolve a name, simulate execution, or claim that a described call is
//! safe. The assurance class is [`TRUSTED_DESCRIPTION`] — the publisher is
//! trusted to describe the listed deployment, and a signature authenticates
//! that assertion and nothing more. A call read through an instance entry is
//! [`STRUCTURAL_DESCRIPTION`]: the description is trusted, but nothing
//! establishes that the address runs that contract.

pub mod artifact;
mod catalog;
mod descriptor;
mod render;

pub use catalog::*;
pub use descriptor::*;
pub use render::*;

use bloom_broker_api::{Digest32, EVM_CLEAR_SIGNING_VERIFIER_ID};
use serde::{Deserialize, Serialize};

/// Not `ProofVerified`: nothing here proves execution. A distinct class keeps
/// "a trusted publisher described this" from being read as "Bloom checked
/// what this call does".
pub const TRUSTED_DESCRIPTION: &str = "trusted_description";
/// A review that read at least one address by an instance entry: the
/// description is trusted, the address's contract is not established.
pub const STRUCTURAL_DESCRIPTION: &str = "structural_description";

/// The six review outcomes. Each one is actionable on its own, and existing
/// transport and authority errors are reused wherever they already say the
/// same thing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewReason {
    /// A compiled-in descriptor or token row is outside the supported subset.
    CatalogRejected,
    /// No matching chain, address or admitted format.
    UnsupportedCall,
    /// Envelope or selector mismatch, or malformed ABI.
    InvalidPayload,
    /// Opaque or unlimited denied.
    PolicyDenied,
    /// Broker's verifier or catalog changed after the review was frozen.
    ReviewChanged,
    /// A size or count bound was exceeded.
    LimitExceeded,
}

impl ReviewReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CatalogRejected => "CATALOG_REJECTED",
            Self::UnsupportedCall => "UNSUPPORTED_CALL",
            Self::InvalidPayload => "INVALID_PAYLOAD",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::ReviewChanged => "REVIEW_CHANGED",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
        }
    }

    /// One sentence the owner can act on.
    pub const fn owner_action(self) -> &'static str {
        match self {
            Self::CatalogRejected => {
                "This Broker build's catalog is invalid. Install a fixed build."
            }
            Self::UnsupportedCall => {
                "Bloom has no description of this call, so it cannot be shown in full."
            }
            Self::InvalidPayload => {
                "The transaction bytes do not match the description. Restage it."
            }
            Self::PolicyDenied => {
                "Wallet policy refuses this request. Change policy in a ceremony first."
            }
            Self::ReviewChanged => "Broker was upgraded. Prepare this approval again.",
            Self::LimitExceeded => "The request is larger than Bloom accepts.",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewError {
    pub reason: ReviewReason,
    pub detail: String,
}

impl ReviewError {
    pub fn new(reason: ReviewReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ReviewError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {} {}",
            self.reason.as_str(),
            self.detail,
            self.reason.owner_action()
        )
    }
}

impl std::error::Error for ReviewError {}

/// The review-wide clear-signing facts, frozen into the manifest beside the
/// per-payload calls.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSigningEvidence {
    pub assurance: String,
    pub verifier_id: String,
    /// The verifier and catalog this build compiled in. The catalog changes
    /// only with Broker, so this is the whole recheck.
    pub verifier_digest: String,
    /// Every entry this review used, complete, in selection order.
    pub entries: Vec<SelectedEntry>,
}

impl ClearSigningEvidence {
    pub fn new(verifier_digest: &Digest32, entries: Vec<SelectedEntry>, structural: bool) -> Self {
        let structural = structural || entries.iter().any(|entry| entry.instance.is_some());
        Self {
            assurance: if structural {
                STRUCTURAL_DESCRIPTION
            } else {
                TRUSTED_DESCRIPTION
            }
            .to_owned(),
            verifier_id: EVM_CLEAR_SIGNING_VERIFIER_ID.to_owned(),
            verifier_digest: verifier_digest.as_str().to_owned(),
            entries,
        }
    }

    /// A Broker upgrade between review and signing may read the same bytes
    /// differently, so it invalidates the review rather than carrying it.
    pub fn recheck(&self, verifier_digest: &Digest32) -> Result<(), ReviewError> {
        if self.verifier_digest != verifier_digest.as_str() {
            return Err(ReviewError::new(
                ReviewReason::ReviewChanged,
                "Broker's clear-signing verifier or catalog changed after this review was frozen",
            ));
        }
        Ok(())
    }
}
