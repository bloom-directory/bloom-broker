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
//! that assertion and nothing more.

pub mod artifact;
mod catalog;
mod descriptor;
mod render;

pub use catalog::*;
pub use descriptor::*;
pub use render::*;

use bloom_broker_api::{Digest32, EVM_CLEAR_SIGNING_VERIFIER_ID};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Not `ProofVerified`: nothing here proves execution. A distinct class keeps
/// "a trusted publisher described this" from being read as "Bloom checked
/// what this call does".
pub const TRUSTED_DESCRIPTION: &str = "trusted_description";

/// The nine review outcomes. Each one is actionable on its own, and existing
/// transport and authority errors are reused wherever they already say the
/// same thing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewReason {
    /// No accepted catalog is loaded.
    CatalogUnavailable,
    /// Shape, descriptor subset or coverage, signature, trust, rollback or
    /// sequence conflict.
    CatalogRejected,
    /// The catalog expired, or an observation is older than policy allows.
    EvidenceExpired,
    /// No matching chain, address or admitted format, or missing metadata.
    UnsupportedCall,
    /// Envelope or selector mismatch, or malformed ABI.
    InvalidPayload,
    /// Opaque or unlimited denied, or the requested expiry exceeds the bound.
    PolicyDenied,
    /// Frozen policy, selected entry or verifier no longer matches.
    ReviewChanged,
    /// An existing or new size or count bound was exceeded.
    LimitExceeded,
    /// The authority clock cannot authorize.
    ClockUntrusted,
}

impl ReviewReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CatalogUnavailable => "CATALOG_UNAVAILABLE",
            Self::CatalogRejected => "CATALOG_REJECTED",
            Self::EvidenceExpired => "EVIDENCE_EXPIRED",
            Self::UnsupportedCall => "UNSUPPORTED_CALL",
            Self::InvalidPayload => "INVALID_PAYLOAD",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::ReviewChanged => "REVIEW_CHANGED",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::ClockUntrusted => "CLOCK_UNTRUSTED",
        }
    }

    /// One sentence the owner can act on.
    pub const fn owner_action(self) -> &'static str {
        match self {
            Self::CatalogUnavailable => {
                "Import a signed clear-signing catalog before approving contract calls."
            }
            Self::CatalogRejected => {
                "The catalog was refused. Import a snapshot signed by the keys this wallet trusts."
            }
            Self::EvidenceExpired => "Import a newer signed catalog and prepare the call again.",
            Self::UnsupportedCall => {
                "Bloom has no signed description of this call, so it cannot be shown in full."
            }
            Self::InvalidPayload => {
                "The transaction bytes do not match the description. Restage it."
            }
            Self::PolicyDenied => {
                "Wallet policy refuses this request. Change policy in a ceremony first."
            }
            Self::ReviewChanged => "The catalog or policy changed. Prepare this approval again.",
            Self::LimitExceeded => "The request or catalog is larger than Bloom accepts.",
            Self::ClockUntrusted => "Bloom cannot establish trusted time. Repair the clock first.",
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

/// Bloom's content identity for a flattened descriptor: SHA-256 over the same
/// canonical JSON the catalog signature covers. It is not an ERC-8176
/// attestation hash, and it is not a claim that upstream text was unchanged.
pub fn descriptor_digest(descriptor: &serde_json::Value) -> Result<Digest32, ReviewError> {
    let bytes = serde_jcs::to_vec(descriptor).map_err(|error| {
        ReviewError::new(
            ReviewReason::CatalogRejected,
            format!("descriptor canonicalization failed: {error}"),
        )
    })?;
    Ok(Digest32::from_bytes(Sha256::digest(bytes).into()))
}

/// The review-wide clear-signing facts, frozen into the manifest beside the
/// per-payload calls. Activation and signing re-read these against the
/// current catalog and policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSigningEvidence {
    pub assurance: String,
    pub verifier_id: String,
    pub verifier_digest: String,
    pub catalog_id: String,
    pub catalog_sequence: String,
    pub catalog_digest: String,
    pub catalog_expires_at_ms: String,
    /// Every entry this review used, complete, in selection order.
    pub entries: Vec<SelectedEntry>,
}

impl ClearSigningEvidence {
    pub fn new(
        catalog: &AcceptedCatalog,
        verifier_digest: &Digest32,
        entries: Vec<SelectedEntry>,
    ) -> Self {
        Self {
            assurance: TRUSTED_DESCRIPTION.to_owned(),
            verifier_id: EVM_CLEAR_SIGNING_VERIFIER_ID.to_owned(),
            verifier_digest: verifier_digest.as_str().to_owned(),
            catalog_id: catalog.catalog.catalog_id.as_str().to_owned(),
            catalog_sequence: catalog.catalog.sequence.as_str().to_owned(),
            catalog_digest: catalog.content_digest.as_str().to_owned(),
            catalog_expires_at_ms: catalog.catalog.expires_at_ms.as_str().to_owned(),
            entries,
        }
    }

    /// The latest instant this evidence can still authorize: the catalog's
    /// own expiry, and each used observation plus the policy's maximum age.
    /// Checked arithmetic, so a large configured age cannot wrap into the past.
    pub fn permitted_expiry_ms(&self, maximum_observation_age_ms: u64) -> u64 {
        let mut bound = self.catalog_expires_at_ms.parse::<u64>().unwrap_or(0);
        for entry in &self.entries {
            let observed = entry.observed_at_ms.parse::<u64>().unwrap_or(0);
            bound = bound.min(observed.saturating_add(maximum_observation_age_ms));
        }
        bound
    }

    /// Re-resolve every selected entry against a currently accepted catalog.
    /// Withdrawal, a changed entry (including a changed observation time), a
    /// changed catalog identity or a changed verifier all invalidate the
    /// review rather than silently carrying it forward.
    pub fn recheck(
        &self,
        catalog: Option<&AcceptedCatalog>,
        verifier_digest: &Digest32,
        now_ms: u64,
        maximum_observation_age_ms: u64,
    ) -> Result<(), ReviewError> {
        if self.verifier_digest != verifier_digest.as_str() {
            return Err(ReviewError::new(
                ReviewReason::ReviewChanged,
                "the compiled clear-signing verifier changed after this review was frozen",
            ));
        }
        let catalog = catalog.ok_or_else(|| {
            ReviewError::new(
                ReviewReason::CatalogUnavailable,
                "no accepted catalog is loaded",
            )
        })?;
        if catalog.catalog.catalog_id.as_str() != self.catalog_id {
            return Err(ReviewError::new(
                ReviewReason::ReviewChanged,
                "wallet policy now trusts a different catalog",
            ));
        }
        catalog.check_validity(now_ms)?;
        for frozen in &self.entries {
            let chain_id = frozen.chain_id.parse::<u64>().unwrap_or(0);
            let current = catalog
                .entry(chain_id, &frozen.contract_address)
                .map(SelectedEntry::of)
                .ok_or_else(|| {
                    ReviewError::new(
                        ReviewReason::ReviewChanged,
                        format!(
                            "{} was withdrawn from the catalog after this review",
                            frozen.contract_address
                        ),
                    )
                })?;
            if &current != frozen {
                return Err(ReviewError::new(
                    ReviewReason::ReviewChanged,
                    format!(
                        "the catalog entry for {} changed after this review",
                        frozen.contract_address
                    ),
                ));
            }
            let observed = frozen.observed_at_ms.parse::<u64>().unwrap_or(0);
            if now_ms > observed.saturating_add(maximum_observation_age_ms) {
                return Err(ReviewError::new(
                    ReviewReason::EvidenceExpired,
                    format!(
                        "the publisher's observation of {} is older than wallet policy allows",
                        frozen.contract_address
                    ),
                ));
            }
        }
        Ok(())
    }
}
