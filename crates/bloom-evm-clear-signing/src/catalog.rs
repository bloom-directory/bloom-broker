//! The signed local catalog: the only thing Broker trusts about a deployment.
//!
//! ERC-7730 supplies *descriptions*. It supplies neither trust nor token
//! decimals, and a wallet cannot read the chain from inside a review. So a
//! publisher signs one snapshot that binds each contract address to the
//! flattened descriptor admitted for it, the action class of each admitted
//! function, and the token metadata amounts are formatted with. Broker
//! verifies that signature offline and never fetches anything.

use std::collections::BTreeSet;

use bloom_broker_api::{Base64UrlBytes, DecimalU64, Digest32, Token};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{AdmittedDescriptor, ReviewError, ReviewReason, admit, descriptor_digest};

pub const CATALOG_SCHEMA: &str = "bloom.clear-signing-catalog.1";
/// Versioned domain for the one catalog signature. This is a Bloom content
/// signature over the admitted snapshot, not an ERC-8176 attestation.
pub const CATALOG_SIGNATURE_DOMAIN: &[u8] = b"bloom-clear-signing-catalog/v1";

pub const CATALOG_MAX_BYTES: usize = 1024 * 1024;
pub const CATALOG_MAX_ENTRIES: usize = 1024;
pub const CATALOG_MAX_SIGNATURES: usize = 8;
pub const TOKEN_SYMBOL_MAX_BYTES: usize = 16;
pub const TOKEN_NAME_MAX_SCALARS: usize = 64;
pub const TOKEN_NAME_MAX_BYTES: usize = 256;
pub const DEFAULT_MAXIMUM_OBSERVATION_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// What a reviewed function is permitted to mean. The class is signed, and
/// Broker checks it against the canonical ERC-20 signature in both
/// directions: renaming `approve` cannot escape allowance policy, and
/// labelling an unrelated call `allowance` cannot borrow its screen.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    Transfer,
    Allowance,
    Other,
}

impl ActionClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Allowance => "allowance",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedFunction {
    /// The reviewed ERC-7730 display format key: a full function signature
    /// with parameter names. The selector is derived from it, never supplied.
    pub signature: String,
    pub action_class: ActionClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMetadata {
    pub decimals: u8,
    pub symbol: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub chain_id: DecimalU64,
    /// Lowercase `0x`-prefixed 20-byte address. The lookup key, and the only
    /// address form compared against the transaction destination.
    pub contract_address: String,
    pub admitted_functions: Vec<AdmittedFunction>,
    /// The flattened ERC-7730 document. Absent for a token-only entry that
    /// exists to supply decimals for another contract's `tokenAmount`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flattened_descriptor: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_digest: Option<Digest32>,
    /// Publisher assertions retained for comparison and provenance. Broker
    /// does not measure them against a chain and cannot certify them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_code_hash: Option<Digest32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_metadata: Option<TokenMetadata>,
    pub upgradeable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_hash: Option<Digest32>,
    /// When the publisher observed this deployment. Freshness is measured
    /// from here, so republishing an old observation does not renew it.
    pub observed_at_ms: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSignature {
    pub key_id: Token,
    pub signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSigningCatalog {
    pub schema: String,
    pub catalog_id: Token,
    pub sequence: DecimalU64,
    pub issued_at_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub entries: Vec<CatalogEntry>,
    pub signatures: Vec<CatalogSignature>,
}

/// One trusted signing key, as wallet policy pins it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedCatalogKey {
    pub key_id: Token,
    pub verifying_key: VerifyingKey,
}

impl ClearSigningCatalog {
    /// Signed content: everything except the signatures themselves.
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ReviewError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            schema: &'a str,
            catalog_id: &'a Token,
            sequence: &'a DecimalU64,
            issued_at_ms: &'a DecimalU64,
            expires_at_ms: &'a DecimalU64,
            entries: &'a [CatalogEntry],
        }
        serde_jcs::to_vec(&Unsigned {
            schema: &self.schema,
            catalog_id: &self.catalog_id,
            sequence: &self.sequence,
            issued_at_ms: &self.issued_at_ms,
            expires_at_ms: &self.expires_at_ms,
            entries: &self.entries,
        })
        .map_err(|error| {
            ReviewError::new(
                ReviewReason::CatalogRejected,
                format!("catalog canonicalization failed: {error}"),
            )
        })
    }

    /// The stored content identity. Two catalogs at the same sequence are the
    /// same catalog only if this matches.
    pub fn content_digest(&self) -> Result<Digest32, ReviewError> {
        Ok(Digest32::from_bytes(
            Sha256::digest(self.unsigned_canonical_bytes()?).into(),
        ))
    }

    fn validate_shape(&self) -> Result<(), ReviewError> {
        if self.schema != CATALOG_SCHEMA {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "catalog schema is unsupported",
            ));
        }
        if self.entries.len() > CATALOG_MAX_ENTRIES {
            return Err(ReviewError::new(
                ReviewReason::LimitExceeded,
                format!("catalog holds more than {CATALOG_MAX_ENTRIES} entries"),
            ));
        }
        if self.signatures.is_empty() || self.signatures.len() > CATALOG_MAX_SIGNATURES {
            return Err(ReviewError::new(
                ReviewReason::LimitExceeded,
                format!("catalog must carry 1-{CATALOG_MAX_SIGNATURES} signatures"),
            ));
        }
        if self.issued_at_ms.get() >= self.expires_at_ms.get() {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "catalog validity interval is empty",
            ));
        }
        let mut key_ids = BTreeSet::new();
        for signature in &self.signatures {
            if !key_ids.insert(signature.key_id.as_str()) {
                return Err(ReviewError::new(
                    ReviewReason::CatalogRejected,
                    "catalog repeats a signing key identity",
                ));
            }
        }
        let mut keys: Vec<(u64, &str)> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate_shape()?;
            keys.push((entry.chain_id.get(), entry.contract_address.as_str()));
        }
        // Sorted and unique: the signed snapshot has one deterministic order,
        // so a duplicate entry cannot shadow an earlier one during lookup.
        if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "catalog entries must be sorted and unique by chain and address",
            ));
        }
        Ok(())
    }

    /// Verify shape, bounds and signature threshold offline. `trusted` and
    /// `threshold` come from the wallet's authenticated policy; nothing here
    /// consults the network, the filesystem or the clock.
    pub fn accept(
        &self,
        encoded_bytes: usize,
        trusted: &[TrustedCatalogKey],
        threshold: usize,
    ) -> Result<AcceptedCatalog, ReviewError> {
        if encoded_bytes > CATALOG_MAX_BYTES {
            return Err(ReviewError::new(
                ReviewReason::LimitExceeded,
                format!("catalog exceeds {CATALOG_MAX_BYTES} bytes"),
            ));
        }
        self.validate_shape()?;
        if threshold == 0 || threshold > trusted.len() {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "policy signature threshold exceeds the number of trusted keys",
            ));
        }
        let mut message = CATALOG_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&self.unsigned_canonical_bytes()?);
        // Count each *trusted key* once, not each signature: a publisher that
        // repeats one key cannot reach a threshold of two.
        let mut satisfied = BTreeSet::new();
        for candidate in &self.signatures {
            let Some(key) = trusted
                .iter()
                .find(|trusted| trusted.key_id == candidate.key_id)
            else {
                continue;
            };
            let bytes: [u8; 64] = candidate.signature.decode().try_into().map_err(|_| {
                ReviewError::new(
                    ReviewReason::CatalogRejected,
                    "catalog signature must contain exactly 64 bytes",
                )
            })?;
            if key
                .verifying_key
                .verify(&message, &Signature::from_bytes(&bytes))
                .is_ok()
            {
                satisfied.insert(key.key_id.as_str().to_owned());
            }
        }
        if satisfied.len() < threshold {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                format!(
                    "catalog carries {} trusted signatures, below the required {threshold}",
                    satisfied.len()
                ),
            ));
        }
        // Admit every descriptor now, at import, rather than at review. An
        // entry Broker cannot read is an operator's problem to fix before a
        // ceremony, not a surprise while the owner is looking at one. A
        // digest match does not make an instruction supported, so both the
        // content identity and the full subset check run here.
        let mut admitted = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let Some(descriptor) = &entry.flattened_descriptor else {
                continue;
            };
            let expected = entry
                .descriptor_digest
                .as_ref()
                .expect("shape validation pairs descriptor and digest");
            if &descriptor_digest(descriptor)? != expected {
                return Err(ReviewError::new(
                    ReviewReason::CatalogRejected,
                    format!(
                        "descriptor content for {} differs from the digest the catalog signed",
                        entry.contract_address
                    ),
                ));
            }
            admitted.push((
                (entry.chain_id.get(), entry.contract_address.clone()),
                admit(
                    descriptor,
                    entry.chain_id.get(),
                    &entry.contract_address,
                    &entry.admitted_functions,
                )?,
            ));
        }
        Ok(AcceptedCatalog {
            content_digest: self.content_digest()?,
            catalog: self.clone(),
            admitted,
        })
    }
}

impl CatalogEntry {
    fn validate_shape(&self) -> Result<(), ReviewError> {
        if !is_canonical_address(&self.contract_address) {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "entry address must be lowercase 0x-prefixed 20 bytes",
            ));
        }
        if self.chain_id.get() == 0 {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "entry chain ID must be nonzero",
            ));
        }
        if self.upgradeable != self.implementation_hash.is_some() {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "an upgradeable entry requires an implementation hash, a direct one forbids it",
            ));
        }
        if self.flattened_descriptor.is_some() != self.descriptor_digest.is_some() {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "a descriptor and its digest are present together or not at all",
            ));
        }
        if self.admitted_functions.is_empty() != self.flattened_descriptor.is_none() {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "admitted functions require a descriptor, and a descriptor requires them",
            ));
        }
        let mut signatures = BTreeSet::new();
        for admitted in &self.admitted_functions {
            if !signatures.insert(admitted.signature.as_str()) {
                return Err(ReviewError::new(
                    ReviewReason::CatalogRejected,
                    "entry admits the same function signature twice",
                ));
            }
        }
        if let Some(metadata) = &self.token_metadata {
            metadata.validate_shape()?;
        }
        Ok(())
    }

    pub fn admitted(&self, signature: &str) -> Option<&AdmittedFunction> {
        self.admitted_functions
            .iter()
            .find(|admitted| admitted.signature == signature)
    }
}

impl TokenMetadata {
    fn validate_shape(&self) -> Result<(), ReviewError> {
        let symbol_ok = !self.symbol.is_empty()
            && self.symbol.len() <= TOKEN_SYMBOL_MAX_BYTES
            && self
                .symbol
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'<' && byte != b'>');
        let name_scalars = self.name.chars().count();
        let name_ok = !self.name.is_empty()
            && name_scalars <= TOKEN_NAME_MAX_SCALARS
            && self.name.len() <= TOKEN_NAME_MAX_BYTES
            && !self.name.chars().any(is_control_or_bidi);
        if !symbol_ok || !name_ok {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "token symbol or name is empty, oversized, or carries unsafe characters",
            ));
        }
        Ok(())
    }
}

/// A catalog that passed shape, bounds and signature checks. Freshness is
/// deliberately *not* checked here: the accepted snapshot is durable, and the
/// clock is consulted per review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedCatalog {
    pub catalog: ClearSigningCatalog,
    pub content_digest: Digest32,
    admitted: Vec<((u64, String), AdmittedDescriptor)>,
}

impl AcceptedCatalog {
    pub fn entry(&self, chain_id: u64, address: &str) -> Option<&CatalogEntry> {
        self.catalog
            .entries
            .iter()
            .find(|entry| entry.chain_id.get() == chain_id && entry.contract_address == address)
    }

    pub fn descriptor(&self, chain_id: u64, address: &str) -> Option<&AdmittedDescriptor> {
        self.admitted
            .iter()
            .find(|((entry_chain, entry_address), _)| {
                *entry_chain == chain_id && entry_address == address
            })
            .map(|(_, descriptor)| descriptor)
    }

    /// Reject a snapshot that is not yet issued or already expired. Both ends
    /// are checked, so a catalog dated in the future cannot pre-authorize.
    pub fn check_validity(&self, now_ms: u64) -> Result<(), ReviewError> {
        if now_ms < self.catalog.issued_at_ms.get() {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                "catalog is not yet valid",
            ));
        }
        if now_ms >= self.catalog.expires_at_ms.get() {
            return Err(ReviewError::new(
                ReviewReason::EvidenceExpired,
                "catalog has expired; import a newer signed snapshot",
            ));
        }
        Ok(())
    }
}

pub fn is_canonical_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_control_or_bidi(character: char) -> bool {
    character.is_control()
        || matches!(character,
            '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
