use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Base64UrlBytes, CryptoSuite, DecimalU64, DerivationProfile, DerivedAccountRequest, Digest32,
    KeyRef, KeySpec, OperationId, PetalKeyScope, ProtocolError, ProtocolErrorCode, Token,
    WalletSeedProfile,
};

const ENCRYPTED_BROWSER_RESULT_MAX_BYTES: usize = 4 * 1024;
const ACCOUNT_TERMS_REQUEST_DOMAIN: &[u8] = b"bloom-account-terms-request/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedBrowserResult {
    pub kem_output: Base64UrlBytes,
    pub ciphertext: Base64UrlBytes,
}

impl<'de> Deserialize<'de> for EncryptedBrowserResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            kem_output: Base64UrlBytes,
            ciphertext: Base64UrlBytes,
        }
        let unchecked = Unchecked::deserialize(deserializer)?;
        let value = Self {
            kem_output: unchecked.kem_output,
            ciphertext: unchecked.ciphertext,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl EncryptedBrowserResult {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let length = self
            .kem_output
            .decode()
            .len()
            .checked_add(self.ciphertext.decode().len())
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::LimitExceededFrame,
                    "HPKE envelope length overflow",
                )
            })?;
        if length > ENCRYPTED_BROWSER_RESULT_MAX_BYTES {
            return Err(ProtocolError::new(
                ProtocolErrorCode::LimitExceededFrame,
                "decoded HPKE envelope exceeds 4 KiB",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyKind {
    SealedApproval,
    WalletRegistration,
    WalletImport,
    WalletExport,
    WalletDelete,
    WalletRecovery,
    CredentialAdd,
    CredentialReplace,
    CredentialRemove,
    BackendEnrollment,
    KeyDerive,
    AccountAllocate,
    AccountRetire,
    PolicyUpdate,
}

/// A caller can ask for a specific existing surface. The default is resolved by
/// Broker from authenticated Signer exposure state and its own readiness;
/// callers cannot name or create a ceremony origin.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonySurfaceSelection {
    #[default]
    Default,
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyExposureMode {
    RemoteEnabled,
    LocalhostOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyExposureStage {
    Unprovisioned,
    CertificatePending,
    RoutingPending,
    Enabled,
    LocalhostOnly,
    Degraded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyExposureStatus {
    pub desired_mode: CeremonyExposureMode,
    pub desired_revision: DecimalU64,
    pub effective_mode: CeremonyExposureMode,
    pub effective_revision: DecimalU64,
    pub local_origin: String,
    pub remote_origin: Option<String>,
    pub remote_tls_ready: bool,
    pub remote_routing_ready: bool,
    pub stage: CeremonyExposureStage,
}

/// Begin an authority-first passkey enrollment on the other existing origin.
/// `destination` must be explicit; Broker resolves both immutable Signer refs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyCrossSurfacePrepareRequest {
    pub operation_id: OperationId,
    pub wallet_id: Token,
    pub destination: CeremonySurfaceSelection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyCrossSurfacePrepareResponse {
    pub operation_id: OperationId,
    pub ceremony_id: Digest32,
    pub state: crate::CeremonyState,
    pub destination_url: String,
    pub expires_at_ms: DecimalU64,
}

/// Public projection of Signer's exact immutable surface binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonySurfaceRef {
    pub surface_id: Token,
    pub identity_digest: Digest32,
}

impl CeremonySurfaceSelection {
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }
}

impl CeremonyKind {
    pub const fn successful_terminal_state(self) -> Option<crate::CeremonyState> {
        match self {
            Self::SealedApproval => None,
            Self::WalletRegistration => Some(crate::CeremonyState::Completed),
            _ => Some(crate::CeremonyState::Succeeded),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedApprovalPrepareResponse {
    pub approval_id: Digest32,
    pub state: ApprovalPrepareState,
    pub ceremony_url: String,
    pub ceremony_expires_at_ms: DecimalU64,
    pub review_manifest_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovalPrepareState {
    #[serde(rename = "AWAITING_CEREMONY")]
    AwaitingCeremony,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyPasskeyMigrationPublic {
    pub schema: Token,
    pub wallet_name: Token,
    pub address: String,
    pub public_key_fingerprint: Digest32,
    pub credential_id_fingerprint: Digest32,
    pub legacy_format_version: u8,
    pub bundle_digest: Digest32,
    pub policy_mode: Token,
}

impl LegacyPasskeyMigrationPublic {
    pub fn terms_digest(&self, operation_id: &OperationId) -> Result<Digest32, ProtocolError> {
        #[derive(Serialize)]
        struct Terms<'a> {
            schema: &'a Token,
            operation_id: &'a OperationId,
            wallet_name: &'a Token,
            address: &'a str,
            public_key_fingerprint: &'a Digest32,
            credential_id_fingerprint: &'a Digest32,
            legacy_format_version: u8,
            bundle_digest: &'a Digest32,
            policy_mode: &'a Token,
        }
        Ok(Digest32::from_bytes(
            Sha256::digest(
                serde_jcs::to_vec(&Terms {
                    schema: &self.schema,
                    operation_id,
                    wallet_name: &self.wallet_name,
                    address: &self.address,
                    public_key_fingerprint: &self.public_key_fingerprint,
                    credential_id_fingerprint: &self.credential_id_fingerprint,
                    legacy_format_version: self.legacy_format_version,
                    bundle_digest: &self.bundle_digest,
                    policy_mode: &self.policy_mode,
                })
                .map_err(canonical_error)?,
            )
            .into(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyPrepareRequest {
    pub ceremony_kind: CeremonyKind,
    #[serde(default, skip_serializing_if = "CeremonySurfaceSelection::is_default")]
    pub surface_selection: CeremonySurfaceSelection,
    pub custody_operation_id: OperationId,
    /// The authoritative wallet ID. New registrations and ordinary imports
    /// require the caller-selected ID; legacy migration derives it from the
    /// authenticated migration receipt instead.
    pub wallet_id: Option<Token>,
    pub key_ref: Option<KeyRef>,
    pub exact_terms_digest: Digest32,
    pub expected_input_class: Token,
    pub browser_output_recipient_key: Option<Base64UrlBytes>,
    #[serde(default)]
    pub petal_key_scope: Option<PetalKeyScope>,
    #[serde(default)]
    pub legacy_passkey_migration: Option<LegacyPasskeyMigrationPublic>,
    /// Selected root seed profile for wallet registration/import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_seed_profile: Option<crate::WalletSeedProfile>,
    /// Family allocation requests (AccountAllocate custody only). Signer
    /// allocates every requested family under one number.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derivation_requests: Vec<crate::DerivedAccountRequest>,
    /// Exact allocation/retirement terms (AccountAllocate/AccountRetire only).
    /// `exact_terms_digest` must equal `AccountTerms::request_digest` so the
    /// reviewed terms, not an opaque caller string, bind the ceremony.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_terms: Option<AccountTerms>,
}

impl CustodyPrepareRequest {
    pub fn validate_wallet_creation_binding(&self) -> Result<(), ProtocolError> {
        if !matches!(
            self.ceremony_kind,
            CeremonyKind::WalletRegistration | CeremonyKind::WalletImport
        ) {
            if self.wallet_seed_profile.is_some() {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::CeremonyKindMismatch,
                    "wallet_seed_profile is valid only for registration and import",
                ));
            }
            if !self.derivation_requests.is_empty() {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::CeremonyKindMismatch,
                    "derivation_requests are valid only for AccountAllocate",
                ));
            }
            return Ok(());
        }
        if self.key_ref.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "wallet creation derives its root KeyRef inside Signer",
            ));
        }
        let legacy_import = self.ceremony_kind == CeremonyKind::WalletImport
            && self.legacy_passkey_migration.is_some();
        if self.wallet_id.is_none() && !legacy_import {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "wallet registration and ordinary import require an authoritative wallet ID",
            ));
        }
        if self.wallet_id.is_some() && legacy_import {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "legacy migration wallet ID must come from its authenticated receipt",
            ));
        }
        Ok(())
    }

    pub fn validate_legacy_passkey_migration_binding(&self) -> Result<(), ProtocolError> {
        let Some(migration) = &self.legacy_passkey_migration else {
            if self.expected_input_class.as_str() == "legacy_passkey_v1_prf" {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::MalformedFrame,
                    "legacy passkey input class requires public migration terms",
                ));
            }
            return Ok(());
        };
        if self.ceremony_kind != CeremonyKind::WalletImport
            || self.expected_input_class.as_str() != "legacy_passkey_v1_prf"
            || self.wallet_id.is_some()
            || self.key_ref.is_some()
            || self.petal_key_scope.is_some()
            || migration.schema.as_str() != "bloom.legacy_passkey_migration_receipt.v1"
            || migration.policy_mode.as_str() != "restrictive_current_policy"
            || migration.legacy_format_version != 1
            || self.exact_terms_digest != migration.terms_digest(&self.custody_operation_id)?
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "legacy passkey migration terms do not match the custody request",
            ));
        }
        Ok(())
    }

    pub fn validate_petal_key_scope_binding(&self) -> Result<(), ProtocolError> {
        let Some(scope) = &self.petal_key_scope else {
            return Ok(());
        };
        if self.ceremony_kind != CeremonyKind::KeyDerive {
            return Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "Petal key scope is valid only for key-derive custody",
            ));
        }
        if !self.derivation_requests.is_empty() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "derivation_requests are valid only for AccountAllocate",
            ));
        }
        scope.validate()?;
        if scope.custody_operation_id != self.custody_operation_id {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "Petal key scope custody operation does not match the request",
            ));
        }
        if self.wallet_id.as_ref() != Some(&scope.wallet_id) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "Petal key scope wallet does not match the custody request",
            ));
        }
        if self.key_ref.as_ref() != Some(&scope.parent_key_ref) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "Petal key scope parent KeyRef does not match the custody request",
            ));
        }
        if self.exact_terms_digest != scope.request_digest()? {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "key-derive exact terms digest does not match the Petal key scope",
            ));
        }
        if self.browser_output_recipient_key.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "Petal key derivation cannot return Browser-provided key material",
            ));
        }
        Ok(())
    }

    /// Account allocation requires a derivation profile this Broker
    /// projects, an authoritative wallet, no pinned root KeyRef, and exact
    /// terms that bind every reviewed fact of the allocation.
    pub fn validate_account_allocation_binding(&self) -> Result<(), ProtocolError> {
        if self.ceremony_kind != CeremonyKind::AccountAllocate {
            return Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "account allocation binding is valid only for AccountAllocate",
            ));
        }
        validate_derivation_requests(&self.derivation_requests)?;
        if self.wallet_id.is_none() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "AccountAllocate requires an authoritative wallet ID",
            ));
        }
        if self.key_ref.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "account allocation derives its child KeyRef inside Signer",
            ));
        }
        let terms = self.validate_account_terms_common()?;
        if terms.retire_key_fingerprint.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "allocation terms cannot carry a retirement fingerprint",
            ));
        }
        if terms.derivations != self.derivation_requests {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "account terms derivations do not match the custody request",
            ));
        }
        Ok(())
    }

    /// Account retirement requires the derived-account KeyRef, an
    /// authoritative wallet, and exact terms naming the same child. The
    /// caller can never retire the root or a legacy key through this
    /// ceremony.
    pub fn validate_account_retire_binding(&self) -> Result<(), ProtocolError> {
        if self.ceremony_kind != CeremonyKind::AccountRetire {
            return Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "account retire binding is valid only for AccountRetire",
            ));
        }
        let Some(key_ref) = &self.key_ref else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "AccountRetire requires the derived-account KeyRef",
            ));
        };
        if self.wallet_id.is_none() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "AccountRetire requires an authoritative wallet ID",
            ));
        }
        if !self.derivation_requests.is_empty() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "AccountRetire cannot carry a derivation request",
            ));
        }
        let Some(crate::DerivationRef::Bip39Multicurve {
            wallet_seed_ref,
            profile,
            ..
        }) = key_ref.derivation.clone()
        else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "AccountRetire requires a derived bip39 child KeyRef",
            ));
        };
        if Some(&wallet_seed_ref) != self.wallet_id.as_ref() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "retired child KeyRef belongs to a different wallet",
            ));
        }
        let terms = self.validate_account_terms_common()?;
        if !terms.derivations.is_empty() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "retirement terms cannot carry a derivation request",
            ));
        }
        if terms.retire_key_fingerprint != Some(key_ref.public_key_fingerprint.clone()) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "retirement terms fingerprint does not match the custody request",
            ));
        }
        if terms.path_template != profile.path_template()
            || terms.key_spec != profile.key_spec()
            || terms.key_spec != key_ref.key_spec
            || terms.allowed_crypto_suites != profile.frozen_crypto_suites()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "retirement terms do not match the child's derivation profile",
            ));
        }
        Ok(())
    }

    /// Cross-ceremony invariants shared by allocation and retirement: the
    /// structured terms exist, agree with the custody request, are frozen to
    /// one seed profile, and digest to `exact_terms_digest`.
    fn validate_account_terms_common(&self) -> Result<&AccountTerms, ProtocolError> {
        let Some(terms) = &self.account_terms else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "account custody requires structured exact terms",
            ));
        };
        terms.validate()?;
        if Some(&terms.wallet_id) != self.wallet_id.as_ref() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "account terms wallet does not match the custody request",
            ));
        }
        if terms.replay_id != self.custody_operation_id {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "account terms replay identity does not match the custody operation",
            ));
        }
        if self.exact_terms_digest != terms.request_digest()? {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "exact terms digest does not match the structured account terms",
            ));
        }
        if self.wallet_seed_profile.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "account custody never selects a wallet seed profile",
            ));
        }
        if self.petal_key_scope.is_some() || self.legacy_passkey_migration.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "account custody cannot carry petal or legacy migration terms",
            ));
        }
        Ok(terms)
    }
}

/// The family request list contains one or two unique profiles and no pinned
/// account. Signer chooses the one number every family shares.
fn validate_derivation_requests(requests: &[DerivedAccountRequest]) -> Result<(), ProtocolError> {
    if requests.is_empty() || requests.len() > 2 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            "account allocation requires one or two derivation requests",
        ));
    }
    let mut profiles = std::collections::HashSet::new();
    for request in requests {
        if !profiles.insert(request.derivation_profile) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "multi-family allocation repeats a derivation profile",
            ));
        }
        if request.account.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "multi-family allocation never pins an account; Signer chooses the number",
            ));
        }
    }
    Ok(())
}

/// Exact, reviewed terms for derived-account allocation and retirement.
///
/// These are the facts the human approves in the ceremony: which wallet and
/// seed profile, which derivation profile and role, the frozen path template
/// and key material shape, the policy/revocation baseline the ceremony runs
/// under, and the replay/expiry/audit identity. `request_digest` is the JCS
/// digest that must equal `CustodyPrepareRequest::exact_terms_digest`, so
/// the browser-bound `public_binding_digest` covers exactly these fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountTerms {
    /// Fixed: `bloom.account_terms.v1`.
    pub schema: Token,
    pub wallet_id: Token,
    /// Only `bip39-multicurve-v1` wallets expose derivable accounts.
    pub seed_profile: WalletSeedProfile,
    /// Allocation only: the committed family derivation requests. The
    /// global `path_template`, `key_spec` and `allowed_crypto_suites` describe
    /// the EVM family when one is requested, otherwise the Solana family;
    /// every listed family's frozen shape follows from its profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derivations: Vec<DerivedAccountRequest>,
    /// Retirement only: fingerprint of the child being retired. `None` for
    /// allocation.
    pub retire_key_fingerprint: Option<Digest32>,
    /// Frozen path template of the derivation profile; commits the
    /// namespace (coin type) and path shape before any child exists.
    pub path_template: String,
    pub key_spec: KeySpec,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
    /// Wallet policy version this ceremony is authorized under.
    pub policy_version: DecimalU64,
    /// Broker wallet revocation epoch at prepare time.
    pub revocation_epoch: DecimalU64,
    /// Replay identity; must equal the custody operation ID.
    pub replay_id: OperationId,
    pub expires_at_ms: DecimalU64,
    /// Human-readable audit purpose token for this ceremony.
    pub audit_purpose: Token,
}

pub const ACCOUNT_TERMS_SCHEMA: &str = "bloom.account_terms.v1";

impl AccountTerms {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema.as_str() != ACCOUNT_TERMS_SCHEMA {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "account terms schema is unrecognized",
            ));
        }
        if self.seed_profile != WalletSeedProfile::Bip39MulticurveV1 {
            return Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "account terms require the bip39-multicurve-v1 seed profile",
            ));
        }
        let several = self.derivations.as_slice();
        if several.is_empty() == self.retire_key_fingerprint.is_none() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "account terms carry either derivations or a retirement fingerprint",
            ));
        }
        if !several.is_empty() {
            validate_derivation_requests(several)?;
            // The reviewed global shape is the EVM family's when the request
            // includes one, otherwise the one Solana family's.
            let anchor = several
                .iter()
                .find(|request| {
                    request.derivation_profile == DerivationProfile::Bip44EvmSecp256k1V1
                })
                .unwrap_or(&several[0]);
            let profile = anchor.derivation_profile;
            if self.path_template != profile.path_template()
                || self.key_spec != profile.key_spec()
                || self.allowed_crypto_suites != profile.frozen_crypto_suites()
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "account terms do not match the derivation profile's frozen shape",
                ));
            }
        }
        if self.allowed_crypto_suites.is_empty() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "account terms must allow at least one crypto suite",
            ));
        }
        if self.policy_version.get() == 0 {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "account terms policy version must be nonzero",
            ));
        }
        if self.expires_at_ms.get() == 0 {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "account terms expiry must be nonzero",
            ));
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<Digest32, ProtocolError> {
        // Hash the terms themselves. A hand-built mirror of this struct used
        // to stand in for it, listing every field again in the same order; a
        // field added here and forgotten there would have dropped silently
        // out of the digest the owner's ceremony binds, with nothing to catch
        // it. JCS canonicalises regardless of declaration order, so hashing
        // `self` is both simpler and impossible to under-cover.
        let mut hasher = Sha256::new();
        hasher.update(ACCOUNT_TERMS_REQUEST_DOMAIN);
        hasher.update(serde_jcs::to_vec(self).map_err(canonical_error)?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyPrepareResponse {
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    pub state: CustodyPrepareState,
    pub ceremony_url: String,
    pub ceremony_expires_at_ms: DecimalU64,
    pub signer_contribution_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CustodyPrepareState {
    #[serde(rename = "AWAITING_USER")]
    AwaitingUser,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<CeremonySurfaceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_authority_generation: Option<DecimalU64>,
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    pub public_status: crate::CeremonyState,
    pub wallet_id: Option<Token>,
    pub public_key_refs: Vec<KeyRef>,
    pub credential_summaries: Vec<CredentialSummary>,
    pub initial_policy: Option<crate::SignedPolicySnapshot>,
    pub receipt_digest: Digest32,
    pub encrypted_browser_result: Option<EncryptedBrowserResult>,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSummary {
    pub credential_id: Base64UrlBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<CeremonySurfaceRef>,
    pub rp_id: RpId,
    pub active: bool,
}

/// A WebAuthn relying-party identifier encoded as a lowercase DNS name.
///
/// DNS labels may begin with a digit, unlike the generic protocol [`Token`].
/// Signer remains the authority for which validated RP ID belongs to a
/// credential; this type preserves that value in the public Machine receipt.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RpId(String);

impl RpId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 253
            || value.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
                    || !label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    || !label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
            })
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "WebAuthn RP ID must be a lowercase DNS name",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RpId {
    type Error = ProtocolError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RpId> for String {
    fn from(value: RpId) -> Self {
        value.0
    }
}

impl CustodyResult {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            surface: &'a Option<CeremonySurfaceRef>,
            #[serde(skip_serializing_if = "Option::is_none")]
            credential_authority_generation: &'a Option<DecimalU64>,
            ceremony_kind: CeremonyKind,
            custody_operation_id: &'a OperationId,
            public_status: crate::CeremonyState,
            wallet_id: &'a Option<Token>,
            public_key_refs: &'a [KeyRef],
            credential_summaries: &'a [CredentialSummary],
            initial_policy: &'a Option<crate::SignedPolicySnapshot>,
            receipt_digest: &'a Digest32,
            encrypted_browser_result: &'a Option<EncryptedBrowserResult>,
            signer_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            surface: &self.surface,
            credential_authority_generation: &self.credential_authority_generation,
            ceremony_kind: self.ceremony_kind,
            custody_operation_id: &self.custody_operation_id,
            public_status: self.public_status,
            wallet_id: &self.wallet_id,
            public_key_refs: &self.public_key_refs,
            credential_summaries: &self.credential_summaries,
            initial_policy: &self.initial_policy,
            receipt_digest: &self.receipt_digest,
            encrypted_browser_result: &self.encrypted_browser_result,
            signer_key_id: &self.signer_key_id,
        })
        .map_err(canonical_error)
    }
}

fn canonical_error(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_accepts_digit_leading_dns_labels_and_round_trips_as_a_string() {
        let hostname = "5ixwab6amyu7e42fjobm3myxqe.relay.bloom.directory";
        let rp_id = RpId::new(hostname).unwrap();
        assert_eq!(rp_id.as_str(), hostname);
        assert_eq!(
            serde_json::to_string(&rp_id).unwrap(),
            format!("\"{hostname}\"")
        );
        assert_eq!(
            serde_json::from_str::<RpId>(&format!("\"{hostname}\"")).unwrap(),
            rp_id
        );

        for invalid in [
            "Relay.example",
            "-relay.example",
            "relay-.example",
            "relay..example",
        ] {
            assert!(RpId::new(invalid).is_err(), "accepted {invalid}");
        }
    }

    fn registration_prepare(wallet_id: Option<Token>) -> CustodyPrepareRequest {
        CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::WalletRegistration,
            surface_selection: CeremonySurfaceSelection::Default,
            custody_operation_id: OperationId::from_bytes([1; 32]),
            wallet_id,
            key_ref: None,
            exact_terms_digest: Digest32::from_bytes([2; 32]),
            expected_input_class: Token::new("passkey-prf").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
            wallet_seed_profile: None,
            derivation_requests: Vec::new(),
            account_terms: None,
        }
    }

    #[test]
    fn new_wallet_creation_requires_its_authoritative_id() {
        assert!(
            registration_prepare(Some(Token::new("quiet-lilac").unwrap()))
                .validate_wallet_creation_binding()
                .is_ok()
        );
        assert_eq!(
            registration_prepare(None)
                .validate_wallet_creation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );
    }

    fn allocation_terms() -> AccountTerms {
        AccountTerms {
            schema: Token::new(ACCOUNT_TERMS_SCHEMA).unwrap(),
            wallet_id: Token::new("quiet-lilac").unwrap(),
            seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            derivations: vec![DerivedAccountRequest {
                derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
                requested_role: Token::new("primary-evm").unwrap(),
                account: None,
            }],
            retire_key_fingerprint: None,
            path_template: DerivationProfile::Bip44EvmSecp256k1V1
                .path_template()
                .to_owned(),
            key_spec: KeySpec::Secp256k1,
            allowed_crypto_suites: DerivationProfile::Bip44EvmSecp256k1V1
                .frozen_crypto_suites()
                .to_vec(),
            policy_version: DecimalU64::new(1),
            revocation_epoch: DecimalU64::new(1),
            replay_id: OperationId::from_bytes([3; 32]),
            expires_at_ms: DecimalU64::new(60_000),
            audit_purpose: Token::new("allocate-derived-account").unwrap(),
        }
    }

    fn allocate_prepare(terms: AccountTerms) -> CustodyPrepareRequest {
        let mut request = registration_prepare(Some(terms.wallet_id.clone()));
        request.ceremony_kind = CeremonyKind::AccountAllocate;
        request.custody_operation_id = terms.replay_id.clone();
        request.expected_input_class = Token::new("generic-custody-v1").unwrap();
        request.derivation_requests = terms.derivations.clone();
        request.exact_terms_digest = terms.request_digest().unwrap();
        request.account_terms = Some(terms);
        request
    }

    fn multi_family_terms(requests: Vec<DerivedAccountRequest>) -> AccountTerms {
        let anchor = requests
            .iter()
            .find(|request| request.derivation_profile == DerivationProfile::Bip44EvmSecp256k1V1)
            .unwrap_or(&requests[0]);
        let profile = anchor.derivation_profile;
        AccountTerms {
            schema: Token::new(ACCOUNT_TERMS_SCHEMA).unwrap(),
            wallet_id: Token::new("quiet-lilac").unwrap(),
            seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            derivations: requests,
            retire_key_fingerprint: None,
            path_template: profile.path_template().to_owned(),
            key_spec: profile.key_spec(),
            allowed_crypto_suites: profile.frozen_crypto_suites().to_vec(),
            policy_version: DecimalU64::new(1),
            revocation_epoch: DecimalU64::new(1),
            replay_id: OperationId::from_bytes([4; 32]),
            expires_at_ms: DecimalU64::new(60_000),
            audit_purpose: Token::new("allocate-derived-account").unwrap(),
        }
    }

    fn evm_request() -> DerivedAccountRequest {
        DerivedAccountRequest {
            derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
            requested_role: Token::new("primary-evm").unwrap(),
            account: None,
        }
    }

    fn solana_request() -> DerivedAccountRequest {
        DerivedAccountRequest {
            derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            requested_role: Token::new("solana-account").unwrap(),
            account: None,
        }
    }

    #[test]
    fn multi_family_allocation_binding_accepts_the_reviewed_list() {
        let terms = multi_family_terms(vec![evm_request(), solana_request()]);
        allocate_prepare(terms)
            .validate_account_allocation_binding()
            .unwrap();
    }

    #[test]
    fn multi_family_allocation_binding_rejects_bad_shapes() {
        let neither = multi_family_terms(vec![evm_request(), solana_request()]);
        let mut neither = allocate_prepare(neither);
        neither.derivation_requests = Vec::new();
        assert_eq!(
            neither
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );

        let duplicated = multi_family_terms(vec![evm_request(), evm_request()]);
        assert_eq!(
            allocate_prepare(duplicated)
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );

        let pinned = multi_family_terms(vec![
            DerivedAccountRequest {
                derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
                requested_role: Token::new("primary-evm").unwrap(),
                account: Some(0),
            },
            solana_request(),
        ]);
        assert_eq!(
            allocate_prepare(pinned)
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );

        let nonzero_evm = multi_family_terms(vec![DerivedAccountRequest {
            derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
            requested_role: Token::new("secondary-evm").unwrap(),
            account: Some(1),
        }]);
        assert_eq!(
            allocate_prepare(nonzero_evm)
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );

        let divergent_terms = multi_family_terms(vec![evm_request(), solana_request()]);
        let mut divergent = allocate_prepare(divergent_terms);
        divergent.derivation_requests = vec![evm_request()];
        assert_eq!(
            divergent
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );
    }

    #[test]
    fn account_terms_never_mix_derivations_with_a_retirement_fingerprint() {
        // The list form of the allocation half must satisfy the same
        // either-or rule as the single form: carrying derivations together
        // with a retirement fingerprint is malformed, and so is carrying
        // neither.
        let mut mixed = multi_family_terms(vec![evm_request(), solana_request()]);
        mixed.retire_key_fingerprint = Some(Digest32::from_bytes([7; 32]));
        assert_eq!(
            mixed.validate().unwrap_err().code,
            ProtocolErrorCode::MalformedFrame
        );

        let mut empty = multi_family_terms(vec![evm_request(), solana_request()]);
        empty.derivations = Vec::new();
        assert_eq!(
            empty.validate().unwrap_err().code,
            ProtocolErrorCode::MalformedFrame
        );
    }

    #[test]
    fn one_family_allocation_uses_the_list_shape() {
        let terms = multi_family_terms(vec![evm_request()]);
        allocate_prepare(terms)
            .validate_account_allocation_binding()
            .unwrap();
    }

    fn retire_prepare(terms: AccountTerms, fingerprint: Digest32) -> CustodyPrepareRequest {
        let mut request = registration_prepare(Some(terms.wallet_id.clone()));
        request.ceremony_kind = CeremonyKind::AccountRetire;
        request.custody_operation_id = terms.replay_id.clone();
        request.expected_input_class = Token::new("generic-custody-v1").unwrap();
        request.key_ref = Some(KeyRef {
            backend: Token::new("local").unwrap(),
            backend_instance: Token::new("quiet-lilac").unwrap(),
            locator: "wallet/quiet-lilac/child-evm-0".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: fingerprint,
            derivation: Some(crate::DerivationRef::Bip39Multicurve {
                wallet_seed_ref: Token::new("quiet-lilac").unwrap(),
                profile: DerivationProfile::Bip44EvmSecp256k1V1,
                path: "m/44'/60'/0'/0/0".into(),
            }),
        });
        request.exact_terms_digest = terms.request_digest().unwrap();
        request.account_terms = Some(terms);
        request
    }

    #[test]
    fn allocation_terms_bind_every_reviewed_fact() {
        let terms = allocation_terms();
        allocate_prepare(terms.clone())
            .validate_account_allocation_binding()
            .unwrap();

        let mut stale_digest = allocate_prepare(terms.clone());
        stale_digest.exact_terms_digest = Digest32::from_bytes([9; 32]);
        assert_eq!(
            stale_digest
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );

        let mut foreign_wallet = allocate_prepare(terms.clone());
        foreign_wallet.wallet_id = Some(Token::new("other-wallet").unwrap());
        assert_eq!(
            foreign_wallet
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::KeyrefMismatch
        );

        let mut replayed = allocate_prepare(terms.clone());
        replayed.custody_operation_id = OperationId::from_bytes([4; 32]);
        assert_eq!(
            replayed
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );

        let mut divergent = allocate_prepare(terms.clone());
        divergent.derivation_requests = vec![DerivedAccountRequest {
            derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            requested_role: Token::new("solana-account").unwrap(),
            account: None,
        }];
        assert_eq!(
            divergent
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );

        let mut missing = allocate_prepare(terms);
        missing.account_terms = None;
        assert_eq!(
            missing
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );
    }

    #[test]
    fn allocation_terms_reject_tampered_frozen_shape() {
        let mut tampered_suites = allocation_terms();
        tampered_suites.allowed_crypto_suites = vec![CryptoSuite::Ed25519Message];
        assert!(tampered_suites.validate().is_err());

        let mut tampered_template = allocation_terms();
        tampered_template.path_template = "m/44'/60'/0'/0".into();
        assert!(tampered_template.validate().is_err());

        let mut tampered_profile = allocation_terms();
        tampered_profile.seed_profile = WalletSeedProfile::ImportedSecp256k1Scalar;
        assert!(tampered_profile.validate().is_err());

        let mut zero_version = allocation_terms();
        zero_version.policy_version = DecimalU64::new(0);
        assert!(zero_version.validate().is_err());
    }

    #[test]
    fn retire_terms_bind_the_exact_child() {
        let mut terms = allocation_terms();
        terms.derivations.clear();
        terms.retire_key_fingerprint = Some(Digest32::from_bytes([5; 32]));
        retire_prepare(terms.clone(), Digest32::from_bytes([5; 32]))
            .validate_account_retire_binding()
            .unwrap();

        let mismatched = retire_prepare(terms.clone(), Digest32::from_bytes([6; 32]));
        assert_eq!(
            mismatched
                .validate_account_retire_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );

        let mut root_key = retire_prepare(terms, Digest32::from_bytes([5; 32]));
        let key_ref = root_key.key_ref.as_mut().unwrap();
        key_ref.derivation = None;
        assert_eq!(
            root_key.validate_account_retire_binding().unwrap_err().code,
            ProtocolErrorCode::KeyrefMismatch
        );
    }

    #[test]
    fn account_custody_never_selects_a_seed_profile() {
        let mut request = allocate_prepare(allocation_terms());
        request.wallet_seed_profile = Some(WalletSeedProfile::Bip39MulticurveV1);
        assert_eq!(
            request
                .validate_account_allocation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::CeremonyKindMismatch
        );
    }

    #[test]
    fn wallet_seed_profile_is_rejected_outside_creation_ceremonies() {
        let mut request = registration_prepare(Some(Token::new("quiet-lilac").unwrap()));
        request.ceremony_kind = CeremonyKind::WalletExport;
        request.wallet_seed_profile = Some(WalletSeedProfile::Bip39MulticurveV1);
        assert_eq!(
            request.validate_wallet_creation_binding().unwrap_err().code,
            ProtocolErrorCode::CeremonyKindMismatch
        );
    }
}
