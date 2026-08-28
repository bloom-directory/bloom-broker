use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Base64UrlBytes, DecimalU64, Digest32, KeyRef, OperationId, PetalKeyScope, ProtocolError,
    ProtocolErrorCode, Token,
};

const ENCRYPTED_BROWSER_RESULT_MAX_BYTES: usize = 4 * 1024;

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
    PolicyUpdate,
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
}

impl CustodyPrepareRequest {
    pub fn validate_wallet_creation_binding(&self) -> Result<(), ProtocolError> {
        if !matches!(
            self.ceremony_kind,
            CeremonyKind::WalletRegistration | CeremonyKind::WalletImport
        ) {
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
    pub rp_id: Token,
    pub active: bool,
}

impl CustodyResult {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
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

    fn registration_prepare(wallet_id: Option<Token>) -> CustodyPrepareRequest {
        CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::WalletRegistration,
            custody_operation_id: OperationId::from_bytes([1; 32]),
            wallet_id,
            key_ref: None,
            exact_terms_digest: Digest32::from_bytes([2; 32]),
            expected_input_class: Token::new("passkey-prf").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
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
}
