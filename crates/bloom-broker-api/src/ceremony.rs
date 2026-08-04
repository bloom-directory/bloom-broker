use serde::{Deserialize, Serialize};

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
pub struct CustodyPrepareRequest {
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    pub wallet_id: Option<Token>,
    pub key_ref: Option<KeyRef>,
    pub exact_terms_digest: Digest32,
    pub expected_input_class: Token,
    pub browser_output_recipient_key: Option<Base64UrlBytes>,
    #[serde(default)]
    pub petal_key_scope: Option<PetalKeyScope>,
}

impl CustodyPrepareRequest {
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
        if self.exact_terms_digest != scope.digest()? {
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
