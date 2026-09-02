use crate::{ProtocolError, ProtocolErrorCode};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};

macro_rules! method_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        pub enum $name { $(#[serde(rename = $wire)] $variant,)+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire),+ } }
            pub fn parse(value: &str) -> Result<Self, ProtocolError> {
                Self::ALL.iter().copied().find(|method| method.as_str() == value).ok_or_else(|| ProtocolError::new(ProtocolErrorCode::UnknownMethod, format!("unknown method {value}")))
            }
        }
    };
}

method_enum!(MachineBrokerMethod {
    SystemHello => "system.hello", BrokerReadiness => "broker.readiness", BrokerCapabilities => "broker.capabilities", ActionValidate => "action.validate",
    SealedApprovalPrepare => "sealed_approval.prepare", SealedApprovalStatus => "sealed_approval.status", SealedApprovalList => "sealed_approval.list", SealedApprovalLimitState => "sealed_approval.limit_state", SealedApprovalRevoke => "sealed_approval.revoke", SealedApprovalRevokeAll => "sealed_approval.revoke_all", SealedApprovalRenew => "sealed_approval.renew",
    SigningSign => "signing.sign", SigningSignBatch => "signing.sign_batch", OperationStatus => "operation.status", OperationCancel => "operation.cancel",
    PolicyRead => "policy.read", PolicyValidateUpdate => "policy.validate_update", PolicyCommitUpdate => "policy.commit_update",
    WalletListPublic => "wallet.list_public", WalletGetPublic => "wallet.get_public", WalletRegistrationPrepare => "wallet.registration_prepare", WalletUnlockPrepare => "wallet.unlock_prepare", WalletImportPrepare => "wallet.import_prepare", WalletExportPrepare => "wallet.export_prepare", WalletDeletePrepare => "wallet.delete_prepare",
    KeyListPublic => "key.list_public", KeyGetPublic => "key.get_public", KeyDerivationCapabilities => "key.derivation_capabilities", KeyDerivePrepare => "key.derive_prepare", KeyListDerived => "key.list_derived", KeyEnrollPrepare => "key.enroll_prepare",
    CredentialListPublic => "credential.list_public", CredentialAddPrepare => "credential.add_prepare", CredentialReplacePrepare => "credential.replace_prepare", CredentialRemovePrepare => "credential.remove_prepare",
    RecoveryPrepare => "recovery.prepare", CeremonyStatus => "ceremony.status", CeremonyCancel => "ceremony.cancel", CustodyResult => "custody.result",
    OwnerInputRequest => "owner_input.request",
});

pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProtocolError>> + Send + 'a>>;
