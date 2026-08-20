use serde::{Deserialize, Serialize};

use crate::{
    Base64UrlBytes, BootEpoch, CeremonyKind, CustodyPrepareRequest, CustodyPrepareResponse,
    CustodyResult, DecimalU64, Digest32, HelloChallenge, KeyRef, MachineSignRequest, OperationId,
    PetalUseClaim, PolicyCommitReceipt, PolicyCommitUpdateRequest, PolicyUpdatePrepareResponse,
    PolicyUpdateRequest, ProtocolError, RevocationState, SealedApprovalPrepareResponse,
    SealedApprovalTerms, ServiceFuture, SignedPolicySnapshot, SigningResult, SystemUseClaim, Token,
    WalletAccountsPublic,
};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Ready,
    DegradedReadOnly,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    pub service_id: Token,
    pub service_version: String,
    pub build_digest: Digest32,
    pub boot_epoch: BootEpoch,
    pub state: ReadinessState,
    pub conditions: Vec<Token>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendPublicCapability {
    pub backend_id: Token,
    pub backend_instance_id: Token,
    pub crypto_suites: Vec<crate::CryptoSuite>,
    pub derivation_schemes: Vec<Token>,
    pub networked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierPublicCapability {
    pub verifier_id: Token,
    pub verifier_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCapabilities {
    pub service_id: Token,
    pub service_version: String,
    pub build_digest: Digest32,
    pub protocol_major: u16,
    pub protocol_minor_min: u16,
    pub protocol_minor_max: u16,
    pub methods: Vec<Token>,
    pub schemas: Vec<Token>,
    pub backends: Vec<BackendPublicCapability>,
    pub assurance_verifiers: Vec<VerifierPublicCapability>,
    pub frame_max_bytes: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdRequest {
    pub id: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletRequest {
    pub wallet_id: Token,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletOperationRequest {
    pub operation_id: OperationId,
    pub wallet_id: Token,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRequest {
    pub key_ref: KeyRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPrepareRequest {
    pub operation_id: OperationId,
    pub terms: SealedApprovalTerms,
    pub canonical_plan_facts_digest: Digest32,
    #[serde(default)]
    pub petal_use_claim: Option<PetalUseClaim>,
    #[serde(default)]
    pub system_use_claim: Option<SystemUseClaim>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRenewRequest {
    pub operation_id: OperationId,
    pub old_approval_id: Digest32,
    pub replacement_terms: SealedApprovalTerms,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub operation_id: OperationId,
    pub approval_id: Digest32,
    pub wallet_id: Token,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovalLifecycleState {
    #[serde(rename = "PREPARED")]
    Prepared,
    #[serde(rename = "AWAITING_CEREMONY")]
    AwaitingCeremony,
    #[serde(rename = "ORPHANED")]
    Orphaned,
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "EXHAUSTED")]
    Exhausted,
    #[serde(rename = "EXPIRED")]
    Expired,
    #[serde(rename = "REVOKED")]
    Revoked,
    #[serde(rename = "CANCELLED")]
    Cancelled,
    #[serde(rename = "FAILED")]
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPublicStatus {
    pub approval_id: Digest32,
    pub wallet_id: Token,
    pub state: ApprovalLifecycleState,
    pub effective_claim_assurance: Option<crate::ClaimAssuranceLevel>,
    pub ceremony_url: Option<String>,
    pub ceremony_expires_at_ms: Option<DecimalU64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLimitState {
    pub approval_id: Digest32,
    pub committed_operations: DecimalU64,
    pub reserved_operations: DecimalU64,
    pub quarantined_operations: DecimalU64,
    pub committed_signatures: DecimalU64,
    pub reserved_signatures: DecimalU64,
    pub quarantined_signatures: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    pub operation_id: OperationId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OperationState {
    #[serde(rename = "RECEIVED")]
    Received,
    #[serde(rename = "VALIDATED")]
    Validated,
    #[serde(rename = "RESERVED")]
    Reserved,
    #[serde(rename = "DISPATCHED")]
    Dispatched,
    #[serde(rename = "DOWNSTREAM_ACCEPTED")]
    DownstreamAccepted,
    #[serde(rename = "COMMITTED")]
    Committed,
    #[serde(rename = "SUCCEEDED")]
    Succeeded,
    #[serde(rename = "DENIED")]
    Denied,
    #[serde(rename = "CANCELLED")]
    Cancelled,
    #[serde(rename = "FAILED")]
    Failed,
    #[serde(rename = "QUARANTINED")]
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPublicStatus {
    pub operation_id: OperationId,
    pub operation_digest: Digest32,
    pub state: OperationState,
    pub result: Option<SigningResult>,
    pub error: Option<ProtocolError>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletPublic {
    pub wallet_id: Token,
    pub wallet_kind: Token,
    /// Signer-identified wallet root for exact owner-authority operations.
    /// Machine must not derive this identity from list order or backend
    /// data. `None` for BIP-39 wallets: their root is a non-signable seed
    /// and only derived accounts are addressable.
    pub root_key_ref: Option<KeyRef>,
    pub key_refs: Vec<KeyRef>,
    pub policy_version: DecimalU64,
    pub policy_digest: Digest32,
    pub wallet_revocation_epoch: DecimalU64,
}

/// Signer-owned classification projected unchanged through Broker.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    WalletRoot,
    Derived,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPublic {
    pub key_ref: KeyRef,
    pub role: KeyRole,
    pub canonical_public_key: Base64UrlBytes,
    pub addresses: Vec<String>,
    pub supported_crypto_suites: Vec<crate::CryptoSuite>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CredentialState {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "REVOKED")]
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialPublic {
    pub credential_id: Base64UrlBytes,
    pub wallet_id: Token,
    pub created_at_ms: DecimalU64,
    pub state: CredentialState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CeremonyState {
    #[serde(rename = "PREPARED")]
    Prepared,
    #[serde(rename = "AWAITING_USER")]
    AwaitingUser,
    #[serde(rename = "VERIFYING")]
    Verifying,
    #[serde(rename = "WALLET_COMMITTED")]
    WalletCommitted,
    #[serde(rename = "AWAITING_RECOVERY_ACK")]
    AwaitingRecoveryAck,
    #[serde(rename = "COMPLETED")]
    Completed,
    #[serde(rename = "APPROVING_ROOT_CHANGE")]
    ApprovingRootChange,
    #[serde(rename = "CREATING_CREDENTIAL")]
    CreatingCredential,
    #[serde(rename = "COMMITTING")]
    Committing,
    #[serde(rename = "SUCCEEDED")]
    Succeeded,
    #[serde(rename = "CANCELLED")]
    Cancelled,
    #[serde(rename = "EXPIRED")]
    Expired,
    #[serde(rename = "FAILED")]
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyPublicStatus {
    pub ceremony_id: Digest32,
    pub ceremony_kind: CeremonyKind,
    pub operation_id: OperationId,
    pub state: CeremonyState,
    pub expires_at_ms: DecimalU64,
    /// Owner-readable launch secret returned only by Broker to the
    /// authenticated originating Machine while the ceremony is awaiting user
    /// action. Signer-originated statuses and terminal Broker statuses omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony_url: Option<String>,
    pub receipt_digest: Option<Digest32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", content = "body", deny_unknown_fields)]
pub enum MachineBrokerRequest {
    #[serde(rename = "system.hello")]
    SystemHello(HelloChallenge),
    #[serde(rename = "broker.readiness")]
    BrokerReadiness(Empty),
    #[serde(rename = "broker.capabilities")]
    BrokerCapabilities(Empty),
    #[serde(rename = "action.validate")]
    ActionValidate(Digest32),
    #[serde(rename = "sealed_approval.prepare")]
    SealedApprovalPrepare(ApprovalPrepareRequest),
    #[serde(rename = "sealed_approval.status")]
    SealedApprovalStatus(IdRequest),
    #[serde(rename = "sealed_approval.list")]
    SealedApprovalList(WalletRequest),
    #[serde(rename = "sealed_approval.limit_state")]
    SealedApprovalLimitState(IdRequest),
    #[serde(rename = "sealed_approval.revoke")]
    SealedApprovalRevoke(RevokeRequest),
    #[serde(rename = "sealed_approval.revoke_all")]
    SealedApprovalRevokeAll(WalletOperationRequest),
    #[serde(rename = "sealed_approval.renew")]
    SealedApprovalRenew(ApprovalRenewRequest),
    #[serde(rename = "signing.sign")]
    SigningSign(MachineSignRequest),
    #[serde(rename = "signing.sign_batch")]
    SigningSignBatch(MachineSignRequest),
    #[serde(rename = "operation.status")]
    OperationStatus(OperationRequest),
    #[serde(rename = "operation.cancel")]
    OperationCancel(OperationRequest),
    #[serde(rename = "policy.read")]
    PolicyRead(WalletRequest),
    #[serde(rename = "policy.validate_update")]
    PolicyValidateUpdate(PolicyUpdateRequest),
    #[serde(rename = "policy.commit_update")]
    PolicyCommitUpdate(PolicyCommitUpdateRequest),
    #[serde(rename = "wallet.list_public")]
    WalletListPublic(Empty),
    #[serde(rename = "wallet.get_public")]
    WalletGetPublic(WalletRequest),
    #[serde(rename = "wallet.registration_prepare")]
    WalletRegistrationPrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.unlock_prepare")]
    WalletUnlockPrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.import_prepare")]
    WalletImportPrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.export_prepare")]
    WalletExportPrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.delete_prepare")]
    WalletDeletePrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.accounts")]
    WalletAccounts(WalletRequest),
    #[serde(rename = "key.list_public")]
    KeyListPublic(WalletRequest),
    #[serde(rename = "key.get_public")]
    KeyGetPublic(KeyRequest),
    #[serde(rename = "key.derivation_capabilities")]
    KeyDerivationCapabilities(KeyRequest),
    #[serde(rename = "key.derive_prepare")]
    KeyDerivePrepare(CustodyPrepareRequest),
    #[serde(rename = "key.list_derived")]
    KeyListDerived(KeyRequest),
    #[serde(rename = "key.enroll_prepare")]
    KeyEnrollPrepare(CustodyPrepareRequest),
    #[serde(rename = "account.allocate_prepare")]
    AccountAllocatePrepare(CustodyPrepareRequest),
    #[serde(rename = "account.retire_prepare")]
    AccountRetirePrepare(CustodyPrepareRequest),
    #[serde(rename = "credential.list_public")]
    CredentialListPublic(WalletRequest),
    #[serde(rename = "credential.add_prepare")]
    CredentialAddPrepare(CustodyPrepareRequest),
    #[serde(rename = "credential.replace_prepare")]
    CredentialReplacePrepare(CustodyPrepareRequest),
    #[serde(rename = "credential.remove_prepare")]
    CredentialRemovePrepare(CustodyPrepareRequest),
    #[serde(rename = "recovery.prepare")]
    RecoveryPrepare(CustodyPrepareRequest),
    #[serde(rename = "ceremony.status")]
    CeremonyStatus(IdRequest),
    #[serde(rename = "ceremony.cancel")]
    CeremonyCancel(IdRequest),
    #[serde(rename = "custody.result")]
    CustodyResult(OperationRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", content = "body", deny_unknown_fields)]
pub enum MachineBrokerResponse {
    #[serde(rename = "system.hello")]
    SystemHello(HelloChallenge),
    #[serde(rename = "broker.readiness")]
    BrokerReadiness(Readiness),
    #[serde(rename = "broker.capabilities")]
    BrokerCapabilities(ServiceCapabilities),
    #[serde(rename = "action.validate")]
    ActionValidate(Digest32),
    #[serde(rename = "sealed_approval.prepare")]
    SealedApprovalPrepare(SealedApprovalPrepareResponse),
    #[serde(rename = "sealed_approval.status")]
    SealedApprovalStatus(ApprovalPublicStatus),
    #[serde(rename = "sealed_approval.list")]
    SealedApprovalList(Vec<ApprovalPublicStatus>),
    #[serde(rename = "sealed_approval.limit_state")]
    SealedApprovalLimitState(ApprovalLimitState),
    #[serde(rename = "sealed_approval.revoke")]
    SealedApprovalRevoke(ApprovalPublicStatus),
    #[serde(rename = "sealed_approval.revoke_all")]
    SealedApprovalRevokeAll(RevocationState),
    #[serde(rename = "sealed_approval.renew")]
    SealedApprovalRenew(SealedApprovalPrepareResponse),
    #[serde(rename = "signing.sign")]
    SigningSign(SigningResult),
    #[serde(rename = "signing.sign_batch")]
    SigningSignBatch(SigningResult),
    #[serde(rename = "operation.status")]
    OperationStatus(OperationPublicStatus),
    #[serde(rename = "operation.cancel")]
    OperationCancel(OperationPublicStatus),
    #[serde(rename = "policy.read")]
    PolicyRead(SignedPolicySnapshot),
    #[serde(rename = "policy.validate_update")]
    PolicyValidateUpdate(PolicyUpdatePrepareResponse),
    #[serde(rename = "policy.commit_update")]
    PolicyCommitUpdate(PolicyCommitReceipt),
    #[serde(rename = "wallet.list_public")]
    WalletListPublic(Vec<WalletPublic>),
    #[serde(rename = "wallet.get_public")]
    WalletGetPublic(WalletPublic),
    #[serde(rename = "wallet.registration_prepare")]
    WalletRegistrationPrepare(CustodyPrepareResponse),
    #[serde(rename = "wallet.unlock_prepare")]
    WalletUnlockPrepare(CustodyPrepareResponse),
    #[serde(rename = "wallet.import_prepare")]
    WalletImportPrepare(CustodyPrepareResponse),
    #[serde(rename = "wallet.export_prepare")]
    WalletExportPrepare(CustodyPrepareResponse),
    #[serde(rename = "wallet.delete_prepare")]
    WalletDeletePrepare(CustodyPrepareResponse),
    #[serde(rename = "wallet.accounts")]
    WalletAccounts(WalletAccountsPublic),
    #[serde(rename = "key.list_public")]
    KeyListPublic(Vec<KeyPublic>),
    #[serde(rename = "key.get_public")]
    KeyGetPublic(KeyPublic),
    #[serde(rename = "key.derivation_capabilities")]
    KeyDerivationCapabilities(Vec<Token>),
    #[serde(rename = "key.list_derived")]
    KeyListDerived(Vec<KeyPublic>),
    #[serde(rename = "key.derive_prepare")]
    KeyDerivePrepare(CustodyPrepareResponse),
    #[serde(rename = "key.enroll_prepare")]
    KeyEnrollPrepare(CustodyPrepareResponse),
    #[serde(rename = "account.allocate_prepare")]
    AccountAllocatePrepare(CustodyPrepareResponse),
    #[serde(rename = "account.retire_prepare")]
    AccountRetirePrepare(CustodyPrepareResponse),
    #[serde(rename = "credential.list_public")]
    CredentialListPublic(Vec<CredentialPublic>),
    #[serde(rename = "credential.add_prepare")]
    CredentialAddPrepare(CustodyPrepareResponse),
    #[serde(rename = "credential.replace_prepare")]
    CredentialReplacePrepare(CustodyPrepareResponse),
    #[serde(rename = "credential.remove_prepare")]
    CredentialRemovePrepare(CustodyPrepareResponse),
    #[serde(rename = "recovery.prepare")]
    RecoveryPrepare(CustodyPrepareResponse),
    #[serde(rename = "ceremony.status")]
    CeremonyStatus(CeremonyPublicStatus),
    #[serde(rename = "ceremony.cancel")]
    CeremonyCancel(CeremonyPublicStatus),
    #[serde(rename = "custody.result")]
    CustodyResult(CustodyResult),
}
pub trait MachineBrokerService: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse>;
}
/// Transitional v1 method classification. Each edge API takes ownership of
/// its own closed inventory when the monolithic protocol crate is split.
pub fn is_read_only_method(method: &Token) -> bool {
    let method = method.as_str();
    method.ends_with(".read")
        || method.ends_with(".readiness")
        || method.ends_with(".capabilities")
        || method.ends_with(".status")
        || method.ends_with(".list")
        || method.ends_with(".list_public")
        || method.ends_with(".get_public")
        || method == "revocation.state"
        || method == "sealed_approval.limit_state"
        || method == "key.derivation_capabilities"
        || method == "key.list_derived"
        || method == "wallet.accounts"
        || method == "credential.list_public"
        || method == "custody.result"
}

impl crate::TypedRequestMethod for MachineBrokerRequest {
    fn operation_id(&self) -> Result<Option<OperationId>, crate::WireError> {
        use MachineBrokerRequest as Request;
        Ok(match self {
            Request::SealedApprovalPrepare(request) => Some(request.operation_id.clone()),
            Request::SealedApprovalRenew(request) => Some(request.operation_id.clone()),
            Request::SealedApprovalRevoke(request) => Some(request.operation_id.clone()),
            Request::SealedApprovalRevokeAll(request) => Some(request.operation_id.clone()),
            Request::SigningSign(request) | Request::SigningSignBatch(request) => {
                Some(request.operation_id.clone())
            }
            Request::OperationStatus(request)
            | Request::OperationCancel(request)
            | Request::CustodyResult(request) => Some(request.operation_id.clone()),
            Request::PolicyValidateUpdate(request) => Some(request.operation_id.clone()),
            Request::PolicyCommitUpdate(request) => Some(request.operation_id.clone()),
            Request::WalletRegistrationPrepare(request)
            | Request::WalletUnlockPrepare(request)
            | Request::WalletImportPrepare(request)
            | Request::WalletExportPrepare(request)
            | Request::WalletDeletePrepare(request)
            | Request::KeyDerivePrepare(request)
            | Request::KeyEnrollPrepare(request)
            | Request::AccountAllocatePrepare(request)
            | Request::AccountRetirePrepare(request)
            | Request::CredentialAddPrepare(request)
            | Request::CredentialReplacePrepare(request)
            | Request::CredentialRemovePrepare(request)
            | Request::RecoveryPrepare(request) => Some(request.custody_operation_id.clone()),
            _ => None,
        })
    }

    fn is_read_only(&self) -> bool {
        self.method()
            .is_ok_and(|method| is_read_only_method(&method))
    }
}
