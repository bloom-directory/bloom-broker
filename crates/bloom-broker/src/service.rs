//! Production Machine→Broker and revoke-control RPC implementation.

use std::sync::Arc;

use bloom_broker_api::{
    ApprovalLifecycleState, ApprovalPrepareRequest, ApprovalRenewRequest, ApprovalSelector,
    Base64UrlBytes, BootEpoch,
    DecimalU64, Digest32, MachineBrokerMethod, MachineBrokerRequest, MachineBrokerResponse,
    MachineBrokerService, MachineSignRequest, OperationId, OperationPublicStatus, OperationState,
    PolicyUpdateRequest, ProtocolError, ProtocolErrorCode, RPC_ENVELOPE_SCHEMA_V1, Readiness,
    ReadinessState, SealedApprovalPrepareResponse, ServiceCapabilities, ServiceFuture,
    SigningPayloads, Token, VerifierPublicCapability, WalletAccountsPublic, WalletPublic,
    WalletRequest, WalletSeedProfile,
};
use bloom_platform_containment::NetworkContainmentGuard;
use bloom_signer_api::{
    BrokerSignerRequest, BrokerSignerResponse, BrokerValidationReceipt, ControlRequest,
    ControlResponse, PolicyCompareAndSwapRequest, PolicyUpdateCeremonyPrepareRequest,
    PolicyValidationReceipt, RevocationControlService, SignRequest, UnsignedSignRequest,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest as _, Sha256};

use crate::{
    authority::{
        AuthorityError, AuthorizationInput, BrokerAuthority, EpochReconciliation,
        PolicyInstallCorrelation,
    },
    ceremony::{
        CeremonyBroker, CeremonyCompletionObserver, PolicyUpdateReviewManifest,
        ReviewManifestContext,
    },
    clock::BrokerClock,
    journal::{BrokerJournal, JournalError, ReservationState},
    signer_client::BrokerSignerClient,
    translation::{
        approval as translate_approval, custody as translate_custody, error as translate_error,
        key as translate_key, policy as translate_policy, revocation as translate_revocation,
        service as translate_service, signing as translate_signing,
        wallet_account as translate_wallet_account,
    },
};

const BROKER_SIGN_REQUEST_SCHEMA: &str = "bloom.sign-request/1";
const POLICY_REVIEW_DOMAIN: &[u8] = b"bloom-policy-update-review/v1";
const POLICY_VALIDATION_DOMAIN: &[u8] = b"bloom-policy-validation-receipt/v1";

pub struct BrokerRpcService {
    authority: Arc<BrokerAuthority>,
    journal: Arc<BrokerJournal>,
    clock: Arc<BrokerClock>,
    ceremony: CeremonyBroker,
    signer: BrokerSignerClient,
    signing_key_id: Token,
    signing_key: SigningKey,
    boot_epoch: BootEpoch,
    build_digest: Digest32,
    service_version: String,
    network_containment: Option<NetworkContainmentGuard>,
}

/// The wallet's seed profile, read from the key projection the Signer
/// published rather than inferred from which fields happen to be populated.
///
/// A wallet with no live derived accounts is still describable: what it is
/// shows in the derivation carried by its keys. Only genuinely
/// unrepresentable shapes fail, and they fail by name instead of being
/// rounded to whichever profile looks closest.
fn seed_profile_from_key_projection(
    public: &bloom_broker_api::WalletPublic,
) -> Result<WalletSeedProfile, ProtocolError> {
    let mut saw_bip32_child = false;
    for key_ref in &public.key_refs {
        match key_ref.derivation.as_ref() {
            // A BIP-39 child proves the seed profile outright.
            Some(bloom_broker_api::DerivationRef::Bip39Multicurve { .. }) => {
                return Ok(WalletSeedProfile::Bip39MulticurveV1);
            }
            // A BIP-32 child means a legacy pre-BIP-39 wallet.
            Some(bloom_broker_api::DerivationRef::Bip32Secp256k1 { .. }) => {
                saw_bip32_child = true;
            }
            None => {}
        }
    }
    if saw_bip32_child {
        // Real custody, but not either Machine-facing profile. Naming it is
        // the point: silently calling it an imported scalar would assert the
        // wallet has no derivable seed, which is false and would mislead a
        // migration decision.
        return Err(ProtocolError::new(
            ProtocolErrorCode::BackendUnsupported,
            "wallet uses legacy BIP-32 custody, which has no wallet.accounts projection; \
             it must be migrated before derived accounts can be listed",
        ));
    }
    match &public.root_key_ref {
        // A root with no derived keys at all is a raw single-key import.
        Some(_) => Ok(WalletSeedProfile::ImportedSecp256k1Scalar),
        // No root and no derived keys: nothing to characterise. A BIP-39
        // wallet whose children were all retired still projects its seed
        // ref, so reaching here means the projection is incomplete.
        None => Err(ProtocolError::new(
            ProtocolErrorCode::BackendUnsupported,
            "wallet projection carries neither a root key nor any derived key, \
             so its seed profile cannot be established",
        )),
    }
}

impl BrokerRpcService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority: Arc<BrokerAuthority>,
        journal: Arc<BrokerJournal>,
        clock: Arc<BrokerClock>,
        ceremony: CeremonyBroker,
        signer: BrokerSignerClient,
        signing_key_id: Token,
        signing_key: SigningKey,
        boot_epoch: BootEpoch,
        build_digest: Digest32,
        service_version: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let service = Self {
            authority,
            journal,
            clock,
            ceremony,
            signer,
            signing_key_id,
            signing_key,
            boot_epoch,
            build_digest,
            service_version: service_version.into(),
            network_containment: None,
        };
        let observer = Arc::new(AuthorityCompletionObserver {
            authority: service.authority.clone(),
        });
        if service.journal.audit_degraded() {
            service.ceremony.set_completion_observer_read_only(observer);
        } else {
            service
                .ceremony
                .set_completion_observer(observer, service.clock.now_ms(false)?)?;
        }
        Ok(service)
    }

    pub fn journal_is_audit_degraded(&self) -> bool {
        self.journal.audit_degraded()
    }

    pub fn with_network_containment(mut self, guard: NetworkContainmentGuard) -> Self {
        self.network_containment = Some(guard);
        self
    }

    pub fn ceremony(&self) -> &CeremonyBroker {
        &self.ceremony
    }

    async fn dispatch_inner(
        &self,
        request: MachineBrokerRequest,
    ) -> Result<MachineBrokerResponse, ProtocolError> {
        use MachineBrokerRequest as Request;
        use MachineBrokerResponse as Response;

        if machine_request_requires_containment(&request) {
            self.require_network_containment()?;
        }
        match request {
            Request::SystemHello(_) => Err(ProtocolError::new(
                ProtocolErrorCode::UnknownMethod,
                "system.hello is consumed by the authenticated transport",
            )),
            Request::BrokerReadiness(_) => {
                Ok(Response::BrokerReadiness(self.triad_readiness().await?))
            }
            Request::BrokerCapabilities(_) => {
                Ok(Response::BrokerCapabilities(self.capabilities()?))
            }
            Request::ActionValidate(digest) => Ok(Response::ActionValidate(digest)),
            Request::SealedApprovalPrepare(request) => Ok(Response::SealedApprovalPrepare(
                self.prepare_approval(request).await?,
            )),
            Request::SealedApprovalRenew(request) => Ok(Response::SealedApprovalRenew(
                self.renew_approval(request).await?,
            )),
            Request::SealedApprovalStatus(request) => Ok(Response::SealedApprovalStatus(
                self.approval_public_status(&request.id)?,
            )),
            Request::SealedApprovalList(request) => {
                let mut statuses = self
                    .authority
                    .approval_public_list(&request.wallet_id)
                    .map_err(authority_error)?;
                for status in &mut statuses {
                    self.attach_pending_approval_ceremony(status);
                }
                Ok(Response::SealedApprovalList(statuses))
            }
            Request::SealedApprovalLimitState(request) => Ok(Response::SealedApprovalLimitState(
                self.journal
                    .approval_limit_state(&request.id)
                    .map_err(journal_error)?,
            )),
            Request::SealedApprovalRevoke(request) => {
                self.authority
                    .revoke_local_approval(&request.approval_id)
                    .map_err(authority_error)?;
                self.signer
                    .request_for_machine(BrokerSignerRequest::SealedApprovalRevoke(
                        translate_revocation::revoke_request_to_signer(request.clone()),
                    ))
                    .await?;
                Ok(Response::SealedApprovalRevoke(
                    self.approval_public_status(&request.approval_id)?,
                ))
            }
            Request::SealedApprovalRevokeAll(request) => {
                let current = self
                    .authority
                    .wallet_epoch(&request.wallet_id)
                    .map_err(authority_error)?;
                self.authority
                    .advance_local_epoch(
                        &request.wallet_id,
                        current,
                        current.checked_add(1).ok_or_else(|| {
                            ProtocolError::new(
                                ProtocolErrorCode::OperationIdConflict,
                                "wallet revocation epoch overflowed",
                            )
                        })?,
                    )
                    .map_err(authority_error)?;
                match self
                    .signer
                    .request_for_machine(BrokerSignerRequest::SealedApprovalRevokeAll(
                        bloom_signer_api::WalletOperationRequest {
                            operation_id: request.operation_id,
                            wallet_id: request.wallet_id,
                        },
                    ))
                    .await?
                {
                    BrokerSignerResponse::SealedApprovalRevokeAll(state) => {
                        Ok(Response::SealedApprovalRevokeAll(
                            translate_revocation::state_to_machine(state),
                        ))
                    }
                    _ => Err(response_mismatch("sealed_approval.revoke_all")),
                }
            }
            Request::SigningSign(request) => {
                Ok(Response::SigningSign(self.sign(request, false).await?))
            }
            Request::SigningSignBatch(request) => {
                Ok(Response::SigningSignBatch(self.sign(request, true).await?))
            }
            Request::OperationStatus(request) => Ok(Response::OperationStatus(
                self.operation_status(&request.operation_id)?,
            )),
            Request::OperationCancel(request) => {
                let snapshot = self
                    .journal
                    .operation(&request.operation_id)
                    .map_err(journal_error)?
                    .ok_or_else(|| {
                        ProtocolError::new(
                            ProtocolErrorCode::ApprovalNotFound,
                            "operation not found",
                        )
                    })?;
                if matches!(
                    snapshot.state,
                    OperationState::Received | OperationState::Validated | OperationState::Reserved
                ) {
                    self.journal
                        .transition_operation(&request.operation_id, OperationState::Cancelled)
                        .map_err(journal_error)?;
                }
                Ok(Response::OperationCancel(
                    self.operation_status(&request.operation_id)?,
                ))
            }
            Request::PolicyRead(request) => {
                Ok(Response::PolicyRead(self.policy_read(&request).await?))
            }
            Request::PolicyValidateUpdate(request) => Ok(Response::PolicyValidateUpdate(
                self.prepare_policy_update(request).await?,
            )),
            Request::PolicyCommitUpdate(request) => {
                let (staged, ceremony_receipt) = self
                    .ceremony
                    .completed_policy_update(&request.operation_id, &request.ceremony_receipt)?;
                let operation_id = request.operation_id.clone();
                let ceremony_receipt_digest = ceremony_receipt.receipt_digest.clone();
                let validation_receipt_digest = staged
                    .broker_validation_receipt
                    .digest()
                    .map_err(translate_error::signer_error_to_machine)?;
                let compare = PolicyCompareAndSwapRequest {
                    update: staged.update.clone(),
                    ceremony_receipt,
                    broker_validation_receipt: staged.broker_validation_receipt,
                };
                match self
                    .signer
                    .request_for_machine(BrokerSignerRequest::PolicyCompareAndSwap(compare))
                    .await?
                {
                    BrokerSignerResponse::PolicyCompareAndSwap(receipt) => {
                        let commit_receipt_digest = Digest32::from_bytes(
                            Sha256::digest(serde_jcs::to_vec(&receipt).map_err(|error| {
                                ProtocolError::new(
                                    ProtocolErrorCode::MalformedFrame,
                                    format!("canonicalize policy commit receipt: {error}"),
                                )
                            })?)
                            .into(),
                        );
                        let committed = self.signer_policy_read(&staged.update.wallet_id).await?;
                        let (policy_key_id, policy_key) = self
                            .authority
                            .policy_verification_key(&staged.update.wallet_id)
                            .map_err(authority_error)?;
                        verify_policy_commit_receipt(
                            &receipt,
                            &staged.update,
                            &committed,
                            &policy_key_id,
                            &policy_key,
                        )?;
                        let committed = translate_policy::snapshot_to_machine(committed);
                        self.authority
                            .install_policy_with_correlation(
                                &committed,
                                &PolicyInstallCorrelation {
                                    operation_id: Some(operation_id),
                                    ceremony_receipt_digest: Some(ceremony_receipt_digest),
                                    validation_receipt_digest: Some(validation_receipt_digest),
                                    commit_receipt_digest: Some(commit_receipt_digest),
                                },
                            )
                            .map_err(authority_error)?;
                        Ok(Response::PolicyCommitUpdate(
                            translate_policy::commit_receipt_to_machine(receipt),
                        ))
                    }
                    _ => Err(response_mismatch("policy.compare_and_swap")),
                }
            }
            Request::WalletListPublic(_) => {
                let mut wallets = Vec::new();
                for wallet_id in self.authority.wallet_ids().map_err(authority_error)? {
                    wallets.push(self.wallet_public(wallet_id).await?);
                }
                Ok(Response::WalletListPublic(wallets))
            }
            Request::WalletGetPublic(request) => Ok(Response::WalletGetPublic(
                self.wallet_public(request.wallet_id).await?,
            )),
            Request::WalletAccounts(request) => Ok(Response::WalletAccounts(
                self.wallet_accounts(request.wallet_id).await?,
            )),
            Request::WalletRegistrationPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::WalletRegistration,
                )?;
                let request = translate_custody::apply_seed_profile_selection(&request);
                request.validate_wallet_creation_binding()?;
                Ok(Response::WalletRegistrationPrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(true)?,
                    )?,
                ))
            }
            Request::WalletUnlockPrepare(_) => Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "wallet.unlock_prepare has no ratified custody ceremony kind",
            )),
            Request::WalletImportPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::WalletImport,
                )?;
                let request = translate_custody::apply_seed_profile_selection(&request);
                request.validate_wallet_creation_binding()?;
                Ok(Response::WalletImportPrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(true)?,
                    )?,
                ))
            }
            Request::WalletExportPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::WalletExport,
                )?;
                Ok(Response::WalletExportPrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(true)?,
                    )?,
                ))
            }
            Request::WalletDeletePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::WalletDelete,
                )?;
                Ok(Response::WalletDeletePrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(true)?,
                    )?,
                ))
            }
            Request::KeyDerivePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::KeyDerive,
                )?;
                request.validate_petal_key_scope_binding()?;
                if let Some(scope) = &request.petal_key_scope {
                    self.authority
                        .prepare_petal_key_scope(scope)
                        .map_err(authority_error)?;
                }
                Ok(Response::KeyDerivePrepare(self.ceremony.prepare_custody(
                    translate_custody::prepare_to_signer(request),
                    self.clock.now_ms(true)?,
                )?))
            }
            Request::KeyEnrollPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::BackendEnrollment,
                )?;
                Ok(Response::KeyEnrollPrepare(self.ceremony.prepare_custody(
                    translate_custody::prepare_to_signer(request),
                    self.clock.now_ms(true)?,
                )?))
            }
            Request::AccountAllocatePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::AccountAllocate,
                )?;
                request.validate_account_allocation_binding()?;
                self.verify_account_terms_baseline(&request).await?;
                self.verify_wallet_supports_allocation(&request).await?;
                self.authority
                    .record_account_terms(
                        request.account_terms.as_ref().expect("validated terms"),
                        self.clock.now_ms(false)?,
                    )
                    .map_err(authority_error)?;
                Ok(Response::AccountAllocatePrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(false)?,
                    )?,
                ))
            }
            Request::AccountRetirePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::AccountRetire,
                )?;
                request.validate_account_retire_binding()?;
                self.verify_account_terms_baseline(&request).await?;
                self.verify_retire_target_matches_terms(&request).await?;
                self.authority
                    .record_account_terms(
                        request.account_terms.as_ref().expect("validated terms"),
                        self.clock.now_ms(false)?,
                    )
                    .map_err(authority_error)?;
                Ok(Response::AccountRetirePrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(false)?,
                    )?,
                ))
            }
            Request::CredentialAddPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::CredentialAdd,
                )?;
                Ok(Response::CredentialAddPrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(true)?,
                    )?,
                ))
            }
            Request::CredentialReplacePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::CredentialReplace,
                )?;
                Ok(Response::CredentialReplacePrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(true)?,
                    )?,
                ))
            }
            Request::CredentialRemovePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::CredentialRemove,
                )?;
                Ok(Response::CredentialRemovePrepare(
                    self.ceremony.prepare_custody(
                        translate_custody::prepare_to_signer(request),
                        self.clock.now_ms(true)?,
                    )?,
                ))
            }
            Request::RecoveryPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_broker_api::CeremonyKind::WalletRecovery,
                )?;
                Ok(Response::RecoveryPrepare(self.ceremony.prepare_custody(
                    translate_custody::prepare_to_signer(request),
                    self.clock.now_ms(true)?,
                )?))
            }
            Request::KeyListPublic(request) => {
                match self
                    .signer
                    .request_for_machine(BrokerSignerRequest::KeyListPublic(
                        translate_service::wallet_request_to_signer(request),
                    ))
                    .await?
                {
                    BrokerSignerResponse::KeyListPublic(keys) => Ok(Response::KeyListPublic(
                        keys.into_iter()
                            .map(translate_service::key_to_machine)
                            .collect(),
                    )),
                    _ => Err(response_mismatch("key.list_public")),
                }
            }
            Request::KeyGetPublic(request) => {
                match self
                    .signer
                    .request_for_machine(BrokerSignerRequest::KeyGetPublic(
                        translate_service::key_request_to_signer(request),
                    ))
                    .await?
                {
                    BrokerSignerResponse::KeyGetPublic(key) => Ok(Response::KeyGetPublic(
                        translate_service::key_to_machine(key),
                    )),
                    _ => Err(response_mismatch("key.get_public")),
                }
            }
            Request::KeyDerivationCapabilities(request) => {
                match self
                    .signer
                    .request_for_machine(BrokerSignerRequest::KeyDerivationCapabilities(
                        translate_service::key_request_to_signer(request),
                    ))
                    .await?
                {
                    BrokerSignerResponse::KeyDerivationCapabilities(capabilities) => {
                        Ok(Response::KeyDerivationCapabilities(capabilities))
                    }
                    _ => Err(response_mismatch("key.derivation_capabilities")),
                }
            }
            Request::KeyListDerived(request) => {
                match self
                    .signer
                    .request_for_machine(BrokerSignerRequest::KeyListDerived(
                        translate_service::key_request_to_signer(request),
                    ))
                    .await?
                {
                    BrokerSignerResponse::KeyListDerived(keys) => Ok(Response::KeyListDerived(
                        keys.into_iter()
                            .map(translate_service::key_to_machine)
                            .collect(),
                    )),
                    _ => Err(response_mismatch("key.list_derived")),
                }
            }
            Request::CredentialListPublic(request) => {
                match self
                    .signer
                    .request_for_machine(BrokerSignerRequest::CredentialListPublic(
                        translate_service::wallet_request_to_signer(request),
                    ))
                    .await?
                {
                    BrokerSignerResponse::CredentialListPublic(credentials) => {
                        Ok(Response::CredentialListPublic(
                            credentials
                                .into_iter()
                                .map(translate_service::credential_to_machine)
                                .collect(),
                        ))
                    }
                    _ => Err(response_mismatch("credential.list_public")),
                }
            }
            Request::CeremonyStatus(request) => {
                let operation_id = OperationId::new(request.id.as_str().to_owned())?;
                Ok(Response::CeremonyStatus(
                    self.ceremony.public_status(&operation_id)?,
                ))
            }
            Request::CeremonyCancel(request) => {
                let operation_id = OperationId::new(request.id.as_str().to_owned())?;
                self.ceremony
                    .cancel(&operation_id, self.clock.now_ms(false)?)?;
                Ok(Response::CeremonyCancel(
                    self.ceremony.public_status(&operation_id)?,
                ))
            }
            Request::CustodyResult(request) => {
                match self
                    .signer
                    .request_for_machine(BrokerSignerRequest::CustodyResult(
                        bloom_signer_api::OperationRequest {
                            operation_id: request.operation_id,
                        },
                    ))
                    .await?
                {
                    BrokerSignerResponse::CustodyResult(result) => Ok(Response::CustodyResult(
                        translate_custody::result_to_machine(result),
                    )),
                    _ => Err(response_mismatch("custody.result")),
                }
            }
        }
    }

    async fn prepare_approval(
        &self,
        request: ApprovalPrepareRequest,
    ) -> Result<SealedApprovalPrepareResponse, ProtocolError> {
        if request.petal_use_claim.is_some() && request.system_use_claim.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "an approval cannot bind both Petal and system claims",
            ));
        }
        self.reconcile_wallet(&request.terms.wallet_id).await?;
        let (exact_ordered_payload_digests, exact_ordered_hashes) = match &request.terms.selector {
            ApprovalSelector::Exact {
                ordered_payload_digests,
                ordered_hashes,
            } => (ordered_payload_digests.clone(), ordered_hashes.clone()),
            ApprovalSelector::Petal { .. } => (Vec::new(), Vec::new()),
        };
        let ceremony_request = bloom_signer_api::CeremonyPrepareRequest {
            activation_operation_id: request.operation_id.clone(),
            terms: translate_approval::validated_terms_to_signer(request.terms.clone()),
            review_manifest_digest: request.canonical_plan_facts_digest,
            exact_ordered_payload_digests,
            exact_ordered_hashes,
            replacement_approval_id: request.terms.renewal_of.clone(),
        };
        let claim_assurance = request
            .petal_use_claim
            .as_ref()
            .map(|claim| claim.claim_assurance.clone())
            .or_else(|| {
                request
                    .system_use_claim
                    .as_ref()
                    .map(|claim| claim.claim_assurance.clone())
            });
        let approved_claim_digest = request
            .petal_use_claim
            .as_ref()
            .map(jcs_digest)
            .transpose()?
            .or(request
                .system_use_claim
                .as_ref()
                .map(jcs_digest)
                .transpose()?);
        let response = self.ceremony.prepare_approval(
            ceremony_request,
            ReviewManifestContext {
                petal_use_claim: request.petal_use_claim,
                system_use_claim: request.system_use_claim,
                claim_assurance,
                attributed_advisory_items: Vec::new(),
            },
            self.clock.now_ms(true)?,
        )?;
        if let Err(error) = self
            .authority
            .prepare_approval_with_claim(
                &request.terms,
                &response.review_manifest_digest,
                approved_claim_digest.as_ref(),
            )
            .map_err(authority_error)
        {
            let _ = self
                .ceremony
                .cancel(&request.operation_id, self.clock.now_ms(false)?);
            return Err(error);
        }
        Ok(response)
    }

    fn approval_public_status(
        &self,
        approval_id: &Digest32,
    ) -> Result<bloom_broker_api::ApprovalPublicStatus, ProtocolError> {
        let mut status = self
            .authority
            .approval_public_status(approval_id)
            .map_err(authority_error)?;
        self.attach_pending_approval_ceremony(&mut status);
        Ok(status)
    }

    fn attach_pending_approval_ceremony(
        &self,
        status: &mut bloom_broker_api::ApprovalPublicStatus,
    ) {
        if let Some((url, expires_at_ms)) =
            self.ceremony.pending_approval_ceremony(&status.approval_id)
        {
            status.ceremony_url = Some(url);
            status.ceremony_expires_at_ms = Some(expires_at_ms);
            return;
        }
        // An approval whose ceremony died still reports `AwaitingCeremony`,
        // but with no URL to await — a state the caller can neither act on
        // nor escape, because cancelling also needs a ceremony. Report the
        // terminal truth so it starts a fresh approval instead of polling a
        // ceremony that no longer exists.
        if matches!(
            status.state,
            ApprovalLifecycleState::Prepared | ApprovalLifecycleState::AwaitingCeremony
        ) && self
            .ceremony
            .approval_ceremony_unreachable(&status.approval_id)
        {
            status.state = ApprovalLifecycleState::Expired;
        }
    }

    async fn prepare_policy_update(
        &self,
        request: PolicyUpdateRequest,
    ) -> Result<bloom_broker_api::PolicyUpdatePrepareResponse, ProtocolError> {
        let signer_update = translate_policy::update_to_signer(request.clone());
        if let Some(response) = self.ceremony.recover_policy_update_prepare(&signer_update) {
            return response;
        }
        let authority_diff = self
            .authority
            .validate_policy_update(&request)
            .map_err(authority_error)?;
        let signer_baseline = self
            .policy_read(&WalletRequest {
                wallet_id: request.wallet_id.clone(),
            })
            .await?;
        if signer_baseline.version != request.baseline_version
            || signer_baseline.policy_digest != request.baseline_digest
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::PolicyBaselineStale,
                "Signer-authenticated policy baseline is stale",
            ));
        }
        let now = self.clock.now_ms(true)?;
        let mut review = PolicyUpdateReviewManifest {
            schema: Token::new("bloom.policy-update-review/1")?,
            operation_id: request.operation_id.clone(),
            wallet_id: request.wallet_id.clone(),
            baseline_version: request.baseline_version.clone(),
            baseline_digest: request.baseline_digest.clone(),
            proposed_policy_digest: request.proposed_policy_digest.clone(),
            authority_diff_digest: request.authority_diff_digest.clone(),
            authority_diff,
            assurance_level: request.assurance_level.clone(),
            issued_at_ms: DecimalU64::new(now),
            expires_at_ms: DecimalU64::new(now.saturating_add(10 * 60 * 1_000)),
            broker_key_id: self.signing_key_id.clone(),
            broker_signature: Base64UrlBytes::from_bytes(&[]),
        };
        review.broker_signature =
            self.sign_domain(POLICY_REVIEW_DOMAIN, &review.unsigned_canonical_bytes()?);
        let review_manifest_digest = review.digest()?;
        let update_terms_digest = request.terms_digest()?;
        let mut validation = PolicyValidationReceipt {
            update_terms_digest: update_terms_digest.clone(),
            review_manifest_digest: review_manifest_digest.clone(),
            broker_key_id: self.signing_key_id.clone(),
            broker_signature: Base64UrlBytes::from_bytes(&[]),
        };
        validation.broker_signature = self.sign_domain(
            POLICY_VALIDATION_DOMAIN,
            &validation
                .unsigned_canonical_bytes()
                .map_err(translate_error::signer_error_to_machine)?,
        );
        self.ceremony.prepare_policy_update(
            PolicyUpdateCeremonyPrepareRequest {
                custody: bloom_signer_api::CustodyPrepareRequest {
                    ceremony_kind: bloom_signer_api::CeremonyKind::PolicyUpdate,
                    custody_operation_id: request.operation_id.clone(),
                    wallet_id: Some(request.wallet_id.clone()),
                    key_ref: None,
                    exact_terms_digest: update_terms_digest,
                    expected_input_class: Token::new("policy_update_credential_prf")?,
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
                },
                update: signer_update,
                broker_validation_receipt: validation,
            },
            review,
            now,
        )
    }

    fn sign_domain(&self, domain: &[u8], message: &[u8]) -> Base64UrlBytes {
        let mut preimage = Vec::with_capacity(domain.len() + message.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(message);
        Base64UrlBytes::from_bytes(&self.signing_key.sign(&preimage).to_bytes())
    }

    async fn renew_approval(
        &self,
        request: ApprovalRenewRequest,
    ) -> Result<SealedApprovalPrepareResponse, ProtocolError> {
        if request.replacement_terms.renewal_of.as_ref() != Some(&request.old_approval_id) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "renewal terms do not name the requested predecessor",
            ));
        }
        self.prepare_approval(ApprovalPrepareRequest {
            operation_id: request.operation_id,
            canonical_plan_facts_digest: request.replacement_terms.approval_digest()?,
            terms: request.replacement_terms,
            petal_use_claim: None,
            system_use_claim: None,
        })
        .await
    }

    async fn sign(
        &self,
        request: MachineSignRequest,
        is_batch: bool,
    ) -> Result<bloom_broker_api::SigningResult, ProtocolError> {
        let signature_count = match &request.payloads {
            SigningPayloads::Single { .. } => 1,
            SigningPayloads::Batch { children } => children.len(),
        };
        let ordered_messages = if request.crypto_suite
            == bloom_broker_api::CryptoSuite::Ed25519Message
        {
            match &request.payloads {
                SigningPayloads::Single { payload } => {
                    vec![bloom_signer_api::Base64UrlBytes::from_bytes(
                        &payload.decode(),
                    )]
                }
                SigningPayloads::Batch { children } => children
                    .iter()
                    .map(|message| bloom_signer_api::Base64UrlBytes::from_bytes(&message.decode()))
                    .collect(),
            }
        } else {
            Vec::new()
        };
        let terms = self
            .authority
            .approval_terms(&request.approval_id)
            .map_err(authority_error)?
            .ok_or_else(|| {
                ProtocolError::new(ProtocolErrorCode::ApprovalNotFound, "approval not found")
            })?;
        let trusted_time_required = !terms.limits.operation_rate_limits.is_empty()
            || !terms.limits.signature_rate_limits.is_empty()
            || terms
                .limits
                .value_limits
                .iter()
                .any(|limit| !limit.rolling_windows.is_empty());
        let clock = self.clock.observe(trusted_time_required)?;
        let reserved_at_ms = clock.effective_now_ms;
        self.reconcile_wallet(&terms.wallet_id).await?;
        // Resolve the account the approval pinned to its canonical public
        // key, so a native Solana claim can bind its fee payer to it. This is
        // the only layer that can: authority is synchronous and journal-
        // backed, while the account projection comes from the Signer.
        let expected_signer_public_key = self.resolve_terms_signer_public_key(&terms).await?;
        let decision = self
            .authority
            .authorize_for_clock_profile(
                &AuthorizationInput {
                    request: request.clone(),
                    expected_signer_public_key,
                    reserved_at_ms,
                    observed_utc_ms: clock.observed_utc_ms,
                    monotonic_anchor_ns: clock.monotonic_anchor_ns,
                    clock_boot_epoch: clock.boot_epoch,
                },
                self.clock.uses_durable_clock_guard(),
            )
            .map_err(authority_error)?;
        let mut attempt_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut attempt_bytes);
        let claim_digest = request
            .petal_use_claim
            .as_ref()
            .map(jcs_digest)
            .transpose()?
            .or(request
                .system_use_claim
                .as_ref()
                .map(jcs_digest)
                .transpose()?);
        let assurance_digest = request
            .petal_use_claim
            .as_ref()
            .map(|claim| jcs_digest(&claim.claim_assurance))
            .transpose()?
            .or(request
                .system_use_claim
                .as_ref()
                .map(|claim| jcs_digest(&claim.claim_assurance))
                .transpose()?);
        let mut validation_receipt = BrokerValidationReceipt {
            approval_id: request.approval_id.clone(),
            approval_digest: terms.approval_digest()?,
            operation_digest: request.operation_digest.clone(),
            policy_version: terms.policy_version.clone(),
            policy_digest: terms.policy_digest.clone(),
            claim_digest: claim_digest.clone(),
            assurance_digest: assurance_digest.clone(),
            reservation_ids: decision.reservation_ids.clone(),
            effective_claim_assurance: decision
                .effective_assurance
                .clone()
                .map(translate_signing::assurance_to_signer),
            broker_key_id: self.signing_key_id.clone(),
            broker_signature: Base64UrlBytes::from_bytes(&[]),
        };
        validation_receipt.broker_signature = Base64UrlBytes::from_bytes(
            &self
                .signing_key
                .sign(
                    &validation_receipt
                        .signature_message()
                        .map_err(translate_error::signer_error_to_machine)?,
                )
                .to_bytes(),
        );
        let validation_receipt_digest = validation_receipt
            .digest()
            .map_err(translate_error::signer_error_to_machine)?;
        let mut unsigned = UnsignedSignRequest {
            schema: Token::new(BROKER_SIGN_REQUEST_SCHEMA)?,
            attempt_id: Digest32::from_bytes(attempt_bytes),
            operation_id: request.operation_id.clone(),
            operation_digest: request.operation_digest,
            attempt_digest: Digest32::from_bytes([0; 32]),
            audience: Token::new("bloom-signer")?,
            issuer_service_id: Token::new("bloom-broker")?,
            issuer_boot_epoch: self.boot_epoch.clone(),
            broker_signing_key_id: self.signing_key_id.clone(),
            approval_id: request.approval_id.clone(),
            wallet_id: terms.wallet_id,
            key_ref: translate_key::key_ref_to_signer(request.key_ref),
            crypto_suite: translate_key::crypto_suite_to_signer(request.crypto_suite),
            selector_kind: translate_signing::selector_to_signer(&terms.selector),
            ordered_payload_digests: decision.ordered_payload_digests,
            ordered_hashes: decision.ordered_hashes,
            ordered_messages,
            signature_count: DecimalU64::new(signature_count as u64),
            petal_use_claim_digest: claim_digest,
            claim_assurance_digest: assurance_digest,
            policy_version: terms.policy_version,
            policy_digest: terms.policy_digest,
            validation_receipt_digest,
            issued_at_ms: DecimalU64::new(reserved_at_ms),
            not_before_ms: DecimalU64::new(reserved_at_ms),
            expires_at_ms: DecimalU64::new(
                reserved_at_ms
                    .saturating_add(30_000)
                    .min(terms.expires_at_ms.get()),
            ),
        };
        unsigned.attempt_digest = unsigned
            .computed_attempt_digest()
            .map_err(translate_error::signer_error_to_machine)?;
        let snapshot = self
            .journal
            .begin_sign_attempt(&unsigned, is_batch, &validation_receipt)
            .map_err(journal_error)?;
        if let Some(result) = snapshot.result {
            return Ok(result);
        }
        match snapshot.state {
            OperationState::Received => {
                self.transition_operation(&unsigned.operation_id, OperationState::Validated)?;
                self.transition_operation(&unsigned.operation_id, OperationState::Reserved)?;
                self.transition_operation(&unsigned.operation_id, OperationState::Dispatched)?;
            }
            OperationState::Validated => {
                self.transition_operation(&unsigned.operation_id, OperationState::Reserved)?;
                self.transition_operation(&unsigned.operation_id, OperationState::Dispatched)?;
            }
            OperationState::Reserved => {
                self.transition_operation(&unsigned.operation_id, OperationState::Dispatched)?;
            }
            OperationState::Dispatched
            | OperationState::DownstreamAccepted
            | OperationState::Committed => {
                return self
                    .resolve_signer_operation(
                        &unsigned.operation_id,
                        &unsigned.approval_id,
                        is_batch,
                    )
                    .await;
            }
            OperationState::Quarantined => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::AmbiguousProviderEffect,
                    "operation is durably quarantined",
                ));
            }
            OperationState::Denied
            | OperationState::Cancelled
            | OperationState::Failed
            | OperationState::Succeeded => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "terminal operation has no publishable result",
                ));
            }
        }
        let request = SignRequest {
            broker_signature: Base64UrlBytes::from_bytes(
                &self
                    .signing_key
                    .sign(&unsigned.attempt_digest.to_bytes())
                    .to_bytes(),
            ),
            unsigned,
        };
        let operation_id = request.unsigned.operation_id.clone();
        let approval_id = request.unsigned.approval_id.clone();
        let response = self
            .signer
            .request_for_machine(if is_batch {
                BrokerSignerRequest::SignerSignBatch(request)
            } else {
                BrokerSignerRequest::SignerSign(request)
            })
            .await;
        if let Err(error) = &response {
            tracing::warn!(
                event = "broker.signer_operation_rejected",
                operation_id = operation_id.as_str(),
                protocol_error_code = error.code.as_str(),
                "Signer rejected Broker operation"
            );
        }
        match response {
            Ok(response) => {
                let result = exact_signing_response(is_batch, response)?;
                self.commit_signer_result(&approval_id, result.clone(), is_batch)?;
                Ok(translate_signing::result_to_machine(result))
            }
            Err(error) if error.code == ProtocolErrorCode::AmbiguousProviderEffect => {
                self.journal
                    .transition_operation(&operation_id, OperationState::Quarantined)
                    .map_err(journal_error)?;
                self.journal
                    .finalize_reservation(
                        &approval_id,
                        &operation_id,
                        ReservationState::Quarantined,
                    )
                    .map_err(journal_error)?;
                Err(error)
            }
            Err(error)
                if matches!(
                    error.code,
                    ProtocolErrorCode::BackendInvalidRequest
                        | ProtocolErrorCode::BackendUnsupported
                        | ProtocolErrorCode::ApprovalNotFound
                        | ProtocolErrorCode::ApprovalExpired
                        | ProtocolErrorCode::ApprovalRevoked
                        | ProtocolErrorCode::KeyrefMismatch
                        | ProtocolErrorCode::SuiteNotAllowed
                        | ProtocolErrorCode::SelectorMismatch
                        | ProtocolErrorCode::SignerRateBackstopDenied
                ) =>
            {
                self.transition_operation(&operation_id, OperationState::Failed)?;
                self.journal
                    .finalize_reservation(&approval_id, &operation_id, ReservationState::Released)
                    .map_err(journal_error)?;
                Err(error)
            }
            Err(error) => match self
                .resolve_signer_operation(&operation_id, &approval_id, is_batch)
                .await
            {
                Ok(result) => Ok(result),
                Err(status_error) if status_error.code != ProtocolErrorCode::ServiceUnavailable => {
                    Err(status_error)
                }
                Err(_) => Err(error),
            },
        }
    }

    async fn resolve_signer_operation(
        &self,
        operation_id: &OperationId,
        approval_id: &Digest32,
        is_batch: bool,
    ) -> Result<bloom_broker_api::SigningResult, ProtocolError> {
        let status = match self
            .signer
            .request_for_machine(BrokerSignerRequest::OperationStatus(
                bloom_signer_api::OperationRequest {
                    operation_id: operation_id.clone(),
                },
            ))
            .await?
        {
            BrokerSignerResponse::OperationStatus(status) => status,
            _ => return Err(response_mismatch("operation.status")),
        };
        match (status.state, status.result) {
            (bloom_signer_api::OperationState::Succeeded, Some(result)) => {
                self.commit_signer_result(approval_id, result.clone(), is_batch)?;
                Ok(translate_signing::result_to_machine(result))
            }
            (bloom_signer_api::OperationState::Quarantined, _) => {
                self.transition_to_quarantined(operation_id)?;
                self.journal
                    .finalize_reservation(approval_id, operation_id, ReservationState::Quarantined)
                    .map_err(journal_error)?;
                Err(ProtocolError::new(
                    ProtocolErrorCode::AmbiguousProviderEffect,
                    "Signer reports an ambiguous provider effect",
                ))
            }
            (
                bloom_signer_api::OperationState::Denied
                | bloom_signer_api::OperationState::Cancelled
                | bloom_signer_api::OperationState::Failed,
                _,
            ) => {
                self.transition_to_failed(operation_id)?;
                self.journal
                    .finalize_reservation(approval_id, operation_id, ReservationState::Released)
                    .map_err(journal_error)?;
                Err(ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    "Signer reports a definite terminal failure",
                ))
            }
            _ => Err(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer operation has not reached a reconcilable terminal state",
            )),
        }
    }

    fn commit_signer_result(
        &self,
        approval_id: &Digest32,
        result: bloom_signer_api::SigningResult,
        is_batch: bool,
    ) -> Result<(), ProtocolError> {
        let validation_receipt = self
            .journal
            .validation_receipt(&result.operation_id)
            .map_err(journal_error)?
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "operation omitted its retained Broker validation receipt",
                )
            })?;
        self.verify_validation_receipt(&validation_receipt)?;
        let snapshot = self
            .journal
            .operation(&result.operation_id)
            .map_err(journal_error)?
            .ok_or_else(|| {
                ProtocolError::new(ProtocolErrorCode::ApprovalNotFound, "operation not found")
            })?;
        let expected_signature_count = self
            .journal
            .reservation_signature_count(approval_id, &result.operation_id)
            .map_err(journal_error)?
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "Signer result has no matching Broker reservation",
                )
            })?;
        validate_signer_result_shape(&snapshot, &result, is_batch, expected_signature_count)?;
        let result = translate_signing::result_to_machine(result);
        match snapshot.state {
            OperationState::Dispatched => {
                self.transition_operation(
                    &result.operation_id,
                    OperationState::DownstreamAccepted,
                )?;
                self.transition_operation(&result.operation_id, OperationState::Committed)?;
            }
            OperationState::DownstreamAccepted => {
                self.transition_operation(&result.operation_id, OperationState::Committed)?;
            }
            OperationState::Committed => {}
            OperationState::Succeeded if snapshot.result.as_ref() == Some(&result) => return Ok(()),
            _ => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "Broker operation state cannot publish the Signer result",
                ));
            }
        }
        if is_batch {
            let children = result
                .signatures
                .iter()
                .enumerate()
                .map(|(ordinal, signature)| {
                    Ok(bloom_broker_api::SigningResult {
                        operation_id: crate::journal::derive_batch_child_operation_id(
                            &result.operation_id,
                            ordinal,
                        )?,
                        operation_digest: result.operation_digest.clone(),
                        signatures: vec![signature.clone()],
                        signer_receipt_digest: result.signer_receipt_digest.clone(),
                        broker_receipt_digest: result.broker_receipt_digest.clone(),
                    })
                })
                .collect::<Result<Vec<_>, JournalError>>()
                .map_err(journal_error)?;
            self.journal
                .publish_batch(approval_id, &result, &children)
                .map_err(journal_error)
        } else {
            self.journal
                .publish_result(approval_id, &result)
                .map_err(journal_error)
        }
    }

    fn verify_validation_receipt(
        &self,
        receipt: &BrokerValidationReceipt,
    ) -> Result<(), ProtocolError> {
        verify_broker_validation_receipt(
            receipt,
            &self.signing_key_id,
            &self.signing_key.verifying_key(),
        )
    }
}

fn verify_broker_validation_receipt(
    receipt: &BrokerValidationReceipt,
    expected_key_id: &Token,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ProtocolError> {
    if &receipt.broker_key_id != expected_key_id {
        return Err(ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "Broker validation receipt key ID changed",
        ));
    }
    let signature = Signature::from_slice(&receipt.broker_signature.decode()).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "Broker validation receipt signature is malformed",
        )
    })?;
    verifying_key
        .verify(
            &receipt
                .signature_message()
                .map_err(translate_error::signer_error_to_machine)?,
            &signature,
        )
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "Broker validation receipt signature is invalid",
            )
        })
}

impl BrokerRpcService {
    fn transition_operation(
        &self,
        operation_id: &OperationId,
        next: OperationState,
    ) -> Result<(), ProtocolError> {
        self.journal
            .transition_operation(operation_id, next)
            .map_err(journal_error)
    }

    fn transition_to_quarantined(&self, operation_id: &OperationId) -> Result<(), ProtocolError> {
        let state = self
            .journal
            .operation(operation_id)
            .map_err(journal_error)?
            .ok_or_else(|| {
                ProtocolError::new(ProtocolErrorCode::ApprovalNotFound, "operation not found")
            })?
            .state;
        if state != OperationState::Quarantined {
            self.transition_operation(operation_id, OperationState::Quarantined)?;
        }
        Ok(())
    }

    fn transition_to_failed(&self, operation_id: &OperationId) -> Result<(), ProtocolError> {
        let state = self
            .journal
            .operation(operation_id)
            .map_err(journal_error)?
            .ok_or_else(|| {
                ProtocolError::new(ProtocolErrorCode::ApprovalNotFound, "operation not found")
            })?
            .state;
        if !matches!(
            state,
            OperationState::Failed | OperationState::Denied | OperationState::Cancelled
        ) {
            self.transition_operation(operation_id, OperationState::Failed)?;
        }
        Ok(())
    }

    pub async fn reconcile_all(&self) -> Result<(), ProtocolError> {
        let wallet_ids = self.authority.wallet_ids().map_err(authority_error)?;
        tracing::info!(
            event = "reconciliation.started",
            wallet_count = wallet_ids.len(),
            "Broker revocation reconciliation started"
        );
        for wallet_id in wallet_ids {
            self.reconcile_wallet(&wallet_id).await?;
        }
        tracing::info!(
            event = "reconciliation.completed",
            outcome = "converged",
            "Broker revocation reconciliation completed"
        );
        Ok(())
    }

    /// The canonical public key of the account named by `terms.key_ref`, when
    /// that account is an Ed25519 child projected by the Signer.
    ///
    /// Returns `None` for terms whose key is not a projected Ed25519 account
    /// — every non-Solana approval — so this stays a no-op for existing
    /// flows. Native Solana verification refuses to proceed on `None` rather
    /// than treating an unresolvable account as unconstrained.
    async fn resolve_terms_signer_public_key(
        &self,
        terms: &bloom_broker_api::SealedApprovalTerms,
    ) -> Result<Option<[u8; 32]>, ProtocolError> {
        if terms.key_ref.key_spec != bloom_broker_api::KeySpec::Ed25519 {
            return Ok(None);
        }
        let accounts = self.wallet_accounts(terms.wallet_id.clone()).await?;
        let Some(account) = accounts
            .accounts
            .iter()
            .find(|account| account.key_ref == terms.key_ref)
        else {
            return Ok(None);
        };
        if account.public_key_encoding != bloom_broker_api::PublicKeyEncoding::Ed25519SpkiDer {
            return Ok(None);
        }
        // Canonical Ed25519 SPKI DER: a fixed 12-byte prefix then the raw key.
        const ED25519_SPKI_PREFIX: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let spki = account.canonical_public_key.decode();
        if spki.len() != 44 || spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
            return Ok(None);
        }
        let mut key = [0_u8; 32];
        key.copy_from_slice(&spki[ED25519_SPKI_PREFIX.len()..]);
        Ok(Some(key))
    }

    async fn reconcile_wallet(&self, wallet_id: &Token) -> Result<(), ProtocolError> {
        let mut snapshot = self.revocation_snapshot(wallet_id).await?;
        loop {
            match self
                .authority
                .reconcile_revocation(&snapshot.state, &snapshot.approval_tombstones)
                .map_err(authority_error)?
            {
                EpochReconciliation::Converged => {
                    tracing::info!(
                        event = "reconciliation.wallet_completed",
                        wallet_id = wallet_id.as_str(),
                        outcome = "converged",
                        "Broker wallet revocation state reconciled"
                    );
                    return Ok(());
                }
                EpochReconciliation::AdoptedSignerEpoch => {
                    tracing::info!(
                        event = "reconciliation.wallet_completed",
                        wallet_id = wallet_id.as_str(),
                        outcome = "adopted_signer_epoch",
                        "Broker adopted Signer revocation epoch"
                    );
                    return Ok(());
                }
                EpochReconciliation::PushLocalEpoch => {
                    let local_epoch = self
                        .authority
                        .wallet_epoch(wallet_id)
                        .map_err(authority_error)?;
                    if snapshot.state.wallet_revocation_epoch.get() >= local_epoch {
                        return Err(ProtocolError::new(
                            ProtocolErrorCode::RevocationEpochUnreconciled,
                            "revocation reconciliation made no monotonic progress",
                        ));
                    }
                    let mut operation_bytes = [0_u8; 32];
                    OsRng.fill_bytes(&mut operation_bytes);
                    let operation_id = OperationId::from_bytes(operation_bytes);
                    match self
                        .signer
                        .request_for_machine(BrokerSignerRequest::SealedApprovalRevokeAll(
                            bloom_signer_api::WalletOperationRequest {
                                operation_id: operation_id.clone(),
                                wallet_id: wallet_id.clone(),
                            },
                        ))
                        .await?
                    {
                        BrokerSignerResponse::SealedApprovalRevokeAll(_) => {}
                        _ => return Err(response_mismatch("sealed_approval.revoke_all")),
                    }
                    tracing::info!(
                        event = "reconciliation.wallet_advanced",
                        wallet_id = wallet_id.as_str(),
                        operation_id = operation_id.as_str(),
                        outcome = "pushed_local_epoch",
                        "Broker pushed local revocation epoch to Signer"
                    );
                    snapshot = self.revocation_snapshot(wallet_id).await?;
                }
            }
        }
    }

    async fn revocation_snapshot(
        &self,
        wallet_id: &Token,
    ) -> Result<bloom_broker_api::RevocationSnapshot, ProtocolError> {
        match self
            .signer
            .request_for_machine(BrokerSignerRequest::RevocationState(
                bloom_signer_api::WalletRequest {
                    wallet_id: wallet_id.clone(),
                },
            ))
            .await?
        {
            BrokerSignerResponse::RevocationState(snapshot) => {
                Ok(translate_revocation::snapshot_to_machine(snapshot))
            }
            _ => Err(response_mismatch("revocation.state")),
        }
    }

    async fn policy_read(
        &self,
        request: &WalletRequest,
    ) -> Result<bloom_broker_api::SignedPolicySnapshot, ProtocolError> {
        let snapshot = self.signer_policy_read(&request.wallet_id).await?;
        let snapshot = translate_policy::snapshot_to_machine(snapshot);
        self.authority
            .install_policy(&snapshot)
            .map_err(authority_error)?;
        Ok(snapshot)
    }

    async fn signer_policy_read(
        &self,
        wallet_id: &Token,
    ) -> Result<bloom_signer_api::SignedPolicySnapshot, ProtocolError> {
        match self
            .signer
            .request_for_machine(BrokerSignerRequest::PolicyRead(
                bloom_signer_api::WalletRequest {
                    wallet_id: wallet_id.clone(),
                },
            ))
            .await?
        {
            BrokerSignerResponse::PolicyRead(snapshot) => Ok(snapshot),
            _ => Err(response_mismatch("policy.read")),
        }
    }

    async fn wallet_public(&self, wallet_id: Token) -> Result<WalletPublic, ProtocolError> {
        let policy = self
            .policy_read(&WalletRequest {
                wallet_id: wallet_id.clone(),
            })
            .await?;
        let mut keys = match self
            .signer
            .request_for_machine(BrokerSignerRequest::KeyListPublic(
                bloom_signer_api::WalletRequest {
                    wallet_id: wallet_id.clone(),
                },
            ))
            .await?
        {
            BrokerSignerResponse::KeyListPublic(keys) => keys,
            _ => return Err(response_mismatch("key.list_public")),
        };
        let root_key_ref = unique_wallet_root(&keys)?;
        // A BIP-39 wallet has no signable root: its KeyListPublic already
        // carries the derived accounts and there is no root to enumerate
        // derived keys from. Legacy wallets keep the root enumeration.
        if let Some(root_key_ref) = root_key_ref.clone() {
            let derived = match self
                .signer
                .request_for_machine(BrokerSignerRequest::KeyListDerived(
                    translate_service::key_request_to_signer(bloom_broker_api::KeyRequest {
                        key_ref: root_key_ref,
                    }),
                ))
                .await?
            {
                BrokerSignerResponse::KeyListDerived(keys) => keys,
                _ => return Err(response_mismatch("key.list_derived")),
            };
            if derived
                .iter()
                .any(|key| key.role != bloom_signer_api::KeyRole::Derived)
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::KeyrefMismatch,
                    "Signer returned a non-derived key from key.list_derived",
                ));
            }
            keys.extend(derived);
        }
        let mut key_refs: Vec<bloom_broker_api::KeyRef> = keys
            .into_iter()
            .map(|key| translate_key::key_ref_to_machine(key.key_ref))
            .collect();
        // BIP-39 derived accounts come from Signer's lock-free registry read;
        // they are not Signer root keys.
        if let BrokerSignerResponse::DerivedAccountList(descriptors) = self
            .signer
            .request_for_machine(BrokerSignerRequest::DerivedAccountList(
                bloom_signer_api::WalletRequest {
                    wallet_id: wallet_id.clone(),
                },
            ))
            .await?
        {
            for descriptor in descriptors {
                let key_ref = translate_key::key_ref_to_machine(descriptor.key_ref);
                if !key_refs.contains(&key_ref) {
                    key_refs.push(key_ref);
                }
            }
        } else {
            return Err(response_mismatch("wallet.derived_accounts"));
        }
        Ok(WalletPublic {
            wallet_revocation_epoch: DecimalU64::new(
                self.authority
                    .wallet_epoch(&wallet_id)
                    .map_err(authority_error)?,
            ),
            wallet_id,
            wallet_kind: Token::new("managed")?,
            root_key_ref,
            key_refs,
            policy_version: policy.version,
            policy_digest: policy.policy_digest,
        })
    }

    async fn wallet_accounts(
        &self,
        wallet_id: Token,
    ) -> Result<WalletAccountsPublic, ProtocolError> {
        // The authoritative lock-free read: Signer serves the persisted
        // derivation registry without unlocking the backend. Broker owns no
        // second copy of account inventory.
        let descriptors = match self
            .signer
            .request_for_machine(BrokerSignerRequest::DerivedAccountList(
                bloom_signer_api::WalletRequest {
                    wallet_id: wallet_id.clone(),
                },
            ))
            .await?
        {
            BrokerSignerResponse::DerivedAccountList(descriptors) => descriptors,
            _ => return Err(response_mismatch("wallet.derived_accounts")),
        };
        if descriptors.is_empty() {
            // No derived accounts, so the seed profile cannot come from a
            // descriptor. It is still read from what the Signer projects
            // rather than inferred from whether a root happens to exist:
            // that inference reported a legacy BIP-32 wallet as
            // `imported-secp256k1-scalar`, which is defined as having no
            // derivable seed — a false statement about custody.
            let public = self.wallet_public(wallet_id.clone()).await?;
            let seed_profile = seed_profile_from_key_projection(&public)?;
            return Ok(WalletAccountsPublic {
                wallet_id,
                seed_profile,
                accounts: Vec::new(),
            });
        }
        // Fail closed on an ambiguous root: every descriptor must name this
        // wallet and agree on one seed profile before anything is projected.
        let profile = descriptors[0].wallet_seed_ref.profile;
        if descriptors
            .iter()
            .any(|descriptor| descriptor.wallet_seed_ref.wallet_id != wallet_id)
            || descriptors
                .iter()
                .any(|descriptor| descriptor.wallet_seed_ref.profile != profile)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "wallet derived accounts disagree on their seed root",
            ));
        }
        let targets = translate_wallet_account::production_chain_targets();
        for descriptor in &descriptors {
            if !targets
                .iter()
                .any(|target| target.accepted_profile == descriptor.derivation_profile)
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "wallet contains a derivation profile with no chain projection",
                ));
            }
            let frozen = translate_wallet_account::derivation_profile_to_machine(
                descriptor.derivation_profile,
            )
            .frozen_crypto_suites();
            let recorded: Vec<bloom_broker_api::CryptoSuite> = descriptor
                .supported_crypto_suites
                .iter()
                .map(|suite| translate_key::crypto_suite_to_machine(*suite))
                .collect();
            if recorded != frozen {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::KeyrefMismatch,
                    "derived account suites do not match its profile's frozen set",
                ));
            }
        }
        translate_wallet_account::wallet_accounts_to_machine(
            wallet_id,
            profile,
            &descriptors,
            &targets,
        )
    }

    /// The terms' policy/revocation baseline must match Broker's live
    /// authority state at prepare time; a stale or tampered baseline fails
    /// closed instead of allocating under terms nobody authorized.
    async fn verify_account_terms_baseline(
        &self,
        request: &bloom_broker_api::CustodyPrepareRequest,
    ) -> Result<(), ProtocolError> {
        let terms = request.account_terms.as_ref().expect("validated terms");
        let wallet_id = terms.wallet_id.clone();
        let epoch = self
            .authority
            .wallet_epoch(&wallet_id)
            .map_err(authority_error)?;
        if terms.revocation_epoch.get() != epoch {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "account terms revocation epoch does not match the wallet",
            ));
        }
        let policy = self
            .policy_read(&bloom_broker_api::WalletRequest {
                wallet_id: wallet_id.clone(),
            })
            .await?;
        if terms.policy_version.get() != policy.version.get() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "account terms policy version does not match the wallet",
            ));
        }
        let now_ms = self.clock.now_ms(false)?;
        if terms.expires_at_ms.get() <= now_ms {
            return Err(ProtocolError::new(
                ProtocolErrorCode::LimitExceededFrame,
                "account terms have expired",
            ));
        }
        Ok(())
    }

    /// Allocation is legal only against a wallet whose registered accounts
    /// already agree on the BIP-39 multi-curve seed profile. A legacy
    /// wallet, an unknown wallet, or a wallet mid-profile-change fails
    /// closed.
    async fn verify_wallet_supports_allocation(
        &self,
        request: &bloom_broker_api::CustodyPrepareRequest,
    ) -> Result<(), ProtocolError> {
        let terms = request.account_terms.as_ref().expect("validated terms");
        let accounts = self
            .wallet_accounts(terms.wallet_id.clone())
            .await
            .map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::KeyrefMismatch,
                    format!("wallet cannot host account allocation: {}", error.message),
                )
            })?;
        if accounts.seed_profile != terms.seed_profile {
            return Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "wallet seed profile does not match the account terms",
            ));
        }
        Ok(())
    }

    /// Retirement terms must name the child Signer currently holds: the
    /// live descriptor's fingerprint, profile, wallet, and active lifecycle
    /// all have to agree with the committed terms.
    async fn verify_retire_target_matches_terms(
        &self,
        request: &bloom_broker_api::CustodyPrepareRequest,
    ) -> Result<(), ProtocolError> {
        let terms = request.account_terms.as_ref().expect("validated terms");
        let key_ref = request.key_ref.clone().expect("validated key ref");
        let accounts = self.wallet_accounts(terms.wallet_id.clone()).await?;
        let Some(account) = accounts
            .accounts
            .iter()
            .find(|account| account.key_ref == key_ref)
        else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "retired child is not an active derived account of this wallet",
            ));
        };
        if account.public_key_fingerprint
            != terms
                .retire_key_fingerprint
                .clone()
                .expect("validated terms")
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "retired child fingerprint does not match the account terms",
            ));
        }
        if account.lifecycle != bloom_broker_api::AccountLifecycleState::Active {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "retired child is not active",
            ));
        }
        Ok(())
    }

    fn operation_status(
        &self,
        operation_id: &OperationId,
    ) -> Result<OperationPublicStatus, ProtocolError> {
        let snapshot = self
            .journal
            .operation(operation_id)
            .map_err(journal_error)?;
        let Some(snapshot) = snapshot else {
            if let Some(result) = self
                .journal
                .batch_child(operation_id)
                .map_err(journal_error)?
            {
                return Ok(OperationPublicStatus {
                    operation_id: operation_id.clone(),
                    operation_digest: result.operation_digest.clone(),
                    state: OperationState::Succeeded,
                    result: Some(result),
                    error: None,
                });
            }
            return Err(ProtocolError::new(
                ProtocolErrorCode::ApprovalNotFound,
                "operation not found",
            ));
        };
        Ok(OperationPublicStatus {
            operation_id: snapshot.operation_id,
            operation_digest: snapshot.operation_digest,
            state: snapshot.state,
            result: snapshot.result,
            error: None,
        })
    }

    fn readiness(&self) -> Result<Readiness, ProtocolError> {
        let (mut state, mut conditions) = self.clock.readiness()?;
        if self.require_network_containment().is_err() {
            state = ReadinessState::Unavailable;
            conditions.push(Token::new("network_containment_unavailable")?);
        }
        Ok(Readiness {
            service_id: Token::new("bloom-broker").expect("static service ID"),
            service_version: self.service_version.clone(),
            build_digest: self.build_digest.clone(),
            boot_epoch: self.boot_epoch.clone(),
            state,
            conditions,
        })
    }

    async fn triad_readiness(&self) -> Result<Readiness, ProtocolError> {
        let broker = self.readiness()?;
        if broker.state != ReadinessState::Ready {
            return Ok(broker);
        }
        let signer = match self
            .signer
            .request_for_machine(BrokerSignerRequest::SignerReadiness(
                bloom_signer_api::Empty {},
            ))
            .await?
        {
            BrokerSignerResponse::SignerReadiness(readiness) => readiness,
            _ => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    "Signer returned the wrong readiness response",
                ));
            }
        };
        validate_signer_readiness(&broker, &translate_service::readiness_to_machine(signer))?;
        Ok(broker)
    }

    fn require_network_containment(&self) -> Result<(), ProtocolError> {
        match &self.network_containment {
            Some(guard) => Ok(guard.check()?),
            None => Ok(()),
        }
    }

    fn capabilities(&self) -> Result<ServiceCapabilities, ProtocolError> {
        Ok(ServiceCapabilities {
            service_id: Token::new("bloom-broker")?,
            service_version: self.service_version.clone(),
            build_digest: self.build_digest.clone(),
            protocol_major: bloom_broker_api::BROKER_API_MAJOR,
            protocol_minor_min: bloom_broker_api::BROKER_API_MINOR_MIN,
            protocol_minor_max: bloom_broker_api::BROKER_API_MINOR_MAX,
            methods: MachineBrokerMethod::ALL
                .iter()
                .map(|method| Token::new(method.as_str()))
                .collect::<Result<_, _>>()?,
            schemas: vec![Token::new(RPC_ENVELOPE_SCHEMA_V1)?],
            backends: Vec::new(),
            assurance_verifiers: self
                .authority
                .verifier_capabilities()
                .into_iter()
                .map(|capability| VerifierPublicCapability {
                    verifier_id: capability.verifier_id,
                    verifier_digest: capability.artifact_digest,
                })
                .collect(),
            frame_max_bytes: DecimalU64::new(bloom_broker_api::FRAME_MAX_BYTES as u64),
        })
    }
}

fn unique_wallet_root(
    keys: &[bloom_signer_api::KeyPublic],
) -> Result<Option<bloom_broker_api::KeyRef>, ProtocolError> {
    let mut root_keys = keys
        .iter()
        .filter(|key| key.role == bloom_signer_api::KeyRole::WalletRoot);
    let root_key_ref = root_keys.next().map(|key| key.key_ref.clone());
    if root_keys.next().is_some() {
        return Err(ProtocolError::new(
            ProtocolErrorCode::KeyrefMismatch,
            "Signer returned multiple wallet root keys",
        ));
    }
    Ok(root_key_ref.map(translate_key::key_ref_to_machine))
}

fn machine_request_requires_containment(request: &MachineBrokerRequest) -> bool {
    use MachineBrokerRequest as Request;

    matches!(
        request,
        Request::SealedApprovalPrepare(_)
            | Request::SealedApprovalRenew(_)
            | Request::SigningSign(_)
            | Request::SigningSignBatch(_)
            | Request::PolicyValidateUpdate(_)
            | Request::PolicyCommitUpdate(_)
            | Request::WalletRegistrationPrepare(_)
            | Request::WalletUnlockPrepare(_)
            | Request::WalletImportPrepare(_)
            | Request::WalletExportPrepare(_)
            | Request::WalletDeletePrepare(_)
            | Request::KeyDerivePrepare(_)
            | Request::KeyEnrollPrepare(_)
            | Request::AccountAllocatePrepare(_)
            | Request::AccountRetirePrepare(_)
            | Request::CredentialAddPrepare(_)
            | Request::CredentialReplacePrepare(_)
            | Request::CredentialRemovePrepare(_)
            | Request::RecoveryPrepare(_)
    )
}

fn validate_signer_readiness(broker: &Readiness, signer: &Readiness) -> Result<(), ProtocolError> {
    if signer.service_id.as_str() != "bloom-signer"
        || signer.build_digest != broker.build_digest
        || signer.state != ReadinessState::Ready
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::ServiceUnavailable,
            "Signer service is not ready",
        ));
    }
    Ok(())
}

fn validate_signer_result_shape(
    snapshot: &crate::journal::OperationSnapshot,
    result: &bloom_signer_api::SigningResult,
    is_batch: bool,
    expected_signature_count: u64,
) -> Result<(), ProtocolError> {
    let actual_signature_count = u64::try_from(result.signatures.len()).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::OperationIdConflict,
            "Signer result signature count is not representable",
        )
    })?;
    if snapshot.operation_digest != result.operation_digest
        || snapshot.is_batch != is_batch
        || actual_signature_count != expected_signature_count
        || (!is_batch && expected_signature_count != 1)
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::OperationIdConflict,
            "Signer result changed operation identity, method, or exact signature count",
        ));
    }
    Ok(())
}

fn exact_signing_response(
    is_batch: bool,
    response: BrokerSignerResponse,
) -> Result<bloom_signer_api::SigningResult, ProtocolError> {
    match (is_batch, response) {
        (false, BrokerSignerResponse::SignerSign(result))
        | (true, BrokerSignerResponse::SignerSignBatch(result)) => Ok(result),
        (false, BrokerSignerResponse::SignerSignBatch(_))
        | (true, BrokerSignerResponse::SignerSign(_)) => Err(response_mismatch(if is_batch {
            "signer.sign_batch"
        } else {
            "signer.sign"
        })),
        (_, _) => Err(response_mismatch(if is_batch {
            "signer.sign_batch"
        } else {
            "signer.sign"
        })),
    }
}

fn verify_policy_commit_receipt(
    receipt: &bloom_signer_api::PolicyCommitReceipt,
    update: &bloom_signer_api::PolicyUpdateRequest,
    reread: &bloom_signer_api::SignedPolicySnapshot,
    expected_key_id: &Token,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ProtocolError> {
    let expected_version = update
        .baseline_version
        .get()
        .checked_add(1)
        .ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorCode::PolicyBaselineStale,
                "policy commit baseline version overflowed",
            )
        })?;
    if receipt.operation_id != update.operation_id
        || receipt.wallet_id != update.wallet_id
        || receipt.previous_version != update.baseline_version
        || receipt.authority_diff_digest != update.authority_diff_digest
        || receipt.committed != *reread
        || receipt.committed.wallet_id != update.wallet_id
        || receipt.committed.version.get() != expected_version
        || receipt.committed.canonical_policy != update.proposed_canonical_policy
        || receipt.committed.policy_digest != update.proposed_policy_digest
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::OperationIdConflict,
            "Signer policy commit receipt differs from the staged update or exact reread",
        ));
    }
    if &receipt.signer_key_id != expected_key_id
        || &receipt.committed.policy_signing_key_id != expected_key_id
        || receipt.committed.policy_verifying_key.decode() != verifying_key.to_bytes()
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "policy commit receipt key differs from the pinned wallet policy key",
        ));
    }
    let signature = Signature::from_slice(&receipt.signer_signature.decode()).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "policy commit receipt signature is malformed",
        )
    })?;
    verifying_key
        .verify(
            &receipt
                .signature_message()
                .map_err(translate_error::signer_error_to_machine)?,
            &signature,
        )
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "policy commit receipt signature is invalid",
            )
        })
}

impl MachineBrokerService for BrokerRpcService {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move { self.dispatch_inner(request).await })
    }
}

impl RevocationControlService for BrokerRpcService {
    fn dispatch<'a>(
        &'a self,
        request: ControlRequest,
    ) -> bloom_signer_api::ServiceFuture<'a, ControlResponse> {
        Box::pin(async move {
            match request {
                ControlRequest::Revoke(request) => {
                    self.authority
                        .revoke_local_approval(&request.approval_id)
                        .map_err(authority_error)
                        .map_err(translate_error::machine_error_to_signer)?;
                    self.signer
                        .request_async(BrokerSignerRequest::SealedApprovalRevoke(request.clone()))
                        .await?;
                    let status = self
                        .authority
                        .approval_public_status(&request.approval_id)
                        .map_err(authority_error)
                        .map_err(translate_error::machine_error_to_signer)?;
                    Ok(ControlResponse::Revoke(
                        translate_service::approval_status_to_signer(status),
                    ))
                }
                ControlRequest::RevokeAll(request) => {
                    let current = self
                        .authority
                        .wallet_epoch(&request.wallet_id)
                        .map_err(authority_error)
                        .map_err(translate_error::machine_error_to_signer)?;
                    self.authority
                        .advance_local_epoch(&request.wallet_id, current, current.saturating_add(1))
                        .map_err(authority_error)
                        .map_err(translate_error::machine_error_to_signer)?;
                    match self
                        .signer
                        .request_async(BrokerSignerRequest::SealedApprovalRevokeAll(request))
                        .await?
                    {
                        BrokerSignerResponse::SealedApprovalRevokeAll(state) => {
                            Ok(ControlResponse::RevokeAll(state))
                        }
                        _ => Err(translate_error::machine_error_to_signer(response_mismatch(
                            "sealed_approval.revoke_all",
                        ))),
                    }
                }
                ControlRequest::Status(request) => match self
                    .signer
                    .request_async(BrokerSignerRequest::RevocationState(request))
                    .await?
                {
                    BrokerSignerResponse::RevocationState(snapshot) => {
                        Ok(ControlResponse::Status(snapshot.state))
                    }
                    _ => Err(translate_error::machine_error_to_signer(response_mismatch(
                        "revocation.state",
                    ))),
                },
            }
        })
    }
}

struct AuthorityCompletionObserver {
    authority: Arc<BrokerAuthority>,
}

impl CeremonyCompletionObserver for AuthorityCompletionObserver {
    fn approval_completed(
        &self,
        receipt: &bloom_signer_api::SignerActivationReceipt,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.authority
            .activate_signer_receipt(receipt, now_ms)
            .map_err(authority_error)
    }

    fn custody_completed(
        &self,
        receipt: &bloom_signer_api::CustodyResult,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.authority
            .adopt_custody_receipt(
                &translate_custody::result_to_machine(receipt.clone()),
                now_ms,
            )
            .map_err(authority_error)
    }
}

fn require_custody_kind(
    actual: bloom_broker_api::CeremonyKind,
    expected: bloom_broker_api::CeremonyKind,
) -> Result<(), ProtocolError> {
    if actual != expected {
        return Err(ProtocolError::new(
            ProtocolErrorCode::CeremonyKindMismatch,
            "custody ceremony kind does not match the called method",
        ));
    }
    Ok(())
}

fn jcs_digest(value: &impl serde::Serialize) -> Result<Digest32, ProtocolError> {
    Ok(Digest32::from_bytes(
        Sha256::digest(serde_jcs::to_vec(value).map_err(malformed)?).into(),
    ))
}

fn authority_error(error: AuthorityError) -> ProtocolError {
    let error_kind = match &error {
        AuthorityError::Journal(_) => "journal",
        AuthorityError::Storage(_) => "storage",
        AuthorityError::Denied { .. } => "denied",
    };
    tracing::warn!(
        event = "broker.authority_rejected",
        error_kind,
        "Broker authority rejected an operation"
    );
    match error {
        AuthorityError::Journal(error) => journal_error(error),
        AuthorityError::Storage(message) => {
            ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message)
        }
        AuthorityError::Denied { code, message } => {
            let protocol_code = match code {
                "APPROVAL_NOT_FOUND" => ProtocolErrorCode::ApprovalNotFound,
                "APPROVAL_REVOKED" => ProtocolErrorCode::ApprovalRevoked,
                "REVOCATION_EPOCH_UNRECONCILED" => ProtocolErrorCode::RevocationEpochUnreconciled,
                "KEYREF_MISMATCH" => ProtocolErrorCode::KeyrefMismatch,
                "SUITE_NOT_ALLOWED" => ProtocolErrorCode::SuiteNotAllowed,
                "SELECTOR_MISMATCH" => ProtocolErrorCode::SelectorMismatch,
                "PROVENANCE_MISMATCH" | "PROVENANCE_REQUIRED" => {
                    ProtocolErrorCode::ProvenanceMismatch
                }
                "ASSURANCE_UNAVAILABLE" => ProtocolErrorCode::AssuranceUnavailable,
                "POLICY_BASELINE_STALE" => ProtocolErrorCode::PolicyBaselineStale,
                "OPERATION_ID_CONFLICT" => ProtocolErrorCode::OperationIdConflict,
                _ => ProtocolErrorCode::ClaimInvalid,
            };
            ProtocolError::new(protocol_code, message)
        }
    }
}

fn journal_error(error: JournalError) -> ProtocolError {
    match error {
        JournalError::Protocol(error) => error,
        JournalError::InjectedCrash { message, .. } | JournalError::Storage(message) => {
            ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message)
        }
    }
}

fn response_mismatch(method: &str) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        format!("Signer returned the wrong typed response for {method}"),
    )
}

fn malformed(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::OperationSnapshot;
    use bloom_broker_api::OperationState;
    use bloom_signer_api::{CryptoSuite, NormalizedSignature, SignerClaimAssurance, SigningResult};

    fn readiness(service_id: &str, build: u8, state: ReadinessState) -> Readiness {
        Readiness {
            service_id: Token::new(service_id).unwrap(),
            service_version: "test".into(),
            build_digest: Digest32::from_bytes([build; 32]),
            boot_epoch: BootEpoch::from_bytes([0x91; 16]),
            state,
            conditions: Vec::new(),
        }
    }

    fn signer_key(role: bloom_signer_api::KeyRole, fingerprint: u8) -> bloom_signer_api::KeyPublic {
        bloom_signer_api::KeyPublic {
            key_ref: bloom_signer_api::KeyRef {
                backend: Token::new("local").unwrap(),
                backend_instance: Token::new("wallet-root-test").unwrap(),
                locator: format!("key-{fingerprint}"),
                key_spec: bloom_signer_api::KeySpec::Secp256k1,
                public_key_fingerprint: Digest32::from_bytes([fingerprint; 32]),
                derivation: (role == bloom_signer_api::KeyRole::Derived).then(|| {
                    bloom_signer_api::DerivationRef::Bip32Secp256k1 {
                        root_key_id: Token::new("root").unwrap(),
                        path: "m/44'/60'/0'/0/1".into(),
                    }
                }),
            },
            role,
            canonical_public_key: Base64UrlBytes::from_bytes(&[fingerprint; 33]),
            addresses: Vec::new(),
            supported_crypto_suites: vec![
                bloom_signer_api::CryptoSuite::Secp256k1Keccak256Recoverable,
            ],
            derived_account: None,
        }
    }

    #[test]
    fn wallet_root_projection_is_exact_and_fails_closed_on_ambiguity() {
        let root = signer_key(bloom_signer_api::KeyRole::WalletRoot, 1);
        let derived = signer_key(bloom_signer_api::KeyRole::Derived, 2);
        assert_eq!(
            unique_wallet_root(&[derived.clone(), root.clone()]).unwrap(),
            Some(translate_key::key_ref_to_machine(root.key_ref.clone()))
        );

        // A wallet with only derived accounts (a bip39 wallet) has no root.
        assert_eq!(unique_wallet_root(&[derived]).unwrap(), None);
        assert_eq!(
            unique_wallet_root(&[root, signer_key(bloom_signer_api::KeyRole::WalletRoot, 3),])
                .unwrap_err()
                .code,
            ProtocolErrorCode::KeyrefMismatch
        );
    }

    fn signed_validation_receipt(key: &SigningKey) -> BrokerValidationReceipt {
        let mut receipt = BrokerValidationReceipt {
            approval_id: Digest32::from_bytes([0x11; 32]),
            approval_digest: Digest32::from_bytes([0x12; 32]),
            operation_digest: Digest32::from_bytes([0x13; 32]),
            policy_version: DecimalU64::new(7),
            policy_digest: Digest32::from_bytes([0x14; 32]),
            claim_digest: Some(Digest32::from_bytes([0x15; 32])),
            assurance_digest: Some(Digest32::from_bytes([0x16; 32])),
            reservation_ids: vec![Digest32::from_bytes([0x17; 32])],
            effective_claim_assurance: Some(SignerClaimAssurance::MachineAsserted),
            broker_key_id: Token::new("broker-validation-test").unwrap(),
            broker_signature: Base64UrlBytes::from_bytes(&[0; 64]),
        };
        receipt.broker_signature =
            Base64UrlBytes::from_bytes(&key.sign(&receipt.signature_message().unwrap()).to_bytes());
        receipt
    }

    #[test]
    fn validation_receipt_signature_binds_every_authorization_field_and_key() {
        let key = SigningKey::from_bytes(&[0x61; 32]);
        let receipt = signed_validation_receipt(&key);
        verify_broker_validation_receipt(&receipt, &receipt.broker_key_id, &key.verifying_key())
            .unwrap();

        let mut changes = Vec::new();
        let mut changed = receipt.clone();
        changed.approval_id = Digest32::from_bytes([0x21; 32]);
        changes.push(changed);
        let mut changed = receipt.clone();
        changed.approval_digest = Digest32::from_bytes([0x22; 32]);
        changes.push(changed);
        let mut changed = receipt.clone();
        changed.operation_digest = Digest32::from_bytes([0x23; 32]);
        changes.push(changed);
        let mut changed = receipt.clone();
        changed.policy_version = DecimalU64::new(8);
        changes.push(changed);
        let mut changed = receipt.clone();
        changed.policy_digest = Digest32::from_bytes([0x24; 32]);
        changes.push(changed);
        let mut changed = receipt.clone();
        changed.claim_digest = None;
        changes.push(changed);
        let mut changed = receipt.clone();
        changed.assurance_digest = None;
        changes.push(changed);
        let mut changed = receipt.clone();
        changed
            .reservation_ids
            .push(Digest32::from_bytes([0x25; 32]));
        changes.push(changed);
        let mut changed = receipt.clone();
        changed.effective_claim_assurance = None;
        changes.push(changed);
        let mut changed = receipt.clone();
        changed.broker_key_id = Token::new("broker-validation-other").unwrap();
        changes.push(changed);

        for changed in changes {
            assert_eq!(
                verify_broker_validation_receipt(
                    &changed,
                    &receipt.broker_key_id,
                    &key.verifying_key(),
                )
                .unwrap_err()
                .code,
                ProtocolErrorCode::UnauthenticatedPeer
            );
        }

        let mut changed = receipt.clone();
        changed.broker_signature = Base64UrlBytes::from_bytes(&[0x62; 64]);
        assert_eq!(
            verify_broker_validation_receipt(
                &changed,
                &receipt.broker_key_id,
                &key.verifying_key(),
            )
            .unwrap_err()
            .code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
        let other_key = SigningKey::from_bytes(&[0x63; 32]);
        assert_eq!(
            verify_broker_validation_receipt(
                &receipt,
                &receipt.broker_key_id,
                &other_key.verifying_key(),
            )
            .unwrap_err()
            .code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
    }

    #[test]
    fn matched_previous_and_current_service_packages_are_compatible_on_the_frozen_wire() {
        let mut previous_broker = readiness("bloom-broker", 0x81, ReadinessState::Ready);
        previous_broker.service_version = "0.1.0".into();
        let mut previous_signer = readiness("bloom-signer", 0x81, ReadinessState::Ready);
        previous_signer.service_version = "0.1.0".into();

        let mut current_broker = readiness("bloom-broker", 0x82, ReadinessState::Ready);
        current_broker.service_version = previous_broker.service_version.clone();
        let mut current_signer = readiness("bloom-signer", 0x82, ReadinessState::Ready);
        current_signer.service_version = "0.1.1".into();

        assert_eq!(
            previous_broker.service_version,
            current_broker.service_version
        );
        assert_ne!(
            previous_signer.service_version,
            current_signer.service_version
        );
        assert_eq!(previous_broker.build_digest, previous_signer.build_digest);
        assert_eq!(current_broker.build_digest, current_signer.build_digest);
        assert_ne!(previous_broker.build_digest, current_broker.build_digest);
        assert_eq!(
            bloom_signer_api::SIGNER_API_CURRENT,
            bloom_broker_api::ProtocolVersion::new(1, 5)
        );
        validate_signer_readiness(&previous_broker, &previous_signer).unwrap();
        validate_signer_readiness(&current_broker, &current_signer).unwrap();
        assert_eq!(
            validate_signer_readiness(&previous_broker, &current_signer)
                .unwrap_err()
                .code,
            ProtocolErrorCode::ServiceUnavailable
        );
        assert_eq!(
            validate_signer_readiness(&current_broker, &previous_signer)
                .unwrap_err()
                .code,
            ProtocolErrorCode::ServiceUnavailable
        );

        for signer in [
            readiness("bloom-signer", 0x81, ReadinessState::DegradedReadOnly),
            readiness("wrong-signer", 0x81, ReadinessState::Ready),
        ] {
            assert_eq!(
                validate_signer_readiness(&previous_broker, &signer)
                    .unwrap_err()
                    .code,
                ProtocolErrorCode::ServiceUnavailable
            );
        }
    }

    fn result(signature_count: usize) -> (OperationSnapshot, SigningResult) {
        let operation_id = OperationId::from_bytes([0x51; 32]);
        let operation_digest = Digest32::from_bytes([0x52; 32]);
        (
            OperationSnapshot {
                operation_id: operation_id.clone(),
                operation_digest: operation_digest.clone(),
                state: OperationState::Dispatched,
                is_batch: signature_count > 1,
                retry_binding_digest: Digest32::from_bytes([0x53; 32]),
                result: None,
            },
            SigningResult {
                operation_id,
                operation_digest,
                signatures: (0..signature_count)
                    .map(|_| NormalizedSignature {
                        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
                        bytes: Base64UrlBytes::from_bytes(&[0x54; 65]),
                    })
                    .collect(),
                signer_receipt_digest: Digest32::from_bytes([0x55; 32]),
                broker_receipt_digest: Digest32::from_bytes([0x56; 32]),
            },
        )
    }

    #[test]
    fn signer_result_must_match_the_exact_reserved_signature_count_and_method() {
        let (single_snapshot, single_result) = result(1);
        validate_signer_result_shape(&single_snapshot, &single_result, false, 1).unwrap();
        assert_eq!(
            validate_signer_result_shape(&single_snapshot, &single_result, false, 2)
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );

        let (batch_snapshot, batch_result) = result(2);
        validate_signer_result_shape(&batch_snapshot, &batch_result, true, 2).unwrap();
        assert_eq!(
            validate_signer_result_shape(&batch_snapshot, &batch_result, true, 1)
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );
        assert_eq!(
            validate_signer_result_shape(&batch_snapshot, &batch_result, false, 2)
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );
    }

    #[test]
    fn swapped_signer_response_variants_fail_even_with_compatible_result_counts() {
        let (_, single) = result(1);
        let (_, batch) = result(2);
        assert_eq!(
            exact_signing_response(false, BrokerSignerResponse::SignerSignBatch(single),)
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );
        assert_eq!(
            exact_signing_response(true, BrokerSignerResponse::SignerSign(batch))
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );
    }

    fn signed_policy_commit_fixture() -> (
        SigningKey,
        bloom_signer_api::PolicyUpdateRequest,
        bloom_signer_api::SignedPolicySnapshot,
        bloom_signer_api::PolicyCommitReceipt,
    ) {
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let wallet_id = Token::new("wallet-policy-test").unwrap();
        let policy_key_id = Token::new("policy-key-test").unwrap();
        let canonical_policy = Base64UrlBytes::from_bytes(br#"{"wallet_id":"wallet-policy-test"}"#);
        let proposed_policy_digest = Digest32::from_bytes([0x72; 32]);
        let update = bloom_signer_api::PolicyUpdateRequest {
            operation_id: OperationId::from_bytes([0x73; 32]),
            wallet_id: wallet_id.clone(),
            baseline_version: DecimalU64::new(4),
            baseline_digest: Digest32::from_bytes([0x74; 32]),
            proposed_canonical_policy: canonical_policy.clone(),
            proposed_policy_digest: proposed_policy_digest.clone(),
            authority_diff_digest: Digest32::from_bytes([0x75; 32]),
            assurance_level: Token::new("passkey").unwrap(),
        };
        let committed = bloom_signer_api::SignedPolicySnapshot {
            wallet_id: wallet_id.clone(),
            version: DecimalU64::new(5),
            canonical_policy,
            policy_digest: proposed_policy_digest,
            policy_signing_key_id: policy_key_id.clone(),
            policy_verifying_key: Base64UrlBytes::from_bytes(&key.verifying_key().to_bytes()),
            signer_signature: Base64UrlBytes::from_bytes(&[0x76; 64]),
        };
        let mut receipt = bloom_signer_api::PolicyCommitReceipt {
            operation_id: update.operation_id.clone(),
            wallet_id,
            previous_version: update.baseline_version.clone(),
            committed: committed.clone(),
            authority_diff_digest: update.authority_diff_digest.clone(),
            signer_key_id: policy_key_id,
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        receipt.signer_signature =
            Base64UrlBytes::from_bytes(&key.sign(&receipt.signature_message().unwrap()).to_bytes());
        (key, update, committed, receipt)
    }

    #[test]
    fn policy_commit_receipt_rejects_every_reviewed_identity_or_signature_mutation() {
        let (key, update, committed, receipt) = signed_policy_commit_fixture();
        let expected_key_id = receipt.signer_key_id.clone();
        let verifying_key = key.verifying_key();
        let verify = |candidate: &bloom_signer_api::PolicyCommitReceipt| {
            verify_policy_commit_receipt(
                candidate,
                &update,
                &committed,
                &expected_key_id,
                &verifying_key,
            )
        };
        verify(&receipt).unwrap();

        let mut changed = receipt.clone();
        changed.operation_id = OperationId::from_bytes([0x81; 32]);
        assert_eq!(
            verify(&changed).unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );
        let mut changed = receipt.clone();
        changed.wallet_id = Token::new("other-wallet").unwrap();
        assert_eq!(
            verify(&changed).unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );
        let mut changed = receipt.clone();
        changed.previous_version = DecimalU64::new(3);
        assert_eq!(
            verify(&changed).unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );
        let mut changed = receipt.clone();
        changed.authority_diff_digest = Digest32::from_bytes([0x82; 32]);
        assert_eq!(
            verify(&changed).unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );
        let mut changed = receipt.clone();
        changed.signer_key_id = Token::new("other-policy-key").unwrap();
        assert_eq!(
            verify(&changed).unwrap_err().code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
        let mut changed = receipt.clone();
        changed.signer_signature = Base64UrlBytes::from_bytes(&[0x83; 64]);
        assert_eq!(
            verify(&changed).unwrap_err().code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
        assert_eq!(
            verify_policy_commit_receipt(
                &receipt,
                &update,
                &committed,
                &Token::new("other-pinned-key").unwrap(),
                &verifying_key,
            )
            .unwrap_err()
            .code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
        assert_eq!(
            verify_policy_commit_receipt(
                &receipt,
                &update,
                &committed,
                &expected_key_id,
                &SigningKey::from_bytes(&[0x84; 32]).verifying_key(),
            )
            .unwrap_err()
            .code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
    }

    /// The seed profile is read from what the Signer projected, never guessed
    /// from which fields happen to be populated. The guess this replaced
    /// reported a legacy BIP-32 wallet as `imported-secp256k1-scalar`, which
    /// is defined as having no derivable seed — a false custody claim, and
    /// exactly the kind of statement a migration decision would rest on.
    mod seed_profile_projection {
        use super::*;

        fn key_ref(
            derivation: Option<bloom_broker_api::DerivationRef>,
        ) -> bloom_broker_api::KeyRef {
            bloom_broker_api::KeyRef {
                backend: bloom_broker_api::Token::new("local").unwrap(),
                backend_instance: bloom_broker_api::Token::new("primary").unwrap(),
                locator: "wallet/primary/k".into(),
                key_spec: bloom_broker_api::KeySpec::Secp256k1,
                public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([7; 32]),
                derivation,
            }
        }

        fn public(
            root: Option<bloom_broker_api::KeyRef>,
            key_refs: Vec<bloom_broker_api::KeyRef>,
        ) -> bloom_broker_api::WalletPublic {
            bloom_broker_api::WalletPublic {
                wallet_id: bloom_broker_api::Token::new("primary").unwrap(),
                wallet_kind: bloom_broker_api::Token::new("managed").unwrap(),
                root_key_ref: root,
                key_refs,
                policy_version: bloom_broker_api::DecimalU64::new(1),
                policy_digest: bloom_broker_api::Digest32::from_bytes([1; 32]),
                wallet_revocation_epoch: bloom_broker_api::DecimalU64::new(0),
            }
        }

        #[test]
        fn a_bip39_child_proves_the_profile() {
            let child = key_ref(Some(bloom_broker_api::DerivationRef::Bip39Multicurve {
                wallet_seed_ref: bloom_broker_api::Token::new("seed").unwrap(),
                profile: bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1,
                path: "m/44'/60'/0'/0/0".into(),
            }));
            assert_eq!(
                seed_profile_from_key_projection(&public(None, vec![child])).unwrap(),
                WalletSeedProfile::Bip39MulticurveV1
            );
        }

        #[test]
        fn a_root_with_no_derived_keys_is_an_imported_scalar() {
            let root = key_ref(None);
            assert_eq!(
                seed_profile_from_key_projection(&public(Some(root.clone()), vec![root])).unwrap(),
                WalletSeedProfile::ImportedSecp256k1Scalar
            );
        }

        /// The case the old inference got wrong. A legacy BIP-32 wallet has a
        /// derivable root, so calling it an imported scalar asserts the
        /// opposite of the truth. It is named instead.
        #[test]
        fn a_legacy_bip32_wallet_is_named_not_relabelled() {
            let root = key_ref(None);
            let child = key_ref(Some(bloom_broker_api::DerivationRef::Bip32Secp256k1 {
                root_key_id: bloom_broker_api::Token::new("primary-root").unwrap(),
                path: "m/44'/60'/0'/0/0".into(),
            }));
            let error =
                seed_profile_from_key_projection(&public(Some(root), vec![child])).unwrap_err();
            assert_eq!(error.code, ProtocolErrorCode::BackendUnsupported);
            assert!(
                error.message.contains("legacy BIP-32"),
                "the error must name the actual custody shape: {}",
                error.message
            );
        }

        #[test]
        fn an_empty_projection_is_incomplete_not_bip39() {
            let error = seed_profile_from_key_projection(&public(None, vec![])).unwrap_err();
            assert_eq!(error.code, ProtocolErrorCode::BackendUnsupported);
            assert!(
                error
                    .message
                    .contains("neither a root key nor any derived key")
            );
        }
    }
}
