//! Production Machine→Broker and revoke-control RPC implementation.

use std::sync::Arc;

use bloom_triad_protocol::{
    ApprovalPrepareRequest, ApprovalRenewRequest, ApprovalSelector, Base64UrlBytes, BootEpoch,
    BrokerSignerRequest, BrokerSignerResponse, ControlRequest, ControlResponse, DecimalU64,
    Digest32, MachineBrokerMethod, MachineBrokerRequest, MachineBrokerResponse,
    MachineBrokerService, MachineSignRequest, OperationId, OperationPublicStatus, OperationState,
    PolicyCompareAndSwapRequest, PolicyUpdateCeremonyPrepareRequest, PolicyUpdateRequest,
    PolicyUpdateReviewManifest, PolicyValidationReceipt, ProtocolError, ProtocolErrorCode,
    RPC_ENVELOPE_SCHEMA_V1, Readiness, RevocationControlService, SealedApprovalPrepareResponse,
    SelectorKind, ServiceCapabilities, ServiceFuture, SignRequest, SigningPayloads, Token,
    UnsignedSignRequest, VerifierPublicCapability, WalletPublic, WalletRequest,
};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest as _, Sha256};

use crate::{
    authority::{AuthorityError, AuthorizationInput, BrokerAuthority, EpochReconciliation},
    ceremony::{CeremonyBroker, CeremonyCompletionObserver, ReviewManifestContext},
    clock::BrokerClock,
    journal::{BrokerJournal, JournalError, ReservationState},
    signer_client::BrokerSignerClient,
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
        };
        service.ceremony.set_completion_observer(
            Arc::new(AuthorityCompletionObserver {
                authority: service.authority.clone(),
            }),
            service.clock.now_ms(false)?,
        )?;
        Ok(service)
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

        match request {
            Request::SystemHello(_) => Err(ProtocolError::new(
                ProtocolErrorCode::UnknownMethod,
                "system.hello is consumed by the authenticated transport",
            )),
            Request::BrokerReadiness(_) => Ok(Response::BrokerReadiness(self.readiness()?)),
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
                self.authority
                    .approval_public_status(&request.id)
                    .map_err(authority_error)?,
            )),
            Request::SealedApprovalList(request) => Ok(Response::SealedApprovalList(
                self.authority
                    .approval_public_list(&request.wallet_id)
                    .map_err(authority_error)?,
            )),
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
                    .request_async(BrokerSignerRequest::SealedApprovalRevoke(request.clone()))
                    .await?;
                Ok(Response::SealedApprovalRevoke(
                    self.authority
                        .approval_public_status(&request.approval_id)
                        .map_err(authority_error)?,
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
                    .request_async(BrokerSignerRequest::SealedApprovalRevokeAll(request))
                    .await?
                {
                    BrokerSignerResponse::SealedApprovalRevokeAll(state) => {
                        Ok(Response::SealedApprovalRevokeAll(state))
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
                let staged = self
                    .ceremony
                    .completed_policy_update(&request.operation_id, &request.ceremony_receipt)?;
                let compare = PolicyCompareAndSwapRequest {
                    update: staged.update,
                    ceremony_receipt: request.ceremony_receipt,
                    broker_validation_receipt: staged.broker_validation_receipt,
                };
                match self
                    .signer
                    .request_async(BrokerSignerRequest::PolicyCompareAndSwap(compare))
                    .await?
                {
                    BrokerSignerResponse::PolicyCompareAndSwap(receipt) => {
                        let committed = match self
                            .signer
                            .request_async(BrokerSignerRequest::PolicyRead(WalletRequest {
                                wallet_id: receipt.wallet_id.clone(),
                            }))
                            .await?
                        {
                            BrokerSignerResponse::PolicyRead(snapshot) => snapshot,
                            _ => return Err(response_mismatch("policy.read")),
                        };
                        if committed != receipt.committed {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::OperationIdConflict,
                                "Signer reread differs from policy commit receipt",
                            ));
                        }
                        self.authority
                            .install_policy(&committed)
                            .map_err(authority_error)?;
                        Ok(Response::PolicyCommitUpdate(receipt))
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
            Request::WalletRegistrationPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::WalletRegistration,
                )?;
                Ok(Response::WalletRegistrationPrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::WalletUnlockPrepare(_) => Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "wallet.unlock_prepare has no ratified custody ceremony kind",
            )),
            Request::WalletImportPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::WalletImport,
                )?;
                Ok(Response::WalletImportPrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::WalletExportPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::WalletExport,
                )?;
                Ok(Response::WalletExportPrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::WalletDeletePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::WalletDelete,
                )?;
                Ok(Response::WalletDeletePrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::KeyDerivePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::KeyDerive,
                )?;
                Ok(Response::KeyDerivePrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::KeyEnrollPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::BackendEnrollment,
                )?;
                Ok(Response::KeyEnrollPrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::CredentialAddPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::CredentialAdd,
                )?;
                Ok(Response::CredentialAddPrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::CredentialReplacePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::CredentialReplace,
                )?;
                Ok(Response::CredentialReplacePrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::CredentialRemovePrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::CredentialRemove,
                )?;
                Ok(Response::CredentialRemovePrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::RecoveryPrepare(request) => {
                require_custody_kind(
                    request.ceremony_kind,
                    bloom_triad_protocol::CeremonyKind::WalletRecovery,
                )?;
                Ok(Response::RecoveryPrepare(
                    self.ceremony
                        .prepare_custody(request, self.clock.now_ms(false)?)?,
                ))
            }
            Request::KeyListPublic(request) => {
                match self
                    .signer
                    .request_async(BrokerSignerRequest::KeyListPublic(request))
                    .await?
                {
                    BrokerSignerResponse::KeyListPublic(keys) => Ok(Response::KeyListPublic(keys)),
                    _ => Err(response_mismatch("key.list_public")),
                }
            }
            Request::KeyGetPublic(request) => {
                match self
                    .signer
                    .request_async(BrokerSignerRequest::KeyGetPublic(request))
                    .await?
                {
                    BrokerSignerResponse::KeyGetPublic(key) => Ok(Response::KeyGetPublic(key)),
                    _ => Err(response_mismatch("key.get_public")),
                }
            }
            Request::KeyDerivationCapabilities(request) => {
                match self
                    .signer
                    .request_async(BrokerSignerRequest::KeyDerivationCapabilities(request))
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
                    .request_async(BrokerSignerRequest::KeyListDerived(request))
                    .await?
                {
                    BrokerSignerResponse::KeyListDerived(keys) => {
                        Ok(Response::KeyListDerived(keys))
                    }
                    _ => Err(response_mismatch("key.list_derived")),
                }
            }
            Request::CredentialListPublic(request) => {
                match self
                    .signer
                    .request_async(BrokerSignerRequest::CredentialListPublic(request))
                    .await?
                {
                    BrokerSignerResponse::CredentialListPublic(credentials) => {
                        Ok(Response::CredentialListPublic(credentials))
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
                    .request_async(BrokerSignerRequest::CustodyResult(request))
                    .await?
                {
                    BrokerSignerResponse::CustodyResult(result) => {
                        Ok(Response::CustodyResult(result))
                    }
                    _ => Err(response_mismatch("custody.result")),
                }
            }
        }
    }

    async fn prepare_approval(
        &self,
        request: ApprovalPrepareRequest,
    ) -> Result<SealedApprovalPrepareResponse, ProtocolError> {
        self.reconcile_wallet(&request.terms.wallet_id).await?;
        let (exact_ordered_payload_digests, exact_ordered_hashes) = match &request.terms.selector {
            ApprovalSelector::Exact {
                ordered_payload_digests,
                ordered_hashes,
            } => (ordered_payload_digests.clone(), ordered_hashes.clone()),
            ApprovalSelector::Petal { .. } => (Vec::new(), Vec::new()),
        };
        let ceremony_request = bloom_triad_protocol::CeremonyPrepareRequest {
            activation_operation_id: request.operation_id.clone(),
            terms: request.terms.clone(),
            review_manifest_digest: request.canonical_plan_facts_digest,
            exact_ordered_payload_digests,
            exact_ordered_hashes,
            replacement_approval_id: request.terms.renewal_of.clone(),
        };
        let response = self.ceremony.prepare_approval(
            ceremony_request,
            ReviewManifestContext::default(),
            self.clock.now_ms(false)?,
        )?;
        if let Err(error) = self
            .authority
            .prepare_approval(&request.terms, &response.review_manifest_digest)
            .map_err(authority_error)
        {
            let _ = self
                .ceremony
                .cancel(&request.operation_id, self.clock.now_ms(false)?);
            return Err(error);
        }
        Ok(response)
    }

    async fn prepare_policy_update(
        &self,
        request: PolicyUpdateRequest,
    ) -> Result<bloom_triad_protocol::PolicyUpdatePrepareResponse, ProtocolError> {
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
        let now = self.clock.now_ms(false)?;
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
            &validation.unsigned_canonical_bytes()?,
        );
        self.ceremony.prepare_policy_update(
            PolicyUpdateCeremonyPrepareRequest {
                custody: bloom_triad_protocol::CustodyPrepareRequest {
                    ceremony_kind: bloom_triad_protocol::CeremonyKind::PolicyUpdate,
                    custody_operation_id: request.operation_id.clone(),
                    wallet_id: Some(request.wallet_id.clone()),
                    key_ref: None,
                    exact_terms_digest: update_terms_digest,
                    expected_input_class: Token::new("policy_update_credential_prf")?,
                    browser_output_recipient_key: None,
                },
                update: request,
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
        })
        .await
    }

    async fn sign(
        &self,
        request: MachineSignRequest,
        is_batch: bool,
    ) -> Result<bloom_triad_protocol::SigningResult, ProtocolError> {
        let signature_count = match &request.payloads {
            SigningPayloads::Single { .. } => 1,
            SigningPayloads::Batch { children } => children.len(),
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
        let decision = self
            .authority
            .authorize(&AuthorizationInput {
                request: request.clone(),
                reserved_at_ms,
                observed_utc_ms: clock.observed_utc_ms,
                monotonic_anchor_ns: clock.monotonic_anchor_ns,
                clock_boot_epoch: clock.boot_epoch,
            })
            .map_err(authority_error)?;
        let mut attempt_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut attempt_bytes);
        let claim_digest = request
            .petal_use_claim
            .as_ref()
            .map(jcs_digest)
            .transpose()?;
        let assurance_digest = request
            .petal_use_claim
            .as_ref()
            .map(|claim| jcs_digest(&claim.claim_assurance))
            .transpose()?;
        let validation_receipt_digest = jcs_digest(&request)?;
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
            key_ref: request.key_ref,
            crypto_suite: request.crypto_suite,
            selector_kind: match terms.selector {
                ApprovalSelector::Exact { .. } => SelectorKind::Exact,
                ApprovalSelector::Petal { .. } => SelectorKind::Petal,
            },
            ordered_payload_digests: decision.ordered_payload_digests,
            ordered_hashes: decision.ordered_hashes,
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
        unsigned.attempt_digest = unsigned.computed_attempt_digest()?;
        let snapshot = self
            .journal
            .begin_sign_attempt(&unsigned, is_batch)
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
            .request_async(if is_batch {
                BrokerSignerRequest::SignerSignBatch(request)
            } else {
                BrokerSignerRequest::SignerSign(request)
            })
            .await;
        match response {
            Ok(BrokerSignerResponse::SignerSign(result))
            | Ok(BrokerSignerResponse::SignerSignBatch(result)) => {
                self.commit_signer_result(&approval_id, result.clone(), is_batch)?;
                Ok(result)
            }
            Ok(_) => Err(response_mismatch("signer.sign")),
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
    ) -> Result<bloom_triad_protocol::SigningResult, ProtocolError> {
        let status = match self
            .signer
            .request_async(BrokerSignerRequest::OperationStatus(
                bloom_triad_protocol::OperationRequest {
                    operation_id: operation_id.clone(),
                },
            ))
            .await?
        {
            BrokerSignerResponse::OperationStatus(status) => status,
            _ => return Err(response_mismatch("operation.status")),
        };
        match (status.state, status.result) {
            (OperationState::Succeeded, Some(result)) => {
                self.commit_signer_result(approval_id, result.clone(), is_batch)?;
                Ok(result)
            }
            (OperationState::Quarantined, _) => {
                self.transition_to_quarantined(operation_id)?;
                self.journal
                    .finalize_reservation(approval_id, operation_id, ReservationState::Quarantined)
                    .map_err(journal_error)?;
                Err(ProtocolError::new(
                    ProtocolErrorCode::AmbiguousProviderEffect,
                    "Signer reports an ambiguous provider effect",
                ))
            }
            (OperationState::Denied | OperationState::Cancelled | OperationState::Failed, _) => {
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
        result: bloom_triad_protocol::SigningResult,
        is_batch: bool,
    ) -> Result<(), ProtocolError> {
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
                    Ok(bloom_triad_protocol::SigningResult {
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
        for wallet_id in self.authority.wallet_ids().map_err(authority_error)? {
            self.reconcile_wallet(&wallet_id).await?;
        }
        Ok(())
    }

    async fn reconcile_wallet(&self, wallet_id: &Token) -> Result<(), ProtocolError> {
        let mut snapshot = self.revocation_snapshot(wallet_id).await?;
        loop {
            match self
                .authority
                .reconcile_revocation(&snapshot.state, &snapshot.approval_tombstones)
                .map_err(authority_error)?
            {
                EpochReconciliation::Converged | EpochReconciliation::AdoptedSignerEpoch => {
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
                    match self
                        .signer
                        .request_async(BrokerSignerRequest::SealedApprovalRevokeAll(
                            bloom_triad_protocol::WalletOperationRequest {
                                operation_id: OperationId::from_bytes(operation_bytes),
                                wallet_id: wallet_id.clone(),
                            },
                        ))
                        .await?
                    {
                        BrokerSignerResponse::SealedApprovalRevokeAll(_) => {}
                        _ => return Err(response_mismatch("sealed_approval.revoke_all")),
                    }
                    snapshot = self.revocation_snapshot(wallet_id).await?;
                }
            }
        }
    }

    async fn revocation_snapshot(
        &self,
        wallet_id: &Token,
    ) -> Result<bloom_triad_protocol::RevocationSnapshot, ProtocolError> {
        match self
            .signer
            .request_async(BrokerSignerRequest::RevocationState(WalletRequest {
                wallet_id: wallet_id.clone(),
            }))
            .await?
        {
            BrokerSignerResponse::RevocationState(snapshot) => Ok(snapshot),
            _ => Err(response_mismatch("revocation.state")),
        }
    }

    async fn policy_read(
        &self,
        request: &WalletRequest,
    ) -> Result<bloom_triad_protocol::SignedPolicySnapshot, ProtocolError> {
        match self
            .signer
            .request_async(BrokerSignerRequest::PolicyRead(request.clone()))
            .await?
        {
            BrokerSignerResponse::PolicyRead(snapshot) => {
                self.authority
                    .install_policy(&snapshot)
                    .map_err(authority_error)?;
                Ok(snapshot)
            }
            _ => Err(response_mismatch("policy.read")),
        }
    }

    async fn wallet_public(&self, wallet_id: Token) -> Result<WalletPublic, ProtocolError> {
        let policy = self
            .policy_read(&WalletRequest {
                wallet_id: wallet_id.clone(),
            })
            .await?;
        let keys = match self
            .signer
            .request_async(BrokerSignerRequest::KeyListPublic(WalletRequest {
                wallet_id: wallet_id.clone(),
            }))
            .await?
        {
            BrokerSignerResponse::KeyListPublic(keys) => keys,
            _ => return Err(response_mismatch("key.list_public")),
        };
        Ok(WalletPublic {
            wallet_revocation_epoch: DecimalU64::new(
                self.authority
                    .wallet_epoch(&wallet_id)
                    .map_err(authority_error)?,
            ),
            wallet_id,
            wallet_kind: Token::new("managed")?,
            key_refs: keys.into_iter().map(|key| key.key_ref).collect(),
            policy_version: policy.version,
            policy_digest: policy.policy_digest,
        })
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
        let (state, conditions) = self.clock.readiness()?;
        Ok(Readiness {
            service_id: Token::new("bloom-broker").expect("static service ID"),
            service_version: self.service_version.clone(),
            build_digest: self.build_digest.clone(),
            boot_epoch: self.boot_epoch.clone(),
            state,
            conditions,
        })
    }

    fn capabilities(&self) -> Result<ServiceCapabilities, ProtocolError> {
        Ok(ServiceCapabilities {
            service_id: Token::new("bloom-broker")?,
            service_version: self.service_version.clone(),
            build_digest: self.build_digest.clone(),
            protocol_major: bloom_triad_protocol::PROTOCOL_MAJOR,
            protocol_minor_min: bloom_triad_protocol::PROTOCOL_MINOR_MIN,
            protocol_minor_max: bloom_triad_protocol::PROTOCOL_MINOR_MAX,
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
            frame_max_bytes: DecimalU64::new(bloom_triad_protocol::FRAME_MAX_BYTES as u64),
        })
    }
}

fn validate_signer_result_shape(
    snapshot: &crate::journal::OperationSnapshot,
    result: &bloom_triad_protocol::SigningResult,
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

impl MachineBrokerService for BrokerRpcService {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move { self.dispatch_inner(request).await })
    }
}

impl RevocationControlService for BrokerRpcService {
    fn dispatch<'a>(&'a self, request: ControlRequest) -> ServiceFuture<'a, ControlResponse> {
        Box::pin(async move {
            match request {
                ControlRequest::Revoke(request) => {
                    self.authority
                        .revoke_local_approval(&request.approval_id)
                        .map_err(authority_error)?;
                    self.signer
                        .request_async(BrokerSignerRequest::SealedApprovalRevoke(request.clone()))
                        .await?;
                    Ok(ControlResponse::Revoke(
                        self.authority
                            .approval_public_status(&request.approval_id)
                            .map_err(authority_error)?,
                    ))
                }
                ControlRequest::RevokeAll(request) => {
                    let current = self
                        .authority
                        .wallet_epoch(&request.wallet_id)
                        .map_err(authority_error)?;
                    self.authority
                        .advance_local_epoch(&request.wallet_id, current, current.saturating_add(1))
                        .map_err(authority_error)?;
                    match self
                        .signer
                        .request_async(BrokerSignerRequest::SealedApprovalRevokeAll(request))
                        .await?
                    {
                        BrokerSignerResponse::SealedApprovalRevokeAll(state) => {
                            Ok(ControlResponse::RevokeAll(state))
                        }
                        _ => Err(response_mismatch("sealed_approval.revoke_all")),
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
                    _ => Err(response_mismatch("revocation.state")),
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
        receipt: &bloom_triad_protocol::SignerActivationReceipt,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.authority
            .activate_signer_receipt(receipt, now_ms)
            .map_err(authority_error)
    }

    fn custody_completed(
        &self,
        receipt: &bloom_triad_protocol::CustodyResult,
    ) -> Result<(), ProtocolError> {
        self.authority
            .adopt_custody_receipt(receipt)
            .map_err(authority_error)
    }
}

fn require_custody_kind(
    actual: bloom_triad_protocol::CeremonyKind,
    expected: bloom_triad_protocol::CeremonyKind,
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
    use bloom_triad_protocol::{CryptoSuite, NormalizedSignature, OperationState, SigningResult};

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
}
