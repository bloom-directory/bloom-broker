//! Authenticated Broker→Signer client.

#![forbid(unsafe_code)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    thread,
};

use bloom_audit_checkpoint::{CheckpointDecision, CheckpointDecisionOutcome, CheckpointSink};
use bloom_signer_api::{
    Base64UrlBytes, BrokerSignerRequest, BrokerSignerResponse, CeremonyCompleteRequest,
    CeremonyKind, CustodyBindOutputRecipientRequest, CustodyCompleteRequest, CustodyPrepareRequest,
    CustodyResult, Digest32, IdRequest, OperationId, PolicyUpdateCeremonyCompleteRequest,
    PolicyUpdateCeremonyPrepareRequest, ProtocolError, ProtocolErrorCode, SignerActivationReceipt,
    SignerCeremonyCompleteRequest, SignerCeremonyCompleteResponse, SignerCeremonyPrepareRequest,
    SignerCeremonyPrepareResponse, SignerCeremonyStatus, SignerPreparedApproval,
    SignerPreparedCustody, Token, TypedRequestMethod, is_read_only_method,
};
use bloom_triad_local_transport::{LocalIdentity, PeerAcl};

use crate::{
    ceremony::CeremonySigner, journal::BrokerJournal, translation::error::signer_error_to_machine,
};

type Job = (
    BrokerSignerRequest,
    mpsc::Sender<Result<BrokerSignerResponse, ProtocolError>>,
);

/// Synchronous facade over a dedicated async transport thread. Ceremony HTTP
/// handlers must not construct or nest a Tokio runtime on an Axum worker.
#[derive(Clone)]
pub struct BrokerSignerClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    jobs: Mutex<Option<mpsc::Sender<Job>>>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        self.jobs.get_mut().ok().and_then(Option::take);
        if let Some(worker) = self.worker.get_mut().ok().and_then(Option::take) {
            let _ = worker.join();
        }
    }
}

impl BrokerSignerClient {
    pub fn connect_unix(
        socket_path: impl Into<PathBuf>,
        identity: LocalIdentity,
        signer: PeerAcl,
        journal: Arc<BrokerJournal>,
        checkpoints: Arc<dyn CheckpointSink>,
    ) -> Result<Self, ProtocolError> {
        let socket_path = socket_path.into();
        let (jobs, receiver) = mpsc::channel::<Job>();
        let service_span = tracing::Span::current();
        let tracing_dispatch = tracing::dispatcher::get_default(Clone::clone);
        let worker = thread::Builder::new()
            .name("bloom-broker-signer-rpc".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&tracing_dispatch, || {
                    let _service_span = service_span.enter();
                    worker(
                        receiver,
                        socket_path,
                        identity,
                        signer,
                        journal,
                        checkpoints,
                    )
                })
            })
            .map_err(|error| unavailable(format!("start Signer RPC worker: {error}")))?;
        Ok(Self {
            inner: Arc::new(ClientInner {
                jobs: Mutex::new(Some(jobs)),
                worker: Mutex::new(Some(worker)),
            }),
        })
    }

    pub fn connect_unix_from_files(
        socket_path: impl Into<PathBuf>,
        identity_path: impl AsRef<Path>,
        edge_manifest_path: impl AsRef<Path>,
        journal: Arc<BrokerJournal>,
        checkpoints: Arc<dyn CheckpointSink>,
    ) -> Result<Self, ProtocolError> {
        let (identity, manifest) = bloom_triad_local_transport::load_identity_and_manifest(
            identity_path.as_ref(),
            edge_manifest_path.as_ref(),
            "bloom-broker",
        )?;
        let signer = manifest.signer.into_acl()?;
        if signer.service_id.as_str() != "bloom-signer" {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "edge manifest Signer service ID is invalid",
            ));
        }
        Self::connect_unix(socket_path, identity, signer, journal, checkpoints)
    }

    pub fn request(
        &self,
        request: BrokerSignerRequest,
    ) -> Result<BrokerSignerResponse, ProtocolError> {
        let (reply, response) = mpsc::channel();
        self.inner
            .jobs
            .lock()
            .map_err(|_| unavailable("Signer RPC worker queue lock is poisoned"))?
            .as_ref()
            .ok_or_else(|| unavailable("Signer RPC worker stopped"))?
            .send((request, reply))
            .map_err(|_| unavailable("Signer RPC worker stopped"))?;
        response
            .recv()
            .map_err(|_| unavailable("Signer RPC worker dropped its response"))?
    }

    pub async fn request_async(
        &self,
        request: BrokerSignerRequest,
    ) -> Result<BrokerSignerResponse, ProtocolError> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || client.request(request))
            .await
            .map_err(|error| unavailable(format!("join Signer RPC request: {error}")))?
    }

    pub(crate) async fn request_for_machine(
        &self,
        request: BrokerSignerRequest,
    ) -> Result<BrokerSignerResponse, bloom_broker_api::ProtocolError> {
        self.request_async(request)
            .await
            .map_err(signer_error_to_machine)
    }
}

fn worker(
    receiver: mpsc::Receiver<Job>,
    socket_path: PathBuf,
    identity: LocalIdentity,
    signer: PeerAcl,
    journal: Arc<BrokerJournal>,
    checkpoints: Arc<dyn CheckpointSink>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return,
    };
    let mut last_verified_head = match journal.verified_audit_head() {
        Ok((sequence, head_hash)) => {
            let head =
                bloom_triad_local_transport::sign_journal_head(&identity, sequence, head_hash);
            match persist_checkpoint_diagnosed(
                journal.as_ref(),
                checkpoints.as_ref(),
                None,
                None,
                &head,
                "broker_signer_initial",
            ) {
                Ok(()) => Some(head),
                Err(_) => checkpoints
                    .latest_peer_head(&identity.service_id)
                    .ok()
                    .flatten(),
            }
        }
        Err(_) => checkpoints
            .latest_peer_head(&identity.service_id)
            .ok()
            .flatten(),
    };
    for (request, reply) in receiver {
        let method = match request.method() {
            Ok(method) => method,
            Err(error) => {
                let _ = reply.send(Err(error.into()));
                continue;
            }
        };
        let operation_id = request
            .operation_id()
            .ok()
            .flatten()
            .map(|operation_id| operation_id.as_str().to_owned());
        let sender_head = match journal.verified_audit_head() {
            Ok((sequence, head_hash)) => {
                let head =
                    bloom_triad_local_transport::sign_journal_head(&identity, sequence, head_hash);
                if let Err(error) = persist_checkpoint_diagnosed(
                    journal.as_ref(),
                    checkpoints.as_ref(),
                    Some(&method),
                    operation_id.as_deref(),
                    &head,
                    "broker_signer_pre_dispatch",
                ) {
                    if !is_read_only_method(&method) {
                        let _ = reply.send(Err(error));
                        continue;
                    }
                } else {
                    last_verified_head = Some(head.clone());
                }
                head
            }
            Err(_) if is_read_only_method(&method) => {
                let Some(head) = last_verified_head.clone() else {
                    let _ = reply.send(Err(unavailable(
                        "no independently retained Broker audit head is available",
                    )));
                    continue;
                };
                head
            }
            Err(error) => {
                let _ = reply.send(Err(journal_error(error)));
                continue;
            }
        };
        let journal_for_checkpoint = journal.clone();
        let checkpoints_for_response = checkpoints.clone();
        let response_operation_id = operation_id.clone();
        let result = runtime.block_on(async {
            let mut stream = tokio::net::UnixStream::connect(&socket_path)
                .await
                .map_err(|error| unavailable(format!("connect Signer: {error}")))?;
            bloom_triad_local_transport::call_with_journal_head(
                &mut stream,
                &identity,
                &signer,
                bloom_signer_api::SIGNER_API_CURRENT,
                bloom_signer_api::SIGNER_API_RANGE,
                request,
                30_000,
                sender_head,
                move |peer_head| {
                    persist_response_checkpoint(
                        journal_for_checkpoint.as_ref(),
                        checkpoints_for_response.as_ref(),
                        &method,
                        response_operation_id.as_deref(),
                        peer_head,
                    )
                },
            )
            .await
        });
        let _ = reply.send(result);
    }
}

fn persist_response_checkpoint(
    journal: &BrokerJournal,
    checkpoints: &dyn CheckpointSink,
    method: &Token,
    operation_id: Option<&str>,
    peer_head: &bloom_signer_api::SignedJournalHead,
) -> Result<(), ProtocolError> {
    if let Err(error) = persist_checkpoint_diagnosed(
        journal,
        checkpoints,
        Some(method),
        operation_id,
        peer_head,
        "broker_signer_response",
    ) {
        if !is_read_only_method(method) {
            return Err(error);
        }
    }
    Ok(())
}

fn persist_checkpoint_diagnosed(
    journal: &BrokerJournal,
    checkpoints: &dyn CheckpointSink,
    method: Option<&Token>,
    operation_id: Option<&str>,
    peer_head: &bloom_signer_api::SignedJournalHead,
    edge: &'static str,
) -> Result<(), ProtocolError> {
    match checkpoints.append_peer_head_diagnosed(peer_head) {
        Ok(decision) => {
            log_checkpoint_decision(&decision, method, operation_id, edge, false);
            Ok(())
        }
        Err(failure) => {
            let decision = &failure.decision;
            journal.latch_checkpoint_degradation(
                checkpoint_outcome(decision.outcome),
                decision.attempted.sequence,
                Digest32::new(decision.attempted.head_digest.clone())
                    .expect("checkpoint metadata preserves a validated digest"),
                decision.retained.as_ref().map(|retained| {
                    (
                        retained.sequence,
                        Digest32::new(retained.head_digest.clone())
                            .expect("checkpoint metadata preserves a validated digest"),
                    )
                }),
            );
            log_checkpoint_decision(decision, method, operation_id, edge, true);
            Err(unavailable(match edge {
                "broker_signer_response" => {
                    "persist Signer audit checkpoint before publishing mutation result"
                }
                "broker_signer_pre_dispatch" => "persist Broker audit head before dispatch",
                _ => "persist initial Broker audit head",
            }))
        }
    }
}

fn log_checkpoint_decision(
    decision: &CheckpointDecision,
    method: Option<&Token>,
    operation_id: Option<&str>,
    edge: &'static str,
    mutations_disabled: bool,
) {
    tracing::info!(
        event = "checkpoint.decision",
        edge,
        recipient_service = decision.recipient_service_id.as_ref().map(Token::as_str),
        peer_service = decision.attempted.service_id.as_str(),
        peer_key_id = decision.attempted.key_id.as_str(),
        method = method.map(Token::as_str),
        operation_id,
        attempted_sequence = decision.attempted.sequence,
        attempted_head = decision.attempted.head_digest.as_str(),
        retained_sequence = decision.retained.as_ref().map(|head| head.sequence),
        retained_head = decision
            .retained
            .as_ref()
            .map(|head| head.head_digest.as_str()),
        outcome = checkpoint_outcome(decision.outcome),
        mutations_disabled,
        "Broker-Signer checkpoint decision"
    );
}

fn checkpoint_outcome(outcome: CheckpointDecisionOutcome) -> &'static str {
    match outcome {
        CheckpointDecisionOutcome::Appended => "appended",
        CheckpointDecisionOutcome::AlreadyPresent => "already_present",
        CheckpointDecisionOutcome::SequenceRollback => "sequence_rollback",
        CheckpointDecisionOutcome::SequenceConflict => "sequence_conflict",
        CheckpointDecisionOutcome::InvalidSignature => "invalid_signature",
        CheckpointDecisionOutcome::UnpinnedPeer => "unpinned_peer",
        CheckpointDecisionOutcome::StorageOrConfigurationFailure => {
            "storage_or_configuration_failure"
        }
    }
}

fn journal_error(error: crate::journal::JournalError) -> ProtocolError {
    unavailable(format!("verify Broker audit head: {error}"))
}

impl CeremonySigner for BrokerSignerClient {
    fn prepare_approval(
        &self,
        request: bloom_signer_api::CeremonyPrepareRequest,
        _now_ms: u64,
    ) -> Result<SignerPreparedApproval, ProtocolError> {
        match self.request(BrokerSignerRequest::CeremonyPrepare(
            SignerCeremonyPrepareRequest::SealedApproval(Box::new(request)),
        ))? {
            BrokerSignerResponse::CeremonyPrepare(
                SignerCeremonyPrepareResponse::SealedApproval(prepared),
            ) => Ok(prepared),
            _ => Err(response_mismatch("ceremony.prepare")),
        }
    }

    fn complete_approval(
        &self,
        request: CeremonyCompleteRequest,
        _now_ms: u64,
    ) -> Result<SignerActivationReceipt, ProtocolError> {
        match self.request(BrokerSignerRequest::CeremonyComplete(
            SignerCeremonyCompleteRequest::SealedApproval(Box::new(request)),
        ))? {
            BrokerSignerResponse::CeremonyComplete(
                SignerCeremonyCompleteResponse::SealedApproval(receipt),
            ) => Ok(*receipt),
            _ => Err(response_mismatch("ceremony.complete")),
        }
    }

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        _now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        let method = match request.ceremony_kind {
            CeremonyKind::WalletRegistration => {
                BrokerSignerRequest::WalletRegistrationPrepare(request)
            }
            CeremonyKind::WalletImport => BrokerSignerRequest::WalletImportPrepare(request),
            CeremonyKind::WalletExport => BrokerSignerRequest::WalletExportPrepare(request),
            CeremonyKind::WalletDelete => BrokerSignerRequest::WalletDeletePrepare(request),
            CeremonyKind::WalletRecovery => BrokerSignerRequest::RecoveryPrepare(request),
            CeremonyKind::CredentialAdd => BrokerSignerRequest::CredentialAddPrepare(request),
            CeremonyKind::CredentialReplace => {
                BrokerSignerRequest::CredentialReplacePrepare(request)
            }
            CeremonyKind::CredentialRemove => BrokerSignerRequest::CredentialRemovePrepare(request),
            CeremonyKind::BackendEnrollment => BrokerSignerRequest::KeyEnrollPrepare(request),
            CeremonyKind::KeyDerive => BrokerSignerRequest::KeyDerivePrepare(request),
            CeremonyKind::AccountAllocate | CeremonyKind::AccountRetire => {
                BrokerSignerRequest::KeyDerivePrepare(request)
            }
            CeremonyKind::SealedApproval | CeremonyKind::PolicyUpdate => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::CeremonyKindMismatch,
                    "custody kind has no matching prepare method",
                ));
            }
        };
        prepared_custody_response(self.request(method)?)
    }

    fn complete_custody(
        &self,
        request: CustodyCompleteRequest,
        _now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        match self.request(BrokerSignerRequest::CustodyComplete(request))? {
            BrokerSignerResponse::CustodyComplete(result) => Ok(result),
            _ => Err(response_mismatch("custody.complete")),
        }
    }

    fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        _now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        match self.request(BrokerSignerRequest::CeremonyPrepare(
            SignerCeremonyPrepareRequest::PolicyUpdate(Box::new(request)),
        ))? {
            BrokerSignerResponse::CeremonyPrepare(SignerCeremonyPrepareResponse::PolicyUpdate(
                prepared,
            )) => Ok(prepared),
            _ => Err(response_mismatch("ceremony.prepare")),
        }
    }

    fn complete_policy_update(
        &self,
        request: PolicyUpdateCeremonyCompleteRequest,
        _now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        match self.request(BrokerSignerRequest::CeremonyComplete(
            SignerCeremonyCompleteRequest::PolicyUpdate(Box::new(request)),
        ))? {
            BrokerSignerResponse::CeremonyComplete(
                SignerCeremonyCompleteResponse::PolicyUpdate(result),
            ) => Ok(*result),
            _ => Err(response_mismatch("ceremony.complete")),
        }
    }

    fn bind_custody_output_recipient(
        &self,
        operation_id: &OperationId,
        recipient_key: Base64UrlBytes,
        _now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        match self.request(BrokerSignerRequest::CustodyBindOutputRecipient(
            CustodyBindOutputRecipientRequest {
                operation_id: operation_id.clone(),
                recipient_key,
            },
        ))? {
            BrokerSignerResponse::CustodyBindOutputRecipient(prepared) => Ok(prepared),
            _ => Err(response_mismatch("custody.bind_output_recipient")),
        }
    }

    fn cancel(&self, operation_id: &OperationId) -> Result<(), ProtocolError> {
        match self.request(BrokerSignerRequest::CeremonyCancel(IdRequest {
            id: Digest32::new(operation_id.as_str().to_owned())?,
        }))? {
            BrokerSignerResponse::CeremonyCancel(_) => Ok(()),
            _ => Err(response_mismatch("ceremony.cancel")),
        }
    }

    fn status(&self, operation_id: &OperationId) -> Result<SignerCeremonyStatus, ProtocolError> {
        match self.request(BrokerSignerRequest::CeremonyStatus(IdRequest {
            id: Digest32::new(operation_id.as_str().to_owned())?,
        }))? {
            BrokerSignerResponse::CeremonyStatus(status) => Ok(status),
            _ => Err(response_mismatch("ceremony.status")),
        }
    }
}

fn prepared_custody_response(
    response: BrokerSignerResponse,
) -> Result<SignerPreparedCustody, ProtocolError> {
    match response {
        BrokerSignerResponse::WalletRegistrationPrepare(prepared)
        | BrokerSignerResponse::WalletUnlockPrepare(prepared)
        | BrokerSignerResponse::WalletImportPrepare(prepared)
        | BrokerSignerResponse::WalletExportPrepare(prepared)
        | BrokerSignerResponse::WalletDeletePrepare(prepared)
        | BrokerSignerResponse::KeyDerivePrepare(prepared)
        | BrokerSignerResponse::KeyEnrollPrepare(prepared)
        | BrokerSignerResponse::CredentialAddPrepare(prepared)
        | BrokerSignerResponse::CredentialRemovePrepare(prepared)
        | BrokerSignerResponse::CredentialReplacePrepare(prepared)
        | BrokerSignerResponse::RecoveryPrepare(prepared) => Ok(prepared),
        _ => Err(response_mismatch("custody prepare")),
    }
}

fn response_mismatch(method: &str) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        format!("Signer returned the wrong typed response for {method}"),
    )
}

fn unavailable(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::AuditSigner;
    use bloom_audit_checkpoint::{AppendOutcome, CheckpointError};
    use bloom_signer_api::{
        Base64UrlBytes, BootEpoch, BrokerSignerService, DecimalU64, Digest32, Empty, Readiness,
        ReadinessState, ServiceFuture, SignedJournalHead, Token,
    };
    use bloom_triad_local_transport::{
        EndpointQuota, JournalExchange, dispatch_connection_with_journal_heads,
    };
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tracing_subscriber::prelude::*;

    struct TestAuditSigner;

    impl AuditSigner for TestAuditSigner {
        fn key_id(&self) -> Token {
            Token::new("broker-audit-test").unwrap()
        }

        fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
            Ok(Base64UrlBytes::from_bytes(message))
        }

        fn verify(
            &self,
            key_id: &Token,
            message: &[u8],
            signature: &Base64UrlBytes,
        ) -> Result<(), String> {
            (key_id == &self.key_id() && signature.decode() == message)
                .then_some(())
                .ok_or_else(|| "test audit signature mismatch".into())
        }
    }

    struct FailingCheckpointSink;

    #[derive(Default)]
    struct RetainingCheckpointSink(Mutex<BTreeMap<Token, SignedJournalHead>>);

    impl CheckpointSink for RetainingCheckpointSink {
        fn append_peer_head(
            &self,
            peer_head: &SignedJournalHead,
        ) -> Result<AppendOutcome, CheckpointError> {
            self.0
                .lock()
                .unwrap()
                .insert(peer_head.service_id.clone(), peer_head.clone());
            Ok(AppendOutcome::Appended)
        }

        fn latest_peer_head(
            &self,
            service_id: &Token,
        ) -> Result<Option<SignedJournalHead>, CheckpointError> {
            Ok(self.0.lock().unwrap().get(service_id).cloned())
        }
    }

    struct ReadinessService;

    impl BrokerSignerService for ReadinessService {
        fn dispatch<'a>(
            &'a self,
            request: BrokerSignerRequest,
        ) -> ServiceFuture<'a, BrokerSignerResponse> {
            Box::pin(async move {
                match request {
                    BrokerSignerRequest::SignerReadiness(_) => {
                        Ok(BrokerSignerResponse::SignerReadiness(Readiness {
                            service_id: Token::new("bloom-signer").unwrap(),
                            service_version: "test".into(),
                            build_digest: Digest32::from_bytes([0x41; 32]),
                            boot_epoch: BootEpoch::from_bytes([0x42; 16]),
                            state: ReadinessState::Ready,
                            conditions: Vec::new(),
                        }))
                    }
                    _ => Err(ProtocolError::new(
                        ProtocolErrorCode::UnknownMethod,
                        "test supports only signer.readiness",
                    )),
                }
            })
        }
    }

    struct RecordingJournalExchange(Mutex<Vec<SignedJournalHead>>);

    impl JournalExchange<ProtocolError> for RecordingJournalExchange {
        fn checkpoint_request_head(
            &self,
            _method: &Token,
            peer_head: &SignedJournalHead,
        ) -> Result<(), ProtocolError> {
            self.0.lock().unwrap().push(peer_head.clone());
            Ok(())
        }

        fn local_journal_head(&self, _method: &Token) -> Result<(u64, Digest32), ProtocolError> {
            Ok((1, Digest32::from_bytes([0x43; 32])))
        }
    }

    impl CheckpointSink for FailingCheckpointSink {
        fn append_peer_head(
            &self,
            _peer_head: &SignedJournalHead,
        ) -> Result<AppendOutcome, CheckpointError> {
            Err(CheckpointError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced response checkpoint failure",
            )))
        }
    }

    fn peer_head() -> SignedJournalHead {
        SignedJournalHead {
            service_id: Token::new("bloom-signer").unwrap(),
            sequence: DecimalU64::new(1),
            head_hash: Digest32::from_bytes([1; 32]),
            key_id: Token::new("signer-app").unwrap(),
            signature: Base64UrlBytes::from_bytes(&[1; 64]),
        }
    }

    #[test]
    fn response_checkpoint_failure_latches_mutations_but_preserves_reads() {
        let journal = BrokerJournal::open_in_memory(Arc::new(TestAuditSigner)).unwrap();
        let sink = FailingCheckpointSink;
        assert!(
            persist_response_checkpoint(
                &journal,
                &sink,
                &Token::new("signer.readiness").unwrap(),
                None,
                &peer_head(),
            )
            .is_ok()
        );
        assert!(journal.audit_degraded());
        assert_eq!(
            persist_response_checkpoint(
                &journal,
                &sink,
                &Token::new("signer.sign").unwrap(),
                Some("11"),
                &peer_head(),
            )
            .unwrap_err()
            .code,
            ProtocolErrorCode::ServiceUnavailable
        );
    }

    #[test]
    fn signer_worker_preserves_trusted_service_span_and_dispatcher() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(capture.clone()),
        );
        let dispatcher = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatcher, || {
            let service_span = tracing::info_span!(
                "trusted_service",
                service_id = "bloom-broker",
                login_uid = 501_u64,
                build_digest = "test-build-digest"
            );
            let _service_span = service_span.enter();
            let identity = LocalIdentity {
                service_id: Token::new("bloom-broker").unwrap(),
                boot_epoch: BootEpoch::from_bytes([0x21; 16]),
                application_key_id: Token::new("broker-app").unwrap(),
                signing_key: Arc::new(SigningKey::from_bytes(&[0x22; 32])),
            };
            let signer = PeerAcl {
                effective_uid: 0,
                service_id: Token::new("bloom-signer").unwrap(),
                boot_epoch: BootEpoch::from_bytes([0x23; 16]),
                application_key_id: Token::new("signer-app").unwrap(),
                application_public_key: SigningKey::from_bytes(&[0x24; 32])
                    .verifying_key()
                    .to_bytes(),
            };
            let client = BrokerSignerClient::connect_unix(
                "/unused/signer.sock",
                identity,
                signer,
                Arc::new(BrokerJournal::open_in_memory(Arc::new(TestAuditSigner)).unwrap()),
                Arc::new(RetainingCheckpointSink::default()),
            )
            .unwrap();
            drop(client);
        });

        let event = capture
            .text()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|event| event["fields"]["event"] == "checkpoint.decision")
            .expect("Signer worker checkpoint event");
        assert_eq!(event["span"]["service_id"], "bloom-broker");
        assert_eq!(event["span"]["login_uid"], 501);
        assert_eq!(event["span"]["build_digest"], "test-build-digest");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn degraded_restart_uses_retained_nonzero_broker_head_for_real_rpc_read() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("signer.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let broker_identity = LocalIdentity {
            service_id: Token::new("bloom-broker").unwrap(),
            boot_epoch: BootEpoch::from_bytes([0x31; 16]),
            application_key_id: Token::new("broker-app").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[0x32; 32])),
        };
        let signer_identity = LocalIdentity {
            service_id: Token::new("bloom-signer").unwrap(),
            boot_epoch: BootEpoch::from_bytes([0x33; 16]),
            application_key_id: Token::new("signer-app").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[0x34; 32])),
        };
        let effective_uid = std::fs::metadata(directory.path()).unwrap().uid();
        let broker_acl = PeerAcl {
            effective_uid,
            service_id: broker_identity.service_id.clone(),
            boot_epoch: broker_identity.boot_epoch.clone(),
            application_key_id: broker_identity.application_key_id.clone(),
            application_public_key: broker_identity.signing_key.verifying_key().to_bytes(),
        };
        let signer_acl = PeerAcl {
            effective_uid,
            service_id: signer_identity.service_id.clone(),
            boot_epoch: signer_identity.boot_epoch.clone(),
            application_key_id: signer_identity.application_key_id.clone(),
            application_public_key: signer_identity.signing_key.verifying_key().to_bytes(),
        };
        let observed = Arc::new(RecordingJournalExchange(Mutex::new(Vec::new())));
        let server = tokio::spawn({
            let observed = observed.clone();
            let signer_identity = signer_identity.clone();
            async move {
                let quota = EndpointQuota::new(8, 100, 60_000, 100, 60_000).unwrap();
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    dispatch_connection_with_journal_heads::<
                        BrokerSignerRequest,
                        BrokerSignerResponse,
                        ProtocolError,
                        _,
                        _,
                    >(
                        &mut stream,
                        &signer_identity,
                        &broker_acl,
                        bloom_signer_api::SIGNER_API_CURRENT,
                        bloom_signer_api::SIGNER_API_RANGE,
                        &quota,
                        observed.as_ref(),
                        |request| ReadinessService.dispatch(request),
                    )
                    .await
                    .unwrap();
                }
            }
        });

        let journal_path = directory.path().join("broker.sqlite");
        let journal =
            Arc::new(BrokerJournal::open(&journal_path, Arc::new(TestAuditSigner)).unwrap());
        journal
            .create_approval(
                &Digest32::from_bytes([0x35; 32]),
                bloom_broker_api::ApprovalLifecycleState::Prepared,
            )
            .unwrap();
        let checkpoints = Arc::new(RetainingCheckpointSink::default());
        let client = BrokerSignerClient::connect_unix(
            &socket_path,
            broker_identity.clone(),
            signer_acl.clone(),
            journal,
            checkpoints.clone(),
        )
        .unwrap();
        assert!(matches!(
            client
                .request(BrokerSignerRequest::SignerReadiness(Empty {}))
                .unwrap(),
            BrokerSignerResponse::SignerReadiness(_)
        ));
        drop(client);

        rusqlite::Connection::open(&journal_path)
            .unwrap()
            .execute(
                "UPDATE audit_chain SET payload_jcs='{}' WHERE sequence=0",
                [],
            )
            .unwrap();
        let degraded =
            Arc::new(BrokerJournal::open(&journal_path, Arc::new(TestAuditSigner)).unwrap());
        assert!(degraded.audit_degraded());
        let restarted = BrokerSignerClient::connect_unix(
            &socket_path,
            broker_identity,
            signer_acl,
            degraded,
            checkpoints,
        )
        .unwrap();
        assert!(matches!(
            restarted
                .request(BrokerSignerRequest::SignerReadiness(Empty {}))
                .unwrap(),
            BrokerSignerResponse::SignerReadiness(_)
        ));
        server.await.unwrap();
        let heads = observed.0.lock().unwrap();
        assert_eq!(heads.len(), 2);
        assert!(heads[0].sequence.get() > 0);
        assert_eq!(heads[1].sequence, heads[0].sequence);
        assert_eq!(heads[1].head_hash, heads[0].head_hash);
    }
}
