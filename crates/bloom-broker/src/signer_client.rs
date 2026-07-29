//! Authenticated Broker→Signer client and ceremony adapter.

#![forbid(unsafe_code)]

use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
};

use bloom_triad_local_transport::{LocalIdentity, PeerAcl};
use bloom_triad_protocol::{
    Base64UrlBytes, BrokerSignerRequest, BrokerSignerResponse, CeremonyCompleteRequest,
    CeremonyKind, CustodyBindOutputRecipientRequest, CustodyCompleteRequest, CustodyPrepareRequest,
    CustodyResult, Digest32, IdRequest, OperationId, PolicyUpdateCeremonyCompleteRequest,
    PolicyUpdateCeremonyPrepareRequest, ProtocolError, ProtocolErrorCode, SignerActivationReceipt,
    SignerCeremonyCompleteRequest, SignerCeremonyCompleteResponse, SignerCeremonyPrepareRequest,
    SignerCeremonyPrepareResponse, SignerCeremonyStatus, SignerPreparedApproval,
    SignerPreparedCustody,
};

use crate::ceremony::CeremonySigner;

type Job = (
    BrokerSignerRequest,
    mpsc::Sender<Result<BrokerSignerResponse, ProtocolError>>,
);

/// Synchronous facade over a dedicated async transport thread. Ceremony HTTP
/// handlers must not construct or nest a Tokio runtime on an Axum worker.
#[derive(Clone)]
pub struct BrokerSignerClient {
    jobs: mpsc::Sender<Job>,
}

impl BrokerSignerClient {
    pub fn connect_unix(
        socket_path: impl Into<PathBuf>,
        identity: LocalIdentity,
        signer: PeerAcl,
    ) -> Result<Self, ProtocolError> {
        let socket_path = socket_path.into();
        let (jobs, receiver) = mpsc::channel::<Job>();
        thread::Builder::new()
            .name("bloom-broker-signer-rpc".into())
            .spawn(move || worker(receiver, socket_path, identity, signer))
            .map_err(|error| unavailable(format!("start Signer RPC worker: {error}")))?;
        Ok(Self { jobs })
    }

    pub fn connect_unix_from_files(
        socket_path: impl Into<PathBuf>,
        identity_path: impl AsRef<Path>,
        edge_manifest_path: impl AsRef<Path>,
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
        Self::connect_unix(socket_path, identity, signer)
    }

    pub fn request(
        &self,
        request: BrokerSignerRequest,
    ) -> Result<BrokerSignerResponse, ProtocolError> {
        let (reply, response) = mpsc::channel();
        self.jobs
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
}

fn worker(
    receiver: mpsc::Receiver<Job>,
    socket_path: PathBuf,
    identity: LocalIdentity,
    signer: PeerAcl,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return,
    };
    for (request, reply) in receiver {
        let result = runtime.block_on(async {
            let mut stream = tokio::net::UnixStream::connect(&socket_path)
                .await
                .map_err(|error| unavailable(format!("connect Signer: {error}")))?;
            bloom_triad_local_transport::call(&mut stream, &identity, &signer, request, 30_000)
                .await
        });
        let _ = reply.send(result);
    }
}

impl CeremonySigner for BrokerSignerClient {
    fn prepare_approval(
        &self,
        request: bloom_triad_protocol::CeremonyPrepareRequest,
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
