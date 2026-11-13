//! Fixtures shared by the Broker integration tests: fixed test identities and
//! keys, accepting audit/checkpoint fakes, and builders for a real
//! Broker↔Signer stack.
#![allow(dead_code)]

use bloom_audit_checkpoint::{AppendOutcome, CheckpointError, CheckpointSink};
use bloom_broker::{
    authority::{AssuranceRegistry, BrokerAuthority},
    ceremony::CeremonyBroker,
    clock::BrokerClock,
    journal::{AuditSigner, BrokerJournal},
    service::BrokerRpcService,
    signer_client::BrokerSignerClient,
};
use bloom_broker_api::{
    Base64UrlBytes, BootEpoch, DerivationProfile, DerivedAccountRequest, Digest32, OperationId,
    Token,
};
use bloom_signer::{
    ceremony::SignerCeremonyService,
    clock::SignerClock,
    engine::{SignerAuditKeys, SignerEngine},
    registry::BackendRegistry,
    service::SignerRpcService,
};
use bloom_signer_api::{
    BrokerSignerRequest, BrokerSignerResponse, BrokerSignerService, SignedJournalHead,
};
use bloom_triad_local_transport::{EndpointQuota, JournalExchange, LocalIdentity, PeerAcl};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Digest as _;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

pub fn url_token(url: &str) -> String {
    url.rsplit_once("/ceremony/").unwrap().1.to_owned()
}

pub fn operation(byte: &str) -> OperationId {
    OperationId::new(byte.repeat(32)).unwrap()
}

pub fn evm_family_request() -> DerivedAccountRequest {
    DerivedAccountRequest {
        derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
        requested_role: Token::new("primary-evm").unwrap(),
        account: None,
    }
}

pub fn solana_family_request() -> DerivedAccountRequest {
    DerivedAccountRequest {
        derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
        requested_role: Token::new("solana-account").unwrap(),
        account: None,
    }
}

pub fn signer_audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: Token::new("signer-audit-key").unwrap(),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

pub fn local_identity(service_id: &str, seed: [u8; 32], epoch: &str) -> LocalIdentity {
    LocalIdentity {
        service_id: Token::new(service_id).unwrap(),
        boot_epoch: BootEpoch::new(epoch.repeat(16)).unwrap(),
        application_key_id: Token::new(format!("{service_id}-app")).unwrap(),
        signing_key: Arc::new(SigningKey::from_bytes(&seed)),
    }
}

pub fn peer_acl(identity: &LocalIdentity, effective_uid: u32) -> PeerAcl {
    PeerAcl {
        effective_uid,
        service_id: identity.service_id.clone(),
        boot_epoch: identity.boot_epoch.clone(),
        application_key_id: identity.application_key_id.clone(),
        application_public_key: identity.signing_key.verifying_key().to_bytes(),
    }
}

/// Audit "signatures" are SHA-256 digests under one fixed key ID.
#[derive(Clone)]
pub struct ServiceTestAuditSigner;

impl AuditSigner for ServiceTestAuditSigner {
    fn key_id(&self) -> Token {
        Token::new("broker-audit-key").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(&sha2::Sha256::digest(message)))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id == &self.key_id()
            && signature.decode() == sha2::Sha256::digest(message).as_slice()
        {
            Ok(())
        } else {
            Err("audit signature mismatch".into())
        }
    }
}

/// [`ServiceTestAuditSigner`] whose writes fail while the flag is set.
pub struct SwitchableAuditSigner(pub Arc<AtomicBool>);

impl AuditSigner for SwitchableAuditSigner {
    fn key_id(&self) -> Token {
        ServiceTestAuditSigner.key_id()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        if self.0.load(Ordering::SeqCst) {
            Err("forced audit write failure".into())
        } else {
            ServiceTestAuditSigner.sign(message)
        }
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        ServiceTestAuditSigner.verify(key_id, message, signature)
    }
}

pub struct AcceptingCheckpointSink;

impl CheckpointSink for AcceptingCheckpointSink {
    fn append_peer_head(
        &self,
        _peer_head: &SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        Ok(AppendOutcome::Appended)
    }
}

pub struct SignerJournalExchange(pub Arc<SignerEngine>);

impl JournalExchange<bloom_signer_api::ProtocolError> for SignerJournalExchange {
    fn checkpoint_request_head(
        &self,
        _method: &Token,
        _peer_head: &SignedJournalHead,
    ) -> Result<(), bloom_signer_api::ProtocolError> {
        Ok(())
    }

    fn local_journal_head(
        &self,
        _method: &Token,
    ) -> Result<(u64, Digest32), bloom_signer_api::ProtocolError> {
        self.0.verified_audit_head()
    }
}

/// A Signer engine under the fixed test keys; `None` opens it in memory.
pub fn open_signer_engine(path: Option<&Path>) -> Arc<SignerEngine> {
    let broker_app = Token::new("broker-app-1").unwrap();
    let broker_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let installer_key = SigningKey::from_bytes(&[6; 32]).verifying_key();
    let revocation_id = Token::new("signer-revocation-key").unwrap();
    let revocation_key = SigningKey::from_bytes(&[4; 32]);
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    Arc::new(
        match path {
            Some(path) => SignerEngine::open(
                path,
                broker_app,
                broker_key,
                installer_key,
                revocation_id,
                revocation_key,
                signer_audit_keys(),
                registry,
            ),
            None => SignerEngine::open_in_memory(
                broker_app,
                broker_key,
                installer_key,
                revocation_id,
                revocation_key,
                signer_audit_keys(),
                registry,
            ),
        }
        .unwrap(),
    )
}

pub fn open_signer_ceremony(engine: Arc<SignerEngine>) -> Arc<SignerCeremonyService> {
    Arc::new(
        SignerCeremonyService::new(
            engine,
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    )
}

pub fn open_signer_rpc(
    engine: Arc<SignerEngine>,
    ceremony: Arc<SignerCeremonyService>,
    time_source: &'static str,
    boot_epoch: &BootEpoch,
    build: &'static str,
) -> Arc<SignerRpcService> {
    Arc::new(SignerRpcService::new(
        engine.clone(),
        ceremony,
        Arc::new(SignerClock::new(engine, time_source, boot_epoch.clone()).unwrap()),
        boot_epoch.clone(),
        digest("e2"),
        build,
    ))
}

/// Serve Broker→Signer RPC on `listener` until the task is aborted.
pub fn spawn_signer_server(
    listener: tokio::net::UnixListener,
    identity: LocalIdentity,
    broker_acl: PeerAcl,
    rpc: Arc<SignerRpcService>,
    engine: Arc<SignerEngine>,
) -> tokio::task::JoinHandle<()> {
    let exchange = SignerJournalExchange(engine);
    tokio::spawn(async move {
        let quota = EndpointQuota::new(16, 1_000, 60_000, 1_000, 60_000).unwrap();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            bloom_triad_local_transport::dispatch_connection_with_journal_heads::<
                BrokerSignerRequest,
                BrokerSignerResponse,
                bloom_signer_api::ProtocolError,
                _,
                _,
            >(
                &mut stream,
                &identity,
                &broker_acl,
                bloom_signer_api::SIGNER_API_CURRENT,
                bloom_signer_api::SIGNER_API_RANGE,
                &quota,
                &exchange,
                |request| BrokerSignerService::dispatch(rpc.as_ref(), request),
            )
            .await
            .unwrap();
        }
    })
}

pub fn connect_signer(
    socket_path: &Path,
    broker_identity: &LocalIdentity,
    signer_acl: &PeerAcl,
    journal: &Arc<BrokerJournal>,
) -> BrokerSignerClient {
    BrokerSignerClient::connect_unix(
        socket_path,
        broker_identity.clone(),
        signer_acl.clone(),
        journal.clone(),
        Arc::new(AcceptingCheckpointSink),
    )
    .unwrap()
}

/// Broker authority trusting the Signer's fixed ceremony and revocation keys.
pub fn broker_authority(
    path: impl AsRef<Path>,
    journal: &Arc<BrokerJournal>,
    policy_keys: BTreeMap<String, (Token, VerifyingKey)>,
) -> BrokerAuthority {
    BrokerAuthority::open(
        path.as_ref(),
        journal.clone(),
        policy_keys,
        Token::new("installer-key").unwrap(),
        SigningKey::from_bytes(&[5; 32]).verifying_key(),
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]).verifying_key(),
        Token::new("signer-revocation-key").unwrap(),
        SigningKey::from_bytes(&[4; 32]).verifying_key(),
        AssuranceRegistry::compiled(Vec::new()).unwrap(),
    )
    .unwrap()
}

pub fn manifest_ceremony(
    path: impl AsRef<Path>,
    signer_client: &BrokerSignerClient,
    journal: &Arc<BrokerJournal>,
) -> CeremonyBroker {
    CeremonyBroker::open_with_manifest_signer(
        path.as_ref(),
        Arc::new(signer_client.clone()),
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        journal.clone(),
    )
    .unwrap()
}

pub fn broker_service(
    authority: Arc<BrokerAuthority>,
    journal: &Arc<BrokerJournal>,
    ceremony: CeremonyBroker,
    signer_client: BrokerSignerClient,
    time_source: &'static str,
    boot_epoch: &BootEpoch,
) -> BrokerRpcService {
    BrokerRpcService::new(
        authority,
        journal.clone(),
        Arc::new(BrokerClock::new(journal.clone(), time_source, boot_epoch.clone()).unwrap()),
        ceremony,
        signer_client,
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        boot_epoch.clone(),
        digest("e3"),
        "test",
    )
    .unwrap()
}
