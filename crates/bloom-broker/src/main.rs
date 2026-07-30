//! OS-activated Bloom Broker service process.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use bloom_broker::{
    authority::{AssuranceRegistry, BrokerAuthority},
    ceremony::CeremonyBroker,
    clock::BrokerClock,
    journal::{AuditSigner, BrokerJournal},
    service::BrokerRpcService,
    signer_client::BrokerSignerClient,
};
use bloom_triad_local_transport::{
    EndpointQuota, LocalIdentity, PeerAcl, load_identity_and_manifest,
};
use bloom_triad_protocol::{
    Base64UrlBytes, Digest32, ProtocolError, ProtocolErrorCode, ProvenanceCatalog, Token,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::{net::UnixListener, sync::Semaphore};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerConfig {
    journal_path: PathBuf,
    authority_path: PathBuf,
    ceremony_path: PathBuf,
    signer_socket_path: PathBuf,
    broker_signing_key_id: String,
    broker_signing_seed_hex: String,
    audit_key_id: String,
    audit_signing_seed_hex: String,
    review_manifest_key_id: String,
    review_manifest_signing_seed_hex: String,
    installer_key_id: String,
    installer_public_key_hex: String,
    signer_ceremony_key_id: String,
    signer_ceremony_public_key_hex: String,
    signer_revocation_key_id: String,
    signer_revocation_public_key_hex: String,
    provenance_catalog_path: PathBuf,
    policy_keys: Vec<PolicyKeyConfig>,
    build_digest: String,
    maximum_connections: usize,
    maximum_in_flight_mutations: usize,
    maximum_requests_per_window: usize,
    request_window_ms: u64,
    maximum_journal_admissions_per_window: usize,
    journal_window_ms: u64,
    control_maximum_connections: usize,
    control_maximum_in_flight_mutations: usize,
    control_maximum_requests_per_window: usize,
    control_request_window_ms: u64,
    control_maximum_journal_admissions_per_window: usize,
    control_journal_window_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyKeyConfig {
    wallet_id: String,
    key_id: String,
    public_key_hex: String,
}

impl Drop for BrokerConfig {
    fn drop(&mut self) {
        self.broker_signing_seed_hex.zeroize();
        self.audit_signing_seed_hex.zeroize();
        self.review_manifest_signing_seed_hex.zeroize();
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() == 2
        && std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--version"))
    {
        println!("bloom-broker {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let identity_path = env_path(
        "BLOOM_BROKER_IDENTITY",
        "/var/run/bloom/broker-identity.json",
    );
    let manifest_path = env_path("BLOOM_EDGE_MANIFEST", "/etc/bloom/edge-manifest.json");
    let config_path = env_path("BLOOM_BROKER_CONFIG", "/etc/bloom/broker.json");
    let rpc_activation =
        std::env::var("BLOOM_BROKER_ACTIVATION_NAME").unwrap_or_else(|_| "broker".into());
    let control_activation = std::env::var("BLOOM_BROKER_CONTROL_ACTIVATION_NAME")
        .unwrap_or_else(|_| "broker-control".into());

    let (identity, manifest) =
        load_identity_and_manifest(&identity_path, &manifest_path, "bloom-broker")?;
    let trusted_time_source = manifest.trusted_time_source.clone();
    let machine_acl = manifest.machine.into_acl()?;
    let revoke_client_acl = manifest.revoke_client.into_acl()?;
    if machine_acl.service_id.as_str() != "bloom-machine"
        || revoke_client_acl.service_id.as_str() != "bloom-revoke-client"
    {
        return Err("edge manifest has the wrong Broker endpoint principals".into());
    }
    let mut config = load_config(&config_path)?;
    let broker_signing_key = take_signing_key(&mut config.broker_signing_seed_hex)?;
    let audit_signing_key = take_signing_key(&mut config.audit_signing_seed_hex)?;
    let review_manifest_signing_key =
        take_signing_key(&mut config.review_manifest_signing_seed_hex)?;
    let policy_keys = config
        .policy_keys
        .iter()
        .map(|entry| {
            Ok((
                entry.wallet_id.clone(),
                (
                    Token::new(entry.key_id.clone())?,
                    verifying_key(&entry.public_key_hex)?,
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ProtocolError>>()?;

    let audit_signer = Arc::new(Ed25519AuditSigner {
        key_id: Token::new(config.audit_key_id.clone())?,
        signing_key: audit_signing_key,
    });
    let journal = Arc::new(BrokerJournal::open(&config.journal_path, audit_signer)?);
    let clock = Arc::new(BrokerClock::new(
        journal.clone(),
        &trusted_time_source,
        identity.boot_epoch.clone(),
    )?);
    if let Some(accepted_utc_ms) = clock_repair_request()? {
        let expiring = journal.active_approvals_expiring_by(accepted_utc_ms)?;
        require_clock_repair_confirmation(accepted_utc_ms, &expiring)?;
        let decision = journal.repair_clock(accepted_utc_ms)?;
        eprintln!(
            "Bloom Broker clock repair accepted: effective_utc_ms={}, condition={:?}, expiring_live_approvals={}",
            decision.effective_now_ms,
            decision.condition,
            serde_json::to_string(&expiring)?
        );
        return Ok(());
    }
    let authority = Arc::new(BrokerAuthority::open(
        &config.authority_path,
        journal.clone(),
        policy_keys,
        Token::new(config.installer_key_id.clone())?,
        verifying_key(&config.installer_public_key_hex)?,
        Token::new(config.signer_ceremony_key_id.clone())?,
        verifying_key(&config.signer_ceremony_public_key_hex)?,
        Token::new(config.signer_revocation_key_id.clone())?,
        verifying_key(&config.signer_revocation_public_key_hex)?,
        AssuranceRegistry::compiled(Vec::new())?,
    )?);
    let provenance_catalog = load_provenance_catalog(&config.provenance_catalog_path)?;
    for record in &provenance_catalog.records {
        authority.install_provenance(record)?;
    }
    let signer = BrokerSignerClient::connect_unix_from_files(
        &config.signer_socket_path,
        &identity_path,
        &manifest_path,
    )?;
    let ceremony = CeremonyBroker::open_with_manifest_signer(
        &config.ceremony_path,
        Arc::new(signer.clone()),
        Token::new(config.review_manifest_key_id.clone())?,
        review_manifest_signing_key,
    )?;
    let service = Arc::new(BrokerRpcService::new(
        authority,
        journal,
        clock,
        ceremony.clone(),
        signer,
        Token::new(config.broker_signing_key_id.clone())?,
        broker_signing_key,
        identity.boot_epoch.clone(),
        Digest32::new(config.build_digest.clone())?,
        env!("CARGO_PKG_VERSION"),
    )?);
    service.reconcile_all().await?;

    let rpc_listener = UnixListener::from_std(bloom_service_activation::take_unix_listener(
        &rpc_activation,
    )?)?;
    let control_listener = UnixListener::from_std(bloom_service_activation::take_unix_listener(
        &control_activation,
    )?)?;
    let rpc_quota = Arc::new(EndpointQuota::new(
        config.maximum_in_flight_mutations,
        config.maximum_requests_per_window,
        config.request_window_ms,
        config.maximum_journal_admissions_per_window,
        config.journal_window_ms,
    )?);
    let control_quota = Arc::new(EndpointQuota::new(
        config.control_maximum_in_flight_mutations,
        config.control_maximum_requests_per_window,
        config.control_request_window_ms,
        config.control_maximum_journal_admissions_per_window,
        config.control_journal_window_ms,
    )?);
    if config.maximum_connections == 0 || config.control_maximum_connections == 0 {
        return Err("Broker connection quotas must be nonzero".into());
    }
    tokio::try_join!(
        serve_rpc(
            rpc_listener,
            identity.clone(),
            machine_acl,
            rpc_quota,
            service.clone(),
            config.maximum_connections,
        ),
        serve_control(
            control_listener,
            identity,
            revoke_client_acl,
            control_quota,
            service,
            config.control_maximum_connections,
        ),
        async move {
            ceremony
                .serve_canonical()
                .await
                .map_err(std::io::Error::other)
        },
    )?;
    Ok(())
}

fn require_clock_repair_confirmation(
    accepted_utc_ms: u64,
    expiring: &[Digest32],
) -> Result<(), Box<dyn std::error::Error>> {
    if expiring.is_empty() {
        return Ok(());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"bloom-clock-repair-confirmation/v1");
    hasher.update(accepted_utc_ms.to_be_bytes());
    hasher.update(serde_jcs::to_vec(expiring)?);
    let expected = Digest32::from_bytes(hasher.finalize().into());
    let supplied = std::env::var("BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST").ok();
    if supplied.as_deref() != Some(expected.as_str()) {
        eprintln!(
            "Bloom Broker clock repair requires confirmation before mutation: accepted_utc_ms={}, expiring_live_approvals={}, confirmation_digest={}",
            accepted_utc_ms,
            serde_json::to_string(expiring)?,
            expected
        );
        return Err(
            "clock repair not committed; set BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST to the reported digest"
                .into(),
        );
    }
    Ok(())
}

fn clock_repair_request() -> Result<Option<u64>, Box<dyn std::error::Error>> {
    std::env::var("BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS")
        .ok()
        .map(|value| {
            value.parse::<u64>().map_err(|error| {
                format!("invalid BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS: {error}").into()
            })
        })
        .transpose()
}

async fn serve_rpc(
    listener: UnixListener,
    identity: LocalIdentity,
    machine_acl: PeerAcl,
    quota: Arc<EndpointQuota>,
    service: Arc<BrokerRpcService>,
    maximum_connections: usize,
) -> std::io::Result<()> {
    let connections = Arc::new(Semaphore::new(maximum_connections));
    loop {
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("Broker RPC connection gate closed"))?;
        let (mut stream, _) = listener.accept().await?;
        let identity = identity.clone();
        let machine_acl = machine_acl.clone();
        let quota = quota.clone();
        let service = service.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = bloom_triad_local_transport::dispatch_machine_broker_connection(
                &mut stream,
                &identity,
                &machine_acl,
                &quota,
                service.as_ref(),
            )
            .await;
        });
    }
}

async fn serve_control(
    listener: UnixListener,
    identity: LocalIdentity,
    revoke_client_acl: PeerAcl,
    quota: Arc<EndpointQuota>,
    service: Arc<BrokerRpcService>,
    maximum_connections: usize,
) -> std::io::Result<()> {
    let connections = Arc::new(Semaphore::new(maximum_connections));
    loop {
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("Broker control connection gate closed"))?;
        let (mut stream, _) = listener.accept().await?;
        let identity = identity.clone();
        let revoke_client_acl = revoke_client_acl.clone();
        let quota = quota.clone();
        let service = service.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = bloom_triad_local_transport::dispatch_control_connection(
                &mut stream,
                &identity,
                &revoke_client_acl,
                &quota,
                service.as_ref(),
            )
            .await;
        });
    }
}

struct Ed25519AuditSigner {
    key_id: Token,
    signing_key: SigningKey,
}

impl AuditSigner for Ed25519AuditSigner {
    fn key_id(&self) -> Token {
        self.key_id.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(
            &self.signing_key.sign(message).to_bytes(),
        ))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id != &self.key_id {
            return Err("audit key ID mismatch".into());
        }
        let signature =
            Signature::from_slice(&signature.decode()).map_err(|error| error.to_string())?;
        self.signing_key
            .verifying_key()
            .verify(message, &signature)
            .map_err(|error| error.to_string())
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn load_config(path: &Path) -> Result<BrokerConfig, ProtocolError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            format!("inspect {}: {error}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "Broker config must be a non-symlink regular file with mode 0600 or stricter",
        ));
    }
    let mut bytes = fs::read(path).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            format!("read {}: {error}", path.display()),
        )
    })?;
    let decoded = serde_json::from_slice(&bytes).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            format!("parse Broker config: {error}"),
        )
    });
    bytes.zeroize();
    decoded
}

fn load_provenance_catalog(path: &Path) -> Result<ProvenanceCatalog, ProtocolError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            format!("inspect {}: {error}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "provenance catalog must be a root-owned, non-symlink regular file not writable by group or other",
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            format!("read {}: {error}", path.display()),
        )
    })?;
    if bytes.len() > 1024 * 1024 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::LimitExceededFrame,
            "provenance catalog exceeds 1 MiB",
        ));
    }
    let catalog: ProvenanceCatalog = serde_json::from_slice(&bytes).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            format!("parse provenance catalog: {error}"),
        )
    })?;
    catalog.validate_shape()?;
    Ok(catalog)
}

fn take_signing_key(encoded: &mut String) -> Result<SigningKey, ProtocolError> {
    let decoded = hex::decode(encoded.as_bytes()).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "signing seed is not hexadecimal",
        )
    })?;
    encoded.zeroize();
    let mut seed: [u8; 32] = decoded.try_into().map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "signing seed must contain 32 bytes",
        )
    })?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

fn verifying_key(encoded: &str) -> Result<VerifyingKey, ProtocolError> {
    let bytes: [u8; 32] = hex::decode(encoded)
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "public key is not hexadecimal",
            )
        })?
        .try_into()
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "public key must contain 32 bytes",
            )
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "public key is not canonical Ed25519",
        )
    })
}
