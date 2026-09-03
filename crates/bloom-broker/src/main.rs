//! OS-activated Bloom Broker service process.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write as _},
    os::unix::fs::{MetadataExt, OpenOptionsExt as _, PermissionsExt as _, chown},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bloom_audit_checkpoint::{
    AppendOutcome, AuthorityEdgeHistory, CheckpointDecision, CheckpointDecisionOutcome,
    CheckpointError, CheckpointSink, CheckpointStore, PinnedAuditKey,
};
use bloom_broker::{
    assurance_verifiers::SolanaSystemTransferVerifier,
    authority::{AssuranceRegistry, BrokerAuthority},
    ceremony::CeremonyBroker,
    clock::BrokerClock,
    journal::{AuditSigner, BrokerJournal},
    service::BrokerRpcService,
    signer_client::{BrokerSignerClient, checkpoint_failure_requires_degradation},
};
use bloom_broker_api::{
    Base64UrlBytes, Digest32, MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService,
    ProtocolError, ProtocolErrorCode, ProvenanceCatalog, SignedJournalHead, Token,
    is_read_only_method,
};
use bloom_platform_containment::NetworkContainmentGuard;
use bloom_signer_api::{
    BrokerSignerRequest, BrokerSignerResponse, ControlRequest, ControlResponse,
    Empty as SignerEmpty, ProtocolError as SignerProtocolError,
    ProtocolErrorCode as SignerProtocolErrorCode, RevocationControlService,
};
#[cfg(feature = "triad-dev-harness")]
use bloom_triad_local_transport::load_developer_identity_and_manifest;
use bloom_triad_local_transport::{
    AuthenticatedRequestContext, EndpointQuota, JournalExchange, LocalIdentity, PeerAcl,
    load_identity_and_manifest,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::AsyncReadExt as _,
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
};
use tracing::Instrument as _;
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
    #[serde(default)]
    audit_historical_public_keys: Vec<AuditPublicKeyConfig>,
    #[serde(default)]
    audit_rotation_previous_key: Option<AuditPreviousSigningKeyConfig>,
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
    /// Non-secret global ceremony admission limits. Kept as a raw document so
    /// the secret-bearing configuration never enters the layered merge; see
    /// [`bloom_broker::config`].
    #[serde(default)]
    ceremony_limits: Option<serde_json::Value>,
    network_containment: Option<NetworkContainmentConfig>,
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
struct AuditPublicKeyConfig {
    key_id: String,
    public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditPreviousSigningKeyConfig {
    key_id: String,
    signing_seed_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkContainmentConfig {
    status_path: PathBuf,
    login_uid: u32,
    maximum_age_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyKeyConfig {
    wallet_id: String,
    key_id: String,
    public_key_hex: String,
}

#[derive(Serialize)]
struct StartupFailure {
    schema: &'static str,
    state: &'static str,
    incident: &'static str,
    address: &'static str,
    message: &'static str,
    observed_at_ms: u64,
}

impl Drop for BrokerConfig {
    fn drop(&mut self) {
        self.broker_signing_seed_hex.zeroize();
        self.audit_signing_seed_hex.zeroize();
        if let Some(previous) = &mut self.audit_rotation_previous_key {
            previous.signing_seed_hex.zeroize();
        }
        self.review_manifest_signing_seed_hex.zeroize();
    }
}

const OBSERVABILITY_INIT_FAILURE_MESSAGE: &str =
    "Bloom Broker logging initialization failed; exiting safely";

#[derive(Debug)]
struct TrustedTerminalError(Box<dyn std::error::Error>);

impl std::fmt::Display for TrustedTerminalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Bloom Broker failed after trusted service metadata was loaded")
    }
}

impl std::error::Error for TrustedTerminalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if std::env::args_os().len() == 2
        && std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--version"))
    {
        println!("bloom-broker {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if init_observability().is_err() {
        eprintln!("{OBSERVABILITY_INIT_FAILURE_MESSAGE}");
        std::process::exit(1);
    }
    if let Err(error) = run().await {
        log_unreported_run_failure(error.as_ref());
        std::process::exit(1);
    }
}

fn log_unreported_run_failure(error: &(dyn std::error::Error + 'static)) {
    if error.downcast_ref::<TrustedTerminalError>().is_none() {
        tracing::error!(
            event = "service.fatal",
            service = "broker",
            error_kind = "bootstrap_failure",
            "Bloom Broker exited before trusted service metadata was loaded"
        );
    }
}

fn init_observability() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    let output = bloom_service_observability::LogOutput::JsonFile(
        bloom_service_observability::SecureLogFile::new(
            PathBuf::from(
                std::env::var_os("BLOOM_BROKER_LOG_PATH")
                    .ok_or("BLOOM_BROKER_LOG_PATH is required by the macOS service profile")?,
            ),
            required_env_u32("BLOOM_BROKER_LOG_OWNER_UID")?,
            required_env_u32("BLOOM_BROKER_LOG_READER_GID")?,
        ),
    );
    #[cfg(not(target_os = "macos"))]
    let output = bloom_service_observability::LogOutput::JsonStderr;
    bloom_service_observability::init("broker", env!("CARGO_PKG_VERSION"), output)?;
    Ok(())
}

fn log_service_terminal(service_span: &tracing::Span, clean: bool) {
    service_span.in_scope(|| {
        if clean {
            tracing::info!(
                event = "service.shutdown",
                service = "broker",
                outcome = "clean",
                "Bloom Broker stopped"
            );
        } else {
            tracing::error!(
                event = "service.fatal",
                service = "broker",
                error_kind = "startup_or_runtime",
                "Bloom Broker exited with an error"
            );
        }
    });
}

#[cfg(target_os = "macos")]
fn required_env_u32(name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(std::env::var(name)
        .map_err(|_| format!("{name} is required by the macOS service profile"))?
        .parse()
        .map_err(|_| format!("{name} must be an unsigned integer"))?)
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    run_with_paths(
        env_path(
            "BLOOM_BROKER_IDENTITY",
            "/var/run/bloom/broker-identity.json",
        ),
        env_path("BLOOM_EDGE_MANIFEST", "/etc/bloom/edge-manifest.json"),
        env_path("BLOOM_BROKER_CONFIG", "/etc/bloom/broker.json"),
    )
    .await
}

async fn run_with_paths(
    identity_path: PathBuf,
    manifest_path: PathBuf,
    config_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "triad-dev-harness")]
    let loaded_identity = match std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT") {
        Some(root) => load_developer_identity_and_manifest(
            Path::new(&root),
            &identity_path,
            &manifest_path,
            "bloom-broker",
        )?,
        None => load_identity_and_manifest(&identity_path, &manifest_path, "bloom-broker")?,
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let loaded_identity =
        load_identity_and_manifest(&identity_path, &manifest_path, "bloom-broker")?;
    let (identity, manifest) = loaded_identity;
    let broker_effective_uid = manifest.broker.effective_uid;
    tracing::info!(
        event = "service.identity_loaded",
        service = "broker",
        service_id = identity.service_id.as_str(),
        application_key_id = identity.application_key_id.as_str(),
        effective_uid = broker_effective_uid,
        "Bloom Broker identity loaded"
    );
    let trusted_time_source = manifest.trusted_time_source.clone();
    let signer_acl = manifest.signer.clone().into_acl()?;
    let session_acl = manifest
        .session
        .clone()
        .ok_or("edge manifest has no login-session identity")?
        .into_acl()?;
    let machine_acl = manifest.machine.into_acl()?;
    let revoke_client_acl = manifest.revoke_client.into_acl()?;
    if machine_acl.service_id.as_str() != "bloom-machine"
        || revoke_client_acl.service_id.as_str() != "bloom-revoke-client"
        || session_acl.service_id.as_str() != "bloom-session"
    {
        return Err("edge manifest has the wrong Broker endpoint principals".into());
    }
    let session_socket_path = env_path(
        "BLOOM_SESSION_SOCKET",
        "/var/run/bloom/session/session.sock",
    );
    let startup_status_path = std::env::var_os("BLOOM_BROKER_STARTUP_STATUS").map(PathBuf::from);
    let mut config = load_config(&config_path)?;
    // Merge and validate admission limits before any durable state is opened,
    // so a mistyped quota fails startup instead of silently widening
    // admission. The four values are non-secret, so the effective policy is
    // reported without the secret-bearing configuration around it.
    let ceremony_limits = bloom_broker::config::ceremony_limits(config.ceremony_limits.as_ref())?;
    let build_digest = Digest32::new(config.build_digest.clone())?;
    let containment = config
        .network_containment
        .as_ref()
        .map(|containment| {
            NetworkContainmentGuard::new(
                containment.status_path.clone(),
                containment.login_uid,
                build_digest.clone(),
                containment.maximum_age_ms,
            )
        })
        .transpose()?;
    let service_span = bloom_service_observability::service_span(
        "broker",
        env!("CARGO_PKG_VERSION"),
        identity.service_id.as_str(),
        config
            .network_containment
            .as_ref()
            .map(|containment| containment.login_uid),
        Some(config.build_digest.as_str()),
    );
    let terminal_span = service_span.clone();
    let result = async move {
        tracing::info!(
            event = "broker.ceremony_limits_configured",
            maximum_concurrent_sessions = ceremony_limits.maximum_concurrent_sessions(),
            creation_window_ms = ceremony_limits.creation_window_ms(),
            maximum_creations_per_wallet = ceremony_limits.maximum_creations_per_wallet(),
            maximum_anonymous_registrations = ceremony_limits.maximum_anonymous_registrations(),
            "Broker ceremony admission limits configured"
        );
        // Own the canonical origin before opening or mutating any durable Broker
        // authority state. A losing AC-31 contender must die without racing the
        // owning Broker's journal or checkpoint store.
        let ceremony_listener = match acquire_ceremony_listener() {
            Ok(listener) => {
                if let Some(path) = startup_status_path.as_deref() {
                    clear_startup_failure(path, broker_effective_uid)?;
                }
                listener
            }
            Err(error) => {
                if let Some(path) = startup_status_path.as_deref() {
                    write_listener_conflict(path, broker_effective_uid, containment.as_ref())?;
                }
                return Err(error);
            }
        };
        let broker_signing_key = take_signing_key(&mut config.broker_signing_seed_hex)?;
        let audit_signing_key = take_signing_key(&mut config.audit_signing_seed_hex)?;
        let previous_audit_signing_key = config
            .audit_rotation_previous_key
            .as_mut()
            .map(|previous| -> Result<(Token, SigningKey), ProtocolError> {
                Ok((
                    Token::new(previous.key_id.clone())?,
                    take_signing_key(&mut previous.signing_seed_hex)?,
                ))
            })
            .transpose()?;
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

        let journal = Arc::new(open_operational_audit_journal(
            &config.journal_path,
            Token::new(config.audit_key_id.clone())?,
            audit_signing_key,
            &config.audit_historical_public_keys,
            previous_audit_signing_key,
        )?);
        if signer_acl.service_id.as_str() != "bloom-signer" {
            return Err("edge manifest does not pin bloom-signer for the Broker edge".into());
        }
        let authority_history_path = env_path(
            "BLOOM_AUTHORITY_EDGE_HISTORY",
            "/etc/bloom/authority-edge-history.json",
        );
        #[cfg(feature = "triad-dev-harness")]
        let history_owner = if std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT").is_some() {
            broker_effective_uid
        } else {
            0
        };
        #[cfg(not(feature = "triad-dev-harness"))]
        let history_owner = 0;
        let checkpoint_store = (|| -> Result<CheckpointStore, CheckpointError> {
            let authority_history =
                AuthorityEdgeHistory::load_trusted(&authority_history_path, history_owner)?;
            let checkpoint_services = [
                &machine_acl.service_id,
                &signer_acl.service_id,
                &identity.service_id,
            ];
            let historical_checkpoint_keys =
                authority_history.historical_pins_for(&checkpoint_services)?;
            let authority_handovers = authority_history.handovers_for(&checkpoint_services);
            CheckpointStore::open_with_history(
                env_path(
                    "BLOOM_BROKER_AUDIT_CHECKPOINT_DIR",
                    "/var/db/bloom/broker/audit-checkpoints",
                ),
                broker_effective_uid,
                identity.service_id.clone(),
                [
                    PinnedAuditKey {
                        service_id: machine_acl.service_id.clone(),
                        key_id: machine_acl.application_key_id.clone(),
                        verifying_key: VerifyingKey::from_bytes(
                            &machine_acl.application_public_key,
                        )
                        .map_err(|_| CheckpointError::InvalidSignature)?,
                    },
                    PinnedAuditKey {
                        service_id: signer_acl.service_id.clone(),
                        key_id: signer_acl.application_key_id.clone(),
                        verifying_key: VerifyingKey::from_bytes(&signer_acl.application_public_key)
                            .map_err(|_| CheckpointError::InvalidSignature)?,
                    },
                    PinnedAuditKey {
                        service_id: identity.service_id.clone(),
                        key_id: identity.application_key_id.clone(),
                        verifying_key: identity.signing_key.verifying_key(),
                    },
                ],
                historical_checkpoint_keys,
                authority_handovers,
            )
        })();
        let signer_checkpoints: Arc<dyn CheckpointSink> = match checkpoint_store {
            Ok(store) => Arc::new(store),
            Err(error) => {
                journal.latch_audit_degradation();
                tracing::error!(
                    event = "checkpoint.store_unavailable",
                    service = "broker",
                    error_kind = checkpoint_error_kind(&error),
                    mutations_disabled = true,
                    "Broker checkpoint store is unavailable"
                );
                Arc::new(UnavailableCheckpointSink {
                    reason: error.to_string(),
                })
            }
        };
        journal.install_self_checkpoint(identity.clone(), signer_checkpoints.clone())?;
        let clock = Arc::new(BrokerClock::new(
            journal.clone(),
            &trusted_time_source,
            identity.boot_epoch.clone(),
        )?);
        if let Some(accepted_utc_ms) = clock_repair_request()? {
            if !clock.uses_durable_clock_guard() {
                return Err(
                    "clock repair is unavailable when the host wall clock is authoritative".into(),
                );
            }
            let expiring = journal.active_approvals_expiring_by(accepted_utc_ms)?;
            require_clock_repair_confirmation(accepted_utc_ms, &expiring)?;
            let decision = journal.repair_clock(accepted_utc_ms)?;
            tracing::info!(
                event = "broker.clock_repair_committed",
                effective_utc_ms = decision.effective_now_ms,
                condition = ?decision.condition,
                expiring_approval_count = expiring.len(),
                "Broker clock repair committed"
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
            compiled_assurance_registry()?,
        )?);
        #[cfg(feature = "triad-dev-harness")]
        let provenance_catalog = match std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT") {
            Some(root) => {
                load_developer_provenance_catalog(Path::new(&root), &config.provenance_catalog_path)
            }
            None => load_provenance_catalog(&config.provenance_catalog_path),
        }?;
        #[cfg(not(feature = "triad-dev-harness"))]
        let provenance_catalog = load_provenance_catalog(&config.provenance_catalog_path)?;
        if !journal.audit_degraded() {
            authority.synchronize_provenance_catalog(&provenance_catalog)?;
        }
        let signer = BrokerSignerClient::connect_unix(
            &config.signer_socket_path,
            identity.clone(),
            signer_acl,
            journal.clone(),
            signer_checkpoints.clone(),
        )?;
        if !journal.audit_degraded()
            || signer_checkpoints
                .latest_peer_head(&identity.service_id)?
                .is_some()
        {
            attempt_initial_signer_head_exchange(&signer).await;
        }
        let signer_head_exchange = signer.clone();
        let ceremony = CeremonyBroker::open_with_manifest_signer_audited(
            &config.ceremony_path,
            Arc::new(signer.clone()),
            Token::new(config.review_manifest_key_id.clone())?,
            review_manifest_signing_key,
            journal.clone(),
            ceremony_limits,
        )?;
        let machine_journal = journal.clone();
        let mut service = BrokerRpcService::new(
            authority,
            journal,
            clock,
            ceremony.clone(),
            signer,
            Token::new(config.broker_signing_key_id.clone())?,
            broker_signing_key,
            identity.boot_epoch.clone(),
            build_digest,
            env!("CARGO_PKG_VERSION"),
        )?;
        if let Some(containment) = containment.clone() {
            service = service.with_network_containment(containment);
        }
        let service = Arc::new(service);
        if !service.journal_is_audit_degraded() {
            service.reconcile_all().await?;
        }

        let rpc_listener = UnixListener::from_std(acquire_unix_listener(
            "BLOOM_BROKER_SOCKET",
            "BLOOM_BROKER_ACTIVATION_NAME",
            "broker",
        )?)?;
        let control_listener = UnixListener::from_std(acquire_unix_listener(
            "BLOOM_BROKER_CONTROL_SOCKET",
            "BLOOM_BROKER_CONTROL_ACTIVATION_NAME",
            "broker-control",
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
        let mut session_stream =
            connect_authenticated_session(&session_socket_path, &identity, &session_acl).await?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut rpc_shutdown = shutdown_rx.clone();
        let mut control_shutdown = shutdown_rx.clone();
        let mut head_exchange_shutdown = shutdown_rx.clone();
        let mut ceremony_shutdown = shutdown_rx;
        let ceremony_for_shutdown = ceremony.clone();
        let machine_journals = Arc::new(BrokerMachineJournals {
            journal: machine_journal,
            checkpoints: signer_checkpoints.clone(),
            identity: identity.clone(),
        });
        tracing::info!(
            event = "service.ready",
            service = "broker",
            rpc_endpoint = "machine",
            control_endpoint = "revocation",
            ceremony_endpoint = true,
            audit_degraded = service.journal_is_audit_degraded(),
            "Bloom Broker listeners ready"
        );
        tokio::try_join!(
            serve_rpc(
                rpc_listener,
                identity.clone(),
                machine_acl,
                rpc_quota,
                service.clone(),
                machine_journals,
                config.maximum_connections,
                &mut rpc_shutdown,
            ),
            serve_control(
                control_listener,
                identity,
                revoke_client_acl,
                control_quota,
                service,
                config.control_maximum_connections,
                &mut control_shutdown,
            ),
            periodically_exchange_signer_head(signer_head_exchange, &mut head_exchange_shutdown),
            async move {
                ceremony_for_shutdown
                    .serve_listener_until(ceremony_listener, async move {
                        wait_for_shutdown(&mut ceremony_shutdown).await;
                    })
                    .await
                    .map_err(std::io::Error::other)
            },
            async move {
                let mut unexpected = [0_u8; 1];
                match session_stream.read(&mut unexpected).await {
                    Ok(0) => shutdown_tx.send(true).map_err(|_| {
                        std::io::Error::other("Broker shutdown receivers disappeared")
                    }),
                    Err(error) if is_session_disconnect(&error) => {
                        shutdown_tx.send(true).map_err(|_| {
                            std::io::Error::other("Broker shutdown receivers disappeared")
                        })
                    }
                    Ok(_) => Err(std::io::Error::other(
                        "session sentinel sent unexpected channel data",
                    )),
                    Err(error) => Err(std::io::Error::new(
                        error.kind(),
                        format!("monitor login-session sentinel: {error}"),
                    )),
                }
            },
        )?;
        ceremony.terminate_live_sessions(unix_time_ms()?)?;
        Ok(())
    }
    .instrument(service_span)
    .await;
    complete_trusted_service_run(&terminal_span, result)
}

fn complete_trusted_service_run(
    service_span: &tracing::Span,
    result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    log_service_terminal(service_span, result.is_ok());
    result.map_err(|error| Box::new(TrustedTerminalError(error)) as Box<dyn std::error::Error>)
}

async fn require_signer_head_exchange(
    signer: &BrokerSignerClient,
) -> Result<(), SignerProtocolError> {
    match signer
        .request_async(BrokerSignerRequest::SignerReadiness(SignerEmpty {}))
        .await?
    {
        BrokerSignerResponse::SignerReadiness(_) => Ok(()),
        _ => Err(SignerProtocolError::new(
            SignerProtocolErrorCode::ServiceUnavailable,
            "Signer returned the wrong journal-head readiness response",
        )),
    }
}

async fn attempt_initial_signer_head_exchange(signer: &BrokerSignerClient) {
    if let Err(error) = require_signer_head_exchange(signer).await {
        // Signer may still be starting. Transport/authentication failure fails
        // readiness and every Signer-backed mutation, but is not evidence that
        // Broker's local audit journal is corrupt. Actual checkpoint failures
        // latch degradation at the append site.
        tracing::warn!(
            event = "checkpoint.exchange_deferred",
            peer_service = "bloom-signer",
            protocol_error_code = error.code.as_str(),
            "Broker deferred initial Signer checkpoint exchange"
        );
    }
}

const AUTHORITY_HEAD_EXCHANGE_CADENCE: Duration = Duration::from_secs(45);
const AUTHORITY_HEAD_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

async fn run_periodic_signer_head_exchange<F, Fut>(
    shutdown: &mut watch::Receiver<bool>,
    mut exchange: F,
) -> std::io::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), SignerProtocolError>>,
{
    let mut interval = tokio::time::interval(AUTHORITY_HEAD_EXCHANGE_CADENCE);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = wait_for_shutdown(shutdown) => return Ok(()),
            _ = interval.tick() => {
                match tokio::time::timeout(AUTHORITY_HEAD_EXCHANGE_TIMEOUT, exchange()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(
                            event = "checkpoint.exchange_failed",
                            peer_service = "bloom-signer",
                            protocol_error_code = error.code.as_str(),
                            "Broker periodic Signer checkpoint exchange failed"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            event = "checkpoint.exchange_failed",
                            peer_service = "bloom-signer",
                            error_kind = "timeout",
                            "Broker periodic Signer checkpoint exchange timed out"
                        );
                    }
                }
            }
        }
    }
}

fn checkpoint_error_kind(error: &CheckpointError) -> &'static str {
    match error {
        CheckpointError::InvalidRoot => "invalid_root",
        CheckpointError::WrongOwner { .. } => "wrong_owner",
        CheckpointError::InsecurePermissions => "insecure_permissions",
        CheckpointError::Malformed(_) => "malformed",
        CheckpointError::SequenceRollback => "sequence_rollback",
        CheckpointError::SequenceConflict => "sequence_conflict",
        CheckpointError::InvalidSignature => "invalid_signature",
        CheckpointError::UnpinnedPeer => "unpinned_peer",
        CheckpointError::Io(_) => "io",
    }
}

async fn periodically_exchange_signer_head(
    signer: BrokerSignerClient,
    shutdown: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    run_periodic_signer_head_exchange(shutdown, || {
        let signer = signer.clone();
        async move { require_signer_head_exchange(&signer).await }
    })
    .await
}

fn is_session_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

fn write_listener_conflict(
    path: &Path,
    broker_uid: u32,
    containment: Option<&NetworkContainmentGuard>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bloom_shaped = canonical_listener_is_bloom_shaped(containment);
    let (incident, message) = if bloom_shaped {
        (
            "another_login_session",
            "another login session owns the Bloom ceremony listener",
        )
    } else {
        (
            "foreign_or_unverifiable_process",
            "a foreign or unverifiable process owns the Bloom ceremony listener",
        )
    };
    write_startup_failure(
        path,
        broker_uid,
        &StartupFailure {
            schema: "bloom.broker-startup.1",
            state: "fatal",
            incident,
            address: "127.0.0.1:18734",
            message,
            observed_at_ms: unix_time_ms()?,
        },
    )
}

fn canonical_listener_is_bloom_shaped(containment: Option<&NetworkContainmentGuard>) -> bool {
    let Some(containment) = containment else {
        return false;
    };
    for attempt in 0..4 {
        if matches!(
            containment.boolean_claim("ceremony_listener_bloom_shaped"),
            Ok(Some(true))
        ) {
            return true;
        }
        if attempt != 3 {
            std::thread::sleep(Duration::from_millis(750));
        }
    }
    false
}

fn write_startup_failure(
    path: &Path,
    broker_uid: u32,
    failure: &StartupFailure,
) -> Result<(), Box<dyn std::error::Error>> {
    let (parent, parent_gid) = verified_status_parent(path, broker_uid)?;
    let bytes = serde_json::to_vec(failure)?;
    if bytes.len() > 1024 {
        return Err("Broker startup diagnostic exceeds its bounded size".into());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != broker_uid
                || metadata.gid() != parent_gid
                || metadata.mode() & 0o777 != 0o640
                || metadata.nlink() != 1
            {
                return Err("refusing to replace a substituted Broker startup diagnostic".into());
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = parent.join(format!(".broker-startup.new.{}", std::process::id()));
    if temporary.exists() {
        let metadata = fs::symlink_metadata(&temporary)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != broker_uid
            || metadata.nlink() != 1
        {
            return Err("refusing to replace a substituted Broker startup temporary".into());
        }
        fs::remove_file(&temporary)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640))?;
    chown(&temporary, None, Some(parent_gid))?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn clear_startup_failure(path: &Path, broker_uid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let (parent, parent_gid) = verified_status_parent(path, broker_uid)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != broker_uid
                || metadata.gid() != parent_gid
                || metadata.mode() & 0o777 != 0o640
                || metadata.nlink() != 1
            {
                return Err("refusing to remove a substituted Broker startup diagnostic".into());
            }
            fs::remove_file(path)?;
            fs::File::open(parent)?.sync_all()?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn verified_status_parent(
    path: &Path,
    broker_uid: u32,
) -> Result<(&Path, u32), Box<dyn std::error::Error>> {
    let parent = path
        .parent()
        .ok_or("Broker startup diagnostic has no parent directory")?;
    // Deliberately no link-count check. Requiring `nlink >= 2` treated the
    // traditional `.`-plus-parent-entry count as evidence of a real directory,
    // but btrfs reports `nlink == 1` for every directory, so this refused a
    // perfectly safe status directory there while proving nothing extra
    // elsewhere. `is_dir()` establishes the type and `symlink_metadata`
    // establishes that the name resolves.
    let metadata = fs::symlink_metadata(parent)?;
    // Directory hard links are forbidden by POSIX, so `is_dir` already rules
    // out substitutes; a link-count floor is not portable (btrfs reports
    // nlink=1 for empty directories) and adds no guarantee beyond `is_dir`.
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != broker_uid
        || metadata.mode() & 0o7777 != 0o750
    {
        return Err("Broker startup status directory has unsafe metadata".into());
    }
    Ok((parent, metadata.gid()))
}

#[cfg(target_os = "macos")]
fn acquire_unix_listener(
    path_variable: &str,
    _activation_variable: &str,
    _default_activation_name: &str,
) -> Result<std::os::unix::net::UnixListener, Box<dyn std::error::Error>> {
    let path = std::env::var_os(path_variable)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{path_variable} is required by the macOS service profile"))?;
    Ok(bloom_service_activation::bind_owned_unix_listener(&path)?)
}

/// Acquire the canonical ceremony listener.
///
/// The platform logic lives in `CeremonyBroker::acquire_canonical_listener`
/// so that the Linux inherited-listener path is covered by a regression rather
/// than only by running the service.
fn acquire_ceremony_listener() -> Result<std::net::TcpListener, Box<dyn std::error::Error>> {
    let name = std::env::var("BLOOM_BROKER_CEREMONY_ACTIVATION_NAME")
        .unwrap_or_else(|_| "broker-ceremony".to_string());
    Ok(CeremonyBroker::acquire_canonical_listener(&name)?)
}

#[cfg(not(target_os = "macos"))]
fn acquire_unix_listener(
    path_variable: &str,
    _activation_variable: &str,
    _default_activation_name: &str,
) -> Result<std::os::unix::net::UnixListener, Box<dyn std::error::Error>> {
    let path = std::env::var_os(path_variable)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{path_variable} is required by the Linux service profile"))?;
    Ok(bloom_service_activation::bind_owned_unix_listener(&path)?)
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
        let affected_approval_ids = expiring
            .iter()
            .map(Digest32::as_str)
            .collect::<Vec<_>>()
            .join(",");
        tracing::warn!(
            event = "broker.clock_repair_confirmation_required",
            accepted_utc_ms,
            expiring_approval_count = expiring.len(),
            affected_approval_ids,
            confirmation_digest = expected.as_str(),
            "Broker clock repair requires operator confirmation"
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

#[allow(clippy::too_many_arguments)]
async fn serve_rpc(
    listener: UnixListener,
    identity: LocalIdentity,
    machine_acl: PeerAcl,
    quota: Arc<EndpointQuota>,
    service: Arc<BrokerRpcService>,
    journals: Arc<BrokerMachineJournals>,
    maximum_connections: usize,
    shutdown: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    let connections = Arc::new(Semaphore::new(maximum_connections));
    loop {
        let permit = tokio::select! {
            _ = wait_for_shutdown(shutdown) => return Ok(()),
            permit = connections.clone().acquire_owned() => {
                permit.map_err(|_| std::io::Error::other("Broker RPC connection gate closed"))?
            }
        };
        let (mut stream, _) = tokio::select! {
            _ = wait_for_shutdown(shutdown) => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let identity = identity.clone();
        let machine_acl = machine_acl.clone();
        let quota = quota.clone();
        let service = service.clone();
        let journals = journals.clone();
        let service_span = tracing::Span::current();
        tokio::spawn(
            async move {
                let _permit = permit;
                let _ =
                bloom_triad_local_transport::dispatch_connection_with_journal_heads_and_context::<
                    MachineBrokerRequest,
                    MachineBrokerResponse,
                    ProtocolError,
                    _,
                    _,
                >(
                    &mut stream,
                    &identity,
                    &machine_acl,
                    bloom_broker_api::BROKER_API_CURRENT,
                    bloom_broker_api::BROKER_API_RANGE,
                    &quota,
                    journals.as_ref(),
                    |request, context| async move {
                        tracing::info!(
                            event = "rpc.admitted",
                            method = context.method.as_str(),
                            operation_id = context.operation_id.as_str(),
                            peer_service = context.caller_service_id.as_str(),
                            peer_key_id = context.caller_application_key_id.as_str(),
                            "Broker admitted authenticated request"
                        );
                        let started = Instant::now();
                        let result =
                            MachineBrokerService::dispatch(service.as_ref(), request).await;
                        log_machine_rpc_completion(&context, started, &result);
                        result
                    },
                )
                .await;
            }
            .instrument(service_span),
        );
    }
}

struct BrokerMachineJournals {
    journal: Arc<BrokerJournal>,
    checkpoints: Arc<dyn CheckpointSink>,
    identity: LocalIdentity,
}

impl JournalExchange<ProtocolError> for BrokerMachineJournals {
    fn checkpoint_request_head(
        &self,
        method: &Token,
        peer_head: &SignedJournalHead,
    ) -> Result<(), ProtocolError> {
        self.checkpoint_request_head_inner(method, None, peer_head)
    }

    fn checkpoint_request_head_with_context(
        &self,
        context: &AuthenticatedRequestContext,
        peer_head: &SignedJournalHead,
    ) -> Result<(), ProtocolError> {
        self.checkpoint_request_head_inner(
            &context.method,
            Some(context.operation_id.as_str()),
            peer_head,
        )
    }

    fn local_journal_head(&self, _method: &Token) -> Result<(u64, Digest32), ProtocolError> {
        self.journal.verified_audit_head().or_else(|_| {
            self.checkpoints
                .latest_peer_head(&self.identity.service_id)
                .map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        format!("load retained Broker audit head: {error}"),
                    )
                })?
                .map(|head| (head.sequence.get(), head.head_hash))
                .ok_or_else(|| {
                    ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        "no independently retained Broker audit head is available",
                    )
                })
        })
    }
}

impl BrokerMachineJournals {
    fn checkpoint_request_head_inner(
        &self,
        method: &Token,
        operation_id: Option<&str>,
        peer_head: &SignedJournalHead,
    ) -> Result<(), ProtocolError> {
        match self.checkpoints.append_peer_head_diagnosed(peer_head) {
            Ok(decision) => {
                log_checkpoint_decision(&decision, method, operation_id, false);
                Ok(())
            }
            Err(failure) => {
                let decision = &failure.decision;
                if !checkpoint_failure_requires_degradation(decision.outcome) {
                    log_checkpoint_decision(decision, method, operation_id, false);
                    return Ok(());
                }
                self.journal.latch_checkpoint_degradation(
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
                log_checkpoint_decision(decision, method, operation_id, true);
                if !is_read_only_method(method) {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        format!(
                            "persist Machine audit checkpoint before Broker mutation dispatch: {}",
                            failure.source
                        ),
                    ));
                }
                Ok(())
            }
        }
    }
}

struct UnavailableCheckpointSink {
    reason: String,
}

impl CheckpointSink for UnavailableCheckpointSink {
    fn append_peer_head(
        &self,
        _peer_head: &SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        Err(CheckpointError::Malformed(self.reason.clone()))
    }
}

async fn serve_control(
    listener: UnixListener,
    identity: LocalIdentity,
    revoke_client_acl: PeerAcl,
    quota: Arc<EndpointQuota>,
    service: Arc<BrokerRpcService>,
    maximum_connections: usize,
    shutdown: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    let connections = Arc::new(Semaphore::new(maximum_connections));
    loop {
        let permit = tokio::select! {
            _ = wait_for_shutdown(shutdown) => return Ok(()),
            permit = connections.clone().acquire_owned() => {
                permit.map_err(|_| std::io::Error::other("Broker control connection gate closed"))?
            }
        };
        let (mut stream, _) = tokio::select! {
            _ = wait_for_shutdown(shutdown) => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let identity = identity.clone();
        let revoke_client_acl = revoke_client_acl.clone();
        let quota = quota.clone();
        let service = service.clone();
        let service_span = tracing::Span::current();
        tokio::spawn(
            async move {
                let _permit = permit;
                let _ = bloom_triad_local_transport::dispatch_connection_with_context::<
                    ControlRequest,
                    ControlResponse,
                    SignerProtocolError,
                    _,
                    _,
                >(
                    &mut stream,
                    &identity,
                    &revoke_client_acl,
                    bloom_signer_api::SIGNER_CONTROL_CURRENT,
                    bloom_signer_api::SIGNER_CONTROL_RANGE,
                    &quota,
                    |request, context| async move {
                        tracing::info!(
                            event = "rpc.admitted",
                            method = context.method.as_str(),
                            operation_id = context.operation_id.as_str(),
                            peer_service = context.caller_service_id.as_str(),
                            peer_key_id = context.caller_application_key_id.as_str(),
                            "Broker admitted authenticated control request"
                        );
                        let started = Instant::now();
                        let result =
                            RevocationControlService::dispatch(service.as_ref(), request).await;
                        log_control_rpc_completion(&context, started, &result);
                        result
                    },
                )
                .await;
            }
            .instrument(service_span),
        );
    }
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

fn log_checkpoint_decision(
    decision: &CheckpointDecision,
    method: &Token,
    operation_id: Option<&str>,
    mutations_disabled: bool,
) {
    let retained_sequence = decision.retained.as_ref().map(|head| head.sequence);
    let retained_head = decision
        .retained
        .as_ref()
        .map(|head| head.head_digest.as_str());
    tracing::info!(
        event = "checkpoint.decision",
        recipient_service = decision.recipient_service_id.as_ref().map(Token::as_str),
        peer_service = decision.attempted.service_id.as_str(),
        peer_key_id = decision.attempted.key_id.as_str(),
        method = method.as_str(),
        operation_id,
        attempted_sequence = decision.attempted.sequence,
        attempted_head = decision.attempted.head_digest.as_str(),
        retained_sequence,
        retained_head,
        outcome = checkpoint_outcome(decision.outcome),
        mutations_disabled,
        "Broker checkpoint decision"
    );
}

fn log_machine_rpc_completion(
    context: &AuthenticatedRequestContext,
    started: Instant,
    result: &Result<MachineBrokerResponse, ProtocolError>,
) {
    let (outcome, code) = match result {
        Ok(_) => ("ok", None),
        Err(error) => ("error", Some(error.code.as_str())),
    };
    tracing::info!(
        event = "rpc.completed",
        method = context.method.as_str(),
        operation_id = context.operation_id.as_str(),
        peer_service = context.caller_service_id.as_str(),
        peer_key_id = context.caller_application_key_id.as_str(),
        duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        outcome,
        protocol_error_code = code,
        "Broker authenticated request completed"
    );
}

fn log_control_rpc_completion(
    context: &AuthenticatedRequestContext,
    started: Instant,
    result: &Result<ControlResponse, SignerProtocolError>,
) {
    let (outcome, code) = match result {
        Ok(_) => ("ok", None),
        Err(error) => ("error", Some(error.code.as_str())),
    };
    tracing::info!(
        event = "rpc.completed",
        method = context.method.as_str(),
        operation_id = context.operation_id.as_str(),
        peer_service = context.caller_service_id.as_str(),
        peer_key_id = context.caller_application_key_id.as_str(),
        duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        outcome,
        protocol_error_code = code,
        "Broker authenticated control request completed"
    );
}

async fn connect_authenticated_session(
    path: &Path,
    identity: &LocalIdentity,
    session_acl: &PeerAcl,
) -> Result<UnixStream, ProtocolError> {
    loop {
        match UnixStream::connect(path).await {
            Ok(mut stream) => {
                bloom_triad_local_transport::authenticate_client(
                    &mut stream,
                    identity,
                    session_acl,
                    bloom_service_activation::SESSION_PROTOCOL_CURRENT,
                    bloom_service_activation::SESSION_PROTOCOL_RANGE,
                )
                .await?;
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) =>
            {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("connect login-session sentinel {}: {error}", path.display()),
                ));
            }
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn unix_time_ms() -> Result<u64, ProtocolError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "system clock is before Unix epoch",
            )
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "system clock does not fit the protocol range",
            )
        })
}

struct Ed25519AuditSigner {
    key_id: Token,
    signing_key: SigningKey,
    verifying_keys: BTreeMap<String, VerifyingKey>,
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
        let verifying_key = self
            .verifying_keys
            .get(key_id.as_str())
            .ok_or_else(|| "audit key ID is not retained in the configured keyring".to_owned())?;
        let signature =
            Signature::from_slice(&signature.decode()).map_err(|error| error.to_string())?;
        verifying_key
            .verify(message, &signature)
            .map_err(|error| error.to_string())
    }
}

fn open_operational_audit_journal(
    path: &Path,
    current_key_id: Token,
    current_signing_key: SigningKey,
    historical: &[AuditPublicKeyConfig],
    previous: Option<(Token, SigningKey)>,
) -> Result<BrokerJournal, ProtocolError> {
    let mut verifying_keys = BTreeMap::new();
    insert_audit_verifying_key(
        &mut verifying_keys,
        current_key_id.as_str(),
        current_signing_key.verifying_key(),
    )?;
    for entry in historical {
        let key_id = Token::new(entry.key_id.clone())?;
        insert_audit_verifying_key(
            &mut verifying_keys,
            key_id.as_str(),
            verifying_key(&entry.public_key_hex)?,
        )?;
    }
    if let Some((previous_key_id, previous_signing_key)) = &previous {
        if previous_key_id == &current_key_id {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "audit rotation previous key must differ from the current key",
            ));
        }
        insert_audit_verifying_key(
            &mut verifying_keys,
            previous_key_id.as_str(),
            previous_signing_key.verifying_key(),
        )?;
    }

    let current_signer = Arc::new(Ed25519AuditSigner {
        key_id: current_key_id,
        signing_key: current_signing_key,
        verifying_keys: verifying_keys.clone(),
    });
    let journal = BrokerJournal::open(path, current_signer.clone()).map_err(audit_startup)?;
    if !journal.audit_degraded() {
        return Ok(journal);
    }

    let Some((previous_key_id, previous_signing_key)) = previous else {
        return Ok(journal);
    };
    let previous_signer = Arc::new(Ed25519AuditSigner {
        key_id: previous_key_id,
        signing_key: previous_signing_key,
        verifying_keys,
    });
    let journal = BrokerJournal::open(path, previous_signer).map_err(audit_startup)?;
    if journal.audit_degraded() {
        // Preserve status/read-only startup on corrupted history. Reopening
        // with the configured current signer produces the same durable view
        // with a mutation-denial latch and cannot publish a rotation.
        return BrokerJournal::open(path, current_signer).map_err(audit_startup);
    }
    journal
        .rotate_audit_key(current_signer)
        .map_err(audit_startup)?;
    journal.verify_audit_chain().map_err(audit_startup)?;
    Ok(journal)
}

fn insert_audit_verifying_key(
    keys: &mut BTreeMap<String, VerifyingKey>,
    key_id: &str,
    key: VerifyingKey,
) -> Result<(), ProtocolError> {
    if let Some(existing) = keys.insert(key_id.to_owned(), key) {
        if existing != key {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("audit key ID {key_id} has conflicting public keys"),
            ));
        }
    }
    Ok(())
}

fn audit_startup(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::ServiceUnavailable,
        format!("open Broker audit journal: {error}"),
    )
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
    decode_provenance_catalog(path)
}

#[cfg(feature = "triad-dev-harness")]
fn load_developer_provenance_catalog(
    root: &Path,
    path: &Path,
) -> Result<ProvenanceCatalog, ProtocolError> {
    bloom_triad_local_transport::validate_developer_security_file(
        root,
        path,
        "provenance catalog",
    )?;
    decode_provenance_catalog(path)
}

fn decode_provenance_catalog(path: &Path) -> Result<ProvenanceCatalog, ProtocolError> {
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

fn compiled_assurance_registry()
-> Result<AssuranceRegistry, bloom_broker::authority::AuthorityError> {
    AssuranceRegistry::compiled(vec![SolanaSystemTransferVerifier::compiled()])
}

#[cfg(test)]
mod startup_failure_tests {
    use super::*;
    use bloom_broker_api::{ApprovalLifecycleState, BootEpoch, ReadinessState};
    use tracing_subscriber::prelude::*;

    #[test]
    fn production_registry_contains_the_digest_pinned_solana_verifier() {
        let capabilities = compiled_assurance_registry().unwrap().capabilities();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(
            capabilities[0].verifier_id.as_str(),
            bloom_broker_api::SOLANA_SYSTEM_TRANSFER_VERIFIER_ID
        );
        assert_eq!(
            capabilities[0].artifact_digest.to_bytes(),
            bloom_broker_api::SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES
        );
    }

    #[test]
    fn observability_init_fallback_is_fixed_and_sanitized() {
        assert_eq!(
            OBSERVABILITY_INIT_FAILURE_MESSAGE,
            "Bloom Broker logging initialization failed; exiting safely"
        );
    }

    #[test]
    fn clock_repair_warning_names_every_affected_approval() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(capture.clone()),
        );
        let accepted_utc_ms = 1_725_000_000_123;
        let approvals = [
            Digest32::from_bytes([0x11; 32]),
            Digest32::from_bytes([0x22; 32]),
        ];
        tracing::subscriber::with_default(subscriber, || {
            assert!(require_clock_repair_confirmation(accepted_utc_ms, &approvals).is_err());
        });

        let output = capture.text();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            event["fields"]["event"],
            "broker.clock_repair_confirmation_required"
        );
        assert_eq!(event["fields"]["accepted_utc_ms"], accepted_utc_ms);
        assert_eq!(event["fields"]["expiring_approval_count"], 2);
        assert_eq!(
            event["fields"]["affected_approval_ids"],
            format!("{},{}", approvals[0].as_str(), approvals[1].as_str())
        );
        let confirmation_digest = event["fields"]["confirmation_digest"].as_str().unwrap();
        assert_eq!(confirmation_digest.len(), 64);
        assert!(
            confirmation_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }

    #[test]
    fn terminal_lifecycle_events_retain_trusted_service_metadata() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(capture.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            let span = bloom_service_observability::service_span(
                "broker",
                "test-version",
                "bloom-broker",
                Some(501),
                Some("test-build-digest"),
            );
            log_service_terminal(&span, true);
        });

        let events = capture
            .text()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| matches!(event["fields"]["event"].as_str(), Some("service.shutdown")))
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        for event in events {
            assert_eq!(event["span"]["service_id"], "bloom-broker");
            assert_eq!(event["span"]["enrolled_login_uid"], 501);
            assert_eq!(event["span"]["release_digest"], "test-build-digest");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_bootstrap_failure_emits_one_safe_root_fatal_event() {
        let temporary = tempfile::tempdir().unwrap();
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(capture.clone()),
        );
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let error = run_with_paths(
            temporary.path().join("missing-identity.json"),
            temporary.path().join("missing-manifest.json"),
            temporary.path().join("missing-config.json"),
        )
        .await
        .unwrap_err();
        log_unreported_run_failure(error.as_ref());

        let output = capture.text();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["fields"]["event"] == "service.fatal")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1, "{output}");
        assert_eq!(events[0]["fields"]["error_kind"], "bootstrap_failure");
        assert!(events[0].get("span").is_none(), "{output}");
    }

    #[test]
    fn trusted_service_failure_is_logged_once_with_metadata() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(capture.clone()),
        );
        let marker_secret = "MARKER_RUN_ERROR_MUST_NOT_BE_LOGGED";
        tracing::subscriber::with_default(subscriber, || {
            let span = bloom_service_observability::service_span(
                "broker",
                "test-version",
                "bloom-broker",
                Some(501),
                Some("test-build-digest"),
            );
            let error = complete_trusted_service_run(
                &span,
                Err(std::io::Error::other(marker_secret).into()),
            )
            .unwrap_err();
            log_unreported_run_failure(error.as_ref());
        });

        let output = capture.text();
        let events = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["fields"]["event"] == "service.fatal")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1, "{output}");
        assert_eq!(events[0]["span"]["service_id"], "bloom-broker");
        assert_eq!(events[0]["span"]["enrolled_login_uid"], 501);
        assert_eq!(events[0]["span"]["release_digest"], "test-build-digest");
        assert!(!output.contains(marker_secret), "{output}");
    }

    #[tokio::test]
    async fn initial_signer_absence_does_not_latch_local_audit_degradation() {
        let temporary = tempfile::tempdir().unwrap();
        let journal = Arc::new(
            open_operational_audit_journal(
                &temporary.path().join("broker.sqlite"),
                Token::new("broker-audit-1").unwrap(),
                SigningKey::from_bytes(&[61; 32]),
                &[],
                None,
            )
            .unwrap(),
        );
        let identity = LocalIdentity {
            service_id: Token::new("bloom-broker").unwrap(),
            boot_epoch: BootEpoch::from_bytes([62; 16]),
            application_key_id: Token::new("broker-app-1").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[63; 32])),
        };
        let checkpoint_root = temporary.path().join("checkpoints");
        fs::create_dir(&checkpoint_root).unwrap();
        fs::set_permissions(&checkpoint_root, fs::Permissions::from_mode(0o700)).unwrap();
        let checkpoints: Arc<dyn CheckpointSink> = Arc::new(
            CheckpointStore::open(
                &checkpoint_root,
                fs::metadata(&checkpoint_root).unwrap().uid(),
                identity.service_id.clone(),
                [PinnedAuditKey {
                    service_id: identity.service_id.clone(),
                    key_id: identity.application_key_id.clone(),
                    verifying_key: identity.signing_key.verifying_key(),
                }],
            )
            .unwrap(),
        );
        journal
            .install_self_checkpoint(identity.clone(), checkpoints.clone())
            .unwrap();
        assert!(!journal.audit_degraded());
        let signer_key = SigningKey::from_bytes(&[64; 32]);
        let signer_acl = PeerAcl {
            effective_uid: fs::metadata(temporary.path()).unwrap().uid(),
            service_id: Token::new("bloom-signer").unwrap(),
            boot_epoch: BootEpoch::from_bytes([65; 16]),
            application_key_id: Token::new("signer-app-1").unwrap(),
            application_public_key: signer_key.verifying_key().to_bytes(),
        };
        let signer = BrokerSignerClient::connect_unix(
            temporary.path().join("missing-signer.sock"),
            identity,
            signer_acl,
            journal.clone(),
            checkpoints,
        )
        .unwrap();

        attempt_initial_signer_head_exchange(&signer).await;

        assert!(!journal.audit_degraded());
    }

    #[test]
    fn unchanged_and_older_machine_heads_remain_admissible_without_degradation() {
        let temporary = tempfile::tempdir().unwrap();
        let journal = Arc::new(
            open_operational_audit_journal(
                &temporary.path().join("broker.sqlite"),
                Token::new("broker-audit-1").unwrap(),
                SigningKey::from_bytes(&[71; 32]),
                &[],
                None,
            )
            .unwrap(),
        );
        let checkpoint_root = temporary.path().join("machine-checkpoints");
        fs::create_dir(&checkpoint_root).unwrap();
        fs::set_permissions(&checkpoint_root, fs::Permissions::from_mode(0o700)).unwrap();

        let machine = LocalIdentity {
            service_id: Token::new("bloom-machine").unwrap(),
            boot_epoch: BootEpoch::new("11".repeat(16)).unwrap(),
            application_key_id: Token::new("machine-app-1").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[72; 32])),
        };
        let broker = LocalIdentity {
            service_id: Token::new("bloom-broker").unwrap(),
            boot_epoch: BootEpoch::new("22".repeat(16)).unwrap(),
            application_key_id: Token::new("broker-app-1").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[73; 32])),
        };
        let checkpoints = CheckpointStore::open(
            &checkpoint_root,
            fs::metadata(&checkpoint_root).unwrap().uid(),
            broker.service_id.clone(),
            [PinnedAuditKey {
                service_id: machine.service_id.clone(),
                key_id: machine.application_key_id.clone(),
                verifying_key: machine.signing_key.verifying_key(),
            }],
        )
        .unwrap();
        let exchange = BrokerMachineJournals {
            journal,
            checkpoints: Arc::new(checkpoints),
            identity: broker,
        };
        let head = bloom_triad_local_transport::sign_journal_head(
            &machine,
            7,
            Digest32::from_bytes([7; 32]),
        );
        let readiness = Token::new("broker.readiness").unwrap();

        // bloom-audit-checkpoint tests the unchanged-head fast path without a
        // history rescan. This integration test verifies Broker repeatedly
        // admits that path without relying on shared-runner wall-clock speed.
        for _ in 0..1_000 {
            exchange.checkpoint_request_head(&readiness, &head).unwrap();
        }
        let newer = bloom_triad_local_transport::sign_journal_head(
            &machine,
            9,
            Digest32::from_bytes([9; 32]),
        );
        exchange
            .checkpoint_request_head(&readiness, &newer)
            .unwrap();
        exchange.checkpoint_request_head(&readiness, &head).unwrap();
        assert!(!exchange.journal.audit_degraded());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_broker_signer_exchange_completes_with_margin_inside_sixty_seconds() {
        let completions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = completions.clone();
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let task = tokio::spawn(async move {
            run_periodic_signer_head_exchange(&mut shutdown, move || {
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                }
            })
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(44)).await;
        tokio::task::yield_now().await;
        assert_eq!(completions.load(std::sync::atomic::Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(completions.load(std::sync::atomic::Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(45)).await;
        tokio::task::yield_now().await;
        assert_eq!(completions.load(std::sync::atomic::Ordering::SeqCst), 2);
        task.abort();
    }

    #[test]
    fn production_audit_rotation_is_restartable_with_retained_public_keys() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("broker.sqlite");
        let old = SigningKey::from_bytes(&[81; 32]);
        let new = SigningKey::from_bytes(&[82; 32]);
        let old_id = Token::new("broker-audit-old").unwrap();
        let new_id = Token::new("broker-audit-new").unwrap();

        let journal =
            open_operational_audit_journal(&path, old_id.clone(), old.clone(), &[], None).unwrap();
        journal
            .create_approval(
                &Digest32::from_bytes([1; 32]),
                ApprovalLifecycleState::Prepared,
            )
            .unwrap();
        drop(journal);

        let retained = vec![AuditPublicKeyConfig {
            key_id: old_id.as_str().to_owned(),
            public_key_hex: hex::encode(old.verifying_key().to_bytes()),
        }];
        let rotated = open_operational_audit_journal(
            &path,
            new_id.clone(),
            new.clone(),
            &retained,
            Some((old_id, old)),
        )
        .unwrap();
        rotated
            .create_approval(
                &Digest32::from_bytes([2; 32]),
                ApprovalLifecycleState::Prepared,
            )
            .unwrap();
        assert_eq!(
            rotated
                .audit_entries()
                .unwrap()
                .iter()
                .filter(|entry| entry.event_type == "audit.key_rotated")
                .count(),
            1
        );
        drop(rotated);

        let restarted =
            open_operational_audit_journal(&path, new_id, new, &retained, None).unwrap();
        restarted.verify_audit_chain().unwrap();
        assert!(!restarted.audit_degraded());
    }

    #[test]
    fn production_startup_preserves_reads_on_signing_mismatch_but_refuses_conflicting_pins() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("broker.sqlite");
        let old = SigningKey::from_bytes(&[83; 32]);
        let new = SigningKey::from_bytes(&[84; 32]);
        let old_id = Token::new("broker-audit-old").unwrap();
        let new_id = Token::new("broker-audit-new").unwrap();
        let journal = open_operational_audit_journal(&path, old_id, old, &[], None).unwrap();
        journal
            .create_approval(
                &Digest32::from_bytes([3; 32]),
                ApprovalLifecycleState::Prepared,
            )
            .unwrap();
        drop(journal);
        let degraded =
            open_operational_audit_journal(&path, new_id.clone(), new.clone(), &[], None).unwrap();
        assert!(degraded.audit_degraded());
        assert_eq!(
            degraded
                .approval_state(&Digest32::from_bytes([3; 32]))
                .unwrap(),
            Some(ApprovalLifecycleState::Prepared)
        );
        assert!(
            degraded
                .transition_approval(
                    &Digest32::from_bytes([3; 32]),
                    ApprovalLifecycleState::AwaitingCeremony,
                )
                .is_err()
        );
        let clock = BrokerClock::new(
            Arc::new(degraded),
            test_time_source(),
            BootEpoch::new("01".repeat(16)).unwrap(),
        )
        .expect("degraded production clock construction must not mutate");
        let readiness = clock.readiness().unwrap();
        assert_eq!(readiness.0, ReadinessState::DegradedReadOnly);
        assert_eq!(
            readiness.1,
            vec![Token::new("audit_journal_degraded").unwrap()]
        );
        let conflicting = vec![AuditPublicKeyConfig {
            key_id: new_id.as_str().to_owned(),
            public_key_hex: hex::encode(SigningKey::from_bytes(&[85; 32]).verifying_key()),
        }];
        assert!(open_operational_audit_journal(&path, new_id, new, &conflicting, None).is_err());
    }

    #[test]
    fn production_startup_preserves_reads_after_audit_payload_tamper() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("broker.sqlite");
        let signing_key = SigningKey::from_bytes(&[86; 32]);
        let key_id = Token::new("broker-audit-current").unwrap();
        let approval_id = Digest32::from_bytes([4; 32]);
        let journal =
            open_operational_audit_journal(&path, key_id.clone(), signing_key.clone(), &[], None)
                .unwrap();
        journal
            .create_approval(&approval_id, ApprovalLifecycleState::Prepared)
            .unwrap();
        drop(journal);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE audit_chain SET payload_jcs='{}' WHERE sequence=0",
                [],
            )
            .unwrap();

        let degraded =
            open_operational_audit_journal(&path, key_id, signing_key, &[], None).unwrap();
        assert!(degraded.audit_degraded());
        assert_eq!(
            degraded.approval_state(&approval_id).unwrap(),
            Some(ApprovalLifecycleState::Prepared)
        );
        assert!(
            degraded
                .transition_approval(&approval_id, ApprovalLifecycleState::AwaitingCeremony,)
                .is_err()
        );
    }

    fn test_time_source() -> &'static str {
        #[cfg(target_os = "linux")]
        return "linux-system-clock";
        #[cfg(target_os = "macos")]
        return "macos-managed-timed";
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        panic!("Broker startup tests require a reviewed trusted-time platform");
    }

    #[test]
    fn session_disconnect_errors_exit_cleanly_without_keepalive_retry() {
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
            ErrorKind::UnexpectedEof,
        ] {
            assert!(is_session_disconnect(&std::io::Error::from(kind)));
        }
        assert!(!is_session_disconnect(&std::io::Error::from(
            ErrorKind::PermissionDenied
        )));
    }

    #[test]
    fn startup_failure_is_bounded_atomic_and_substitution_safe() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o750))
            .expect("set status directory permissions");
        let metadata = fs::symlink_metadata(temporary.path()).expect("status directory metadata");
        let path = temporary.path().join("broker-startup.json");
        let failure = StartupFailure {
            schema: "bloom.broker-startup.1",
            state: "fatal",
            incident: "foreign_or_unverifiable_process",
            address: "127.0.0.1:18734",
            message: "a foreign or unverifiable process owns the Bloom ceremony listener",
            observed_at_ms: 1,
        };

        write_startup_failure(&path, metadata.uid(), &failure).expect("write startup failure");
        let written = fs::symlink_metadata(&path).expect("startup failure metadata");
        assert_eq!(written.uid(), metadata.uid());
        assert_eq!(written.gid(), metadata.gid());
        assert_eq!(written.mode() & 0o777, 0o640);
        assert_eq!(written.nlink(), 1);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read startup failure"))
                .expect("parse startup failure");
        assert_eq!(value["incident"], "foreign_or_unverifiable_process");

        clear_startup_failure(&path, metadata.uid()).expect("clear startup failure");
        assert!(!path.exists());

        std::os::unix::fs::symlink("/dev/null", &path).expect("substitute status path");
        assert!(write_startup_failure(&path, metadata.uid(), &failure).is_err());
    }
}
