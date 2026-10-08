//! Broker-owned ACME and relay credential lifecycle. Relay only leases the
//! installation's DNS-01 TXT record; the account and TLS private keys stay here.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bloom_relay_client::{DnsChallengeClient, renew_scoped_credential};
use bloom_relay_protocol::{CertificateMetadata, CredentialIssueReceipt, Scope};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::{
    crypto::aws_lc_rs,
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{PemObject, SectionKind},
    },
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_parser::{
    extensions::GeneralName,
    prelude::{FromDer, X509Certificate},
};
use zeroize::{Zeroize, Zeroizing};

use crate::RemoteTlsConfig;

type Failure = Box<dyn std::error::Error + Send + Sync>;
const RENEW_BEFORE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const SCOPED_RENEW_BEFORE_MS: u64 = 6 * 60 * 60 * 1000;

#[derive(Clone, Copy)]
enum AcmeDirectory {
    Production,
    #[cfg(test)]
    Staging,
}

impl AcmeDirectory {
    fn url(self) -> &'static str {
        match self {
            Self::Production => LetsEncrypt::Production.url(),
            #[cfg(test)]
            Self::Staging => LetsEncrypt::Staging.url(),
        }
    }

    fn account_prefix(self) -> &'static str {
        match self {
            Self::Production => "https://acme-v02.api.letsencrypt.org/acme/acct/",
            #[cfg(test)]
            Self::Staging => "https://acme-staging-v02.api.letsencrypt.org/acme/acct/",
        }
    }

    fn accepts_account_id(self, account_id: &str) -> bool {
        account_id
            .strip_prefix(self.account_prefix())
            .is_some_and(|identifier| {
                !identifier.is_empty() && identifier.bytes().all(|byte| byte.is_ascii_digit())
            })
    }
}

fn certificate_renewal_due(not_after_ms: u64, now_ms: u64, renew_before_ms: u64) -> bool {
    not_after_ms <= now_ms.saturating_add(renew_before_ms)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopedMetadata {
    version: u8,
    installation_id: Uuid,
    scope: Scope,
    generation: u64,
    expires_at_ms: u64,
    operation_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingRenewal {
    version: u8,
    new_token: String,
    operation_id: Uuid,
    receipt: Option<CredentialIssueReceipt>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublishedTlsBundle {
    version: u8,
    hostname: String,
    pub(super) cert_pem: String,
    pub(super) key_pem: String,
}

impl Drop for PublishedTlsBundle {
    fn drop(&mut self) {
        self.key_pem.zeroize();
    }
}

/// The relay refused the first DNS-01 ensure of a round with 409: its serving
/// DNS is not ready yet. Raised before any ACME validation, so the caller may
/// retry soon; any other failure (including later relay 409s) is not this.
#[derive(Debug)]
pub(super) struct RelayNotReady;

impl std::fmt::Display for RelayNotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay is not ready for DNS-01 yet (HTTP 409); retrying shortly")
    }
}

impl std::error::Error for RelayNotReady {}

pub(super) fn relay_not_ready(error: &Failure) -> bool {
    error.downcast_ref::<RelayNotReady>().is_some()
}

pub(super) fn load_published_bundle(
    path: &Path,
    hostname: &str,
    uid: u32,
) -> Result<PublishedTlsBundle, Failure> {
    let encoded = Zeroizing::new(read_protected(path, uid)?);
    let bundle: PublishedTlsBundle = serde_json::from_slice(&encoded)?;
    validate_bundle(&bundle, hostname, now_ms()?)?;
    Ok(bundle)
}

fn validate_bundle(
    bundle: &PublishedTlsBundle,
    hostname: &str,
    now: u64,
) -> Result<CertificateInfo, Failure> {
    if bundle.version != 1 || bundle.hostname != hostname {
        return Err("TLS bundle identity mismatch".into());
    }
    let info = certificate_info(bundle.cert_pem.as_bytes(), hostname, now)?;
    validate_key_match(bundle.cert_pem.as_bytes(), bundle.key_pem.as_bytes())?;
    Ok(info)
}

fn publish_bundle(path: &Path, bundle: &PublishedTlsBundle, now: u64) -> Result<(), Failure> {
    validate_bundle(bundle, &bundle.hostname, now)?;
    let encoded = Zeroizing::new(serde_json::to_vec(bundle)?);
    atomic_private(path, &encoded)
}

fn now_ms() -> Result<u64, Failure> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn sibling(path: &Path, suffix: &str) -> Result<PathBuf, Failure> {
    let stem = path
        .file_stem()
        .ok_or("credential path has no stem")?
        .to_string_lossy();
    Ok(path.with_file_name(format!("{stem}.{suffix}")))
}

fn read_protected(path: &Path, uid: u32) -> Result<Vec<u8>, Failure> {
    // Validate the opened inode, not a pathname that could be replaced after
    // inspection. Signer's root handoff and our own atomic renewal both swap
    // these files by rename.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("Broker private material has unsafe ownership or permissions".into());
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err("Broker private material has invalid length".into());
    }
    Ok(bytes)
}

/// The pinned relay control roots: a PEM bundle of one or more certificates.
pub(super) fn read_control_ca(path: &Path, uid: u32) -> Result<Vec<u8>, Failure> {
    let bytes = read_protected(path, uid)?;
    control_roots(&bytes)?;
    Ok(bytes)
}

/// Every certificate in a control CA bundle. Any malformed or non-certificate
/// item fails the whole bundle rather than silently narrowing the roots.
pub(super) fn control_roots(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, Failure> {
    let mut roots = Vec::new();
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
        match item? {
            (SectionKind::Certificate, der) => roots.push(CertificateDer::from(der)),
            _ => return Err("relay control CA bundle holds a non-certificate item".into()),
        }
    }
    if roots.is_empty() {
        return Err("relay control CA bundle holds no certificate".into());
    }
    Ok(roots)
}

fn atomic_private(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let parent = path.parent().ok_or("private path has no parent")?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .ok_or("private path has no name")?
            .to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok::<(), Failure>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn metadata_path(credential: &Path) -> Result<PathBuf, Failure> {
    sibling(credential, "metadata.json")
}

/// The durable record for the renewal in flight, created on first use.
///
/// One scope has at most one renewal operation at a time: the new token and
/// its operation ID are durable before the relay is asked to issue against
/// them, so a crash before the receipt arrives resumes the same operation
/// rather than minting a second one the relay would have to arbitrate.
fn load_or_create_pending(pending_path: &Path, uid: u32) -> Result<PendingRenewal, Failure> {
    let pending: PendingRenewal = if pending_path.exists() {
        serde_json::from_slice(&read_protected(pending_path, uid)?)?
    } else {
        let mut secret = [0u8; 32];
        rand::fill(&mut secret);
        let pending = PendingRenewal {
            version: 1,
            new_token: hex::encode(secret),
            operation_id: Uuid::new_v4(),
            receipt: None,
        };
        atomic_private(pending_path, &serde_json::to_vec(&pending)?)?;
        pending
    };
    if pending.version != 1 || pending.operation_id.is_nil() {
        return Err("invalid persisted scoped renewal".into());
    }
    Ok(pending)
}

async fn renew_scope(
    credential: &Path,
    ca: &[u8],
    installation_id: Uuid,
    scope: Scope,
    uid: u32,
) -> Result<ScopedMetadata, Failure> {
    let path = metadata_path(credential)?;
    let metadata: ScopedMetadata = serde_json::from_slice(&read_protected(&path, uid)?)?;
    if metadata.version != 1
        || metadata.installation_id != installation_id
        || metadata.scope != scope
        || metadata.generation == 0
    {
        return Err("scoped credential metadata does not match installation".into());
    }
    let _token = read_protected(credential, uid)?;
    let pending_path = sibling(credential, "renewal.json")?;
    if metadata.expires_at_ms > now_ms()?.saturating_add(SCOPED_RENEW_BEFORE_MS)
        && !pending_path.exists()
    {
        return Ok(metadata);
    }
    let mut pending = load_or_create_pending(&pending_path, uid)?;
    if pending.receipt.is_none() {
        let receipt = renew_scoped_credential(
            ca.to_vec(),
            installation_id,
            scope,
            metadata.generation,
            credential.to_path_buf(),
            pending.new_token.clone(),
            pending.operation_id,
        )
        .await?;
        pending.receipt = Some(receipt);
        atomic_private(&pending_path, &serde_json::to_vec(&pending)?)?;
    }
    let receipt = pending.receipt.as_ref().ok_or("missing renewal receipt")?;
    if receipt.scope != scope || receipt.operation_id != pending.operation_id {
        return Err("scoped renewal receipt mismatches pending operation".into());
    }
    // The replacement below writes the credential, then the metadata, then
    // deletes this record. A crash after both writes leaves a record whose
    // receipt is already installed, and whose generation is therefore no
    // longer ahead of the live metadata. Recognise exactly that state and
    // finish the interrupted deletion instead of refusing forever: the live
    // metadata is field-for-field what this receipt installed, and the
    // credential is written before it, so the new token is already in place.
    // Expiry is deliberately not consulted here. An applied receipt stays
    // applied, and one that lapsed during a long outage must still be able to
    // clear its record so the next round can start a fresh renewal.
    if metadata.generation == receipt.generation
        && metadata.operation_id == receipt.operation_id
        && metadata.expires_at_ms == receipt.expires_at_ms
    {
        fs::remove_file(&pending_path)?;
        return Ok(metadata);
    }
    if receipt.generation <= metadata.generation || receipt.expires_at_ms <= now_ms()? {
        return Err("scoped renewal receipt mismatches pending operation".into());
    }
    let next = ScopedMetadata {
        version: 1,
        installation_id,
        scope,
        generation: receipt.generation,
        expires_at_ms: receipt.expires_at_ms,
        operation_id: receipt.operation_id,
    };
    // Crash recovery is idempotent: the authenticated receipt is durable before
    // either split file is replaced. A restart completes the same replacement.
    atomic_private(credential, pending.new_token.as_bytes())?;
    atomic_private(&path, &serde_json::to_vec(&next)?)?;
    fs::remove_file(&pending_path)?;
    Ok(next)
}

pub(super) async fn maintain_scoped_credentials(
    config: &RemoteTlsConfig,
    installation_id: Uuid,
    uid: u32,
) -> Result<(), Failure> {
    let ca = read_control_ca(&config.control_ca_path, uid)?;
    renew_scope(
        &config.tunnel_credential_path,
        &ca,
        installation_id,
        Scope::Tunnel,
        uid,
    )
    .await?;
    let dns = config.dns_credential_path();
    renew_scope(&dns, &ca, installation_id, Scope::DnsChallenge, uid).await?;
    Ok(())
}

pub(super) async fn maintain_certificate(
    config: &RemoteTlsConfig,
    hostname: &str,
    installation_id: Uuid,
    uid: u32,
) -> Result<(), Failure> {
    maintain_certificate_with_policy(
        config,
        hostname,
        installation_id,
        uid,
        AcmeDirectory::Production,
        RENEW_BEFORE_MS,
    )
    .await
}

async fn maintain_certificate_with_policy(
    config: &RemoteTlsConfig,
    hostname: &str,
    installation_id: Uuid,
    uid: u32,
    directory: AcmeDirectory,
    renew_before_ms: u64,
) -> Result<(), Failure> {
    bloom_relay_protocol::validate_hostname(hostname)?;
    let account = ensure_acme_account_at(config, uid, directory).await?;
    if let Ok(bundle) = load_published_bundle(&config.bundle_path, hostname, uid) {
        if let Ok(info) = validate_bundle(&bundle, hostname, now_ms()?) {
            if !certificate_renewal_due(info.not_after_ms, now_ms()?, renew_before_ms) {
                return Ok(());
            }
        }
    }
    let ca = read_control_ca(&config.control_ca_path, uid)?;
    let dns_credential = config.dns_credential_path();
    let metadata: ScopedMetadata =
        serde_json::from_slice(&read_protected(&metadata_path(&dns_credential)?, uid)?)?;
    if metadata.version != 1
        || metadata.scope != Scope::DnsChallenge
        || metadata.installation_id != installation_id
        || metadata.expires_at_ms <= now_ms()?
    {
        return Err("DNS credential is unavailable or expired".into());
    }
    let dns = DnsChallengeClient::new(ca, installation_id, dns_credential)?;
    let mut order = account
        .new_order(&NewOrder::new(&[Identifier::Dns(hostname.to_owned())]))
        .await?;
    // DNS-01 values are ensured, not leased: the relay keeps each published
    // for five minutes after the last ensure, so a restarted Broker simply
    // ensures the same value again (Let's Encrypt returns the same pending
    // authorization) and an abandoned one lapses on its own.
    let mut values = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => return Err("ACME authorization is not pending".into()),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or("ACME order lacks DNS-01 challenge")?;
            if challenge.identifier().to_string() != hostname {
                return Err("ACME challenge identifier differs from assigned hostname".into());
            }
            let value = challenge.key_authorization().dns_value();
            // Before anything is sent to the CA: a 409 here means the relay's
            // serving DNS is not ready yet (or its value set is full), so the
            // worker may retry soon without spending ACME validations.
            let mut ensured = dns.ensure(&value).await.map_err(|error| -> Failure {
                match error {
                    bloom_relay_client::ClientError::Refused(409) => Box::new(RelayNotReady),
                    other => Box::new(other),
                }
            })?;
            let mut last_ensure = tokio::time::Instant::now();
            let deadline = last_ensure + Duration::from_secs(180);
            while !dns.ready(&value, ensured.revision).await? {
                if tokio::time::Instant::now() >= deadline {
                    return Err("DNS-01 challenge did not propagate in time".into());
                }
                if last_ensure.elapsed() >= CHALLENGE_REFRESH {
                    ensured = dns.ensure(&value).await?;
                    last_ensure = tokio::time::Instant::now();
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            challenge.set_ready().await?;
            values.push(value);
        }
    }
    // Keep the values published until the CA has validated them.
    let retry = RetryPolicy::default();
    let validated = tokio::select! {
        status = order.poll_ready(&retry) => status?,
        () = keep_challenges_alive(&dns, &values) => unreachable!("keep-alive never ends"),
    };
    if validated != OrderStatus::Ready {
        return Err("ACME order was not ready".into());
    }
    let key = Zeroizing::new(order.finalize().await?);
    let cert = order.poll_certificate(&RetryPolicy::default()).await?;
    let info = certificate_info(cert.as_bytes(), hostname, now_ms()?)?;
    validate_key_match(cert.as_bytes(), key.as_bytes())?;
    dns.report_certificate(CertificateMetadata {
        hostname: hostname.to_owned(),
        acme_account_uri: account.id().to_owned(),
        key_fingerprint: info.spki_sha256,
        lineage: Uuid::new_v4().to_string(),
        not_before_ms: info.not_before_ms,
        not_after_ms: info.not_after_ms,
    })
    .await?;
    // The old valid pair remains intact until this one protected bundle
    // has been validated, fsync'd, and atomically renamed into place.
    publish_bundle(
        &config.bundle_path,
        &PublishedTlsBundle {
            version: 1,
            hostname: hostname.to_owned(),
            cert_pem: cert,
            key_pem: key.to_string(),
        },
        now_ms()?,
    )?;
    Ok(())
}

/// How often a published DNS-01 value is ensured again; well inside the
/// relay's five-minute lifetime.
const CHALLENGE_REFRESH: Duration = Duration::from_secs(120);

async fn keep_challenges_alive(dns: &DnsChallengeClient, values: &[String]) {
    loop {
        tokio::time::sleep(CHALLENGE_REFRESH).await;
        for value in values {
            if let Err(error) = dns.ensure(value).await {
                tracing::warn!(event = "broker.acme_challenge_refresh_failed", %error);
            }
        }
    }
}

pub(super) async fn ensure_acme_account(
    config: &RemoteTlsConfig,
    uid: u32,
) -> Result<Account, Failure> {
    ensure_acme_account_at(config, uid, AcmeDirectory::Production).await
}

async fn ensure_acme_account_at(
    config: &RemoteTlsConfig,
    uid: u32,
    directory: AcmeDirectory,
) -> Result<Account, Failure> {
    let parent = config
        .bundle_path
        .parent()
        .ok_or("certificate path has no parent")?;
    let account_path = parent.join("acme-account.json");
    let account_uri_path = parent.join("acme-account-uri");
    if !account_path.exists() && account_uri_path.exists() {
        return Err(
            "ACME account key missing; ordinary provisioning will not rebind account".into(),
        );
    }
    let account = if account_path.exists() {
        let encoded = Zeroizing::new(read_protected(&account_path, uid)?);
        validate_persisted_account_credentials(&encoded, directory)?;
        let credentials: AccountCredentials = serde_json::from_slice(&encoded)?;
        Account::builder()?.from_credentials(credentials).await?
    } else {
        let (account, credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.url().to_owned(),
                None,
            )
            .await?;
        if !directory.accepts_account_id(account.id()) {
            return Err("ACME server returned an account outside its directory".into());
        }
        atomic_private(&account_path, &serde_json::to_vec(&credentials)?)?;
        account
    };
    if !directory.accepts_account_id(account.id()) {
        return Err("persisted ACME account belongs to a different directory".into());
    }
    if account_uri_path.exists() {
        if read_protected(&account_uri_path, uid)? != account.id().as_bytes() {
            return Err("ACME account URI differs from published binding".into());
        }
    } else {
        atomic_private(&account_uri_path, account.id().as_bytes())?;
    }
    Ok(account)
}

fn validate_persisted_account_credentials(
    encoded: &[u8],
    directory: AcmeDirectory,
) -> Result<(), Failure> {
    let value: serde_json::Value = serde_json::from_slice(encoded)?;
    if value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|id| !directory.accepts_account_id(id))
        || value.get("directory").and_then(serde_json::Value::as_str) != Some(directory.url())
    {
        return Err("persisted ACME credentials belong to a different directory".into());
    }
    Ok(())
}

struct CertificateInfo {
    spki_sha256: String,
    not_before_ms: u64,
    not_after_ms: u64,
}

fn certificate_info(pem: &[u8], hostname: &str, now: u64) -> Result<CertificateInfo, Failure> {
    let first = CertificateDer::from_pem_slice(pem)?;
    let (_, cert) = X509Certificate::from_der(first.as_ref())?;
    let san = cert
        .subject_alternative_name()?
        .ok_or("certificate has no SAN")?;
    if san.value.general_names.len() != 1
        || !matches!(san.value.general_names[0], GeneralName::DNSName(value) if value == hostname)
    {
        return Err("certificate SAN does not match assigned hostname".into());
    }
    let not_before_ms = u64::try_from(cert.validity().not_before.timestamp())?.saturating_mul(1000);
    let not_after_ms = u64::try_from(cert.validity().not_after.timestamp())?.saturating_mul(1000);
    if not_before_ms > now || not_after_ms <= now {
        return Err("certificate is not currently valid".into());
    }
    Ok(CertificateInfo {
        spki_sha256: hex::encode(Sha256::digest(cert.public_key().raw)),
        not_before_ms,
        not_after_ms,
    })
}

fn validate_key_match(cert_pem: &[u8], key_pem: &[u8]) -> Result<(), Failure> {
    let certs = CertificateDer::pem_slice_iter(cert_pem).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(key_pem)?;
    CertifiedKey::from_der(certs, key, &aws_lc_rs::default_provider())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_relay_admin_client::{
        EnrollmentConfig, EnrollmentError, SecretToken, enroll, installation_status,
        issue_credential, register_acme_account, retire_installation,
    };
    use bloom_relay_protocol::{Allocation, AllocationState};
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::{env, os::unix::fs::PermissionsExt};

    const STAGING_SMOKE_TIMEOUT: Duration = Duration::from_secs(300);
    const STAGING_SMOKE_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

    struct StagingInputs {
        control_ca: Vec<u8>,
        receipt_public_keys: Vec<[u8; 32]>,
    }

    impl StagingInputs {
        fn read(uid: u32) -> Result<Self, Failure> {
            if env::var("BLOOM_BROKER_ACME_STAGING_SMOKE").as_deref() != Ok("1") {
                return Err(
                    "set BLOOM_BROKER_ACME_STAGING_SMOKE=1 for this destructive opt-in test".into(),
                );
            }
            let control_ca_path = env::var_os("BLOOM_RELAY_SMOKE_CONTROL_CA_FILE")
                .ok_or("BLOOM_RELAY_SMOKE_CONTROL_CA_FILE is required")?;
            let receipt_key_path = env::var_os("BLOOM_RELAY_SMOKE_RECEIPT_PUBLIC_KEY_FILE")
                .ok_or("BLOOM_RELAY_SMOKE_RECEIPT_PUBLIC_KEY_FILE is required")?;
            let control_ca = read_control_ca(Path::new(&control_ca_path), uid)?;
            let encoded = read_protected(Path::new(&receipt_key_path), uid)?;
            // One pinned key per line: the current key and its successor.
            let receipt_public_keys = std::str::from_utf8(&encoded)?
                .split_whitespace()
                .map(|encoded| {
                    if encoded.len() != 64
                        || !encoded
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err("relay receipt public key must be 64 lowercase hex characters");
                    }
                    let decoded = hex::decode(encoded).map_err(|_| "invalid hex")?;
                    decoded
                        .try_into()
                        .map_err(|_| "relay receipt public key must be exactly 32 bytes")
                })
                .collect::<Result<Vec<[u8; 32]>, _>>()?;
            if receipt_public_keys.is_empty() {
                return Err("no relay receipt public key is pinned".into());
            }
            Ok(Self {
                control_ca,
                receipt_public_keys,
            })
        }

        fn enrollment(&self) -> EnrollmentConfig {
            EnrollmentConfig {
                control_ca_pem: self.control_ca.clone(),
            }
        }
    }

    fn admin_signer(key: &SigningKey) -> impl Fn(&[u8]) -> Result<[u8; 64], EnrollmentError> + '_ {
        move |message| Ok(key.sign(message).to_bytes())
    }

    async fn await_dns_ready(
        inputs: &StagingInputs,
        admin_key: &SigningKey,
        allocation: &Allocation,
    ) -> Result<(), Failure> {
        let deadline = tokio::time::Instant::now() + STAGING_SMOKE_TIMEOUT;
        loop {
            let status = installation_status(
                inputs.enrollment(),
                allocation.installation_id,
                Uuid::new_v4(),
                admin_signer(admin_key),
            )?;
            match status.state {
                AllocationState::DnsReady => return Ok(()),
                AllocationState::PendingDns if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                AllocationState::PendingDns => return Err("relay DNS readiness timed out".into()),
                AllocationState::Retired => {
                    return Err("relay installation retired before DNS readiness".into());
                }
            }
        }
    }

    fn certificate_identity(
        bundle: &PublishedTlsBundle,
        hostname: &str,
    ) -> Result<(String, String, String), Failure> {
        let info = validate_bundle(bundle, hostname, now_ms()?)?;
        let first = CertificateDer::from_pem_slice(bundle.cert_pem.as_bytes())?;
        let (_, certificate) = X509Certificate::from_der(first.as_ref())?;
        Ok((
            certificate.tbs_certificate.raw_serial_as_string(),
            info.spki_sha256,
            certificate.issuer().to_string(),
        ))
    }

    async fn staging_shutdown_signal() -> Result<(), Failure> {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(Into::into),
            _ = terminate.recv() => Ok(()),
        }
    }

    async fn run_staging_issuance_and_renewal(
        inputs: &StagingInputs,
        admin_key: &SigningKey,
        allocation: &Allocation,
        config: &RemoteTlsConfig,
        uid: u32,
    ) -> Result<(), Failure> {
        let account = ensure_acme_account_at(config, uid, AcmeDirectory::Staging).await?;
        if !AcmeDirectory::Staging.accepts_account_id(account.id()) {
            return Err("ACME account was not created by Let's Encrypt staging".into());
        }
        register_acme_account(
            inputs.enrollment(),
            allocation.installation_id,
            account.id().to_owned(),
            Uuid::new_v4(),
            admin_signer(admin_key),
        )?;
        println!(
            "PASS acme-account {} {}",
            allocation.installation_id, allocation.hostname
        );

        let dns_token = SecretToken::generate();
        let dns_receipt = issue_credential(
            inputs.enrollment(),
            allocation.installation_id,
            Scope::DnsChallenge,
            &dns_token,
            Uuid::new_v4(),
            admin_signer(admin_key),
        )?;
        let dns_path = config.dns_credential_path();
        atomic_private(&dns_path, dns_token.expose().as_bytes())?;
        atomic_private(
            &metadata_path(&dns_path)?,
            &serde_json::to_vec(&ScopedMetadata {
                version: 1,
                installation_id: allocation.installation_id,
                scope: Scope::DnsChallenge,
                generation: dns_receipt.generation,
                expires_at_ms: dns_receipt.expires_at_ms,
                operation_id: dns_receipt.operation_id,
            })?,
        )?;
        await_dns_ready(inputs, admin_key, allocation).await?;
        println!(
            "PASS dns-ready {} {}",
            allocation.installation_id, allocation.hostname
        );

        maintain_certificate_with_policy(
            config,
            &allocation.hostname,
            allocation.installation_id,
            uid,
            AcmeDirectory::Staging,
            RENEW_BEFORE_MS,
        )
        .await?;
        let first = load_published_bundle(&config.bundle_path, &allocation.hostname, uid)?;
        let (first_serial, first_spki, first_issuer) =
            certificate_identity(&first, &allocation.hostname)?;
        if !first_issuer.contains("(STAGING)") {
            return Err(
                "issued certificate does not identify a Let's Encrypt staging issuer".into(),
            );
        }
        println!(
            "PASS certificate-issued {} {} serial={} spki_sha256={}",
            allocation.installation_id, allocation.hostname, first_serial, first_spki
        );
        let metadata = fs::symlink_metadata(&config.bundle_path)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("published TLS bundle is not a protected owner-only file".into());
        }
        // Staging certificates are long-lived enough that the production 30-day
        // threshold cannot exercise renewal in one run. Saturation marks the
        // still-valid certificate due without changing production policy.
        maintain_certificate_with_policy(
            config,
            &allocation.hostname,
            allocation.installation_id,
            uid,
            AcmeDirectory::Staging,
            u64::MAX,
        )
        .await?;
        let renewed = load_published_bundle(&config.bundle_path, &allocation.hostname, uid)?;
        let (renewed_serial, renewed_spki, renewed_issuer) =
            certificate_identity(&renewed, &allocation.hostname)?;
        if renewed_serial == first_serial || renewed_spki == first_spki {
            return Err("staging renewal did not rotate certificate serial and SPKI".into());
        }
        if !renewed_issuer.contains("(STAGING)") {
            return Err("renewed certificate does not identify a staging issuer".into());
        }
        println!(
            "PASS certificate-renewed {} {} serial={} spki_sha256={}",
            allocation.installation_id, allocation.hostname, renewed_serial, renewed_spki
        );
        let published_account = read_protected(
            &config
                .bundle_path
                .parent()
                .ok_or("TLS bundle has no parent")?
                .join("acme-account-uri"),
            uid,
        )?;
        if published_account != account.id().as_bytes() {
            return Err("renewal changed the registered staging ACME account".into());
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "destructive opt-in test against disposable public Relay and Let's Encrypt staging"]
    async fn letsencrypt_staging_issuance_and_renewal() -> Result<(), Failure> {
        aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| "a process-wide rustls provider is already installed")?;
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let uid = fs::symlink_metadata(directory.path())?.uid();
        let inputs = StagingInputs::read(uid)?;
        let config = RemoteTlsConfig::defaults(directory.path());
        atomic_private(&config.control_ca_path, &inputs.control_ca)?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        rand::fill(seed.as_mut());
        let admin_key = SigningKey::from_bytes(&seed);
        let receipt = enroll(
            inputs.enrollment(),
            admin_key.verifying_key().as_bytes(),
            &inputs.receipt_public_keys,
            Uuid::new_v4(),
            admin_signer(&admin_key),
        )?;
        let allocation = receipt.allocation;
        println!(
            "PASS enroll {} {}",
            allocation.installation_id, allocation.hostname
        );

        let operation = tokio::time::timeout(
            STAGING_SMOKE_TOTAL_TIMEOUT,
            run_staging_issuance_and_renewal(&inputs, &admin_key, &allocation, &config, uid),
        );
        let result = tokio::select! {
            result = operation => match result {
                Ok(result) => result,
                Err(_) => Err("ACME staging smoke exceeded its 15-minute bound".into()),
            },
            signal = staging_shutdown_signal() => match signal {
                Ok(()) => Err("ACME staging smoke interrupted; retiring allocation".into()),
                Err(error) => Err(error),
            },
        };
        let retirement = retire_installation(
            inputs.enrollment(),
            allocation.installation_id,
            Uuid::new_v4(),
            admin_signer(&admin_key),
        );
        if retirement.is_ok() {
            println!(
                "PASS retire {} {}",
                allocation.installation_id, allocation.hostname
            );
        }
        match (result, retirement) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(Box::new(error) as Failure),
            (Err(operation), Err(retirement)) => Err(format!(
                "staging operation failed ({operation}); retirement also failed ({retirement})"
            )
            .into()),
        }
    }

    #[test]
    fn only_the_pre_validation_relay_refusal_counts_as_not_ready() {
        let not_ready: Failure = Box::new(RelayNotReady);
        // A 409 from any other relay call (for example reporting an issued
        // certificate) must not speed up rounds: it could repeat issuance.
        let later_conflict: Failure = Box::new(bloom_relay_client::ClientError::Refused(409));
        let unauthorized: Failure = Box::new(bloom_relay_client::ClientError::Refused(401));
        let acme: Failure = "ACME order was not ready".into();
        assert!(relay_not_ready(&not_ready));
        assert!(!relay_not_ready(&later_conflict));
        assert!(!relay_not_ready(&unauthorized));
        assert!(!relay_not_ready(&acme));
    }

    #[test]
    fn control_roots_load_every_certificate_or_fail() {
        let bundle = include_bytes!("../tests/fixtures/relay/isrg-roots.pem");
        assert_eq!(control_roots(bundle).unwrap().len(), 2);
        assert!(control_roots(b"").is_err());
        let mut with_key = bundle.to_vec();
        with_key.extend_from_slice(
            b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n",
        );
        assert!(control_roots(&with_key).is_err());
    }

    #[test]
    fn acme_directory_accepts_only_its_exact_account_namespace() {
        assert!(
            AcmeDirectory::Production
                .accepts_account_id("https://acme-v02.api.letsencrypt.org/acme/acct/42")
        );
        assert!(
            !AcmeDirectory::Production
                .accepts_account_id("https://acme-staging-v02.api.letsencrypt.org/acme/acct/42")
        );
        assert!(
            AcmeDirectory::Staging
                .accepts_account_id("https://acme-staging-v02.api.letsencrypt.org/acme/acct/42")
        );
        assert!(
            !AcmeDirectory::Staging
                .accepts_account_id("https://acme-v02.api.letsencrypt.org/acme/acct/42")
        );
        assert!(
            !AcmeDirectory::Production
                .accepts_account_id("https://acme-v02.api.letsencrypt.org/acme/acct/")
        );
        assert!(
            !AcmeDirectory::Production
                .accepts_account_id("https://acme-v02.api.letsencrypt.org/acme/acct/42/path")
        );

        let production = br#"{
            "id":"https://acme-v02.api.letsencrypt.org/acme/acct/42",
            "directory":"https://acme-v02.api.letsencrypt.org/directory"
        }"#;
        let staging = br#"{
            "id":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/42",
            "directory":"https://acme-staging-v02.api.letsencrypt.org/directory"
        }"#;
        validate_persisted_account_credentials(production, AcmeDirectory::Production).unwrap();
        validate_persisted_account_credentials(staging, AcmeDirectory::Staging).unwrap();
        assert!(
            validate_persisted_account_credentials(production, AcmeDirectory::Staging).is_err()
        );
        assert!(
            validate_persisted_account_credentials(staging, AcmeDirectory::Production).is_err()
        );
    }

    #[test]
    fn certificate_validation_requires_exact_san_and_matching_key() {
        let host = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";
        let issued = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
        let cert = issued.cert.pem();
        let key = issued.signing_key.serialize_pem();
        let info = certificate_info(cert.as_bytes(), host, now_ms().unwrap()).unwrap();
        assert_eq!(info.spki_sha256.len(), 64);
        validate_key_match(cert.as_bytes(), key.as_bytes()).unwrap();
        assert!(
            certificate_info(
                cert.as_bytes(),
                "other.relay.bloom.directory",
                now_ms().unwrap()
            )
            .is_err()
        );
        let multi_san = rcgen::generate_simple_self_signed(vec![
            host.to_owned(),
            "other.relay.bloom.directory".to_owned(),
        ])
        .unwrap();
        assert!(
            certificate_info(multi_san.cert.pem().as_bytes(), host, now_ms().unwrap()).is_err()
        );
        let different = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
        assert!(
            validate_key_match(
                cert.as_bytes(),
                different.signing_key.serialize_pem().as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn protected_material_rejects_world_readable_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        atomic_private(&path, b"sensitive").unwrap();
        let uid = fs::symlink_metadata(&path).unwrap().uid();
        assert_eq!(read_protected(&path, uid).unwrap(), b"sensitive");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_protected(&path, uid).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("credential-link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_protected(&link, uid).is_err());
    }

    #[test]
    fn atomic_bundle_keeps_valid_old_pair_when_renewal_fails_or_is_interrupted() {
        let host = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay-tls-bundle.json");
        let first = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
        let old = PublishedTlsBundle {
            version: 1,
            hostname: host.to_owned(),
            cert_pem: first.cert.pem(),
            key_pem: first.signing_key.serialize_pem(),
        };
        publish_bundle(&path, &old, now_ms().unwrap()).unwrap();
        let uid = fs::symlink_metadata(&path).unwrap().uid();
        let original = read_protected(&path, uid).unwrap();
        let second = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
        let mismatched = PublishedTlsBundle {
            version: 1,
            hostname: host.to_owned(),
            cert_pem: second.cert.pem(),
            key_pem: first.signing_key.serialize_pem(),
        };
        assert!(publish_bundle(&path, &mismatched, now_ms().unwrap()).is_err());
        assert_eq!(read_protected(&path, uid).unwrap(), original);

        // A crash before rename leaves the staged file unreferenced. The
        // listener still loads the validated old bundle at the active path.
        atomic_private(
            &directory
                .path()
                .join(".relay-tls-bundle.json.abandoned.tmp"),
            b"partial",
        )
        .unwrap();
        load_published_bundle(&path, host, uid).unwrap();
        let next = PublishedTlsBundle {
            version: 1,
            hostname: host.to_owned(),
            cert_pem: second.cert.pem(),
            key_pem: second.signing_key.serialize_pem(),
        };
        publish_bundle(&path, &next, now_ms().unwrap()).unwrap();
        let selected = load_published_bundle(&path, host, uid).unwrap();
        assert_eq!(selected.cert_pem, next.cert_pem);
        assert_ne!(read_protected(&path, uid).unwrap(), original);
    }

    #[test]
    fn expired_and_not_yet_valid_bundles_are_rejected_and_renewal_is_bounded() {
        let host = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";
        let now = now_ms().unwrap();
        let make = |start, end| {
            let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).unwrap();
            params.not_before = start;
            params.not_after = end;
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();
            PublishedTlsBundle {
                version: 1,
                hostname: host.to_owned(),
                cert_pem: cert.pem(),
                key_pem: key.serialize_pem(),
            }
        };
        let expired = make(
            rcgen::date_time_ymd(2020, 1, 1),
            rcgen::date_time_ymd(2021, 1, 1),
        );
        let future = make(
            rcgen::date_time_ymd(2040, 1, 1),
            rcgen::date_time_ymd(2041, 1, 1),
        );
        assert!(validate_bundle(&expired, host, now).is_err());
        assert!(validate_bundle(&future, host, now).is_err());
        assert!(certificate_renewal_due(
            now + RENEW_BEFORE_MS,
            now,
            RENEW_BEFORE_MS
        ));
        assert!(!certificate_renewal_due(
            now + RENEW_BEFORE_MS + 1,
            now,
            RENEW_BEFORE_MS
        ));
    }

    const ORIGINAL_TOKEN: &str = "original-tunnel-token";
    const RENEWED_TOKEN: &str = "renewed-tunnel-token";

    /// A provisioned Tunnel credential and the siblings its split-file
    /// renewal writes.
    struct ScopedCredential {
        _directory: tempfile::TempDir,
        credential: PathBuf,
        metadata: PathBuf,
        pending: PathBuf,
        installation_id: Uuid,
        uid: u32,
    }

    impl ScopedCredential {
        fn provision() -> Result<Self, Failure> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            let credential = directory.path().join("relay-tunnel-credential");
            atomic_private(&credential, ORIGINAL_TOKEN.as_bytes())?;
            Ok(Self {
                metadata: metadata_path(&credential)?,
                pending: sibling(&credential, "renewal.json")?,
                installation_id: Uuid::new_v4(),
                uid: fs::symlink_metadata(&credential)?.uid(),
                credential,
                _directory: directory,
            })
        }

        fn write_metadata(
            &self,
            generation: u64,
            expires_at_ms: u64,
            operation_id: Uuid,
        ) -> Result<(), Failure> {
            atomic_private(
                &self.metadata,
                &serde_json::to_vec(&ScopedMetadata {
                    version: 1,
                    installation_id: self.installation_id,
                    scope: Scope::Tunnel,
                    generation,
                    expires_at_ms,
                    operation_id,
                })?,
            )
        }

        fn write_pending(
            &self,
            operation_id: Uuid,
            receipt: Option<CredentialIssueReceipt>,
        ) -> Result<(), Failure> {
            atomic_private(
                &self.pending,
                &serde_json::to_vec(&PendingRenewal {
                    version: 1,
                    new_token: RENEWED_TOKEN.to_owned(),
                    operation_id,
                    receipt,
                })?,
            )
        }

        /// Run one maintenance round. The receipt in the pending record is
        /// already durable in every case below, so no relay call is reached
        /// and the control CA is never read.
        async fn round(&self) -> Result<ScopedMetadata, Failure> {
            renew_scope(
                &self.credential,
                &[],
                self.installation_id,
                Scope::Tunnel,
                self.uid,
            )
            .await
        }

        fn token(&self) -> Result<Vec<u8>, Failure> {
            read_protected(&self.credential, self.uid)
        }
    }

    fn tunnel_receipt(
        generation: u64,
        operation_id: Uuid,
        expires_at_ms: u64,
    ) -> CredentialIssueReceipt {
        CredentialIssueReceipt {
            version: 1,
            scope: Scope::Tunnel,
            generation,
            operation_id,
            expires_at_ms,
        }
    }

    #[test]
    fn scoped_renewal_resumes_one_operation_until_its_receipt_is_durable() {
        let scoped = ScopedCredential::provision().unwrap();
        let first = load_or_create_pending(&scoped.pending, scoped.uid).unwrap();
        assert_eq!(first.new_token.len(), 64);
        assert!(!first.operation_id.is_nil());
        assert!(first.receipt.is_none());
        // A crash between writing this record and hearing back from the relay
        // must resume the same operation. A second token and operation ID
        // would leave the relay arbitrating two renewals of one generation.
        let resumed = load_or_create_pending(&scoped.pending, scoped.uid).unwrap();
        assert_eq!(resumed.new_token, first.new_token);
        assert_eq!(resumed.operation_id, first.operation_id);
        // The record holds the next bearer token, so it is owner-only private
        // material like the credential beside it.
        assert_eq!(
            fs::symlink_metadata(&scoped.pending).unwrap().mode() & 0o777,
            0o600
        );
        scoped.write_pending(Uuid::nil(), None).unwrap();
        assert!(load_or_create_pending(&scoped.pending, scoped.uid).is_err());
    }

    #[tokio::test]
    async fn interrupted_scoped_renewal_converges_and_clears_its_pending_record() {
        let scoped = ScopedCredential::provision().unwrap();
        let now = now_ms().unwrap();
        let renewed_until = now + 48 * 60 * 60 * 1000;
        let operation_id = Uuid::new_v4();
        let receipt = tunnel_receipt(8, operation_id, renewed_until);

        // Boundary one: the authenticated receipt is durable and neither split
        // file has been replaced yet.
        scoped
            .write_metadata(7, now + 60_000, Uuid::new_v4())
            .unwrap();
        scoped
            .write_pending(operation_id, Some(receipt.clone()))
            .unwrap();
        let applied = scoped.round().await.unwrap();
        assert_eq!(applied.generation, 8);
        assert_eq!(applied.operation_id, operation_id);
        assert_eq!(applied.expires_at_ms, renewed_until);
        assert_eq!(scoped.token().unwrap(), RENEWED_TOKEN.as_bytes());
        assert!(!scoped.pending.exists());

        // Boundary two: the credential was replaced and the metadata write was
        // lost. The same receipt reapplies both writes.
        scoped
            .write_metadata(7, now + 60_000, Uuid::new_v4())
            .unwrap();
        scoped
            .write_pending(operation_id, Some(receipt.clone()))
            .unwrap();
        let reapplied = scoped.round().await.unwrap();
        assert_eq!(reapplied.generation, 8);
        assert_eq!(scoped.token().unwrap(), RENEWED_TOKEN.as_bytes());
        assert!(!scoped.pending.exists());

        // Boundary three, the reported crash: the credential and the metadata
        // were both replaced and only the record deletion was lost. The
        // receipt is no longer ahead of the metadata it installed, which used
        // to fail this scope's maintenance on every round forever.
        scoped
            .write_metadata(8, renewed_until, operation_id)
            .unwrap();
        scoped.write_pending(operation_id, Some(receipt)).unwrap();
        let converged = scoped.round().await.unwrap();
        assert_eq!(converged.generation, 8);
        assert_eq!(converged.operation_id, operation_id);
        assert_eq!(converged.expires_at_ms, renewed_until);
        assert_eq!(scoped.token().unwrap(), RENEWED_TOKEN.as_bytes());
        assert!(!scoped.pending.exists());
        // With the record gone and the credential fresh, the next round is a
        // no-op rather than a second renewal.
        assert_eq!(scoped.round().await.unwrap().generation, 8);
        assert_eq!(scoped.token().unwrap(), RENEWED_TOKEN.as_bytes());

        // An applied receipt that lapsed during a long outage still clears its
        // record. Holding it would deadlock the scope on a receipt no later
        // round could ever satisfy.
        let lapsed = Uuid::new_v4();
        scoped.write_metadata(9, now - 1, lapsed).unwrap();
        scoped
            .write_pending(lapsed, Some(tunnel_receipt(9, lapsed, now - 1)))
            .unwrap();
        let cleared = scoped.round().await.unwrap();
        assert_eq!(cleared.generation, 9);
        assert!(!scoped.pending.exists());
    }

    #[tokio::test]
    async fn scoped_renewal_still_rejects_stale_and_mismatched_receipts() {
        let now = now_ms().unwrap();
        let live_until = now + 48 * 60 * 60 * 1000;
        let operation_id = Uuid::new_v4();
        let other_operation = Uuid::new_v4();
        let rejected: [(&str, u64, Uuid, CredentialIssueReceipt); 6] = [
            (
                "a receipt issued for the other scope",
                7,
                operation_id,
                CredentialIssueReceipt {
                    scope: Scope::DnsChallenge,
                    ..tunnel_receipt(8, operation_id, live_until)
                },
            ),
            (
                "a receipt naming a different renewal operation",
                7,
                operation_id,
                tunnel_receipt(8, other_operation, live_until),
            ),
            (
                "a replayed receipt behind the live generation",
                9,
                operation_id,
                tunnel_receipt(8, operation_id, live_until),
            ),
            (
                // The near miss of convergence: the generation matches but the
                // metadata was installed by a different operation, so this
                // receipt was never the one applied.
                "a receipt at the live generation from another operation",
                8,
                operation_id,
                tunnel_receipt(8, operation_id, live_until),
            ),
            (
                // Same generation and operation, but a different deadline:
                // not the receipt that produced the live metadata either.
                "a receipt disagreeing with the live expiry",
                8,
                operation_id,
                tunnel_receipt(8, operation_id, live_until + 1),
            ),
            (
                "an unapplied receipt that already expired",
                7,
                operation_id,
                tunnel_receipt(8, operation_id, now - 1),
            ),
        ];
        for (reason, generation, pending_operation, receipt) in rejected {
            let scoped = ScopedCredential::provision().unwrap();
            // Case four installs metadata from an unrelated operation; the
            // others keep a live operation ID that cannot match the receipt.
            scoped
                .write_metadata(generation, live_until, other_operation)
                .unwrap();
            scoped
                .write_pending(pending_operation, Some(receipt))
                .unwrap();
            assert!(scoped.round().await.is_err(), "accepted {reason}");
            // Fail closed: the credential in service is untouched and the
            // record is retained for an operator to inspect.
            assert_eq!(
                scoped.token().unwrap(),
                ORIGINAL_TOKEN.as_bytes(),
                "{reason}"
            );
            assert!(scoped.pending.exists(), "{reason}");
        }
    }

    #[tokio::test]
    async fn missing_acme_key_never_silently_rebinds_existing_account_uri() {
        let directory = tempfile::tempdir().unwrap();
        let config = RemoteTlsConfig::defaults(directory.path());
        let uri = directory.path().join("acme-account-uri");
        atomic_private(&uri, b"https://acme-v02.api.letsencrypt.org/acme/acct/42").unwrap();
        let uid = fs::symlink_metadata(&uri).unwrap().uid();
        assert!(ensure_acme_account(&config, uid).await.is_err());
        assert_eq!(
            read_protected(&uri, uid).unwrap(),
            b"https://acme-v02.api.letsencrypt.org/acme/acct/42"
        );
        assert!(!directory.path().join("acme-account.json").exists());
    }
}
