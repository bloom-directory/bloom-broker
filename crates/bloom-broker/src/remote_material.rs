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
use bloom_relay_protocol::{CertificateMetadata, ChallengeLease, CredentialIssueReceipt, Scope};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::{
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
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

fn certificate_renewal_due(not_after_ms: u64, now_ms: u64) -> bool {
    not_after_ms <= now_ms.saturating_add(RENEW_BEFORE_MS)
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

pub(super) fn read_control_ca(path: &Path, uid: u32) -> Result<Vec<u8>, Failure> {
    let bytes = read_protected(path, uid)?;
    CertificateDer::from_pem_slice(&bytes)?;
    Ok(bytes)
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
    let mut pending: PendingRenewal = if pending_path.exists() {
        serde_json::from_slice(&read_protected(&pending_path, uid)?)?
    } else {
        let mut secret = [0u8; 32];
        rand::fill(&mut secret);
        let pending = PendingRenewal {
            version: 1,
            new_token: hex::encode(secret),
            operation_id: Uuid::new_v4(),
            receipt: None,
        };
        atomic_private(&pending_path, &serde_json::to_vec(&pending)?)?;
        pending
    };
    if pending.version != 1 || pending.operation_id.is_nil() {
        return Err("invalid persisted scoped renewal".into());
    }
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
    if receipt.scope != scope
        || receipt.operation_id != pending.operation_id
        || receipt.generation <= metadata.generation
        || receipt.expires_at_ms <= now_ms()?
    {
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
    bloom_relay_protocol::validate_hostname(hostname)?;
    let account = ensure_acme_account(config, uid).await?;
    if let Ok(bundle) = load_published_bundle(&config.bundle_path, hostname, uid) {
        if let Ok(info) = validate_bundle(&bundle, hostname, now_ms()?) {
            if !certificate_renewal_due(info.not_after_ms, now_ms()?) {
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
    let dns = DnsChallengeClient::new(ca, installation_id, metadata.generation, dns_credential)?;
    let mut order = account
        .new_order(&NewOrder::new(&[Identifier::Dns(hostname.to_owned())]))
        .await?;
    let mut leases = Vec::new();
    let operation = async {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => return Err::<(), Failure>("ACME authorization is not pending".into()),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or("ACME order lacks DNS-01 challenge")?;
            if challenge.identifier().to_string() != hostname {
                return Err("ACME challenge identifier differs from assigned hostname".into());
            }
            let lease_id = Uuid::new_v4();
            dns.create(ChallengeLease {
                operation_id: lease_id,
                txt_value: challenge.key_authorization().dns_value(),
                expires_at_ms: now_ms()?.saturating_add(15 * 60 * 1000),
            })
            .await?;
            leases.push(lease_id);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
            loop {
                if dns.ready(lease_id).await? {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err("DNS-01 lease did not propagate in time".into());
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            challenge.set_ready().await?;
        }
        if order.poll_ready(&RetryPolicy::default()).await? != OrderStatus::Ready {
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
    .await;
    for lease_id in leases {
        if let Err(error) = dns.delete(lease_id).await {
            tracing::warn!(event = "broker.acme_lease_delete_failed", %error);
        }
    }
    operation
}

pub(super) async fn ensure_acme_account(
    config: &RemoteTlsConfig,
    uid: u32,
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
        let credentials: AccountCredentials =
            serde_json::from_slice(&read_protected(&account_path, uid)?)?;
        Account::builder()?.from_credentials(credentials).await?
    } else {
        let (account, credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                LetsEncrypt::Production.url().to_owned(),
                None,
            )
            .await?;
        atomic_private(&account_path, &serde_json::to_vec(&credentials)?)?;
        account
    };
    if account_uri_path.exists() {
        if read_protected(&account_uri_path, uid)? != account.id().as_bytes() {
            return Err("ACME account URI differs from published binding".into());
        }
    } else {
        atomic_private(&account_uri_path, account.id().as_bytes())?;
    }
    Ok(account)
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
    use std::os::unix::fs::PermissionsExt;

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
        assert!(certificate_renewal_due(now + RENEW_BEFORE_MS, now));
        assert!(!certificate_renewal_due(now + RENEW_BEFORE_MS + 1, now));
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
