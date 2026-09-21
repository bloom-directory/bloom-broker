use std::{
    env, fs,
    io::{Read as _, Write as _},
    net::TcpStream,
    path::{Path, PathBuf},
    time::Duration,
};

use bloom_broker_debug_driver::{BrowserResultRecipient, VirtualAuthenticator, seal_hpke};
use bloom_signer_api::{
    Base64UrlBytes, CeremonyChallenge, CeremonyKind, CustodyHpkeAad, CustodyOutputHpkeAad,
    CustodySignerContribution, Digest32, HpkeEnvelope, LocalPrfHpkeAad, SignerCeremonyContribution,
    Token, WebAuthnCeremonyProof,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

mod artifact_scan;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or("usage: bloom-broker-debug-driver complete URL (--authenticator-seed-file PATH | SEED) [--mnemonic-file PATH | --raw-private-key VALUE] [options] | assert-machine-secret-confinement --signer-db PATH --authenticator-seed SEED --artifact PATH [...]")?;
    if command == "assert-machine-secret-confinement" {
        return assert_machine_secret_confinement_command(args);
    }
    if command != "complete" {
        return Err(format!("unsupported debug-driver command: {command}").into());
    }
    let url = args.next().ok_or("complete requires a ceremony URL")?;
    let mut seed = None;
    let mut new_seed = None;
    let mut new_seed_from_file = false;
    let mut browser_result_file = None;
    let mut recovery_record_file = None;
    let mut raw_private_key = None;
    let mut mnemonic = None;
    let mut sign_count = 1_u32;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--authenticator-seed-file" => {
                if seed.is_some() {
                    return Err("authenticator seed was specified more than once".into());
                }
                let path = PathBuf::from(
                    args.next()
                        .ok_or("--authenticator-seed-file requires a path")?,
                );
                seed = Some(read_protected_seed_file(&path)?);
            }
            "--new-authenticator-seed" => {
                if new_seed.is_some() {
                    return Err("new authenticator seed was specified more than once".into());
                }
                new_seed = Some(
                    args.next()
                        .ok_or("--new-authenticator-seed requires a value")?,
                );
            }
            "--new-authenticator-seed-file" => {
                if new_seed.is_some() {
                    return Err("new authenticator seed was specified more than once".into());
                }
                let path = PathBuf::from(
                    args.next()
                        .ok_or("--new-authenticator-seed-file requires a path")?,
                );
                new_seed = Some(read_protected_seed_file(&path)?);
                new_seed_from_file = true;
            }
            "--browser-result-file" => {
                if browser_result_file.is_some() {
                    return Err("browser result file was specified more than once".into());
                }
                browser_result_file = Some(PathBuf::from(
                    args.next().ok_or("--browser-result-file requires a path")?,
                ));
            }
            "--recovery-record-file" => {
                if recovery_record_file.is_some() {
                    return Err("recovery record file was specified more than once".into());
                }
                recovery_record_file = Some(PathBuf::from(
                    args.next()
                        .ok_or("--recovery-record-file requires a path")?,
                ));
            }
            "--raw-private-key" => {
                raw_private_key = Some(args.next().ok_or("--raw-private-key requires a value")?);
            }
            "--mnemonic-file" => {
                let path = PathBuf::from(args.next().ok_or("--mnemonic-file requires a path")?);
                mnemonic = Some(read_protected_seed_file(&path)?);
            }
            "--sign-count" => {
                sign_count = args
                    .next()
                    .ok_or("--sign-count requires a value")?
                    .parse()?;
            }
            _ if !flag.starts_with('-') && seed.is_none() => seed = Some(flag),
            _ => return Err("unknown debug-driver option".into()),
        }
    }

    let client = CeremonyClient::connect(&url)?;
    let mut session = client.read_session()?;
    let origin = client.origin();
    let rp_id = client.rp_id();
    let kind: CeremonyKind = serde_json::from_value(session["ceremony_kind"].clone())?;
    if kind == CeremonyKind::WalletRecovery && recovery_record_file.is_none() {
        return Err("wallet recovery requires --recovery-record-file".into());
    }
    if kind == CeremonyKind::WalletRecovery && browser_result_file.is_none() {
        return Err("wallet recovery requires --browser-result-file".into());
    }
    if kind == CeremonyKind::WalletRecovery && !new_seed_from_file {
        return Err("wallet recovery requires --new-authenticator-seed-file".into());
    }
    if kind != CeremonyKind::WalletRecovery && seed.is_none() {
        return Err("ceremony requires an authenticator seed".into());
    }
    if let (Some(input), Some(output)) = (&recovery_record_file, &browser_result_file) {
        if input == output {
            return Err("recovery input and result paths must differ".into());
        }
    }
    if browser_result_file
        .as_ref()
        .is_some_and(|path| path.exists())
    {
        return Err("browser result file already exists".into());
    }
    let output_recipient = if browser_result_file.is_some() {
        let recipient = BrowserResultRecipient::generate();
        let ceremony_id: Digest32 =
            serde_json::from_value(session["signer_contribution"]["ceremony_id"].clone())?;
        session = client.bind_output_key(&ceremony_id, recipient.public_key())?;
        Some(recipient)
    } else {
        None
    };
    let challenges = session["challenges"]
        .as_array()
        .ok_or("ceremony session omitted challenges")?
        .iter()
        .map(|challenge| serde_json::from_value::<CeremonyChallenge>(challenge["binding"].clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let public_binding_digest: Digest32 =
        serde_json::from_value(session["challenges"][0]["binding"]["exact_terms_digest"].clone())?;
    let authenticator = VirtualAuthenticator::from_seed(
        seed.as_deref().or(new_seed.as_deref()).unwrap().as_bytes(),
    );

    if kind == CeremonyKind::SealedApproval {
        let contribution: SignerCeremonyContribution =
            serde_json::from_value(session["signer_contribution"].clone())?;
        let assertion = authenticator.assertion_for(
            &challenges[0].canonical_bytes()?,
            sign_count,
            origin,
            rp_id,
        );
        let aad = LocalPrfHpkeAad {
            surface: contribution.surface.clone(),
            ceremony_id: contribution.ceremony_id.clone(),
            signer_nonce: contribution.signer_nonce.clone(),
            approval_id: serde_json::from_value(session["review_manifest"]["approval_id"].clone())?,
            approval_digest: contribution.approval_digest.clone(),
            review_manifest_digest: contribution.review_manifest_digest.clone(),
            key_ref: contribution.key_ref.clone(),
            allowed_crypto_suites: contribution.allowed_crypto_suites.clone(),
            credential_id: assertion.credential_id.clone(),
            activation_mode: contribution.activation_mode.clone(),
            wallet_revocation_epoch: contribution.wallet_revocation_epoch.clone(),
        }
        .canonical_bytes()?;
        let recipient = contribution
            .ephemeral_encryption_public_key
            .as_ref()
            .ok_or("sealed approval omitted its local PRF encryption recipient")?;
        let encrypted_input = seal_hpke(
            recipient,
            b"bloom-local-prf/v1",
            &aad,
            &authenticator.deterministic_prf(),
        )?;
        let body = serde_json::to_vec(&serde_json::json!({
            "proof": WebAuthnCeremonyProof::Assertion { assertion },
            "encrypted_input": encrypted_input,
            "public_binding_digest": public_binding_digest,
        }))?;
        let result = client.complete(&contribution.ceremony_id, &body)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone())?;

    let (proof, credential_id, plaintext) = match kind {
        CeremonyKind::WalletRegistration | CeremonyKind::WalletImport => {
            if challenges.len() < 2 {
                return Err("registration ceremony omitted a proof phase".into());
            }
            let attestation =
                authenticator.attestation_for(&challenges[0].canonical_bytes()?, origin, rp_id);
            let assertion = authenticator.assertion_for(
                &challenges[1].canonical_bytes()?,
                sign_count,
                origin,
                rp_id,
            );
            let credential_id = attestation.credential_id.clone();
            let plaintext = if kind == CeremonyKind::WalletImport {
                match (raw_private_key, mnemonic) {
                    (Some(_), Some(_)) => {
                        return Err(
                            "wallet_import accepts exactly one of --mnemonic-file or --raw-private-key"
                                .into(),
                        );
                    }
                    (Some(raw_private_key), None) => serde_jcs::to_vec(&serde_json::json!({
                        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
                        "raw_private_key": raw_private_key,
                    }))?,
                    (None, Some(mnemonic)) => serde_jcs::to_vec(&serde_json::json!({
                        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
                        "mnemonic": mnemonic,
                    }))?,
                    (None, None) => {
                        return Err(
                            "wallet_import requires --mnemonic-file or --raw-private-key".into(),
                        );
                    }
                }
            } else {
                authenticator.deterministic_prf().to_vec()
            };
            (
                WebAuthnCeremonyProof::Registration {
                    attestation,
                    prf_assertion: Some(assertion),
                },
                credential_id,
                plaintext,
            )
        }
        CeremonyKind::CredentialAdd | CeremonyKind::CredentialReplace => {
            if challenges.len() < 3 {
                return Err("credential-change ceremony omitted a proof phase".into());
            }
            let new_seed = new_seed.ok_or("credential change requires --new-authenticator-seed")?;
            let replacement = VirtualAuthenticator::from_seed(new_seed.as_bytes());
            let authority_assertion = authenticator.assertion_for(
                &challenges[0].canonical_bytes()?,
                sign_count,
                origin,
                rp_id,
            );
            let new_credential_attestation =
                replacement.attestation_for(&challenges[1].canonical_bytes()?, origin, rp_id);
            let new_credential_prf_assertion =
                replacement.assertion_for(&challenges[2].canonical_bytes()?, 1, origin, rp_id);
            let credential_id = new_credential_attestation.credential_id.clone();
            let plaintext = serde_jcs::to_vec(&serde_json::json!({
                "authority_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
                "new_credential_prf": Base64UrlBytes::from_bytes(&replacement.deterministic_prf()),
            }))?;
            (
                WebAuthnCeremonyProof::AuthorityCredentialChange {
                    authority_assertion,
                    new_credential_attestation,
                    new_credential_prf_assertion: Some(new_credential_prf_assertion),
                },
                credential_id,
                plaintext,
            )
        }
        CeremonyKind::WalletRecovery => {
            if challenges.len() < 2 {
                return Err("recovery ceremony omitted a proof phase".into());
            }
            let record = read_recovery_record(recovery_record_file.as_deref().unwrap())?;
            let replacement_seed =
                new_seed.ok_or("wallet recovery requires a new authenticator seed")?;
            if seed.as_deref() == Some(replacement_seed.as_str()) {
                return Err(
                    "replacement authenticator seed must differ from the prior seed".into(),
                );
            }
            let replacement = VirtualAuthenticator::from_seed(replacement_seed.as_bytes());
            let attestation =
                replacement.attestation_for(&challenges[0].canonical_bytes()?, origin, rp_id);
            let assertion =
                replacement.assertion_for(&challenges[1].canonical_bytes()?, 1, origin, rp_id);
            let credential_id = attestation.credential_id.clone();
            let plaintext = serde_jcs::to_vec(&serde_json::json!({
                "recovery_id": record.recovery_id,
                "recovery_secret": record.recovery_secret,
                "new_credential_prf": Base64UrlBytes::from_bytes(&replacement.deterministic_prf()),
            }))?;
            (
                WebAuthnCeremonyProof::RecoveryCredentialChange {
                    new_credential_attestation: attestation,
                    new_credential_prf_assertion: Some(assertion),
                },
                credential_id,
                plaintext,
            )
        }
        CeremonyKind::WalletDelete
        | CeremonyKind::KeyDerive
        | CeremonyKind::AccountAllocate
        | CeremonyKind::AccountRetire
        | CeremonyKind::PolicyUpdate
        | CeremonyKind::WalletExport
        | CeremonyKind::BackendEnrollment => {
            let assertion = authenticator.assertion_for(
                &challenges[0].canonical_bytes()?,
                sign_count,
                origin,
                rp_id,
            );
            let credential_id = assertion.credential_id.clone();
            let effect_kind = custody_effect_kind(kind)?;
            let plaintext = serde_jcs::to_vec(&serde_json::json!({
                "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
                "effect": {"kind": effect_kind},
            }))?;
            (
                WebAuthnCeremonyProof::Assertion { assertion },
                credential_id,
                plaintext,
            )
        }
        unsupported => {
            return Err(format!("debug driver does not complete {unsupported:?}").into());
        }
    };

    let aad = CustodyHpkeAad {
        surface: contribution.surface.clone(),
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: contribution.ceremony_kind,
        custody_operation_id: contribution.custody_operation_id.clone(),
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest()?,
        wallet_id: contribution.wallet_id.clone(),
        key_ref: contribution.key_ref.clone(),
        credential_id: Some(credential_id),
        expected_input_class: contribution.expected_input_class.clone(),
    }
    .canonical_bytes()?;
    let encrypted_input = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &plaintext,
    )?;
    let body = serde_json::to_vec(&serde_json::json!({
        "proof": proof,
        "encrypted_input": encrypted_input,
        "public_binding_digest": public_binding_digest,
    }))?;
    let result = client.complete(&contribution.ceremony_id, &body)?;
    if let (Some(recipient), Some(path)) = (output_recipient, browser_result_file) {
        let envelope: HpkeEnvelope =
            serde_json::from_value(result["encrypted_browser_result"].clone())?;
        let output_aad = CustodyOutputHpkeAad {
            surface: contribution.surface.clone(),
            ceremony_id: contribution.ceremony_id.clone(),
            ceremony_kind: contribution.ceremony_kind,
            custody_operation_id: contribution.custody_operation_id.clone(),
            signer_contribution_digest: contribution.digest()?,
            public_binding_digest,
        }
        .canonical_bytes()?;
        let plaintext =
            Zeroizing::new(recipient.open(&envelope, b"bloom-custody-output/v1", &output_aad)?);
        write_protected_result(&path, &plaintext)?;
        client.ack(&contribution.ceremony_id)?;
    }
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[cfg(unix)]
fn read_protected_seed_file(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err("authenticator seed path must be a regular file".into());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("authenticator seed file must not be accessible by group or other".into());
    }
    read_nonempty_seed(path)
}

#[cfg(not(unix))]
fn read_protected_seed_file(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    read_nonempty_seed(path)
}

fn read_nonempty_seed(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let seed = fs::read_to_string(path)?;
    let seed = seed.trim_end_matches(['\r', '\n']).to_owned();
    if seed.is_empty() {
        return Err("authenticator seed file is empty".into());
    }
    Ok(seed)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRecord {
    recovery_id: Token,
    recovery_secret: Base64UrlBytes,
}

fn read_recovery_record(path: &Path) -> Result<RecoveryRecord, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("recovery record must be a private regular file".into());
        }
    }
    let input = Zeroizing::new(fs::read(path)?);
    let record: RecoveryRecord = serde_json::from_slice(&input)?;
    if record.recovery_secret.decode().len() != 32 {
        return Err("recovery record has an invalid secret length".into());
    }
    Ok(record)
}

fn write_protected_result(path: &Path, plaintext: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Registration and recovery yield the same typed record. Validate before
    // creating the file so a malformed result never becomes a recovery token.
    let record: RecoveryRecord = serde_json::from_slice(plaintext)?;
    if record.recovery_secret.decode().len() != 32 {
        return Err("Signer returned an invalid recovery secret length".into());
    }
    let bytes = Zeroizing::new(serde_jcs::to_vec(&record)?);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

fn custody_effect_kind(kind: CeremonyKind) -> Result<serde_json::Value, serde_json::Error> {
    Ok(match kind {
        CeremonyKind::AccountAllocate => serde_json::json!("account_allocate"),
        CeremonyKind::AccountRetire => serde_json::json!("account_retire"),
        _ => serde_json::to_value(kind)?,
    })
}

fn assert_machine_secret_confinement_command(
    mut args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut signer_database: Option<PathBuf> = None;
    let mut authenticator_seed = None;
    let mut artifacts: Vec<PathBuf> = Vec::new();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--signer-db" => {
                signer_database = Some(args.next().ok_or("--signer-db requires a path")?.into());
            }
            "--authenticator-seed" => {
                authenticator_seed =
                    Some(args.next().ok_or("--authenticator-seed requires a value")?);
            }
            "--artifact" => {
                artifacts.push(args.next().ok_or("--artifact requires a path")?.into());
            }
            _ => return Err(format!("unknown artifact-scanner option: {flag}").into()),
        }
    }
    let signer_database = signer_database.ok_or("--signer-db is required")?;
    let authenticator_seed = authenticator_seed.ok_or("--authenticator-seed is required")?;
    let (file_count, byte_count) = artifact_scan::assert_machine_secret_confinement(
        &signer_database,
        authenticator_seed.as_bytes(),
        &artifacts,
    )?;
    println!(
        "MA-08 Machine secret-artifact confinement passed: scanned {file_count} stable files ({byte_count} bytes); deterministic credential PRF and verified-decryptable Signer key records were absent"
    );
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum CeremonyLaunch {
    Local { token: String },
    Remote { origin: String, capability: String },
}

fn parse_ceremony_url(value: &str) -> Result<CeremonyLaunch, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(value)?;
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.query().is_some() {
        return Err("ceremony URL contains unsupported authority or query data".into());
    }
    if parsed.scheme() == "http"
        && parsed.host_str() == Some("localhost")
        && parsed.port() == Some(18734)
    {
        let token = if parsed.path() == "/ceremony/" {
            parsed
                .fragment()
                .and_then(|fragment| fragment.strip_prefix("cap="))
                .ok_or("local ceremony URL has no launch capability")?
        } else if parsed.fragment().is_none() {
            parsed
                .path()
                .strip_prefix("/ceremony/")
                .ok_or("local ceremony URL has an invalid path")?
        } else {
            return Err("local ceremony URL has an invalid path or fragment".into());
        };
        validate_capability(token)?;
        return Ok(CeremonyLaunch::Local {
            token: token.to_owned(),
        });
    }
    if parsed.scheme() != "https"
        || parsed.port_or_known_default() != Some(443)
        || parsed.path() != "/ceremony/"
    {
        return Err("ceremony URL is not an approved Broker origin".into());
    }
    let hostname = parsed.host_str().ok_or("remote ceremony URL has no host")?;
    bloom_signer_api::SurfaceIdentity::remote(hostname, 0)?;
    let capability = parsed
        .fragment()
        .and_then(|fragment| fragment.strip_prefix("cap="))
        .ok_or("remote ceremony URL has no launch capability")?;
    validate_capability(capability)?;
    Ok(CeremonyLaunch::Remote {
        origin: format!("https://{hostname}"),
        capability: capability.to_owned(),
    })
}

fn validate_capability(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let capability = Base64UrlBytes::parse(value.to_owned())?;
    if value.len() != 43 || capability.decode().len() != 32 {
        return Err("ceremony URL has an invalid launch capability".into());
    }
    Ok(())
}

struct RemoteSession {
    agent: ureq::Agent,
    origin: String,
    hostname: String,
    ceremony_id: Digest32,
    cookie: String,
    csrf: String,
}

enum CeremonyClient {
    Local { token: String },
    Remote(RemoteSession),
}

impl CeremonyClient {
    fn connect(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        match parse_ceremony_url(url)? {
            CeremonyLaunch::Local { token } => Ok(Self::Local { token }),
            CeremonyLaunch::Remote { origin, capability } => {
                let hostname = origin
                    .strip_prefix("https://")
                    .ok_or("remote ceremony origin is malformed")?
                    .to_owned();
                let agent = ureq::Agent::config_builder()
                    .https_only(true)
                    .max_redirects(0)
                    .proxy(None)
                    .timeout_global(Some(Duration::from_secs(20)))
                    .http_status_as_error(false)
                    .tls_config(
                        ureq::tls::TlsConfig::builder()
                            .provider(ureq::tls::TlsProvider::Rustls)
                            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                            .build(),
                    )
                    .build()
                    .new_agent();
                let encoded = serde_json::to_vec(&serde_json::json!({
                    "capability": capability,
                }))?;
                let mut response = agent
                    .post(format!("{origin}/api/session/exchange"))
                    .header("origin", &origin)
                    .header("sec-fetch-site", "same-origin")
                    .header("content-type", "application/json")
                    .send(encoded.as_slice())?;
                let status = response.status().as_u16();
                let set_cookie = response.headers().get("set-cookie").cloned();
                let body = read_remote_body(&mut response)?;
                if status != 200 {
                    return Err(format!(
                        "Broker ceremony exchange failed with HTTP {status}: {}",
                        String::from_utf8_lossy(&body)
                    )
                    .into());
                }
                let set_cookie = set_cookie
                    .as_ref()
                    .and_then(|value| value.to_str().ok())
                    .ok_or("remote fragment exchange omitted its scoped cookie")?;
                let exchange: serde_json::Value = serde_json::from_slice(&body)?;
                let ceremony_id: Digest32 =
                    serde_json::from_value(exchange["ceremony_id"].clone())?;
                let csrf = exchange["csrf"]
                    .as_str()
                    .ok_or("remote fragment exchange omitted CSRF proof")?;
                validate_capability(csrf)?;
                let cookie = validate_remote_cookie(set_cookie, &ceremony_id)?;
                Ok(Self::Remote(RemoteSession {
                    agent,
                    origin,
                    hostname,
                    ceremony_id,
                    cookie,
                    csrf: csrf.to_owned(),
                }))
            }
        }
    }

    fn origin(&self) -> &str {
        match self {
            Self::Local { .. } => "http://localhost:18734",
            Self::Remote(session) => &session.origin,
        }
    }

    fn rp_id(&self) -> &str {
        match self {
            Self::Local { .. } => "localhost",
            Self::Remote(session) => &session.hostname,
        }
    }

    fn read_session(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        match self {
            Self::Local { token } => request_local("GET", "/api/session", token, None),
            Self::Remote(session) => session.request(
                "GET",
                &format!("/api/session/{}", session.ceremony_id),
                None,
            ),
        }
    }

    fn complete(
        &self,
        ceremony_id: &Digest32,
        body: &[u8],
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        match self {
            Self::Local { token } => request_local(
                "POST",
                &format!("/api/session/{ceremony_id}/complete"),
                token,
                Some(body),
            ),
            Self::Remote(session) => {
                if &session.ceremony_id != ceremony_id {
                    return Err("remote session identity differs from Signer contribution".into());
                }
                session.request(
                    "POST",
                    &format!("/api/session/{ceremony_id}/complete"),
                    Some(body),
                )
            }
        }
    }

    fn bind_output_key(
        &self,
        ceremony_id: &Digest32,
        recipient_key: &Base64UrlBytes,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let body = serde_json::to_vec(&serde_json::json!({"recipient_key": recipient_key}))?;
        self.post(ceremony_id, "output-key", &body)
    }

    fn ack(&self, ceremony_id: &Digest32) -> Result<(), Box<dyn std::error::Error>> {
        self.post(ceremony_id, "ack", b"{}")?;
        Ok(())
    }

    fn post(
        &self,
        ceremony_id: &Digest32,
        action: &str,
        body: &[u8],
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let path = format!("/api/session/{ceremony_id}/{action}");
        match self {
            Self::Local { token } => request_local("POST", &path, token, Some(body)),
            Self::Remote(session) => {
                if &session.ceremony_id != ceremony_id {
                    return Err("remote session identity differs from Signer contribution".into());
                }
                session.request("POST", &path, Some(body))
            }
        }
    }
}

impl RemoteSession {
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let url = format!("{}{path}", self.origin);
        let mut response = match (method, body) {
            ("GET", None) => self.agent.get(url).header("cookie", &self.cookie).call()?,
            ("POST", Some(body)) => self
                .agent
                .post(url)
                .header("cookie", &self.cookie)
                .header("origin", &self.origin)
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/json")
                .header("x-bloom-csrf", &self.csrf)
                .send(body)?,
            _ => return Err("unsupported remote ceremony request".into()),
        };
        let status = response.status().as_u16();
        let response_body = read_remote_body(&mut response)?;
        parse_ceremony_response(status, path, &response_body)
    }
}

fn read_remote_body(
    response: &mut ureq::http::Response<ureq::Body>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut body)?;
    if body.len() > 1024 * 1024 {
        return Err("Broker ceremony response exceeded 1 MiB".into());
    }
    Ok(body)
}

fn validate_remote_cookie(
    set_cookie: &str,
    ceremony_id: &Digest32,
) -> Result<String, Box<dyn std::error::Error>> {
    let pair = set_cookie
        .split(';')
        .next()
        .ok_or("remote ceremony cookie is malformed")?;
    let expected = format!("__Host-bloom-ceremony-{ceremony_id}=");
    let value = pair
        .strip_prefix(&expected)
        .ok_or("remote ceremony cookie has the wrong scope")?;
    validate_capability(value)?;
    for required in [
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=1500",
    ] {
        if !set_cookie
            .split(';')
            .map(str::trim)
            .any(|part| part == required)
        {
            return Err("remote ceremony cookie omitted a required security attribute".into());
        }
    }
    Ok(pair.to_owned())
}

fn request_local(
    method: &str,
    path: &str,
    token: &str,
    body: Option<&[u8]>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let body = body.unwrap_or_default();
    let mut stream = TcpStream::connect("127.0.0.1:18734")?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost:18734\r\nConnection: close\r\nX-Bloom-Ceremony-Token: {token}\r\n"
    )?;
    if method == "POST" {
        write!(
            stream,
            "Origin: http://localhost:18734\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("Broker returned a malformed HTTP response")?;
    let headers = std::str::from_utf8(&response[..split])?;
    let status: u16 = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Broker returned no HTTP status")?
        .parse()?;
    let response_body = &response[split + 4..];
    parse_ceremony_response(status, path, response_body)
}

fn parse_ceremony_response(
    status: u16,
    path: &str,
    body: &[u8],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if status == 204 && path.ends_with("/ack") && body.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    if status != 200 {
        return Err(format!(
            "Broker ceremony request failed with HTTP {status}: {}",
            String::from_utf8_lossy(body)
        )
        .into());
    }
    Ok(serde_json::from_slice(body)?)
}

#[cfg(test)]
mod tests {
    use super::{
        CeremonyKind, CeremonyLaunch, Digest32, custody_effect_kind, parse_ceremony_response,
        parse_ceremony_url, read_protected_seed_file, read_recovery_record, validate_remote_cookie,
        write_protected_result,
    };
    use std::{fs, path::PathBuf};

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "bloom-debug-driver-{name}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn private_output_ack_accepts_only_empty_204_ack_response() {
        let ack = "/api/session/example/ack";
        assert_eq!(
            parse_ceremony_response(204, ack, b"").unwrap(),
            serde_json::Value::Null
        );
        assert!(parse_ceremony_response(204, ack, b"unexpected").is_err());
        assert!(parse_ceremony_response(204, "/api/session/example/complete", b"").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_record_is_private_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = temp_path("recovery-result");
        let secret = bloom_signer_api::Base64UrlBytes::from_bytes(&[7; 32]);
        let record = serde_json::to_vec(&serde_json::json!({
            "recovery_id": "recovery-test",
            "recovery_secret": secret,
        }))
        .unwrap();
        write_protected_result(&path, &record).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(read_recovery_record(&path).unwrap().recovery_secret, secret);
        assert!(write_protected_result(&path, &record).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_recovery_record(&path).is_err());
        fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn protected_seed_file_rejects_group_readable_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = temp_path("permissions");
        fs::write(&path, "secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let error = read_protected_seed_file(&path).unwrap_err();
        fs::remove_file(&path).unwrap();
        assert!(error.to_string().contains("group or other"));
    }

    #[cfg(unix)]
    #[test]
    fn protected_seed_file_reads_mode_0600_and_trims_newline() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = temp_path("success");
        fs::write(&path, "secret\r\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_protected_seed_file(&path).unwrap(), "secret");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn account_custody_effects_match_the_signer_contract() {
        assert_eq!(
            custody_effect_kind(CeremonyKind::AccountAllocate).unwrap(),
            serde_json::json!("account_allocate")
        );
        assert_eq!(
            custody_effect_kind(CeremonyKind::AccountRetire).unwrap(),
            serde_json::json!("account_retire")
        );
    }

    #[test]
    fn ceremony_urls_accept_only_canonical_local_or_assigned_remote_launches() {
        let capability = "A".repeat(43);
        assert_eq!(
            parse_ceremony_url(&format!("http://localhost:18734/ceremony/{capability}")).unwrap(),
            CeremonyLaunch::Local {
                token: capability.clone()
            }
        );
        assert_eq!(
            parse_ceremony_url(&format!(
                "http://localhost:18734/ceremony/#cap={capability}"
            ))
            .unwrap(),
            CeremonyLaunch::Local {
                token: capability.clone()
            }
        );
        let hostname = "5ixwab6amyu7e42fjobm3myxqe.relay.bloom.directory";
        assert_eq!(
            parse_ceremony_url(&format!("https://{hostname}/ceremony/#cap={capability}")).unwrap(),
            CeremonyLaunch::Remote {
                origin: format!("https://{hostname}"),
                capability: capability.clone()
            }
        );
        for invalid in [
            format!("https://{hostname}/#cap={capability}"),
            format!("http://{hostname}/#cap={capability}"),
            format!("https://other.example/ceremony/#cap={capability}"),
            format!("https://{hostname}/ceremony/{capability}"),
            format!("https://{hostname}/ceremony/#cap={capability}&extra=1"),
            format!("https://user@{hostname}/ceremony/#cap={capability}"),
        ] {
            assert!(parse_ceremony_url(&invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn remote_cookie_must_be_exactly_scoped_and_hardened() {
        let ceremony_id = Digest32::from_bytes([0x42; 32]);
        let value = "A".repeat(43);
        let valid = format!(
            "__Host-bloom-ceremony-{ceremony_id}={value}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=1500"
        );
        assert_eq!(
            validate_remote_cookie(&valid, &ceremony_id).unwrap(),
            format!("__Host-bloom-ceremony-{ceremony_id}={value}")
        );

        for invalid in [
            valid.replace("__Host-bloom-ceremony-", "bloom-ceremony-"),
            valid.replace("; Secure", ""),
            valid.replace("SameSite=Strict", "SameSite=Lax"),
            valid.replace("Max-Age=1500", "Max-Age=1501"),
        ] {
            assert!(validate_remote_cookie(&invalid, &ceremony_id).is_err());
        }
    }
}
