use std::{
    env, fs,
    io::{Read as _, Write as _},
    net::TcpStream,
    path::PathBuf,
};

use bloom_broker_debug_driver::{VirtualAuthenticator, seal_hpke};
use bloom_signer_api::{
    Base64UrlBytes, CeremonyChallenge, CeremonyKind, CustodyHpkeAad, CustodySignerContribution,
    Digest32, LocalPrfHpkeAad, SignerCeremonyContribution, WebAuthnCeremonyProof,
};

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
    let seed_arg = args
        .next()
        .ok_or("complete requires an authenticator seed")?;
    let seed = if seed_arg == "--authenticator-seed-file" {
        let path = PathBuf::from(
            args.next()
                .ok_or("--authenticator-seed-file requires a path")?,
        );
        read_protected_seed_file(&path)?
    } else {
        seed_arg
    };
    let mut new_seed = None;
    let mut raw_private_key = None;
    let mut mnemonic = None;
    let mut sign_count = 1_u32;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--new-authenticator-seed" => {
                new_seed = Some(
                    args.next()
                        .ok_or("--new-authenticator-seed requires a value")?,
                );
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
            _ => return Err(format!("unknown debug-driver option: {flag}").into()),
        }
    }

    let target = parse_ceremony_url(&url)?;
    let session = request("GET", "/api/session", &target, None)?;
    let kind: CeremonyKind = serde_json::from_value(session["ceremony_kind"].clone())?;
    let challenges = session["challenges"]
        .as_array()
        .ok_or("ceremony session omitted challenges")?
        .iter()
        .map(|challenge| serde_json::from_value::<CeremonyChallenge>(challenge["binding"].clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let public_binding_digest: Digest32 =
        serde_json::from_value(session["challenges"][0]["binding"]["exact_terms_digest"].clone())?;
    let authenticator =
        VirtualAuthenticator::from_seed_with_origin(seed.as_bytes(), &target.origin);

    if kind == CeremonyKind::SealedApproval {
        let contribution: SignerCeremonyContribution =
            serde_json::from_value(session["signer_contribution"].clone())?;
        let assertion = authenticator.assertion(&challenges[0].canonical_bytes()?, sign_count);
        let aad = LocalPrfHpkeAad {
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
        let result = request(
            "POST",
            &format!("/api/session/{}/complete", contribution.ceremony_id),
            &target,
            Some(&body),
        )?;
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
            let attestation = authenticator.attestation(&challenges[0].canonical_bytes()?);
            let assertion = authenticator.assertion(&challenges[1].canonical_bytes()?, sign_count);
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
            let replacement =
                VirtualAuthenticator::from_seed_with_origin(new_seed.as_bytes(), &target.origin);
            let authority_assertion =
                authenticator.assertion(&challenges[0].canonical_bytes()?, sign_count);
            let new_credential_attestation =
                replacement.attestation(&challenges[1].canonical_bytes()?);
            let new_credential_prf_assertion =
                replacement.assertion(&challenges[2].canonical_bytes()?, 1);
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
        CeremonyKind::WalletDelete
        | CeremonyKind::KeyDerive
        | CeremonyKind::AccountAllocate
        | CeremonyKind::AccountRetire
        | CeremonyKind::PolicyUpdate
        | CeremonyKind::WalletExport
        | CeremonyKind::BackendEnrollment => {
            let assertion = authenticator.assertion(&challenges[0].canonical_bytes()?, sign_count);
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
    let result = request(
        "POST",
        &format!("/api/session/{}/complete", contribution.ceremony_id),
        &target,
        Some(&body),
    )?;
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

struct CeremonyTarget {
    port: u16,
    host: String,
    origin: String,
    token: String,
}

fn parse_ceremony_url(url: &str) -> Result<CeremonyTarget, Box<dyn std::error::Error>> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("ceremony URL is not a canonical local Broker origin")?;
    let (authority, path) = rest
        .split_once('/')
        .ok_or("ceremony URL is not a canonical local Broker origin")?;
    if authority.contains('@') {
        return Err("ceremony URL must not carry credentials".into());
    }
    let port = match authority.split_once(':') {
        Some((name, port_text)) => {
            if name != "localhost" {
                return Err("ceremony URL is not a canonical local Broker origin".into());
            }
            let port: u32 = port_text
                .parse()
                .map_err(|_| "ceremony URL has a malformed port")?;
            if port == 0 || port > u32::from(u16::MAX) {
                return Err("ceremony URL has a malformed port".into());
            }
            port as u16
        }
        None => {
            if authority != "localhost" {
                return Err("ceremony URL is not a canonical local Broker origin".into());
            }
            80
        }
    };
    let token = path
        .strip_prefix("ceremony/")
        .ok_or("ceremony URL is not a canonical local Broker origin")?;
    if token.is_empty()
        || token.contains('/')
        || token.contains('?')
        || token.contains('#')
        || path.contains('?')
        || path.contains('#')
        || url.contains('?')
        || url.contains('#')
    {
        return Err("ceremony URL has an invalid session token".into());
    }
    // The token is interpolated into an HTTP header, so it must be a
    // canonical unpadded base64url encoding of exactly the 32 session-token
    // bytes: this rejects control characters (including CR/LF injection)
    // and any other non-alphabet input before a request is constructed.
    let parsed =
        Base64UrlBytes::parse(token).map_err(|_| "ceremony URL has an invalid session token")?;
    if parsed.decode().len() != 32 {
        return Err("ceremony URL has an invalid session token".into());
    }
    let origin = format!("http://{}", {
        if port == 80 {
            "localhost".to_owned()
        } else {
            format!("localhost:{port}")
        }
    });
    Ok(CeremonyTarget {
        port,
        host: if port == 80 {
            "localhost".to_owned()
        } else {
            format!("localhost:{port}")
        },
        origin,
        token: token.to_owned(),
    })
}

fn request(
    method: &str,
    path: &str,
    target: &CeremonyTarget,
    body: Option<&[u8]>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let body = body.unwrap_or_default();
    let mut stream = TcpStream::connect(("127.0.0.1", target.port))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nX-Bloom-Ceremony-Token: {}\r\n",
        target.host, target.token
    )?;
    if method == "POST" {
        write!(
            stream,
            "Origin: {}\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            target.origin,
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
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Broker returned no HTTP status")?;
    let response_body = &response[split + 4..];
    if status != "200" {
        return Err(format!(
            "Broker ceremony request failed with HTTP {status}: {}",
            String::from_utf8_lossy(response_body)
        )
        .into());
    }
    Ok(serde_json::from_slice(response_body)?)
}

#[cfg(test)]
mod tests {
    use super::{
        Base64UrlBytes, CeremonyKind, custody_effect_kind, parse_ceremony_url,
        read_protected_seed_file,
    };
    use std::{fs, path::PathBuf};

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "bloom-debug-driver-{name}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
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
    fn ceremony_url_parsing_accepts_canonical_local_origins() {
        // A genuinely encoded 32-byte session token, not a repeated letter.
        let token = Base64UrlBytes::from_bytes(&[7u8; 32]).encoded().to_owned();
        assert_eq!(token.len(), 43);
        let target =
            parse_ceremony_url(&format!("http://localhost:28735/ceremony/{token}")).unwrap();
        assert_eq!(target.port, 28_735);
        assert_eq!(target.host, "localhost:28735");
        assert_eq!(target.origin, "http://localhost:28735");
        assert_eq!(target.token, token);
        let default =
            parse_ceremony_url(&format!("http://localhost:18734/ceremony/{token}")).unwrap();
        assert_eq!(default.port, 18_734);
        // Port 80 serializes bare, as browsers do.
        let bare = parse_ceremony_url(&format!("http://localhost/ceremony/{token}")).unwrap();
        assert_eq!(bare.port, 80);
        assert_eq!(bare.host, "localhost");
        assert_eq!(bare.origin, "http://localhost");
    }

    #[test]
    fn ceremony_url_parsing_rejects_remote_or_malformed_urls() {
        let token = Base64UrlBytes::from_bytes(&[7u8; 32]).encoded().to_owned();
        // Tokens that fail canonical base64url validation: non-alphabet
        // bytes, CR/LF header injection, padding, wrong byte length, and
        // noncanonical trailing bits.
        let bad_tokens = [
            "!".repeat(43),
            "a".repeat(35) + "\r\nX: y\r\n",
            format!("{}=", &token[..42]),
            Base64UrlBytes::from_bytes(&[7u8; 31]).encoded().to_owned(),
            "b".repeat(43),
        ];
        for url in [
            format!("http://127.0.0.1:28735/ceremony/{token}"),
            format!("http://[::1]:28735/ceremony/{token}"),
            format!("http://attacker.invalid:28735/ceremony/{token}"),
            format!("https://localhost:28735/ceremony/{token}"),
            format!("http://user@localhost:28735/ceremony/{token}"),
            format!("http://localhost:28735/ceremony/{token}?x=1"),
            format!("http://localhost:28735/ceremony/{token}#f"),
            format!("http://localhost:0/ceremony/{token}"),
            format!("http://localhost:99999/ceremony/{token}"),
            format!("http://localhost:abc/ceremony/{token}"),
            "http://localhost:28735/ceremony/short".to_owned(),
            "http://localhost:28735/other/".to_owned() + &token,
        ]
        .into_iter()
        .chain(
            bad_tokens
                .iter()
                .map(|bad| format!("http://localhost:28735/ceremony/{bad}")),
        ) {
            assert!(parse_ceremony_url(&url).is_err(), "must reject {url}");
        }
    }
}
