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
        .ok_or("usage: bloom-broker-debug-driver complete URL (--authenticator-seed-file PATH | SEED) [options] | assert-machine-secret-confinement --signer-db PATH --authenticator-seed SEED --artifact PATH [...]")?;
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
            "--sign-count" => {
                sign_count = args
                    .next()
                    .ok_or("--sign-count requires a value")?
                    .parse()?;
            }
            _ => return Err(format!("unknown debug-driver option: {flag}").into()),
        }
    }

    let token = ceremony_token(&url)?;
    let session = request("GET", "/api/session", token, None)?;
    let kind: CeremonyKind = serde_json::from_value(session["ceremony_kind"].clone())?;
    let challenges = session["challenges"]
        .as_array()
        .ok_or("ceremony session omitted challenges")?
        .iter()
        .map(|challenge| serde_json::from_value::<CeremonyChallenge>(challenge["binding"].clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let public_binding_digest: Digest32 =
        serde_json::from_value(session["challenges"][0]["binding"]["exact_terms_digest"].clone())?;
    let authenticator = VirtualAuthenticator::from_seed(seed.as_bytes());

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
            token,
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
                let raw_private_key =
                    raw_private_key.ok_or("wallet_import requires --raw-private-key")?;
                serde_jcs::to_vec(&serde_json::json!({
                    "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
                    "raw_private_key": raw_private_key,
                }))?
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
        | CeremonyKind::PolicyUpdate
        | CeremonyKind::WalletExport
        | CeremonyKind::BackendEnrollment => {
            let assertion = authenticator.assertion(&challenges[0].canonical_bytes()?, sign_count);
            let credential_id = assertion.credential_id.clone();
            let plaintext = serde_jcs::to_vec(&serde_json::json!({
                "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
                "effect": {"kind": kind},
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
        token,
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

fn ceremony_token(url: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let prefix = "http://localhost:18734/ceremony/";
    let token = url
        .strip_prefix(prefix)
        .ok_or("ceremony URL is not the canonical Broker origin")?;
    if token.len() != 43 || token.contains('/') {
        return Err("ceremony URL has an invalid session token".into());
    }
    Ok(token)
}

fn request(
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
    use super::read_protected_seed_file;
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
}
