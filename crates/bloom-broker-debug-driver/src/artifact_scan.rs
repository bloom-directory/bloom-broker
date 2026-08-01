//! Test-only MA-08 artifact scanner.
//!
//! This module deliberately lives in the debug driver, which production
//! bundle gates reject.  It proves that at least one Signer-local encrypted
//! wallet record is actually decryptable through the deterministic
//! credential's PRF -> credential wrap -> WKEK -> backend-key chain,
//! then searches Machine-owned artifacts for that record and for the PRF.  It
//! never prints or writes either the decrypted root or the encrypted record.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use bip32::{DerivationPath, XPrv};
use bloom_broker_api::{Base64UrlBytes, DerivationRef, KeyRef};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use hkdf::Hkdf;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const ROOT_AAD_DOMAIN: &[u8] = b"bloom-local-root-wrap/v1";
const CREDENTIAL_WRAP_INFO: &[u8] = b"bloom-passkey-wallet-wrap/v1";
const LOCAL_BACKEND_WRAP_INFO: &[u8] = b"bloom-local-backend-wrap/v1";
const SCAN_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    backend: String,
    backend_instance: String,
    encrypted_record: Base64UrlBytes,
    #[allow(dead_code)]
    pinned_keys: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct EncryptedLocalBackup {
    root_key_id: String,
    #[serde(default = "default_root_material_kind")]
    root_material_kind: String,
    wrap_format_version: u32,
    nonce: Base64UrlBytes,
    encrypted_seed: Base64UrlBytes,
    #[serde(default)]
    derivation_registry: Vec<KeyRef>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EncryptedBlob {
    nonce: Base64UrlBytes,
    ciphertext: Base64UrlBytes,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialWrap {
    credential_id: Base64UrlBytes,
    active: bool,
    wrap_format_version: u32,
    wrapped_wkek: EncryptedBlob,
}

#[derive(Debug, Deserialize)]
struct WalletCustodyBackup {
    wallet_id: String,
    encrypted_root: EncryptedBlob,
    credential_wraps: Vec<CredentialWrap>,
}

fn default_root_material_kind() -> String {
    "bip32_seed".to_owned()
}

#[derive(Clone)]
struct Needle {
    description: &'static str,
    bytes: Zeroizing<Vec<u8>>,
}

pub(crate) fn assert_machine_secret_confinement(
    signer_database: &Path,
    authenticator_seed: &[u8],
    artifact_roots: &[PathBuf],
) -> Result<(usize, u64), Box<dyn std::error::Error>> {
    if artifact_roots.is_empty() {
        return Err("at least one --artifact path is required".into());
    }
    let authenticator = crate::VirtualAuthenticator::from_seed(authenticator_seed);
    let prf = Zeroizing::new(authenticator.deterministic_prf());
    let encrypted_needles =
        verified_decryptable_record_needles(signer_database, &prf, authenticator.credential_id())?;

    let mut needles = vec![
        Needle {
            description: "raw deterministic credential PRF",
            bytes: Zeroizing::new(prf.to_vec()),
        },
        Needle {
            description: "hex deterministic credential PRF",
            bytes: Zeroizing::new(hex::encode(prf.as_slice()).into_bytes()),
        },
        Needle {
            description: "uppercase hex deterministic credential PRF",
            bytes: Zeroizing::new(hex::encode_upper(prf.as_slice()).into_bytes()),
        },
        Needle {
            description: "base64url deterministic credential PRF",
            bytes: Zeroizing::new(
                json_string(&Base64UrlBytes::from_bytes(prf.as_slice()))?.into_bytes(),
            ),
        },
    ];
    needles.extend(encrypted_needles);
    needles.retain(|needle| needle.bytes.len() >= 16);

    let files = artifact_files(artifact_roots)?;
    if files.is_empty() {
        return Err("artifact roots did not contain a regular file".into());
    }
    let mut scanned_bytes = 0_u64;
    for path in &files {
        scanned_bytes = scanned_bytes.saturating_add(scan_file(path, &needles)?);
    }
    Ok((files.len(), scanned_bytes))
}

fn verified_decryptable_record_needles(
    signer_database: &Path,
    prf: &[u8; 32],
    credential_id: &Base64UrlBytes,
) -> Result<Vec<Needle>, Box<dyn std::error::Error>> {
    let connection = Connection::open_with_flags(
        signer_database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    let mut statement = connection.prepare(
        "SELECT enrollment_jcs FROM ceremony_backend_enrollments ORDER BY backend_instance",
    )?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let scoped_fingerprints = connection
        .prepare("SELECT key_fingerprint FROM petal_key_scopes ORDER BY key_fingerprint")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    if scoped_fingerprints.is_empty() {
        return Err("Signer database contains no persisted Petal-scoped child".into());
    }
    let mut decryptable = Vec::new();
    let mut child_count = 0_usize;
    for enrollment_jcs in rows {
        let enrollment: Enrollment = serde_json::from_str(&enrollment_jcs)?;
        if enrollment.backend != "local" {
            continue;
        }
        let record = enrollment.encrypted_record.decode();
        let backup: EncryptedLocalBackup = serde_json::from_slice(&record)?;
        let contains_scoped_child = backup
            .derivation_registry
            .iter()
            .any(|key_ref| scoped_fingerprints.contains(key_ref.public_key_fingerprint.as_str()));
        if !contains_scoped_child {
            continue;
        }
        let custody_jcs: String = connection.query_row(
            "SELECT custody_jcs FROM ceremony_wallets WHERE wallet_id = ?1",
            [&enrollment.backend_instance],
            |row| row.get(0),
        )?;
        let custody: WalletCustodyBackup = serde_json::from_str(&custody_jcs)?;
        if custody.wallet_id != enrollment.backend_instance {
            return Err("Signer wallet custody/backend enrollment identity mismatch".into());
        }
        let credential_wrap = custody
            .credential_wraps
            .iter()
            .find(|wrap| wrap.active && &wrap.credential_id == credential_id)
            .ok_or("deterministic credential has no active Signer wallet wrap")?;
        let credential_key = credential_wrap_key(prf, &custody.wallet_id, credential_id)?;
        let root_fingerprint =
            hex::encode(Sha256::digest(custody.encrypted_root.ciphertext.decode()));
        let credential_aad = serde_jcs::to_vec(&CredentialWrapAad {
            wallet_id: &custody.wallet_id,
            credential_id,
            root_ciphertext_fingerprint: &root_fingerprint,
            wrap_format_version: credential_wrap.wrap_format_version,
        })?;
        let wrap_nonce: [u8; 24] = credential_wrap
            .wrapped_wkek
            .nonce
            .decode()
            .try_into()
            .map_err(|_| "Signer credential wrap contains a malformed nonce")?;
        let wkek = Zeroizing::new(
            XChaCha20Poly1305::new(Key::from_slice(&credential_key))
                .decrypt(
                    XNonce::from_slice(&wrap_nonce),
                    Payload {
                        msg: &credential_wrap.wrapped_wkek.ciphertext.decode(),
                        aad: &credential_aad,
                    },
                )
                .map_err(|_| "deterministic credential PRF did not unwrap Signer WKEK")?,
        );
        let backend_key = local_backend_key(&wkek, &custody.wallet_id)?;
        if backup.wrap_format_version != 1 || backup.nonce.decode().len() != 24 {
            continue;
        }
        let mut aad = ROOT_AAD_DOMAIN.to_vec();
        aad.extend_from_slice(enrollment.backend_instance.as_bytes());
        aad.extend_from_slice(backup.root_key_id.as_bytes());
        aad.extend_from_slice(&backup.wrap_format_version.to_be_bytes());
        let nonce: [u8; 24] = backup
            .nonce
            .decode()
            .try_into()
            .map_err(|_| "Signer local-backend encrypted record contains a malformed nonce")?;
        let plaintext = XChaCha20Poly1305::new(Key::from_slice(&backend_key)).decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &backup.encrypted_seed.decode(),
                aad: &aad,
            },
        );
        let Ok(plaintext) = plaintext else {
            continue;
        };
        let plaintext = Zeroizing::new(plaintext);
        // Local root material is either a BIP-32 seed (16..=64 bytes) or a
        // secp256k1 scalar (32 bytes).  Authentication plus this structural
        // check makes the negative scan depend on a real decryptable key blob,
        // not an arbitrary ciphertext-shaped fixture.
        if !(16..=64).contains(&plaintext.len()) {
            continue;
        }
        if backup.root_material_kind != "bip32_seed" {
            if backup.derivation_registry.iter().any(|key_ref| {
                scoped_fingerprints.contains(key_ref.public_key_fingerprint.as_str())
            }) {
                return Err(
                    "persisted Petal child is bound to a non-derivable scalar root record".into(),
                );
            }
            continue;
        }
        for key_ref in &backup.derivation_registry {
            if !scoped_fingerprints.contains(key_ref.public_key_fingerprint.as_str()) {
                continue;
            }
            let Some(DerivationRef::Bip32Secp256k1 { path, .. }) = &key_ref.derivation else {
                return Err("persisted Petal child lacks a BIP-32 derivation binding".into());
            };
            let path = DerivationPath::from_str(path)?;
            let child = XPrv::derive_from_path(plaintext.as_slice(), &path)?;
            let signing_key = k256::ecdsa::SigningKey::from(child);
            let public_key = k256::PublicKey::from_sec1_bytes(
                signing_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            )?;
            let spki = k256::pkcs8::EncodePublicKey::to_public_key_der(&public_key)?;
            let derived_fingerprint = hex::encode(Sha256::digest(spki.as_bytes()));
            if derived_fingerprint != key_ref.public_key_fingerprint.as_str() {
                return Err(
                    "derived Petal child public fingerprint does not match its persisted KeyRef"
                        .into(),
                );
            }
            let child_secret = Zeroizing::new(signing_key.to_bytes().to_vec());
            decryptable.extend(secret_needles(
                "actual persisted Petal scoped-child private key",
                child_secret.as_slice(),
            )?);
            child_count += 1;
        }
        decryptable.push(Needle {
            description: "complete decryptable Signer local-key record",
            bytes: Zeroizing::new(record),
        });
        decryptable.push(Needle {
            description: "base64url decryptable Signer local-key record",
            bytes: Zeroizing::new(json_string(&enrollment.encrypted_record)?.into_bytes()),
        });
        decryptable.push(Needle {
            description: "decryptable Signer local-key ciphertext",
            bytes: Zeroizing::new(backup.encrypted_seed.decode()),
        });
        decryptable.push(Needle {
            description: "base64url decryptable Signer local-key ciphertext",
            bytes: Zeroizing::new(json_string(&backup.encrypted_seed)?.into_bytes()),
        });
        let credential_wrap_jcs = serde_jcs::to_vec(credential_wrap)?;
        decryptable.push(Needle {
            description: "complete Signer credential WKEK wrap",
            bytes: Zeroizing::new(credential_wrap_jcs),
        });
        decryptable.push(Needle {
            description: "raw Signer wrapped-WKEK ciphertext",
            bytes: Zeroizing::new(credential_wrap.wrapped_wkek.ciphertext.decode()),
        });
        decryptable.push(Needle {
            description: "base64url Signer wrapped-WKEK ciphertext",
            bytes: Zeroizing::new(
                json_string(&credential_wrap.wrapped_wkek.ciphertext)?.into_bytes(),
            ),
        });
        decryptable.push(Needle {
            description: "complete Signer wallet custody record",
            bytes: Zeroizing::new(custody_jcs.into_bytes()),
        });
    }
    if decryptable.is_empty() {
        return Err(
            "no Signer local-key record was decryptable through the deterministic credential WKEK chain"
                .into(),
        );
    }
    if child_count == 0 {
        return Err(
            "no actual Petal scoped-child private key could be derived from the verified Signer record"
                .into(),
        );
    }
    Ok(decryptable)
}

#[derive(Serialize)]
struct CredentialWrapAad<'a> {
    wallet_id: &'a str,
    credential_id: &'a Base64UrlBytes,
    root_ciphertext_fingerprint: &'a str,
    wrap_format_version: u32,
}

fn credential_wrap_key(
    prf: &[u8; 32],
    wallet_id: &str,
    credential_id: &Base64UrlBytes,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    #[derive(Serialize)]
    struct Salt<'a> {
        wallet_id: &'a str,
        credential_id: &'a Base64UrlBytes,
    }
    let salt: [u8; 32] = Sha256::digest(serde_jcs::to_vec(&Salt {
        wallet_id,
        credential_id,
    })?)
    .into();
    let mut key = Zeroizing::new(vec![0_u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), prf)
        .expand(CREDENTIAL_WRAP_INFO, key.as_mut_slice())
        .map_err(|_| "credential wrap-key derivation failed")?;
    Ok(key)
}

fn local_backend_key(
    wkek: &[u8],
    wallet_id: &str,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let salt: [u8; 32] = Sha256::digest(wallet_id.as_bytes()).into();
    let mut key = Zeroizing::new(vec![0_u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), wkek)
        .expand(LOCAL_BACKEND_WRAP_INFO, key.as_mut_slice())
        .map_err(|_| "local backend wrap-key derivation failed")?;
    Ok(key)
}

fn secret_needles(
    description: &'static str,
    secret: &[u8],
) -> Result<Vec<Needle>, serde_json::Error> {
    Ok(vec![
        Needle {
            description,
            bytes: Zeroizing::new(secret.to_vec()),
        },
        Needle {
            description,
            bytes: Zeroizing::new(hex::encode(secret).into_bytes()),
        },
        Needle {
            description,
            bytes: Zeroizing::new(hex::encode_upper(secret).into_bytes()),
        },
        Needle {
            description,
            bytes: Zeroizing::new(json_string(&Base64UrlBytes::from_bytes(secret))?.into_bytes()),
        },
    ])
}

fn json_string(value: &Base64UrlBytes) -> Result<String, serde_json::Error> {
    serde_json::to_string(value).map(|encoded| encoded.trim_matches('"').to_owned())
}

fn artifact_files(roots: &[PathBuf]) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut pending = roots.to_vec();
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing to skip or follow artifact symlink: {}",
                path.display()
            )
            .into());
        }
        if metadata.is_file() {
            files.push(path);
        } else if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else {
            return Err(format!("unsupported artifact type: {}", path.display()).into());
        }
    }
    files.sort();
    Ok(files)
}

fn scan_file(path: &Path, needles: &[Needle]) -> Result<u64, Box<dyn std::error::Error>> {
    let maximum_needle = needles
        .iter()
        .map(|needle| needle.bytes.len())
        .max()
        .unwrap_or(0);
    let overlap = maximum_needle.saturating_sub(1);
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    let path_before = fs::symlink_metadata(path)?;
    if before.dev() != path_before.dev() || before.ino() != path_before.ino() {
        return Err(format!(
            "artifact path changed while being opened: {}",
            path.display()
        )
        .into());
    }
    let length = before.len();
    let mut offset = 0_u64;
    let mut retained = Vec::new();
    loop {
        let mut next = vec![0_u8; SCAN_CHUNK_BYTES];
        let read = file.read(&mut next)?;
        if read == 0 {
            break;
        }
        next.truncate(read);
        retained.extend_from_slice(&next);
        for needle in needles {
            if memchr::memmem::find(&retained, needle.bytes.as_slice()).is_some() {
                return Err(format!(
                    "MA-08 secret confinement failure: {} found in {}",
                    needle.description,
                    path.display()
                )
                .into());
            }
        }
        if retained.len() > overlap {
            let keep_from = retained.len() - overlap;
            retained.drain(..keep_from);
        }
        offset = offset.saturating_add(read as u64);
    }
    // Defend against replacement and same-length rewrite races as well as
    // truncation: compare the opened object and current path identity plus
    // size, mtime, and ctime before/after the streaming scan.
    let after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    let stable = offset == length
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && after.dev() == path_after.dev()
        && after.ino() == path_after.ino();
    if !stable {
        return Err(format!("artifact changed while being scanned: {}", path.display()).into());
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> (PathBuf, PathBuf, Vec<u8>, Vec<u8>, Vec<u8>, String) {
        let root = std::env::temp_dir().join(format!(
            "bloom-ma08-scanner-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let database = root.join("signer.db");
        let artifact = root.join("machine.core");
        fs::write(&artifact, b"public machine diagnostic only").unwrap();
        let seed = "ma08-scanner-auth".to_owned();
        let authenticator = crate::VirtualAuthenticator::from_seed(seed.as_bytes());
        let prf = authenticator.deterministic_prf();
        let credential_id = authenticator.credential_id().clone();
        let backend_instance = "wallet-ma08";
        let root_key_id = "wallet-root";
        let nonce = [0x23; 24];
        let wrap_nonce = [0x24; 24];
        let wkek = [0x31; 32];
        let encrypted_root = EncryptedBlob {
            nonce: Base64UrlBytes::from_bytes(&[0x25; 24]),
            ciphertext: Base64UrlBytes::from_bytes(&[0x26; 48]),
        };
        let root_fingerprint = hex::encode(Sha256::digest(encrypted_root.ciphertext.decode()));
        let credential_key = credential_wrap_key(&prf, backend_instance, &credential_id).unwrap();
        let credential_aad = serde_jcs::to_vec(&CredentialWrapAad {
            wallet_id: backend_instance,
            credential_id: &credential_id,
            root_ciphertext_fingerprint: &root_fingerprint,
            wrap_format_version: 1,
        })
        .unwrap();
        let wrapped_wkek = XChaCha20Poly1305::new(Key::from_slice(&credential_key))
            .encrypt(
                XNonce::from_slice(&wrap_nonce),
                Payload {
                    msg: &wkek,
                    aad: &credential_aad,
                },
            )
            .unwrap();
        let backend_key = local_backend_key(&wkek, backend_instance).unwrap();
        let root_seed = [0x42; 32];
        let child_path = "m/2147483647'/0'";
        let child_signing_key = k256::ecdsa::SigningKey::from(
            XPrv::derive_from_path(root_seed, &DerivationPath::from_str(child_path).unwrap())
                .unwrap(),
        );
        let child_secret = child_signing_key.to_bytes().to_vec();
        let child_public = k256::PublicKey::from_sec1_bytes(
            child_signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();
        let child_spki = k256::pkcs8::EncodePublicKey::to_public_key_der(&child_public).unwrap();
        let child_fingerprint = hex::encode(Sha256::digest(child_spki.as_bytes()));
        let child_ref = serde_json::json!({
            "backend": "local",
            "backend_instance": backend_instance,
            "locator": child_path,
            "key_spec": "secp256k1",
            "public_key_fingerprint": child_fingerprint,
            "derivation": {
                "scheme": "bip32-secp256k1",
                "root_key_id": root_key_id,
                "path": child_path
            }
        });
        let mut aad = ROOT_AAD_DOMAIN.to_vec();
        aad.extend_from_slice(backend_instance.as_bytes());
        aad.extend_from_slice(root_key_id.as_bytes());
        aad.extend_from_slice(&1_u32.to_be_bytes());
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&backend_key))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &root_seed,
                    aad: &aad,
                },
            )
            .unwrap();
        let record = serde_json::json!({
            "root_key_id": root_key_id,
            "root_material_kind": "bip32_seed",
            "pinned_root": null,
            "wrap_format_version": 1,
            "nonce": Base64UrlBytes::from_bytes(&nonce),
            "encrypted_seed": Base64UrlBytes::from_bytes(&ciphertext),
            "authority_verifying_key": Base64UrlBytes::from_bytes(&[0x11; 32]),
            "public_descriptions": [],
            "derivation_registry": [child_ref],
            "derivation_namespaces": [],
            "derivation_tombstones": [],
            "pending_derivations": {}
        });
        let record_bytes = serde_jcs::to_vec(&record).unwrap();
        let enrollment = serde_json::json!({
            "backend": "local",
            "backend_instance": backend_instance,
            "encrypted_record": Base64UrlBytes::from_bytes(&record_bytes),
            "pinned_keys": []
        });
        let mut unrelated_record = record.clone();
        unrelated_record["derivation_registry"] = serde_json::json!([]);
        let unrelated_enrollment = serde_json::json!({
            "backend": "local",
            "backend_instance": "wallet-unrelated",
            "encrypted_record": Base64UrlBytes::from_bytes(
                &serde_jcs::to_vec(&unrelated_record).unwrap()
            ),
            "pinned_keys": []
        });
        let custody = serde_json::json!({
            "wallet_id": backend_instance,
            "policy_version": 0,
            "wrap_format_version": 1,
            "encrypted_root": encrypted_root,
            "encrypted_policy_signing_key": {
                "nonce": Base64UrlBytes::from_bytes(&[0x27; 24]),
                "ciphertext": Base64UrlBytes::from_bytes(&[0x28; 48])
            },
            "credential_wraps": [{
                "credential_id": credential_id,
                "active": true,
                "wrap_format_version": 1,
                "wrapped_wkek": {
                    "nonce": Base64UrlBytes::from_bytes(&wrap_nonce),
                    "ciphertext": Base64UrlBytes::from_bytes(&wrapped_wkek)
                }
            }],
            "recovery_wrap": null
        });
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ceremony_backend_enrollments(
                backend_instance TEXT PRIMARY KEY, enrollment_jcs TEXT NOT NULL);
             CREATE TABLE ceremony_wallets(
                wallet_id TEXT PRIMARY KEY, custody_jcs TEXT NOT NULL);
             CREATE TABLE petal_key_scopes(key_fingerprint TEXT PRIMARY KEY);",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO ceremony_wallets VALUES (?1, ?2)",
                rusqlite::params![backend_instance, serde_jcs::to_string(&custody).unwrap()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO ceremony_backend_enrollments VALUES (?1, ?2)",
                rusqlite::params![backend_instance, serde_jcs::to_string(&enrollment).unwrap()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO ceremony_backend_enrollments VALUES (?1, ?2)",
                rusqlite::params![
                    "wallet-unrelated",
                    serde_jcs::to_string(&unrelated_enrollment).unwrap()
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO petal_key_scopes VALUES (?1)",
                [child_fingerprint],
            )
            .unwrap();
        drop(connection);
        (
            database,
            artifact,
            record_bytes,
            child_secret,
            wrapped_wkek,
            seed,
        )
    }

    #[test]
    fn scanner_has_positive_controls_for_prf_and_decryptable_record() {
        let (database, artifact, record, child_secret, wrapped_wkek, seed) = fixture();
        assert_machine_secret_confinement(
            &database,
            seed.as_bytes(),
            std::slice::from_ref(&artifact),
        )
        .unwrap();

        fs::write(&artifact, &record).unwrap();
        let error = assert_machine_secret_confinement(
            &database,
            seed.as_bytes(),
            std::slice::from_ref(&artifact),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("decryptable Signer local-key record")
        );

        fs::write(&artifact, child_secret).unwrap();
        let error = assert_machine_secret_confinement(
            &database,
            seed.as_bytes(),
            std::slice::from_ref(&artifact),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("actual persisted Petal scoped-child private key")
        );

        fs::write(&artifact, wrapped_wkek).unwrap();
        let error = assert_machine_secret_confinement(
            &database,
            seed.as_bytes(),
            std::slice::from_ref(&artifact),
        )
        .unwrap_err();
        assert!(error.to_string().contains("wrapped-WKEK ciphertext"));

        let prf = crate::VirtualAuthenticator::from_seed(seed.as_bytes()).deterministic_prf();
        fs::write(&artifact, prf).unwrap();
        let error = assert_machine_secret_confinement(
            &database,
            seed.as_bytes(),
            std::slice::from_ref(&artifact),
        )
        .unwrap_err();
        assert!(error.to_string().contains("deterministic credential PRF"));
        fs::remove_dir_all(database.parent().unwrap()).unwrap();
    }
}
