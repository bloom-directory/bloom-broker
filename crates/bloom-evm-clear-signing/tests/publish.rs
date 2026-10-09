//! The publication gate: what the publisher tool refuses to sign.
//!
//! These run the real binary, because the point of each rule is that it stops
//! a publication, not that a function returns an error.

mod support;

use std::{path::Path, process::Command};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use support::*;

const TOOL: &str = env!("CARGO_BIN_EXE_bloom-clear-signing-catalog");
/// The pins the tool itself prints; a report naming anything else is refused.
const SCHEMA_COMMIT: &str = "2528d6a0cd463d7309464a33889774368ab52df3";
const SCHEMA_SHA256: &str = "53c0fe0ed07c3e032fc3bfabb105585b6648b2adae4858fbf45b3a09dfe691f5";

struct Publication {
    directory: tempfile::TempDir,
}

impl Publication {
    /// A source catalog with one entry, whose descriptor is written verbatim
    /// so a test can put anything at all in it.
    fn new(descriptor: &str) -> Self {
        let publication = Self {
            directory: tempfile::tempdir().unwrap(),
        };
        publication.write("descriptor.json", descriptor);
        publication.write(
            "source.json",
            &serde_json::to_string_pretty(&json!({
                "catalog_id": "bloom-tokens",
                "sequence": 1,
                "issued_at_ms": NOW_MS - 10_000,
                "expires_at_ms": NOW_MS + 86_400_000,
                "entries": [{
                    "chain_id": CHAIN_ID,
                    "contract_address": TOKEN,
                    "descriptor": "descriptor.json",
                    "admitted_functions": [
                        {"signature": "transfer(address _to, uint256 _value)",
                         "action_class": "transfer"}
                    ],
                    "token_metadata": {"decimals": 6, "symbol": "EXA", "name": "Example Token"},
                    "observed_at_ms": NOW_MS - 1000
                }]
            }))
            .unwrap(),
        );
        publication.write("key.hex", &hex::encode([1_u8; 32]));
        publication
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.path(name), contents).unwrap();
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.directory.path().join(name)
    }

    /// A report covering the named files, as the validation script writes it.
    fn report(&self, files: &[&str]) -> &Self {
        self.report_for(SCHEMA_COMMIT, SCHEMA_SHA256, files)
    }

    fn report_for(&self, commit: &str, schema: &str, files: &[&str]) -> &Self {
        let validated: serde_json::Map<String, Value> = files
            .iter()
            .map(|name| {
                let bytes = std::fs::read(self.path(name)).unwrap();
                (
                    (*name).to_owned(),
                    Value::String(hex::encode(Sha256::digest(&bytes))),
                )
            })
            .collect();
        self.write(
            "report.json",
            &serde_json::to_string(&json!({
                "schema_commit": commit,
                "schema_sha256": schema,
                "validator": "check-jsonschema 0.33.0",
                "validated": validated,
            }))
            .unwrap(),
        );
        self
    }

    fn build(&self) -> Result<String, String> {
        self.build_with(&["--schema-report", "report.json"])
    }

    fn build_with(&self, extra: &[&str]) -> Result<String, String> {
        let mut command = Command::new(TOOL);
        command
            .current_dir(self.directory.path())
            .args(["build", "source.json"])
            .args(["--key", "key.hex"])
            .args(["--key-id", "publisher-1"])
            .args(["--out", "catalog.json"])
            .args(extra);
        let output = command.output().unwrap();
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }
}

fn transfer_descriptor() -> String {
    serde_json::to_string_pretty(&erc20_descriptor()).unwrap()
}

#[test]
fn a_catalog_with_a_validated_descriptor_publishes_and_verifies() {
    let publication = Publication::new(&transfer_descriptor());
    publication.report(&["descriptor.json"]);
    let message = publication.build().expect("a validated source publishes");
    assert!(
        message.contains("1 descriptor files validated"),
        "{message}"
    );
    assert!(message.contains("check-jsonschema"), "{message}");

    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes(),
    );
    let verified = Command::new(TOOL)
        .current_dir(publication.directory.path())
        .args(["verify", "catalog.json"])
        .args(["--key-id", "publisher-1"])
        .args(["--public-key", &key])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn publication_requires_a_schema_report() {
    let publication = Publication::new(&transfer_descriptor());
    let error = publication.build_with(&[]).unwrap_err();
    assert!(error.contains("--schema-report"), "{error}");
    assert!(!publication.path("catalog.json").exists());
}

#[test]
fn a_report_against_another_schema_revision_is_refused() {
    let publication = Publication::new(&transfer_descriptor());
    publication.report_for(&"a".repeat(40), SCHEMA_SHA256, &["descriptor.json"]);
    let error = publication.build().unwrap_err();
    assert!(error.contains("not the pinned"), "{error}");

    publication.report_for(SCHEMA_COMMIT, &"b".repeat(64), &["descriptor.json"]);
    let error = publication.build().unwrap_err();
    assert!(error.contains("not the pinned"), "{error}");
}

#[test]
fn an_edited_descriptor_no_longer_matches_its_report() {
    let publication = Publication::new(&transfer_descriptor());
    publication.report(&["descriptor.json"]);
    // Validated, then changed: the report covers bytes that are no longer
    // the bytes being published.
    let mut descriptor = erc20_descriptor();
    descriptor["metadata"]["contractName"] = json!("Something Else");
    publication.write(
        "descriptor.json",
        &serde_json::to_string_pretty(&descriptor).unwrap(),
    );
    let error = publication.build().unwrap_err();
    assert!(error.contains("is not in the schema report"), "{error}");
}

#[test]
fn every_included_file_must_be_validated_not_just_the_top_document() {
    let publication = Publication::new(&json!({"includes": "base.json"}).to_string());
    publication.write("base.json", &transfer_descriptor());
    // A report covering only the including document leaves everything the
    // include merged in unchecked.
    publication.report(&["descriptor.json"]);
    let error = publication.build().unwrap_err();
    assert!(error.contains("is not in the schema report"), "{error}");

    publication.report(&["descriptor.json", "base.json"]);
    let message = publication.build().expect("both files validated");
    assert!(
        message.contains("2 descriptor files validated"),
        "{message}"
    );
}

#[test]
fn an_include_cycle_is_refused_rather_than_followed() {
    let publication = Publication::new(&json!({"includes": "base.json"}).to_string());
    publication.write(
        "base.json",
        &json!({"includes": "descriptor.json"}).to_string(),
    );
    publication.report(&["descriptor.json", "base.json"]);
    let error = publication.build().unwrap_err();
    assert!(error.contains("cycle"), "{error}");
}

#[test]
fn an_include_chain_longer_than_the_limit_is_refused() {
    let publication = Publication::new(&json!({"includes": "a.json"}).to_string());
    publication.write("a.json", &json!({"includes": "b.json"}).to_string());
    publication.write("b.json", &json!({"includes": "c.json"}).to_string());
    publication.write("c.json", &json!({"includes": "d.json"}).to_string());
    publication.write("d.json", &transfer_descriptor());
    publication.report(&["descriptor.json", "a.json", "b.json", "c.json", "d.json"]);
    let error = publication.build().unwrap_err();
    assert!(error.contains("include limit"), "{error}");
}

#[test]
fn a_duplicate_key_is_refused_rather_than_resolved_by_position() {
    // Which `metadata` applies is not decidable from the document, and the
    // digest would record whichever one the parser happened to keep.
    let publication = Publication::new(
        r#"{"metadata": {"contractName": "One"}, "metadata": {"contractName": "Two"}}"#,
    );
    publication.report(&["descriptor.json"]);
    let error = publication.build().unwrap_err();
    assert!(error.contains("appears twice"), "{error}");
}

#[test]
fn a_number_that_is_not_an_exact_integer_is_refused() {
    let publication = Publication::new(
        r#"{"context": {"contract": {"deployments":
        [{"chainId": 123456789012345678901234567890, "address": "0x1"}]}}}"#,
    );
    publication.report(&["descriptor.json"]);
    let error = publication.build().unwrap_err();
    assert!(error.contains("not an exact integer"), "{error}");
}

#[test]
fn a_remote_include_is_refused() {
    let publication =
        Publication::new(&json!({"includes": "https://example.test/base.json"}).to_string());
    publication.report(&["descriptor.json"]);
    let error = publication.build().unwrap_err();
    assert!(error.contains("remote document"), "{error}");
}

/// The validation script and the tool must agree about which schema is
/// pinned; nothing else keeps the shell script and the constants in step.
#[test]
fn the_script_reads_the_pins_the_tool_prints() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("publish/validate-descriptors.sh");
    let text = std::fs::read_to_string(script).unwrap();
    assert!(
        text.contains("schema-pin"),
        "the script must read the tool's own pins"
    );
    assert!(
        !text.contains(SCHEMA_SHA256),
        "the script must not restate the digest"
    );
}
