use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bloom-broker belongs to its workspace")
        .to_path_buf()
}

fn production_tree(package: &str) -> String {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            package,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .current_dir(workspace())
        .output()
        .expect("run cargo tree for a production graph");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("cargo tree output is UTF-8")
}

fn rust_sources(root: &Path) -> String {
    fn append(directory: &Path, output: &mut String) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                append(&path, output);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                output.push_str(&fs::read_to_string(path).unwrap());
            }
        }
    }
    let mut output = String::new();
    append(root, &mut output);
    output
}

#[test]
fn production_broker_reports_its_semantic_version_without_starting_services() {
    let output = Command::new(env!("CARGO_BIN_EXE_bloom-broker"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("bloom-broker {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn production_broker_dependency_graph_has_no_machine_signer_backend_or_debug_driver() {
    let graph = production_tree("bloom-broker");
    for forbidden in [
        "bloom-triad-protocol ",
        "bloom-machine ",
        "bloom-machine-client ",
        "bloom-daemon ",
        "bloom-keystore ",
        "bloom-auth ",
        "bloom-auth-api ",
        "bloom-signer ",
        "bloom-signer-backend-api ",
        "bloom-signer-backend-local ",
        "bloom-signer-backend-aws-kms ",
        "bloom-broker-debug-driver ",
    ] {
        assert!(
            !graph.contains(forbidden),
            "production Broker graph contains forbidden dependency {forbidden}:\n{graph}"
        );
    }

    let broker_root = workspace().join("crates/bloom-broker");
    let manifest = fs::read_to_string(broker_root.join("Cargo.toml")).unwrap();
    let sources = rust_sources(&broker_root.join("src"));
    assert!(!manifest.contains("bloom-triad-protocol"));
    for forbidden in [
        "bloom_triad_protocol",
        "bloom_machine::",
        "bloom_signer_backend",
    ] {
        assert!(
            !sources.contains(forbidden),
            "production Broker source contains stale implementation reference {forbidden}"
        );
    }
}

#[test]
fn broker_api_graph_and_sources_are_domain_isolated() {
    let graph = production_tree("bloom-broker-api");
    for line in graph.lines().filter(|line| line.starts_with("bloom-")) {
        let package = line.split_whitespace().next().unwrap();
        assert!(
            matches!(package, "bloom-broker-api" | "bloom-rpc-wire"),
            "Broker API graph contains non-mechanical Bloom dependency {package}:\n{graph}"
        );
    }

    let api_root = workspace().join("crates/bloom-broker-api");
    let manifest = fs::read_to_string(api_root.join("Cargo.toml")).unwrap();
    let sources = rust_sources(&api_root.join("src"));
    for forbidden in [
        "bloom-triad-protocol",
        "bloom-signer-api",
        "bloom-machine",
        "bloom-signer-backend",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "Broker API manifest contains forbidden boundary dependency {forbidden}"
        );
    }
    for forbidden in [
        "bloom_triad_protocol",
        "bloom_signer_api",
        "bloom_machine::",
        "bloom_signer_backend",
    ] {
        assert!(
            !sources.contains(forbidden),
            "Broker API source contains forbidden boundary reference {forbidden}"
        );
    }
}
