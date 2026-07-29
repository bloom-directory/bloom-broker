use std::path::Path;
use std::process::Command;

#[test]
fn production_broker_dependency_graph_has_no_machine_signer_backend_or_debug_driver() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bloom-broker belongs to its workspace");
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "bloom-broker",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .current_dir(workspace)
        .output()
        .expect("run cargo tree for the production Broker graph");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let graph = String::from_utf8(output.stdout).expect("cargo tree output is UTF-8");
    for forbidden in [
        "bloom-machine ",
        "bloom-machine-client ",
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
}
