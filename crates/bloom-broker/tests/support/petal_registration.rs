use bloom_broker_api::{OperationId, PetalRegistrationPrepareRequest, Token};
use bloom_petal_package::{
    FileDigestEntry, PackageEvidence, RequestedRoutePermission, package_hash_from_entries,
};

pub fn proposal(
    operation_id: OperationId,
    owner_wallet_id: Token,
) -> PetalRegistrationPrepareRequest {
    let manifest = r#"schema = "bloom.petal.package.v1"
name = "example"
[caps]
allowed = ["bloom:sign", "bloom:tx.outbox"]
[sign]
allowed_intents = ["example.sign"]
[source]
kind = "git"
repository = "https://unverified.example/any-author/petal"
"#;
    let entries = [
        ("petal.toml", manifest.as_bytes()),
        ("README.md", b"# Example".as_slice()),
        ("AGENTS.md", b"Instructions".as_slice()),
        (
            "petal/example/action.tx.wasm",
            b"claimed artifact A".as_slice(),
        ),
        ("petal/example/view.wasm", b"claimed artifact B".as_slice()),
    ]
    .into_iter()
    .map(|(path, bytes)| FileDigestEntry {
        path: path.into(),
        byte_len: bytes.len() as u64,
        blake3_hex: blake3::hash(bytes).to_hex().to_string(),
    })
    .collect::<Vec<_>>();
    PetalRegistrationPrepareRequest {
        operation_id,
        owner_wallet_id,
        evidence: PackageEvidence {
            package_hash: package_hash_from_entries(&entries).unwrap(),
            file_pages: vec![entries],
            manifest_utf8: manifest.into(),
        },
        requested_routes: vec![
            RequestedRoutePermission {
                route_id: "r000001".into(),
                source_path: "petal/example/action.tx.wasm".into(),
                capabilities: vec!["bloom:tx.outbox".into()],
                signing_operations: vec![],
                key_derive_operations: vec![],
            },
            RequestedRoutePermission {
                route_id: "r000002".into(),
                source_path: "petal/example/view.wasm".into(),
                capabilities: vec!["bloom:sign".into()],
                signing_operations: vec!["example.sign".into()],
                key_derive_operations: vec![],
            },
        ],
    }
}

#[allow(dead_code)]
pub fn change_artifact(request: &mut PetalRegistrationPrepareRequest, tag: u8) {
    request.evidence.file_pages[0]
        .last_mut()
        .unwrap()
        .blake3_hex = blake3::hash(&[tag]).to_hex().to_string();
    request.evidence.package_hash = package_hash_from_entries(
        &request
            .evidence
            .file_pages
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .unwrap();
}
