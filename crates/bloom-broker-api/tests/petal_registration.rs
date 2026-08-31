use bloom_broker_api::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::json;

fn terms() -> PetalRegistrationTerms {
    serde_json::from_value(json!({
        "schema": "bloom.petal-registration/1",
        "operation_id": "11".repeat(32),
        "enrollment_digest": "22".repeat(32),
        "owner_wallet_id": "wallet-owner",
        "package_hash": "33".repeat(32),
        "manifest_digest": "44".repeat(32),
        "permissions_digest": "55".repeat(32),
        "lineage_id": format!("pln1_{}", "a".repeat(52)),
    }))
    .unwrap()
}

fn receipt() -> CustodyResult {
    serde_json::from_value(json!({
        "ceremony_kind": "petal_registration",
        "custody_operation_id": "11".repeat(32),
        "public_status": "SUCCEEDED",
        "wallet_id": "wallet-owner",
        "public_key_refs": [], "credential_summaries": [], "initial_policy": null,
        "receipt_digest": "66".repeat(32),
        "petal_registration_terms_digest": terms().digest().unwrap(),
        "encrypted_browser_result": null,
        "signer_key_id": "signer-key", "signer_signature": ""
    }))
    .unwrap()
}

#[test]
fn terms_digest_binds_every_exact_field_and_matches_independent_vector() {
    let original = terms();
    let digest = original.digest().unwrap();
    assert_eq!(
        digest.as_str(),
        "0697036022c3e2830c782aac96c0d7fd53302dc2da11e4c93bd08f6b6934f744"
    );
    let original_json = serde_json::to_value(&original).unwrap();
    for (field, value) in [
        ("operation_id", json!("77".repeat(32))),
        ("enrollment_digest", json!("77".repeat(32))),
        ("owner_wallet_id", json!("another-owner")),
        ("package_hash", json!("77".repeat(32))),
        ("manifest_digest", json!("77".repeat(32))),
        ("permissions_digest", json!("77".repeat(32))),
        (
            "lineage_id",
            json!(format!("pln1_{}", "b".repeat(51) + "a")),
        ),
    ] {
        let mut changed = original_json.clone();
        changed[field] = value;
        let changed: PetalRegistrationTerms = serde_json::from_value(changed).unwrap();
        assert_ne!(changed.digest().unwrap(), digest, "{field}");
    }
    assert_eq!(
        serde_json::from_value::<PetalRegistrationTerms>(original_json).unwrap(),
        original
    );
}

#[test]
fn terms_reject_unknown_fields_and_wrong_schema() {
    let mut value = serde_json::to_value(terms()).unwrap();
    value["unreviewed"] = json!(true);
    assert!(serde_json::from_value::<PetalRegistrationTerms>(value).is_err());
    let mut value = serde_json::to_value(terms()).unwrap();
    value["schema"] = json!("bloom.petal-registration/0");
    assert!(serde_json::from_value::<PetalRegistrationTerms>(value).is_err());
    let mut wrong = terms();
    wrong.schema = Token::new("bloom.petal-registration/0").unwrap();
    assert!(wrong.digest().is_err());
}

fn public(hex: &str) -> VerifyingKey {
    VerifyingKey::from_bytes(&hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
}

#[test]
fn enrollment_binds_both_key_ids_and_validated_public_bytes() {
    let broker_id = Token::new("broker-key").unwrap();
    let signer_id = Token::new("signer-key").unwrap();
    let broker = public("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signer = public("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let digest =
        petal_registration_enrollment_digest(&broker_id, &broker, &signer_id, &signer).unwrap();
    assert_eq!(
        digest.as_str(),
        "6e6973cef8feb7f45b68ba33ca474a8ef80e3dad5ff94396c11b28ee4afab34a"
    );
    let other = Token::new("other-key").unwrap();
    for changed in [
        petal_registration_enrollment_digest(&other, &broker, &signer_id, &signer),
        petal_registration_enrollment_digest(&broker_id, &signer, &signer_id, &signer),
        petal_registration_enrollment_digest(&broker_id, &broker, &other, &signer),
        petal_registration_enrollment_digest(&broker_id, &broker, &signer_id, &broker),
    ] {
        assert_ne!(changed.unwrap(), digest);
    }
}

#[test]
fn receipt_requires_exact_registration_binding_and_success_shape() {
    let original = receipt();
    original
        .validate_petal_registration_binding(&terms())
        .unwrap();
    assert_eq!(
        CeremonyKind::PetalRegistration.successful_terminal_state(),
        Some(CeremonyState::Succeeded)
    );
    for (field, value) in [
        ("ceremony_kind", json!("policy_update")),
        ("custody_operation_id", json!("77".repeat(32))),
        ("public_status", json!("COMPLETED")),
        ("wallet_id", json!("other-owner")),
        ("petal_registration_terms_digest", json!("77".repeat(32))),
        ("petal_registration_terms_digest", json!(null)),
        (
            "credential_summaries",
            json!([{"credential_id":"AQ", "rp_id":"localhost", "active":true}]),
        ),
    ] {
        let mut changed = serde_json::to_value(&original).unwrap();
        changed[field] = value;
        let changed: CustodyResult = serde_json::from_value(changed).unwrap();
        assert!(
            changed
                .validate_petal_registration_binding(&terms())
                .is_err(),
            "{field}"
        );
    }
    let mut missing = original.clone();
    missing.petal_registration_terms_digest = None;
    assert!(missing.unsigned_canonical_bytes().is_err());
    let mut cross_kind = original;
    cross_kind.ceremony_kind = CeremonyKind::PolicyUpdate;
    assert!(cross_kind.unsigned_canonical_bytes().is_err());
}

#[test]
fn receipt_signature_covers_registration_binding_and_old_kinds_keep_their_bytes() {
    let original = receipt();
    let key = SigningKey::from_bytes(&[9; 32]);
    let bytes = original.unsigned_canonical_bytes().unwrap();
    let signature = key.sign(&bytes);
    key.verifying_key()
        .verify_strict(&bytes, &signature)
        .unwrap();
    let mut changed = original.clone();
    changed.petal_registration_terms_digest = Some(Digest32::from_bytes([9; 32]));
    assert!(
        key.verifying_key()
            .verify_strict(&changed.unsigned_canonical_bytes().unwrap(), &signature)
            .is_err()
    );
    let mut old = original;
    old.ceremony_kind = CeremonyKind::PolicyUpdate;
    old.petal_registration_terms_digest = None;
    let mut legacy = serde_json::to_value(&old).unwrap();
    assert!(legacy.get("petal_registration_terms_digest").is_none());
    legacy.as_object_mut().unwrap().remove("signer_signature");
    assert_eq!(
        old.unsigned_canonical_bytes().unwrap(),
        serde_jcs::to_vec(&legacy).unwrap()
    );
}

fn route(id: &str) -> RequestedRoutePermission {
    RequestedRoutePermission {
        route_id: id.into(),
        source_path: format!("src/{id}.rs"),
        capabilities: vec!["store".into()],
        signing_operations: vec![],
        key_derive_operations: vec![],
    }
}

#[test]
fn record_digest_binds_exact_terms_ordered_routes_and_receipt_excluding_itself() {
    let mut record = PetalRegistration {
        terms: terms(),
        approved_routes: vec![route("first"), route("second")],
        ceremony_receipt: receipt(),
        registration_digest: Digest32::from_bytes([0; 32]),
    };
    let digest = record.digest().unwrap();
    assert_eq!(
        digest.as_str(),
        "7309a16b85d599382a2fa48d1cd73f2ca4e8f62d7d5d875bcb8ef338fb43f209"
    );
    record.registration_digest = digest.clone();
    assert_eq!(record.digest().unwrap(), digest);
    let mut changed = record.clone();
    changed.approved_routes.reverse();
    assert_ne!(changed.digest().unwrap(), digest);
    let mut changed = record.clone();
    changed.approved_routes.push(route("second"));
    assert_ne!(changed.digest().unwrap(), digest);
    let mut changed = record.clone();
    changed.terms.package_hash = Digest32::from_bytes([9; 32]);
    assert_ne!(changed.digest().unwrap(), digest);
    let mut changed = record.clone();
    changed.ceremony_receipt.signer_signature = Base64UrlBytes::from_bytes(&[1; 64]);
    assert_ne!(changed.digest().unwrap(), digest);
    let mut changed = serde_json::to_value(record).unwrap();
    changed["authority"] = json!("unreviewed");
    assert!(serde_json::from_value::<PetalRegistration>(changed).is_err());
}

#[test]
fn registration_wire_methods_preserve_operation_identity_and_read_option() {
    let prepare = MachineBrokerRequest::PetalRegistrationPrepare(PetalRegistrationPrepareRequest {
        operation_id: terms().operation_id.clone(),
        owner_wallet_id: terms().owner_wallet_id,
        evidence: PackageEvidence {
            package_hash: "33".repeat(32),
            file_pages: vec![],
            manifest_utf8: String::new(),
        },
        requested_routes: vec![route("first")],
    });
    assert_eq!(
        prepare.method().unwrap().as_str(),
        "petal.registration_prepare"
    );
    assert_eq!(prepare.operation_id().unwrap(), Some(terms().operation_id));
    assert!(!prepare.is_read_only());
    let commit = MachineBrokerRequest::PetalRegistrationCommit(PetalRegistrationCommitRequest {
        operation_id: terms().operation_id.clone(),
        ceremony_receipt: receipt(),
    });
    assert_eq!(
        commit.method().unwrap().as_str(),
        "petal.registration_commit"
    );
    assert_eq!(commit.operation_id().unwrap(), Some(terms().operation_id));
    assert!(!commit.is_read_only());
    let read = MachineBrokerRequest::PetalRegistrationRead(PetalRegistrationReadRequest {
        package_hash: terms().package_hash,
    });
    assert_eq!(read.method().unwrap().as_str(), "petal.registration_read");
    assert_eq!(read.operation_id().unwrap(), None);
    assert!(read.is_read_only());
    for request in [prepare, commit, read] {
        let wire = serde_json::to_value(&request).unwrap();
        assert!(MachineBrokerMethod::parse(wire["method"].as_str().unwrap()).is_ok());
        assert_eq!(
            serde_json::from_value::<MachineBrokerRequest>(wire).unwrap(),
            request
        );
    }
    let response = MachineBrokerResponse::PetalRegistrationRead(None);
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({"method":"petal.registration_read","body":null})
    );
}
