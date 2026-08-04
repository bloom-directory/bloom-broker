use bloom_broker_api::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalVector {
    name: String,
    terms: SealedApprovalTerms,
    canonical_jcs: String,
    approval_digest: Digest32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorVector {
    code: String,
    retry: RetryClass,
    durable_effect: DurableEffect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRefVector {
    name: String,
    key_ref: KeyRef,
    canonical_jcs: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeGoldenBody {
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHeadEnvelopeVector {
    name: String,
    unsigned_envelope: UnsignedEnvelope<EnvelopeGoldenBody>,
    canonical_jcs: String,
    head_signature_message_base64url: Base64UrlBytes,
}

#[test]
fn keyref_jcs_and_exact_equality_match_reviewed_artifact() {
    let vector: KeyRefVector =
        serde_json::from_str(include_str!("../vectors/keyref-local-bip32-v1.json")).unwrap();
    assert_eq!(vector.name, "local-bip32-v1");
    vector.key_ref.validate().unwrap();
    assert_eq!(
        String::from_utf8(serde_jcs::to_vec(&vector.key_ref).unwrap()).unwrap(),
        vector.canonical_jcs
    );

    let mut changed = vector.key_ref.clone();
    changed.backend_instance = Token::new("local-other").unwrap();
    assert_ne!(changed, vector.key_ref);
    let mut changed = vector.key_ref.clone();
    changed.public_key_fingerprint = Digest32::new("aa".repeat(32)).unwrap();
    assert_ne!(changed, vector.key_ref);
    let mut changed = vector.key_ref.clone();
    changed.derivation = None;
    assert_ne!(changed, vector.key_ref);
}

#[test]
fn approval_jcs_and_digest_match_reviewed_artifact() {
    let vector: ApprovalVector = serde_json::from_str(include_str!(
        "../vectors/approval-exact-local-bip32-v1.json"
    ))
    .unwrap();
    assert_eq!(vector.name, "exact-local-bip32-v1");
    assert_eq!(
        String::from_utf8(vector.terms.canonical_bytes().unwrap()).unwrap(),
        vector.canonical_jcs
    );
    assert_eq!(
        vector.terms.approval_digest().unwrap(),
        vector.approval_digest
    );
    assert_eq!(vector.terms.approval_id().unwrap(), vector.approval_digest);
    for excluded in [
        "approval_id",
        "review_manifest_digest",
        "state",
        "activation_receipt",
        "created_at",
        "updated_at",
    ] {
        assert!(!vector.canonical_jcs.contains(excluded));
    }
}

#[test]
fn every_immutable_authority_field_changes_the_approval_digest() {
    let vector: ApprovalVector = serde_json::from_str(include_str!(
        "../vectors/approval-exact-local-bip32-v1.json"
    ))
    .unwrap();
    let baseline = vector.approval_digest;
    let mut mutations = Vec::new();

    let mut changed = vector.terms.clone();
    changed.subject = ApprovalSubject::Cli {
        client_id: Token::new("other-cli").unwrap(),
        command_class: Token::new("wallet.sign").unwrap(),
    };
    mutations.push(("subject", changed));

    let mut changed = vector.terms.clone();
    changed.key_ref.locator = "key-2".into();
    mutations.push(("KeyRef", changed));

    let mut changed = vector.terms.clone();
    changed
        .allowed_crypto_suites
        .push(CryptoSuite::Secp256k1Sha256Recoverable);
    mutations.push(("allowed_crypto_suites", changed));

    let mut changed = vector.terms.clone();
    changed.selector = ApprovalSelector::Exact {
        ordered_payload_digests: vec![Digest32::new("66".repeat(32)).unwrap()],
        ordered_hashes: vec![Digest32::new("33".repeat(32)).unwrap()],
    };
    mutations.push(("selector", changed));

    let mut changed = vector.terms.clone();
    changed.limits.operation_rate_limits.push(SlidingWindow {
        maximum: DecimalU64::new(1),
        duration_ms: DecimalU64::new(60_000),
    });
    mutations.push(("limits", changed));

    let mut changed = vector.terms.clone();
    changed.activation_mode = ActivationMode::BackendManaged;
    mutations.push(("activation_mode", changed));

    let mut changed = vector.terms.clone();
    changed.wallet_revocation_epoch = DecimalU64::new(8);
    mutations.push(("wallet_revocation_epoch", changed));

    let mut changed = vector.terms.clone();
    changed.policy_version = DecimalU64::new(4);
    changed.policy_digest = Digest32::new("77".repeat(32)).unwrap();
    mutations.push(("policy", changed));

    let mut changed = vector.terms.clone();
    changed.provenance_digest = Digest32::new("88".repeat(32)).unwrap();
    mutations.push(("provenance", changed));

    let mut changed = vector.terms.clone();
    changed.request_nonce = RequestNonce::new("99".repeat(16)).unwrap();
    mutations.push(("request_nonce", changed));

    let mut changed = vector.terms.clone();
    changed.expires_at_ms = DecimalU64::new(1_900_000_700_000);
    mutations.push(("validity", changed));

    for (field, terms) in mutations {
        assert_ne!(terms.approval_digest().unwrap(), baseline, "{field}");
    }
}

#[test]
fn identical_terms_with_distinct_request_nonces_have_distinct_ids() {
    let vector: ApprovalVector = serde_json::from_str(include_str!(
        "../vectors/approval-exact-local-bip32-v1.json"
    ))
    .unwrap();
    let mut second = vector.terms.clone();
    second.request_nonce = RequestNonce::new("01".repeat(16)).unwrap();
    assert_ne!(
        vector.terms.approval_id().unwrap(),
        second.approval_id().unwrap()
    );
}

#[test]
fn closed_error_contract_matches_reviewed_artifact() {
    let vectors: Vec<ErrorVector> =
        serde_json::from_str(include_str!("../vectors/error-taxonomy-v1.json")).unwrap();
    assert_eq!(vectors.len(), ProtocolErrorCode::ALL.len());
    for (vector, code) in vectors.into_iter().zip(ProtocolErrorCode::ALL) {
        assert_eq!(vector.code, code.as_str());
        assert_eq!(vector.retry, code.contract().retry);
        assert_eq!(vector.durable_effect, code.contract().durable_effect);
        assert_eq!(vector.code.parse::<ProtocolErrorCode>().unwrap(), code);
    }
}
#[test]
fn machine_broker_journal_head_envelope_matches_reviewed_artifact() {
    let vector: JournalHeadEnvelopeVector = serde_json::from_str(include_str!(
        "../vectors/machine-broker-journal-head-v1.json"
    ))
    .unwrap();
    assert_eq!(vector.name, "machine-broker-journal-head-minor-1");
    assert_eq!(
        String::from_utf8(vector.unsigned_envelope.canonical_bytes().unwrap()).unwrap(),
        vector.canonical_jcs
    );
    let head = vector.unsigned_envelope.sender_journal_head.unwrap();
    assert_eq!(
        Base64UrlBytes::from_bytes(&head.signature_message()),
        vector.head_signature_message_base64url
    );
}
