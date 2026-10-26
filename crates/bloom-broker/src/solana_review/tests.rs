use super::*;
use bloom_broker_api::*;
use bloom_solana_clear_signing::message::parse_versioned_message;

fn request(bytes: &[u8], class: &str) -> ApprovalPrepareRequest {
    let digest = Digest32::from_bytes([1; 32]);
    let token = |s: &str| Token::new(s).unwrap();
    let mut batch = Sha256::new();
    batch.update(b"bloom.petal.payload-batch.v1\0");
    batch.update(1u64.to_be_bytes());
    batch.update((bytes.len() as u64).to_be_bytes());
    batch.update(bytes);
    let claim = PetalUseClaim {
        package_hash: digest.clone(),
        route: "trade/alice/0/buy.json".into(),
        operation_class: token(class),
        crypto_suite: CryptoSuite::Ed25519Message,
        payload_digest: Digest32::from_bytes(batch.finalize().into()),
        ordered_hashes: vec![Digest32::from_bytes(Sha256::digest(bytes).into())],
        declared_debits: vec![],
        declared_destinations: vec![],
        declared_fee: DeclaredFee::None,
        nonce: RequestNonce::from_bytes([3; 16]),
        claim_assurance: ClaimAssurance::MachineAsserted,
    };
    ApprovalPrepareRequest {
        operation_id: OperationId::from_bytes([2; 32]),
        surface_selection: CeremonySurfaceSelection::Default,
        canonical_plan_facts_digest: digest.clone(),
        message_review_payloads: vec![Base64UrlBytes::from_bytes(bytes)],
        evm_review_payloads: vec![],
        safe_review_payloads: vec![],
        evm_reported_token: None,
        petal_use_claim: Some(claim),
        system_use_claim: None,
        terms: SealedApprovalTerms {
            session_budget: None,
            subject: ApprovalSubject::Petal {
                package_hash: digest.clone(),
                route: "trade/alice/0/buy.json".into(),
                agent_id: None,
            },
            wallet_id: token("alice"),
            key_ref: KeyRef {
                backend: token("local"),
                backend_instance: token("default"),
                locator: "test".into(),
                key_spec: KeySpec::Ed25519,
                public_key_fingerprint: digest.clone(),
                derivation: None,
            },
            allowed_crypto_suites: vec![CryptoSuite::Ed25519Message],
            selector: ApprovalSelector::Petal {
                package_hash: digest.clone(),
                route: "trade/alice/0/buy.json".into(),
                allowed_operation_classes: vec![token(class)],
                route_grants: vec![],
                required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(1),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: vec![],
            },
            activation_mode: ActivationMode::BootBound,
            wallet_revocation_epoch: DecimalU64::new(0),
            policy_version: DecimalU64::new(1),
            policy_digest: digest.clone(),
            provenance_digest: digest,
            request_nonce: RequestNonce::from_bytes([3; 16]),
            issued_at_ms: DecimalU64::new(1),
            not_before_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(2),
            renewal_of: None,
        },
    }
}

fn signing(input: &ApprovalPrepareRequest, bytes: &[u8]) -> MachineSignRequest {
    MachineSignRequest {
        session_use: None,
        operation_id: input.operation_id.clone(),
        operation_digest: Digest32::from_bytes([4; 32]),
        approval_id: input.terms.approval_id().unwrap(),
        key_ref: input.terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Ed25519Message,
        payloads: SigningPayloads::Batch {
            children: vec![Base64UrlBytes::from_bytes(bytes)],
        },
        petal_use_claim: input.petal_use_claim.clone(),
        system_use_claim: None,
        claim_assurance_evidence: None,
        provenance: ProvenanceSubject::Petal {
            package_hash: Digest32::from_bytes([1; 32]),
            route: "trade/alice/0/buy.json".into(),
        },
    }
}

#[test]
fn reviewed_real_messages_allow_only_blockhash_refresh() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../bloom-solana-clear-signing/tests/pump-messages.json"
    ))
    .unwrap();
    for (name, fixture) in fixtures["fixtures"].as_object().unwrap() {
        let bytes = hex::decode(fixture["message_hex"].as_str().unwrap()).unwrap();
        let parsed = parse_versioned_message(&bytes).unwrap();
        let signer = parsed.message.fee_payer();
        let class = if name == "create" {
            "pumpfun.launch"
        } else if name.starts_with("sell") {
            "pumpfun.sell"
        } else {
            "pumpfun.buy"
        };
        let input = request(&bytes, class);
        let review = prepare(&input, signer).unwrap();
        if let Some(root) = std::env::var_os("BLOOM_SOLANA_REVIEW_FIXTURES") {
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(
                std::path::Path::new(&root).join(format!("{name}.json")),
                serde_json::to_vec_pretty(&review).unwrap(),
            )
            .unwrap();
        }
        assert!(review.fields.len() <= 256);
        assert!(review.fields.iter().any(|f| f.path.contains("Program")));
        let mut fresh = parsed.clone();
        fresh.message.recent_blockhash = [0x55; 32];
        let fresh_bytes = fresh.serialize();
        assert_eq!(
            bloom_broker_api::solana_message_binding(&fresh_bytes)
                .unwrap()
                .as_str(),
            parsed
                .blockhash_independent_digest()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        verify_use(
            &input.terms,
            &signing(&input, &fresh_bytes),
            signer,
            &review,
        )
        .unwrap();
        for instruction in 0..parsed.message.instructions.len() {
            let mut changed = parsed.clone();
            changed.message.instructions[instruction].data.push(0);
            assert!(
                verify_use(
                    &input.terms,
                    &signing(&input, &changed.serialize()),
                    signer,
                    &review
                )
                .is_err(),
                "{name} instruction {instruction}"
            );
        }
        let mut changed = parsed.clone();
        changed.message.account_keys[1] = Pubkey::from_bytes([9; 32]);
        assert!(
            verify_use(
                &input.terms,
                &signing(&input, &changed.serialize()),
                signer,
                &review
            )
            .is_err()
        );
        assert!(prepare(&input, Pubkey::from_bytes([8; 32])).is_err());
        let mut omitted = input.clone();
        omitted.message_review_payloads.clear();
        assert!(prepare(&omitted, signer).is_err());
        let mut changed = input.clone();
        changed.terms.limits.max_operations = DecimalU64::new(2);
        assert!(prepare(&changed, signer).is_err());
        let mut changed = review.clone();
        changed.fields.retain(|f| f.path != BINDING_FIELD);
        assert!(verify_use(&input.terms, &signing(&input, &bytes), signer, &changed).is_err());
    }
}

#[test]
fn priority_fee_uses_integer_ceiling_and_excludes_missing_or_duplicate_settings() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../bloom-solana-clear-signing/tests/pump-messages.json"
    ))
    .unwrap();
    let bytes = hex::decode(
        fixtures["fixtures"]["buy_bond"]["message_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut parsed = parse_versioned_message(&bytes).unwrap();
    parsed.message.instructions[0].data = [vec![2], 3u32.to_le_bytes().to_vec()].concat();
    parsed.message.instructions[1].data = [vec![3], 333_334u64.to_le_bytes().to_vec()].concat();
    let reading = inspection::inspect(&parsed.serialize()).unwrap();
    assert_eq!(priority_fee_budget(&reading), Some(2));
    let mut duplicate = reading.clone();
    duplicate.instructions.push(reading.instructions[1].clone());
    assert_eq!(priority_fee_budget(&duplicate), None);
    let mut missing = reading;
    missing.instructions.remove(1);
    assert_eq!(priority_fee_budget(&missing), None);
    assert_eq!(sol_display("1"), "0.000000001");
    assert_eq!(sol_display("18446744073709551615"), "18446744073.709551615");
}
