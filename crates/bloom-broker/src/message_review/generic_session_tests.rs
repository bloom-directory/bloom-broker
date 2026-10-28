//! Regressions for the boundary between generic token sessions and existing
//! stronger review profiles. Economic admission is tested separately.
use super::*;
use bloom_broker_api::*;

fn token(v: &str) -> Token {
    Token::new(v).unwrap()
}
fn digest() -> Digest32 {
    Digest32::from_bytes([7; 32])
}
fn terms(class: &str) -> SealedApprovalTerms {
    let limits = ApprovalLimits {
        max_operations: DecimalU64::new(10),
        max_signatures: DecimalU64::new(10),
        operation_rate_limits: vec![],
        signature_rate_limits: vec![],
        value_limits: vec![],
    };
    let key = KeyRef {
        backend: token("local"),
        backend_instance: token("test"),
        locator: "test".into(),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: digest(),
        derivation: None,
    };
    SealedApprovalTerms {
        subject: ApprovalSubject::Petal {
            package_hash: digest(),
            route: "trade".into(),
            agent_id: None,
        },
        wallet_id: token("test"),
        key_ref: key.clone(),
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        selector: ApprovalSelector::Petal {
            package_hash: digest(),
            route: "trade".into(),
            allowed_operation_classes: vec![token(class)],
            route_grants: vec![],
            required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
        },
        limits: limits.clone(),
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(0),
        policy_version: DecimalU64::new(1),
        policy_digest: digest(),
        provenance_digest: digest(),
        request_nonce: RequestNonce::from_bytes([1; 16]),
        issued_at_ms: DecimalU64::new(1),
        not_before_ms: DecimalU64::new(1),
        expires_at_ms: DecimalU64::new(100),
        renewal_of: None,
        // Selector validation must preserve exact-review restrictions even when
        // a caller presents the new token envelope. Other budget validation is
        // intentionally independent of this profile-dispatch regression.
        session_budget: Some(SessionBudget {
            token_policy: Some(SessionTokenPolicy {
                schema_version: 3,
                budget_nonce: RequestNonce::from_bytes([2; 16]),
                member_scope_digests: vec![],
                member_templates: vec![],
                member_backstop_allocations: vec![],
                assets: vec![],
            }),
            wallet_id: token("test"),
            policy_version: DecimalU64::new(1),
            policy_digest: digest(),
            wallet_revocation_epoch: DecimalU64::new(0),
            member_keys: vec![key],
            limits,
            per_action_value_limits: vec![],
            not_before_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(100),
        }),
    }
}

#[test]
fn generic_token_envelope_does_not_downgrade_existing_exact_review_classes() {
    let classes = MESSAGE_REVIEW_OPERATION_CLASSES.iter().chain([
        &SAFE_CONFIRM_OPERATION_CLASS,
        &"polymarket.onboard",
        &"polymarket.relayer_batch",
    ]);
    for class in classes {
        let mut direct = terms(class);
        assert!(validate_selector(&direct, None).is_err(), "{class}");
        // Moving a stronger class into a secondary route must not evade the
        // same rule while the top-level route looks like an ordinary Petal.
        if let ApprovalSelector::Petal {
            allowed_operation_classes,
            route_grants,
            ..
        } = &mut direct.selector
        {
            *allowed_operation_classes = vec![token("generic.swap")];
            route_grants.push(PetalRouteGrant {
                route: "secondary".into(),
                allowed_operation_classes: vec![token(class)],
                provenance_digest: digest(),
            });
        }
        assert!(
            validate_selector(&direct, None).is_err(),
            "secondary {class}"
        );
    }
    validate_selector(&terms("generic.swap"), None).unwrap();
    validate_selector(&terms("polymarket.order.poly1271"), None).unwrap();
}

fn order_review(side: &str) -> MessageReview {
    MessageReview {
        kind: "polymarket_exact".into(),
        title: String::new(),
        signer: String::new(),
        payload_keccak: String::new(),
        domain: vec![],
        fields: vec![
            MessageField {
                path: "Side (0 buy, 1 sell)".into(),
                value: side.into(),
            },
            MessageField {
                path: "Maker amount (raw protocol units)".into(),
                value: "1000000".into(),
            },
            MessageField {
                path: "Taker amount (raw protocol units)".into(),
                value: "2000000".into(),
            },
            MessageField {
                path: "Outcome token ID (market identity unverified)".into(),
                value: "42".into(),
            },
        ],
        warnings: vec![],
        payment: None,
        venue_asset: None,
        collateral_asset: None,
    }
}
fn order_claim() -> PetalUseClaim {
    PetalUseClaim {
        economic_effects: Some(EconomicEffectsV1 {
            schema_version: 1,
            payload_contexts: vec![],
            permission_effect: SessionPermissionEffect::None,
        }),
        package_hash: digest(),
        route: "trade".into(),
        operation_class: token("polymarket.order.poly1271"),
        crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
        payload_digest: digest(),
        ordered_hashes: vec![],
        declared_debits: vec![DeclaredDebit {
            asset: AssetId {
                chain: token("evm-137"),
                asset: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
            },
            amount: DecimalU256::parse("1000000").unwrap(),
        }],
        declared_destinations: vec![],
        declared_fee: DeclaredFee::None,
        nonce: RequestNonce::from_bytes([3; 16]),
        claim_assurance: ClaimAssurance::MachineAsserted,
    }
}
#[test]
fn canonical_pusd_cannot_use_a_legacy_alias_or_hide_sold_outcome_units() {
    let buy = order_review("0");
    let claim = order_claim();
    validate_order_debit(&claim, &buy, true).unwrap();
    let mut alias = claim.clone();
    alias.declared_debits[0].asset = AssetId {
        chain: token("polygon"),
        asset: "pusd".into(),
    };
    assert!(validate_order_debit(&alias, &buy, true).is_err());
    // Legacy exact records retain their old representation, but never become
    // an alternate accounting identity in the new effects contract.
    alias.economic_effects = None;
    validate_order_debit(&alias, &buy, true).unwrap();
    let sell = order_review("1");
    assert!(validate_order_debit(&claim, &sell, true).is_err());
    let mut shares = claim;
    shares.declared_debits[0].asset.asset =
        "erc1155:0x4d97dcd97ec945f40cf65f87097ace5ea0476045:42".into();
    validate_order_debit(&shares, &sell, false).unwrap();
    assert!(validate_order_debit(&shares, &sell, true).is_err());
}
