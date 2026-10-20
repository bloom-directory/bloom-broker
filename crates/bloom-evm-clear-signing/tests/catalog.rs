//! The compiled-in catalog: what it admits, and extension by data alone.

mod support;

use alloy_primitives::U256;
use bloom_evm_clear_signing::*;
use serde_json::json;
use support::*;

const LOCK: &str = "lock(address beneficiary, uint256 amount, uint256 unlockTime)";

#[test]
fn maximum_chain_lookup_keeps_direct_and_standard_resolution_without_overflow() {
    let catalog = Catalog::built_in().unwrap();
    let selector = &calldata(
        "deposit(uint256,address)",
        &[U256::from(1), address_word(RECIPIENT)],
    )[..4];
    for chain in [u64::MAX - 1, u64::MAX] {
        assert!(catalog.resolve(chain, VAULT, selector).is_some());
        assert!(catalog.resolve(chain, VAULT, &[0xff; 4]).is_none());
        let mut descriptor = erc20_descriptor();
        descriptor["context"]["contract"]["deployments"][0]["chainId"] = json!(chain);
        let mut metadata = token(TOKEN, 6);
        metadata.chain_id = chain;
        let direct = build(vec![descriptor], vec![metadata]).unwrap();
        let transfer = calldata(
            "transfer(address,uint256)",
            &[address_word(RECIPIENT), U256::from(1)],
        );
        assert!(!direct.resolve(chain, TOKEN, &transfer[..4]).unwrap().2);
        assert!(direct.resolve(chain, VAULT, &[0xff; 4]).is_none());
    }
}

/// The catalog this build ships must admit, or clear signing is down.
#[test]
fn the_built_in_catalog_admits_and_lists_the_safe_deployments() {
    let catalog = Catalog::built_in().unwrap();
    let factory = catalog
        .entry(8453, "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67")
        .unwrap();
    assert!(!factory.applies_to_instances);
    let singleton = catalog
        .entry(1, "0x41675c099f32341bf84bfc5382af534df5c7461a")
        .unwrap();
    assert!(singleton.applies_to_instances);
    assert!(singleton.token_metadata.is_none());
    let usdc = catalog
        .entry(8453, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
        .unwrap();
    assert_eq!(usdc.token_metadata.as_ref().unwrap().decimals, 6);
    assert!(usdc.upgradeable);
    assert!(catalog.len() > 1000);
}

/// The extension proof. A third static function becomes reviewable by
/// publishing signed catalog data: no decoder, selector switch, formatter
/// branch or executable plugin is added to reach it.
#[test]
fn a_third_function_arrives_as_catalog_data_and_displays_every_argument() {
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "metadata": {"contractName": "Example Token"},
        "display": {"formats": {LOCK: {
            "intent": "Lock",
            "fields": [
                {"path": "beneficiary", "label": "Beneficiary", "format": "addressName", "visible": "always"},
                {"path": "amount", "label": "Amount", "format": "tokenAmount", "params": {"tokenPath": "@.to"}, "visible": "always"},
                {"path": "unlockTime", "label": "Unlocks", "format": "date", "params": {"encoding": "timestamp"}, "visible": "always"}
            ]
        }}}
    });
    let catalog = build(vec![descriptor], vec![token(TOKEN, 6)]).unwrap();

    let bytes = calldata(
        LOCK,
        &[
            address_word(RECIPIENT),
            U256::from(25_000_000u64),
            U256::from(1_800_000_000u64),
        ],
    );
    let (call, _) = review_call(&catalog, &context(&bytes)).unwrap();

    // Every decoded argument is on screen, and none of them borrowed a
    // transfer or allowance guarantee.
    assert_eq!(call.fields.len(), 3);
    assert_eq!(call.action, "other");
    assert_eq!(field(&call, "Beneficiary").value, checksum(RECIPIENT));
    assert_eq!(field(&call, "Amount").value, "25 EXA");
    assert_eq!(
        field(&call, "Unlocks").value,
        "2027-01-15 08:00:00 UTC (1800000000)"
    );
}

#[test]
fn the_four_reasons_each_carry_an_actionable_sentence() {
    let reasons = [
        ReviewReason::CatalogRejected,
        ReviewReason::UnsupportedCall,
        ReviewReason::InvalidPayload,
        ReviewReason::LimitExceeded,
    ];
    let mut codes: Vec<_> = reasons.iter().map(|reason| reason.as_str()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), reasons.len());
    for reason in reasons {
        assert!(reason.owner_action().ends_with('.'), "{}", reason.as_str());
    }
}

/// A token row alone: the built-in profile reads its transfers and approvals
/// with the same rules a full descriptor gets.
#[test]
fn a_token_listed_by_metadata_alone_reads_through_the_built_in_profile() {
    let accepted = build(Vec::new(), vec![token(TOKEN, 6)]).unwrap();

    let transfer = calldata(
        "transfer(address,uint256)",
        &[address_word(RECIPIENT), U256::from(2_500_000u64)],
    );
    let (call, used) = review_call(&accepted, &context(&transfer)).unwrap();
    assert_eq!(call.action, "transfer");
    assert_eq!(call.contract_name.as_deref(), Some("Example Token"));
    assert_eq!(field(&call, "Amount").value, "2.5 EXA");
    assert_eq!(
        call.intent_summary.unwrap().counterparty,
        checksum(RECIPIENT)
    );
    assert!(!call.structural);
    assert_eq!(used.len(), 1);

    // The ERC-20 safety rules still apply: an unlimited allowance warns.
    let unlimited = calldata(
        "approve(address,uint256)",
        &[address_word(RECIPIENT), U256::MAX],
    );
    let (call, _) = review_call(&accepted, &context(&unlimited)).unwrap();
    assert_eq!(call.intent_summary.unwrap().magnitude, "unlimited");
    // And nothing else is admitted.
    let other = calldata(
        "mint(address,uint256)",
        &[address_word(RECIPIENT), U256::from(1u8)],
    );
    assert_eq!(
        review_call(&accepted, &context(&other)).unwrap_err().reason,
        ReviewReason::UnsupportedCall
    );
}

#[test]
fn a_deployment_listed_twice_is_refused() {
    assert_eq!(
        build(Vec::new(), vec![token(TOKEN, 6), token(TOKEN, 18)])
            .unwrap_err()
            .reason,
        ReviewReason::CatalogRejected
    );
    let mut uppercase = token(TOKEN, 6);
    uppercase.address = "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD".into();
    assert!(build(Vec::new(), vec![uppercase]).is_err());
}

#[test]
fn invisible_and_line_breaking_characters_are_refused_in_a_token_name() {
    for (what, injected) in [
        ("line separator", "Real\u{2028}Fake Token"),
        ("paragraph separator", "Real\u{2029}Fake Token"),
        ("zero-width space", "Te\u{200b}ther"),
        ("zero-width non-joiner", "Te\u{200c}ther"),
        ("zero-width joiner", "Te\u{200d}ther"),
        ("soft hyphen", "Te\u{00ad}ther"),
        ("word joiner", "Te\u{2060}ther"),
        ("byte order mark", "Tether\u{feff}"),
        ("arabic letter mark", "Tether\u{061c}"),
        ("invisible times", "Tether\u{2062}"),
        ("interlinear annotation", "Tether\u{fff9}"),
        ("language tag", "Tether\u{e0001}"),
        // Already covered before this change; kept so the set cannot regress.
        ("left-to-right mark", "Tether\u{200e}"),
        ("right-to-left override", "Tether\u{202e}"),
        ("null", "Tether\u{0}"),
    ] {
        let mut row = token(TOKEN, 6);
        row.name = injected.into();
        assert_eq!(
            build(Vec::new(), vec![row]).unwrap_err().reason,
            ReviewReason::CatalogRejected,
            "a token name carrying a {what} must be refused"
        );
    }

    // An ordinary name with non-ASCII letters is still accepted: the rule is
    // about characters that hide themselves, not about scripts.
    let mut row = token(TOKEN, 6);
    row.name = "Tether Über Ünïcødé".into();
    build(Vec::new(), vec![row]).expect("an ordinary non-ASCII token name is not unsafe");
}
