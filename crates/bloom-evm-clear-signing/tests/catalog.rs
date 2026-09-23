//! Catalog trust, withdrawal, freshness, and extension by data alone.

mod support;

use alloy_primitives::U256;
use bloom_broker_api::{
    Base64UrlBytes, DecimalU64, Digest32, EVM_CLEAR_SIGNING_VERIFIER_ID, Token,
};
use bloom_evm_clear_signing::*;
use serde_json::json;
use support::*;

const LOCK: &str = "lock(address beneficiary, uint256 amount, uint256 unlockTime)";

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
    let functions = vec![AdmittedFunction {
        signature: LOCK.into(),
        action_class: ActionClass::Other,
    }];
    let mut catalog = catalog(vec![entry(descriptor, functions, 6)]);
    sign(&mut catalog, &[(1, "publisher-1")]);
    let catalog = accept(&catalog).unwrap();

    let bytes = calldata(
        LOCK,
        &[
            address_word(RECIPIENT),
            U256::from(25_000_000u64),
            U256::from(1_800_000_000u64),
        ],
    );
    let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();

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
fn only_a_snapshot_signed_by_the_trusted_keys_is_accepted() {
    let mut valid = catalog(vec![erc20_entry()]);
    sign(&mut valid, &[(1, "publisher-1")]);
    let size = serde_jcs::to_vec(&valid).unwrap().len();
    valid.accept(size, &[trusted(1, "publisher-1")], 1).unwrap();

    // An untrusted key that signs correctly still does not count.
    let mut stranger = catalog(vec![erc20_entry()]);
    sign(&mut stranger, &[(2, "publisher-1")]);
    assert_eq!(
        stranger
            .accept(size, &[trusted(1, "publisher-1")], 1)
            .unwrap_err()
            .reason,
        ReviewReason::CatalogRejected
    );

    // A forged signature under the right key identity is refused.
    let mut forged = valid.clone();
    forged.signatures[0].signature = Base64UrlBytes::from_bytes(&[9; 64]);
    assert!(
        forged
            .accept(size, &[trusted(1, "publisher-1")], 1)
            .is_err()
    );

    // Content changed after signing.
    let mut tampered = valid.clone();
    tampered.sequence = DecimalU64::new(8);
    assert!(
        tampered
            .accept(size, &[trusted(1, "publisher-1")], 1)
            .is_err()
    );
}

#[test]
fn a_threshold_counts_distinct_trusted_keys_not_signatures() {
    let trust = [trusted(1, "publisher-1"), trusted(2, "publisher-2")];

    let mut both = catalog(vec![erc20_entry()]);
    sign(&mut both, &[(1, "publisher-1"), (2, "publisher-2")]);
    let size = serde_jcs::to_vec(&both).unwrap().len();
    both.accept(size, &trust, 2).unwrap();

    // One maintainer signing twice reaches one, not two.
    let mut doubled = catalog(vec![erc20_entry()]);
    sign(&mut doubled, &[(1, "publisher-1")]);
    let repeated = doubled.signatures[0].clone();
    doubled.signatures.push(repeated);
    assert!(doubled.accept(size, &trust, 2).is_err());
    // And the repetition is refused outright as a duplicate identity.
    assert_eq!(
        doubled.accept(size, &trust, 1).unwrap_err().reason,
        ReviewReason::CatalogRejected
    );

    // A threshold no key set can satisfy is refused rather than lowered.
    let mut single = catalog(vec![erc20_entry()]);
    sign(&mut single, &[(1, "publisher-1")]);
    assert!(single.accept(size, &trust[..1], 2).is_err());
}

#[test]
fn malformed_snapshots_are_refused_before_anything_is_stored() {
    let trust = [trusted(1, "publisher-1")];
    let mut cases: Vec<(&str, ClearSigningCatalog)> = Vec::new();

    let mut duplicate = catalog(vec![erc20_entry(), erc20_entry()]);
    cases.push(("duplicate entry key", duplicate.clone()));

    let mut second = erc20_entry();
    second.contract_address = "0x0111111111111111111111111111111111111111".into();
    second.flattened_descriptor = None;
    second.descriptor_digest = None;
    second.admitted_functions = Vec::new();
    // Sorted ascending is required; this pair is descending.
    cases.push((
        "unsorted entries",
        catalog(vec![erc20_entry(), second.clone()]),
    ));

    let mut uppercase = erc20_entry();
    // A checksummed address is not the lookup key; only lowercase is.
    uppercase.contract_address = "0x111111111111111111111111111111111111Aa11".into();
    cases.push(("noncanonical address", catalog(vec![uppercase])));

    let mut short = erc20_entry();
    short.contract_address = "0x1111".into();
    cases.push(("truncated address", catalog(vec![short])));

    let mut upgradeable = erc20_entry();
    upgradeable.upgradeable = true;
    cases.push((
        "upgradeable without implementation hash",
        catalog(vec![upgradeable]),
    ));

    let mut unpaired = erc20_entry();
    unpaired.descriptor_digest = None;
    cases.push(("descriptor without its digest", catalog(vec![unpaired])));

    let mut empty_interval = catalog(vec![erc20_entry()]);
    empty_interval.expires_at_ms = empty_interval.issued_at_ms.clone();
    cases.push(("empty validity interval", empty_interval));

    let mut wrong_schema = catalog(vec![erc20_entry()]);
    wrong_schema.schema = "bloom.clear-signing-catalog.2".into();
    cases.push(("unknown schema", wrong_schema));

    let mut bad_symbol = erc20_entry();
    bad_symbol.token_metadata.as_mut().unwrap().symbol = "<script>".into();
    cases.push(("unsafe token symbol", catalog(vec![bad_symbol])));

    let mut long_name = erc20_entry();
    long_name.token_metadata.as_mut().unwrap().name = "x".repeat(65);
    cases.push(("oversized token name", catalog(vec![long_name])));

    for (name, mut candidate) in cases {
        sign(&mut candidate, &[(1, "publisher-1")]);
        let size = serde_jcs::to_vec(&candidate).unwrap().len();
        assert!(
            candidate.accept(size, &trust, 1).is_err(),
            "`{name}` must be refused"
        );
    }

    // Bounds are checked against the encoded size, not the entry count alone.
    duplicate.entries.truncate(1);
    sign(&mut duplicate, &[(1, "publisher-1")]);
    assert_eq!(
        duplicate
            .accept(CATALOG_MAX_BYTES + 1, &trust, 1)
            .unwrap_err()
            .reason,
        ReviewReason::LimitExceeded
    );
}

fn evidence(catalog: &AcceptedCatalog, digest: &Digest32) -> ClearSigningEvidence {
    let entries = vec![SelectedEntry::of(catalog.entry(CHAIN_ID, TOKEN).unwrap())];
    ClearSigningEvidence::new(catalog, digest, entries)
}

#[test]
fn a_withdrawn_or_changed_entry_invalidates_an_unsigned_review() {
    let digest = Digest32::from_bytes([5; 32]);
    let accepted = accepted_erc20();
    let frozen = evidence(&accepted, &digest);
    frozen
        .recheck(Some(&accepted), &digest, NOW_MS, 86_400_000)
        .unwrap();

    // A complete newer snapshot that omits the entry withdraws it.
    let mut withdrawn = catalog(Vec::new());
    withdrawn.sequence = DecimalU64::new(8);
    sign(&mut withdrawn, &[(1, "publisher-1")]);
    let withdrawn = accept(&withdrawn).unwrap();
    assert_eq!(
        frozen
            .recheck(Some(&withdrawn), &digest, NOW_MS, 86_400_000)
            .unwrap_err()
            .reason,
        ReviewReason::ReviewChanged
    );

    // A changed entry, including one that only moved its observation time.
    let mut moved = erc20_entry();
    moved.observed_at_ms = DecimalU64::new(NOW_MS - 500);
    let mut changed = catalog(vec![moved]);
    changed.sequence = DecimalU64::new(8);
    sign(&mut changed, &[(1, "publisher-1")]);
    let changed = accept(&changed).unwrap();
    assert_eq!(
        frozen
            .recheck(Some(&changed), &digest, NOW_MS, 86_400_000)
            .unwrap_err()
            .reason,
        ReviewReason::ReviewChanged
    );

    // A verifier upgrade that changes the source digest.
    assert_eq!(
        frozen
            .recheck(
                Some(&accepted),
                &Digest32::from_bytes([6; 32]),
                NOW_MS,
                86_400_000
            )
            .unwrap_err()
            .reason,
        ReviewReason::ReviewChanged
    );

    // No catalog at all.
    assert_eq!(
        frozen
            .recheck(None, &digest, NOW_MS, 86_400_000)
            .unwrap_err()
            .reason,
        ReviewReason::CatalogUnavailable
    );
}

#[test]
fn republishing_an_old_observation_does_not_make_it_fresh() {
    let digest = Digest32::from_bytes([5; 32]);
    let mut stale = erc20_entry();
    stale.observed_at_ms = DecimalU64::new(NOW_MS - 90_000_000);
    let mut catalog = catalog(vec![stale]);
    // A brand new snapshot, issued now, carrying the same old observation.
    catalog.sequence = DecimalU64::new(99);
    sign(&mut catalog, &[(1, "publisher-1")]);
    let accepted = accept(&catalog).unwrap();
    let frozen = evidence(&accepted, &digest);

    assert_eq!(
        frozen
            .recheck(Some(&accepted), &digest, NOW_MS, 86_400_000)
            .unwrap_err()
            .reason,
        ReviewReason::EvidenceExpired
    );
}

#[test]
fn permitted_expiry_is_the_smallest_of_catalog_and_observation_bounds() {
    let digest = Digest32::from_bytes([5; 32]);
    let accepted = accepted_erc20();
    let frozen = evidence(&accepted, &digest);

    // The catalog runs to NOW+24h and the observation is 1s old, so a 24h
    // maximum age binds one second tighter than the catalog does.
    assert_eq!(
        frozen.permitted_expiry_ms(86_400_000),
        NOW_MS - 1000 + 86_400_000
    );
    // A short maximum age binds instead.
    assert_eq!(frozen.permitted_expiry_ms(60_000), NOW_MS - 1000 + 60_000);
    // A huge maximum age cannot wrap past the catalog's own expiry.
    assert_eq!(frozen.permitted_expiry_ms(u64::MAX), NOW_MS + 86_400_000);
}

#[test]
fn an_expired_catalog_stops_authorizing_without_any_network_access() {
    let accepted = accepted_erc20();
    accepted.check_validity(NOW_MS).unwrap();
    assert_eq!(
        accepted
            .check_validity(NOW_MS + 86_400_001)
            .unwrap_err()
            .reason,
        ReviewReason::EvidenceExpired
    );
    // A snapshot dated in the future cannot pre-authorize either.
    assert_eq!(
        accepted.check_validity(NOW_MS - 20_000).unwrap_err().reason,
        ReviewReason::CatalogRejected
    );
}

#[test]
fn the_nine_reasons_each_carry_an_actionable_sentence() {
    let reasons = [
        ReviewReason::CatalogUnavailable,
        ReviewReason::CatalogRejected,
        ReviewReason::EvidenceExpired,
        ReviewReason::UnsupportedCall,
        ReviewReason::InvalidPayload,
        ReviewReason::PolicyDenied,
        ReviewReason::ReviewChanged,
        ReviewReason::LimitExceeded,
        ReviewReason::ClockUntrusted,
    ];
    let mut codes: Vec<_> = reasons.iter().map(|reason| reason.as_str()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), reasons.len());
    for reason in reasons {
        assert!(reason.owner_action().ends_with('.'), "{}", reason.as_str());
    }
}

#[test]
fn a_token_only_entry_supplies_units_without_admitting_any_call() {
    let mut token_only = erc20_entry();
    token_only.admitted_functions = Vec::new();
    token_only.flattened_descriptor = None;
    token_only.descriptor_digest = None;
    let mut catalog = catalog(vec![token_only]);
    sign(&mut catalog, &[(1, "publisher-1")]);
    let accepted = accept(&catalog).unwrap();

    assert!(
        accepted
            .entry(CHAIN_ID, TOKEN)
            .unwrap()
            .token_metadata
            .is_some()
    );
    let bytes = calldata(
        "transfer(address _to, uint256 _value)",
        &[address_word(RECIPIENT), U256::from(1u8)],
    );
    assert_eq!(
        review_call(&accepted, &context(&bytes, false))
            .unwrap_err()
            .reason,
        ReviewReason::UnsupportedCall
    );
}

#[test]
fn the_catalog_identity_a_wallet_trusts_is_part_of_the_frozen_review() {
    let digest = Digest32::from_bytes([5; 32]);
    let accepted = accepted_erc20();
    let frozen = evidence(&accepted, &digest);
    assert_eq!(frozen.assurance, TRUSTED_DESCRIPTION);
    assert_eq!(frozen.verifier_id, EVM_CLEAR_SIGNING_VERIFIER_ID);

    let mut renamed = catalog(vec![erc20_entry()]);
    renamed.catalog_id = Token::new("other-catalog").unwrap();
    sign(&mut renamed, &[(1, "publisher-1")]);
    let renamed = accept(&renamed).unwrap();
    assert_eq!(
        frozen
            .recheck(Some(&renamed), &digest, NOW_MS, 86_400_000)
            .unwrap_err()
            .reason,
        ReviewReason::ReviewChanged
    );
}
