//! One strict generic decoder, and the transfer/allowance rules over it.

mod support;

use alloy_primitives::U256;
use bloom_evm_clear_signing::*;
use support::*;

fn transfer_bytes(to: &str, amount: U256) -> Vec<u8> {
    calldata(
        "transfer(address _to, uint256 _value)",
        &[address_word(to), amount],
    )
}

fn approve_bytes(spender: &str, amount: U256) -> Vec<u8> {
    calldata(
        "approve(address _spender, uint256 _value)",
        &[address_word(spender), amount],
    )
}

#[test]
fn a_transfer_shows_the_actual_recipient_and_exact_amount() {
    let catalog = accepted_erc20();
    let bytes = transfer_bytes(RECIPIENT, U256::from(100_000_000u64));
    let (call, used) = review_call(&catalog, &context(&bytes, false)).unwrap();

    assert_eq!(call.action, "transfer");
    assert_eq!(
        call.function_signature,
        "transfer(address _to, uint256 _value)"
    );
    assert_eq!(field(&call, "To").value, checksum(RECIPIENT));
    // Six decimals, exact integer arithmetic: 100000000 base units.
    assert_eq!(field(&call, "Amount").value, "100 EXA");
    assert_eq!(field(&call, "Amount").raw, "100000000");
    // The token is identified by its contract, never by the symbol alone.
    assert_eq!(call.token.as_ref().unwrap().address, checksum(TOKEN));
    assert_eq!(used.len(), 1);
    assert_eq!(used[0].contract_address, TOKEN);
    // Intent is supplemental and never becomes the heading.
    assert_eq!(call.intent.as_deref(), Some("Send"));
}

#[test]
fn an_allowance_shows_the_spender_and_the_total_it_sets() {
    let catalog = accepted_erc20();
    let bytes = approve_bytes(RECIPIENT, U256::from(250u64));
    let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();

    assert_eq!(call.action, "allowance");
    assert_eq!(field(&call, "Spender").value, checksum(RECIPIENT));
    assert_eq!(field(&call, "Amount").value, "0.00025 EXA");
    assert!(
        call.warnings
            .iter()
            .any(|warning| warning.contains("move your tokens later")),
        "the later-spending warning is mandatory: {:?}",
        call.warnings
    );
    assert!(
        call.warnings
            .iter()
            .any(|warning| warning.contains("not added to any existing allowance")),
        "a finite allowance sets a total, not an increment: {:?}",
        call.warnings
    );
}

#[test]
fn a_zero_allowance_is_shown_as_clearing_it() {
    let catalog = accepted_erc20();
    let bytes = approve_bytes(RECIPIENT, U256::ZERO);
    let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();
    assert_eq!(field(&call, "Amount").value, "0 EXA");
    assert!(
        call.warnings
            .iter()
            .any(|warning| warning.contains("clearing it"))
    );
}

#[test]
fn a_maximum_allowance_is_denied_until_policy_enables_it() {
    let catalog = accepted_erc20();
    let bytes = approve_bytes(RECIPIENT, U256::MAX);

    let denied = review_call(&catalog, &context(&bytes, false)).unwrap_err();
    assert_eq!(denied.reason, ReviewReason::PolicyDenied);

    // Enabling the policy does not approve the transaction: it only makes the
    // request reviewable, and the exact amount stays visible.
    let (call, _) = review_call(&catalog, &context(&bytes, true)).unwrap();
    assert!(
        call.warnings
            .iter()
            .any(|warning| warning.contains("UNLIMITED ALLOWANCE"))
    );
    assert_eq!(field(&call, "Amount").raw, U256::MAX.to_string());
}

#[test]
fn a_large_finite_allowance_is_never_relabelled_unlimited() {
    // The registry template's threshold would have called this one
    // "unlimited". The admitted derivative has no threshold, so the exact
    // amount is shown and Bloom's own maximum-U256 rule does not fire.
    let catalog = accepted_erc20();
    let large = U256::from(2u8).pow(U256::from(255u8));
    let bytes = approve_bytes(RECIPIENT, large);
    let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();
    assert_eq!(field(&call, "Amount").raw, large.to_string());
    assert!(
        !call
            .warnings
            .iter()
            .any(|warning| warning.contains("UNLIMITED"))
    );
}

#[test]
fn trailing_dirty_and_truncated_calldata_are_all_refused() {
    let catalog = accepted_erc20();
    let valid = transfer_bytes(RECIPIENT, U256::from(1u8));
    review_call(&catalog, &context(&valid, false)).unwrap();

    let mut trailing = valid.clone();
    trailing.extend_from_slice(&[0; 32]);
    let mut dirty = valid.clone();
    // A nonzero byte in an address argument's left padding.
    dirty[4] = 1;
    let truncated = &valid[..valid.len() - 1];
    let mut wrong_selector = valid.clone();
    wrong_selector[0] ^= 0xff;

    for (name, bytes) in [
        ("trailing", trailing.as_slice()),
        ("dirty padding", dirty.as_slice()),
        ("truncated", truncated),
    ] {
        let error = review_call(&catalog, &context(bytes, false)).unwrap_err();
        assert_eq!(error.reason, ReviewReason::InvalidPayload, "{name}");
    }
    // An unknown selector is not malformed, it is undescribed.
    assert_eq!(
        review_call(&catalog, &context(&wrong_selector, false))
            .unwrap_err()
            .reason,
        ReviewReason::UnsupportedCall
    );
}

#[test]
fn a_narrow_integer_with_high_bits_set_is_refused() {
    // `uint64` occupies one word; a word whose top bits are set does not
    // re-encode to the same bytes, so the round-trip refuses it.
    let descriptor = serde_json::json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "display": {"formats": {"cap(uint64 limit)": {
            "fields": [{"path": "limit", "label": "Limit", "format": "raw", "visible": "always"}]
        }}}
    });
    let functions = vec![AdmittedFunction {
        signature: "cap(uint64 limit)".into(),
        action_class: ActionClass::Other,
    }];
    let mut catalog = catalog(vec![entry(descriptor, functions, 6)]);
    sign(&mut catalog, &[(1, "publisher-1")]);
    let catalog = accept(&catalog).unwrap();

    let ok = calldata("cap(uint64 limit)", &[U256::from(u64::MAX)]);
    review_call(&catalog, &context(&ok, false)).unwrap();

    let overflowing = calldata(
        "cap(uint64 limit)",
        &[U256::from(u64::MAX) + U256::from(1u8)],
    );
    assert_eq!(
        review_call(&catalog, &context(&overflowing, false))
            .unwrap_err()
            .reason,
        ReviewReason::InvalidPayload
    );
}

#[test]
fn a_contract_call_carrying_native_value_is_refused() {
    let catalog = accepted_erc20();
    let bytes = transfer_bytes(RECIPIENT, U256::from(1u8));
    let mut context = context(&bytes, false);
    context.value = U256::from(1u8);
    assert_eq!(
        review_call(&catalog, &context).unwrap_err().reason,
        ReviewReason::InvalidPayload
    );
}

#[test]
fn the_token_contract_is_not_a_valid_recipient_and_zero_never_is() {
    let catalog = accepted_erc20();
    for bytes in [
        transfer_bytes(TOKEN, U256::from(1u8)),
        transfer_bytes(
            "0x0000000000000000000000000000000000000000",
            U256::from(1u8),
        ),
        approve_bytes(
            "0x0000000000000000000000000000000000000000",
            U256::from(1u8),
        ),
    ] {
        assert_eq!(
            review_call(&catalog, &context(&bytes, false))
                .unwrap_err()
                .reason,
            ReviewReason::InvalidPayload
        );
    }
}

#[test]
fn a_zero_amount_transfer_is_shown_honestly_rather_than_hidden() {
    let catalog = accepted_erc20();
    let bytes = transfer_bytes(RECIPIENT, U256::ZERO);
    let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();
    assert_eq!(field(&call, "Amount").value, "0 EXA");
}

#[test]
fn decimals_zero_six_eighteen_and_255_all_format_exactly() {
    for (decimals, amount, expected) in [
        (0u8, "1", "1 EXA"),
        (6, "1", "0.000001 EXA"),
        (6, "1000000", "1 EXA"),
        (18, "1000000000000000000", "1 EXA"),
        (18, "1", "0.000000000000000001 EXA"),
    ] {
        let mut catalog = catalog(vec![entry(erc20_descriptor(), erc20_functions(), decimals)]);
        sign(&mut catalog, &[(1, "publisher-1")]);
        let catalog = accept(&catalog).unwrap();
        let bytes = transfer_bytes(RECIPIENT, amount.parse::<U256>().unwrap());
        let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();
        assert_eq!(
            field(&call, "Amount").value,
            expected,
            "decimals {decimals}"
        );
    }
    // 255 decimals is representable and is not rounded to zero.
    let mut catalog = catalog(vec![entry(erc20_descriptor(), erc20_functions(), 255)]);
    sign(&mut catalog, &[(1, "publisher-1")]);
    let catalog = accept(&catalog).unwrap();
    let bytes = transfer_bytes(RECIPIENT, U256::from(1u8));
    let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();
    let value = &field(&call, "Amount").value;
    assert!(
        value.starts_with("0.") && value.ends_with("1 EXA"),
        "{value}"
    );
}

#[test]
fn two_tokens_sharing_a_symbol_stay_distinct_by_contract() {
    let mut second = erc20_entry();
    second.contract_address = "0x3333333333333333333333333333333333333333".into();
    let descriptor = serde_json::json!({
        "context": {"contract": {"deployments": [
            {"chainId": CHAIN_ID, "address": "0x3333333333333333333333333333333333333333"}]}},
        "display": {"formats": {"transfer(address _to, uint256 _value)": {
            "fields": [
                {"path": "_to", "label": "To", "format": "addressName", "visible": "always"},
                {"path": "_value", "label": "Amount", "format": "tokenAmount",
                 "params": {"tokenPath": "@.to"}, "visible": "always"}
            ]
        }}}
    });
    second.descriptor_digest = Some(descriptor_digest(&descriptor).unwrap());
    second.flattened_descriptor = Some(descriptor);
    second.admitted_functions = vec![AdmittedFunction {
        signature: "transfer(address _to, uint256 _value)".into(),
        action_class: ActionClass::Transfer,
    }];

    let mut catalog = catalog(vec![erc20_entry(), second]);
    sign(&mut catalog, &[(1, "publisher-1")]);
    let catalog = accept(&catalog).unwrap();

    let bytes = transfer_bytes(RECIPIENT, U256::from(1u8));
    let (first, _) = review_call(&catalog, &context(&bytes, false)).unwrap();
    let mut other = context(&bytes, false);
    other.to = "0x3333333333333333333333333333333333333333"
        .parse()
        .unwrap();
    let (second, _) = review_call(&catalog, &other).unwrap();

    assert_eq!(
        first.token.as_ref().unwrap().symbol,
        second.token.as_ref().unwrap().symbol
    );
    assert_ne!(first.token.unwrap().address, second.token.unwrap().address);
}

#[test]
fn a_call_to_an_undescribed_contract_is_unsupported_not_guessed() {
    let catalog = accepted_erc20();
    let bytes = transfer_bytes(RECIPIENT, U256::from(1u8));
    let mut elsewhere = context(&bytes, false);
    elsewhere.to = "0x9999999999999999999999999999999999999999"
        .parse()
        .unwrap();
    assert_eq!(
        review_call(&catalog, &elsewhere).unwrap_err().reason,
        ReviewReason::UnsupportedCall
    );

    let mut wrong_chain = context(&bytes, false);
    wrong_chain.chain_id = 8453;
    assert_eq!(
        review_call(&catalog, &wrong_chain).unwrap_err().reason,
        ReviewReason::UnsupportedCall
    );
}

#[test]
fn a_token_without_signed_decimals_cannot_display_an_amount() {
    let mut entry = erc20_entry();
    entry.token_metadata = None;
    let mut catalog = catalog(vec![entry]);
    sign(&mut catalog, &[(1, "publisher-1")]);
    let catalog = accept(&catalog).unwrap();
    let bytes = transfer_bytes(RECIPIENT, U256::from(1u8));
    assert_eq!(
        review_call(&catalog, &context(&bytes, false))
            .unwrap_err()
            .reason,
        ReviewReason::UnsupportedCall
    );
}

/// A scalar-only third function: the token is an address argument, not the
/// contract being called. The same generic decoder handles it, and the
/// decimals come from the catalog entry the decoded address names.
#[test]
fn a_token_named_by_an_argument_is_resolved_from_the_signed_catalog() {
    let catalog = accepted_vault();
    let bytes = calldata(
        VAULT_DEPOSIT,
        &[
            address_word(TOKEN),
            U256::from(2_500_000u64),
            address_word(RECIPIENT),
        ],
    );
    let (call, used) = review_call(&catalog, &vault_context(&bytes)).unwrap();

    assert_eq!(call.contract, checksum(VAULT));
    assert_eq!(field(&call, "Token").value, checksum(TOKEN));
    // Six decimals from the token's own entry, not the vault's.
    assert_eq!(field(&call, "Amount").value, "2.5 EXA");
    assert_eq!(field(&call, "Credited to").value, checksum(RECIPIENT));

    // Both entries the reading depended on are evidence, in selection order.
    assert_eq!(used.len(), 2);
    assert_eq!(used[0].contract_address, VAULT);
    assert_eq!(used[1].contract_address, TOKEN);
}

#[test]
fn a_token_the_catalog_does_not_describe_cannot_be_shown() {
    let catalog = accepted_vault();
    let bytes = calldata(
        VAULT_DEPOSIT,
        &[
            address_word(RECIPIENT),
            U256::from(1u64),
            address_word(RECIPIENT),
        ],
    );
    let error = review_call(&catalog, &vault_context(&bytes)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::UnsupportedCall);
    assert!(
        error.detail.contains("no signed description of the token"),
        "{error}"
    );
}

#[test]
fn withdrawing_or_changing_the_named_token_invalidates_the_frozen_review() {
    let accepted = accepted_vault();
    let bytes = calldata(
        VAULT_DEPOSIT,
        &[
            address_word(TOKEN),
            U256::from(2_500_000u64),
            address_word(RECIPIENT),
        ],
    );
    let (_, used) = review_call(&accepted, &vault_context(&bytes)).unwrap();
    let verifier = bloom_broker_api::Digest32::from_bytes([7; 32]);
    let evidence = ClearSigningEvidence::new(&accepted, &verifier, used);
    evidence
        .recheck(Some(&accepted), &verifier, NOW_MS, 86_400_000)
        .expect("nothing has changed yet");

    // Withdrawing the token entry leaves the vault entry intact, and the
    // review is still invalid: the amount was denominated in that token.
    let mut without_token = catalog(vec![vault_entry()]);
    sign(&mut without_token, &[(1, "publisher-1")]);
    let without_token = accept(&without_token).unwrap();
    let error = evidence
        .recheck(Some(&without_token), &verifier, NOW_MS, 86_400_000)
        .unwrap_err();
    assert_eq!(error.reason, ReviewReason::ReviewChanged);
    assert!(error.detail.contains(TOKEN), "{error}");

    // So does changing its decimals, which would change what "2.5 EXA" means.
    let mut redenominated = catalog(vec![
        entry(erc20_descriptor(), erc20_functions(), 8),
        vault_entry(),
    ]);
    sign(&mut redenominated, &[(1, "publisher-1")]);
    let redenominated = accept(&redenominated).unwrap();
    let error = evidence
        .recheck(Some(&redenominated), &verifier, NOW_MS, 86_400_000)
        .unwrap_err();
    assert_eq!(error.reason, ReviewReason::ReviewChanged);
    assert!(error.detail.contains(TOKEN), "{error}");
}
