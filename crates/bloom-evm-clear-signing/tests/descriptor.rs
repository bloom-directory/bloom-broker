//! What the admitted ERC-7730 subset accepts, and what it refuses.

mod support;

use alloy_primitives::U256;
use bloom_evm_clear_signing::*;
use serde_json::{Value, json};
use support::*;

const SIX: &str = "configure(address operator, uint256 fee, uint256 native, uint256 deadline, uint8 mode, bytes32 tag)";

fn six_format_descriptor() -> Value {
    json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "metadata": {"contractName": "Example Token", "enums": {"mode": {"0": "Off", "1": "On"}}},
        "display": {"formats": {SIX: {
            "intent": "Configure",
            "fields": [
                {"path": "operator", "label": "Operator", "format": "addressName", "visible": "always"},
                {"path": "fee", "label": "Fee", "format": "tokenAmount", "params": {"tokenPath": "@.to"}},
                {"path": "native", "label": "Deposit", "format": "amount"},
                {"path": "deadline", "label": "Deadline", "format": "date", "params": {"encoding": "timestamp"}},
                {"path": "mode", "label": "Mode", "format": "enum", "params": {"$ref": "$.metadata.enums.mode"}},
                {"path": "tag", "label": "Tag", "format": "raw"}
            ]
        }}}
    })
}

fn six_catalog(descriptor: Value) -> Result<Catalog, ReviewError> {
    build(vec![descriptor], vec![token(TOKEN, 6)])
}

fn six_calldata(mode: u64, deadline: u64) -> Vec<u8> {
    calldata(
        SIX,
        &[
            address_word(RECIPIENT),
            U256::from(1_500_000u64),
            U256::from(2_000_000_000_000_000_000u64),
            U256::from(deadline),
            U256::from(mode),
            U256::from(0xabu8) << 248,
        ],
    )
}

#[test]
fn all_six_formats_render_from_authenticated_data() {
    let catalog = six_catalog(six_format_descriptor()).unwrap();
    let bytes = six_calldata(1, 1_760_000_000);
    let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();

    assert_eq!(field(&call, "Operator").value, checksum(RECIPIENT));
    assert_eq!(field(&call, "Fee").value, "1.5 EXA");
    assert_eq!(field(&call, "Deposit").value, "2 ETH");
    assert_eq!(
        field(&call, "Deadline").value,
        "2025-10-09 08:53:20 UTC (1760000000)"
    );
    // The label never replaces the raw value it stands for.
    assert_eq!(field(&call, "Mode").value, "On (1)");
    assert_eq!(field(&call, "Mode").raw, "1");
    assert!(field(&call, "Tag").value.starts_with("0xab"));
    // A neutral contract-call class invents no economic guarantee.
    assert_eq!(call.action, "other");
    assert!(call.token.is_some());
}

#[test]
fn each_format_has_an_invalid_input_that_fails_review() {
    let accepted = six_catalog(six_format_descriptor()).unwrap();

    // enum: a value the signed map does not label.
    let unknown_mode = six_calldata(2, 1_760_000_000);
    assert_eq!(
        review_call(&accepted, &context(&unknown_mode, false))
            .unwrap_err()
            .reason,
        ReviewReason::UnsupportedCall
    );

    // date: beyond the representable range.
    let far_future = six_calldata(1, 253_402_300_800);
    assert_eq!(
        review_call(&accepted, &context(&far_future, false))
            .unwrap_err()
            .reason,
        ReviewReason::UnsupportedCall
    );

    // amount: no authenticated native units for this chain.
    let bytes = six_calldata(1, 1_760_000_000);
    let mut without_native = context(&bytes, false);
    without_native.native = None;
    assert_eq!(
        review_call(&accepted, &without_native).unwrap_err().reason,
        ReviewReason::UnsupportedCall
    );

    // tokenAmount: no listed decimals for the token.
    let catalog = build(vec![six_format_descriptor()], Vec::new()).unwrap();
    assert_eq!(
        review_call(&catalog, &context(&bytes, false))
            .unwrap_err()
            .reason,
        ReviewReason::UnsupportedCall
    );
}

/// Each case replaces one instruction in an otherwise valid descriptor. All
/// of them make the descriptor unusable rather than partly rendered.
#[test]
fn unsupported_instructions_make_a_descriptor_unusable() {
    type Mutation = (&'static str, Box<dyn Fn(&mut Value)>);
    let cases: Vec<Mutation> = vec![
        (
            "unresolved include",
            Box::new(|value: &mut Value| {
                value["includes"] = json!("https://example.invalid/base.json");
            }),
        ),
        (
            "deprecated inline ABI",
            Box::new(|value: &mut Value| {
                value["context"]["contract"]["abi"] = json!([]);
            }),
        ),
        (
            "factory binding",
            Box::new(|value: &mut Value| {
                value["context"]["contract"]["factory"] =
                    json!({"deployments": [], "deployEvent": "Deployed(address)"});
            }),
        ),
        (
            "threshold replacement",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][1]["params"]["threshold"] =
                    json!("0x8000000000000000000000000000000000000000000000000000000000000000");
            }),
        ),
        (
            "unlimited message substitution",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][1]["params"]["message"] =
                    json!("Unlimited");
            }),
        ),
        (
            "token path naming an argument that is not an address",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][1]["params"]["tokenPath"] =
                    json!("deadline");
            }),
        ),
        (
            "token path naming no argument at all",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][1]["params"]["tokenPath"] =
                    json!("missing");
            }),
        ),
        (
            "token path reaching outside this call",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][1]["params"]["tokenPath"] =
                    json!("@.value");
            }),
        ),
        (
            "hidden field",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][5]["visible"] = json!("never");
            }),
        ),
        (
            "conditional field",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][5]["visible"] = json!({"ifNotIn": [0]});
            }),
        ),
        (
            "uncovered argument",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }),
        ),
        (
            "constant standing in for an argument",
            Box::new(|value: &mut Value| {
                let field = &mut value["display"]["formats"][SIX]["fields"][5];
                field["value"] = json!("0xab");
            }),
        ),
        (
            "shared definition reference",
            Box::new(|value: &mut Value| {
                value["display"]["definitions"] =
                    json!({"shared": {"label": "x", "format": "raw"}});
            }),
        ),
        (
            "interpolated intent",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["interpolatedIntent"] =
                    json!("Configure {operator}");
            }),
        ),
        (
            "unsupported unit format",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][1]["format"] = json!("unit");
            }),
        ),
        (
            "embedded calldata format",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][5]["format"] = json!("calldata");
            }),
        ),
        (
            "block-height date",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][3]["params"]["encoding"] =
                    json!("blockheight");
            }),
        ),
        (
            "enum map that does not exist",
            Box::new(|value: &mut Value| {
                value["display"]["formats"][SIX]["fields"][4]["params"]["$ref"] =
                    json!("$.metadata.enums.missing");
            }),
        ),
        (
            "document-supplied token units",
            Box::new(|value: &mut Value| {
                value["metadata"]["token"] =
                    json!({"name": "Fake", "ticker": "FAKE", "decimals": 2});
            }),
        ),
    ];
    for (name, mutate) in cases {
        let mut descriptor = six_format_descriptor();
        mutate(&mut descriptor);
        let error = six_catalog(descriptor)
            .err()
            .unwrap_or_else(|| panic!("`{name}` must make the descriptor unusable"));
        assert!(
            matches!(
                error.reason,
                ReviewReason::CatalogRejected | ReviewReason::LimitExceeded
            ),
            "`{name}` produced {error}"
        );
    }
}

fn admit_one(signature: &str, fields: Value) -> Result<Catalog, ReviewError> {
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "display": {"formats": {signature: {"fields": fields}}}
    });
    build(vec![descriptor], vec![token(TOKEN, 6)])
}

#[test]
fn strings_signed_integers_and_fixed_or_nested_arrays_are_outside_the_subset() {
    for (signature, path) in [
        ("note(string text)", "text"),
        ("pair(uint256[2] amounts)", "amounts"),
        ("grid(uint256[][] cells)", "cells.[]"),
        ("signed(int256 delta)", "delta"),
    ] {
        let error = admit_one(
            signature,
            json!([{"path": path, "label": "X", "format": "raw"}]),
        )
        .expect_err(signature);
        assert!(
            error.detail.contains("outside the supported"),
            "{signature}: {error}"
        );
    }
}

#[test]
fn bytes_arrays_and_must_match_rules_are_admitted_in_their_one_shape() {
    const SIGNATURE: &str = "f(address[] owners, bytes blob, uint8 mode)";
    let fields = |owners: Value, blob: Value, mode: Value| json!([owners, blob, mode]);
    let owners = json!({"path": "owners.[]", "label": "Owner", "format": "addressName"});
    let blob = json!({"path": "blob", "label": "Blob", "format": "raw"});
    let mode = json!({"path": "mode", "label": "Mode", "visible": {"mustMatch": [0]}});
    admit_one(
        SIGNATURE,
        fields(owners.clone(), blob.clone(), mode.clone()),
    )
    .unwrap();

    let refused = [
        (
            "an array without .[]",
            json!({"path": "owners", "label": "Owner", "format": "addressName"}),
            blob.clone(),
            mode.clone(),
        ),
        (
            "a token amount per element",
            json!({"path": "owners.[]", "label": "Owner", "format": "tokenAmount", "params": {"tokenPath": "@.to"}}),
            blob.clone(),
            mode.clone(),
        ),
        (
            "a mustMatch on an array",
            json!({"path": "owners.[]", "label": "Owner", "visible": {"mustMatch": []}}),
            blob.clone(),
            mode.clone(),
        ),
        (
            "calldata on a non-bytes argument",
            owners.clone(),
            blob.clone(),
            json!({"path": "mode", "label": "Mode", "format": "calldata", "params": {"calleePath": "@.to"}}),
        ),
        (
            "calldata without a callee",
            owners.clone(),
            json!({"path": "blob", "label": "Blob", "format": "calldata"}),
            mode.clone(),
        ),
        (
            "calldata with a redirected selector",
            owners.clone(),
            json!({"path": "blob", "label": "Blob", "format": "calldata", "params": {"calleePath": "@.to", "selector": "0x12345678"}}),
            mode.clone(),
        ),
        (
            "calldata naming a non-address callee",
            owners.clone(),
            json!({"path": "blob", "label": "Blob", "format": "calldata", "params": {"calleePath": "mode"}}),
            mode.clone(),
        ),
        (
            "a scalar addressed with .[]",
            owners.clone(),
            blob.clone(),
            json!({"path": "mode.[]", "label": "Mode", "format": "raw"}),
        ),
        (
            "a mustMatch that also formats",
            owners.clone(),
            blob.clone(),
            json!({"path": "mode", "label": "Mode", "format": "raw", "visible": {"mustMatch": [0]}}),
        ),
        (
            "a mustMatch value of the wrong type",
            owners.clone(),
            blob.clone(),
            json!({"path": "mode", "label": "Mode", "visible": {"mustMatch": ["zero"]}}),
        ),
        (
            "an empty mustMatch",
            owners.clone(),
            blob.clone(),
            json!({"path": "mode", "label": "Mode", "visible": {"mustMatch": []}}),
        ),
        (
            "a conditional rule beside mustMatch",
            owners,
            blob,
            json!({"path": "mode", "label": "Mode", "visible": {"mustMatch": [0], "ifNotIn": [1]}}),
        ),
    ];
    for (name, owners, blob, mode) in refused {
        let error = admit_one(SIGNATURE, fields(owners, blob, mode))
            .err()
            .unwrap_or_else(|| panic!("{name} must be refused"));
        assert_eq!(
            error.reason,
            ReviewReason::CatalogRejected,
            "{name}: {error}"
        );
    }
}

#[test]
fn a_renamed_or_reclassified_erc20_call_cannot_bypass_allowance_policy() {
    // `approve` relabelled "Login" and signed as an ordinary contract call.
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "display": {"formats": {"approve(address _spender, uint256 _value)": {
            "intent": "Login",
            "fields": [
                {"path": "_spender", "label": "Site", "format": "addressName"},
                {"path": "_value", "label": "Session", "format": "raw"}
            ]
        }}}
    });
    // The class comes from the signature, not the descriptor, so the
    // allowance rules still run and still refuse an unlimited allowance.
    let catalog = build(vec![descriptor], vec![token(TOKEN, 6)]).unwrap();
    let bytes = calldata(
        "approve(address _spender, uint256 _value)",
        &[address_word(RECIPIENT), U256::MAX],
    );
    let error = review_call(&catalog, &context(&bytes, false)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::PolicyDenied, "{error}");
}

#[test]
fn an_unrelated_call_cannot_borrow_the_transfer_screen() {
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "display": {"formats": {"donate(address _to, uint256 _value, uint256 _tip)": {
            "fields": [
                {"path": "_to", "label": "To", "format": "addressName"},
                {"path": "_value", "label": "Amount", "format": "tokenAmount", "params": {"tokenPath": "@.to"}},
                {"path": "_tip", "label": "Tip", "format": "tokenAmount", "params": {"tokenPath": "@.to"}}
            ]
        }}}
    });
    let catalog = build(vec![descriptor], vec![token(TOKEN, 6)]).unwrap();
    let bytes = calldata(
        "donate(address _to, uint256 _value, uint256 _tip)",
        &[address_word(RECIPIENT), U256::from(1u8), U256::from(2u8)],
    );
    let (call, _) = review_call(&catalog, &context(&bytes, false)).unwrap();
    assert_eq!(call.action, "other");
    assert!(call.intent_summary.is_none());
}

#[test]
fn two_format_keys_selecting_the_same_function_are_ambiguous() {
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "display": {"formats": {
            "transfer(address _to, uint256 _value)": {
                "fields": [
                    {"path": "_to", "label": "To", "format": "addressName"},
                    {"path": "_value", "label": "Amount", "format": "tokenAmount", "params": {"tokenPath": "@.to"}}
                ]
            },
            "transfer(address recipient, uint256 amount)": {
                "fields": [
                    {"path": "recipient", "label": "To", "format": "addressName"},
                    {"path": "amount", "label": "Amount", "format": "raw"}
                ]
            }
        }}
    });
    assert!(build(vec![descriptor], Vec::new()).is_err());
}

#[test]
fn a_tuple_argument_is_refused_because_no_path_can_reach_it() {
    // Uniswap's `exactInputSingle` is shaped like this. The signature parser
    // that format keys are written for drops the component names, so the
    // router slice needs a second signed input before tuples can be read.
    let signature = "settle((address,uint256) terms, bool finalize)";
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "display": {"formats": {signature: {
            "fields": [
                {"path": "terms", "label": "Terms", "format": "raw"},
                {"path": "finalize", "label": "Final", "format": "raw"}
            ]
        }}}
    });
    let error = build(vec![descriptor], Vec::new()).unwrap_err();
    assert_eq!(error.reason, ReviewReason::CatalogRejected);
    assert!(error.detail.contains("tuple"), "{error}");
}

#[test]
fn a_noncanonical_boolean_word_does_not_survive_the_round_trip() {
    let signature = "toggle(bool on)";
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "display": {"formats": {signature: {
            "fields": [{"path": "on", "label": "On", "format": "raw"}]
        }}}
    });
    let catalog = build(vec![descriptor], vec![token(TOKEN, 6)]).unwrap();
    let bytes = calldata(signature, &[U256::from(2u8)]);
    assert_eq!(
        review_call(&catalog, &context(&bytes, false))
            .unwrap_err()
            .reason,
        ReviewReason::InvalidPayload
    );
}
