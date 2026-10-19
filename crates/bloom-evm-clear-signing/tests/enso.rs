mod support;

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_primitives::U256;
use bloom_evm_clear_signing::*;
use support::*;

const ROUTER: &str = "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf";
const USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const SINGLE: &str = "routeSingle((uint8 tokenType,bytes data) tokenIn,bytes data)";
const MULTI: &str = "routeMulti((uint8 tokenType,bytes data)[] tokensIn,bytes data)";
const SAFE_SINGLE: &str = "safeRouteSingle((uint8 tokenType,bytes data) tokenIn,(uint8 tokenType,bytes data) tokenOut,address receiver,bytes data)";
const SAFE_MULTI: &str = "safeRouteMulti((uint8 tokenType,bytes data)[] tokensIn,(uint8 tokenType,bytes data)[] tokensOut,address receiver,bytes data)";

fn input(address: &str, amount: u64) -> DynSolValue {
    let mut data = address_word(address).to_be_bytes::<32>().to_vec();
    data.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
    DynSolValue::Tuple(vec![
        DynSolValue::Uint(U256::from(1), 8),
        DynSolValue::Bytes(data),
    ])
}

fn encode(signature: &str, input: DynSolValue) -> Vec<u8> {
    parse_function(signature)
        .unwrap()
        .abi_encode_input(&[input, DynSolValue::Bytes(vec![1, 2, 3, 4])])
        .unwrap()
}

fn review(bytes: &[u8], value: u64) -> Result<ClearSignedCall, ReviewError> {
    let mut ctx = context(bytes);
    ctx.chain_id = 8453;
    ctx.to = ROUTER.parse().unwrap();
    ctx.value = U256::from(value);
    review_call(Catalog::built_in().unwrap(), &ctx).map(|(call, _)| call)
}

#[test]
fn source_amount_and_identity_are_read_but_shortcut_effects_stay_unverified() {
    let bytes = encode(SINGLE, input(USDC, 2_500_000));
    let call = review(&bytes, 0).unwrap();
    assert!(
        field(&call, "Source asset / amount")
            .value
            .starts_with("2.5 USDC (")
    );
    assert_eq!(field(&call, "Shortcut program").raw, "0x01020304");
    assert!(call.structural);
    assert!(call.intent_summary.is_none());
    export_ui_fixture("enso-source", &call);
    let asset = field(&call, "Source asset / amount")
        .asset
        .as_ref()
        .unwrap();
    assert_eq!(asset.chain_id, 8453);
    assert_eq!(asset.token.address.to_lowercase(), USDC);
    assert_eq!(asset.amount_display, "2.5 USDC");
    assert!(
        call.warnings
            .iter()
            .any(|warning| warning.contains("not independently decoded"))
    );
    assert!(review(&bytes, 1).is_err());
    let call = review(&encode(SINGLE, input(TOKEN, 2_500_000)), 0).unwrap();
    assert!(field(&call, "Source asset / amount").asset.is_none());
    assert!(
        field(&call, "Source asset / amount")
            .value
            .contains("2500000 raw units")
    );
    assert!(!field(&call, "Source asset / amount").value.contains("USDC"));
}

#[test]
fn multi_inputs_are_scoped_to_their_own_element_and_dirty_padding_is_rejected() {
    let bytes = encode(
        MULTI,
        DynSolValue::Array(vec![input(USDC, 2_500_000), input(TOKEN, 7)]),
    );
    let call = review(&bytes, 0).unwrap();
    assert!(
        field(&call, "Source asset / amount 1")
            .value
            .starts_with("2.5 USDC")
    );
    assert!(
        field(&call, "Source asset / amount 2")
            .value
            .starts_with("7 raw units")
    );
    let mut dirty = input(USDC, 1);
    if let DynSolValue::Tuple(ref mut values) = dirty {
        if let DynSolValue::Bytes(ref mut bytes) = values[1] {
            bytes[0] = 1;
        }
    }
    assert!(review(&encode(SINGLE, dirty), 0).is_err());
}

#[test]
fn native_input_uses_transaction_value_and_duplicate_native_inputs_are_refused() {
    let native = DynSolValue::Tuple(vec![
        DynSolValue::Uint(U256::ZERO, 8),
        DynSolValue::Bytes(U256::from(99).to_be_bytes::<32>().to_vec()),
    ]);
    let call = review(&encode(SINGLE, native.clone()), 1_000_000_000_000_000_000).unwrap();
    assert_eq!(
        field(&call, "Source asset / amount").value,
        "1 ETH (transaction value)"
    );
    assert!(
        review(
            &encode(MULTI, DynSolValue::Array(vec![native.clone(), native])),
            0
        )
        .is_err()
    );
}

fn safe_encode(signature: &str, inputs: DynSolValue, outputs: DynSolValue) -> Vec<u8> {
    parse_function(signature)
        .unwrap()
        .abi_encode_input(&[
            inputs,
            outputs,
            DynSolValue::Address(RECIPIENT.parse().unwrap()),
            DynSolValue::Bytes(vec![1, 2, 3, 4]),
        ])
        .unwrap()
}

fn native_minimum(data: Vec<u8>) -> DynSolValue {
    DynSolValue::Tuple(vec![
        DynSolValue::Uint(U256::ZERO, 8),
        DynSolValue::Bytes(data),
    ])
}

#[test]
fn safe_route_reads_actual_token_minimum_and_receiver_without_borrowing_identity() {
    let bytes = safe_encode(SAFE_SINGLE, input(USDC, 2_500_000), input(USDC, 1_250_000));
    let call = review(&bytes, 0).unwrap();
    let minimum = field(&call, "Requested minimum balance increase");
    assert!(minimum.value.starts_with("1.25 USDC"));
    assert_eq!(minimum.asset.as_ref().unwrap().amount_display, "1.25 USDC");
    assert_eq!(
        minimum.asset.as_ref().unwrap().token.address.to_lowercase(),
        USDC
    );
    assert_eq!(
        field(&call, "Output receiver").value.to_lowercase(),
        RECIPIENT
    );
    assert_eq!(field(&call, "Shortcut program").raw, "0x01020304");
    assert!(
        call.warnings
            .iter()
            .any(|w| w.contains("not proof of received funds"))
    );
    export_ui_fixture("enso-output", &call);
    let unknown = review(
        &safe_encode(SAFE_SINGLE, input(USDC, 2_500_000), input(TOKEN, 7)),
        0,
    )
    .unwrap();
    let minimum = field(&unknown, "Requested minimum balance increase");
    assert!(minimum.asset.is_none());
    assert!(minimum.value.starts_with("7 raw units"));
    assert!(!minimum.value.contains("USDC"));
    assert!(
        review(&bytes, 1).is_err(),
        "an output cannot authorize native input value"
    );
}

#[test]
fn safe_route_native_minimum_uses_output_bytes_not_transaction_value() {
    let output = native_minimum(
        U256::from(1_000_000_000_000_000_000u64)
            .to_be_bytes::<32>()
            .to_vec(),
    );
    let bytes = safe_encode(SAFE_SINGLE, input(USDC, 2_500_000), output.clone());
    let call = review(&bytes, 0).unwrap();
    assert_eq!(
        field(&call, "Requested minimum balance increase").value,
        "1 ETH (minimum balance increase)"
    );
    for malformed in [vec![], vec![0; 31], vec![0; 33], vec![0; 64]] {
        assert!(
            review(
                &safe_encode(SAFE_SINGLE, input(USDC, 1), native_minimum(malformed)),
                0
            )
            .is_err()
        );
    }
    // Outputs may repeat, and are never counted as native inputs. Source
    // native input remains the transaction value, not its arbitrary data.
    let bytes = safe_encode(
        SAFE_MULTI,
        DynSolValue::Array(vec![native_minimum(vec![])]),
        DynSolValue::Array(vec![output.clone(), output]),
    );
    let call = review(&bytes, 2_000_000_000_000_000_000).unwrap();
    assert_eq!(
        field(&call, "Source asset / amount 1").value,
        "2 ETH (transaction value)"
    );
    assert_eq!(
        field(&call, "Requested minimum balance increase 2").value,
        "1 ETH (minimum balance increase)"
    );
}

#[test]
fn safe_route_arrays_preserve_element_binding_and_show_absent_output_checks() {
    let bytes = safe_encode(
        SAFE_MULTI,
        DynSolValue::Array(vec![input(USDC, 2_500_000)]),
        DynSolValue::Array(vec![input(TOKEN, 7), input(USDC, 1_250_000)]),
    );
    let call = review(&bytes, 0).unwrap();
    assert!(
        field(&call, "Requested minimum balance increase 1")
            .asset
            .is_none()
    );
    assert_eq!(
        field(&call, "Requested minimum balance increase 2")
            .asset
            .as_ref()
            .unwrap()
            .amount_display,
        "1.25 USDC"
    );
    let bytes = safe_encode(
        SAFE_MULTI,
        DynSolValue::Array(vec![input(USDC, 1)]),
        DynSolValue::Array(vec![]),
    );
    let call = review(&bytes, 0).unwrap();
    assert_eq!(field(&call, "Output token type").value, "Empty list");
    assert!(
        call.warnings
            .iter()
            .any(|w| w.contains("no output minimums"))
    );
    export_ui_fixture("enso-output-empty", &call);
    let bytes = safe_encode(
        SAFE_MULTI,
        DynSolValue::Array(vec![]),
        DynSolValue::Array(vec![input(USDC, 1)]),
    );
    assert!(
        review(&bytes, 0).is_err(),
        "an output cannot replace missing source inputs"
    );
}

#[test]
fn safe_route_is_bound_to_reviewed_deployments_and_canonical_output_data() {
    let bytes = safe_encode(SAFE_SINGLE, input(USDC, 1), input(USDC, 2));
    let deployments = [
        (1, ROUTER),
        (10, ROUTER),
        (56, ROUTER),
        (100, ROUTER),
        (137, ROUTER),
        (8453, ROUTER),
        (42161, ROUTER),
        (43114, ROUTER),
        (999, ROUTER),
        (59144, "0xa146d46823f3f594b785200102be5385cafce9b5"),
        (4217, "0xcfbaa9cfce952ca4f4069874ff1df8c05e37a3c7"),
        (4663, "0xcfbaa9cfce952ca4f4069874ff1df8c05e37a3c7"),
    ];
    for (chain, router) in deployments {
        let mut ctx = context(&bytes);
        ctx.chain_id = chain;
        ctx.to = router.parse().unwrap();
        ctx.value = U256::ZERO;
        if chain == 4217 {
            ctx.native = None;
        }
        assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_ok());
        ctx.to = RECIPIENT.parse().unwrap();
        assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_err());
    }
    let mut ctx = context(&bytes);
    ctx.chain_id = 8453;
    ctx.to = RECIPIENT.parse().unwrap();
    ctx.value = U256::ZERO;
    assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_err());
    ctx.to = ROUTER.parse().unwrap();
    ctx.chain_id = 31337;
    assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_err());
    let mut dirty = input(USDC, 2);
    if let DynSolValue::Tuple(ref mut values) = dirty {
        if let DynSolValue::Bytes(ref mut bytes) = values[1] {
            bytes[0] = 1;
        }
    }
    assert!(review(&safe_encode(SAFE_SINGLE, input(USDC, 1), dirty), 0).is_err());
}

#[test]
fn native_amounts_have_explicit_presentation_and_missing_units_never_guess() {
    let bytes = safe_encode(
        SAFE_SINGLE,
        native_minimum(vec![]),
        native_minimum(U256::from(7).to_be_bytes::<32>().to_vec()),
    );
    let call = review(&bytes, 11).unwrap();
    assert_eq!(field(&call, "Source asset / amount").format, "nativeAmount");
    assert_eq!(
        field(&call, "Requested minimum balance increase").format,
        "nativeAmount"
    );
    let mut ctx = context(&bytes);
    ctx.chain_id = 4217;
    ctx.to = "0xcfbaa9cfce952ca4f4069874ff1df8c05e37a3c7"
        .parse()
        .unwrap();
    ctx.native = None;
    ctx.value = U256::from(11);
    assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_err());
}

#[test]
fn shortcut_constants_receive_catalog_readings_and_runtime_slots_stay_explicit() {
    let mut command = [0u8; 32];
    command[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    command[4] = 1;
    command[5..11].fill(0xff);
    command[5] = 0;
    command[6] = 1;
    command[11] = 1;
    command[12..].copy_from_slice(&USDC.parse::<alloy_primitives::Address>().unwrap()[..]);
    let shortcut = parse_function("executeShortcut(bytes32,bytes32,bytes32[],bytes[])")
        .unwrap()
        .abi_encode_input(&[
            DynSolValue::FixedBytes(Default::default(), 32),
            DynSolValue::FixedBytes(Default::default(), 32),
            DynSolValue::Array(vec![
                DynSolValue::FixedBytes(command.into(), 32),
                DynSolValue::FixedBytes(command.into(), 32),
            ]),
            DynSolValue::Array(vec![
                DynSolValue::Bytes(address_word(RECIPIENT).to_be_bytes::<32>().to_vec()),
                DynSolValue::Bytes(U256::from(2_500_000).to_be_bytes::<32>().to_vec()),
            ]),
        ])
        .unwrap();
    let outer = parse_function(SINGLE)
        .unwrap()
        .abi_encode_input(&[input(USDC, 2_500_000), DynSolValue::Bytes(shortcut)])
        .unwrap();
    let call = review(&outer, 0).unwrap();
    let program: serde_json::Value =
        serde_json::from_str(&field(&call, "Shortcut program").value).unwrap();
    assert!(program["steps"][0]["reading"].is_object(), "{program}");
    assert!(program["steps"][1]["reading"].is_null());
    assert!(
        program["steps"][1]["unread_reason"]
            .as_str()
            .unwrap()
            .contains("runtime")
    );
    assert!(
        program["steps"][0]["reading"]
            .to_string()
            .contains("2.5 USDC")
    );
    export_ui_fixture("enso-shortcut", &call);
}
