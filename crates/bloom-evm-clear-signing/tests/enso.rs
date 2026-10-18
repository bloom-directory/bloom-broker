mod support;

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_primitives::U256;
use bloom_evm_clear_signing::*;
use support::*;

const ROUTER: &str = "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf";
const USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const SINGLE: &str = "routeSingle((uint8 tokenType,bytes data) tokenIn,bytes data)";
const MULTI: &str = "routeMulti((uint8 tokenType,bytes data)[] tokensIn,bytes data)";

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
    assert_eq!(
        field(&call, "Shortcut program (not decoded)").raw,
        "0x01020304"
    );
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
