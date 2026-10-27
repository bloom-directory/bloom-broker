//! The calls the Morpho Petal stages, read with the built-in catalog: a
//! protected deposit through Bundler3, and a withdrawal from the vault.

use alloy_dyn_abi::{DynSolValue, JsonAbiExt as _};
use alloy_primitives::U256;
use bloom_evm_clear_signing::*;

const BASE: u64 = 8453;
const BUNDLER: &str = "0x6bfd8137e702540e7a42b74178a4a49ba43920c4";
const ADAPTER: &str = "0xb98c948cfa24072e58935bc004a8a7b376ae746a";
const USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const VAULT: &str = "0xc1256ae5ff1cf2719d4937adb3bbccab2e00a2ca";
const OWNER: &str = "0x8d4fafba75a9dc50b4b296211509e856d2c6d081";

fn address(value: &str) -> DynSolValue {
    DynSolValue::Address(value.parse().unwrap())
}

fn uint(value: u64) -> DynSolValue {
    DynSolValue::Uint(U256::from(value), 256)
}

fn encode(signature: &str, args: &[DynSolValue]) -> Vec<u8> {
    parse_function(signature)
        .unwrap()
        .abi_encode_input(args)
        .unwrap()
}

fn review(to: &str, input: &[u8]) -> Result<ClearSignedCall, ReviewError> {
    review_call(
        Catalog::built_in().unwrap(),
        &CallContext {
            chain_id: BASE,
            to: to.parse().unwrap(),
            value: U256::ZERO,
            calldata: input,
            native: Some(NativeUnits {
                decimals: 18,
                symbol: "ETH".into(),
            }),
        },
    )
    .map(|(call, _)| call)
}

fn field<'a>(call: &'a ClearSignedCall, label: &str) -> &'a str {
    &call
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap_or_else(|| panic!("no `{label}` in {:#?}", call.fields))
        .value
}

/// `erc4626::protected_deposit_calldata` in bloom-petal-morpho.
fn protected_deposit(callback: u8) -> Vec<u8> {
    let step = |data: Vec<u8>| {
        DynSolValue::Tuple(vec![
            address(ADAPTER),
            DynSolValue::Bytes(data),
            uint(0),
            DynSolValue::Bool(false),
            DynSolValue::FixedBytes([callback; 32].into(), 32),
        ])
    };
    let pull = encode(
        "erc20TransferFrom(address,address,uint256)",
        &[address(USDC), address(ADAPTER), uint(2_500_000)],
    );
    let deposit = encode(
        "erc4626Deposit(address,uint256,uint256,address)",
        &[
            address(VAULT),
            uint(2_500_000),
            uint(1_000_000_000),
            address(OWNER),
        ],
    );
    encode(
        "multicall((address,bytes,uint256,bool,bytes32)[])",
        &[DynSolValue::Array(vec![step(pull), step(deposit)])],
    )
}

#[test]
fn a_protected_deposit_reads_step_by_step() {
    let call = review(BUNDLER, &protected_deposit(0)).unwrap();
    assert_eq!(call.contract_name.as_deref(), Some("Morpho Bundler3"));
    let adapter = checksum(ADAPTER);
    assert_eq!(
        field(&call, "Action 1"),
        format!("erc20TransferFrom on Morpho GeneralAdapter1 {adapter}")
    );
    assert_eq!(field(&call, "Action 1 · Amount"), "2.5 USDC");
    assert_eq!(
        field(&call, "Action 2"),
        format!("erc4626Deposit on Morpho GeneralAdapter1 {adapter}")
    );
    assert_eq!(field(&call, "Action 2 · Assets"), "2.5 USDC");
    let asset = call
        .fields
        .iter()
        .find(|field| field.label == "Action 2 · Assets")
        .unwrap()
        .asset
        .as_ref()
        .unwrap();
    assert_eq!(asset.token.address.to_lowercase(), USDC);
    assert_eq!(field(&call, "Action 2 · Shares go to"), checksum(OWNER));
    assert!(!call.structural);
}

#[test]
fn a_bundle_with_a_callback_is_refused() {
    let error = review(BUNDLER, &protected_deposit(1)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::UnsupportedCall, "{error}");
}

/// Vaults are created by curators and cannot all be listed, so a withdrawal
/// is read by the ERC-4626 standard and says the vault is unverified.
#[test]
fn a_vault_withdrawal_is_read_by_the_standard() {
    let input = encode(
        "withdraw(uint256,address,address)",
        &[uint(1_000_000), address(OWNER), address(OWNER)],
    );
    let call = review(VAULT, &input).unwrap();
    assert_eq!(call.contract_name.as_deref(), Some("ERC-4626 vault"));
    assert_eq!(field(&call, "Assets"), "1 USDC");
    assert_eq!(field(&call, "Assets go to"), checksum(OWNER));
    assert!(call.structural);
    assert!(
        call.warnings[0].contains("cannot check") && call.warnings[0].contains("an ERC-4626 vault"),
        "{:?}",
        call.warnings
    );
}

#[test]
fn vault_underlying_units_are_bound_to_the_exact_address_and_chain() {
    let input = encode(
        "deposit(uint256,address)",
        &[uint(2_500_000), address(OWNER)],
    );
    let wrong_vault = "0xc1256ae5ff1cf2719d4937adb3bbccab2e00a2cb";
    let call = review(wrong_vault, &input).unwrap();
    assert!(field(&call, "Assets").starts_with("2500000 raw units"));
    assert!(field(&call, "Assets").contains("identity unverified"));
    assert!(call.fields.iter().all(|field| field.asset.is_none()));
    let (call, _) = review_call(
        Catalog::built_in().unwrap(),
        &CallContext {
            chain_id: 1,
            to: VAULT.parse().unwrap(),
            value: U256::ZERO,
            calldata: &input,
            native: Some(NativeUnits {
                decimals: 18,
                symbol: "ETH".into(),
            }),
        },
    )
    .unwrap();
    assert!(field(&call, "Assets").starts_with("2500000 raw units"));
    assert!(call.fields.iter().all(|field| field.asset.is_none()));
}

#[test]
fn vault_shares_do_not_borrow_the_underlying_usdc_identity_or_units() {
    let input = encode(
        "redeem(uint256,address,address)",
        &[uint(1_000_000), address(OWNER), address(OWNER)],
    );
    let call = review(VAULT, &input).unwrap();
    assert_eq!(field(&call, "Shares (raw units)"), "1000000");
    assert!(call.fields.iter().all(|field| field.asset.is_none()));
    assert!(!call.fields.iter().any(|field| field.value.contains("USDC")));
}
