//! Fixture builders shared by the verifier tests.
#![allow(dead_code)]

use alloy_json_abi::Function;
use alloy_primitives::{Address, U256};
use bloom_evm_clear_signing::*;
use serde_json::{Value, json};

pub const CHAIN_ID: u64 = 1;
pub const TOKEN: &str = "0x1111111111111111111111111111111111111111";
pub const RECIPIENT: &str = "0x2222222222222222222222222222222222222222";
/// A second contract that is not itself a token: its calls name the token as
/// an argument, which is what an argument-based token path has to resolve.
pub const VAULT: &str = "0x3333333333333333333333333333333333333333";
pub const NOW_MS: u64 = 1_750_000_000_000;

/// The reviewed ERC-20 derivative: the registry template without its
/// finite-value threshold, which would have labelled a large finite
/// allowance unlimited.
pub fn erc20_descriptor() -> Value {
    json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "metadata": {"owner": "Example Labs", "contractName": "Example Token"},
        "display": {"formats": {
            "transfer(address _to, uint256 _value)": {
                "intent": "Send",
                "fields": [
                    {"path": "_to", "label": "To", "format": "addressName",
                     "params": {"types": ["eoa"], "sources": ["local", "ens"]}, "visible": "always"},
                    {"path": "_value", "label": "Amount", "format": "tokenAmount",
                     "params": {"tokenPath": "@.to"}, "visible": "always"}
                ]
            },
            "approve(address _spender, uint256 _value)": {
                "intent": "Approve",
                "fields": [
                    {"path": "_spender", "label": "Spender", "format": "addressName",
                     "params": {"types": ["eoa", "contract"]}, "visible": "always"},
                    {"path": "_value", "label": "Amount", "format": "tokenAmount",
                     "params": {"tokenPath": "@.to"}, "visible": "always"}
                ]
            }
        }}
    })
}

pub fn erc20_functions() -> Vec<AdmittedFunction> {
    vec![
        AdmittedFunction {
            signature: "transfer(address _to, uint256 _value)".into(),
            action_class: ActionClass::Transfer,
        },
        AdmittedFunction {
            signature: "approve(address _spender, uint256 _value)".into(),
            action_class: ActionClass::Allowance,
        },
    ]
}

pub fn token(address: &str, decimals: u8) -> TokenRecord {
    TokenRecord {
        chain_id: CHAIN_ID,
        address: address.into(),
        symbol: "EXA".into(),
        name: "Example Token".into(),
        decimals,
        upgradeable: false,
    }
}

pub fn build(descriptors: Vec<Value>, tokens: Vec<TokenRecord>) -> Result<Catalog, ReviewError> {
    let descriptors: Vec<_> = descriptors
        .into_iter()
        .map(|descriptor| (descriptor, None, false))
        .collect();
    Catalog::build(&descriptors, tokens)
}

/// A scalar-only third function whose token is an address argument rather
/// than the contract being called. Nothing about the decoder changes: the
/// same generic path decodes it, and the token's decimals still come from a
/// signed catalog entry — the one the decoded address names.
pub fn vault_descriptor() -> Value {
    json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": VAULT}]}},
        "metadata": {"contractName": "Example Vault"},
        "display": {"formats": {
            "deposit(address token, uint256 amount, address beneficiary)": {
                "intent": "Deposit",
                "fields": [
                    {"path": "token", "label": "Token", "format": "addressName", "visible": "always"},
                    {"path": "amount", "label": "Amount", "format": "tokenAmount",
                     "params": {"tokenPath": "token"}, "visible": "always"},
                    {"path": "beneficiary", "label": "Credited to", "format": "addressName",
                     "visible": "always"}
                ]
            }
        }}
    })
}

pub const VAULT_DEPOSIT: &str = "deposit(address token, uint256 amount, address beneficiary)";

/// Both contracts: the vault being called, and the token its argument names.
pub fn accepted_vault() -> Catalog {
    build(
        vec![erc20_descriptor(), vault_descriptor()],
        vec![token(TOKEN, 6)],
    )
    .unwrap()
}

pub fn vault_context(calldata: &[u8]) -> CallContext<'_> {
    CallContext {
        to: VAULT.parse().unwrap(),
        ..context(calldata, false)
    }
}

pub fn accepted_erc20() -> Catalog {
    build(vec![erc20_descriptor()], vec![token(TOKEN, 6)]).unwrap()
}

pub fn calldata(signature: &str, words: &[U256]) -> Vec<u8> {
    let function = Function::parse(signature).unwrap();
    let mut encoded = function.selector().to_vec();
    for word in words {
        encoded.extend_from_slice(&word.to_be_bytes::<32>());
    }
    encoded
}

pub fn address_word(address: &str) -> U256 {
    U256::from_be_slice(address.parse::<Address>().unwrap().as_slice())
}

pub fn context(calldata: &[u8], unlimited: bool) -> CallContext<'_> {
    CallContext {
        chain_id: CHAIN_ID,
        to: TOKEN.parse().unwrap(),
        value: U256::ZERO,
        calldata,
        native: Some(NativeUnits {
            decimals: 18,
            symbol: "ETH".into(),
        }),
        unlimited_allowance_allowed: unlimited,
    }
}

pub fn field<'a>(call: &'a ClearSignedCall, label: &str) -> &'a DisplayField {
    call.fields
        .iter()
        .find(|field| field.label == label)
        .unwrap_or_else(|| panic!("no field labelled {label} in {:?}", call.fields))
}
