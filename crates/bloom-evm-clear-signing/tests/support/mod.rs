//! Fixture builders shared by the verifier tests.
#![allow(dead_code)]

use alloy_json_abi::Function;
use alloy_primitives::{Address, U256};
use bloom_broker_api::{Base64UrlBytes, DecimalU64, Digest32, Token};
use bloom_evm_clear_signing::*;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

pub const CHAIN_ID: u64 = 1;
pub const TOKEN: &str = "0x1111111111111111111111111111111111111111";
pub const RECIPIENT: &str = "0x2222222222222222222222222222222222222222";
/// A second contract that is not itself a token: its calls name the token as
/// an argument, which is what an argument-based token path has to resolve.
pub const VAULT: &str = "0x3333333333333333333333333333333333333333";
pub const NOW_MS: u64 = 1_750_000_000_000;

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn trusted(seed: u8, id: &str) -> TrustedCatalogKey {
    TrustedCatalogKey {
        key_id: Token::new(id).unwrap(),
        verifying_key: key(seed).verifying_key(),
    }
}

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

pub fn entry(descriptor: Value, functions: Vec<AdmittedFunction>, decimals: u8) -> CatalogEntry {
    entry_at(TOKEN, descriptor, functions, Some(decimals))
}

pub fn entry_at(
    address: &str,
    descriptor: Value,
    functions: Vec<AdmittedFunction>,
    decimals: Option<u8>,
) -> CatalogEntry {
    CatalogEntry {
        chain_id: DecimalU64::new(CHAIN_ID),
        contract_address: address.into(),
        admitted_functions: functions,
        descriptor_digest: Some(descriptor_digest(&descriptor).unwrap()),
        flattened_descriptor: Some(descriptor),
        runtime_code_hash: Some(Digest32::from_bytes([3; 32])),
        token_metadata: decimals.map(|decimals| TokenMetadata {
            decimals,
            symbol: "EXA".into(),
            name: "Example Token".into(),
        }),
        upgradeable: false,
        implementation_hash: None,
        observed_at_ms: DecimalU64::new(NOW_MS - 1000),
    }
}

pub fn erc20_entry() -> CatalogEntry {
    entry(erc20_descriptor(), erc20_functions(), 6)
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

pub fn vault_entry() -> CatalogEntry {
    entry_at(
        VAULT,
        vault_descriptor(),
        vec![AdmittedFunction {
            signature: VAULT_DEPOSIT.into(),
            action_class: ActionClass::Other,
        }],
        None,
    )
}

/// Both entries: the vault being called, and the token its argument names.
pub fn accepted_vault() -> AcceptedCatalog {
    let mut catalog = catalog(vec![erc20_entry(), vault_entry()]);
    sign(&mut catalog, &[(1, "publisher-1")]);
    accept(&catalog).unwrap()
}

pub fn vault_context(calldata: &[u8]) -> CallContext<'_> {
    CallContext {
        to: VAULT.parse().unwrap(),
        ..context(calldata, false)
    }
}

pub fn catalog(entries: Vec<CatalogEntry>) -> ClearSigningCatalog {
    ClearSigningCatalog {
        schema: CATALOG_SCHEMA.into(),
        catalog_id: Token::new("bloom-tokens").unwrap(),
        sequence: DecimalU64::new(7),
        issued_at_ms: DecimalU64::new(NOW_MS - 10_000),
        expires_at_ms: DecimalU64::new(NOW_MS + 86_400_000),
        entries,
        signatures: Vec::new(),
    }
}

pub fn sign(catalog: &mut ClearSigningCatalog, seeds: &[(u8, &str)]) {
    let mut message = CATALOG_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&catalog.unsigned_canonical_bytes().unwrap());
    catalog.signatures = seeds
        .iter()
        .map(|(seed, id)| CatalogSignature {
            key_id: Token::new(*id).unwrap(),
            signature: Base64UrlBytes::from_bytes(&key(*seed).sign(&message).to_bytes()),
        })
        .collect();
}

pub fn accept(catalog: &ClearSigningCatalog) -> Result<AcceptedCatalog, ReviewError> {
    catalog.accept(
        serde_jcs::to_vec(catalog).unwrap().len(),
        &[trusted(1, "publisher-1")],
        1,
    )
}

pub fn accepted_erc20() -> AcceptedCatalog {
    let mut catalog = catalog(vec![erc20_entry()]);
    sign(&mut catalog, &[(1, "publisher-1")]);
    accept(&catalog).unwrap()
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
