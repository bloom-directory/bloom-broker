//! The Safe catalog data in `catalogs/safe`, read the way Broker reads it.
//!
//! The transaction inputs are real Base mainnet transactions: one Safe
//! creation through the 1.4.1 factory, and three executions of that Safe.

mod support;

use std::path::Path;

use alloy_dyn_abi::{DynSolValue, JsonAbiExt as _};
use alloy_json_abi::Function;
use alloy_primitives::{Address, U256};
use bloom_broker_api::{DecimalU64, Digest32};
use bloom_evm_clear_signing::*;
use serde_json::{Value, json};
use support::*;

const BASE: u64 = 8453;
const SAFE: &str = "0xaefda71ded59b48920131d03454893ec2ad93e88";
const WALLET: &str = "0x8d4fafba75a9dc50b4b296211509e856d2c6d081";
const FACTORY: &str = "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67";
const SAFE_141: &str = "0x41675c099f32341bf84bfc5382af534df5c7461a";
const USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const EXEC: &str =
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";

const SEND: &str = "0x6a7612020000000000000000000000008d4fafba75a9dc50b4b296211509e856d2c6d081000000000000000000000000000000000000000000000000000009184e72a00000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000411fca12a0c7a67fc6ca9ca271335af2680fae0ce704f5c75fe373ddce47674df33a341f86acbc619d6db40b37ef330f3f2dd47897f0551799f28f20ef7288d69b1b00000000000000000000000000000000000000000000000000000000000000";
const BATCH: &str = "0x6a7612020000000000000000000000009641d764fc13c8b624c04430c7356c1c7c8102e20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000001448d80ff0a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000ee008d4fafba75a9dc50b4b296211509e856d2c6d0810000000000000000000000000000000000000000000000000000048c27395000000000000000000000000000000000000000000000000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda0291300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000008d4fafba75a9dc50b4b296211509e856d2c6d0810000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041387df176124ae8ab24202005fda4428eff86fcd8d9636ec9239aa8646e414ec75fc7a978870c915eb4e85c7f237e6b5fb6167bde0a1b4dad73a3820b055283f91c00000000000000000000000000000000000000000000000000000000000000";
const REMOVE_OWNER: &str = "0x6a761202000000000000000000000000aefda71ded59b48920131d03454893ec2ad93e880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000064f8dc5dd9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000043d2fdfed480f95b8848840031546e30a60c0a5f000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008200bcff01bcd29252f7a7d20e0fd09d28da5cf5d0f8d4a0165a15e4e62a9e83862f1c20464a3b2cee24762885ff9b86a060d999eb18e74dacdb3256ca919e17121bf5e7e63c173815be4ee254ae96388767b18a7df6c69191bb9bfd9734106efc7b737b98399b57d8847a2f5de37e3ac14b5a3f33bd6d3347f92fa6ac2eec6e80d01c000000000000000000000000000000000000000000000000000000000000";
const CREATION: &str = "0x1688f0b900000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c762000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000013528400000000000000000000000000000000000000000000000000000000000000164b63e800d0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000fd0732dc9e303f09fcef3a7388ad10a83459ec9900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000008d4fafba75a9dc50b4b296211509e856d2c6d081000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn safe_entries() -> Vec<CatalogEntry> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalogs/safe");
    let read = |name: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(directory.join(name)).unwrap()).unwrap()
    };
    let Value::Array(entries) = read("entries.json") else {
        panic!("entries.json is a list")
    };
    entries
        .into_iter()
        .map(|entry| {
            let descriptor = read(entry["descriptor"].as_str().unwrap());
            CatalogEntry {
                chain_id: DecimalU64::new(entry["chain_id"].as_u64().unwrap()),
                contract_address: entry["contract_address"].as_str().unwrap().into(),
                admitted_functions: serde_json::from_value(entry["admitted_functions"].clone())
                    .unwrap(),
                descriptor_digest: Some(descriptor_digest(&descriptor).unwrap()),
                flattened_descriptor: Some(descriptor),
                runtime_code_hash: Some(
                    Digest32::new(entry["runtime_code_hash"].as_str().unwrap().to_owned()).unwrap(),
                ),
                token_metadata: None,
                upgradeable: false,
                implementation_hash: None,
                observed_at_ms: DecimalU64::new(NOW_MS - 1000),
                applies_to_instances: entry["applies_to_instances"].as_bool().unwrap_or(false),
            }
        })
        .collect()
}

/// USDC on Base, listed the way a token is: by its metadata alone.
fn usdc() -> CatalogEntry {
    let mut entry = entry_at(USDC, json!({}), Vec::new(), Some(6));
    entry.chain_id = DecimalU64::new(BASE);
    entry.flattened_descriptor = None;
    entry.descriptor_digest = None;
    let token = entry.token_metadata.as_mut().unwrap();
    token.symbol = "USDC".into();
    token.name = "USD Coin".into();
    entry
}

fn accepted(mut entries: Vec<CatalogEntry>) -> Result<AcceptedCatalog, ReviewError> {
    entries.sort_by(|left, right| {
        (left.chain_id.get(), &left.contract_address)
            .cmp(&(right.chain_id.get(), &right.contract_address))
    });
    let mut catalog = catalog(entries);
    sign(&mut catalog, &[(1, "publisher-1")]);
    accept(&catalog)
}

fn safe_catalog() -> AcceptedCatalog {
    let mut entries = safe_entries();
    entries.push(usdc());
    accepted(entries).unwrap()
}

fn review(to: &str, input: &[u8]) -> Result<(ClearSignedCall, Vec<SelectedEntry>), ReviewError> {
    review_call(
        &safe_catalog(),
        &CallContext {
            chain_id: BASE,
            to: to.parse().unwrap(),
            value: U256::ZERO,
            calldata: input,
            native: Some(NativeUnits {
                decimals: 18,
                symbol: "ETH".into(),
            }),
            unlimited_allowance_allowed: false,
        },
    )
}

fn hex_input(input: &str) -> Vec<u8> {
    hex::decode(input.trim_start_matches("0x")).unwrap()
}

fn field<'a>(call: &'a ClearSignedCall, label: &str) -> &'a str {
    call.fields
        .iter()
        .find(|field| field.label == label)
        .unwrap_or_else(|| panic!("no `{label}` in {:#?}", call.fields))
        .value
        .as_str()
}

/// `execTransaction` with every refund field zero unless overridden.
fn exec(to: &str, value: u64, data: Vec<u8>, operation: u8, gas_price: u64) -> Vec<u8> {
    let function = Function::parse(EXEC).unwrap();
    let address = |value: &str| DynSolValue::Address(value.parse::<Address>().unwrap());
    let uint = |value: u64, bits| DynSolValue::Uint(U256::from(value), bits);
    function
        .abi_encode_input(&[
            address(to),
            uint(value, 256),
            DynSolValue::Bytes(data),
            uint(operation.into(), 8),
            uint(0, 256),
            uint(0, 256),
            uint(gas_price, 256),
            address("0x0000000000000000000000000000000000000000"),
            address("0x0000000000000000000000000000000000000000"),
            DynSolValue::Bytes(vec![1; 65]),
        ])
        .unwrap()
}

fn token_call(signature: &str, counterparty: &str, amount: U256) -> Vec<u8> {
    let function = Function::parse(signature).unwrap();
    function
        .abi_encode_input(&[
            DynSolValue::Address(counterparty.parse().unwrap()),
            DynSolValue::Uint(amount, 256),
        ])
        .unwrap()
}

#[test]
fn a_safe_creation_is_read_through_the_factory_and_the_singleton() {
    let (call, entries) = review(FACTORY, &hex_input(CREATION)).unwrap();
    assert_eq!(call.contract_name.as_deref(), Some("Safe proxy factory"));
    assert_eq!(
        field(&call, "New Safe"),
        "setup on Safe 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"
    );
    assert_eq!(
        field(&call, "New Safe · Owner 1"),
        checksum(WALLET),
        "{call:#?}"
    );
    assert_eq!(field(&call, "New Safe · Signatures required"), "1");
    // Both contracts are listed, so this is the ordinary assurance.
    assert_eq!(call.assurance, standing_assurance());
    assert!(call.warnings.is_empty(), "{:?}", call.warnings);
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| entry.instance.is_none()));
}

#[test]
fn a_creation_outside_the_official_shape_is_refused() {
    let input = hex_input(CREATION);
    let function = Function::parse("createProxyWithNonce(address,bytes,uint256)").unwrap();
    let decoded = function.abi_decode_input(&input[4..]).unwrap();
    let encode = |values: &[DynSolValue]| function.abi_encode_input(values).unwrap();
    // A singleton nobody listed: the proxy would run code someone else chose.
    let mut values = decoded.clone();
    values[0] = DynSolValue::Address(RECIPIENT.parse().unwrap());
    let error = review(FACTORY, &encode(&values)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::UnsupportedCall, "{error}");
    assert!(error.detail.contains("_singleton"), "{error}");

    // Setup code: `setup` would delegatecall it from the new Safe.
    let setup =
        Function::parse("setup(address[],uint256,address,bytes,address,address,uint256,address)")
            .unwrap();
    let DynSolValue::Bytes(initializer) = &decoded[1] else {
        panic!()
    };
    let mut fields = setup.abi_decode_input(&initializer[4..]).unwrap();
    fields[2] = DynSolValue::Address(RECIPIENT.parse().unwrap());
    let mut values = decoded;
    values[1] = DynSolValue::Bytes(setup.abi_encode_input(&fields).unwrap());
    let error = review(FACTORY, &encode(&values)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::UnsupportedCall, "{error}");
    assert!(error.detail.contains("`to`"), "{error}");
}

#[test]
fn an_unlisted_safe_is_read_structurally_and_says_so() {
    let (call, entries) = review(SAFE, &hex_input(SEND)).unwrap();
    assert_eq!(call.contract, checksum(SAFE));
    assert_eq!(call.assurance, structural_assurance());
    assert!(
        call.warnings[0].contains("has not verified") && call.warnings[0].contains("a Safe"),
        "{:?}",
        call.warnings
    );
    assert_eq!(field(&call, "Safe sends"), "0.00001 ETH");
    assert_eq!(
        field(&call, "Safe transaction"),
        format!("Send 0.00001 ETH to {}", checksum(WALLET))
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].contract_address, SAFE_141);
    assert_eq!(entries[0].instance.as_deref(), Some(SAFE));

    let catalog = safe_catalog();
    let evidence = ClearSigningEvidence::new(&catalog, &Digest32::from_bytes([9; 32]), entries);
    assert_eq!(evidence.assurance, STRUCTURAL_DESCRIPTION);
    evidence
        .recheck(
            Some(&catalog),
            &Digest32::from_bytes([9; 32]),
            NOW_MS,
            86_400_000,
        )
        .unwrap();
    // Withdrawing the instance flag withdraws every reading that relied on it.
    let mut entries = safe_entries();
    for entry in &mut entries {
        entry.applies_to_instances = false;
    }
    let withdrawn = accepted(entries).unwrap();
    let error = evidence
        .recheck(
            Some(&withdrawn),
            &Digest32::from_bytes([9; 32]),
            NOW_MS,
            86_400_000,
        )
        .unwrap_err();
    assert_eq!(error.reason, ReviewReason::ReviewChanged, "{error}");
}

#[test]
fn an_owner_change_is_read_as_the_safe_calling_itself() {
    let (call, _) = review(SAFE, &hex_input(REMOVE_OWNER)).unwrap();
    assert_eq!(
        field(&call, "Safe transaction"),
        format!("removeOwner on Safe {}", checksum(SAFE))
    );
    assert_eq!(call.warnings.len(), 1, "{:?}", call.warnings);
    assert_eq!(field(&call, "Safe transaction · Signatures required"), "1");
    assert!(
        call.fields
            .iter()
            .any(|field| field.label == "Safe transaction · Removed owner")
    );
}

#[test]
fn a_safe_batch_is_a_delegatecall_and_is_refused() {
    let error = review(SAFE, &hex_input(BATCH)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::UnsupportedCall, "{error}");
    assert!(error.detail.contains("`operation` is 1"), "{error}");
}

#[test]
fn a_safe_token_call_is_read_and_policed_by_the_token_entry() {
    let transfer = exec(
        USDC,
        0,
        token_call("transfer(address,uint256)", WALLET, U256::from(2_500_000)),
        0,
        0,
    );
    let (call, entries) = review(SAFE, &transfer).unwrap();
    assert_eq!(
        field(&call, "Safe transaction"),
        format!("transfer on USD Coin {}", checksum(USDC))
    );
    assert_eq!(field(&call, "Safe transaction · Amount"), "2.5 USDC");
    assert_eq!(field(&call, "Safe transaction · To"), checksum(WALLET));
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].contract_address, USDC);

    let unlimited = exec(
        USDC,
        0,
        token_call("approve(address,uint256)", WALLET, U256::MAX),
        0,
        0,
    );
    let error = review(SAFE, &unlimited).unwrap_err();
    assert_eq!(error.reason, ReviewReason::PolicyDenied, "{error}");

    let unknown = exec(RECIPIENT, 0, vec![0xde, 0xad, 0xbe, 0xef], 0, 0);
    let error = review(SAFE, &unknown).unwrap_err();
    assert_eq!(error.reason, ReviewReason::UnsupportedCall, "{error}");
}

/// A token the catalog does not list is still readable inside a Safe: by its
/// ERC-20 shape, in raw units, and the review says it is structural.
#[test]
fn a_safe_call_to_an_unlisted_token_is_read_by_its_shape() {
    let transfer = exec(
        RECIPIENT,
        0,
        token_call("transfer(address,uint256)", WALLET, U256::from(7)),
        0,
        0,
    );
    let (call, entries) = review(SAFE, &transfer).unwrap();
    assert_eq!(
        field(&call, "Safe transaction"),
        format!("transfer on {}", checksum(RECIPIENT))
    );
    assert_eq!(
        field(&call, "Safe transaction · Recipient"),
        checksum(WALLET)
    );
    assert_eq!(field(&call, "Safe transaction · Raw token amount"), "7");
    assert!(call.structural);
    assert!(
        call.warnings
            .iter()
            .any(|warning| warning.contains("ERC-20-shaped"))
    );
    // Only the Safe's entry is evidence: the token contributed none.
    assert_eq!(entries.len(), 1);

    let unlimited = exec(
        RECIPIENT,
        0,
        token_call("approve(address,uint256)", WALLET, U256::MAX),
        0,
        0,
    );
    let error = review(SAFE, &unlimited).unwrap_err();
    assert_eq!(error.reason, ReviewReason::PolicyDenied, "{error}");

    // Native value riding on a token call is not a token transfer.
    let with_value = exec(
        RECIPIENT,
        1,
        token_call("transfer(address,uint256)", WALLET, U256::from(7)),
        0,
        0,
    );
    assert_eq!(
        review(SAFE, &with_value).unwrap_err().reason,
        ReviewReason::InvalidPayload
    );
}

#[test]
fn a_gas_refund_is_refused() {
    let error = review(SAFE, &exec(WALLET, 1, Vec::new(), 0, 1)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::UnsupportedCall, "{error}");
    assert!(error.detail.contains("`gasPrice`"), "{error}");
}

#[test]
fn a_listed_contract_is_never_read_as_a_safe() {
    let error = review(USDC, &exec(WALLET, 1, Vec::new(), 0, 0)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::UnsupportedCall, "{error}");
    assert!(error.detail.contains("selector"), "{error}");
}

#[test]
fn safes_nested_past_the_limit_are_refused() {
    let mut input = exec(WALLET, 1, Vec::new(), 0, 0);
    for _ in 0..MAX_NESTED_CALLS {
        input = exec(SAFE, 0, input, 0, 0);
    }
    review(SAFE, &input).unwrap();
    let error = review(SAFE, &exec(SAFE, 0, input, 0, 0)).unwrap_err();
    assert_eq!(error.reason, ReviewReason::LimitExceeded, "{error}");
}

#[test]
fn instance_entries_cannot_overlap_or_borrow_token_identity() {
    let mut entries = safe_entries();
    let second = entries
        .iter_mut()
        .find(|entry| {
            entry.chain_id.get() == BASE
                && entry.contract_address == "0x29fcb43b46531bca003ddc8fcb67ffe91900c762"
        })
        .unwrap();
    second.applies_to_instances = true;
    let error = accepted(entries).unwrap_err();
    assert_eq!(error.reason, ReviewReason::CatalogRejected, "{error}");
    assert!(error.detail.contains("ambiguous"), "{error}");

    let mut token = usdc();
    token.applies_to_instances = true;
    let error = accepted(vec![token]).unwrap_err();
    assert_eq!(error.reason, ReviewReason::CatalogRejected, "{error}");
}
