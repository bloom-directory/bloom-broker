//! Representative ABI shapes, not endorsements of deployed protocols.
//! Synthetic signed catalogs isolate what this verifier can actually explain.
mod support;

use alloy_primitives::U256;
use bloom_evm_clear_signing::*;
use serde_json::{Value, json};
use support::*;

fn other(signature: &str, fields: Value) -> Result<AcceptedCatalog, ReviewError> {
    let descriptor = json!({
        "context": {"contract": {"deployments": [{"chainId": CHAIN_ID, "address": TOKEN}]}},
        "metadata": {"contractName": "Example contract"},
        "display": {"formats": {signature: {"fields": fields}}}
    });
    let mut signed = catalog(vec![entry_at(
        TOKEN,
        descriptor,
        vec![AdmittedFunction {
            signature: signature.into(),
            action_class: ActionClass::Other,
        }],
        None,
    )]);
    sign(&mut signed, &[(1, "publisher-1")]);
    accept(&signed)
}

fn export(name: &str, call: &ClearSignedCall) {
    if let Some(directory) = std::env::var_os("BLOOM_UI_FIXTURE_DIR") {
        let path = std::path::Path::new(&directory).join(format!("{name}.json"));
        std::fs::write(path, serde_json::to_vec_pretty(call).unwrap()).unwrap();
    }
}

#[test]
fn scalar_vault_deposit_identifies_the_asset_but_does_not_invent_shares() {
    let mut signed = catalog(vec![erc20_entry(), vault_entry()]);
    sign(&mut signed, &[(1, "publisher-1")]);
    let accepted = accept(&signed).unwrap();
    let bytes = calldata(
        VAULT_DEPOSIT,
        &[
            address_word(TOKEN),
            U256::from(250_000_000),
            address_word(RECIPIENT),
        ],
    );
    let mut ctx = context(&bytes, false);
    ctx.to = VAULT.parse().unwrap();
    let (call, _) = review_call(&accepted, &ctx).unwrap();
    assert_eq!(field(&call, "Amount").value, "250 EXA");
    assert_eq!(field(&call, "Credited to").value, checksum(RECIPIENT));
    assert!(call.intent_summary.is_none());
    assert_eq!(call.action, "other");
    export("deposit-static", &call);
}

#[test]
fn stake_scalar_is_readable_but_does_not_guess_which_token_it_uses() {
    let signature = "stake(uint256 amount)";
    let accepted = other(
        signature,
        json!([
            {"path":"amount", "label":"Amount (raw units)", "format":"raw"}
        ]),
    )
    .unwrap();
    let bytes = calldata(signature, &[U256::from(250_000_000)]);
    let (call, _) = review_call(&accepted, &context(&bytes, false)).unwrap();
    assert_eq!(field(&call, "Amount (raw units)").raw, "250000000");
    assert!(call.intent_summary.is_none());
    assert!(call.token.is_none());
    export("stake-static", &call);
}

#[test]
fn operator_approval_is_not_misclassified_as_an_erc20_allowance() {
    let signature = "setApprovalForAll(address operator, bool approved)";
    let accepted = other(
        signature,
        json!([
            {"path":"operator", "label":"Operator", "format":"addressName"},
            {"path":"approved", "label":"Approved", "format":"raw"}
        ]),
    )
    .unwrap();
    let bytes = calldata(signature, &[address_word(RECIPIENT), U256::from(1)]);
    let (call, _) = review_call(&accepted, &context(&bytes, false)).unwrap();
    assert_eq!(call.action, "other");
    assert!(call.intent_summary.is_none());
    assert_eq!(field(&call, "Approved").value, "true");
    export("operator-approval", &call);
}

#[test]
fn zero_argument_native_deposit_is_outside_the_current_subset() {
    let error = other("deposit()", json!([])).unwrap_err();
    assert_eq!(error.reason, ReviewReason::LimitExceeded);
}

#[test]
fn router_command_arrays_are_not_silently_rendered_as_a_swap() {
    assert!(
        other(
            "route(bytes32[] commands, bytes[] state)",
            json!([
                {"path":"commands", "label":"Commands", "format":"raw"},
                {"path":"state", "label":"State", "format":"raw"}
            ])
        )
        .is_err()
    );
}
