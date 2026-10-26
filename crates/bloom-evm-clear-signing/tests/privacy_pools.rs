//! Exact supported mainnet calls, without claiming ZK-proof or settlement verification.
mod support;

use alloy_primitives::{Address, U256};
use bloom_evm_clear_signing::*;
use support::*;

const ENTRYPOINT: &str = "0x6818809eefce719e480a7526d76bd3e561526b46";
const POOL: &str = "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb";
const WITHDRAW: &str = "withdraw((address processooor,bytes data) withdrawal,(uint256[2] pA,uint256[2][2] pB,uint256[2] pC,uint256[8] pubSignals) proof)";

#[test]
fn native_deposit_reads_value_and_marks_the_upgradeable_entrypoint() {
    let bytes = calldata("deposit(uint256 precommitment)", &[U256::from(1234)]);
    let mut ctx = context(&bytes);
    ctx.to = ENTRYPOINT.parse().unwrap();
    ctx.value = U256::from(2_500_000_000_000_000_000u64);
    let (call, selected) = review_call(Catalog::built_in().unwrap(), &ctx).unwrap();
    assert_eq!(field(&call, "Deposit").value, "2.5 ETH");
    export_ui_fixture("privacy-deposit", &call);
    assert_eq!(field(&call, "Note precommitment").raw, "1234");
    assert!(selected.iter().any(|entry| entry.upgradeable));
    assert!(call.intent_summary.is_none());
    ctx.chain_id = 8453;
    assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_err());
}

fn direct_withdrawal() -> Vec<u8> {
    let mut bytes = parse_function(WITHDRAW).unwrap().selector().to_vec();
    // The proof is static (16 words); the dynamic withdrawal tuple follows it.
    let mut words = vec![U256::from(17 * 32)];
    words.extend((1u64..=16).map(U256::from));
    words[11] = U256::from(1_250_000_000_000_000_000u64); // public signal 2
    words.extend([address_word(RECIPIENT), U256::from(64), U256::ZERO]);
    for word in words {
        bytes.extend_from_slice(&word.to_be_bytes::<32>());
    }
    bytes
}

#[test]
fn direct_withdrawal_reads_recipient_amount_and_every_proof_word() {
    let bytes = direct_withdrawal();
    let mut ctx = context(&bytes);
    ctx.to = POOL.parse::<Address>().unwrap();
    let (call, selected) = review_call(Catalog::built_in().unwrap(), &ctx).unwrap();
    assert_eq!(field(&call, "Withdrawal").value, "1.25 ETH");
    export_ui_fixture("privacy-withdrawal", &call);
    assert_eq!(
        field(&call, "Recipient / required caller").value,
        checksum(RECIPIENT)
    );
    assert_eq!(field(&call, "Proof B 2 1").raw, "5");
    assert_eq!(call.fields.len(), 17);
    assert!(selected.iter().all(|entry| !entry.upgradeable));
    assert!(call.intent_summary.is_none());
    ctx.value = U256::from(1);
    assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_err());
}

#[test]
fn withdrawal_never_mislabels_processor_as_recipient_for_nonempty_relay_data() {
    let mut bytes = direct_withdrawal();
    // Change the empty bytes to canonical one-byte data. The direct-only
    // descriptor must refuse instead of borrowing its recipient explanation.
    bytes[4 + 19 * 32 + 31] = 1;
    bytes.extend_from_slice(&[0; 32]);
    let mut ctx = context(&bytes);
    ctx.to = POOL.parse().unwrap();
    assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_err());
    let mut bytes = direct_withdrawal();
    bytes[4 + 17 * 32] = 1; // dirty address padding
    let mut ctx = context(&bytes);
    ctx.to = POOL.parse().unwrap();
    assert!(review_call(Catalog::built_in().unwrap(), &ctx).is_err());
}
