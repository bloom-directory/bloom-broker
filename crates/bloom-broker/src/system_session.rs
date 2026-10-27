//! Typed transfer verification at the Broker signing boundary. No price hints,
//! arbitrary calldata, allowance writes or router semantics are inferred.
use alloy::rlp::Decodable;
use alloy::{
    consensus::{SignableTransaction, Transaction, TxEip1559, TxLegacy},
    primitives::{Address, Signature, TxKind, U256},
};
use bloom_broker_api::{
    AssetId, CryptoSuite, DecimalU256, ProtocolError, ProtocolErrorCode, SystemSessionAction,
    SystemSessionChain, SystemSessionUse,
};

pub(crate) fn verify_evm(
    bytes: &[u8],
    suite: CryptoSuite,
    claimed: &SystemSessionUse,
) -> Result<(), ProtocolError> {
    if suite != CryptoSuite::Secp256k1Keccak256Recoverable {
        return Err(refused("EVM session requires Keccak signing"));
    }
    let actual = if bytes.first() == Some(&2) {
        let mut input = &bytes[1..];
        let tx = TxEip1559::decode(&mut input)
            .map_err(|_| refused("invalid EIP1559 session preimage"))?;
        if !input.is_empty()
            || !tx.access_list.0.is_empty()
            || tx.max_priority_fee_per_gas > tx.max_fee_per_gas
        {
            return Err(refused("unsupported EVM session envelope"));
        }
        decode_transfer(&tx, bytes, tx.max_fee_per_gas, &claimed.chain)?
    } else {
        let mut input = bytes;
        let tx =
            TxLegacy::decode(&mut input).map_err(|_| refused("invalid legacy session preimage"))?;
        if !input.is_empty() {
            return Err(refused("trailing session preimage bytes"));
        }
        decode_transfer(&tx, bytes, tx.gas_price, &claimed.chain)?
    };
    if actual != *claimed {
        return Err(refused(
            "typed session claim differs from transaction bytes",
        ));
    }
    Ok(())
}
fn decode_transfer<T: Transaction + SignableTransaction<Signature>>(
    tx: &T,
    bytes: &[u8],
    fee_per_gas: u128,
    declared_chain: &SystemSessionChain,
) -> Result<SystemSessionUse, ProtocolError> {
    if tx.encoded_for_signing() != bytes || tx.gas_limit() == 0 {
        return Err(refused("session transaction is noncanonical or gasless"));
    }
    let SystemSessionChain::Evm { chain, chain_id } = declared_chain else {
        return Err(refused("EVM bytes require an EVM session chain"));
    };
    if !matches!(chain_id.get(), 1 | 137 | 31337)
        || chain.as_str() != format!("evm-{}", chain_id.get())
        || tx.chain_id() != Some(chain_id.get())
    {
        return Err(refused("session transaction chain id mismatch"));
    }
    let TxKind::Call(to) = tx.kind() else {
        return Err(refused("contract creation is outside transfer sessions"));
    };
    let data = tx.input();
    let (action, token, recipient, amount) = if data.is_empty() {
        (SystemSessionAction::NativeTransfer, None, to, tx.value())
    } else {
        if data.len() != 68
            || data[..4] != [0xa9, 0x05, 0x9c, 0xbb]
            || data[4..16].iter().any(|b| *b != 0)
            || tx.value() != U256::ZERO
        {
            return Err(refused(
                "only canonical ERC20 transfer calldata belongs to token sessions",
            ));
        }
        (
            SystemSessionAction::Erc20Transfer,
            Some(AssetId {
                chain: chain.clone(),
                asset: format!("{to:#x}"),
            }),
            Address::from_slice(&data[16..36]),
            U256::from_be_slice(&data[36..68]),
        )
    };
    let fee = U256::from(tx.gas_limit())
        .checked_mul(U256::from(fee_per_gas))
        .ok_or_else(|| refused("session fee ceiling overflow"))?;
    Ok(SystemSessionUse {
        action,
        chain: declared_chain.clone(),
        token,
        recipient: format!("{recipient:#x}"),
        amount: DecimalU256::parse(amount.to_string())
            .map_err(|_| refused("invalid transfer amount"))?,
        maximum_fee: DecimalU256::parse(fee.to_string())
            .map_err(|_| refused("invalid fee ceiling"))?,
    })
}
fn refused(message: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::SelectorMismatch, message)
}

/// The initial native SOL profile is pinned to mainnet and this release-owned
/// endpoint. Machine/Petals cannot choose a URL or assert cluster freshness.
const SOLANA_MAINNET_RPC: &str = "https://api.mainnet-beta.solana.com";
const SOLANA_MAINNET_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/// A live observation must still be fresh when service reserves authority.
/// Kept outside custody scopes; these are trusted RPC facts, not signature proofs.
#[derive(Clone, Debug)]
pub(crate) struct SolanaSessionObservation {
    observed_at: std::time::Instant,
    pub(crate) fee_lamports: u64,
    pub(crate) context_slot: u64,
}
impl SolanaSessionObservation {
    pub(crate) fn ensure_fresh(&self) -> Result<(), ProtocolError> {
        if self.observed_at.elapsed() > std::time::Duration::from_secs(5) {
            return Err(refused("native SOL observation expired before reservation"));
        }
        Ok(())
    }
}

/// Check the configured cluster during preparation; admission repeats this with
/// the exact message, blockhash and fee. No Machine-provided genesis is trusted.
pub(crate) async fn validate_solana_scope_live(
    scope: &bloom_broker_api::SystemSessionScope,
) -> Result<(), ProtocolError> {
    scope.validate()?;
    if !scope
        .chains
        .iter()
        .any(|c| matches!(c, SystemSessionChain::Solana { .. }))
    {
        return Ok(());
    }
    tokio::task::spawn_blocking(|| {
        let request =
            serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"getGenesisHash", "params":[]});
        let response = solana_rpc(&request)?;
        if rpc_result(&response, 1)?.as_str() != Some(SOLANA_MAINNET_GENESIS) {
            return Err(refused(
                "configured SOL RPC genesis differs from reviewed mainnet",
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| refused("native SOL cluster observation failed"))?
}

/// Independently verify one legacy SOL transfer, then obtain all live facts in
/// one bounded RPC batch. SPL, CPI, account creation, nonce and compute-budget
/// instructions are rejected by the existing strict transfer verifier.
pub(crate) async fn verify_solana_live(
    bytes: &[u8],
    suite: CryptoSuite,
    claimed: &SystemSessionUse,
    system_claim: &bloom_broker_api::SystemUseClaim,
    expected_signer: &[u8; 32],
) -> Result<SolanaSessionObservation, ProtocolError> {
    let blockhash = verify_solana_bytes(bytes, suite, claimed, system_claim, expected_signer)?;
    let mut encoded = bloom_broker_api::Base64UrlBytes::from_bytes(bytes)
        .encoded()
        .replace('-', "+")
        .replace('_', "/");
    while encoded.len() % 4 != 0 {
        encoded.push('=');
    }
    let request = serde_json::json!([
        {"jsonrpc":"2.0", "id":1, "method":"getGenesisHash", "params":[]},
        {"jsonrpc":"2.0", "id":2, "method":"isBlockhashValid", "params":[blockhash,{"commitment":"confirmed"}]},
        {"jsonrpc":"2.0", "id":3, "method":"getFeeForMessage", "params":[encoded,{"commitment":"confirmed"}]},
    ]);
    let maximum_fee: u64 = claimed
        .maximum_fee
        .as_str()
        .parse()
        .map_err(|_| refused("native SOL maximum fee exceeds u64"))?;
    tokio::task::spawn_blocking(move || {
        let started_at = std::time::Instant::now();
        let response = solana_rpc(&request)?;
        let (fee_lamports, context_slot) = validate_solana_rpc_observation(&response, maximum_fee)?;
        let observation = SolanaSessionObservation {
            observed_at: started_at,
            fee_lamports,
            context_slot,
        };
        observation.ensure_fresh()?;
        Ok(observation)
    })
    .await
    .map_err(|_| refused("native SOL observation failed"))?
}

fn verify_solana_bytes(
    bytes: &[u8],
    suite: CryptoSuite,
    claimed: &SystemSessionUse,
    system_claim: &bloom_broker_api::SystemUseClaim,
    expected_signer: &[u8; 32],
) -> Result<String, ProtocolError> {
    use std::str::FromStr;
    let SystemSessionChain::Solana {
        chain,
        genesis_hash,
    } = &claimed.chain
    else {
        return Err(refused("SOL bytes require a Solana session chain"));
    };
    if suite != CryptoSuite::Ed25519Message
        || claimed.action != SystemSessionAction::NativeTransfer
        || claimed.token.is_some()
        || chain.as_str() != "solana-mainnet"
        || genesis_hash != SOLANA_MAINNET_GENESIS
        || system_claim.chain_context.chain_family.as_str() != "solana"
        || system_claim.chain_context.genesis_hash != *genesis_hash
    {
        return Err(refused("unsupported native SOL scope or cluster"));
    }
    let destination = bloom_solana_verify::Pubkey::from_str(&claimed.recipient)
        .map_err(|_| refused("invalid native SOL recipient"))?;
    let lamports = claimed
        .amount
        .as_str()
        .parse::<u64>()
        .map_err(|_| refused("native SOL amount exceeds u64"))?;
    let verified = bloom_solana_verify::verify_native_transfer(
        bytes,
        bloom_solana_verify::Pubkey::from_bytes(*expected_signer),
        destination,
        lamports,
        None,
    )
    .map_err(|_| refused("native SOL bytes differ from single-transfer claim"))?;
    if verified.recent_blockhash != system_claim.chain_context.recent_blockhash {
        return Err(refused("native SOL blockhash differs from signed bytes"));
    }
    Ok(verified.recent_blockhash)
}

fn solana_rpc(request: &serde_json::Value) -> Result<serde_json::Value, ProtocolError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .max_redirects(0)
        .build()
        .into();
    let body = serde_json::to_vec(request).map_err(|_| refused("cannot encode SOL observation"))?;
    let response = agent
        .post(SOLANA_MAINNET_RPC)
        .header("Content-Type", "application/json")
        .send(body.as_slice())
        .map_err(|_| refused("native SOL RPC unavailable; exact approval required"))?;
    let body = response
        .into_body()
        .with_config()
        .limit(256 * 1024)
        .read_to_string()
        .map_err(|_| refused("invalid native SOL RPC response"))?;
    serde_json::from_str(&body).map_err(|_| refused("invalid native SOL RPC JSON"))
}
fn rpc_result(response: &serde_json::Value, id: u64) -> Result<&serde_json::Value, ProtocolError> {
    if response["jsonrpc"] != "2.0"
        || response["id"].as_u64() != Some(id)
        || response.get("error").is_some()
    {
        return Err(refused("invalid native SOL RPC result identity"));
    }
    response
        .get("result")
        .filter(|r| !r.is_null())
        .ok_or_else(|| refused("native SOL RPC result is unavailable"))
}
fn validate_solana_rpc_observation(
    response: &serde_json::Value,
    maximum_fee: u64,
) -> Result<(u64, u64), ProtocolError> {
    let rows = response
        .as_array()
        .filter(|r| r.len() == 3)
        .ok_or_else(|| refused("incomplete native SOL observation batch"))?;
    let result = |id| {
        let matches = rows
            .iter()
            .filter(|r| r["id"].as_u64() == Some(id))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(refused("duplicate or missing native SOL observation"));
        }
        rpc_result(matches[0], id)
    };
    if result(1)?.as_str() != Some(SOLANA_MAINNET_GENESIS) {
        return Err(refused("native SOL observation has wrong genesis"));
    }
    let valid = result(2)?;
    let fee = result(3)?;
    let valid_slot = valid["context"]["slot"]
        .as_u64()
        .ok_or_else(|| refused("missing blockhash observation slot"))?;
    let fee_slot = fee["context"]["slot"]
        .as_u64()
        .ok_or_else(|| refused("missing fee observation slot"))?;
    let lamports = fee["value"]
        .as_u64()
        .ok_or_else(|| refused("SOL fee unavailable for exact message"))?;
    if valid["value"].as_bool() != Some(true)
        || lamports == 0
        || lamports > maximum_fee
        || valid_slot.abs_diff(fee_slot) > 32
    {
        return Err(refused(
            "SOL blockhash expired, fee exceeds scope, or observations disagree",
        ));
    }
    Ok((lamports, valid_slot.min(fee_slot)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::{DecimalU64, Token};
    fn solana_fixture() -> (
        Vec<u8>,
        SystemSessionUse,
        bloom_broker_api::SystemUseClaim,
        [u8; 32],
    ) {
        use bloom_broker_api::{ClaimAssurance, Digest32, RequestNonce, SystemChainContext};
        use bloom_solana_verify::{Pubkey, system_transfer::transfer_message};
        let signer = [1; 32];
        let recipient = Pubkey::from_bytes([2; 32]);
        let blockhash = [3; 32];
        let bytes = transfer_message(Pubkey::from_bytes(signer), recipient, 100, blockhash)
            .unwrap()
            .serialize();
        let claimed = SystemSessionUse {
            action: SystemSessionAction::NativeTransfer,
            chain: SystemSessionChain::Solana {
                chain: Token::new("solana-mainnet").unwrap(),
                genesis_hash: SOLANA_MAINNET_GENESIS.into(),
            },
            token: None,
            recipient: recipient.to_string(),
            amount: DecimalU256::parse("100").unwrap(),
            maximum_fee: DecimalU256::parse("5000").unwrap(),
        };
        let system = bloom_broker_api::SystemUseClaim {
            component_id: Token::new("bloom-machine").unwrap(),
            action_class: Token::new("solana.transfer.confirm").unwrap(),
            operation_class: Token::new("solana.native-transfer").unwrap(),
            crypto_suite: CryptoSuite::Ed25519Message,
            payload_digest: Digest32::from_bytes(bloom_solana_verify::message_digest(&bytes)),
            ordered_hashes: vec![],
            declared_debits: vec![],
            declared_destinations: vec![],
            declared_fee: bloom_broker_api::DeclaredFee::None,
            nonce: RequestNonce::new("00".repeat(16)).unwrap(),
            chain_context: SystemChainContext {
                chain_family: Token::new("solana").unwrap(),
                genesis_hash: SOLANA_MAINNET_GENESIS.into(),
                recent_blockhash: bs58::encode(blockhash).into_string(),
                last_valid_block_height: DecimalU64::new(123),
            },
            claim_assurance: ClaimAssurance::MachineAsserted,
        };
        (bytes, claimed, system, signer)
    }

    #[test]
    fn solana_single_transfer_binds_account_recipient_amount_cluster_and_blockhash() {
        let (bytes, claimed, system, signer) = solana_fixture();
        verify_solana_bytes(
            &bytes,
            CryptoSuite::Ed25519Message,
            &claimed,
            &system,
            &signer,
        )
        .unwrap();
        for field in ["recipient", "amount", "token", "genesis"] {
            let mut changed = claimed.clone();
            match field {
                "recipient" => {
                    changed.recipient = bloom_solana_verify::Pubkey::from_bytes([4; 32]).to_string()
                }
                "amount" => changed.amount = DecimalU256::parse("99").unwrap(),
                "token" => {
                    changed.token = Some(AssetId {
                        chain: Token::new("solana-mainnet").unwrap(),
                        asset: "mint".into(),
                    })
                }
                _ => {
                    changed.chain = SystemSessionChain::Solana {
                        chain: Token::new("solana-mainnet").unwrap(),
                        genesis_hash: "untrusted".into(),
                    }
                }
            }
            assert!(
                verify_solana_bytes(
                    &bytes,
                    CryptoSuite::Ed25519Message,
                    &changed,
                    &system,
                    &signer
                )
                .is_err(),
                "{field}"
            );
        }
        assert!(
            verify_solana_bytes(
                &bytes,
                CryptoSuite::Ed25519Message,
                &claimed,
                &system,
                &[4; 32]
            )
            .is_err()
        );
        let mut changed = system.clone();
        changed.chain_context.recent_blockhash = "wrong".into();
        assert!(
            verify_solana_bytes(
                &bytes,
                CryptoSuite::Ed25519Message,
                &claimed,
                &changed,
                &signer
            )
            .is_err()
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            verify_solana_bytes(
                &trailing,
                CryptoSuite::Ed25519Message,
                &claimed,
                &system,
                &signer
            )
            .is_err()
        );
        let mut parsed = bloom_solana_verify::message::parse_message(&bytes).unwrap();
        parsed.instructions.push(parsed.instructions[0].clone());
        assert!(
            verify_solana_bytes(
                &parsed.serialize(),
                CryptoSuite::Ed25519Message,
                &claimed,
                &system,
                &signer
            )
            .is_err()
        );
        parsed.instructions.truncate(1);
        parsed.account_keys[2] = bloom_solana_verify::Pubkey::from_bytes([5; 32]);
        assert!(
            verify_solana_bytes(
                &parsed.serialize(),
                CryptoSuite::Ed25519Message,
                &claimed,
                &system,
                &signer
            )
            .is_err()
        );
    }

    #[test]
    fn solana_rpc_requires_live_blockhash_genesis_exact_message_fee_and_coherent_slots() {
        let good = serde_json::json!([
            {"jsonrpc":"2.0","id":3,"result":{"context":{"slot":101},"value":5000}},
            {"jsonrpc":"2.0","id":1,"result":SOLANA_MAINNET_GENESIS},
            {"jsonrpc":"2.0","id":2,"result":{"context":{"slot":100},"value":true}},
        ]);
        assert_eq!(
            validate_solana_rpc_observation(&good, 5000).unwrap(),
            (5000, 100)
        );
        assert!(validate_solana_rpc_observation(&good, 4999).is_err());
        for (row, field, value) in [
            (0, "value", serde_json::Value::Null),
            (0, "value", serde_json::json!(0)),
            (2, "value", serde_json::json!(false)),
        ] {
            let mut bad = good.clone();
            bad[row]["result"][field] = value;
            assert!(validate_solana_rpc_observation(&bad, 5000).is_err());
        }
        let mut bad = good.clone();
        bad[1]["result"] = serde_json::json!("other genesis");
        assert!(validate_solana_rpc_observation(&bad, 5000).is_err());
        let mut bad = good.clone();
        bad[0]["result"]["context"]["slot"] = serde_json::json!(1000);
        assert!(validate_solana_rpc_observation(&bad, 5000).is_err());
        let mut bad = good.clone();
        bad[0]["id"] = serde_json::json!(2);
        assert!(validate_solana_rpc_observation(&bad, 5000).is_err());
        let expired = SolanaSessionObservation {
            observed_at: std::time::Instant::now() - std::time::Duration::from_secs(6),
            fee_lamports: 5000,
            context_slot: 100,
        };
        assert!(expired.ensure_fresh().is_err());
    }

    fn claim(chain: u64, recipient: Address, amount: U256, fee: u64) -> SystemSessionUse {
        SystemSessionUse {
            action: SystemSessionAction::NativeTransfer,
            chain: SystemSessionChain::Evm {
                chain: Token::new("evm-31337").unwrap(),
                chain_id: DecimalU64::new(chain),
            },
            token: None,
            recipient: format!("{recipient:#x}"),
            amount: DecimalU256::parse(amount.to_string()).unwrap(),
            maximum_fee: DecimalU256::parse(fee.to_string()).unwrap(),
        }
    }
    #[test]
    fn independently_verifies_legacy_and_eip1559_preimages_and_refuses_changed_economics() {
        let to = Address::repeat_byte(0x11);
        let amount = U256::from(25u64);
        let legacy = TxLegacy {
            chain_id: Some(31337),
            nonce: 0,
            gas_price: 2,
            gas_limit: 21000,
            to: TxKind::Call(to),
            value: amount,
            input: Default::default(),
        };
        let bytes = legacy.encoded_for_signing();
        let expected = claim(31337, to, amount, 42000);
        verify_evm(
            &bytes,
            CryptoSuite::Secp256k1Keccak256Recoverable,
            &expected,
        )
        .unwrap();
        let modern = TxEip1559 {
            chain_id: 31337,
            gas_limit: 21000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(to),
            value: amount,
            ..Default::default()
        };
        verify_evm(
            &modern.encoded_for_signing(),
            CryptoSuite::Secp256k1Keccak256Recoverable,
            &expected,
        )
        .unwrap();
        // Matching chain bytes alone do not cover OP Stack L1 fee economics.
        let layer_two = TxEip1559 {
            chain_id: 8453,
            ..modern.clone()
        };
        let mut layer_two_claim = expected.clone();
        layer_two_claim.chain = SystemSessionChain::Evm {
            chain: Token::new("evm-8453").unwrap(),
            chain_id: DecimalU64::new(8453),
        };
        assert!(
            verify_evm(
                &layer_two.encoded_for_signing(),
                CryptoSuite::Secp256k1Keccak256Recoverable,
                &layer_two_claim
            )
            .is_err()
        );
        for changed in [
            claim(1, to, amount, 42000),
            claim(31337, Address::repeat_byte(0x22), amount, 42000),
            claim(31337, to, amount + U256::from(1u8), 42000),
            claim(31337, to, amount, 41999),
        ] {
            assert!(
                verify_evm(&bytes, CryptoSuite::Secp256k1Keccak256Recoverable, &changed).is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            verify_evm(
                &trailing,
                CryptoSuite::Secp256k1Keccak256Recoverable,
                &expected
            )
            .is_err()
        );
        let malicious = TxEip1559 {
            input: vec![0xde, 0xad, 0xbe, 0xef].into(),
            ..modern
        };
        assert!(
            verify_evm(
                &malicious.encoded_for_signing(),
                CryptoSuite::Secp256k1Keccak256Recoverable,
                &expected
            )
            .is_err()
        );
    }
    #[test]
    fn canonical_token_transfer_is_bound_to_token_recipient_amount_and_fee() {
        let token = Address::repeat_byte(0x33);
        let recipient = Address::repeat_byte(0x11);
        let amount = U256::from(1_000_000u64);
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(recipient.as_slice());
        data.extend_from_slice(&amount.to_be_bytes::<32>());
        let tx = TxEip1559 {
            chain_id: 31337,
            gas_limit: 50000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(token),
            input: data.clone().into(),
            ..Default::default()
        };
        let mut expected = claim(31337, recipient, amount, 100000);
        expected.action = SystemSessionAction::Erc20Transfer;
        expected.token = Some(AssetId {
            chain: Token::new("evm-31337").unwrap(),
            asset: format!("{token:#x}"),
        });
        verify_evm(
            &tx.encoded_for_signing(),
            CryptoSuite::Secp256k1Keccak256Recoverable,
            &expected,
        )
        .unwrap();
        data[0] = 0x09;
        let changed = TxEip1559 {
            input: data.into(),
            ..tx
        };
        assert!(
            verify_evm(
                &changed.encoded_for_signing(),
                CryptoSuite::Secp256k1Keccak256Recoverable,
                &expected
            )
            .is_err()
        );
    }
}
