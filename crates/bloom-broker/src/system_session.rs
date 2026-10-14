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

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::{DecimalU64, Token};
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
