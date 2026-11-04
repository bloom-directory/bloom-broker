//! Machine's Tempo MPP payments (shared/pm89-payment-review-contract, sections
//! 2 and 3). The transaction is decoded by hand from the exact `0x76` signing
//! preimage: `tempo-primitives` pulls in revm, and its decoder refuses the
//! sponsored placeholder byte. Only charge transfers and the escrow session
//! open are accepted; every other call shape is refused.
use super::{MessageField, MessageReview, ProtocolError, display_amount, invalid, known_token};
use alloy::primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy::rlp::{Decodable, Header};
use serde::Deserialize;

const TX_TYPE: u8 = 0x76;
const MAX_CALLS: usize = 16;
const TRANSFER: &str = "transfer(address,uint256)";
const TRANSFER_WITH_MEMO: &str = "transferWithMemo(address,uint256,bytes32)";
const APPROVE: &str = "approve(address,uint256)";
const OPEN: &str = "open(address,address,uint128,bytes32,address)";
const UNKNOWN_SHAPE: &str = "Tempo transaction is neither a charge (token transfers) nor a session open (approve, then open on the escrow); Bloom refuses other call shapes";

/// The stream-channel escrow Bloom accepts on each Tempo chain. A merchant
/// naming its own contract could otherwise take the deposit.
fn known_escrow(chain_id: u64) -> Option<Address> {
    match chain_id {
        4217 => Some(address!("33b901018174DDabE4841042ab76ba85D4e24f25")),
        42431 => Some(address!("e1c4d3dce17bc111181ddf716f75bae49e61a336")),
        _ => None,
    }
}

#[derive(Debug, PartialEq)]
struct Call {
    to: Address,
    value: U256,
    input: Bytes,
}

#[derive(Debug, PartialEq)]
struct Transaction {
    chain_id: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    calls: Vec<Call>,
    nonce_key: U256,
    nonce: u64,
    valid_before: Option<u64>,
    valid_after: Option<u64>,
    fee_token: Option<Address>,
    sponsored: bool,
}

fn item<T: Decodable>(buf: &mut &[u8]) -> Result<T, ProtocolError> {
    T::decode(buf).map_err(|_| invalid("Tempo transaction has a malformed field"))
}

fn list<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], ProtocolError> {
    let header = Header::decode(buf).map_err(|_| invalid("Tempo transaction is malformed"))?;
    if !header.list || header.payload_length > buf.len() {
        return Err(invalid("Tempo transaction is malformed"));
    }
    let (payload, rest) = buf.split_at(header.payload_length);
    *buf = rest;
    Ok(payload)
}

fn take(buf: &mut &[u8], byte: u8) -> bool {
    let found = buf.first() == Some(&byte);
    if found {
        *buf = &buf[1..];
    }
    found
}

fn optional<T: Decodable>(buf: &mut &[u8]) -> Result<Option<T>, ProtocolError> {
    if take(buf, 0x80) {
        Ok(None)
    } else {
        item(buf).map(Some)
    }
}

fn decode_transaction(bytes: &[u8]) -> Result<Transaction, ProtocolError> {
    let Some((&TX_TYPE, mut rest)) = bytes.split_first() else {
        return Err(invalid("Tempo signing preimage must start with type 0x76"));
    };
    let mut fields = list(&mut rest)?;
    if !rest.is_empty() {
        return Err(invalid("Tempo signing preimage has trailing bytes"));
    }
    let chain_id = item(&mut fields)?;
    let max_priority_fee_per_gas = item(&mut fields)?;
    let max_fee_per_gas = item(&mut fields)?;
    let gas_limit = item(&mut fields)?;
    let mut encoded_calls = list(&mut fields)?;
    let mut calls = Vec::new();
    while !encoded_calls.is_empty() {
        if calls.len() == MAX_CALLS {
            return Err(invalid("Tempo transaction has too many calls"));
        }
        let mut call = list(&mut encoded_calls)?;
        if call.first() == Some(&0x80) {
            return Err(invalid(
                "Tempo transaction creates a contract; Bloom refuses contract creation",
            ));
        }
        calls.push(Call {
            to: item(&mut call)?,
            value: item(&mut call)?,
            input: item(&mut call)?,
        });
        if !call.is_empty() {
            return Err(invalid("Tempo call has extra fields"));
        }
    }
    if !take(&mut fields, 0xc0) {
        return Err(invalid(
            "Tempo transaction carries an access list; Bloom refuses it",
        ));
    }
    let nonce_key = item(&mut fields)?;
    let nonce = item(&mut fields)?;
    let valid_before = optional(&mut fields)?;
    let valid_after = optional(&mut fields)?;
    let fee_token = optional(&mut fields)?;
    let sponsored = if take(&mut fields, 0x00) {
        true
    } else if take(&mut fields, 0x80) {
        false
    } else {
        return Err(invalid(
            "Tempo fee-payer slot must be 0x80 (unsponsored) or 0x00 (sponsored)",
        ));
    };
    if sponsored && fee_token.is_some() {
        return Err(invalid(
            "A sponsored Tempo transaction cannot commit to a fee token",
        ));
    }
    if !take(&mut fields, 0xc0) {
        return Err(invalid(
            "Tempo transaction carries an authorization list; Bloom refuses it",
        ));
    }
    if !fields.is_empty() {
        return Err(invalid(
            "Tempo transaction carries a key authorization or extra fields; Bloom refuses them",
        ));
    }
    if known_escrow(chain_id).is_none() {
        return Err(invalid(
            "Tempo transaction is for a chain Bloom does not review (only 4217 and 42431)",
        ));
    }
    if calls.iter().any(|call| !call.value.is_zero()) {
        return Err(invalid(
            "Tempo call carries a native value; Bloom refuses it",
        ));
    }
    Ok(Transaction {
        chain_id,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        calls,
        nonce_key,
        nonce,
        valid_before,
        valid_after,
        fee_token,
        sponsored,
    })
}

/// The ABI words of `input` when it calls exactly `signature` with `N` static arguments.
fn words<const N: usize>(input: &[u8], signature: &str) -> Option<[B256; N]> {
    (input.len() == 4 + 32 * N && input[..4] == keccak256(signature)[..4])
        .then(|| std::array::from_fn(|i| B256::from_slice(&input[4 + 32 * i..36 + 32 * i])))
}

fn word_address(word: &B256) -> Option<Address> {
    word[..12]
        .iter()
        .all(|byte| *byte == 0)
        .then(|| Address::from_slice(&word[12..]))
}

fn transfer(call: &Call) -> Option<(Address, U256, Option<B256>)> {
    if let Some([to, amount]) = words::<2>(&call.input, TRANSFER) {
        return Some((word_address(&to)?, U256::from_be_bytes(amount.0), None));
    }
    let [to, amount, memo] = words::<3>(&call.input, TRANSFER_WITH_MEMO)?;
    Some((
        word_address(&to)?,
        U256::from_be_bytes(amount.0),
        Some(memo),
    ))
}

fn channel_id(
    payer: Address,
    payee: Address,
    token: Address,
    salt: B256,
    authorized_signer: Address,
    escrow: Address,
    chain_id: u64,
) -> B256 {
    let mut encoded = Vec::with_capacity(7 * 32);
    for address in [payer, payee, token] {
        encoded.extend_from_slice(address.into_word().as_slice());
    }
    encoded.extend_from_slice(salt.as_slice());
    for address in [authorized_signer, escrow] {
        encoded.extend_from_slice(address.into_word().as_slice());
    }
    encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    keccak256(encoded)
}

fn token_label(chain_id: u64, token: Address) -> String {
    match known_token(chain_id, token) {
        Some(known) => format!("{} ({token:#x})", known.symbol),
        None => format!("{token:#x} (unlisted token; amounts are raw units)"),
    }
}

fn amount(chain_id: u64, token: Address, value: U256) -> String {
    display_amount(&value.to_string(), known_token(chain_id, token).as_ref())
}

fn push(review: &mut MessageReview, path: &str, value: String) {
    review.fields.push(MessageField {
        path: path.into(),
        value,
    });
}

pub(super) fn transaction(
    hex_preimage: &str,
    signer: Address,
    review: &mut MessageReview,
) -> Result<Vec<u8>, ProtocolError> {
    let preimage = hex_preimage
        .strip_prefix("0x")
        .and_then(|digits| hex::decode(digits).ok())
        .ok_or_else(|| invalid("Tempo transaction must be 0x-prefixed hex"))?;
    let tx = decode_transaction(&preimage)?;
    let chain = tx.chain_id;
    review.kind = "tempo_transaction".into();
    push(review, "Chain ID", chain.to_string());
    let transfers: Option<Vec<_>> = tx.calls.iter().map(transfer).collect();
    if let Some(transfers) = transfers.filter(|transfers| !transfers.is_empty()) {
        let token = tx.calls[0].to;
        if tx.calls.iter().any(|call| call.to != token) {
            return Err(invalid(
                "Tempo charge transfers more than one token; Bloom refuses mixed-token charges",
            ));
        }
        review.title = "Pay with Tempo".into();
        push(review, "Token", token_label(chain, token));
        let mut total = U256::ZERO;
        let several = transfers.len() > 1;
        for (index, (to, value, memo)) in transfers.into_iter().enumerate() {
            let suffix = if several {
                format!(" {}", index + 1)
            } else {
                String::new()
            };
            total = total
                .checked_add(value)
                .ok_or_else(|| invalid("Tempo charge total overflows"))?;
            push(review, &format!("Recipient{suffix}"), format!("{to:#x}"));
            push(
                review,
                &format!("Amount{suffix}"),
                amount(chain, token, value),
            );
            if let Some(memo) = memo {
                push(review, &format!("Memo{suffix}"), format!("{memo:#x}"));
            }
        }
        push(review, "Total", amount(chain, token, total));
    } else {
        let [approve, open] = tx.calls.as_slice() else {
            return Err(invalid(UNKNOWN_SHAPE));
        };
        let (Some([spender, allowance]), Some([payee, token, deposit, salt, authorized])) = (
            words::<2>(&approve.input, APPROVE),
            words::<5>(&open.input, OPEN),
        ) else {
            return Err(invalid(UNKNOWN_SHAPE));
        };
        let escrow = known_escrow(chain).ok_or_else(|| invalid(UNKNOWN_SHAPE))?;
        if open.to != escrow {
            return Err(invalid(&format!(
                "Session open uses escrow {:#x}, not Bloom's known escrow {escrow:#x} for chain {chain}",
                open.to
            )));
        }
        let (Some(spender), Some(payee), Some(token), Some(authorized)) = (
            word_address(&spender),
            word_address(&payee),
            word_address(&token),
            word_address(&authorized),
        ) else {
            return Err(invalid("Session open has a non-canonical address argument"));
        };
        let deposit = U256::from_be_bytes(deposit.0);
        if spender != escrow {
            return Err(invalid(
                "Session open approves a spender other than the escrow",
            ));
        }
        if approve.to != token {
            return Err(invalid(
                "Session open approves a different token from the channel token",
            ));
        }
        if U256::from_be_bytes(allowance.0) != deposit || deposit >= U256::from(1) << 128 {
            return Err(invalid(
                "Session open approves an amount different from its deposit",
            ));
        }
        if authorized != signer {
            return Err(invalid(
                "Session open authorizes a voucher signer other than this wallet",
            ));
        }
        review.title = "Open a Tempo payment channel".into();
        push(review, "Payee", format!("{payee:#x}"));
        push(review, "Token", token_label(chain, token));
        push(review, "Deposit", amount(chain, token, deposit));
        push(review, "Escrow", format!("{escrow:#x}"));
        push(
            review,
            "Channel ID",
            format!(
                "{:#x}",
                channel_id(signer, payee, token, salt, authorized, escrow, chain)
            ),
        );
    }
    if tx.sponsored {
        push(
            review,
            "Network fee",
            "The merchant pays the network fee.".into(),
        );
    } else {
        push(
            review,
            "Network fee",
            "Bloom does not show the network fee amount".into(),
        );
        push(
            review,
            "Network fee token",
            tx.fee_token.map_or_else(
                || "Not named in the transaction".into(),
                |token| token_label(chain, token),
            ),
        );
        push(review, "Gas limit", tx.gas_limit.to_string());
        push(
            review,
            "Max fee per gas (raw units)",
            tx.max_fee_per_gas.to_string(),
        );
        push(
            review,
            "Max priority fee per gas (raw units)",
            tx.max_priority_fee_per_gas.to_string(),
        );
    }
    if let Some(after) = tx.valid_after {
        push(review, "Valid from", format!("{after} Unix seconds"));
    }
    if let Some(before) = tx.valid_before {
        push(review, "Valid until", format!("{before} Unix seconds"));
    }
    push(review, "Nonce key", tx.nonce_key.to_string());
    push(review, "Nonce", tx.nonce.to_string());
    Ok(preimage)
}

/// Payee, token, salt and authorized signer Machine recorded when it opened
/// the channel. They let Broker recompute the channel ID.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Channel {
    payee: String,
    token: String,
    salt: String,
    authorized_signer: String,
}

fn hex_field<const N: usize>(text: &str, name: &str) -> Result<[u8; N], ProtocolError> {
    text.strip_prefix("0x")
        .filter(|digits| digits.len() == 2 * N)
        .and_then(|digits| hex::decode(digits).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| invalid(&format!("Tempo voucher {name} is not {N} hex bytes")))
}

pub(super) fn voucher(
    chain_id: u64,
    escrow: &str,
    channel: &str,
    cumulative: &str,
    details: Option<Channel>,
    signer: Address,
    review: &mut MessageReview,
) -> Result<Vec<u8>, ProtocolError> {
    let escrow = Address::from(hex_field::<20>(escrow, "escrow")?);
    let channel = B256::from(hex_field::<32>(channel, "channel ID")?);
    if cumulative.is_empty()
        || !cumulative.bytes().all(|b| b.is_ascii_digit())
        || (cumulative.len() > 1 && cumulative.starts_with('0'))
    {
        return Err(invalid("Tempo voucher amount is not a decimal integer"));
    }
    let cumulative: u128 = cumulative
        .parse()
        .map_err(|_| invalid("Tempo voucher amount exceeds uint128"))?;
    if known_escrow(chain_id) != Some(escrow) {
        return Err(invalid(&format!(
            "Tempo voucher names escrow {escrow:#x}, not Bloom's known escrow for chain {chain_id}"
        )));
    }
    let mut domain = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
    .to_vec();
    domain.extend_from_slice(keccak256("Tempo Stream Channel").as_slice());
    domain.extend_from_slice(keccak256("1").as_slice());
    domain.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    domain.extend_from_slice(escrow.into_word().as_slice());
    let mut message = keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)").to_vec();
    message.extend_from_slice(channel.as_slice());
    message.extend_from_slice(&U256::from(cumulative).to_be_bytes::<32>());
    let mut preimage = vec![0x19, 0x01];
    preimage.extend_from_slice(keccak256(domain).as_slice());
    preimage.extend_from_slice(keccak256(message).as_slice());

    review.kind = "tempo_voucher".into();
    review.title = "Sign a Tempo payment channel voucher".into();
    push(review, "Chain ID", chain_id.to_string());
    match details {
        Some(details) => {
            let payee = Address::from(hex_field::<20>(&details.payee, "payee")?);
            let token = Address::from(hex_field::<20>(&details.token, "token")?);
            let salt = B256::from(hex_field::<32>(&details.salt, "salt")?);
            let authorized = Address::from(hex_field::<20>(
                &details.authorized_signer,
                "authorized signer",
            )?);
            if authorized != signer {
                return Err(invalid(
                    "Tempo voucher channel authorizes a signer other than this wallet",
                ));
            }
            if channel_id(signer, payee, token, salt, authorized, escrow, chain_id) != channel {
                return Err(invalid(
                    "Tempo voucher channel details do not produce its channel ID",
                ));
            }
            let total = amount(chain_id, token, U256::from(cumulative));
            push(
                review,
                "Authorizes",
                format!("Lets {payee:#x} collect up to {total} in total from this channel"),
            );
            push(review, "Payee", format!("{payee:#x}"));
            push(review, "Token", token_label(chain_id, token));
            push(review, "Cumulative amount", total);
        }
        None => {
            push(
                review,
                "Cumulative amount (raw units)",
                cumulative.to_string(),
            );
            review.warnings.push("Bloom cannot confirm who this channel pays or in which token; it was opened before Bloom recorded channel details.".into());
        }
    }
    push(review, "Channel ID", format!("{channel:#x}"));
    push(review, "Escrow", format!("{escrow:#x}"));
    Ok(preimage)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloy::rlp::Encodable;
    use serde_json::json;

    // Produced once by a throwaway crate (not in this repository) against
    // mpp 0.10.4 / tempo-primitives 1.8.0 / tempo-alloy 1.8.0:
    // `build_tempo_tx(TempoTxOptions { .. }).encoded_for_signing()` with calls
    // from `ITIP20::{transferWithMemoCall, transferCall, approveCall}` and the
    // escrow `openCall`, `compute_channel_id`, and `Voucher::eip712_hash_struct`
    // under the `Tempo Stream Channel` domain. Signer is 0x…07, chain 4217.
    pub(in crate::message_review) const CHARGE_UNSPONSORED_MEMO: &str = "0x76f8ae821079018504a817c8008307a120f87ef87c9420c000000000000000000000000000000000000080b86495777d590000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000016e360ababababababababababababababababababababababababababababababababc080078477359400809420c000000000000000000000000000000000000080c0";
    const CHARGE_SPONSORED_SPLIT: &str = "0x76f8f8821079018504a817c800830f4240f8bcf85c9420c000000000000000000000b9537d11c60e8b5080b844a9059cbb000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000f4240f85c9420c000000000000000000000b9537d11c60e8b5080b844a9059cbb0000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000003d090c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff808477359400808000c0";
    const OPEN_SPONSORED: &str = "0x76f90159821079018504a817c800830f4240f9011cf85c9420c000000000000000000000000000000000000080b844095ea7b300000000000000000000000033b901018174ddabe4841042ab76ba85d4e24f2500000000000000000000000000000000000000000000000000000000004c4b40f8bc9433b901018174ddabe4841042ab76ba85d4e24f2580b8a4c79ea485000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000020c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c4b4055555555555555555555555555555555555555555555555555555555555555550000000000000000000000000000000000000000000000000000000000000007c0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff808477359400808000c0";
    const OPEN_CHANNEL_ID: &str =
        "0xda89d81be4024742e07d18f1281d42a6f617881eddc36fe5706b55fd5fd6ad5b";
    const VOUCHER_PREIMAGE: &str = "0x1901c3eb96493d8b195ca1671190861b10909e09ea4f1662c5a577f2bcc7ecf47eb813ebbcd32aa7e2877c04a33cfdd0be6837ba492ec9ac14c875c202be7018ed6b";

    pub(in crate::message_review) const PATH_USD: Address =
        address!("20c0000000000000000000000000000000000000");
    const USDC_E: Address = address!("20C000000000000000000000b9537d11c60E8b50");
    const ESCROW: Address = address!("33b901018174DDabE4841042ab76ba85D4e24f25");

    fn signer() -> Address {
        Address::with_last_byte(7)
    }

    /// Encodes the contract's byte layout field by field, independently of
    /// the decoder. `extra` is appended inside the list (a key authorization).
    #[derive(Clone)]
    struct Draft {
        chain_id: u64,
        gas_limit: u64,
        calls: Vec<(Option<Address>, U256, Vec<u8>)>,
        access_list: Vec<u8>,
        nonce_key: U256,
        nonce: u64,
        valid_before: Option<u64>,
        fee_token: Option<Address>,
        sponsored: bool,
        extra: Vec<u8>,
    }

    impl Draft {
        fn new(calls: Vec<(Address, Vec<u8>)>) -> Self {
            Self {
                chain_id: 4217,
                gas_limit: 1_000_000,
                calls: calls
                    .into_iter()
                    .map(|(to, input)| (Some(to), U256::ZERO, input))
                    .collect(),
                access_list: vec![0xc0],
                nonce_key: U256::MAX,
                nonce: 0,
                valid_before: Some(2_000_000_000),
                fee_token: None,
                sponsored: true,
                extra: vec![],
            }
        }

        fn encode(&self) -> Vec<u8> {
            let mut calls = Vec::new();
            for (to, value, input) in &self.calls {
                let mut call = Vec::new();
                match to {
                    Some(to) => to.encode(&mut call),
                    None => call.push(0x80),
                }
                value.encode(&mut call);
                Bytes::from(input.clone()).encode(&mut call);
                Header {
                    list: true,
                    payload_length: call.len(),
                }
                .encode(&mut calls);
                calls.extend(call);
            }
            let mut fields = Vec::new();
            self.chain_id.encode(&mut fields);
            1u128.encode(&mut fields);
            20_000_000_000u128.encode(&mut fields);
            self.gas_limit.encode(&mut fields);
            Header {
                list: true,
                payload_length: calls.len(),
            }
            .encode(&mut fields);
            fields.extend(calls);
            fields.extend(&self.access_list);
            self.nonce_key.encode(&mut fields);
            self.nonce.encode(&mut fields);
            match self.valid_before {
                Some(before) => before.encode(&mut fields),
                None => fields.push(0x80),
            }
            fields.push(0x80);
            match self.fee_token {
                Some(token) => token.encode(&mut fields),
                None => fields.push(0x80),
            }
            fields.push(if self.sponsored { 0x00 } else { 0x80 });
            fields.push(0xc0);
            fields.extend(&self.extra);
            let mut out = vec![TX_TYPE];
            Header {
                list: true,
                payload_length: fields.len(),
            }
            .encode(&mut out);
            out.extend(fields);
            out
        }
    }

    pub(in crate::message_review) fn calldata(signature: &str, words: &[B256]) -> Vec<u8> {
        let mut out = keccak256(signature)[..4].to_vec();
        for word in words {
            out.extend_from_slice(word.as_slice());
        }
        out
    }

    fn word(value: u128) -> B256 {
        U256::from(value).into()
    }

    fn open_calls(
        escrow: Address,
        approved: u128,
        deposit: u128,
        authorized: Address,
    ) -> Vec<(Address, Vec<u8>)> {
        vec![
            (
                PATH_USD,
                calldata(APPROVE, &[escrow.into_word(), word(approved)]),
            ),
            (
                escrow,
                calldata(
                    OPEN,
                    &[
                        Address::with_last_byte(10).into_word(),
                        PATH_USD.into_word(),
                        word(deposit),
                        B256::repeat_byte(0x55),
                        authorized.into_word(),
                    ],
                ),
            ),
        ]
    }

    fn empty() -> MessageReview {
        MessageReview {
            kind: String::new(),
            title: String::new(),
            signer: String::new(),
            payload_keccak: String::new(),
            domain: vec![],
            fields: vec![],
            payment: None,
            venue_asset: None,
            collateral_asset: None,
            warnings: vec![],
        }
    }

    fn read(bytes: &[u8]) -> Result<MessageReview, ProtocolError> {
        let mut review = empty();
        let preimage = transaction(&format!("0x{}", hex::encode(bytes)), signer(), &mut review)?;
        assert_eq!(preimage, bytes);
        Ok(review)
    }

    fn field<'a>(review: &'a MessageReview, path: &str) -> &'a str {
        &review
            .fields
            .iter()
            .find(|field| field.path == path)
            .unwrap_or_else(|| panic!("{path} missing from {:?}", review.fields))
            .value
    }

    fn refused(bytes: &[u8], expected: &str) {
        let error = read(bytes).unwrap_err();
        assert!(
            error.message.contains(expected),
            "{expected}: {}",
            error.message
        );
    }

    #[test]
    fn real_tempo_encodings_match_the_contract_layout_and_show_the_payment() {
        let memo = Draft {
            calls: vec![(
                Some(PATH_USD),
                U256::ZERO,
                calldata(
                    TRANSFER_WITH_MEMO,
                    &[
                        Address::with_last_byte(8).into_word(),
                        word(1_500_000),
                        B256::repeat_byte(0xab),
                    ],
                ),
            )],
            gas_limit: 500_000,
            nonce_key: U256::ZERO,
            nonce: 7,
            fee_token: Some(PATH_USD),
            sponsored: false,
            ..Draft::new(vec![])
        };
        assert_eq!(
            format!("0x{}", hex::encode(memo.encode())),
            CHARGE_UNSPONSORED_MEMO
        );
        let review = read(&memo.encode()).unwrap();
        assert_eq!(review.title, "Pay with Tempo");
        assert_eq!(
            field(&review, "Recipient"),
            "0x0000000000000000000000000000000000000008"
        );
        assert_eq!(field(&review, "Amount"), "1.5 pathUSD");
        assert_eq!(field(&review, "Memo"), format!("0x{}", "ab".repeat(32)));
        assert_eq!(field(&review, "Total"), "1.5 pathUSD");
        assert_eq!(
            field(&review, "Network fee"),
            "Bloom does not show the network fee amount"
        );
        assert!(field(&review, "Network fee token").starts_with("pathUSD (0x20c0"));
        assert_eq!(field(&review, "Gas limit"), "500000");
        assert_eq!(field(&review, "Max fee per gas (raw units)"), "20000000000");
        assert_eq!(field(&review, "Valid until"), "2000000000 Unix seconds");

        let split = Draft {
            calls: [8u8, 9]
                .iter()
                .zip([1_000_000u128, 250_000])
                .map(|(to, amount)| {
                    (
                        Some(USDC_E),
                        U256::ZERO,
                        calldata(
                            TRANSFER,
                            &[Address::with_last_byte(*to).into_word(), word(amount)],
                        ),
                    )
                })
                .collect(),
            ..Draft::new(vec![])
        };
        assert_eq!(
            format!("0x{}", hex::encode(split.encode())),
            CHARGE_SPONSORED_SPLIT
        );
        let review = read(&split.encode()).unwrap();
        assert_eq!(
            field(&review, "Recipient 2"),
            "0x0000000000000000000000000000000000000009"
        );
        assert_eq!(field(&review, "Amount 1"), "1 USDC.e");
        assert_eq!(field(&review, "Amount 2"), "0.25 USDC.e");
        assert_eq!(field(&review, "Total"), "1.25 USDC.e");
        assert_eq!(
            field(&review, "Network fee"),
            "The merchant pays the network fee."
        );
        assert!(review.fields.iter().all(|field| field.path != "Gas limit"));

        let open = Draft::new(open_calls(ESCROW, 5_000_000, 5_000_000, signer()));
        assert_eq!(format!("0x{}", hex::encode(open.encode())), OPEN_SPONSORED);
        let review = read(&open.encode()).unwrap();
        assert_eq!(review.title, "Open a Tempo payment channel");
        assert_eq!(
            field(&review, "Payee"),
            "0x000000000000000000000000000000000000000a"
        );
        assert_eq!(field(&review, "Deposit"), "5 pathUSD");
        assert_eq!(field(&review, "Channel ID"), OPEN_CHANNEL_ID);
    }

    #[test]
    fn session_open_refuses_other_escrows_amounts_tokens_and_signers() {
        let other = Address::with_last_byte(0x99);
        refused(
            &Draft::new(open_calls(other, 5_000_000, 5_000_000, signer())).encode(),
            "not Bloom's known escrow",
        );
        let mut spender = open_calls(ESCROW, 5_000_000, 5_000_000, signer());
        spender[0].1 = calldata(APPROVE, &[other.into_word(), word(5_000_000)]);
        refused(
            &Draft::new(spender).encode(),
            "spender other than the escrow",
        );
        refused(
            &Draft::new(open_calls(ESCROW, 5_000_001, 5_000_000, signer())).encode(),
            "different from its deposit",
        );
        let mut token = open_calls(ESCROW, 5_000_000, 5_000_000, signer());
        token[0].0 = USDC_E;
        refused(&Draft::new(token).encode(), "different token");
        refused(
            &Draft::new(open_calls(ESCROW, 5_000_000, 5_000_000, other)).encode(),
            "voucher signer other than this wallet",
        );
        let mut extra = open_calls(ESCROW, 5_000_000, 5_000_000, signer());
        extra.push((PATH_USD, calldata(TRANSFER, &[other.into_word(), word(1)])));
        refused(&Draft::new(extra).encode(), "neither a charge");
        let mut unknown = open_calls(ESCROW, 5_000_000, 5_000_000, signer());
        unknown[1].1.push(0);
        refused(&Draft::new(unknown).encode(), "neither a charge");
    }

    #[test]
    fn charges_refuse_mixed_tokens_and_unknown_calls() {
        let transfer = |token| {
            (
                token,
                calldata(TRANSFER, &[Address::with_last_byte(8).into_word(), word(1)]),
            )
        };
        refused(
            &Draft::new(vec![transfer(PATH_USD), transfer(USDC_E)]).encode(),
            "more than one token",
        );
        refused(
            &Draft::new(vec![(PATH_USD, calldata("burn(uint256)", &[word(1)]))]).encode(),
            "neither a charge",
        );
        refused(&Draft::new(vec![]).encode(), "neither a charge");
        let mut dirty = transfer(PATH_USD);
        dirty.1[5] = 1; // upper address bytes must be zero
        refused(&Draft::new(vec![dirty]).encode(), "neither a charge");
        // A charge to an unlisted token still shows raw units.
        let review =
            read(&Draft::new(vec![transfer(Address::with_last_byte(0x44))]).encode()).unwrap();
        assert_eq!(field(&review, "Amount"), "1 raw units");
        assert!(field(&review, "Token").contains("unlisted token"));
    }

    #[test]
    fn strict_decoding_refuses_every_field_outside_the_contract() {
        let base = Draft::new(vec![(
            PATH_USD,
            calldata(TRANSFER, &[Address::with_last_byte(8).into_word(), word(1)]),
        )]);
        read(&base.encode()).unwrap();
        let mut value = base.clone();
        value.calls[0].1 = U256::from(1);
        refused(&value.encode(), "native value");
        let mut create = base.clone();
        create.calls[0].0 = None;
        refused(&create.encode(), "creates a contract");
        let mut access = base.clone();
        let mut entry = Vec::new();
        Address::with_last_byte(3).encode(&mut entry);
        entry.push(0xc0);
        access.access_list = vec![0xc0 + 1 + entry.len() as u8, 0xc0 + entry.len() as u8];
        access.access_list.extend(entry);
        refused(&access.encode(), "access list");
        let mut key = base.clone();
        key.extra = vec![0xc1, 0x01];
        refused(&key.encode(), "key authorization");
        let mut trailing = base.encode();
        trailing.push(0);
        refused(&trailing, "trailing bytes");
        let mut chain = base.clone();
        chain.chain_id = 1;
        refused(&chain.encode(), "chain Bloom does not review");
        let mut sponsored_fee = base.clone();
        sponsored_fee.fee_token = Some(PATH_USD);
        refused(&sponsored_fee.encode(), "cannot commit to a fee token");
        let mut slot = base.encode();
        let index = slot.len() - 2;
        assert_eq!(slot[index], 0x00);
        slot[index] = 0x01;
        refused(&slot, "fee-payer slot");
        let mut kind = base.encode();
        kind[0] = 0x02;
        refused(&kind, "type 0x76");
        assert!(transaction("76", signer(), &mut empty()).is_err());
        // Testnet escrow and chain are accepted, with unverified tokens.
        let mut testnet = Draft::new(open_calls(
            address!("e1c4d3dce17bc111181ddf716f75bae49e61a336"),
            5,
            5,
            signer(),
        ));
        testnet.chain_id = 42431;
        assert_eq!(
            field(&read(&testnet.encode()).unwrap(), "Deposit"),
            "5 raw units"
        );
    }

    fn voucher_json(channel: Option<serde_json::Value>) -> serde_json::Value {
        let mut value = json!({"schema":"bloom.message.review.v1","kind":"tempo_voucher","chain_id":4217,
            "escrow":format!("{ESCROW:#x}"),"channel_id":OPEN_CHANNEL_ID,"cumulative_amount":"1250000"});
        if let Some(channel) = channel {
            value["channel"] = channel;
        }
        value
    }

    pub(in crate::message_review) fn voucher_channel() -> serde_json::Value {
        json!({"payee":format!("{:#x}", Address::with_last_byte(10)),"token":format!("{PATH_USD:#x}"),
            "salt":format!("{:#x}", B256::repeat_byte(0x55)),"authorized_signer":format!("{:#x}", signer())})
    }

    fn read_voucher(value: serde_json::Value) -> Result<(Vec<u8>, MessageReview), ProtocolError> {
        super::super::decode(&serde_json::to_vec(&value).unwrap(), signer())
    }

    #[test]
    fn vouchers_rebuild_the_real_preimage_and_bind_the_channel() {
        let (preimage, review) = read_voucher(voucher_json(Some(voucher_channel()))).unwrap();
        assert_eq!(format!("0x{}", hex::encode(&preimage)), VOUCHER_PREIMAGE);
        assert_eq!(review.kind, "tempo_voucher");
        assert_eq!(
            field(&review, "Authorizes"),
            "Lets 0x000000000000000000000000000000000000000a collect up to 1.25 pathUSD in total from this channel"
        );
        for (key, value) in [
            ("salt", format!("{:#x}", B256::repeat_byte(0x56))),
            ("payee", format!("{:#x}", Address::with_last_byte(11))),
            ("token", format!("{USDC_E:#x}")),
        ] {
            let mut channel = voucher_channel();
            channel[key] = json!(value);
            let error = read_voucher(voucher_json(Some(channel))).unwrap_err();
            assert!(
                error.message.contains("do not produce its channel ID"),
                "{key}"
            );
        }
        let mut channel = voucher_channel();
        channel["authorized_signer"] = json!(format!("{:#x}", Address::with_last_byte(8)));
        assert!(
            read_voucher(voucher_json(Some(channel)))
                .unwrap_err()
                .message
                .contains("signer other")
        );
        let mut escrow = voucher_json(Some(voucher_channel()));
        escrow["escrow"] = json!(format!("{:#x}", Address::with_last_byte(9)));
        assert!(
            read_voucher(escrow)
                .unwrap_err()
                .message
                .contains("known escrow")
        );
        let mut chain = voucher_json(None);
        chain["chain_id"] = json!(1);
        assert!(read_voucher(chain).is_err());
        let mut amount = voucher_json(None);
        amount["cumulative_amount"] = json!("+1");
        assert!(read_voucher(amount).is_err());
        let mut unknown = voucher_json(Some(voucher_channel()));
        unknown["channel"]["display"] = json!("Merchant");
        assert!(read_voucher(unknown).is_err());

        let (legacy_preimage, legacy) = read_voucher(voucher_json(None)).unwrap();
        assert_eq!(legacy_preimage, preimage);
        assert_eq!(field(&legacy, "Cumulative amount (raw units)"), "1250000");
        assert_eq!(field(&legacy, "Channel ID"), OPEN_CHANNEL_ID);
        assert!(
            legacy
                .warnings
                .iter()
                .any(|warning| warning.contains("cannot confirm who this channel pays"))
        );
        assert!(legacy.fields.iter().all(|field| field.path != "Authorizes"));
    }
}
