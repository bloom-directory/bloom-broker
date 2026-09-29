//! Independent semantic review for Safe owner signatures.

use std::str::FromStr;

use alloy::primitives::{Address, B256, U256, keccak256};
use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalSelector, CanonicalWalletPolicy, CryptoSuite, DeclaredFee,
    Digest32, ProtocolError, ProtocolErrorCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Facts Broker rebuilt from the exact Safe signing bytes, plus what the
/// Petal reported about the Safe and Broker could not check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeReview {
    pub chain_id: String,
    pub chain: String,
    pub safe: String,
    pub owner: String,
    pub nonce: String,
    pub operation: String,
    pub destination: String,
    pub value: String,
    pub value_display: String,
    pub action: Vec<String>,
    pub safe_tx_hash: String,
    pub reported: SafeReported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeReported {
    pub version: String,
    pub singleton: String,
    pub singleton_code_hash: String,
    pub owners: Vec<String>,
    pub threshold: String,
    pub guard: String,
    pub modules: Vec<String>,
    pub fallback_handler: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library_code_hash: Option<String>,
}

const MAX_REVIEW_BYTES: usize = 256 * 1024;
const MAX_CALLDATA_BYTES: usize = 128 * 1024;
const MAX_OWNERS: usize = 64;
const MAX_MODULES: usize = 64;
const ZERO: &str = "0x0000000000000000000000000000000000000000";
const SAFE_TX_TYPE: &str = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";
const DOMAIN_TYPE: &str = "EIP712Domain(uint256 chainId,address verifyingContract)";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    chain_id: String,
    safe_address: String,
    safe_version: String,
    singleton: String,
    singleton_code_hash: String,
    owner: String,
    owners: Vec<String>,
    threshold: String,
    guard: String,
    modules: Vec<String>,
    fallback_handler: String,
    safe_tx: SafeTx,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    library_code_hash: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SafeTx {
    to: String,
    value: String,
    data: String,
    operation: u8,
    safe_tx_gas: String,
    base_gas: String,
    gas_price: String,
    gas_token: String,
    refund_receiver: String,
    nonce: String,
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::SelectorMismatch, message)
}

fn address(value: &str, field: &str) -> Result<Address, ProtocolError> {
    Address::from_str(value).map_err(|_| invalid(format!("{field} is not an EVM address")))
}

fn uint(value: &str, field: &str) -> Result<U256, ProtocolError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid(format!(
            "{field} must be a canonical decimal integer"
        )));
    }
    U256::from_str(value).map_err(|_| invalid(format!("{field} is too large")))
}

fn bytes(value: &str, field: &str) -> Result<Vec<u8>, ProtocolError> {
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("{field} must be 0x-prefixed hex")))?;
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!("{field} is invalid hex")));
    }
    let decoded = hex::decode(value).map_err(|_| invalid(format!("{field} is invalid hex")))?;
    if decoded.len() > MAX_CALLDATA_BYTES {
        return Err(invalid(format!("{field} is too large")));
    }
    Ok(decoded)
}

fn word_uint(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

fn word_address(value: Address) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(value.as_slice());
    word
}

fn safe_preimage(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    let chain_id = uint(&envelope.chain_id, "chain_id")?;
    if chain_id == U256::ZERO {
        return Err(invalid("Safe review requires a nonzero chain ID"));
    }
    let safe = address(&envelope.safe_address, "safe_address")?;
    let to = address(&envelope.safe_tx.to, "safe_tx.to")?;
    let data = bytes(&envelope.safe_tx.data, "safe_tx.data")?;
    let gas_token = address(&envelope.safe_tx.gas_token, "safe_tx.gas_token")?;
    let refund_receiver = address(&envelope.safe_tx.refund_receiver, "safe_tx.refund_receiver")?;

    let mut domain = Vec::with_capacity(96);
    domain.extend_from_slice(keccak256(DOMAIN_TYPE).as_slice());
    domain.extend_from_slice(&word_uint(chain_id));
    domain.extend_from_slice(&word_address(safe));
    let domain_separator = keccak256(domain);

    let mut tx = Vec::with_capacity(352);
    tx.extend_from_slice(keccak256(SAFE_TX_TYPE).as_slice());
    tx.extend_from_slice(&word_address(to));
    tx.extend_from_slice(&word_uint(uint(&envelope.safe_tx.value, "safe_tx.value")?));
    tx.extend_from_slice(keccak256(data).as_slice());
    tx.extend_from_slice(&word_uint(U256::from(envelope.safe_tx.operation)));
    tx.extend_from_slice(&word_uint(uint(
        &envelope.safe_tx.safe_tx_gas,
        "safe_tx.safe_tx_gas",
    )?));
    tx.extend_from_slice(&word_uint(uint(
        &envelope.safe_tx.base_gas,
        "safe_tx.base_gas",
    )?));
    tx.extend_from_slice(&word_uint(uint(
        &envelope.safe_tx.gas_price,
        "safe_tx.gas_price",
    )?));
    tx.extend_from_slice(&word_address(gas_token));
    tx.extend_from_slice(&word_address(refund_receiver));
    tx.extend_from_slice(&word_uint(uint(&envelope.safe_tx.nonce, "safe_tx.nonce")?));
    let struct_hash = keccak256(tx);

    let mut preimage = Vec::with_capacity(66);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(domain_separator.as_slice());
    preimage.extend_from_slice(struct_hash.as_slice());
    Ok(preimage)
}

fn exact_bytes(
    request: &ApprovalPrepareRequest,
) -> Result<(&[Digest32], &[Digest32]), ProtocolError> {
    let ApprovalSelector::Exact {
        ordered_payload_digests,
        ordered_hashes,
    } = &request.terms.selector
    else {
        return Err(invalid("Safe review requires an exact selector"));
    };
    if request.terms.allowed_crypto_suites != [CryptoSuite::Secp256k1Keccak256Recoverable]
        || request.safe_review_payloads.len() != 1
        || ordered_payload_digests.len() != 1
        || ordered_hashes.len() != 1
    {
        return Err(invalid(
            "Safe review requires one recoverable secp256k1 payload",
        ));
    }
    Ok((ordered_payload_digests, ordered_hashes))
}

fn validate_state(envelope: &Envelope, from: Address) -> Result<(), ProtocolError> {
    if envelope.schema != "bloom.safe.review.v1" {
        return Err(invalid("unsupported Safe review schema"));
    }
    // Petal-reported fields outside the EIP-712 preimage are bounded for
    // display only: a pinned table could refuse an honest Petal and not a
    // dishonest one. A pre-1.3.0 domain separator fails the selector check.
    address(&envelope.singleton, "singleton")?;
    address(&envelope.guard, "guard")?;
    address(&envelope.fallback_handler, "fallback_handler")?;
    if envelope.owners.len() > MAX_OWNERS || envelope.modules.len() > MAX_MODULES {
        return Err(invalid(
            "Safe owner or module count is outside supported bounds",
        ));
    }
    for value in &envelope.owners {
        address(value, "owners[]")?;
    }
    for value in &envelope.modules {
        address(value, "modules[]")?;
    }
    uint(&envelope.threshold, "threshold")?;

    // `from` comes from the Signer-held key, so this is the one configuration
    // fact Broker can establish itself.
    if address(&envelope.owner, "owner")? != from {
        return Err(invalid(
            "Safe review owner differs from the Bloom signing key",
        ));
    }

    // These five are EIP-712 members, so the selector comparison binds them.
    if envelope.safe_tx.safe_tx_gas != "0"
        || envelope.safe_tx.base_gas != "0"
        || envelope.safe_tx.gas_price != "0"
        || !envelope.safe_tx.gas_token.eq_ignore_ascii_case(ZERO)
        || !envelope.safe_tx.refund_receiver.eq_ignore_ascii_case(ZERO)
    {
        return Err(invalid(
            "Safe gas reimbursement fields must all be zero in this release",
        ));
    }
    Ok(())
}

/// Chains where every library below was read from the chain and found to hold
/// the canonical Safe runtime code. The chain ID is an EIP-712 domain member,
/// so the signature cannot be replayed on a chain outside this list, where the
/// same address could hold other code.
const LIBRARY_CHAINS: &[u64] = &[1, 10, 100, 137, 8453, 42161];

/// Official Safe libraries a delegatecall may enter. `safe_tx.to` is bound by
/// the selector, so this is a real constraint. Addresses are pinned per chain
/// in `LIBRARY_CHAINS`; a Petal-reported code hash is not trusted.
struct Library {
    kind: &'static str,
    address: &'static str,
}

const LIBRARIES: &[Library] = &[
    // MultiSendCallOnly, Safe 1.3.0 (two deployments), 1.4.1, and 1.5.0.
    Library {
        kind: "MultiSendCallOnly",
        address: "0x40a2accbd92bca938b02010e17a5b8929b49130d",
    },
    Library {
        kind: "MultiSendCallOnly",
        address: "0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b",
    },
    Library {
        kind: "MultiSendCallOnly",
        address: "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
    },
    Library {
        kind: "MultiSendCallOnly",
        address: "0xa83c336b20401af773b6219ba5027174338d1836",
    },
    // CreateCall, Safe 1.3.0 (two deployments), 1.4.1, and 1.5.0.
    Library {
        kind: "CreateCall",
        address: "0x7cbb62eaa69f79e6873cd1ecb2392971036cfaa4",
    },
    Library {
        kind: "CreateCall",
        address: "0xb19d6ffc2182150f8eb585b79d4abcd7c5640a9d",
    },
    Library {
        kind: "CreateCall",
        address: "0x9b35af71d77eaf8d7e40252370304687390a1a52",
    },
    Library {
        kind: "CreateCall",
        address: "0x2ef5ecfbea521449e4de05edb1ce63b75eda90b4",
    },
];

fn dynamic_bytes(
    data: &[u8],
    head_words: usize,
    offset_word: usize,
) -> Result<&[u8], ProtocolError> {
    if data.len() < head_words * 32 {
        return Err(invalid("delegatecall ABI data is truncated"));
    }
    let offset = U256::from_be_slice(&data[offset_word * 32..offset_word * 32 + 32])
        .try_into()
        .map_err(|_| invalid("delegatecall ABI offset is too large"))?;
    if offset != head_words * 32 || offset + 32 > data.len() {
        return Err(invalid("delegatecall ABI offset is invalid"));
    }
    let length: usize = U256::from_be_slice(&data[offset..offset + 32])
        .try_into()
        .map_err(|_| invalid("delegatecall ABI length is too large"))?;
    let end = offset
        .checked_add(32)
        .and_then(|start| start.checked_add(length))
        .ok_or_else(|| invalid("delegatecall ABI length overflow"))?;
    let padded_end = end
        .checked_add(31)
        .map(|value| value / 32 * 32)
        .ok_or_else(|| invalid("delegatecall ABI padding overflow"))?;
    if padded_end != data.len() || data[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid(
            "delegatecall ABI bytes are truncated or noncanonical",
        ));
    }
    Ok(&data[offset + 32..end])
}

/// A native amount in the chain's own unit, from the shared asset table.
fn native(value: U256, chain: &str) -> String {
    crate::evm_review::native_value_display(&value.to_string(), chain)
}

/// One disclosed line per call-only batch entry, decoded the same way a
/// top-level call is.
fn entry_summary(chain: &str, index: usize, to: Address, value: U256, data: &[u8]) -> String {
    if data.len() == 68 && data[..4] == [0xa9, 0x05, 0x9c, 0xbb] {
        format!(
            "{index}. ERC-20 transfer of {} base units of token {to} to {}",
            U256::from_be_slice(&data[36..68]),
            Address::from_slice(&data[16..36])
        )
    } else if data.is_empty() {
        format!("{index}. Send {} to {to}", native(value, chain))
    } else {
        format!(
            "{index}. Contract call to {to} with {}, selector 0x{}, calldata keccak256 {:#x}",
            native(value, chain),
            hex::encode(&data[..data.len().min(4)]),
            keccak256(data)
        )
    }
}

/// One ABI word that must hold an address and nothing above it.
fn word_as_address(word: &[u8]) -> Result<Address, ProtocolError> {
    if word[..12].iter().any(|byte| *byte != 0) {
        return Err(invalid("Safe owner change carries a malformed address"));
    }
    Ok(Address::from_slice(&word[12..]))
}

/// The four Safe self-calls that change who may sign and how many must. Every
/// other self-call stays refused: enabling a module, or setting a guard or
/// fallback handler, hands the Safe to code Broker cannot review.
///
/// The `prevOwner` argument only locates an entry in the Safe's owner list,
/// so it is checked for shape and not shown.
fn owner_change(signer: Address, value: U256, data: &[u8]) -> Result<String, ProtocolError> {
    let refused =
        || invalid("Safe self-calls other than owner and threshold changes are not supported");
    if !value.is_zero() || data.len() < 4 || (data.len() - 4) % 32 != 0 {
        return Err(refused());
    }
    let words: Vec<&[u8]> = data[4..].chunks(32).collect();
    let selector = |signature: &str| data[..4] == keccak256(signature).as_slice()[..4];
    let removes_signer = |removed: Address| {
        if removed == signer {
            "\nWarning: this removes this Bloom wallet from the Safe's owners"
        } else {
            ""
        }
    };
    let threshold = |word: &[u8]| {
        let threshold = U256::from_be_slice(word);
        if threshold.is_zero() {
            return Err(invalid("Safe threshold must be at least 1"));
        }
        Ok(threshold)
    };
    if selector("addOwnerWithThreshold(address,uint256)") && words.len() == 2 {
        Ok(format!(
            "Action: Add Safe owner\nNew owner: {}\nNew threshold: {}",
            word_as_address(words[0])?,
            threshold(words[1])?
        ))
    } else if selector("removeOwner(address,address,uint256)") && words.len() == 3 {
        word_as_address(words[0])?;
        let removed = word_as_address(words[1])?;
        Ok(format!(
            "Action: Remove Safe owner\nOwner removed: {removed}\nNew threshold: {}{}",
            threshold(words[2])?,
            removes_signer(removed)
        ))
    } else if selector("swapOwner(address,address,address)") && words.len() == 3 {
        word_as_address(words[0])?;
        let removed = word_as_address(words[1])?;
        Ok(format!(
            "Action: Replace Safe owner\nOwner removed: {removed}\nNew owner: {}{}",
            word_as_address(words[2])?,
            removes_signer(removed)
        ))
    } else if selector("changeThreshold(uint256)") && words.len() == 1 {
        Ok(format!(
            "Action: Change Safe threshold\nNew threshold: {}",
            threshold(words[0])?
        ))
    } else {
        Err(refused())
    }
}

fn classify(envelope: &Envelope) -> Result<String, ProtocolError> {
    classify_call(
        uint(&envelope.chain_id, "chain_id")?,
        address(&envelope.safe_address, "safe_address")?,
        address(&envelope.owner, "owner")?,
        address(&envelope.safe_tx.to, "safe_tx.to")?,
        uint(&envelope.safe_tx.value, "safe_tx.value")?,
        &bytes(&envelope.safe_tx.data, "safe_tx.data")?,
        envelope.safe_tx.operation,
    )
}

/// Read one Safe transaction. `signer` is the Bloom wallet approving, so a
/// change that removes it can say so.
fn classify_call(
    chain: U256,
    safe: Address,
    signer: Address,
    to: Address,
    value: U256,
    data: &[u8],
    operation: u8,
) -> Result<String, ProtocolError> {
    match operation {
        0 => {
            if to == safe {
                if value.is_zero() && data.is_empty() {
                    return Ok("Action: Reject competing Safe transaction\nValue: 0".into());
                }
                return owner_change(signer, value, data);
            }
            if data.len() == 68 && data[..4] == [0xa9, 0x05, 0x9c, 0xbb] {
                let recipient = Address::from_slice(&data[16..36]);
                let amount = U256::from_be_slice(&data[36..68]);
                Ok(format!(
                    "Action: ERC-20 transfer\nToken: {to}\nRecipient: {recipient}\nToken amount (base units): {amount}"
                ))
            } else if data.is_empty() {
                Ok(format!("Action: Native transfer\nRecipient: {to}"))
            } else {
                Ok(format!(
                    "Action: Contract call\nCalldata selector: 0x{}\nCalldata keccak256: {:#x}",
                    hex::encode(&data[..data.len().min(4)]),
                    keccak256(data)
                ))
            }
        }
        1 => {
            if value != U256::ZERO {
                return Err(invalid("Safe delegatecall transaction value must be zero"));
            }
            let chain_name = u64::try_from(chain)
                .map(crate::evm_review::chain_name)
                .unwrap_or_else(|_| format!("evm-{chain}"));
            if !LIBRARY_CHAINS.iter().any(|id| U256::from(*id) == chain) {
                return Err(invalid(
                    "Safe delegatecalls are refused on this chain because Broker has no verified Safe library deployment for it",
                ));
            }
            let target = format!("{to:#x}");
            let library = LIBRARIES
                .iter()
                .find(|entry| entry.address == target)
                .ok_or_else(|| invalid("delegatecall target is not an official Safe library"))?;
            if data.len() < 4 {
                return Err(invalid("Safe library calldata is truncated"));
            }
            if library.kind == "MultiSendCallOnly" {
                if data[..4] != keccak256("multiSend(bytes)").as_slice()[..4] {
                    return Err(invalid("unexpected MultiSendCallOnly selector"));
                }
                let packed = dynamic_bytes(&data[4..], 1, 0)?;
                let mut cursor = 0;
                let mut calls = 0usize;
                let mut total = U256::ZERO;
                let mut entries = Vec::new();
                while cursor < packed.len() {
                    if calls == 32 || packed.len() - cursor < 85 {
                        return Err(invalid("MultiSendCallOnly batch is malformed or too large"));
                    }
                    if packed[cursor] != 0 {
                        return Err(invalid("MultiSendCallOnly contains a delegatecall"));
                    }
                    let destination = Address::from_slice(&packed[cursor + 1..cursor + 21]);
                    if destination == safe {
                        return Err(invalid("MultiSendCallOnly contains a Safe self-call"));
                    }
                    let call_value = U256::from_be_slice(&packed[cursor + 21..cursor + 53]);
                    let length: usize = U256::from_be_slice(&packed[cursor + 53..cursor + 85])
                        .try_into()
                        .map_err(|_| invalid("MultiSend call data length is too large"))?;
                    let data_start = cursor
                        .checked_add(85)
                        .ok_or_else(|| invalid("MultiSend call data length overflow"))?;
                    let next = data_start
                        .checked_add(length)
                        .ok_or_else(|| invalid("MultiSend call data length overflow"))?;
                    if next > packed.len() {
                        return Err(invalid("MultiSend call data is truncated"));
                    }
                    total = total
                        .checked_add(call_value)
                        .ok_or_else(|| invalid("MultiSend native value overflow"))?;
                    calls += 1;
                    // Every entry is disclosed; a batch must not hide a call.
                    entries.push(entry_summary(
                        &chain_name,
                        calls,
                        destination,
                        call_value,
                        &packed[data_start..next],
                    ));
                    cursor = next;
                }
                if calls == 0 {
                    return Err(invalid("MultiSendCallOnly batch is empty"));
                }
                Ok(format!(
                    "Action: Call-only batch\nCalls: {calls}\nTotal native value: {}\n{}\nPacked calls keccak256: {:#x}",
                    native(total, &chain_name),
                    entries.join("\n"),
                    keccak256(packed)
                ))
            } else {
                let create = keccak256("performCreate(uint256,bytes)");
                let create2 = keccak256("performCreate2(uint256,bytes,bytes32)");
                let deployment_value = if data.len() >= 36 {
                    U256::from_be_slice(&data[4..36])
                } else {
                    return Err(invalid("CreateCall calldata is truncated"));
                };
                let (kind, initcode, salt) = if data[..4] == create.as_slice()[..4] {
                    if data.len() < 68 {
                        return Err(invalid("CreateCall calldata is truncated"));
                    }
                    ("CREATE", dynamic_bytes(&data[4..], 2, 1)?, None)
                } else if data[..4] == create2.as_slice()[..4] {
                    if data.len() < 100 {
                        return Err(invalid("CreateCall CREATE2 calldata is truncated"));
                    }
                    (
                        "CREATE2",
                        dynamic_bytes(&data[4..], 3, 1)?,
                        Some(B256::from_slice(&data[68..100])),
                    )
                } else {
                    return Err(invalid("unexpected CreateCall selector"));
                };
                if initcode.is_empty() {
                    return Err(invalid("contract deployment initcode is empty"));
                }
                let mut result = format!(
                    "Action: Deploy contract ({kind})\nDeployment value: {}\nInitcode keccak256: {:#x}",
                    native(deployment_value, &chain_name),
                    keccak256(initcode)
                );
                if let Some(salt) = salt {
                    result.push_str(&format!(
                        "\nSalt: {salt:#x}\nPredicted address: {}",
                        safe.create2(salt, keccak256(initcode))
                    ));
                }
                Ok(result)
            }
        }
        _ => Err(invalid("unsupported Safe operation")),
    }
}

pub(crate) fn review(
    request: &ApprovalPrepareRequest,
    policy: &CanonicalWalletPolicy,
    from: Address,
) -> Result<Option<SafeReview>, ProtocolError> {
    if request.safe_review_payloads.is_empty() {
        return Ok(None);
    }
    if !request.evm_review_payloads.is_empty() {
        return Err(invalid(
            "Safe and native EVM review payloads cannot be mixed",
        ));
    }
    // The rebuilt transaction is the review; a claim may not tell another story.
    if request.system_use_claim.is_some()
        || request.petal_use_claim.as_ref().is_some_and(|claim| {
            !claim.declared_debits.is_empty()
                || !claim.declared_destinations.is_empty()
                || !matches!(claim.declared_fee, DeclaredFee::None)
        })
    {
        return Err(invalid(
            "Safe review claims must not declare amounts, destinations, or fees",
        ));
    }
    let (digests, hashes) = exact_bytes(request)?;
    let raw = request.safe_review_payloads[0].decode();
    if raw.len() > MAX_REVIEW_BYTES {
        return Err(invalid("Safe review envelope is too large"));
    }
    let envelope: Envelope =
        serde_json::from_slice(&raw).map_err(|_| invalid("invalid Safe review envelope"))?;
    let canonical =
        serde_jcs::to_vec(&envelope).map_err(|_| invalid("cannot canonicalize Safe review"))?;
    if canonical != raw {
        return Err(invalid("Safe review envelope is not canonical JCS"));
    }
    validate_state(&envelope, from)?;
    let preimage = safe_preimage(&envelope)?;
    if Digest32::from_bytes(Sha256::digest(&preimage).into()) != digests[0]
        || Digest32::from_bytes(keccak256(&preimage).0) != hashes[0]
    {
        return Err(invalid(
            "Safe review transaction differs from the exact signing selector",
        ));
    }
    let chain = uint(&envelope.chain_id, "chain_id")?;
    let chain_policy = format!("evm-{chain}");
    if !policy.allowed_destinations.iter().any(|destination| {
        destination.chain.as_str() == chain_policy && destination.destination == "exact"
    }) {
        return Err(invalid(format!(
            "wallet policy must allow destination exact on {chain_policy} for Safe signing"
        )));
    }
    let action = classify(&envelope)?.lines().map(str::to_owned).collect();
    let chain_name = u64::try_from(chain)
        .map(crate::evm_review::chain_name)
        .unwrap_or(chain_policy);
    Ok(Some(SafeReview {
        chain_id: chain.to_string(),
        value_display: crate::evm_review::native_value_display(
            &envelope.safe_tx.value,
            &chain_name,
        ),
        chain: chain_name,
        safe: address(&envelope.safe_address, "safe_address")?.to_string(),
        owner: from.to_string(),
        nonce: envelope.safe_tx.nonce,
        operation: if envelope.safe_tx.operation == 0 {
            "call".into()
        } else {
            "delegatecall".into()
        },
        destination: address(&envelope.safe_tx.to, "safe_tx.to")?.to_string(),
        value: envelope.safe_tx.value,
        action,
        safe_tx_hash: format!("{:#x}", keccak256(&preimage)),
        reported: SafeReported {
            version: envelope.safe_version,
            singleton: envelope.singleton,
            singleton_code_hash: envelope.singleton_code_hash,
            owners: envelope.owners,
            threshold: envelope.threshold,
            guard: envelope.guard,
            modules: envelope.modules,
            fallback_handler: envelope.fallback_handler,
            library_code_hash: envelope.library_code_hash,
        },
    }))
}

fn word(data: &[u8], index: usize) -> Option<&[u8]> {
    data.get(index.checked_mul(32)?..index.checked_mul(32)?.checked_add(32)?)
}

fn word_usize(data: &[u8], index: usize) -> Option<usize> {
    U256::from_be_slice(word(data, index)?).try_into().ok()
}

fn address_at(data: &[u8], index: usize) -> Option<Address> {
    word_as_address(word(data, index)?).ok()
}

/// ABI `bytes` whose offset sits in head word `index`.
fn tail_bytes(data: &[u8], index: usize) -> Option<&[u8]> {
    let offset = word_usize(data, index)?;
    if offset % 32 != 0 {
        return None;
    }
    let length = word_usize(data, offset / 32)?;
    data.get(offset.checked_add(32)?..offset.checked_add(32)?.checked_add(length)?)
}

/// Safe proxy factories whose `createProxyWithNonce` Broker reads: 1.3.0 (two
/// deployments), 1.4.1 and 1.5.0.
const FACTORIES: &[&str] = &[
    "0xa6b71e26c5e0845f74c812102ca7114b6a896ab2",
    "0xc22834581ebc8527d974f8a1c97e1bea4ef910bc",
    "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67",
    "0x14f2982d601c9458f93bd70b218933a6f8165e7b",
];

/// What a native transaction that calls a Safe or a Safe factory does, read
/// from the exact bytes being signed. `None` leaves the call to the ordinary
/// envelope review. Broker reads no chain state, so it cannot tell whether the
/// destination really is a Safe; the page says so.
pub(crate) fn outer_call(
    chain: u64,
    from: Address,
    to: Address,
    value: U256,
    input: &[u8],
) -> Option<Vec<String>> {
    let (selector, data) = input.split_at_checked(4)?;
    let is = |signature: &str| selector == &keccak256(signature).as_slice()[..4];
    let chain_name = crate::evm_review::chain_name(chain);
    let mut lines = Vec::new();
    if is(
        "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    ) {
        let inner_to = address_at(data, 0)?;
        let inner_value = U256::from_be_slice(word(data, 1)?);
        let inner_data = tail_bytes(data, 2)?;
        let operation = u8::try_from(U256::from_be_slice(word(data, 3)?)).ok()?;
        let signatures = tail_bytes(data, 9)?;
        if signatures.len() % 65 != 0 {
            return None;
        }
        lines.push("Action: Execute a Safe transaction".to_owned());
        lines.push(format!("Safe: {to}"));
        match classify_call(
            U256::from(chain),
            to,
            from,
            inner_to,
            inner_value,
            inner_data,
            operation,
        ) {
            Ok(action) => {
                for (index, line) in action.lines().enumerate() {
                    match (index, line.strip_prefix("Action: ")) {
                        (0, Some(action)) => lines.push(format!("The Safe will: {action}")),
                        _ => lines.push(line.to_owned()),
                    }
                }
                if inner_data.is_empty() && operation == 0 && inner_to != to {
                    lines.push(format!("Amount: {}", native(inner_value, &chain_name)));
                }
            }
            Err(error) => {
                lines.push("The Safe will: make a call Bloom cannot read".to_owned());
                lines.push(format!("Reason: {}", error.message));
                lines.push(format!("Call target: {inner_to}"));
                lines.push(format!("Call value: {}", native(inner_value, &chain_name)));
            }
        }
        lines.push(format!(
            "Owner signatures attached: {}",
            signatures.len() / 65
        ));
        let refund = (4..=6)
            .any(|index| word(data, index).is_none_or(|word| word.iter().any(|byte| *byte != 0)));
        if refund {
            lines.push("Warning: the Safe pays a gas refund for this execution".to_owned());
        }
        if !value.is_zero() {
            lines.push(format!(
                "Warning: this also sends {} to the Safe",
                native(value, &chain_name)
            ));
        }
        return Some(lines);
    }
    if is("createProxyWithNonce(address,bytes,uint256)")
        && FACTORIES.contains(&format!("{to:#x}").as_str())
    {
        let singleton = address_at(data, 0)?;
        let initializer = tail_bytes(data, 1)?;
        let salt = U256::from_be_slice(word(data, 2)?);
        let (selector, setup) = initializer.split_at_checked(4)?;
        if selector
            != &keccak256("setup(address[],uint256,address,bytes,address,address,uint256,address)")
                .as_slice()[..4]
        {
            return None;
        }
        let owners_at = word_usize(setup, 0)?;
        if owners_at % 32 != 0 {
            return None;
        }
        let count = word_usize(setup, owners_at / 32)?;
        if count == 0 || count > 64 {
            return None;
        }
        let owners = (0..count)
            .map(|index| address_at(setup, owners_at / 32 + 1 + index))
            .collect::<Option<Vec<_>>>()?;
        let threshold = U256::from_be_slice(word(setup, 1)?);
        let setup_target = address_at(setup, 2)?;
        let setup_data = tail_bytes(setup, 3)?;
        let fallback = address_at(setup, 4)?;
        let payment = U256::from_be_slice(word(setup, 6)?);
        lines.push("Action: Create a Safe".to_owned());
        lines.push(format!("Signatures required: {threshold} of {count}"));
        for (index, owner) in owners.iter().enumerate() {
            let mine = if *owner == from { " (this wallet)" } else { "" };
            lines.push(format!("Owner {}: {owner}{mine}", index + 1));
        }
        lines.push(format!("Safe implementation: {singleton}"));
        lines.push(format!("Fallback handler: {fallback}"));
        lines.push(format!("Salt nonce: {salt}"));
        if !owners.contains(&from) {
            lines.push("Warning: this wallet is not an owner of the new Safe".to_owned());
        }
        if setup_target != Address::ZERO || !setup_data.is_empty() {
            lines.push(format!(
                "Warning: setup runs extra code at {setup_target} that Bloom cannot read"
            ));
        }
        if !payment.is_zero() {
            lines.push("Warning: the new Safe makes a payment during setup".to_owned());
        }
        if !value.is_zero() {
            lines.push(format!(
                "Warning: this also sends {} to the factory",
                native(value, &chain_name)
            ));
        }
        return Some(lines);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::*;

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }

    fn envelope() -> Vec<u8> {
        serde_jcs::to_vec(&serde_json::json!({
            "schema":"bloom.safe.review.v1",
            "chain_id":"31337",
            "safe_address":"0x1000000000000000000000000000000000000000",
            "safe_version":"1.4.1",
            "singleton":"0x41675c099f32341bf84bfc5382af534df5c7461a",
            "singleton_code_hash":"0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4",
            "owner":"0x3000000000000000000000000000000000000000",
            "owners":["0x3000000000000000000000000000000000000000"],
            "threshold":"1",
            "guard":"0x0000000000000000000000000000000000000000",
            "modules":[],
            "fallback_handler":"0x0000000000000000000000000000000000000000",
            "safe_tx":{
                "to":"0x4000000000000000000000000000000000000000",
                "value":"7",
                "data":"0x",
                "operation":0,
                "safe_tx_gas":"0",
                "base_gas":"0",
                "gas_price":"0",
                "gas_token":"0x0000000000000000000000000000000000000000",
                "refund_receiver":"0x0000000000000000000000000000000000000000",
                "nonce":"4"
            }
        }))
        .unwrap()
    }

    fn request(review: Vec<u8>) -> ApprovalPrepareRequest {
        let parsed: Envelope = serde_json::from_slice(&review).unwrap();
        let preimage = safe_preimage(&parsed).unwrap();
        let digest = Digest32::from_bytes([1; 32]);
        ApprovalPrepareRequest {
            operation_id: OperationId::from_bytes([2; 32]),
            canonical_plan_facts_digest: digest.clone(),
            requested_review_mode: None,
            evm_review_payloads: vec![],
            safe_review_payloads: vec![Base64UrlBytes::from_bytes(&review)],
            petal_use_claim: None,
            system_use_claim: None,
            terms: SealedApprovalTerms {
                subject: ApprovalSubject::Petal {
                    package_hash: digest.clone(),
                    route: "transactions/a/b/confirm.json".into(),
                    agent_id: None,
                },
                wallet_id: token("alice"),
                key_ref: KeyRef {
                    backend: token("local"),
                    backend_instance: token("default"),
                    locator: "test".into(),
                    key_spec: KeySpec::Secp256k1,
                    public_key_fingerprint: digest.clone(),
                    derivation: None,
                },
                allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
                selector: ApprovalSelector::Exact {
                    ordered_payload_digests: vec![Digest32::from_bytes(
                        Sha256::digest(&preimage).into(),
                    )],
                    ordered_hashes: vec![Digest32::from_bytes(keccak256(&preimage).0)],
                },
                limits: ApprovalLimits {
                    max_operations: DecimalU64::new(1),
                    max_signatures: DecimalU64::new(1),
                    operation_rate_limits: vec![],
                    signature_rate_limits: vec![],
                    value_limits: vec![],
                },
                activation_mode: ActivationMode::BootBound,
                wallet_revocation_epoch: DecimalU64::new(0),
                policy_version: DecimalU64::new(1),
                policy_digest: digest.clone(),
                provenance_digest: digest,
                request_nonce: RequestNonce::from_bytes([3; 16]),
                issued_at_ms: DecimalU64::new(1),
                not_before_ms: DecimalU64::new(1),
                expires_at_ms: DecimalU64::new(2),
                renewal_of: None,
            },
        }
    }

    fn policy() -> CanonicalWalletPolicy {
        CanonicalWalletPolicy {
            wallet_id: token("alice"),
            maximum_approval_lifetime_ms: 60_000,
            allowed_petal_packages: vec![],
            allowed_destinations: vec![PolicyDestination {
                chain: token("evm-31337"),
                destination: "exact".into(),
            }],
            required_verifiers: vec![],
            clear_signing: None,
        }
    }

    /// Vectors from `@safe-global/protocol-kit` (`preimageSafeTransactionHash`
    /// and `calculateSafeTransactionHash`): the other tests derive selectors
    /// from `safe_preimage` itself and cannot catch it encoding the wrong thing.
    #[test]
    fn safe_sdk_vectors_reproduce_the_preimage_hash_and_digest() {
        struct Vector {
            chain_id: &'static str,
            safe: &'static str,
            to: &'static str,
            value: &'static str,
            data: &'static str,
            operation: u8,
            nonce: &'static str,
            preimage: &'static str,
            safe_tx_hash: &'static str,
        }

        let vectors = [
            // Native transfer, Safe 1.4.1 on chain 31337.
            Vector {
                chain_id: "31337",
                safe: "0x1000000000000000000000000000000000000000",
                to: "0x4000000000000000000000000000000000000000",
                value: "7",
                data: "0x",
                operation: 0,
                nonce: "5",
                preimage: "0x19012fa662b1cd388662ad0139a7648d932107600c53cbfe554866bafcf8f79876c075d89fefa6ab96630f8f7f3c3c44947ae58e7e081b5a579a10d9d34d5c104ffd",
                safe_tx_hash: "0x8fecd20521a47264afd4874dc21442d5e2358d970c6ebb18a275cc2d6f92a30e",
            },
            // ERC-20 transfer, Safe 1.3.0 on mainnet, nonce 0.
            Vector {
                chain_id: "1",
                safe: "0x1000000000000000000000000000000000000000",
                to: "0x5000000000000000000000000000000000000000",
                value: "0",
                data: "0xa9059cbb0000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b",
                operation: 0,
                nonce: "0",
                preimage: "0x1901f11e395fb0c3742c59880738d0df8db3ca45878ef6f46f9b37a9b01c84b409f24a606158c4912b58dbe906461237bedd662fd76316ff5744929aab1611cf39f3",
                safe_tx_hash: "0x956542e1feec0ba0e1f4a1a2839687535907640f43c5be4c8c272fa8c1305434",
            },
            // Same-nonce rejection self-call, Safe 1.5.0 on Base.
            Vector {
                chain_id: "8453",
                safe: "0x1000000000000000000000000000000000000000",
                to: "0x1000000000000000000000000000000000000000",
                value: "0",
                data: "0x",
                operation: 0,
                nonce: "41",
                preimage: "0x19016b1338b549d61e6a4ba84997f691dcdfb8889c86ea077ee3c65c2ab930679b99ff20059b0b3c4a439b81876dc4d7b4332ed1b7f92336cb88b733255b51e6befc",
                safe_tx_hash: "0xbb1fb961349f5cc1df55151bcb12b8fd502973d889a5598154371fafd1c0f686",
            },
            // Saturated chain ID, value, and nonce with a delegatecall
            // operation: catches a width or endianness slip in `word_uint`.
            Vector {
                chain_id: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                safe: "0xffffffffffffffffffffffffffffffffffffffff",
                to: "0x0000000000000000000000000000000000000001",
                value: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                data: "0xdeadbeef",
                operation: 1,
                nonce: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                preimage: "0x1901f57cdfc36cb71b17bae154d27e0c9dc02f3617926d3d63de25f77edef943a92e4375389562d98656e0eb54b194362bd807b49d519fabe00c38dd302760b9e4ce",
                safe_tx_hash: "0xd2aa752e4f8f564ed98902666e0d200298867ad16e424b590a87d8bb39bd014c",
            },
        ];

        for Vector {
            chain_id,
            safe,
            to,
            value,
            data,
            operation,
            nonce,
            preimage,
            safe_tx_hash,
        } in vectors
        {
            let envelope: Envelope = serde_json::from_value(serde_json::json!({
                "schema": "bloom.safe.review.v1",
                "chain_id": chain_id,
                "safe_address": safe,
                "safe_version": "1.4.1",
                "singleton": "0x41675c099f32341bf84bfc5382af534df5c7461a",
                "singleton_code_hash": "0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4",
                "owner": "0x3000000000000000000000000000000000000000",
                "owners": ["0x3000000000000000000000000000000000000000"],
                "threshold": "1",
                "guard": "0x0000000000000000000000000000000000000000",
                "modules": [],
                "fallback_handler": "0x0000000000000000000000000000000000000000",
                "safe_tx": {
                    "to": to,
                    "value": value,
                    "data": data,
                    "operation": operation,
                    "safe_tx_gas": "0",
                    "base_gas": "0",
                    "gas_price": "0",
                    "gas_token": "0x0000000000000000000000000000000000000000",
                    "refund_receiver": "0x0000000000000000000000000000000000000000",
                    "nonce": nonce
                }
            }))
            .unwrap();

            let rebuilt = safe_preimage(&envelope).unwrap();
            assert_eq!(
                format!("0x{}", hex::encode(&rebuilt)),
                preimage,
                "preimage for Safe {safe} nonce {nonce}"
            );
            // The exact selector compares both of these, so both are locked.
            assert_eq!(
                format!("{:#x}", keccak256(&rebuilt)),
                safe_tx_hash,
                "safeTxHash for Safe {safe} nonce {nonce}"
            );
            assert_eq!(
                Digest32::from_bytes(Sha256::digest(&rebuilt).into()).as_str(),
                hex::encode(Sha256::digest(hex::decode(&preimage[2..]).unwrap())),
                "payload digest for Safe {safe} nonce {nonce}"
            );
        }
    }

    #[test]
    fn verifies_safe_preimage_and_rejects_tampering() {
        let bytes = envelope();
        let request = request(bytes.clone());
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        let plan = review(&request, &policy(), from).unwrap().unwrap();
        assert_eq!(
            plan.action,
            [
                "Action: Native transfer",
                "Recipient: 0x4000000000000000000000000000000000000000"
            ]
        );
        assert_eq!(plan.nonce, "4");
        assert_eq!(plan.value_display, "0.000000000000000007 ETH");
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["safe_tx"]["value"] = serde_json::json!("8");
        let changed = serde_jcs::to_vec(&changed).unwrap();
        let mut request = request;
        request.safe_review_payloads[0] = Base64UrlBytes::from_bytes(&changed);
        assert!(review(&request, &policy(), from).is_err());
    }

    #[test]
    fn permits_only_the_canonical_same_nonce_rejection_self_call() {
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["safe_tx"]["to"] = value["safe_address"].clone();
        value["safe_tx"]["value"] = serde_json::json!("0");
        value["safe_tx"]["data"] = serde_json::json!("0x");
        let envelope: Envelope = serde_json::from_value(value.clone()).unwrap();
        assert!(classify(&envelope).unwrap().contains("Reject competing"));

        value["safe_tx"]["data"] = serde_json::json!("0x01");
        let envelope: Envelope = serde_json::from_value(value).unwrap();
        assert!(classify(&envelope).is_err());
    }

    #[test]
    fn create_review_discloses_endowment_and_requires_canonical_abi() {
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        let mut calldata = keccak256("performCreate(uint256,bytes)").as_slice()[..4].to_vec();
        calldata.extend_from_slice(&U256::from(9).to_be_bytes::<32>());
        calldata.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
        calldata.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        calldata.push(0);
        calldata.extend_from_slice(&[0; 31]);
        value["safe_tx"]["to"] = serde_json::json!("0x9b35af71d77eaf8d7e40252370304687390a1a52");
        value["safe_tx"]["value"] = serde_json::json!("0");
        value["safe_tx"]["operation"] = serde_json::json!(1);
        value["safe_tx"]["data"] = serde_json::json!(format!("0x{}", hex::encode(&calldata)));
        value["library_code_hash"] =
            serde_json::json!("0x2b3060c55fcb8275653e99ad511a71f67ba76934ed66a7d74d6e68b52afff889");
        value["chain_id"] = serde_json::json!("8453");
        let parsed: Envelope = serde_json::from_value(value.clone()).unwrap();
        assert!(
            classify(&parsed)
                .unwrap()
                .contains("Deployment value: 0.000000000000000009 ETH")
        );

        calldata.extend_from_slice(&[0; 32]);
        value["safe_tx"]["data"] = serde_json::json!(format!("0x{}", hex::encode(calldata)));
        let parsed: Envelope = serde_json::from_value(value).unwrap();
        assert!(classify(&parsed).is_err());
    }

    #[test]
    fn owner_and_threshold_changes_are_decoded_and_other_self_calls_refused() {
        let base: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        let signer = "0x3000000000000000000000000000000000000000";
        let other = "0x7000000000000000000000000000000000000000";
        let word = |value: &str| {
            let mut word = [0_u8; 32];
            word[12..].copy_from_slice(address(value, "test").unwrap().as_slice());
            word.to_vec()
        };
        let number = |value: u64| U256::from(value).to_be_bytes::<32>().to_vec();
        let self_call = |signature: &str, words: Vec<Vec<u8>>, value: &str| {
            let mut data = keccak256(signature).as_slice()[..4].to_vec();
            data.extend(words.into_iter().flatten());
            let mut envelope = base.clone();
            envelope["safe_tx"]["to"] = envelope["safe_address"].clone();
            envelope["safe_tx"]["value"] = serde_json::json!(value);
            envelope["safe_tx"]["data"] = serde_json::json!(format!("0x{}", hex::encode(data)));
            classify(&serde_json::from_value::<Envelope>(envelope).unwrap())
        };
        let checksum = |value: &str| address(value, "test").unwrap().to_string();

        let added = self_call(
            "addOwnerWithThreshold(address,uint256)",
            vec![word(other), number(2)],
            "0",
        )
        .unwrap();
        assert_eq!(
            added,
            format!(
                "Action: Add Safe owner\nNew owner: {}\nNew threshold: 2",
                checksum(other)
            )
        );
        let removed = self_call(
            "removeOwner(address,address,uint256)",
            vec![word(other), word(signer), number(1)],
            "0",
        )
        .unwrap();
        assert!(removed.contains(&format!("Owner removed: {}", checksum(signer))));
        assert!(removed.contains("removes this Bloom wallet"));
        let swapped = self_call(
            "swapOwner(address,address,address)",
            vec![word(signer), word(other), word(signer)],
            "0",
        )
        .unwrap();
        assert!(swapped.contains(&format!("Owner removed: {}", checksum(other))));
        assert!(swapped.contains(&format!("New owner: {}", checksum(signer))));
        assert!(!swapped.contains("Warning"));
        assert!(
            self_call("changeThreshold(uint256)", vec![number(3)], "0")
                .unwrap()
                .contains("New threshold: 3")
        );

        // Shape: no value, exact argument count, clean address words, threshold >= 1.
        let add = "addOwnerWithThreshold(address,uint256)";
        assert!(self_call(add, vec![word(other), number(2)], "1").is_err());
        assert!(self_call(add, vec![word(other)], "0").is_err());
        assert!(self_call(add, vec![word(other), number(2), number(0)], "0").is_err());
        assert!(self_call(add, vec![vec![1; 32], number(2)], "0").is_err());
        assert!(self_call(add, vec![word(other), number(0)], "0").is_err());
        assert!(self_call("changeThreshold(uint256)", vec![number(0)], "0").is_err());

        // Anything that hands the Safe to other code stays refused.
        for signature in [
            "enableModule(address)",
            "setGuard(address)",
            "setFallbackHandler(address)",
            "setModuleGuard(address)",
        ] {
            assert!(self_call(signature, vec![word(other)], "0").is_err());
        }
        assert!(
            self_call(
                "disableModule(address,address)",
                vec![word(other), word(other)],
                "0"
            )
            .is_err()
        );
    }

    fn multisend_entry(to: &str, value: u64, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0_u8];
        out.extend_from_slice(address(to, "to").unwrap().as_slice());
        out.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
        out.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
        out.extend_from_slice(data);
        out
    }

    fn multisend_calldata(packed: &[u8]) -> Vec<u8> {
        let mut data = keccak256("multiSend(bytes)").as_slice()[..4].to_vec();
        data.extend_from_slice(&U256::from(32).to_be_bytes::<32>());
        data.extend_from_slice(&U256::from(packed.len()).to_be_bytes::<32>());
        data.extend_from_slice(packed);
        data.resize(4 + 64 + packed.len().div_ceil(32) * 32, 0);
        data
    }

    #[test]
    fn call_only_batches_disclose_every_entry() {
        let mut erc20 = vec![0xa9, 0x05, 0x9c, 0xbb];
        erc20.extend_from_slice(&[0; 12]);
        erc20.extend_from_slice(
            address("0x4000000000000000000000000000000000000000", "to")
                .unwrap()
                .as_slice(),
        );
        erc20.extend_from_slice(&U256::from(7).to_be_bytes::<32>());

        let mut packed = multisend_entry("0x5000000000000000000000000000000000000000", 2, &erc20);
        packed.extend(multisend_entry(
            "0x6000000000000000000000000000000000000000",
            3,
            &[],
        ));

        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["safe_tx"]["to"] = serde_json::json!("0x9641d764fc13c8b624c04430c7356c1c7c8102e2");
        value["safe_tx"]["value"] = serde_json::json!("0");
        value["safe_tx"]["operation"] = serde_json::json!(1);
        value["safe_tx"]["data"] =
            serde_json::json!(format!("0x{}", hex::encode(multisend_calldata(&packed))));
        value["library_code_hash"] =
            serde_json::json!("0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939");

        // The same address on a chain Broker has not verified may hold other
        // code, and the Petal's code hash cannot vouch for it.
        let unverified: Envelope = serde_json::from_value(value.clone()).unwrap();
        assert!(
            classify(&unverified)
                .unwrap_err()
                .message
                .contains("no verified Safe library deployment")
        );

        value["chain_id"] = serde_json::json!("8453");
        let parsed: Envelope = serde_json::from_value(value).unwrap();
        let action = classify(&parsed).unwrap();

        // A batch must not be a cheaper way to hide a call than sending it
        // directly: every destination and amount is disclosed.
        assert!(action.contains("Calls: 2"));
        assert!(action.contains("Total native value: 0.000000000000000005 ETH"));
        assert!(action.contains(
            "1. ERC-20 transfer of 7 base units of token 0x5000000000000000000000000000000000000000 to 0x4000000000000000000000000000000000000000"
        ));
        assert!(action.contains(
            "2. Send 0.000000000000000003 ETH to 0x6000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn unverifiable_safe_state_is_reported_separately_from_the_rebuilt_transaction() {
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        // `threshold` is not an EIP-712 member, so the digest cannot constrain
        // it and Broker has no chain client to check it against. It must not be
        // presented as something Broker established.
        value["threshold"] = serde_json::json!("3");
        value["owners"] = serde_json::json!([
            "0x3000000000000000000000000000000000000000",
            "0xaaaa000000000000000000000000000000000000",
            "0xbbbb000000000000000000000000000000000000"
        ]);
        let canonical = serde_jcs::to_vec(&value).unwrap();
        let plan = review(&request(canonical), &policy(), from)
            .unwrap()
            .unwrap();
        assert_eq!(plan.reported.threshold, "3");
        assert_eq!(plan.reported.owners.len(), 3);
        assert!(
            !serde_json::to_string(&plan)
                .unwrap()
                .contains("Broker-verified")
        );
    }

    // Inputs of transactions that ran on Base: a Safe creation, and three
    // executions of that Safe.
    const SAFE: &str = "0xaefda71ded59b48920131d03454893ec2ad93e88";
    const WALLET: &str = "0x8d4fafba75a9dc50b4b296211509e856d2c6d081";
    const FACTORY: &str = "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67";

    fn outer(to: &str, input: &str) -> Option<String> {
        outer_call(
            8453,
            address(WALLET, "wallet").unwrap(),
            address(to, "to").unwrap(),
            U256::ZERO,
            &hex::decode(input.trim_start_matches("0x")).unwrap(),
        )
        .map(|lines| lines.join("\n"))
    }

    #[test]
    fn a_call_that_executes_a_safe_transaction_says_what_the_safe_will_do() {
        let send = outer(SAFE, "0x6a7612020000000000000000000000008d4fafba75a9dc50b4b296211509e856d2c6d081000000000000000000000000000000000000000000000000000009184e72a00000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000411fca12a0c7a67fc6ca9ca271335af2680fae0ce704f5c75fe373ddce47674df33a341f86acbc619d6db40b37ef330f3f2dd47897f0551799f28f20ef7288d69b1b00000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert!(
            send.starts_with("Action: Execute a Safe transaction"),
            "{send}"
        );
        assert!(send.contains("The Safe will: Native transfer"), "{send}");
        assert!(send.contains("Amount: 0.00001 ETH"), "{send}");
        assert!(send.contains("Owner signatures attached: 1"), "{send}");
        assert!(!send.contains("Warning"), "{send}");

        let batch = outer(SAFE, "0x6a7612020000000000000000000000009641d764fc13c8b624c04430c7356c1c7c8102e20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000001448d80ff0a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000ee008d4fafba75a9dc50b4b296211509e856d2c6d0810000000000000000000000000000000000000000000000000000048c27395000000000000000000000000000000000000000000000000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda0291300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000008d4fafba75a9dc50b4b296211509e856d2c6d0810000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041387df176124ae8ab24202005fda4428eff86fcd8d9636ec9239aa8646e414ec75fc7a978870c915eb4e85c7f237e6b5fb6167bde0a1b4dad73a3820b055283f91c00000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert!(batch.contains("The Safe will: Call-only batch"), "{batch}");
        assert!(batch.contains("1. Send 0.000005 ETH to"), "{batch}");
        assert!(
            batch.contains("2. ERC-20 transfer of 0 base units"),
            "{batch}"
        );

        let remove = outer(SAFE, "0x6a761202000000000000000000000000aefda71ded59b48920131d03454893ec2ad93e880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000064f8dc5dd9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000043d2fdfed480f95b8848840031546e30a60c0a5f000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008200bcff01bcd29252f7a7d20e0fd09d28da5cf5d0f8d4a0165a15e4e62a9e83862f1c20464a3b2cee24762885ff9b86a060d999eb18e74dacdb3256ca919e17121bf5e7e63c173815be4ee254ae96388767b18a7df6c69191bb9bfd9734106efc7b737b98399b57d8847a2f5de37e3ac14b5a3f33bd6d3347f92fa6ac2eec6e80d01c000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert!(
            remove.contains("The Safe will: Remove Safe owner"),
            "{remove}"
        );
        assert!(remove.contains("New threshold: 1"), "{remove}");
        assert!(remove.contains("Owner signatures attached: 2"), "{remove}");
    }

    #[test]
    fn a_call_that_creates_a_safe_names_its_owners_and_threshold() {
        let input = "0x1688f0b900000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c762000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000013528400000000000000000000000000000000000000000000000000000000000000164b63e800d0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000fd0732dc9e303f09fcef3a7388ad10a83459ec9900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000008d4fafba75a9dc50b4b296211509e856d2c6d081000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let create = outer(FACTORY, input).unwrap();
        assert!(create.starts_with("Action: Create a Safe"), "{create}");
        assert!(create.contains("Signatures required: 1 of 1"), "{create}");
        assert!(create.contains("(this wallet)"), "{create}");
        assert!(!create.contains("Warning"), "{create}");

        // The same bytes sent anywhere but a Safe factory are not read as one.
        assert!(outer(SAFE, input).is_none());
        // Truncated input falls back to the ordinary review.
        assert!(outer(FACTORY, &input[..input.len() - 64]).is_none());
        assert!(outer(SAFE, "0x6a761202").is_none());
    }

    #[test]
    fn rejects_refunds_and_delegatecalls_outside_the_official_safe_libraries() {
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();

        // Refund fields are EIP-712 members, so the digest binds them and this
        // is a real constraint on what the owner is signing.
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["safe_tx"]["gas_price"] = serde_json::json!("1");
        let canonical = serde_jcs::to_vec(&value).unwrap();
        assert!(review(&request(canonical), &policy(), from).is_err());

        // `safe_tx.to` is an EIP-712 member too, so restricting a delegatecall
        // to the official libraries constrains the transaction rather than the
        // Petal's description of it.
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["safe_tx"]["operation"] = serde_json::json!(1);
        value["safe_tx"]["value"] = serde_json::json!("0");
        value["safe_tx"]["data"] = serde_json::json!("0xdeadbeef");
        value["safe_tx"]["to"] = serde_json::json!("0x4000000000000000000000000000000000000000");
        let canonical = serde_jcs::to_vec(&value).unwrap();
        assert!(review(&request(canonical), &policy(), from).is_err());

        // Reaching an official library is not enough; the call into it must
        // still decode.
        value["safe_tx"]["to"] = serde_json::json!("0x9641d764fc13c8b624c04430c7356c1c7c8102e2");
        let canonical = serde_jcs::to_vec(&value).unwrap();
        assert!(review(&request(canonical), &policy(), from).is_err());
    }

    #[test]
    fn an_unrecognized_safe_deployment_is_disclosed_rather_than_refused() {
        // Deployment fields are outside the preimage: a pinned table could only
        // refuse an honest Petal, so they are disclosed as unverified instead.
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["singleton"] = serde_json::json!("0x4000000000000000000000000000000000000000");
        value["singleton_code_hash"] = serde_json::json!("0x".to_owned() + &"ab".repeat(32));
        value["safe_version"] = serde_json::json!("1.4.2");
        let canonical = serde_jcs::to_vec(&value).unwrap();

        let plan = review(&request(canonical), &policy(), from)
            .unwrap()
            .unwrap();
        assert_eq!(
            plan.reported.singleton,
            "0x4000000000000000000000000000000000000000"
        );
        assert_eq!(
            plan.reported.singleton_code_hash,
            "0x".to_owned() + &"ab".repeat(32)
        );
        assert_eq!(plan.reported.version, "1.4.2");
    }

    #[test]
    fn a_claim_may_not_describe_the_transaction() {
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        let mut request = request(envelope());
        let claim = PetalUseClaim {
            package_hash: Digest32::from_bytes([1; 32]),
            route: "transactions/a/b/confirm.json".into(),
            operation_class: token(SAFE_CONFIRM_OPERATION_CLASS),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: Digest32::from_bytes([1; 32]),
            ordered_hashes: vec![],
            declared_debits: vec![],
            declared_destinations: vec![],
            declared_fee: DeclaredFee::None,
            nonce: RequestNonce::from_bytes([3; 16]),
            claim_assurance: ClaimAssurance::MachineAsserted,
        };
        request.petal_use_claim = Some(claim.clone());
        assert!(review(&request, &policy(), from).unwrap().is_some());
        request.petal_use_claim = Some(PetalUseClaim {
            declared_destinations: vec![DeclaredDestination {
                chain: token("evm-31337"),
                destination: "0x4000000000000000000000000000000000000000".into(),
            }],
            ..claim
        });
        assert!(review(&request, &policy(), from).is_err());
    }
}
