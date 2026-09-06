//! Independent semantic review for Safe owner signatures.

use std::{collections::HashSet, str::FromStr};

use alloy::primitives::{Address, B256, U256, keccak256};
use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalSelector, CanonicalWalletPolicy, CryptoSuite, Digest32,
    ProtocolError, ProtocolErrorCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

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

fn exact_bytes<'a>(
    request: &'a ApprovalPrepareRequest,
) -> Result<(&'a [Digest32], &'a [Digest32]), ProtocolError> {
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
    if envelope.schema != "bloom.safe.review.v1"
        || !matches!(envelope.safe_version.as_str(), "1.3.0" | "1.4.1" | "1.5.0")
    {
        return Err(invalid("unsupported Safe review schema or Safe version"));
    }
    let singleton = address(&envelope.singleton, "singleton")?;
    let singleton = format!("{singleton:#x}");
    let code_hash = envelope.singleton_code_hash.to_ascii_lowercase();
    let supported_singleton = [
        (
            "1.3.0",
            "0xd9db270c1b5e3bd161e8c8503c55ceabee709552",
            "0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e",
        ),
        (
            "1.3.0",
            "0x69f4d1788e39c87893c980c06edf4b7f686e2938",
            "0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e",
        ),
        (
            "1.3.0",
            "0x3e5c63644e683549055b9be8653de26e0b4cd36e",
            "0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f",
        ),
        (
            "1.3.0",
            "0xfb1bffc9d739b8d520daf37df666da4c687191ea",
            "0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f",
        ),
        (
            "1.4.1",
            "0x41675c099f32341bf84bfc5382af534df5c7461a",
            "0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4",
        ),
        (
            "1.4.1",
            "0x29fcb43b46531bca003ddc8fcb67ffe91900c762",
            "0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff",
        ),
        (
            "1.5.0",
            "0xff51a5898e281db6dfc7855790607438df2ca44b",
            "0xdda019cbd7c867a533a2a86e5c53434fdc50b13122b5a5ddb4a8df61b31c20f2",
        ),
        (
            "1.5.0",
            "0xedd160febbd92e350d4d398fb636302fccd67c7e",
            "0x180193227186ccb85316c94db1f0d156ed932b14712cfaac78901899178572dc",
        ),
    ]
    .contains(&(
        envelope.safe_version.as_str(),
        singleton.as_str(),
        code_hash.as_str(),
    ));
    if !supported_singleton {
        return Err(invalid(
            "Safe singleton address/code hash is not a pinned official deployment",
        ));
    }
    address(&envelope.guard, "guard")?;
    address(&envelope.fallback_handler, "fallback_handler")?;
    if envelope.owners.is_empty()
        || envelope.owners.len() > MAX_OWNERS
        || envelope.modules.len() > MAX_MODULES
    {
        return Err(invalid(
            "Safe owner or module count is outside supported bounds",
        ));
    }
    let owner = address(&envelope.owner, "owner")?;
    if owner != from {
        return Err(invalid(
            "Safe review owner differs from the Bloom signing key",
        ));
    }
    let mut owners = HashSet::new();
    for value in &envelope.owners {
        let value = address(value, "owners[]")?;
        if value == Address::ZERO || !owners.insert(value) {
            return Err(invalid("Safe owners contain a zero or duplicate address"));
        }
    }
    if !owners.contains(&owner) {
        return Err(invalid("Bloom signing key is not a reported Safe owner"));
    }
    let threshold = uint(&envelope.threshold, "threshold")?;
    if threshold == U256::ZERO || threshold > U256::from(owners.len()) {
        return Err(invalid(
            "Safe threshold is invalid for the reported owner set",
        ));
    }
    let mut modules = HashSet::new();
    for value in &envelope.modules {
        let module = address(value, "modules[]")?;
        if module == Address::ZERO || !modules.insert(module) {
            return Err(invalid("Safe modules contain a zero or duplicate address"));
        }
    }
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

struct Library {
    kind: &'static str,
    address: &'static str,
    code_hash: &'static str,
}

const LIBRARIES: &[Library] = &[
    Library {
        kind: "MultiSendCallOnly",
        address: "0x40a2accbd92bca938b02010e17a5b8929b49130d",
        code_hash: "0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad",
    },
    Library {
        kind: "MultiSendCallOnly",
        address: "0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b",
        code_hash: "0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad",
    },
    Library {
        kind: "MultiSendCallOnly",
        address: "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
        code_hash: "0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939",
    },
    Library {
        kind: "MultiSendCallOnly",
        address: "0xa83c336b20401af773b6219ba5027174338d1836",
        code_hash: "0xcdbdcec38d2f1c7d961b0029ff8416b7e86e9974d6f0e9c9580c7d17fcfb6663",
    },
    Library {
        kind: "CreateCall",
        address: "0x7cbb62eaa69f79e6873cd1ecb2392971036cfaa4",
        code_hash: "0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82",
    },
    Library {
        kind: "CreateCall",
        address: "0xb19d6ffc2182150f8eb585b79d4abcd7c5640a9d",
        code_hash: "0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82",
    },
    Library {
        kind: "CreateCall",
        address: "0x9b35af71d77eaf8d7e40252370304687390a1a52",
        code_hash: "0x2b3060c55fcb8275653e99ad511a71f67ba76934ed66a7d74d6e68b52afff889",
    },
    Library {
        kind: "CreateCall",
        address: "0x2ef5ecfbea521449e4de05edb1ce63b75eda90b4",
        code_hash: "0x6b7d8d29bdf7004c4617d95041923774f3f7e74b056bff55c1861c9ec92ce54f",
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
    if offset % 32 != 0 || offset + 32 > data.len() {
        return Err(invalid("delegatecall ABI offset is invalid"));
    }
    let length: usize = U256::from_be_slice(&data[offset..offset + 32])
        .try_into()
        .map_err(|_| invalid("delegatecall ABI length is too large"))?;
    let end = offset
        .checked_add(32)
        .and_then(|start| start.checked_add(length))
        .ok_or_else(|| invalid("delegatecall ABI length overflow"))?;
    if end > data.len() || data[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid(
            "delegatecall ABI bytes are truncated or noncanonical",
        ));
    }
    Ok(&data[offset + 32..end])
}

fn classify(envelope: &Envelope) -> Result<String, ProtocolError> {
    let safe = address(&envelope.safe_address, "safe_address")?;
    let to = address(&envelope.safe_tx.to, "safe_tx.to")?;
    let value = uint(&envelope.safe_tx.value, "safe_tx.value")?;
    let data = bytes(&envelope.safe_tx.data, "safe_tx.data")?;
    match envelope.safe_tx.operation {
        0 => {
            if to == safe {
                return Err(invalid(
                    "Safe self-calls and configuration changes are not supported",
                ));
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
                    keccak256(&data)
                ))
            }
        }
        1 => {
            if value != U256::ZERO {
                return Err(invalid("Safe delegatecall transaction value must be zero"));
            }
            let target = envelope.safe_tx.to.to_ascii_lowercase();
            let hash = envelope
                .library_code_hash
                .as_deref()
                .ok_or_else(|| invalid("Safe delegatecall requires an observed library code hash"))?
                .to_ascii_lowercase();
            let library = LIBRARIES
                .iter()
                .find(|entry| entry.address == target && entry.code_hash == hash)
                .ok_or_else(|| {
                    invalid("delegatecall target/code hash is not a pinned Safe library")
                })?;
            if data.len() < 4 {
                return Err(invalid("Safe library calldata is truncated"));
            }
            if library.kind == "MultiSendCallOnly" {
                if data[..4] != keccak256("multiSend(bytes)").as_slice()[..4] {
                    return Err(invalid("unexpected MultiSendCallOnly selector"));
                }
                let packed = dynamic_bytes(&data[4..], 1, 0)?;
                let mut cursor = 0;
                let mut calls = 0;
                let mut total = U256::ZERO;
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
                    cursor = cursor
                        .checked_add(85)
                        .and_then(|next| next.checked_add(length))
                        .ok_or_else(|| invalid("MultiSend call data length overflow"))?;
                    if cursor > packed.len() {
                        return Err(invalid("MultiSend call data is truncated"));
                    }
                    total = total
                        .checked_add(call_value)
                        .ok_or_else(|| invalid("MultiSend native value overflow"))?;
                    calls += 1;
                }
                if calls == 0 {
                    return Err(invalid("MultiSendCallOnly batch is empty"));
                }
                Ok(format!(
                    "Action: Call-only batch\nCalls: {calls}\nTotal native value (wei): {total}\nPacked calls keccak256: {:#x}",
                    keccak256(packed)
                ))
            } else {
                let create = keccak256("performCreate(uint256,bytes)");
                let create2 = keccak256("performCreate2(uint256,bytes,bytes32)");
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
                    "Action: Deploy contract ({kind})\nInitcode keccak256: {:#x}",
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
) -> Result<Vec<String>, ProtocolError> {
    if request.safe_review_payloads.is_empty() {
        return Ok(Vec::new());
    }
    if !request.evm_review_payloads.is_empty() {
        return Err(invalid(
            "Safe and native EVM review payloads cannot be mixed",
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
    let action = classify(&envelope)?;
    let safe = address(&envelope.safe_address, "safe_address")?;
    let to = address(&envelope.safe_tx.to, "safe_tx.to")?;
    Ok(vec![format!(
        "Broker-decoded Safe transaction\nSafe: {safe}\nSafe version: {}\nSingleton: {}\nChain ID: {chain}\nOwner: {from}\nOwners: {}\nThreshold: {}\nSafe nonce: {}\nOperation: {}\nDestination: {to}\nNative value (wei): {}\nSafe transaction hash: {:#x}\nGuard: {}\nEnabled modules: {}\nFallback handler: {}\n{action}\nSafe gas reimbursement: disabled",
        envelope.safe_version,
        envelope.singleton,
        envelope.owners.join(", "),
        envelope.threshold,
        envelope.safe_tx.nonce,
        envelope.safe_tx.operation,
        envelope.safe_tx.value,
        keccak256(&preimage),
        envelope.guard,
        if envelope.modules.is_empty() {
            "none".into()
        } else {
            envelope.modules.join(", ")
        },
        envelope.fallback_handler,
    )])
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
            evm_review_payloads: vec![],
            safe_review_payloads: vec![Base64UrlBytes::from_bytes(&review)],
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
        }
    }

    #[test]
    fn verifies_safe_preimage_and_rejects_tampering() {
        let bytes = envelope();
        let request = request(bytes.clone());
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        let plan = review(&request, &policy(), from).unwrap().join("\n");
        assert!(plan.contains("Native transfer"));
        assert!(plan.contains("Safe nonce: 4"));
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["safe_tx"]["value"] = serde_json::json!("8");
        let changed = serde_jcs::to_vec(&changed).unwrap();
        let mut request = request;
        request.safe_review_payloads[0] = Base64UrlBytes::from_bytes(&changed);
        assert!(review(&request, &policy(), from).is_err());
    }
}
