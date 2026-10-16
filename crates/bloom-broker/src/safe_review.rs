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
    /// The catalog entries that read the inner calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_signing: Option<bloom_evm_clear_signing::ClearSigningEvidence>,
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

/// A 32-byte hash as a Petal reports it.
///
/// Broker cannot verify these against a chain, but a hash has a shape, and a
/// field with a checkable shape is checked: the value is rendered into the
/// ceremony, so accepting arbitrary text here means accepting whatever a
/// Petal puts on the approval screen.
fn code_hash(value: &str, field: &str) -> Result<(), ProtocolError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("{field} must be 0x-prefixed hex")))?;
    if digits.len() != 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "{field} must be a 0x-prefixed 32-byte hash"
        )));
    }
    Ok(())
}

/// A Safe version as a Petal reports it: `major.minor.patch`, optionally with
/// a short alphanumeric suffix such as `1.3.0+L2`. Short and printable, for
/// the same reason as `code_hash`.
fn safe_version(value: &str) -> Result<(), ProtocolError> {
    let invalid_version = || invalid("safe_version must look like 1.4.1, with an optional +suffix");
    if value.is_empty() || value.len() > 16 {
        return Err(invalid_version());
    }
    let (core, suffix) = match value.split_once('+') {
        Some((core, suffix)) => (core, Some(suffix)),
        None => (value, None),
    };
    if let Some(suffix) = suffix
        && (suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    {
        return Err(invalid_version());
    }
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid_version());
    }
    for part in parts {
        if part.is_empty()
            || part.len() > 3
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(invalid_version());
        }
    }
    Ok(())
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
    // Bounded still means checked, though -- every one of these is rendered
    // into the ceremony, so each is held to the shape its own type has.
    address(&envelope.singleton, "singleton")?;
    address(&envelope.guard, "guard")?;
    address(&envelope.fallback_handler, "fallback_handler")?;
    safe_version(&envelope.safe_version)?;
    code_hash(&envelope.singleton_code_hash, "singleton_code_hash")?;
    if let Some(hash) = &envelope.library_code_hash {
        code_hash(hash, "library_code_hash")?;
    }
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
    let threshold = uint(&envelope.threshold, "threshold")?;
    let owners = envelope
        .owners
        .iter()
        .map(|value| address(value, "owners[]"))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if threshold == U256::ZERO
        || threshold > U256::from(owners.len())
        || owners.len() != envelope.owners.len()
    {
        return Err(invalid(
            "reported Safe owners must be distinct and threshold must be between one and owner count",
        ));
    }

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

/// Chains on which every deployment in [`DEPLOYMENTS`] was read and found to
/// hold the code its `code_hash` names.
///
/// The chain ID is an EIP-712 domain member, so a signature cannot be replayed
/// onto a chain outside this list, where the same address could hold other
/// code. Adding a chain means reading every address on it -- which is what
/// `safe_deployments_hold_the_pinned_code` does, so the list cannot grow
/// ahead of the evidence.
const VERIFIED_CHAINS: &[u64] = &[1, 10, 100, 137, 8453, 42161];

/// One canonical Safe library a `delegatecall` may enter. `safe_tx.to` is
/// bound by the selector, so this is a real constraint on the executing code.
///
/// `code_hash` is keccak-256 of the deployed runtime code, which is what makes
/// the address list checkable rather than asserted: the addresses alone say
/// only that somebody wrote them down. The hash is not read at approval time
/// -- Broker performs no chain access -- but it is what the ignored RPC test
/// compares, so a wrong address or a chain that does not actually carry the
/// deployment fails a test instead of silently widening what a delegatecall
/// may enter.
struct Deployment {
    kind: &'static str,
    /// Read only by `safe_deployments_hold_the_pinned_code`'s messages.
    #[cfg_attr(not(test), allow(dead_code))]
    version: &'static str,
    address: &'static str,
    /// Read only by `safe_deployments_hold_the_pinned_code`. Approval-time
    /// code is offline and compares nothing; this is the recorded evidence
    /// that the addresses above are what they claim to be.
    #[cfg_attr(not(test), allow(dead_code))]
    code_hash: &'static str,
}

/// Canonical Safe deployments, from `@safe-global/safe-deployments`.
///
/// The 1.3.0 entries come in a canonical and an EIP-155 pair: the same
/// bytecode at two addresses, because it was deployed two ways. Later
/// versions have a single address.
const DEPLOYMENTS: &[Deployment] = &[
    Deployment {
        kind: "MultiSendCallOnly",
        version: "1.3.0",
        address: "0x40a2accbd92bca938b02010e17a5b8929b49130d",
        code_hash: "0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad",
    },
    Deployment {
        kind: "MultiSendCallOnly",
        version: "1.3.0-eip155",
        address: "0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b",
        code_hash: "0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad",
    },
    Deployment {
        kind: "MultiSendCallOnly",
        version: "1.4.1",
        address: "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
        code_hash: "0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939",
    },
    Deployment {
        kind: "MultiSendCallOnly",
        version: "1.5.0",
        address: "0xa83c336b20401af773b6219ba5027174338d1836",
        code_hash: "0xcdbdcec38d2f1c7d961b0029ff8416b7e86e9974d6f0e9c9580c7d17fcfb6663",
    },
    Deployment {
        kind: "CreateCall",
        version: "1.3.0",
        address: "0x7cbb62eaa69f79e6873cd1ecb2392971036cfaa4",
        code_hash: "0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82",
    },
    Deployment {
        kind: "CreateCall",
        version: "1.3.0-eip155",
        address: "0xb19d6ffc2182150f8eb585b79d4abcd7c5640a9d",
        code_hash: "0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82",
    },
    Deployment {
        kind: "CreateCall",
        version: "1.4.1",
        address: "0x9b35af71d77eaf8d7e40252370304687390a1a52",
        code_hash: "0x2b3060c55fcb8275653e99ad511a71f67ba76934ed66a7d74d6e68b52afff889",
    },
    Deployment {
        kind: "CreateCall",
        version: "1.5.0",
        address: "0x2ef5ecfbea521449e4de05edb1ce63b75eda90b4",
        code_hash: "0x6b7d8d29bdf7004c4617d95041923774f3f7e74b056bff55c1861c9ec92ce54f",
    },
];

/// The canonical library at `address`, if Broker accepts it on `chain`.
///
/// An address is evidence only on a chain where its code was read, so the
/// chain is part of the lookup: on any other chain the same address can hold
/// code someone else chose, and nothing may be recognised by identity there.
fn library(chain: U256, address: &str) -> Option<&'static Deployment> {
    if !VERIFIED_CHAINS.iter().any(|id| U256::from(*id) == chain) {
        return None;
    }
    DEPLOYMENTS.iter().find(|entry| entry.address == address)
}

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
            "{index}. ERC-20 transfer of {} base units of token {to} to {} with native value {}",
            U256::from_be_slice(&data[36..68]),
            Address::from_slice(&data[16..36]),
            native(value, chain)
        )
    } else if data.is_empty() {
        format!("{index}. Send {} to {to}", native(value, chain))
    } else {
        format!(
            "{index}. {OPAQUE_ENTRY}{to} with {}, selector 0x{}, calldata keccak256 {:#x}",
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

/// The Safe's current signing configuration, as the Petal reports it.
///
/// Unverified -- the envelope discloses it separately for that reason -- but a
/// threshold change is unreadable without a baseline, so the reading uses it
/// and says that is where it came from.
struct SafeSigners {
    threshold: U256,
    owners: usize,
}

/// The four Safe self-calls that change who may sign and how many must. Every
/// other self-call stays refused: enabling a module, or setting a guard or
/// fallback handler, hands the Safe to code Broker cannot review.
///
/// The `prevOwner` argument only locates an entry in the Safe's owner list,
/// so it is checked for shape and not shown.
fn owner_change(
    signer: Address,
    value: U256,
    data: &[u8],
    current: &SafeSigners,
) -> Result<String, ProtocolError> {
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
    // A bare "New threshold: 1" reads identically whether it leaves the Safe
    // as it was or drops it from 3-of-4 to 1-of-4, which is the difference
    // between a no-op and handing the Safe to any single owner. The current
    // values come from the Petal and Broker cannot verify them, so the line
    // says where the comparison came from and stays silent without it.
    let describe_threshold = |new: U256, owners: i64| -> String {
        let single_owner_warning = if new == U256::from(1u8) {
            "\nWarning: any single owner will then be able to move the Safe's funds alone"
        } else {
            ""
        };
        let count = (current.owners as i64 + owners).max(0);
        let mut line = format!(
            "New threshold: {new} of {count} owners (reported now: {} of {})",
            current.threshold, current.owners
        );
        if new < current.threshold {
            line.push_str(&format!(
                "\nWarning: this lowers the signatures the Safe requires, from {} to {new}",
                current.threshold
            ));
        }
        line.push_str(single_owner_warning);
        line
    };
    if selector("addOwnerWithThreshold(address,uint256)") && words.len() == 2 {
        Ok(format!(
            "Action: Add Safe owner\nNew owner: {}\n{}",
            word_as_address(words[0])?,
            describe_threshold(threshold(words[1])?, 1)
        ))
    } else if selector("removeOwner(address,address,uint256)") && words.len() == 3 {
        word_as_address(words[0])?;
        let removed = word_as_address(words[1])?;
        Ok(format!(
            "Action: Remove Safe owner\nOwner removed: {removed}\n{}{}",
            describe_threshold(threshold(words[2])?, -1),
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
            "Action: Change Safe threshold\n{}",
            describe_threshold(threshold(words[0])?, 0)
        ))
    } else {
        Err(refused())
    }
}

/// The heading `classify` uses when it could read nothing about the inner
/// call beyond its selector and hash. Named rather than spelled out at each
/// use so the wallet-policy gate can ask whether the reading was opaque
/// instead of re-deriving the question from the rendered text.
pub(crate) const OPAQUE_ACTION: &str = "Action: Contract call";

/// What follows the index of a batch entry Bloom could not read.
const OPAQUE_ENTRY: &str = "Contract call to ";

/// Whether a rendered line is a call Bloom read no further than its selector
/// and hash: the whole transaction, or any one entry of a call-only batch.
/// Both gates ask this one question, so a batch cannot hide what a direct
/// call would have to disclose.
fn is_opaque_line(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with(OPAQUE_ACTION)
        || line.split_once(". ").is_some_and(|(index, rest)| {
            !index.is_empty()
                && index.bytes().all(|byte| byte.is_ascii_digit())
                && (rest.starts_with(OPAQUE_ENTRY) || rest.starts_with(OPAQUE_ACTION))
        })
}

fn classify_calls(
    envelope: &Envelope,
    read_call: impl FnMut(Address, U256, &[u8]) -> Result<Option<String>, ProtocolError>,
) -> Result<String, ProtocolError> {
    let current = SafeSigners {
        threshold: uint(&envelope.threshold, "threshold")?,
        owners: envelope.owners.len(),
    };
    classify_call_with_reader(
        &SafeCall {
            chain: uint(&envelope.chain_id, "chain_id")?,
            safe: address(&envelope.safe_address, "safe_address")?,
            signer: address(&envelope.owner, "owner")?,
            to: address(&envelope.safe_tx.to, "safe_tx.to")?,
            value: uint(&envelope.safe_tx.value, "safe_tx.value")?,
            data: &bytes(&envelope.safe_tx.data, "safe_tx.data")?,
            operation: envelope.safe_tx.operation,
            current: &current,
        },
        read_call,
    )
}

/// Read one Safe transaction. `signer` is the Bloom wallet approving, so a
/// change that removes it can say so.
/// One Safe transaction to read, as the bytes being signed describe it.
struct SafeCall<'a> {
    chain: U256,
    safe: Address,
    signer: Address,
    to: Address,
    value: U256,
    data: &'a [u8],
    operation: u8,
    /// The Safe's current signing configuration, as the Petal reports it.
    current: &'a SafeSigners,
}

fn classify_call_with_reader(
    call: &SafeCall<'_>,
    mut read_call: impl FnMut(Address, U256, &[u8]) -> Result<Option<String>, ProtocolError>,
) -> Result<String, ProtocolError> {
    let SafeCall {
        chain,
        safe,
        signer,
        to,
        value,
        data,
        operation,
        current,
    } = *call;
    match operation {
        0 => {
            if to == safe {
                if value.is_zero() && data.is_empty() {
                    return Ok("Action: Reject competing Safe transaction\nValue: 0".into());
                }
                return owner_change(signer, value, data, current);
            }
            if !data.is_empty()
                && let Some(reading) = read_call(to, value, data)?
            {
                return Ok(reading);
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
                    "{OPAQUE_ACTION}\nCalldata selector: 0x{}\nCalldata keccak256: {:#x}",
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
            if !VERIFIED_CHAINS.iter().any(|id| U256::from(*id) == chain) {
                return Err(invalid(concat!(
                    "Safe delegatecalls are refused on this chain because Broker has no ",
                    "verified Safe library deployment for it",
                )));
            }
            let target = format!("{to:#x}");
            let library = library(chain, &target)
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
                    if destination == safe || destination == Address::ZERO {
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
                    total = total.checked_add(call_value).ok_or_else(|| {
                        invalid(format!(
                            "MultiSend native value overflow at entry {}",
                            calls + 1
                        ))
                    })?;
                    calls += 1;
                    // Every entry is disclosed; a batch must not hide a call.
                    let call_data = &packed[data_start..next];
                    if !call_data.is_empty()
                        && let Some(reading) = read_call(destination, call_value, call_data)?
                    {
                        entries.push(format!("  {calls}. {}", reading.replace('\n', "\n     ")));
                    } else {
                        entries.push(entry_summary(
                            &chain_name,
                            calls,
                            destination,
                            call_value,
                            call_data,
                        ));
                    }
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
    catalog: &bloom_evm_clear_signing::Catalog,
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
    let mut entries = Vec::new();
    let mut structural = false;
    let rendered = classify_calls(&envelope, |to, value, calldata| {
        let chain_id = u64::try_from(chain)
            .map_err(|_| invalid("Safe chain ID is too large for catalog review"))?;
        let reading = crate::evm_review::read_contract_call(
            &crate::evm_review::DecodedCall {
                chain_id,
                to,
                value,
                calldata: calldata.to_vec(),
            },
            catalog,
        );
        // A call Bloom cannot read keeps the Safe's own summary of its bytes.
        let Ok((reading, selected)) = reading else {
            return Ok(None);
        };
        structural |= reading.structural;
        for entry in selected {
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
        let mut lines = vec![
            format!("Action: {}", reading.action),
            format!("Contract: {}", reading.contract),
        ];
        if let Some(summary) = reading.intent_summary {
            lines.push(match &summary.token {
                Some(token) => format!(
                    "Token: {} — {} ({})",
                    token.symbol, token.name, token.address
                ),
                None => format!("Token: unidentified contract {}", reading.contract),
            });
            let role = if summary.counterparty_role == "recipient" {
                "Recipient"
            } else {
                "Spender"
            };
            lines.push(format!("{role}: {}", summary.counterparty));
            lines.push(format!(
                "Token amount: {} (base units: {})",
                summary.amount_display, summary.amount
            ));
        } else {
            for field in reading.fields {
                lines.push(format!(
                    "{}: {} (signed: {})",
                    field.label, field.value, field.raw
                ));
            }
        }
        lines.push(format!("Native value (wei): {value}"));
        lines.push(reading.assurance);
        lines.extend(
            reading
                .warnings
                .into_iter()
                .map(|warning| format!("Warning: {warning}")),
        );
        Ok(Some(lines.join("\n")))
    })?;
    let evidence = (!entries.is_empty())
        .then(|| bloom_evm_clear_signing::ClearSigningEvidence::new(entries, structural));
    let action = rendered.lines().map(str::to_owned).collect();
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
            singleton: address(&envelope.singleton, "singleton")?.to_string(),
            singleton_code_hash: envelope.singleton_code_hash,
            owners: envelope
                .owners
                .iter()
                .map(|value| address(value, "owners[]").map(|address| address.to_string()))
                .collect::<Result<_, _>>()?,
            threshold: envelope.threshold,
            guard: address(&envelope.guard, "guard")?.to_string(),
            modules: envelope
                .modules
                .iter()
                .map(|value| address(value, "modules[]").map(|address| address.to_string()))
                .collect::<Result<_, _>>()?,
            fallback_handler: address(&envelope.fallback_handler, "fallback_handler")?.to_string(),
            library_code_hash: envelope.library_code_hash,
        },
        clear_signing: evidence,
    }))
}

/// Whether a prepared Safe review read its inner call, for the frozen record.
pub(crate) fn is_opaque(review: &SafeReview) -> bool {
    review.action.iter().any(|line| is_opaque_line(line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::*;

    fn no_catalog() -> bloom_evm_clear_signing::Catalog {
        bloom_evm_clear_signing::Catalog::build(&[], Vec::new()).unwrap()
    }

    fn review(
        request: &ApprovalPrepareRequest,
        policy: &CanonicalWalletPolicy,
        from: Address,
    ) -> Result<Option<SafeReview>, ProtocolError> {
        super::review(request, policy, from, &no_catalog())
    }

    fn classify(envelope: &Envelope) -> Result<String, ProtocolError> {
        classify_calls(envelope, |_, _, _| Ok(None))
    }

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
            surface_selection: bloom_broker_api::CeremonySurfaceSelection::Default,
            operation_id: OperationId::from_bytes([2; 32]),
            canonical_plan_facts_digest: digest.clone(),
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
    fn safe_inner_calls_are_read_with_the_catalog() {
        let catalog = crate::evm_review::mode_tests::accepted_catalog_on_chain(31337);
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["safe_tx"]["to"] = serde_json::json!("0x1111111111111111111111111111111111111111");
        value["safe_tx"]["value"] = serde_json::json!("0");
        value["safe_tx"]["data"] = serde_json::json!(format!(
            "0xa9059cbb{}{}",
            "0".repeat(24) + &"2".repeat(40),
            format!("{:064x}", 1_000_000),
        ));
        let plan = super::review(
            &request(serde_jcs::to_vec(&value).unwrap()),
            &policy(),
            from,
            &catalog,
        )
        .unwrap()
        .unwrap();
        assert!(!is_opaque(&plan));
        assert!(
            plan.action.iter().any(|line| line.contains("EXA")),
            "{:?}",
            plan.action
        );
        assert!(plan.clear_signing.is_some());

        // A call Bloom cannot read is shown as its bytes, not refused.
        value["safe_tx"]["to"] = serde_json::json!("0x4000000000000000000000000000000000000000");
        value["safe_tx"]["data"] = serde_json::json!("0xdeadbeef");
        let plan = super::review(
            &request(serde_jcs::to_vec(&value).unwrap()),
            &policy(),
            from,
            &catalog,
        )
        .unwrap()
        .unwrap();
        assert!(is_opaque(&plan));
    }

    #[test]
    fn petal_reported_version_and_code_hashes_must_have_their_own_shape() {
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        for (field, bad) in [
            ("safe_version", serde_json::json!("1.4.1; see attached")),
            ("safe_version", serde_json::json!("")),
            ("safe_version", serde_json::json!("1.4")),
            ("safe_version", serde_json::json!("01.4.1")),
            ("singleton_code_hash", serde_json::json!("not a hash")),
            ("singleton_code_hash", serde_json::json!("0xabcd")),
            ("library_code_hash", serde_json::json!("0xzz")),
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
            value[field] = bad.clone();
            let bytes = serde_jcs::to_vec(&value).unwrap();
            assert!(
                review(&request(bytes), &policy(), from).is_err(),
                "{field} = {bad} must be refused"
            );
        }

        // The shapes an honest Petal reports are all still accepted.
        for version in ["1.3.0", "1.4.1", "1.5.0", "1.3.0+L2"] {
            let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
            value["safe_version"] = serde_json::json!(version);
            let bytes = serde_jcs::to_vec(&value).unwrap();
            review(&request(bytes), &policy(), from)
                .unwrap_or_else(|error| panic!("{version} must be accepted: {error}"));
        }
    }

    /// The evidence behind [`DEPLOYMENTS`] and [`VERIFIED_CHAINS`].
    ///
    /// Everything else here runs offline, and Broker itself never reads a
    /// chain. But the delegatecall allowlist, the factory list and the
    /// singleton check are all claims about what code lives at an address on
    /// six chains, and a comment asserting it is not evidence. This reads
    /// every address on every chain and compares keccak-256 of the deployed
    /// runtime code against the pinned `code_hash`, so the claim is
    /// falsifiable and adding a chain or a Safe version cannot outrun it.
    ///
    /// Ignored because it needs network. `curl` rather than an HTTP crate:
    /// Broker has no HTTP dependency and should not gain one for a test.
    ///
    /// ```sh
    /// BLOOM_SAFE_RPC_1=https://ethereum-rpc.publicnode.com \
    /// BLOOM_SAFE_RPC_10=https://optimism-rpc.publicnode.com \
    /// BLOOM_SAFE_RPC_100=https://gnosis-rpc.publicnode.com \
    /// BLOOM_SAFE_RPC_137=https://polygon-bor-rpc.publicnode.com \
    /// BLOOM_SAFE_RPC_8453=https://mainnet.base.org \
    /// BLOOM_SAFE_RPC_42161=https://arbitrum-one-rpc.publicnode.com \
    ///   cargo test -p bloom-broker safe_deployments_hold_the_pinned_code -- --ignored
    /// ```
    #[test]
    #[ignore = "reads six public RPC endpoints; set BLOOM_SAFE_RPC_<chain_id>"]
    fn safe_deployments_hold_the_pinned_code() {
        fn rpc(url: &str, address: &str) -> Result<Vec<u8>, String> {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["{address}","latest"]}}"#
            );
            let output = std::process::Command::new("curl")
                .args([
                    "-sS",
                    "--max-time",
                    "30",
                    "-X",
                    "POST",
                    url,
                    "-H",
                    "content-type: application/json",
                    "--data",
                    &body,
                ])
                .output()
                .map_err(|error| format!("curl is required for this test: {error}"))?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).into_owned());
            }
            let text = String::from_utf8_lossy(&output.stdout).into_owned();
            let marker = "\"result\":\"0x";
            let start = text
                .find(marker)
                .ok_or_else(|| format!("no result in response: {text}"))?
                + marker.len();
            let hex = text[start..]
                .split('"')
                .next()
                .ok_or_else(|| format!("truncated result: {text}"))?;
            hex::decode(hex).map_err(|error| format!("result is not hex: {error}"))
        }

        let mut missing = Vec::new();
        let mut endpoints = Vec::new();
        for chain in VERIFIED_CHAINS {
            match std::env::var(format!("BLOOM_SAFE_RPC_{chain}")) {
                Ok(url) if !url.trim().is_empty() => endpoints.push((*chain, url)),
                _ => missing.push(format!("BLOOM_SAFE_RPC_{chain}")),
            }
        }
        assert!(
            missing.is_empty(),
            "every verified chain needs an endpoint, or the evidence is partial; missing: {}",
            missing.join(" ")
        );

        let mut wrong = Vec::new();
        for (chain, url) in &endpoints {
            for entry in DEPLOYMENTS {
                match rpc(url, entry.address) {
                    Ok(code) if code.is_empty() => wrong.push(format!(
                        "chain {chain}: {} {} at {} has no code",
                        entry.kind, entry.version, entry.address
                    )),
                    Ok(code) => {
                        let actual = format!("{:#x}", keccak256(&code));
                        if actual != entry.code_hash {
                            wrong.push(format!(
                                "chain {chain}: {} {} at {} holds {actual}, pinned {}",
                                entry.kind, entry.version, entry.address, entry.code_hash
                            ));
                        }
                    }
                    Err(error) => wrong.push(format!(
                        "chain {chain}: reading {} failed: {error}",
                        entry.address
                    )),
                }
            }
        }
        assert!(
            wrong.is_empty(),
            "a pinned Safe deployment is not what this table says it is. Until every line \
             here is explained, a delegatecall allowlist and a singleton check built on it \
             are not verified:\n{}",
            wrong.join("\n")
        );
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
        // The envelope reports a 1-of-1 Safe, so the new threshold is shown
        // against that baseline: "2" alone would read the same whether it
        // raised the requirement or left it alone.
        assert_eq!(
            added,
            format!(
                "Action: Add Safe owner\nNew owner: {}\nNew threshold: 2 of 2 owners \
                 (reported now: 1 of 1)",
                checksum(other)
            )
        );
        // Raising the requirement carries no warning.
        assert!(!added.contains("Warning"));
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
                .contains("New threshold: 3 of 1 owners (reported now: 1 of 1)")
        );

        // A reduction has to be unmistakable. This Safe is 1-of-1, so build a
        // 3-of-4 baseline and drop it to 1: before, the page said only
        // "New threshold: 1", which reads the same as no change at all.
        let mut multi = base.clone();
        multi["threshold"] = serde_json::json!("3");
        multi["owners"] = serde_json::json!([
            signer,
            other,
            "0x8000000000000000000000000000000000000000",
            "0x9000000000000000000000000000000000000000"
        ]);
        let lowered = {
            let mut data = keccak256("changeThreshold(uint256)").as_slice()[..4].to_vec();
            data.extend(number(1));
            let mut envelope = multi.clone();
            envelope["safe_tx"]["to"] = envelope["safe_address"].clone();
            envelope["safe_tx"]["value"] = serde_json::json!("0");
            envelope["safe_tx"]["data"] = serde_json::json!(format!("0x{}", hex::encode(data)));
            classify(&serde_json::from_value::<Envelope>(envelope).unwrap()).unwrap()
        };
        assert!(
            lowered.contains("New threshold: 1 of 4 owners (reported now: 3 of 4)"),
            "{lowered}"
        );
        assert!(
            lowered.contains("lowers the signatures the Safe requires, from 3 to 1"),
            "{lowered}"
        );
        assert!(
            lowered.contains("any single owner will then be able to move"),
            "{lowered}"
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

    #[test]
    fn threshold_one_warning_does_not_trust_the_reported_owner_count() {
        let mut data = keccak256("changeThreshold(uint256)").as_slice()[..4].to_vec();
        data.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        let reported = SafeSigners {
            threshold: U256::from(1),
            owners: 1,
        };
        let action = owner_change(Address::ZERO, U256::ZERO, &data, &reported).unwrap();
        assert!(action.contains("any single owner will then be able to move"));
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
    fn safe_batch_calls_are_read_with_the_catalog() {
        let catalog = crate::evm_review::mode_tests::accepted_catalog_on_chain(8453);
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        let mut policy = policy();
        policy.allowed_destinations[0].chain = token("evm-8453");
        let mut parsed: Envelope = serde_json::from_slice(&envelope()).unwrap();
        parsed.chain_id = "8453".into();
        parsed.safe_tx.to = "0xa83c336b20401af773b6219ba5027174338d1836".into();
        parsed.safe_tx.operation = 1;
        parsed.safe_tx.value = "0".into();
        let mut transfer = vec![0xa9, 0x05, 0x9c, 0xbb];
        transfer.extend_from_slice(&[0; 12]);
        transfer.extend_from_slice(&[0x22; 20]);
        transfer.extend_from_slice(&U256::from(1_000_000).to_be_bytes::<32>());
        for (target, data, known) in [
            ("0x1111111111111111111111111111111111111111", transfer, true),
            (
                "0x4000000000000000000000000000000000000000",
                vec![0xde, 0xad, 0xbe, 0xef],
                false,
            ),
        ] {
            let packed = multisend_entry(target, 0, &data);
            parsed.safe_tx.data = format!("0x{}", hex::encode(multisend_calldata(&packed)));
            let plan = super::review(
                &request(serde_jcs::to_vec(&parsed).unwrap()),
                &policy,
                from,
                &catalog,
            )
            .unwrap()
            .unwrap();
            assert_eq!(is_opaque(&plan), !known, "{:?}", plan.action);
            assert_eq!(plan.action.iter().any(|line| line.contains("EXA")), known);
        }
    }

    #[test]
    fn batch_value_overflow_names_the_offending_entry() {
        let target = "0x4000000000000000000000000000000000000000";
        let mut packed = multisend_entry(target, 0, &[]);
        packed[21..53].copy_from_slice(&U256::MAX.to_be_bytes::<32>());
        packed.extend(multisend_entry(target, 1, &[]));
        let mut parsed: Envelope = serde_json::from_slice(&envelope()).unwrap();
        parsed.chain_id = "8453".into();
        parsed.safe_tx.to = "0xa83c336b20401af773b6219ba5027174338d1836".into();
        parsed.safe_tx.operation = 1;
        parsed.safe_tx.value = "0".into();
        parsed.safe_tx.data = format!("0x{}", hex::encode(multisend_calldata(&packed)));
        assert!(
            classify(&parsed)
                .unwrap_err()
                .message
                .contains("overflow at entry 2")
        );
    }

    #[test]
    fn version_150_batch_rejects_zero_and_explicit_safe_self_calls() {
        for target in [ZERO, "0x1000000000000000000000000000000000000000"] {
            let mut parsed: Envelope = serde_json::from_slice(&envelope()).unwrap();
            parsed.chain_id = "8453".into();
            parsed.safe_tx.to = "0xa83c336b20401af773b6219ba5027174338d1836".into();
            parsed.safe_tx.operation = 1;
            parsed.safe_tx.value = "0".into();
            parsed.safe_tx.data = format!(
                "0x{}",
                hex::encode(multisend_calldata(&multisend_entry(
                    target,
                    0,
                    &[0x61, 0x0b, 0x59, 0x25]
                )))
            );
            assert!(
                classify(&parsed)
                    .unwrap_err()
                    .message
                    .contains("Safe self-call")
            );
        }
    }

    #[test]
    fn safe_review_requires_exact_chain_opt_in_canonical_json_and_unmixed_payloads() {
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        let mut blocked = policy();
        blocked.allowed_destinations.clear();
        assert!(
            review(&request(envelope()), &blocked, from)
                .unwrap_err()
                .message
                .contains("allow destination exact")
        );
        let mut noncanonical = request(envelope());
        noncanonical.safe_review_payloads[0] = Base64UrlBytes::from_bytes(
            &serde_json::to_vec_pretty(
                &serde_json::from_slice::<serde_json::Value>(&envelope()).unwrap(),
            )
            .unwrap(),
        );
        assert!(
            review(&noncanonical, &policy(), from)
                .unwrap_err()
                .message
                .contains("canonical JCS")
        );
        let mut mixed = request(envelope());
        mixed
            .evm_review_payloads
            .push(Base64UrlBytes::from_bytes(&[1]));
        assert!(
            review(&mixed, &policy(), from)
                .unwrap_err()
                .message
                .contains("cannot be mixed")
        );
        let mut delegate: Envelope = serde_json::from_slice(&envelope()).unwrap();
        delegate.safe_tx.operation = 1;
        assert!(
            classify(&delegate)
                .unwrap_err()
                .message
                .contains("value must be zero")
        );
    }

    #[test]
    fn impossible_reported_owner_sets_and_thresholds_are_refused() {
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();
        for threshold in ["0", "2"] {
            let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
            value["threshold"] = serde_json::json!(threshold);
            let request = request(serde_jcs::to_vec(&value).unwrap());
            assert!(
                review(&request, &policy(), from)
                    .unwrap_err()
                    .message
                    .contains("threshold must be between")
            );
        }
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["owners"] = serde_json::json!([from.to_string(), from.to_string()]);
        let request = request(serde_jcs::to_vec(&value).unwrap());
        assert!(
            review(&request, &policy(), from)
                .unwrap_err()
                .message
                .contains("owners must be distinct")
        );
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
