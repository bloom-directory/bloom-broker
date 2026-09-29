//! Independent semantic review for Safe owner signatures.

use std::str::FromStr;

use alloy::primitives::{Address, U256, keccak256};
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

fn classify(envelope: &Envelope) -> Result<String, ProtocolError> {
    let safe = address(&envelope.safe_address, "safe_address")?;
    let to = address(&envelope.safe_tx.to, "safe_tx.to")?;
    let value = uint(&envelope.safe_tx.value, "safe_tx.value")?;
    let data = bytes(&envelope.safe_tx.data, "safe_tx.data")?;
    match envelope.safe_tx.operation {
        0 => {
            if to == safe {
                if value.is_zero() && data.is_empty() {
                    return Ok("Action: Reject competing Safe transaction\nValue: 0".into());
                }
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
        1 => Err(invalid(
            "Safe delegatecalls are not supported because Broker cannot authenticate target code",
        )),
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
    fn rejects_refunds_and_every_delegatecall() {
        let from = address("0x3000000000000000000000000000000000000000", "owner").unwrap();

        // Refund fields are EIP-712 members, so the digest binds them and this
        // is a real constraint on what the owner is signing.
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["safe_tx"]["gas_price"] = serde_json::json!("1");
        let canonical = serde_jcs::to_vec(&value).unwrap();
        assert!(review(&request(canonical), &policy(), from).is_err());

        // An address and Petal-reported code hash cannot authenticate the code
        // another chain will execute in the Safe's storage context.
        let mut value: serde_json::Value = serde_json::from_slice(&envelope()).unwrap();
        value["safe_tx"]["operation"] = serde_json::json!(1);
        value["safe_tx"]["value"] = serde_json::json!("0");
        value["safe_tx"]["data"] = serde_json::json!("0x8d80ff0a");
        value["safe_tx"]["to"] = serde_json::json!("0x9641d764fc13c8b624c04430c7356c1c7c8102e2");
        value["library_code_hash"] =
            serde_json::json!("0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939");
        let canonical = serde_jcs::to_vec(&value).unwrap();
        let error = review(&request(canonical), &policy(), from).unwrap_err();
        assert!(error.message.contains("cannot authenticate target code"));
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
