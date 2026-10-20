//! Independent semantic review for Safe owner signatures.

use std::str::FromStr;

use alloy::primitives::{Address, U256, keccak256};
use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalSelector, CanonicalWalletPolicy, CryptoSuite, DeclaredFee,
    Digest32, ProtocolError, ProtocolErrorCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Facts Broker rebuilt from the exact Safe signing bytes.
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
    /// The catalog entries that read the inner calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_signing: Option<bloom_evm_clear_signing::ClearSigningEvidence>,
}

const MAX_REVIEW_BYTES: usize = 256 * 1024;
const MAX_CALLDATA_BYTES: usize = 128 * 1024;
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

/// The Safe's version, singleton, owners, threshold, guard, modules and
/// fallback handler are the Petal's report and outside the signed bytes, so
/// Broker neither checks nor shows them. It checks the one thing it can: the
/// signing owner is this wallet's key.
fn validate_state(envelope: &Envelope, from: Address) -> Result<(), ProtocolError> {
    if envelope.schema != "bloom.safe.review.v1" {
        return Err(invalid("unsupported Safe review schema"));
    }
    if address(&envelope.owner, "owner")? != from {
        return Err(invalid(
            "Safe review owner differs from the Bloom signing key",
        ));
    }
    Ok(())
}

/// The heading of a Safe transaction Bloom could not read.
pub(crate) const OPAQUE_ACTION: &str = "Action: Contract call Bloom cannot read";

const EXEC_TRANSACTION: &str =
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";

/// The Safe transaction as the `execTransaction` call that runs it, so it is
/// read with the same catalog and rules as a Safe execution: inner calls,
/// owner changes, batches and deployments. Signatures are not part of it.
fn exec_calldata(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    use alloy_dyn_abi::{DynSolValue, JsonAbiExt as _};
    let tx = &envelope.safe_tx;
    let address = |value: &str, field| address(value, field).map(DynSolValue::Address);
    let uint = |value: &str, field| uint(value, field).map(|value| DynSolValue::Uint(value, 256));
    bloom_evm_clear_signing::parse_function(EXEC_TRANSACTION)
        .map_err(|error| invalid(error.to_string()))?
        .abi_encode_input(&[
            address(&tx.to, "safe_tx.to")?,
            uint(&tx.value, "safe_tx.value")?,
            DynSolValue::Bytes(bytes(&tx.data, "safe_tx.data")?),
            DynSolValue::Uint(U256::from(tx.operation), 8),
            uint(&tx.safe_tx_gas, "safe_tx.safe_tx_gas")?,
            uint(&tx.base_gas, "safe_tx.base_gas")?,
            uint(&tx.gas_price, "safe_tx.gas_price")?,
            address(&tx.gas_token, "safe_tx.gas_token")?,
            address(&tx.refund_receiver, "safe_tx.refund_receiver")?,
            DynSolValue::Bytes(Vec::new()),
        ])
        .map_err(|error| invalid(error.to_string()))
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
    let chain_id = u64::try_from(chain)
        .map_err(|_| invalid("Safe chain ID is too large for catalog review"))?;
    let reading = bloom_evm_clear_signing::review_call(
        catalog,
        &bloom_evm_clear_signing::CallContext {
            chain_id,
            to: address(&envelope.safe_address, "safe_address")?,
            value: U256::ZERO,
            calldata: &exec_calldata(&envelope)?,
            native: crate::evm_review::native_units(&crate::evm_review::chain_name(chain_id)),
        },
    );
    let (action, evidence) = match reading {
        Ok((call, entries)) => {
            // The inner call's heading first, then what it adds. The page
            // shows the destination, value and operation separately, the
            // signatures are not part of what the owner signs, and zero gas
            // settings say nothing.
            let heading = call
                .fields
                .iter()
                .find(|field| field.label == "Safe transaction")
                .map_or(call.function_signature.clone(), |field| field.value.clone());
            let mut lines = vec![format!("Action: {heading}")];
            lines.extend(
                call.fields
                    .iter()
                    .filter(|field| {
                        !matches!(
                            field.label.as_str(),
                            "Safe transaction" | "Safe calls" | "Safe sends" | "Operation"
                        ) && !field.label.starts_with("Owner signatures")
                            && !(field.raw == "0"
                                && matches!(field.label.as_str(), "Safe gas limit" | "Base gas"))
                    })
                    .flat_map(|field| {
                        let label = field.label.trim_start_matches("Safe transaction · ");
                        let mut rows = vec![format!("{label}: {}", field.value)];
                        if let Some(asset) = &field.asset {
                            rows.push(format!("{label} asset: {}", asset.token.address));
                            if !field.raw.is_empty()
                                && field.raw.bytes().all(|byte| byte.is_ascii_digit())
                            {
                                rows.push(format!("{label} (raw units): {}", field.raw));
                            }
                        }
                        rows
                    }),
            );
            lines.extend(
                call.warnings
                    .iter()
                    .map(|warning| format!("Warning: {warning}")),
            );
            (
                lines,
                Some(bloom_evm_clear_signing::ClearSigningEvidence::new(
                    entries,
                    call.structural,
                )),
            )
        }
        Err(error) => (
            vec![
                OPAQUE_ACTION.to_owned(),
                format!("Reason: {}", error.detail),
            ],
            None,
        ),
    };
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
        clear_signing: evidence,
    }))
}

/// Whether Bloom could not read the Safe transaction.
pub(crate) fn is_opaque(review: &SafeReview) -> bool {
    review
        .action
        .first()
        .is_some_and(|line| line == OPAQUE_ACTION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::*;

    const SINGLETON: &str = "0x41675c099f32341bf84bfc5382af534df5c7461a";

    /// The Safe description on `chain_id`, and an example token there.
    fn catalog_on(chain_id: u64) -> bloom_evm_clear_signing::Catalog {
        use bloom_broker_api::KnownToken;
        use bloom_evm_clear_signing::{Binding, DESCRIPTORS};
        let mut safe: serde_json::Value = serde_json::from_str(DESCRIPTORS[0].1).unwrap();
        safe["context"]["contract"]["deployments"] =
            serde_json::json!([{"chainId": chain_id, "address": SINGLETON}]);
        let token = KnownToken {
            chain_id,
            address: "0x1111111111111111111111111111111111111111".into(),
            symbol: "EXA".into(),
            name: "Example Token".into(),
            decimals: 6,
            upgradeable: false,
        };
        bloom_evm_clear_signing::Catalog::build(
            &[(safe, Binding::Instances(SINGLETON))],
            vec![token],
        )
        .unwrap()
    }

    fn review(
        request: &ApprovalPrepareRequest,
        policy: &CanonicalWalletPolicy,
        from: Address,
    ) -> Result<Option<SafeReview>, ProtocolError> {
        super::review(request, policy, from, &catalog_on(31337))
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
            evm_reported_token: None,
            surface_selection: bloom_broker_api::CeremonySurfaceSelection::Default,
            operation_id: OperationId::from_bytes([2; 32]),
            canonical_plan_facts_digest: digest.clone(),
            evm_review_payloads: vec![],
            message_review_payloads: Vec::new(),
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
            plan.action[0],
            "Action: Send 0.000000000000000007 ETH to 0x4000000000000000000000000000000000000000"
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
        let catalog = catalog_on(31337);
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
        let catalog = catalog_on(8453);
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
