//! Independently decode native EVM preimages for exact owner review. Machine
//! descriptions are never used to infer transaction destination or authority.
use alloy::{
    consensus::{SignableTransaction, Transaction, TxEip1559, TxLegacy},
    primitives::{Address, Signature, TxKind, keccak256},
    rlp::Decodable,
};
use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalSelector, ApprovalSubject, CanonicalWalletPolicy, CryptoSuite,
    Digest32, ProtocolError, ProtocolErrorCode, SystemUseClaim,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvmReview {
    pub payloads: Vec<EvmReviewPayload>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvmReviewPayload {
    pub chain_id: String,
    pub chain: String,
    pub sender: String,
    pub destination: Option<String>,
    pub value: String,
    pub value_display: String,
    pub nonce: String,
    pub gas_limit: String,
    pub fee: EvmFeeReview,
    pub payload_keccak: String,
    /// Decimal length of the transaction input bytes (calldata, or initcode
    /// for creation). Present so the owner can tell a plain transfer from a
    /// contract call: execution effects remain unverified either way.
    pub calldata_bytes: String,
    /// Keccak-256 of the transaction input bytes, present only when the input
    /// is non-empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calldata_keccak: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvmFeeReview {
    Legacy {
        gas_price: String,
        gas_price_display: String,
    },
    Eip1559 {
        max_fee_per_gas: String,
        max_fee_per_gas_display: String,
        max_priority_fee_per_gas: String,
        max_priority_fee_per_gas_display: String,
    },
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::SelectorMismatch, message)
}

fn malformed(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, message)
}

/// Whether this approval subject is a native exact EVM transaction class
/// whose owner review is the Broker-decoded signing preimage.
///
/// This list is mirrored as `native_evm_review` in Bloom's machine client:
/// drift means Machine sends payloads Broker will not require, or vice
/// versa. Keep the two in step; the coupling is a shared constant, not a
/// shared crate, because nothing else crosses the service boundary here.
pub(crate) fn subject_is_native_evm_transaction(subject: &ApprovalSubject) -> bool {
    match subject {
        ApprovalSubject::Cli { command_class, .. } => matches!(
            command_class.as_str(),
            "transaction.confirm" | "transaction.replace" | "transaction.cancel"
        ),
        ApprovalSubject::System {
            operation_class, ..
        } => matches!(
            operation_class.as_str(),
            "transaction.confirm" | "transaction.replace" | "transaction.cancel"
        ),
        _ => false,
    }
}

pub(crate) fn review(
    request: &ApprovalPrepareRequest,
    policy: &CanonicalWalletPolicy,
    from: Address,
) -> Result<Option<EvmReview>, ProtocolError> {
    if request.evm_review_payloads.is_empty() {
        // No payloads means no review: returning None (rather than an empty
        // review) keeps the opaque-digest disclosure in place instead of
        // suppressing it while showing nothing.
        return Ok(None);
    }
    if request.petal_use_claim.is_some() {
        // Only a system claim is cross-checked against the decoded bytes
        // (compare_claim below). A Petal claim would otherwise render under
        // the verified framing with nothing comparing it to the transaction,
        // so refuse it at the boundary instead of displaying it as verified.
        // Malformed, like the adjacent both-claims rejection: the request
        // shape itself is invalid, not the payloads.
        return Err(malformed(
            "EVM review payloads cannot carry a Petal claim; use a system claim",
        ));
    }
    if !subject_is_native_evm_transaction(&request.terms.subject) {
        // The service gate refuses native subjects without payloads; this is
        // the mirror: payloads on any other subject (Petal, VFS, ...) would
        // render EVM facts while hiding the subject class they ride on.
        return Err(malformed(
            "EVM review payloads require a native transaction subject",
        ));
    }
    if request.system_use_claim.is_some() && request.evm_review_payloads.len() != 1 {
        return Err(invalid(
            "an EVM system claim is ambiguous for multiple review payloads",
        ));
    }
    let ApprovalSelector::Exact {
        ordered_payload_digests,
        ordered_hashes,
    } = &request.terms.selector
    else {
        return Err(invalid("EVM review requires an exact selector"));
    };
    // One exact approval covers a whole transaction batch; the cap matches
    // Machine's documented batch maximum (32 children) so no approvable batch
    // is rejected here.
    if request.terms.allowed_crypto_suites != [CryptoSuite::Secp256k1Keccak256Recoverable]
        || request.evm_review_payloads.len() != ordered_payload_digests.len()
        || ordered_hashes.len() != ordered_payload_digests.len()
        || request.evm_review_payloads.len() > 32
    {
        return Err(invalid(
            "EVM review payload count or cryptographic suite mismatch",
        ));
    }
    let payloads = request
        .evm_review_payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            let bytes = payload.decode();
            if bytes.len() > 128 * 1024
                || Digest32::from_bytes(Sha256::digest(&bytes).into())
                    != ordered_payload_digests[index]
                || Digest32::from_bytes(keccak256(&bytes).0) != ordered_hashes[index]
            {
                return Err(invalid(
                    "EVM review payload differs from the approved selector",
                ));
            }
            let reviewed = if bytes.first() == Some(&2) {
                let mut input = &bytes[1..];
                let tx = TxEip1559::decode(&mut input)
                    .map_err(|_| invalid("invalid EIP-1559 signing preimage"))?;
                if !input.is_empty() || !tx.access_list.0.is_empty() {
                    return Err(invalid("unsupported EVM review encoding or access list"));
                }
                render_eip1559(&tx, &bytes, policy, from, request.system_use_claim.as_ref())?
            } else {
                // Any other EIP-2718 type byte (0x00..=0x7f) is a typed
                // envelope, not a legacy RLP list: name it instead of failing
                // with a misleading decode error.
                if matches!(bytes.first(), Some(b) if *b < 0x80) {
                    return Err(invalid(format!(
                        "unsupported EVM transaction type {:#04x}; only legacy and EIP-1559 preimages review",
                        bytes[0],
                    )));
                }
                let mut input = bytes.as_slice();
                let tx = TxLegacy::decode(&mut input)
                    .map_err(|_| invalid("invalid legacy signing preimage"))?;
                if !input.is_empty() {
                    return Err(invalid("trailing EVM signing preimage bytes"));
                }
                render_legacy(&tx, &bytes, policy, from, request.system_use_claim.as_ref())?
            };
            Ok(reviewed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(EvmReview { payloads }))
}

fn render_eip1559(
    tx: &TxEip1559,
    bytes: &[u8],
    policy: &CanonicalWalletPolicy,
    from: Address,
    claim: Option<&SystemUseClaim>,
) -> Result<EvmReviewPayload, ProtocolError> {
    let fee = EvmFeeReview::Eip1559 {
        max_fee_per_gas: tx.max_fee_per_gas.to_string(),
        max_fee_per_gas_display: format_gwei(tx.max_fee_per_gas),
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas.to_string(),
        max_priority_fee_per_gas_display: format_gwei(tx.max_priority_fee_per_gas),
    };
    render(tx, bytes, policy, from, claim, fee)
}

fn render_legacy(
    tx: &TxLegacy,
    bytes: &[u8],
    policy: &CanonicalWalletPolicy,
    from: Address,
    claim: Option<&SystemUseClaim>,
) -> Result<EvmReviewPayload, ProtocolError> {
    let fee = EvmFeeReview::Legacy {
        gas_price: tx.gas_price.to_string(),
        gas_price_display: format_gwei(tx.gas_price),
    };
    render(tx, bytes, policy, from, claim, fee)
}

fn render<T: Transaction + SignableTransaction<Signature>>(
    tx: &T,
    bytes: &[u8],
    policy: &CanonicalWalletPolicy,
    from: Address,
    claim: Option<&SystemUseClaim>,
    fee: EvmFeeReview,
) -> Result<EvmReviewPayload, ProtocolError> {
    if tx.encoded_for_signing() != bytes {
        return Err(invalid(
            "noncanonical or signed EVM payload cannot be reviewed as an unsigned transaction",
        ));
    }
    let chain = tx
        .chain_id()
        .filter(|id| *id != 0)
        .ok_or_else(|| invalid("EVM approval requires a replay-protected chain ID"))?;
    let chain_policy = format!("evm-{chain}");
    let chain_name = chain_name(chain);
    let destination = match tx.kind() {
        TxKind::Call(to) => Some(to.to_string()),
        TxKind::Create => None,
    };
    // Creation has no destination in the existing policy model and needs an
    // explicit numeric-chain opt-in. Ordinary call policy enforcement retains
    // the existing authority path and Machine's chain-scoped advisory checks.
    if tx.kind() == TxKind::Create
        && !policy
            .allowed_destinations
            .iter()
            .any(|d| d.chain.as_str() == chain_policy && d.destination == "exact")
    {
        return Err(invalid(format!(
            "wallet policy must allow destination exact on {chain_policy} for contract creation"
        )));
    }
    if let Some(claim) = claim {
        compare_claim(claim, chain_name.as_str(), tx.kind(), tx.value())?;
    }
    let input = tx.input();
    if tx.kind() == TxKind::Create && input.is_empty() {
        return Err(invalid("creation requires initcode"));
    }
    let value = tx.value().to_string();
    Ok(EvmReviewPayload {
        chain_id: chain.to_string(),
        chain: chain_name.clone(),
        sender: from.to_string(),
        destination,
        value_display: native_value_display(&value, &chain_name),
        value,
        nonce: tx.nonce().to_string(),
        gas_limit: tx.gas_limit().to_string(),
        fee,
        payload_keccak: format!("{:#x}", keccak256(bytes)),
        calldata_bytes: input.len().to_string(),
        calldata_keccak: (!input.is_empty()).then(|| format!("{:#x}", keccak256(input))),
    })
}

pub(crate) fn chain_name(chain_id: u64) -> String {
    match chain_id {
        1 => "ethereum".into(),
        10 => "optimism".into(),
        137 => "polygon".into(),
        8453 => "base".into(),
        31337 => "anvil".into(),
        42161 => "arbitrum".into(),
        id => format!("evm-{id}"),
    }
}

fn native_value_display(value: &str, chain: &str) -> String {
    // Decimals and symbols come from the shared asset table so the EVM
    // review can never disagree with the claim amount display.
    match crate::ceremony::native_asset_metadata(chain, "native") {
        Some((decimals, symbol)) => format!(
            "{} {symbol}",
            crate::ceremony::format_base_units(value, usize::from(decimals))
        ),
        None => format!("{value} raw native units on {chain} (token decimals unknown)"),
    }
}

fn format_gwei(value: u128) -> String {
    format!(
        "{} Gwei",
        crate::ceremony::format_base_units(&value.to_string(), 9)
    )
}

fn compare_claim(
    claim: &SystemUseClaim,
    chain: &str,
    kind: TxKind,
    value: alloy::primitives::U256,
) -> Result<(), ProtocolError> {
    let [destination] = claim.declared_destinations.as_slice() else {
        return Err(invalid(
            "an EVM system claim must declare exactly one destination",
        ));
    };
    let [debit] = claim.declared_debits.as_slice() else {
        return Err(invalid(
            "an EVM system claim must declare exactly one native debit",
        ));
    };
    let TxKind::Call(decoded_destination) = kind else {
        return Err(invalid(
            "an EVM contract creation cannot carry a system claim",
        ));
    };
    let claimed_destination = destination
        .destination
        .parse::<Address>()
        .map_err(|_| invalid("EVM system claim destination is not an address"))?;
    // One error per field so a mismatch tells Machine which fact diverged.
    // The decoded chain here is the canonical alias (anvil, base, ...), not
    // the numeric creation scope (evm-31337): a mismatch usually means
    // Machine supplied one where the other belongs.
    if destination.chain.as_str() != chain {
        return Err(invalid(format!(
            "EVM system claim destination chain does not match the decoded chain alias: {chain}",
        )));
    }
    if debit.asset.chain.as_str() != chain {
        return Err(invalid(format!(
            "EVM system claim debit chain does not match the decoded chain alias: {chain}",
        )));
    }
    if debit.asset.asset != "native" {
        return Err(invalid("EVM system claim debit must be the native asset"));
    }
    if claimed_destination != decoded_destination {
        return Err(invalid(
            "EVM system claim destination does not match the decoded recipient",
        ));
    }
    if debit.amount.as_str() != value.to_string() {
        return Err(invalid(
            "EVM system claim amount does not match the decoded native value",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::*;
    fn request(bytes: &[u8]) -> ApprovalPrepareRequest {
        let token = |s: &str| Token::new(s).unwrap();
        let digest = Digest32::from_bytes([1; 32]);
        ApprovalPrepareRequest {
            operation_id: OperationId::from_bytes([2; 32]),
            canonical_plan_facts_digest: digest.clone(),
            evm_review_payloads: vec![Base64UrlBytes::from_bytes(bytes)],
            petal_use_claim: None,
            system_use_claim: None,
            terms: SealedApprovalTerms {
                subject: ApprovalSubject::Cli {
                    client_id: token("machine"),
                    command_class: token("transaction.confirm"),
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
                        Sha256::digest(bytes).into(),
                    )],
                    ordered_hashes: vec![Digest32::from_bytes(keccak256(bytes).0)],
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
                issued_at_ms: DecimalU64::new(10),
                not_before_ms: DecimalU64::new(10),
                expires_at_ms: DecimalU64::new(20),
                renewal_of: None,
            },
        }
    }
    fn policy() -> CanonicalWalletPolicy {
        CanonicalWalletPolicy {
            wallet_id: Token::new("alice").unwrap(),
            maximum_approval_lifetime_ms: 60000,
            allowed_petal_packages: vec![],
            allowed_destinations: vec![PolicyDestination {
                chain: Token::new("evm-31337").unwrap(),
                destination: "exact".into(),
            }],
            required_verifiers: vec![],
        }
    }
    fn system_claim(destination: Address, value: u64) -> SystemUseClaim {
        SystemUseClaim {
            component_id: Token::new("machine").unwrap(),
            action_class: Token::new("transaction.confirm").unwrap(),
            operation_class: Token::new("transaction.confirm").unwrap(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: Digest32::from_bytes([4; 32]),
            ordered_hashes: vec![Digest32::from_bytes([5; 32])],
            declared_debits: vec![DeclaredDebit {
                asset: AssetId {
                    chain: Token::new("anvil").unwrap(),
                    asset: "native".into(),
                },
                amount: DecimalU256::parse(value.to_string()).unwrap(),
            }],
            declared_destinations: vec![DeclaredDestination {
                chain: Token::new("anvil").unwrap(),
                destination: destination.to_string(),
            }],
            declared_fee: DeclaredFee::None,
            nonce: RequestNonce::from_bytes([6; 16]),
            chain_context: SystemChainContext {
                chain_family: Token::new("ethereum").unwrap(),
                genesis_hash: "not-expressible-for-evm".into(),
                recent_blockhash: "not-expressible-for-evm".into(),
                last_valid_block_height: DecimalU64::new(0),
            },
            claim_assurance: ClaimAssurance::MachineAsserted,
        }
    }
    fn review_ok(req: &ApprovalPrepareRequest) -> EvmReview {
        review(req, &policy(), Address::ZERO)
            .unwrap()
            .expect("review with payloads yields a review")
    }
    #[test]
    fn verifies_both_preimages_and_renders_creation_without_claiming_ownership() {
        let modern = TxEip1559 {
            chain_id: 31337,
            nonce: 3,
            gas_limit: 100000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            to: TxKind::Create,
            value: alloy::primitives::U256::from(123),
            input: vec![0x60, 0, 0x60, 0, 0xf3].into(),
            access_list: Default::default(),
        };
        let legacy = TxLegacy {
            chain_id: Some(31337),
            nonce: 3,
            gas_limit: 100000,
            gas_price: 10,
            to: modern.to,
            value: modern.value,
            input: modern.input.clone(),
        };
        let modern_review = review_ok(&request(&modern.encoded_for_signing()));
        assert!(matches!(
            &modern_review.payloads[0].fee,
            EvmFeeReview::Eip1559 {
                max_fee_per_gas_display,
                max_priority_fee_per_gas_display,
                ..
            } if max_fee_per_gas_display == "0.00000001 Gwei"
                && max_priority_fee_per_gas_display == "0.000000001 Gwei"
        ));
        for bytes in [modern.encoded_for_signing(), legacy.encoded_for_signing()] {
            let req = request(&bytes);
            let plan = review_ok(&req);
            let reviewed = &plan.payloads[0];
            assert_eq!(reviewed.destination, None);
            assert_eq!(reviewed.value, "123");
            assert_eq!(reviewed.value_display, "0.000000000000000123 ETH");
            // Initcode is disclosed by size and commitment, not hidden: the
            // owner sees this creation carries 5 bytes of initcode.
            assert_eq!(reviewed.calldata_bytes, "5");
            let initcode_keccak = reviewed
                .calldata_keccak
                .as_deref()
                .expect("initcode keccak");
            assert_eq!(initcode_keccak.len(), 66);
            assert_eq!(
                initcode_keccak,
                format!("{:#x}", keccak256([0x60, 0, 0x60, 0, 0xf3])).as_str()
            );
            assert_eq!(reviewed.chain_id, "31337");
            assert_eq!(reviewed.chain, "anvil");
            assert_eq!(reviewed.nonce, "3");
            let mut altered = req.clone();
            altered.evm_review_payloads[0] = Base64UrlBytes::from_bytes(&[0]);
            assert!(review(&altered, &policy(), Address::ZERO).is_err());
            let mut denied = policy();
            denied.allowed_destinations.clear();
            assert!(review(&req, &denied, Address::ZERO).is_err());
            let mut wrong_chain = policy();
            wrong_chain.allowed_destinations[0].chain = Token::new("evm-1").unwrap();
            assert!(review(&req, &wrong_chain, Address::ZERO).is_err());
            let mut trailing = bytes;
            trailing.push(0);
            assert!(review(&request(&trailing), &policy(), Address::ZERO).is_err());
        }
        let mut call = modern;
        call.to = TxKind::Call(Address::ZERO);
        let plan = review_ok(&request(&call.encoded_for_signing()));
        assert_eq!(
            plan.payloads[0].destination,
            Some(Address::ZERO.to_string())
        );
    }

    #[test]
    fn reviews_a_full_maximum_batch_and_rejects_more() {
        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::ZERO,
            input: Vec::new().into(),
            access_list: Default::default(),
        };
        let payload = tx.encoded_for_signing();
        for count in [32usize, 33] {
            let mut req = request(&payload);
            req.evm_review_payloads = vec![Base64UrlBytes::from_bytes(&payload); count];
            let ApprovalSelector::Exact {
                ordered_payload_digests,
                ordered_hashes,
            } = &mut req.terms.selector
            else {
                unreachable!()
            };
            *ordered_payload_digests = req
                .evm_review_payloads
                .iter()
                .map(|p| Digest32::from_bytes(Sha256::digest(p.decode()).into()))
                .collect();
            *ordered_hashes = req
                .evm_review_payloads
                .iter()
                .map(|p| Digest32::from_bytes(keccak256(p.decode()).0))
                .collect();
            assert_eq!(
                review(&req, &policy(), Address::ZERO).is_ok(),
                count <= 32,
                "{count}"
            );
        }
    }

    #[test]
    fn compares_only_an_unambiguous_single_evm_claim() {
        let destination = Address::repeat_byte(7);
        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1_500_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(destination),
            value: alloy::primitives::U256::from(300_000_u64),
            input: Vec::new().into(),
            access_list: Default::default(),
        };
        let mut req = request(&tx.encoded_for_signing());
        req.system_use_claim = Some(system_claim(destination, 300_000));
        let reviewed = review_ok(&req);
        assert_eq!(reviewed.payloads[0].value, "300000");

        req.system_use_claim.as_mut().unwrap().declared_destinations[0].destination =
            Address::repeat_byte(8).to_string();
        assert_eq!(
            review(&req, &policy(), Address::ZERO).unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );
    }

    #[test]
    fn rejects_a_multi_payload_evm_claim_as_ambiguous() {
        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::ZERO,
            input: Vec::new().into(),
            access_list: Default::default(),
        };
        let payload = tx.encoded_for_signing();
        let mut req = request(&payload);
        req.evm_review_payloads
            .push(Base64UrlBytes::from_bytes(&payload));
        let ApprovalSelector::Exact {
            ordered_payload_digests,
            ordered_hashes,
        } = &mut req.terms.selector
        else {
            unreachable!()
        };
        ordered_payload_digests.push(ordered_payload_digests[0].clone());
        ordered_hashes.push(ordered_hashes[0].clone());
        req.system_use_claim = Some(system_claim(Address::ZERO, 0));
        let error = review(&req, &policy(), Address::ZERO).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);
        assert!(error.message.contains("ambiguous"));
    }

    #[test]
    fn formats_known_and_unknown_chains_without_inventing_unknown_units() {
        let legacy = TxLegacy {
            chain_id: Some(8453),
            nonce: 7,
            gas_limit: 21000,
            gas_price: 1_500_000_000,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::from(300_000_000_000_000_u64),
            input: Vec::new().into(),
        };
        let known = review_ok(&request(&legacy.encoded_for_signing()));
        assert_eq!(known.payloads[0].chain, "base");
        assert_eq!(known.payloads[0].value_display, "0.0003 ETH");
        // A plain transfer carries no input: the page must say so.
        assert_eq!(known.payloads[0].calldata_bytes, "0");
        assert_eq!(known.payloads[0].calldata_keccak, None);
        assert!(matches!(
            &known.payloads[0].fee,
            EvmFeeReview::Legacy { gas_price_display, .. } if gas_price_display == "1.5 Gwei"
        ));

        let mut unknown = legacy;
        unknown.chain_id = Some(999_999);
        let unknown = review_ok(&request(&unknown.encoded_for_signing()));
        assert_eq!(unknown.payloads[0].chain, "evm-999999");
        assert_eq!(
            unknown.payloads[0].value_display,
            "300000000000000 raw native units on evm-999999 (token decimals unknown)"
        );
    }

    /// Minimal hand-rolled RLP for crafting adversarial encodings the
    /// canonical encoder would never emit.
    mod hostile_rlp {
        pub fn bytes(data: &[u8]) -> Vec<u8> {
            if data.len() == 1 && data[0] < 0x80 {
                return vec![data[0]];
            }
            let mut out = len_prefix(data.len(), 0x80);
            out.extend_from_slice(data);
            out
        }
        pub fn uint_trimmed(big_endian: &[u8]) -> Vec<u8> {
            let mut start = 0;
            while start < big_endian.len() && big_endian[start] == 0 {
                start += 1;
            }
            bytes(&big_endian[start..])
        }
        pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
            let payload = items.concat();
            let mut out = len_prefix(payload.len(), 0xc0);
            out.extend(payload);
            out
        }
        fn len_prefix(len: usize, offset: u8) -> Vec<u8> {
            if len < 56 {
                return vec![offset + len as u8];
            }
            let mut be = (len as u64).to_be_bytes().to_vec();
            while be.len() > 1 && be[0] == 0 {
                be.remove(0);
            }
            let mut out = vec![offset + 55 + be.len() as u8];
            out.extend(be);
            out
        }
    }

    #[test]
    fn rejects_a_signed_legacy_preimage_that_still_decodes() {
        use alloy::primitives::U256;
        let chain_id = 31337u64;
        let unsigned = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 3,
            gas_limit: 21000,
            gas_price: 10,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Vec::new().into(),
        };
        // A real secp256k1 signature over the signing hash, so the bytes are
        // a genuinely signed transaction rather than random trailing data.
        let sighash = keccak256(unsigned.encoded_for_signing());
        let secret = k256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let (signature, recovery_id) = secret.sign_prehash_recoverable(sighash.as_slice()).unwrap();
        let compact = signature.to_bytes();
        let r = U256::from_be_slice(&compact[..32]);
        let s = U256::from_be_slice(&compact[32..]);
        let v = recovery_id.to_byte() as u64 + chain_id * 2 + 35;
        let signed = hostile_rlp::list(&[
            hostile_rlp::uint_trimmed(&3u64.to_be_bytes()),
            hostile_rlp::uint_trimmed(&10u128.to_be_bytes()),
            hostile_rlp::uint_trimmed(&21000u64.to_be_bytes()),
            hostile_rlp::bytes(Address::ZERO.as_slice()),
            hostile_rlp::uint_trimmed(&U256::ZERO.to_be_bytes::<32>()),
            hostile_rlp::bytes(&[]),
            hostile_rlp::uint_trimmed(&v.to_be_bytes()),
            hostile_rlp::uint_trimmed(&r.to_be_bytes::<32>()),
            hostile_rlp::uint_trimmed(&s.to_be_bytes::<32>()),
        ]);
        // The decoder tolerates it (v folds into a chain id, r/s are
        // discarded) — the canonicality fence must still refuse it, because
        // re-encoding yields the unsigned preimage, not these bytes.
        let mut slice = signed.as_slice();
        TxLegacy::decode(&mut slice).expect("signed bytes still decode");
        assert!(slice.is_empty());
        let error = review(&request(&signed), &policy(), Address::ZERO).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);
        assert!(
            error.message.contains("noncanonical or signed"),
            "{error:?}"
        );
    }

    #[test]
    fn rejects_noncanonical_rlp_forms_of_a_valid_transaction() {
        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 3,
            gas_limit: 21000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::ZERO,
            input: Vec::new().into(),
            access_list: Default::default(),
        };
        let canonical = tx.encoded_for_signing();
        assert!(
            review(&request(&canonical), &policy(), Address::ZERO)
                .unwrap()
                .is_some()
        );
        // Layout: 0x02, short list prefix (33-byte payload), chain_id
        // (0x82 0x7a69), then nonce 0x03 at index 5.
        assert_eq!(&canonical[..6], &[0x02, 0xe1, 0x82, 0x7a, 0x69, 0x03]);

        // Non-minimal integer: nonce 3 as 0x81 0x03, growing the list by one.
        // alloy's decoder rejects this itself (NonCanonicalSingleByte); the
        // review must refuse it regardless of which layer fires first.
        let mut padded = canonical.clone();
        padded[1] += 1;
        padded.splice(5..6, [0x81, 0x03]);
        let error = review(&request(&padded), &policy(), Address::ZERO).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);

        // Non-minimal list header: short length rewritten in long form with a
        // leading zero length byte (likewise NonCanonicalSize at decode).
        let len = canonical[1] - 0xc0;
        let mut relisted = vec![0x02, 0xf9, 0x00, len];
        relisted.extend_from_slice(&canonical[2..]);
        let error = review(&request(&relisted), &policy(), Address::ZERO).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);
    }

    #[test]
    fn rejects_typed_envelopes_outside_eip1559() {
        let legacy = TxLegacy {
            chain_id: Some(31337),
            nonce: 3,
            gas_limit: 21000,
            gas_price: 10,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::ZERO,
            input: Vec::new().into(),
        };
        let preimage = legacy.encoded_for_signing();
        for envelope in [0x00u8, 0x01, 0x03, 0x04, 0x05, 0x7f] {
            let mut typed = vec![envelope];
            typed.extend_from_slice(&preimage);
            let error = review(&request(&typed), &policy(), Address::ZERO).unwrap_err();
            assert_eq!(
                error.code,
                ProtocolErrorCode::SelectorMismatch,
                "{envelope:#x}"
            );
            assert!(
                error.message.contains("unsupported EVM transaction type"),
                "{envelope:#x}: {error:?}"
            );
        }
    }

    #[test]
    fn refuses_a_petal_claim_alongside_evm_payloads() {
        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::ZERO,
            input: Vec::new().into(),
            access_list: Default::default(),
        };
        let mut req = request(&tx.encoded_for_signing());
        req.petal_use_claim = Some(PetalUseClaim {
            package_hash: Digest32::from_bytes([9; 32]),
            route: "orders/place".into(),
            operation_class: Token::new("transaction.confirm").unwrap(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: Digest32::from_bytes([10; 32]),
            ordered_hashes: vec![],
            declared_debits: vec![],
            declared_destinations: vec![],
            declared_fee: DeclaredFee::None,
            nonce: RequestNonce::from_bytes([11; 16]),
            claim_assurance: ClaimAssurance::MachineAsserted,
        });
        // Nothing compares a Petal claim to the decoded bytes, so carrying
        // one must fail rather than render under the verified framing.
        let error = review(&req, &policy(), Address::ZERO).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::MalformedFrame);
        assert!(error.message.contains("Petal"), "{error:?}");
    }

    #[test]
    fn payloads_on_a_non_native_subject_are_refused() {
        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::ZERO,
            input: Vec::new().into(),
            access_list: Default::default(),
        };
        let bytes = tx.encoded_for_signing();
        // Payloads on a Petal subject would render EVM facts while hiding
        // the subject class they ride on; the same holds for any non-native
        // command class.
        for subject in [
            ApprovalSubject::Petal {
                package_hash: Digest32::from_bytes([12; 32]),
                route: "orders/place".into(),
                agent_id: None,
            },
            ApprovalSubject::Cli {
                client_id: Token::new("machine").unwrap(),
                command_class: Token::new("vfs.test").unwrap(),
            },
        ] {
            let mut req = request(&bytes);
            req.terms.subject = subject;
            let error = review(&req, &policy(), Address::ZERO).unwrap_err();
            assert_eq!(error.code, ProtocolErrorCode::MalformedFrame);
            assert!(
                error.message.contains("native transaction subject"),
                "{error:?}"
            );
        }
    }

    #[test]
    fn empty_payloads_yield_no_review_so_the_digest_disclosure_stays() {
        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::ZERO,
            input: Vec::new().into(),
            access_list: Default::default(),
        };
        let mut req = request(&tx.encoded_for_signing());
        req.evm_review_payloads.clear();
        assert!(review(&req, &policy(), Address::ZERO).unwrap().is_none());
    }

    #[test]
    fn populated_evm_review_freezes_its_wire_shape() {
        let tx = TxEip1559 {
            chain_id: 31337,
            nonce: 3,
            gas_limit: 100000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            to: TxKind::Create,
            value: alloy::primitives::U256::from(123),
            input: vec![0x60, 0, 0x60, 0, 0xf3].into(),
            access_list: Default::default(),
        };
        let bytes = tx.encoded_for_signing();
        let payload = &review_ok(&request(&bytes)).payloads[0];
        let expected = format!(
            "{{\
            \"calldata_bytes\":\"5\",\
            \"calldata_keccak\":\"{:#x}\",\
            \"chain\":\"anvil\",\
            \"chain_id\":\"31337\",\
            \"destination\":null,\
            \"fee\":{{\"kind\":\"eip1559\",\"max_fee_per_gas\":\"10\",\
            \"max_fee_per_gas_display\":\"0.00000001 Gwei\",\
            \"max_priority_fee_per_gas\":\"1\",\
            \"max_priority_fee_per_gas_display\":\"0.000000001 Gwei\"}},\
            \"gas_limit\":\"100000\",\"nonce\":\"3\",\
            \"payload_keccak\":\"{:#x}\",\
            \"sender\":\"0x0000000000000000000000000000000000000000\",\
            \"value\":\"123\",\
            \"value_display\":\"0.000000000000000123 ETH\"}}",
            keccak256([0x60, 0, 0x60, 0, 0xf3]),
            keccak256(&bytes),
        );
        assert_eq!(serde_jcs::to_string(payload).unwrap(), expected);
    }
}
