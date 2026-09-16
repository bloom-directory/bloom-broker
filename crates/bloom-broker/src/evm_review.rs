//! Independently decode native EVM preimages for exact owner review. Machine
//! descriptions are never used to infer transaction destination or authority.
use alloy::{
    consensus::{SignableTransaction, Transaction, TxEip1559, TxLegacy},
    primitives::{Address, Signature, TxKind, keccak256},
    rlp::Decodable,
};
use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalSelector, CanonicalWalletPolicy, CryptoSuite, Digest32,
    ProtocolError, ProtocolErrorCode, SystemUseClaim,
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

pub(crate) fn review(
    request: &ApprovalPrepareRequest,
    policy: &CanonicalWalletPolicy,
    from: Address,
) -> Result<EvmReview, ProtocolError> {
    if request.evm_review_payloads.is_empty() {
        return Ok(EvmReview {
            payloads: Vec::new(),
        });
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
    Ok(EvmReview { payloads })
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
    if tx.kind() == TxKind::Create && tx.input().is_empty() {
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
    match chain {
        "ethereum" | "optimism" | "base" | "arbitrum" | "anvil" => {
            format!("{} ETH", format_base_units(value, 18))
        }
        "polygon" => format!("{} POL", format_base_units(value, 18)),
        _ => format!("{value} raw native units on {chain} (token decimals unknown)"),
    }
}

fn format_gwei(value: u128) -> String {
    format!("{} Gwei", format_base_units(&value.to_string(), 9))
}

fn format_base_units(base_units: &str, decimals: usize) -> String {
    let padded = format!("{:0>width$}", base_units, width = decimals + 1);
    let split = padded.len() - decimals;
    let fractional = padded[split..].trim_end_matches('0');
    if fractional.is_empty() {
        padded[..split].to_owned()
    } else {
        format!("{}.{}", &padded[..split], fractional)
    }
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
    if destination.chain.as_str() != chain
        || debit.asset.chain.as_str() != chain
        || debit.asset.asset != "native"
        || claimed_destination != decoded_destination
        || debit.amount.as_str() != value.to_string()
    {
        return Err(invalid(
            "EVM system claim does not match the decoded destination, native value, or chain",
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
        let modern_review = review(
            &request(&modern.encoded_for_signing()),
            &policy(),
            Address::ZERO,
        )
        .unwrap();
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
            let plan = review(&req, &policy(), Address::ZERO).unwrap();
            let reviewed = &plan.payloads[0];
            assert_eq!(reviewed.destination, None);
            assert_eq!(reviewed.value, "123");
            assert_eq!(reviewed.value_display, "0.000000000000000123 ETH");
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
        let plan = review(
            &request(&call.encoded_for_signing()),
            &policy(),
            Address::ZERO,
        )
        .unwrap();
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
        let reviewed = review(&req, &policy(), Address::ZERO).unwrap();
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
        let known = review(
            &request(&legacy.encoded_for_signing()),
            &policy(),
            Address::ZERO,
        )
        .unwrap();
        assert_eq!(known.payloads[0].chain, "base");
        assert_eq!(known.payloads[0].value_display, "0.0003 ETH");
        assert!(matches!(
            &known.payloads[0].fee,
            EvmFeeReview::Legacy { gas_price_display, .. } if gas_price_display == "1.5 Gwei"
        ));

        let mut unknown = legacy;
        unknown.chain_id = Some(999_999);
        let unknown = review(
            &request(&unknown.encoded_for_signing()),
            &policy(),
            Address::ZERO,
        )
        .unwrap();
        assert_eq!(unknown.payloads[0].chain, "evm-999999");
        assert_eq!(
            unknown.payloads[0].value_display,
            "300000000000000 raw native units on evm-999999 (token decimals unknown)"
        );
    }
}
