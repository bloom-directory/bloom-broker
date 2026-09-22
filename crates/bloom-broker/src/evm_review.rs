//! Independently decode native EVM preimages for exact owner review. Machine
//! descriptions are never used to infer transaction destination or authority.
use crate::journal::ReviewKind;
use alloy::{
    consensus::{SignableTransaction, Transaction, TxEip1559, TxLegacy},
    primitives::{Address, Signature, TxKind, keccak256},
    rlp::Decodable,
};
use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalSelector, ApprovalSubject, CanonicalWalletPolicy, CryptoSuite,
    Digest32, ProtocolError, ProtocolErrorCode, ReviewMode, SigningPayloads,
};
use bloom_evm_clear_signing::{
    AcceptedCatalog, CallContext, ClearSignedCall, ClearSigningEvidence, NativeUnits, ReviewError,
    ReviewReason, SelectedEntry, review_call,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvmReview {
    pub payloads: Vec<EvmReviewPayload>,
    /// Review-wide clear-signing facts: the catalog this reading came from,
    /// the verifier that produced it, and every entry it used. Activation and
    /// signing re-read these against the current catalog and policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_signing: Option<ClearSigningEvidence>,
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
    /// The most this transaction can pay for *execution gas*: `gas_limit`
    /// times the envelope's price ceiling, in the chain's authenticated
    /// native units. It is a ceiling on that charge and nothing else — a
    /// chain that bills separately, for data availability or anything the
    /// envelope does not price, is not covered. Absent rather than guessed
    /// when the chain's units are unknown; the page then says the fee cannot
    /// be shown rather than omitting the subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_execution_gas_fee_display: Option<String>,
    /// The clear-signed reading of this call, when a signed description
    /// covered it. Absent for native sends, deployments, and every member of
    /// an explicitly opaque batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_call: Option<ClearSignedCall>,
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

/// What the wallet's authenticated policy and Broker's accepted catalog say
/// about clear signing, resolved once per preparation.
pub(crate) struct ClearSigningContext {
    pub catalog: Option<AcceptedCatalog>,
    pub verifier_digest: Digest32,
    pub now_ms: u64,
}

/// Which review Broker produced, to be frozen with the approval record.
///
/// Read from Broker's own rendered review and the policy it reviewed
/// against — never from the mode the caller requested, which is a request
/// and not a result.
pub(crate) fn review_kind(
    review: Option<&EvmReview>,
    policy: &CanonicalWalletPolicy,
) -> ReviewKind {
    let Some(review) = review else {
        return ReviewKind::Legacy;
    };
    if policy.clear_signing.is_none() {
        return ReviewKind::Legacy;
    }
    if review.clear_signing.is_some() {
        return ReviewKind::Clear;
    }
    // A call with a destination and calldata that carries no reading is one
    // the owner approved opaquely: a batch that could not be read under the
    // clear mode fails preparation instead of reaching here.
    let opaque = review.payloads.iter().any(|payload| {
        payload.destination.is_some()
            && payload.calldata_keccak.is_some()
            && payload.contract_call.is_none()
    });
    if opaque {
        ReviewKind::OpaqueExact
    } else {
        ReviewKind::Native
    }
}

/// Carry the nine review reasons out on the existing transport codes rather
/// than inventing a tenth: the reason and its owner sentence travel in the
/// message, which is what the ceremony and the CLI both show.
fn review_error(error: ReviewError) -> ProtocolError {
    let code = match error.reason {
        ReviewReason::InvalidPayload => ProtocolErrorCode::SelectorMismatch,
        ReviewReason::LimitExceeded => ProtocolErrorCode::LimitExceededFrame,
        ReviewReason::ClockUntrusted => ProtocolErrorCode::ClockUntrusted,
        ReviewReason::CatalogUnavailable
        | ReviewReason::EvidenceExpired
        | ReviewReason::UnsupportedCall => ProtocolErrorCode::AssuranceUnavailable,
        ReviewReason::CatalogRejected
        | ReviewReason::PolicyDenied
        | ReviewReason::ReviewChanged => ProtocolErrorCode::ClaimInvalid,
    };
    ProtocolError::new(code, error.to_string())
}

fn denied(reason: ReviewReason, message: impl Into<String>) -> ProtocolError {
    review_error(ReviewError::new(reason, message))
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
    clear_signing: &ClearSigningContext,
) -> Result<Option<EvmReview>, ProtocolError> {
    if request.evm_review_payloads.is_empty() {
        // No payloads means no review: returning None (rather than an empty
        // review) keeps the opaque-digest disclosure in place instead of
        // suppressing it while showing nothing.
        return Ok(None);
    }
    if request.petal_use_claim.is_some() || request.system_use_claim.is_some() {
        // A claim would render beside the decoded facts with nothing
        // comparing the two, and authorization accepts system claims only for
        // Solana, so an EVM approval carrying one could never sign.
        return Err(malformed("EVM review payloads cannot carry a claim"));
    }
    if !subject_is_native_evm_transaction(&request.terms.subject) {
        // The service gate refuses native subjects without payloads; this is
        // the mirror: payloads on any other subject (Petal, VFS, ...) would
        // render EVM facts while hiding the subject class they ride on.
        return Err(malformed(
            "EVM review payloads require a native transaction subject",
        ));
    }
    let ApprovalSelector::Exact {
        ordered_payload_digests,
        ordered_hashes,
    } = &request.terms.selector
    else {
        return Err(invalid("EVM review requires an exact selector"));
    };
    if request.terms.allowed_crypto_suites != [CryptoSuite::Secp256k1Keccak256Recoverable]
        || request.evm_review_payloads.len() != ordered_payload_digests.len()
        || ordered_hashes.len() != ordered_payload_digests.len()
    {
        return Err(invalid(
            "EVM review payload count or cryptographic suite mismatch",
        ));
    }
    // Refuse before the owner is asked what signing would refuse anyway. One
    // payload is checked as a single signing payload; Machine applies the
    // stricter batch limits to a one-child batch before it prepares.
    match request.evm_review_payloads.as_slice() {
        [payload] => SigningPayloads::Single {
            payload: payload.clone(),
        },
        children => SigningPayloads::Batch {
            children: children.to_vec(),
        },
    }
    .validate()?;
    let mut decoded_calls = Vec::with_capacity(request.evm_review_payloads.len());
    let payloads = request
        .evm_review_payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            let bytes = payload.decode();
            if Digest32::from_bytes(Sha256::digest(&bytes).into())
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
                render_eip1559(&tx, &bytes, policy, from)?
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
                render_legacy(&tx, &bytes, policy, from)?
            };
            let (reviewed, call) = reviewed;
            decoded_calls.push(call);
            Ok(reviewed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut review = EvmReview {
        payloads,
        clear_signing: None,
    };
    apply_review_mode(
        &mut review,
        &decoded_calls,
        policy,
        request.requested_review_mode,
        clear_signing,
    )?;
    Ok(Some(review))
}

/// One mode for the whole batch.
///
/// A member that cannot be described fails the batch; it is never split off,
/// never shown beside clear-signed members, and never quietly downgraded to a
/// digest the owner would have to trust blind. Native sends and deployments
/// carry no calldata and keep their existing exact envelope review.
fn apply_review_mode(
    review: &mut EvmReview,
    calls: &[Option<DecodedCall>],
    policy: &CanonicalWalletPolicy,
    requested: Option<ReviewMode>,
    context: &ClearSigningContext,
) -> Result<(), ProtocolError> {
    let Some(settings) = policy.clear_signing.as_ref() else {
        // An incapable wallet refuses a required mode rather than ignoring it.
        if requested.is_some() {
            return Err(denied(
                ReviewReason::PolicyDenied,
                "clear signing is not enabled for this wallet",
            ));
        }
        return Ok(());
    };
    settings.validate()?;
    if requested == Some(ReviewMode::OpaqueExact) {
        if !settings.opaque_exact_allowed {
            return Err(denied(
                ReviewReason::PolicyDenied,
                "wallet policy does not allow approving payloads Bloom cannot explain",
            ));
        }
        return Ok(());
    }
    let mut entries: Vec<SelectedEntry> = Vec::new();
    for (payload, call) in review.payloads.iter_mut().zip(calls) {
        let Some(call) = call else { continue };
        let catalog = context.catalog.as_ref().ok_or_else(|| {
            denied(
                ReviewReason::CatalogUnavailable,
                "no accepted clear-signing catalog is loaded",
            )
        })?;
        catalog
            .check_validity(context.now_ms)
            .map_err(review_error)?;
        let (clear, selected) = review_call(
            catalog,
            &CallContext {
                chain_id: call.chain_id,
                to: call.to,
                value: call.value,
                calldata: &call.calldata,
                native: native_units(&payload.chain),
                unlimited_allowance_allowed: settings.unlimited_allowance_allowed,
            },
        )
        .map_err(review_error)?;
        // Every entry the reading depended on, including a token an argument
        // named, is held to the same observation age.
        for entry in selected {
            let observed = entry.observed_at_ms.parse::<u64>().unwrap_or(0);
            if context.now_ms > observed.saturating_add(settings.maximum_observation_age_ms) {
                return Err(denied(
                    ReviewReason::EvidenceExpired,
                    format!(
                        "the publisher's observation of {} is older than wallet policy allows",
                        entry.contract_address
                    ),
                ));
            }
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
        payload.contract_call = Some(clear);
    }
    if let Some(catalog) = context.catalog.as_ref()
        && !entries.is_empty()
    {
        review.clear_signing = Some(ClearSigningEvidence::new(
            catalog,
            &context.verifier_digest,
            entries,
        ));
    }
    Ok(())
}

fn native_units(chain: &str) -> Option<NativeUnits> {
    crate::ceremony::native_asset_metadata(chain, "native").map(|(decimals, symbol)| NativeUnits {
        decimals,
        symbol: symbol.to_owned(),
    })
}

/// The decoded call an admitted descriptor may describe. Native sends and
/// deployments produce `None`: there is no calldata to read.
pub(crate) struct DecodedCall {
    pub chain_id: u64,
    pub to: Address,
    pub value: alloy::primitives::U256,
    pub calldata: Vec<u8>,
}

fn render_eip1559(
    tx: &TxEip1559,
    bytes: &[u8],
    policy: &CanonicalWalletPolicy,
    from: Address,
) -> Result<(EvmReviewPayload, Option<DecodedCall>), ProtocolError> {
    let fee_ceiling = tx.max_fee_per_gas;
    let fee = EvmFeeReview::Eip1559 {
        max_fee_per_gas: tx.max_fee_per_gas.to_string(),
        max_fee_per_gas_display: format_gwei(tx.max_fee_per_gas),
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas.to_string(),
        max_priority_fee_per_gas_display: format_gwei(tx.max_priority_fee_per_gas),
    };
    render(tx, bytes, policy, from, fee, fee_ceiling)
}

fn render_legacy(
    tx: &TxLegacy,
    bytes: &[u8],
    policy: &CanonicalWalletPolicy,
    from: Address,
) -> Result<(EvmReviewPayload, Option<DecodedCall>), ProtocolError> {
    let fee_ceiling = tx.gas_price;
    let fee = EvmFeeReview::Legacy {
        gas_price: tx.gas_price.to_string(),
        gas_price_display: format_gwei(tx.gas_price),
    };
    render(tx, bytes, policy, from, fee, fee_ceiling)
}

fn render<T: Transaction + SignableTransaction<Signature>>(
    tx: &T,
    bytes: &[u8],
    policy: &CanonicalWalletPolicy,
    from: Address,
    fee: EvmFeeReview,
    fee_ceiling: u128,
) -> Result<(EvmReviewPayload, Option<DecodedCall>), ProtocolError> {
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
    let input = tx.input();
    if tx.kind() == TxKind::Create && input.is_empty() {
        return Err(invalid("creation requires initcode"));
    }
    let value = tx.value().to_string();
    let call = match tx.kind() {
        TxKind::Call(to) if !input.is_empty() => Some(DecodedCall {
            chain_id: chain,
            to,
            value: tx.value(),
            calldata: input.to_vec(),
        }),
        _ => None,
    };
    Ok((
        EvmReviewPayload {
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
            maximum_execution_gas_fee_display: maximum_execution_gas_fee_display(
                &fee_ceiling,
                tx.gas_limit(),
                &chain_name,
            ),
            contract_call: None,
        },
        call,
    ))
}

fn chain_name(chain_id: u64) -> String {
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

/// `gas_limit * price ceiling`, in the chain's native units. `u128` cannot
/// overflow here: both inputs are `u64`/`u128` envelope fields and the
/// product is taken in `u128` with a checked multiply, so an absurd envelope
/// yields no fee line rather than a wrong one.
fn maximum_execution_gas_fee_display(
    price_ceiling: &u128,
    gas_limit: u64,
    chain: &str,
) -> Option<String> {
    let total = price_ceiling.checked_mul(u128::from(gas_limit))?;
    let (decimals, symbol) = crate::ceremony::native_asset_metadata(chain, "native")?;
    Some(format!(
        "{} {symbol}",
        crate::ceremony::format_base_units(&total.to_string(), usize::from(decimals))
    ))
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bloom_broker_api::*;
    pub(crate) fn request(bytes: &[u8]) -> ApprovalPrepareRequest {
        let token = |s: &str| Token::new(s).unwrap();
        let digest = Digest32::from_bytes([1; 32]);
        ApprovalPrepareRequest {
            requested_review_mode: None,
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
    pub(crate) fn policy() -> CanonicalWalletPolicy {
        CanonicalWalletPolicy {
            wallet_id: Token::new("alice").unwrap(),
            maximum_approval_lifetime_ms: 60000,
            allowed_petal_packages: vec![],
            allowed_destinations: vec![PolicyDestination {
                chain: Token::new("evm-31337").unwrap(),
                destination: "exact".into(),
            }],
            required_verifiers: vec![],
            clear_signing: None,
        }
    }
    fn no_clear_signing() -> ClearSigningContext {
        ClearSigningContext {
            catalog: None,
            verifier_digest: Digest32::from_bytes([0; 32]),
            now_ms: 10,
        }
    }
    fn review_ok(req: &ApprovalPrepareRequest) -> EvmReview {
        review(req, &policy(), Address::ZERO, &no_clear_signing())
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
            assert!(review(&altered, &policy(), Address::ZERO, &no_clear_signing()).is_err());
            let mut denied = policy();
            denied.allowed_destinations.clear();
            assert!(review(&req, &denied, Address::ZERO, &no_clear_signing()).is_err());
            let mut wrong_chain = policy();
            wrong_chain.allowed_destinations[0].chain = Token::new("evm-1").unwrap();
            assert!(review(&req, &wrong_chain, Address::ZERO, &no_clear_signing()).is_err());
            let mut trailing = bytes;
            trailing.push(0);
            assert!(
                review(
                    &request(&trailing),
                    &policy(),
                    Address::ZERO,
                    &no_clear_signing()
                )
                .is_err()
            );
        }
        let mut call = modern;
        call.to = TxKind::Call(Address::ZERO);
        let plan = review_ok(&request(&call.encoded_for_signing()));
        assert_eq!(
            plan.payloads[0].destination,
            Some(Address::ZERO.to_string())
        );
    }

    /// A call carrying `calldata` bytes of input, repeated `count` times with
    /// a selector that matches every copy.
    fn call_batch(calldata: usize, count: usize) -> ApprovalPrepareRequest {
        let payload = TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::ZERO),
            value: alloy::primitives::U256::ZERO,
            input: vec![1; calldata].into(),
            access_list: Default::default(),
        }
        .encoded_for_signing();
        let mut req = request(&payload);
        req.evm_review_payloads = vec![Base64UrlBytes::from_bytes(&payload); count];
        req.terms.selector = ApprovalSelector::Exact {
            ordered_payload_digests: vec![
                Digest32::from_bytes(Sha256::digest(&payload).into());
                count
            ],
            ordered_hashes: vec![Digest32::from_bytes(keccak256(&payload).0); count],
        };
        req
    }

    #[test]
    fn reviews_a_full_maximum_batch_and_rejects_more() {
        assert!(
            review(
                &call_batch(0, 32),
                &policy(),
                Address::ZERO,
                &no_clear_signing()
            )
            .is_ok()
        );
        let error = review(
            &call_batch(0, 33),
            &policy(),
            Address::ZERO,
            &no_clear_signing(),
        )
        .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::LimitExceededFrame);
    }

    #[test]
    fn applies_signing_payload_size_limits_by_payload_count() {
        let kib = 1024;
        // One payload is a single signing payload: up to 256 KiB.
        assert!(
            review(
                &call_batch(200 * kib, 1),
                &policy(),
                Address::ZERO,
                &no_clear_signing()
            )
            .is_ok()
        );
        let error = review(
            &call_batch(256 * kib, 1),
            &policy(),
            Address::ZERO,
            &no_clear_signing(),
        )
        .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::LimitExceededFrame);
        // Several payloads are batch children: 64 KiB each, 512 KiB in total.
        assert!(
            review(
                &call_batch(60 * kib, 2),
                &policy(),
                Address::ZERO,
                &no_clear_signing()
            )
            .is_ok()
        );
        let error = review(
            &call_batch(65 * kib, 2),
            &policy(),
            Address::ZERO,
            &no_clear_signing(),
        )
        .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::LimitExceededFrame);
        let error = review(
            &call_batch(60 * kib, 9),
            &policy(),
            Address::ZERO,
            &no_clear_signing(),
        )
        .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::LimitExceededFrame);
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
        let error = review(
            &request(&signed),
            &policy(),
            Address::ZERO,
            &no_clear_signing(),
        )
        .unwrap_err();
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
            review(
                &request(&canonical),
                &policy(),
                Address::ZERO,
                &no_clear_signing()
            )
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
        let error = review(
            &request(&padded),
            &policy(),
            Address::ZERO,
            &no_clear_signing(),
        )
        .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);

        // Non-minimal list header: short length rewritten in long form with a
        // leading zero length byte (likewise NonCanonicalSize at decode).
        let len = canonical[1] - 0xc0;
        let mut relisted = vec![0x02, 0xf9, 0x00, len];
        relisted.extend_from_slice(&canonical[2..]);
        let error = review(
            &request(&relisted),
            &policy(),
            Address::ZERO,
            &no_clear_signing(),
        )
        .unwrap_err();
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
            let error = review(
                &request(&typed),
                &policy(),
                Address::ZERO,
                &no_clear_signing(),
            )
            .unwrap_err();
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
    fn refuses_any_claim_alongside_evm_payloads() {
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
        let error = review(&req, &policy(), Address::ZERO, &no_clear_signing()).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::MalformedFrame);
        assert!(error.message.contains("cannot carry a claim"), "{error:?}");

        req.petal_use_claim = None;
        req.system_use_claim = Some(SystemUseClaim {
            component_id: Token::new("bloom-machine").unwrap(),
            action_class: Token::new("transaction.confirm").unwrap(),
            operation_class: Token::new("transaction.confirm").unwrap(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: Digest32::from_bytes([10; 32]),
            ordered_hashes: vec![],
            declared_debits: vec![],
            declared_destinations: vec![],
            declared_fee: DeclaredFee::None,
            nonce: RequestNonce::from_bytes([11; 16]),
            chain_context: SystemChainContext {
                chain_family: Token::new("ethereum").unwrap(),
                genesis_hash: String::new(),
                recent_blockhash: String::new(),
                last_valid_block_height: DecimalU64::new(0),
            },
            claim_assurance: ClaimAssurance::MachineAsserted,
        });
        let error = review(&req, &policy(), Address::ZERO, &no_clear_signing()).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::MalformedFrame);
        assert!(error.message.contains("cannot carry a claim"), "{error:?}");
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
            let error = review(&req, &policy(), Address::ZERO, &no_clear_signing()).unwrap_err();
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
        assert!(
            review(&req, &policy(), Address::ZERO, &no_clear_signing())
                .unwrap()
                .is_none()
        );
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
            \"gas_limit\":\"100000\",\
            \"maximum_execution_gas_fee_display\":\"0.000000000001 ETH\",\
            \"nonce\":\"3\",\
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

/// One mode for the whole batch, and what a clear-signed member looks like
/// once the catalog is in play.
#[cfg(test)]
mod mode_tests {
    use super::tests::*;
    use super::*;
    use alloy::primitives::U256;
    use bloom_broker_api::{Base64UrlBytes, DecimalU64, Token};
    use bloom_evm_clear_signing::{
        ActionClass, AdmittedFunction, CATALOG_SCHEMA, CATALOG_SIGNATURE_DOMAIN, CatalogEntry,
        CatalogSignature, ClearSigningCatalog, TokenMetadata, TrustedCatalogKey, descriptor_digest,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    const TOKEN_ADDRESS: &str = "0x1111111111111111111111111111111111111111";
    const RECIPIENT: &str = "0x2222222222222222222222222222222222222222";
    const NOW_MS: u64 = 1_750_000_000_000;
    const TRANSFER: &str = "transfer(address _to, uint256 _value)";

    fn accepted_catalog() -> AcceptedCatalog {
        let descriptor = serde_json::json!({
            "context": {"contract": {"deployments": [{"chainId": 31337, "address": TOKEN_ADDRESS}]}},
            "display": {"formats": {TRANSFER: {
                "intent": "Send",
                "fields": [
                    {"path": "_to", "label": "To", "format": "addressName", "visible": "always"},
                    {"path": "_value", "label": "Amount", "format": "tokenAmount",
                     "params": {"tokenPath": "@.to"}, "visible": "always"}
                ]
            }}}
        });
        let mut catalog = ClearSigningCatalog {
            schema: CATALOG_SCHEMA.into(),
            catalog_id: Token::new("bloom-tokens").unwrap(),
            sequence: DecimalU64::new(1),
            issued_at_ms: DecimalU64::new(NOW_MS - 1000),
            expires_at_ms: DecimalU64::new(NOW_MS + 86_400_000),
            entries: vec![CatalogEntry {
                chain_id: DecimalU64::new(31337),
                contract_address: TOKEN_ADDRESS.into(),
                admitted_functions: vec![AdmittedFunction {
                    signature: TRANSFER.into(),
                    action_class: ActionClass::Transfer,
                }],
                descriptor_digest: Some(descriptor_digest(&descriptor).unwrap()),
                flattened_descriptor: Some(descriptor),
                runtime_code_hash: None,
                token_metadata: Some(TokenMetadata {
                    decimals: 6,
                    symbol: "EXA".into(),
                    name: "Example Token".into(),
                }),
                upgradeable: false,
                implementation_hash: None,
                observed_at_ms: DecimalU64::new(NOW_MS - 500),
            }],
            signatures: Vec::new(),
        };
        let key = SigningKey::from_bytes(&[5; 32]);
        let mut message = CATALOG_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&catalog.unsigned_canonical_bytes().unwrap());
        catalog.signatures = vec![CatalogSignature {
            key_id: Token::new("publisher-1").unwrap(),
            signature: Base64UrlBytes::from_bytes(&key.sign(&message).to_bytes()),
        }];
        let size = serde_jcs::to_vec(&catalog).unwrap().len();
        catalog
            .accept(
                size,
                &[TrustedCatalogKey {
                    key_id: Token::new("publisher-1").unwrap(),
                    verifying_key: key.verifying_key(),
                }],
                1,
            )
            .unwrap()
    }

    fn enabled_context() -> ClearSigningContext {
        ClearSigningContext {
            catalog: Some(accepted_catalog()),
            verifier_digest: Digest32::from_bytes(
                bloom_broker_api::EVM_CLEAR_SIGNING_VERIFIER_DIGEST_BYTES,
            ),
            now_ms: NOW_MS,
        }
    }

    fn enabled_policy() -> CanonicalWalletPolicy {
        let mut policy = policy();
        policy.clear_signing = Some(bloom_broker_api::ClearSigningPolicy {
            catalog_id: Token::new("bloom-tokens").unwrap(),
            trusted_keys: vec![bloom_broker_api::CatalogTrustedKey {
                key_id: Token::new("publisher-1").unwrap(),
                verifying_key: Base64UrlBytes::from_bytes(
                    &SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes(),
                ),
            }],
            signature_threshold: 1,
            maximum_observation_age_ms: 86_400_000,
            opaque_exact_allowed: false,
            unlimited_allowance_allowed: false,
            verifier: bloom_broker_api::RequiredVerifier {
                verifier_id: Token::new(bloom_broker_api::EVM_CLEAR_SIGNING_VERIFIER_ID).unwrap(),
                verifier_digest: Digest32::from_bytes(
                    bloom_broker_api::EVM_CLEAR_SIGNING_VERIFIER_DIGEST_BYTES,
                ),
            },
        });
        policy
    }

    fn transfer_calldata(to: &str, amount: u64) -> Vec<u8> {
        let function = bloom_evm_clear_signing::parse_function(TRANSFER).unwrap();
        let mut encoded = function.selector().to_vec();
        encoded.extend_from_slice(
            &U256::from_be_slice(to.parse::<Address>().unwrap().as_slice()).to_be_bytes::<32>(),
        );
        encoded.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
        encoded
    }

    fn call(to: &str, input: Vec<u8>) -> Vec<u8> {
        TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(to.parse().unwrap()),
            value: U256::ZERO,
            input: input.into(),
            access_list: Default::default(),
        }
        .encoded_for_signing()
    }

    fn batch(payloads: &[Vec<u8>]) -> ApprovalPrepareRequest {
        let mut request = request(&payloads[0]);
        request.evm_review_payloads = payloads
            .iter()
            .map(|bytes| Base64UrlBytes::from_bytes(bytes))
            .collect();
        let digests = payloads
            .iter()
            .map(|bytes| Digest32::from_bytes(Sha256::digest(bytes).into()))
            .collect();
        let hashes = payloads
            .iter()
            .map(|bytes| Digest32::from_bytes(keccak256(bytes).0))
            .collect();
        request.terms.selector = ApprovalSelector::Exact {
            ordered_payload_digests: digests,
            ordered_hashes: hashes,
        };
        request.terms.limits.max_signatures =
            bloom_broker_api::DecimalU64::new(payloads.len() as u64);
        request
    }

    #[test]
    fn an_enabled_wallet_reads_a_contract_call_without_being_asked_to() {
        let request = batch(&[call(TOKEN_ADDRESS, transfer_calldata(RECIPIENT, 2_500_000))]);
        let review = review(
            &request,
            &enabled_policy(),
            Address::ZERO,
            &enabled_context(),
        )
        .unwrap()
        .unwrap();
        let call = review.payloads[0]
            .contract_call
            .as_ref()
            .expect("clear call");
        assert_eq!(call.action, "transfer");
        assert!(call.fields.iter().any(|field| field.value == "2.5 EXA"));
        let evidence = review.clear_signing.as_ref().expect("evidence");
        assert_eq!(evidence.assurance, "trusted_description");
        assert_eq!(evidence.entries.len(), 1);
        // The bound is the observation age, one entry deep.
        assert_eq!(
            evidence.permitted_expiry_ms(86_400_000),
            NOW_MS - 500 + 86_400_000
        );
    }

    #[test]
    fn one_undescribed_member_blocks_the_whole_clear_batch() {
        let request = batch(&[
            call(TOKEN_ADDRESS, transfer_calldata(RECIPIENT, 1)),
            call(RECIPIENT, vec![0xde, 0xad, 0xbe, 0xef]),
        ]);
        let error = review(
            &request,
            &enabled_policy(),
            Address::ZERO,
            &enabled_context(),
        )
        .unwrap_err();
        assert!(
            error.message.contains("UNSUPPORTED_CALL"),
            "{}",
            error.message
        );
    }

    #[test]
    fn an_explicitly_opaque_batch_needs_policy_permission_and_stays_opaque() {
        let mut request = batch(&[call(RECIPIENT, vec![0xde, 0xad, 0xbe, 0xef])]);
        request.requested_review_mode = Some(ReviewMode::OpaqueExact);

        let denied = review(
            &request,
            &enabled_policy(),
            Address::ZERO,
            &enabled_context(),
        )
        .unwrap_err();
        assert!(
            denied.message.contains("POLICY_DENIED"),
            "{}",
            denied.message
        );

        let mut policy = enabled_policy();
        policy.clear_signing.as_mut().unwrap().opaque_exact_allowed = true;
        let review = review(&request, &policy, Address::ZERO, &enabled_context())
            .unwrap()
            .unwrap();
        // No downgrade badge, no partial reading: the member stays opaque and
        // the evidence block is absent.
        assert!(review.payloads[0].contract_call.is_none());
        assert!(review.clear_signing.is_none());
    }

    #[test]
    fn a_wallet_without_clear_signing_refuses_a_required_mode_rather_than_ignoring_it() {
        let mut request = batch(&[call(TOKEN_ADDRESS, transfer_calldata(RECIPIENT, 1))]);
        request.requested_review_mode = Some(ReviewMode::Clear);
        let error = review(
            &request,
            &policy(),
            Address::ZERO,
            &ClearSigningContext {
                catalog: None,
                verifier_digest: Digest32::from_bytes([0; 32]),
                now_ms: NOW_MS,
            },
        )
        .unwrap_err();
        assert!(error.message.contains("POLICY_DENIED"), "{}", error.message);
    }

    #[test]
    fn an_enabled_wallet_with_no_catalog_refuses_the_contract_call() {
        let request = batch(&[call(TOKEN_ADDRESS, transfer_calldata(RECIPIENT, 1))]);
        let error = review(
            &request,
            &enabled_policy(),
            Address::ZERO,
            &ClearSigningContext {
                catalog: None,
                verifier_digest: Digest32::from_bytes([0; 32]),
                now_ms: NOW_MS,
            },
        )
        .unwrap_err();
        assert!(
            error.message.contains("CATALOG_UNAVAILABLE"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_stale_observation_stops_authorizing_even_from_a_valid_catalog() {
        let request = batch(&[call(TOKEN_ADDRESS, transfer_calldata(RECIPIENT, 1))]);
        let mut policy = enabled_policy();
        policy
            .clear_signing
            .as_mut()
            .unwrap()
            .maximum_observation_age_ms = 100;
        let error = review(&request, &policy, Address::ZERO, &enabled_context()).unwrap_err();
        assert!(
            error.message.contains("EVIDENCE_EXPIRED"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_plain_native_send_keeps_its_envelope_review_inside_an_enabled_wallet() {
        let request = batch(&[call(RECIPIENT, Vec::new())]);
        let review = review(
            &request,
            &enabled_policy(),
            Address::ZERO,
            &enabled_context(),
        )
        .unwrap()
        .unwrap();
        assert!(review.payloads[0].contract_call.is_none());
        assert!(review.clear_signing.is_none());
        assert_eq!(review.payloads[0].calldata_bytes, "0");
    }
}
