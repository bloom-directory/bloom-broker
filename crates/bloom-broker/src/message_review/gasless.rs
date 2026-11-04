//! Narrow Relay EIP-3009 adapter. The existing canonical payment decoder binds
//! the exact authorization; this reviewed profile bounds the signed USDC value
//! sent to Relay's permit receiver, not bridge outputs, fees or settlement.
//! USDC deployments and the receiver are trusted to retain reviewed semantics
//! through upgrades. No chain reads or arbitrary-contract exposure claim.
use alloy::primitives::{Address, U256};
use alloy_dyn_abi::eip712::TypedData;
use bloom_broker_api::{
    CryptoSuite, DeclaredFee, MachineSignRequest, ProtocolError, ProtocolErrorCode, SigningPayloads,
};

use super::{Envelope, invalid};

pub(super) const RELAY_RECEIVER: &str = "0xccc88a9d1b4ed6b0eaba998850414b24f1c315be";
const MAX_REMAINING_SECS: u64 = 600;

fn outside_scope(message: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::EffectsUnsupported, message)
}

pub(crate) fn verify_use(
    request: &MachineSignRequest,
    signer: Address,
    now_ms: u64,
) -> Result<(), ProtocolError> {
    let claim = request
        .petal_use_claim
        .as_ref()
        .ok_or_else(|| invalid("Relay session needs its claim"))?;
    if claim.operation_class.as_str() != "gasless.relay"
        || request.crypto_suite != CryptoSuite::Secp256k1Keccak256Recoverable
        || claim.crypto_suite != request.crypto_suite
        || claim.economic_effects.is_none()
        || claim.declared_fee != DeclaredFee::None
        || !claim.declared_destinations.is_empty()
        || request.system_use_claim.is_some()
        || request.session_use.is_some()
    {
        return Err(invalid("Unsupported Relay session claim"));
    }
    let evidence = request
        .claim_assurance_evidence
        .as_ref()
        .ok_or_else(|| invalid("Relay session needs its full typed authorization"))?
        .decode();
    // Decode first, including bounded input, signed type/schema, account and
    // struct checks. A malformed or mismatched witness never becomes fallback.
    let (preimage, review) = super::decode(&evidence, signer)?;
    let payload = match &request.payloads {
        SigningPayloads::Single { payload } => payload,
        SigningPayloads::Batch { children } if children.len() == 1 => &children[0],
        _ => return Err(invalid("Relay session needs exactly one signing payload")),
    };
    if payload.decode() != preimage {
        return Err(invalid("Relay authorization differs from signing bytes"));
    }
    let payment = review
        .payment
        .as_ref()
        .ok_or_else(|| invalid("Relay requires a canonical EIP-3009 payment"))?;
    let [debit] = claim.declared_debits.as_slice() else {
        return Err(invalid("Relay requires one exact signed token debit"));
    };
    let chain = format!("evm-{}", payment.chain_id);
    if debit.asset.chain.as_str() != chain
        || debit.asset.asset != payment.token_address
        || debit.amount.as_str() != payment.amount
    {
        return Err(invalid("Relay debit differs from signed authorization"));
    }
    let effects = claim.economic_effects.as_ref().expect("checked effects");
    if effects.schema_version != 1
        || effects.permission_effect != bloom_broker_api::SessionPermissionEffect::None
        || effects.payload_contexts.len() != 1
        || effects.payload_contexts[0].payload_index != 0
        || effects.payload_contexts[0].network != debit.asset.chain
        || effects.payload_contexts[0].spending_accounts != [request.key_ref.clone()]
    {
        return Err(invalid(
            "Relay effects must bind its exact payload network/account",
        ));
    }
    let amount: U256 = payment
        .amount
        .parse()
        .map_err(|_| invalid("Invalid Relay amount"))?;
    if amount.is_zero() {
        return Err(invalid("Relay payment must be positive"));
    }
    let after: U256 = payment
        .valid_after
        .parse()
        .map_err(|_| invalid("Invalid Relay validity"))?;
    let before: U256 = payment
        .valid_before
        .parse()
        .map_err(|_| invalid("Invalid Relay validity"))?;
    let now = U256::from(now_ms / 1000);
    // EIP-3009 requires timestamp > validAfter and timestamp < validBefore.
    if after >= now || before <= now {
        return Err(invalid("Relay authorization is expired or not yet valid"));
    }
    let Envelope::Eip712 { typed_data, .. } =
        serde_json::from_slice(&evidence).map_err(|_| invalid("Invalid Relay envelope"))?
    else {
        return Err(invalid("Relay requires typed payment data"));
    };
    let typed: TypedData =
        serde_json::from_value(typed_data).map_err(|_| invalid("Invalid Relay typed data"))?;
    let profile = bloom_broker_api::reusable_signing_profile_for_class("gasless.relay")
        .expect("compiled Relay profile");
    if typed.domain.name.as_deref() != Some("USD Coin")
        || typed.domain.version.as_deref() != Some("2")
        || typed.domain.salt.is_some()
        || !profile
            .assets
            .iter()
            .any(|asset| asset.network == chain && asset.asset == payment.token_address)
        || payment.recipient != RELAY_RECEIVER
        || before - now > U256::from(MAX_REMAINING_SECS)
    {
        return Err(outside_scope(
            "Valid Relay payment is outside the reviewed USDC/receiver/600-second profile",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::*;
    use serde_json::{Value, json};
    const NOW: u64 = 1_800_000_000_000;
    fn signer() -> Address {
        Address::with_last_byte(7)
    }
    fn data() -> Value {
        let mut data = super::super::tests::payment_data();
        data["message"]["to"] = json!(RELAY_RECEIVER);
        data["message"]["validBefore"] = json!(NOW / 1000 + 600);
        data
    }
    fn request(data: Value) -> MachineSignRequest {
        let bytes = super::super::tests::envelope(data.clone());
        let (payload, _) = super::super::decode(&bytes, signer()).unwrap();
        let digest = Digest32::from_bytes([1; 32]);
        let token = |s| Token::new(s).unwrap();
        let mut request = MachineSignRequest {
            session_use: None,
            operation_id: OperationId::from_bytes([1; 32]),
            operation_digest: digest.clone(),
            approval_id: digest.clone(),
            key_ref: KeyRef {
                backend: token("local"),
                backend_instance: token("test"),
                locator: "test".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: digest.clone(),
                derivation: None,
            },
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payloads: SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(&payload),
            },
            petal_use_claim: Some(PetalUseClaim {
                economic_effects: Some(EconomicEffectsV1 {
                    schema_version: 1,
                    payload_contexts: vec![],
                    permission_effect: SessionPermissionEffect::None,
                }),
                package_hash: digest.clone(),
                route: "relay".into(),
                operation_class: token("gasless.relay"),
                crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
                payload_digest: digest.clone(),
                ordered_hashes: vec![],
                declared_debits: vec![DeclaredDebit {
                    asset: AssetId {
                        chain: token(&format!("evm-{}", data["domain"]["chainId"])),
                        asset: data["domain"]["verifyingContract"].as_str().unwrap().into(),
                    },
                    amount: DecimalU256::parse(data["message"]["value"].as_str().unwrap()).unwrap(),
                }],
                declared_destinations: vec![],
                declared_fee: DeclaredFee::None,
                nonce: RequestNonce::from_bytes([1; 16]),
                claim_assurance: ClaimAssurance::MachineAsserted,
            }),
            system_use_claim: None,
            claim_assurance_evidence: Some(Base64UrlBytes::from_bytes(&bytes)),
            provenance: ProvenanceSubject::Petal {
                package_hash: digest,
                route: "relay".into(),
            },
        };
        let claim = request.petal_use_claim.as_mut().unwrap();
        claim.economic_effects.as_mut().unwrap().payload_contexts = vec![SessionPayloadContext {
            payload_index: 0,
            network: claim.declared_debits[0].asset.chain.clone(),
            spending_accounts: vec![request.key_ref.clone()],
        }];
        request
    }
    #[test]
    fn supported_usdc_deployments_and_both_canonical_payment_types_are_bound() {
        for asset in bloom_broker_api::reusable_signing_profile_for_class("gasless.relay")
            .unwrap()
            .assets
        {
            for primary in ["TransferWithAuthorization", "ReceiveWithAuthorization"] {
                let mut typed = data();
                typed["domain"]["chainId"] = json!(
                    asset
                        .network
                        .strip_prefix("evm-")
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                );
                typed["domain"]["verifyingContract"] = json!(asset.asset);
                typed["primaryType"] = json!(primary);
                let fields = typed["types"]["TransferWithAuthorization"].take();
                typed["types"]
                    .as_object_mut()
                    .unwrap()
                    .remove("TransferWithAuthorization");
                typed["types"][primary] = fields;
                verify_use(&request(typed), signer(), NOW).unwrap();
            }
        }
    }
    #[test]
    fn valid_scope_misses_step_up_but_bound_mismatches_do_not() {
        for (section, key, value) in [
            ("domain", "name", json!("Other token")),
            ("domain", "version", json!("1")),
            ("domain", "chainId", json!(999)),
            (
                "domain",
                "verifyingContract",
                json!(Address::with_last_byte(8)),
            ),
            ("message", "to", json!(Address::with_last_byte(8))),
            ("message", "validBefore", json!(NOW / 1000 + 601)),
            ("message", "validBefore", json!(U256::MAX.to_string())),
        ] {
            let mut changed = data();
            changed[section][key] = value;
            let rebuilt = request(changed.clone());
            assert_eq!(
                verify_use(&rebuilt, signer(), NOW).unwrap_err().code,
                ProtocolErrorCode::EffectsUnsupported,
                "{key}"
            );
            let mut mismatched = request(data());
            mismatched.claim_assurance_evidence = Some(Base64UrlBytes::from_bytes(
                &super::super::tests::envelope(changed),
            ));
            assert_eq!(
                verify_use(&mismatched, signer(), NOW).unwrap_err().code,
                ProtocolErrorCode::SelectorMismatch,
                "{key}"
            );
        }
    }
    #[test]
    fn invalid_effects_cannot_turn_into_exact_review_scope_misses() {
        let mut typed = data();
        typed["message"]["to"] = json!(Address::with_last_byte(8));
        let base = request(typed);
        for mutation in 0..6 {
            let mut changed = base.clone();
            let effects = changed
                .petal_use_claim
                .as_mut()
                .unwrap()
                .economic_effects
                .as_mut()
                .unwrap();
            match mutation {
                0 => effects.schema_version = 2,
                1 => effects.payload_contexts.clear(),
                2 => effects.payload_contexts[0].payload_index = 1,
                3 => effects.payload_contexts[0].network = Token::new("evm-1").unwrap(),
                4 => effects.payload_contexts[0].spending_accounts.clear(),
                _ => effects
                    .payload_contexts
                    .push(effects.payload_contexts[0].clone()),
            }
            assert_eq!(
                verify_use(&changed, signer(), NOW).unwrap_err().code,
                ProtocolErrorCode::SelectorMismatch,
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn malformed_claims_fields_and_invalid_liveness_are_hard_errors() {
        for (key, value) in [
            ("value", json!("-1")),
            ("nonce", json!("0x1234")),
            ("from", json!(Address::with_last_byte(8))),
            ("validAfter", json!(NOW / 1000 + 1)),
            ("validBefore", json!(NOW / 1000)),
        ] {
            let mut changed = data();
            changed["message"][key] = value;
            let mut r = request(data());
            r.claim_assurance_evidence = Some(Base64UrlBytes::from_bytes(
                &super::super::tests::envelope(changed),
            ));
            assert_eq!(
                verify_use(&r, signer(), NOW).unwrap_err().code,
                ProtocolErrorCode::SelectorMismatch,
                "{key}"
            );
        }
        for (key, value) in [
            ("validAfter", json!(NOW / 1000)),
            ("validBefore", json!(NOW / 1000)),
            ("value", json!("0")),
        ] {
            let mut changed = data();
            changed["message"][key] = value;
            assert_eq!(
                verify_use(&request(changed), signer(), NOW)
                    .unwrap_err()
                    .code,
                ProtocolErrorCode::SelectorMismatch
            );
        }
        let mut r = request(data());
        r.petal_use_claim.as_mut().unwrap().declared_debits[0].amount =
            DecimalU256::parse("1").unwrap();
        assert_eq!(
            verify_use(&r, signer(), NOW).unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );
        let mut r = request(data());
        r.petal_use_claim.as_mut().unwrap().operation_class =
            Token::new("venice-x402.topup").unwrap();
        assert_eq!(
            verify_use(&r, signer(), NOW).unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );
        let mut r = request(data());
        r.claim_assurance_evidence = Some(Base64UrlBytes::from_bytes(b"not-json"));
        assert_eq!(
            verify_use(&r, signer(), NOW).unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );
    }
}
