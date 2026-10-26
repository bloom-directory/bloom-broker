//! Immutable `polymarket.clob_auth.v1` future-message profile. Changing any
//! accepted field or widening the time window requires a new operation class.
//! Protocol source: https://github.com/Polymarket/clob-client-v2/blob/main/src/signing/eip712.ts
use super::{MessageField, MessageReview, invalid};
use alloy::primitives::{Address, U256, keccak256};
use bloom_broker_api::{
    ApprovalSelector, CryptoSuite, MachineSignRequest, POLYMARKET_CLOB_AUTH_CLASS, ProtocolError,
    SealedApprovalTerms, SigningPayloads,
};

const ATTESTATION: &str = "This message attests that I control the given wallet";
const WINDOW_SECONDS: u64 = 300;

pub(crate) fn is_scope(terms: &SealedApprovalTerms) -> bool {
    matches!(&terms.selector, ApprovalSelector::Petal { allowed_operation_classes, route_grants, .. }
        if allowed_operation_classes.iter().chain(route_grants.iter().flat_map(|grant| &grant.allowed_operation_classes))
            .any(|class| class.as_str() == POLYMARKET_CLOB_AUTH_CLASS))
}

fn validate_scope(terms: &SealedApprovalTerms) -> Result<(), ProtocolError> {
    let ApprovalSelector::Petal {
        allowed_operation_classes,
        route_grants,
        ..
    } = &terms.selector
    else {
        return Err(invalid(
            "CLOB authentication requires its versioned one-use scope",
        ));
    };
    if !matches!(
        terms.subject,
        bloom_broker_api::ApprovalSubject::Petal { .. }
    ) || allowed_operation_classes.len() != 1
        || allowed_operation_classes[0].as_str() != POLYMARKET_CLOB_AUTH_CLASS
        || !route_grants.is_empty()
        || terms.allowed_crypto_suites != [CryptoSuite::Secp256k1Keccak256Recoverable]
        || terms.limits.max_operations.get() != 1
        || terms.limits.max_signatures.get() != 1
        || !terms.limits.value_limits.is_empty()
    {
        return Err(invalid(
            "CLOB v1 scope allows only one authentication signature without financial claims",
        ));
    }
    Ok(())
}

fn preimage(owner: Address, timestamp: u64) -> Vec<u8> {
    let mut domain = Vec::with_capacity(128);
    domain.extend_from_slice(
        keccak256("EIP712Domain(string name,string version,uint256 chainId)").as_slice(),
    );
    domain.extend_from_slice(keccak256("ClobAuthDomain").as_slice());
    domain.extend_from_slice(keccak256("1").as_slice());
    domain.extend_from_slice(&U256::from(137).to_be_bytes::<32>());
    let mut message = Vec::with_capacity(160);
    message.extend_from_slice(
        keccak256("ClobAuth(address address,string timestamp,uint256 nonce,string message)")
            .as_slice(),
    );
    message.extend_from_slice(&[0; 12]);
    message.extend_from_slice(owner.as_slice());
    message.extend_from_slice(keccak256(timestamp.to_string()).as_slice());
    message.extend_from_slice(&[0; 32]);
    message.extend_from_slice(keccak256(ATTESTATION).as_slice());
    let mut bytes = vec![0x19, 0x01];
    bytes.extend_from_slice(keccak256(domain).as_slice());
    bytes.extend_from_slice(keccak256(message).as_slice());
    bytes
}

pub(crate) fn review(
    terms: &SealedApprovalTerms,
    owner: Address,
) -> Result<MessageReview, ProtocolError> {
    validate_scope(terms)?;
    let field = |path: &str, value: &str| MessageField {
        path: path.into(),
        value: value.into(),
    };
    Ok(MessageReview {
        kind:"polymarket_auth_scope".into(), title:"Allow one Polymarket CLOB authentication".into(),
        signer:format!("{owner:#x}"), payload_keccak:String::new(), payment:None,
        venue_asset:None, collateral_asset:None,
        domain:vec![field("name","ClobAuthDomain"),field("version","1"),field("chainId","137")],
        fields:vec![field("Permission profile",POLYMARKET_CLOB_AUTH_CLASS),field("Signed attestation",ATTESTATION),
            field("Nonce","0"),field("Signature limit","One signature in one operation"),
            field("Timestamp","Fresh Unix seconds within 300 seconds of Broker time at signing")],
        warnings:vec!["This permission can create or derive CLOB API credentials. Those credentials authorize account API operations; review the Petal's access separately. It cannot sign an order, wallet batch or payment. The timestamp is chosen after approval and verified when used; no exact message hash exists yet.".into()],
    })
}

pub(crate) fn verify_use(
    terms: &SealedApprovalTerms,
    request: &MachineSignRequest,
    owner: Address,
    now_ms: u64,
) -> Result<(), ProtocolError> {
    validate_scope(terms)?;
    let claim = request
        .petal_use_claim
        .as_ref()
        .ok_or_else(|| invalid("CLOB authentication requires its claim"))?;
    validate_claim(claim)?;
    if request.crypto_suite != CryptoSuite::Secp256k1Keccak256Recoverable {
        return Err(invalid("CLOB authentication requires recoverable Keccak"));
    }
    let bytes = match &request.payloads {
        SigningPayloads::Single { payload } => payload.decode(),
        SigningPayloads::Batch { children } if children.len() == 1 => children[0].decode(),
        _ => return Err(invalid("CLOB authentication permits one signature")),
    };
    let now = now_ms / 1000;
    let reference = preimage(owner, now);
    if bytes.len() != 66 || bytes[..34] != reference[..34] {
        return Err(invalid("CLOB authentication domain or preimage is invalid"));
    }
    // Only timestamp varies. Bounded reconstruction avoids trusting a caller's
    // claimed typed fields or adding an unauthenticated use-time review object.
    if (now.saturating_sub(WINDOW_SECONDS)..=now.saturating_add(WINDOW_SECONDS))
        .any(|timestamp| bytes == preimage(owner, timestamp))
    {
        return Ok(());
    }
    Err(invalid(
        "CLOB authentication is stale or differs from the approved owner/nonce/attestation",
    ))
}

pub(crate) fn validate_claim(claim: &bloom_broker_api::PetalUseClaim) -> Result<(), ProtocolError> {
    if claim.operation_class.as_str() != POLYMARKET_CLOB_AUTH_CLASS
        || claim.crypto_suite != CryptoSuite::Secp256k1Keccak256Recoverable
        || !claim.declared_debits.is_empty()
        || !claim.declared_destinations.is_empty()
        || claim.declared_fee != bloom_broker_api::DeclaredFee::None
    {
        return Err(invalid("CLOB authentication claim exceeds its profile"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn typed(owner: Address, time: u64) -> serde_json::Value {
        serde_json::json!({"schema":"bloom.message.review.v1","kind":"eip712",
            "typed_data":{"domain":{"name":"ClobAuthDomain","version":"1","chainId":137},
            "types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"}],
            "ClobAuth":[{"name":"address","type":"address"},{"name":"timestamp","type":"string"},{"name":"nonce","type":"uint256"},{"name":"message","type":"string"}]},
            "primaryType":"ClobAuth","message":{"address":owner,"timestamp":time.to_string(),"nonce":0,"message":ATTESTATION}}})
    }
    #[test]
    fn clob_auth_matches_independent_typed_data_encoding() {
        let owner = Address::with_last_byte(7);
        let time = 1_800_000_000;
        let value = typed(owner, time);
        let (actual, _) =
            super::super::decode(&serde_json::to_vec(&value).unwrap(), owner).unwrap();
        assert_eq!(actual, preimage(owner, time));
    }

    #[test]
    fn scope_checks_actual_bytes_freshness_owner_and_one_use_limits() {
        use bloom_broker_api::{
            Base64UrlBytes, ClaimAssurance, DecimalU64, DeclaredFee, Digest32, PetalUseClaim,
            ProvenanceSubject, RequestNonce, Token,
        };
        let owner = Address::with_last_byte(7);
        let now = 1_800_000_000u64;
        let base = super::super::tests::request(serde_json::to_vec(&typed(owner, now)).unwrap());
        let mut terms = base.terms;
        terms.selector = ApprovalSelector::Petal {
            package_hash: Digest32::from_bytes([1; 32]),
            route: "auth/wallet/0".into(),
            allowed_operation_classes: vec![Token::new(POLYMARKET_CLOB_AUTH_CLASS).unwrap()],
            route_grants: vec![],
            required_claim_assurance: bloom_broker_api::ClaimAssuranceLevel::MachineAsserted,
        };
        let claim = PetalUseClaim {
            package_hash: Digest32::from_bytes([1; 32]),
            route: "auth/wallet/0".into(),
            operation_class: Token::new(POLYMARKET_CLOB_AUTH_CLASS).unwrap(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: Digest32::from_bytes([2; 32]),
            ordered_hashes: vec![],
            declared_debits: vec![],
            declared_destinations: vec![],
            declared_fee: DeclaredFee::None,
            nonce: RequestNonce::from_bytes([3; 16]),
            claim_assurance: ClaimAssurance::MachineAsserted,
        };
        let mut request = MachineSignRequest {
            session_use: None,
            operation_id: base.operation_id,
            operation_digest: Digest32::from_bytes([4; 32]),
            approval_id: Digest32::from_bytes([5; 32]),
            key_ref: terms.key_ref.clone(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payloads: SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(&preimage(owner, now)),
            },
            petal_use_claim: Some(claim),
            system_use_claim: None,
            claim_assurance_evidence: None,
            provenance: ProvenanceSubject::Petal {
                package_hash: Digest32::from_bytes([1; 32]),
                route: "auth/wallet/0".into(),
            },
        };
        let review = review(&terms, owner).unwrap();
        assert_eq!(review.kind, "polymarket_auth_scope");
        assert!(review.payload_keccak.is_empty());
        if let Some(directory) = std::env::var_os("BLOOM_UI_FIXTURE_DIR") {
            std::fs::write(
                std::path::Path::new(&directory).join("polymarket-auth.json"),
                serde_json::to_vec_pretty(&review).unwrap(),
            )
            .unwrap();
        }
        for timestamp in [now - 300, now, now + 300] {
            request.payloads = SigningPayloads::Batch {
                children: vec![Base64UrlBytes::from_bytes(&preimage(owner, timestamp))],
            };
            verify_use(&terms, &request, owner, now * 1000).unwrap();
        }
        for timestamp in [now - 301, now + 301] {
            request.payloads = SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(&preimage(owner, timestamp)),
            };
            assert!(verify_use(&terms, &request, owner, now * 1000).is_err());
        }
        for (field, value) in [
            ("address", serde_json::json!(Address::ZERO)),
            ("nonce", serde_json::json!(1)),
            ("message", serde_json::json!("Authorize payment")),
        ] {
            let mut value_typed = typed(owner, now);
            value_typed["typed_data"]["message"][field] = value;
            let (bytes, _) =
                super::super::decode(&serde_json::to_vec(&value_typed).unwrap(), owner).unwrap();
            request.payloads = SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(&bytes),
            };
            assert!(
                verify_use(&terms, &request, owner, now * 1000).is_err(),
                "{field}"
            );
        }
        let mut wrong_domain = preimage(owner, now);
        wrong_domain[2] ^= 1;
        request.payloads = SigningPayloads::Single {
            payload: Base64UrlBytes::from_bytes(&wrong_domain),
        };
        assert!(verify_use(&terms, &request, owner, now * 1000).is_err());
        request.payloads = SigningPayloads::Batch {
            children: vec![Base64UrlBytes::from_bytes(&preimage(owner, now)); 2],
        };
        assert!(verify_use(&terms, &request, owner, now * 1000).is_err());
        terms.limits.max_operations = DecimalU64::new(2);
        assert!(validate_scope(&terms).is_err());
        terms.limits.max_operations = DecimalU64::new(1);
        terms.limits.max_signatures = DecimalU64::new(2);
        assert!(validate_scope(&terms).is_err());
        terms.limits.max_signatures = DecimalU64::new(1);
        for class in [
            "polymarket.onboard",
            "polymarket.order.poly1271",
            POLYMARKET_CLOB_AUTH_CLASS,
        ] {
            let mut changed = terms.clone();
            if let ApprovalSelector::Petal {
                allowed_operation_classes,
                ..
            } = &mut changed.selector
            {
                allowed_operation_classes[0] = Token::new(class).unwrap();
            }
            let result =
                super::super::validate_selector(&changed, request.petal_use_claim.as_ref());
            assert_eq!(result.is_ok(), class == POLYMARKET_CLOB_AUTH_CLASS);
        }
    }
}
