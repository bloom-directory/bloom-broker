//! Current Polymarket PreparedSigning records, reconstructed independently.
//! Auxiliary draft/quote fields never become signed review facts.
use alloy::primitives::{Address, B256, keccak256};
use bloom_broker_api::{ProtocolError, SINGLE_PAYLOAD_MAX_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{MessageField, MessageReview, bounded, invalid};

const EXCHANGE: &str = "0xe111180000d2663c0091e4f400237545b87b996b";
const NEG_RISK_EXCHANGE: &str = "0xe2222d279d744050d28e00520010520000310f59";
const ORDER: &str = "uint256 salt,address maker,address signer,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    operation: String,
    intent: String,
    owner: Address,
    signing_hash: B256,
    signing_preimage_hex: String,
    preimage: Value,
}

fn fields(signature: &str) -> Value {
    Value::Array(
        signature
            .split(',')
            .map(|field| {
                let (kind, name) = field.split_once(' ').expect("static type fields");
                json!({"name":name,"type":kind})
            })
            .collect(),
    )
}

fn check_keys(value: &Value, allowed: &[&str]) -> Result<(), ProtocolError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("Polymarket prepared data must be an object"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("Polymarket prepared data has an unsupported field"));
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProtocolError> {
    value[key]
        .as_str()
        .ok_or_else(|| invalid("Polymarket prepared text field is missing"))
}

fn address(value: &Value, key: &str) -> Result<Address, ProtocolError> {
    text(value, key)?
        .parse()
        .map_err(|_| invalid("Polymarket prepared address is invalid"))
}

fn typed(prepared: &Prepared, class: &str) -> Result<Value, ProtocolError> {
    let value = &prepared.preimage;
    if value["chain_id"].as_u64() != Some(137) {
        return Err(invalid(
            "Polymarket review currently supports Polygon mainnet only",
        ));
    }
    let domain_type =
        fields("string name,string version,uint256 chainId,address verifyingContract");
    if class == "polymarket.order.poly1271" {
        check_keys(
            value,
            &[
                "draft_id",
                "owner",
                "funder",
                "token_id",
                "salt",
                "maker_amount",
                "taker_amount",
                "side",
                "signature_type",
                "timestamp_ms",
                "neg_risk",
                "chain_id",
                "review_intent_hash",
                "policy_warnings_acknowledged",
            ],
        )?;
        if prepared.operation != "order"
            || address(value, "owner")? != prepared.owner
            || value["signature_type"].as_u64() != Some(3)
            || !matches!(value["side"].as_u64(), Some(0 | 1))
        {
            return Err(invalid(
                "Polymarket order identity, side or signature type is unsupported",
            ));
        }
        let neg_risk = value["neg_risk"]
            .as_bool()
            .ok_or_else(|| invalid("order neg-risk choice is missing"))?;
        let wallet = address(value, "funder")?;
        if wallet.is_zero() {
            return Err(invalid("deposit wallet must be nonzero"));
        }
        Ok(json!({
            "domain":{"name":"Polymarket CTF Exchange","version":"2","chainId":137,"verifyingContract":if neg_risk {NEG_RISK_EXCHANGE}else{EXCHANGE}},
            "types":{"EIP712Domain":domain_type,"Order":fields(ORDER),
                "TypedDataSign":fields("Order contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt")},
            "primaryType":"TypedDataSign",
            "message":{"contents":{"salt":text(value,"salt")?,"maker":wallet,"signer":wallet,
                "tokenId":text(value,"token_id")?,"makerAmount":text(value,"maker_amount")?,
                "takerAmount":text(value,"taker_amount")?,"side":value["side"],"signatureType":3,
                "timestamp":text(value,"timestamp_ms")?,"metadata":B256::ZERO,"builder":B256::ZERO},
                "name":"DepositWallet","version":"1","chainId":137,"verifyingContract":wallet,"salt":B256::ZERO}
        }))
    } else {
        check_keys(
            value,
            &[
                "deposit_wallet",
                "chain_id",
                "nonce",
                "deadline",
                "calls",
                "review_intent_hash",
            ],
        )?;
        if class == "polymarket.onboard" && prepared.operation != "onboard_approvals" {
            return Err(invalid(
                "reusable Polymarket login is not an exact wallet-batch review",
            ));
        }
        let wallet = address(value, "deposit_wallet")?;
        let calls = value["calls"]
            .as_array()
            .filter(|calls| !calls.is_empty() && calls.len() <= 32)
            .ok_or_else(|| invalid("Polymarket wallet batch requires 1-32 calls"))?;
        if wallet.is_zero()
            || value["nonce"].as_u64().is_none()
            || value["deadline"].as_u64().is_none()
        {
            return Err(invalid(
                "Polymarket wallet batch identity or nonce/deadline is invalid",
            ));
        }
        for call in calls {
            check_keys(call, &["target", "value", "data"])?;
        }
        Ok(
            json!({"domain":{"name":"DepositWallet","version":"1","chainId":137,"verifyingContract":wallet},
            "types":{"EIP712Domain":domain_type,"Call":fields("address target,uint256 value,bytes data"),
                "Batch":fields("address wallet,uint256 nonce,uint256 deadline,Call[] calls")},
            "primaryType":"Batch","message":{"wallet":wallet,"nonce":value["nonce"],"deadline":value["deadline"],"calls":calls}}),
        )
    }
}

pub(super) fn decode(
    bytes: &[u8],
    signer: Address,
    class: &str,
) -> Result<(Vec<u8>, MessageReview), ProtocolError> {
    if !bloom_broker_api::POLYMARKET_REVIEW_OPERATION_CLASSES.contains(&class) {
        return Err(invalid("unsupported Polymarket review operation"));
    }
    if bytes.len() > SINGLE_PAYLOAD_MAX_BYTES {
        return Err(invalid("Polymarket review exceeds its bound"));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid Polymarket prepared review"))?;
    bounded(&value, 0, &mut 0)?;
    let mut records: Vec<Prepared> =
        serde_json::from_value(value).map_err(|_| invalid("invalid Polymarket prepared record"))?;
    if records.len() != 1 {
        return Err(invalid(
            "current Polymarket review requires one prepared signature",
        ));
    }
    let prepared = records.remove(0);
    if prepared.owner != signer || prepared.intent != class {
        return Err(invalid(
            "Polymarket prepared owner or operation class differs from approval",
        ));
    }
    let typed = typed(&prepared, class)?;
    let envelope =
        serde_json::to_vec(&json!({"schema":super::SCHEMA,"kind":"eip712","typed_data":typed}))
            .map_err(|_| invalid("cannot encode Polymarket typed review"))?;
    let (preimage, mut review) = super::decode(&envelope, signer)?;
    let advertised = hex::decode(&prepared.signing_preimage_hex)
        .map_err(|_| invalid("invalid advertised Polymarket preimage"))?;
    if advertised != preimage || keccak256(&preimage) != prepared.signing_hash {
        return Err(invalid(
            "Polymarket prepared fields do not reconstruct the signed preimage",
        ));
    }
    review.kind = "polymarket_exact".into();
    if class == "polymarket.order.poly1271" {
        review.title = if prepared.preimage["side"] == 0 {
            "Sign a prediction-market buy order"
        } else {
            "Sign a prediction-market sell order"
        }
        .into();
        for field in &mut review.fields {
            field.path = match field.path.as_str() {
                "contents.makerAmount" => "Maker amount (raw protocol units)",
                "contents.takerAmount" => "Taker amount (raw protocol units)",
                "contents.tokenId" => "Outcome token ID (market identity unverified)",
                "contents.side" => "Side (0 buy, 1 sell)",
                other => other,
            }
            .to_owned();
        }
        let collateral_key = if prepared.preimage["side"] == 0 {
            "Maker amount (raw protocol units)"
        } else {
            "Taker amount (raw protocol units)"
        };
        let collateral = "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb";
        let token = bloom_broker_api::tokens_on(137)
            .find(|token| token.address == collateral)
            .ok_or_else(|| invalid("Polymarket collateral is missing from the compiled catalog"))?;
        // The typed reader has already coerced this signed uint256 to decimal.
        // Never format the caller's original spelling (which can be hex).
        let amount = &review
            .fields
            .iter()
            .find(|field| field.path == collateral_key)
            .ok_or_else(|| invalid("decoded order collateral amount is missing"))?
            .value;
        review.collateral_asset = Some(bloom_evm_clear_signing::FieldAsset {
            chain_id: 137,
            token: bloom_evm_clear_signing::TokenIdentity {
                address: token.address.clone(),
                name: token.name.clone(),
                symbol: token.symbol.clone(),
                decimals: token.decimals,
            },
            amount_display: format!(
                "{} {}",
                super::format_base_units(amount, token.decimals),
                token.symbol
            ),
        });
        review.fields.push(MessageField {
            path: "Collateral contract (Polygon)".into(),
            value: collateral.into(),
        });
        review.fields.push(MessageField {
            path: "Signed order expiry".into(),
            value: "None; HTTP expiration is not part of this signature".into(),
        });
        review.warnings.push("pUSD is not Circle USDC. Its 6 decimals and exchange bindings were checked at Polygon block 95772650; these contracts can upgrade. Outcome identity/units, fees, fill and settlement are unverified. HTTP order options are not signed.".into());
    } else {
        review.title = "Authorize deposit-wallet calls".into();
        describe_calls(&prepared.preimage["calls"], &mut review)?;
    }
    review.warnings.push("Deposit-wallet ownership/implementation, live nonce, balances and execution effects are unverified. Draft IDs, intent hashes and acknowledgement flags are unsigned metadata.".into());
    Ok((preimage, review))
}

fn describe_calls(value: &Value, review: &mut MessageReview) -> Result<(), ProtocolError> {
    use alloy::primitives::U256;
    use bloom_evm_clear_signing::{CallContext, Catalog, review_call};
    for (index, call) in value
        .as_array()
        .expect("validated calls")
        .iter()
        .enumerate()
    {
        let to = address(call, "target")?;
        let amount = U256::from_str_radix(text(call, "value")?, 10)
            .map_err(|_| invalid("invalid wallet-call native value"))?;
        let data = text(call, "data")?
            .strip_prefix("0x")
            .ok_or_else(|| invalid("wallet-call data requires hex prefix"))?;
        let data = hex::decode(data).map_err(|_| invalid("invalid wallet-call data"))?;
        let result = review_call(
            Catalog::built_in().map_err(|_| invalid("compiled EVM catalog is invalid"))?,
            &CallContext {
                chain_id: 137,
                to,
                value: amount,
                calldata: &data,
                native: None,
            },
        );
        match result {
            Ok((call,_))=> {
                if call.function_signature.starts_with("setApprovalForAll(")
                    && call.fields.iter().any(|field|field.label=="Approved"&&field.raw=="true") {
                    review.warnings.push(format!("Call {} grants an operator permission for every current and future token ID if the contract implements this interface. The permission has no signed expiry; revoke it separately.",index+1));
                }
                if call.intent_summary.as_ref().is_some_and(|intent|intent.action=="allowance"&&intent.magnitude=="unlimited") {
                    review.fields.push(MessageField {path:format!("Call {} permission",index+1),value:"Unlimited ERC-20 allowance (maximum uint256); all current and future balances may be spent".into()});
                }
                review.fields.push(MessageField {path:format!("Call {} interpretation",index+1),value:call.function_signature});
                for field in call.fields {
                    review.fields.push(MessageField {path:format!("Call {} · {}",index+1,field.label),value:super::escaped(&field.value)});
                }
                for warning in call.warnings {review.warnings.push(super::escaped(&warning));}
            }
            Err(error)=>review.warnings.push(format!("Call {} is not independently decoded: {}. Exact target, native value and calldata remain in the signed fields.",index+1,super::escaped(&error.detail))),
        }
        if review.fields.len() > super::MAX_FIELDS {
            return Err(invalid("wallet batch exceeds its field bound"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn erc7739_order_matches_independent_known_answer() {
        let signer = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            .parse()
            .unwrap();
        let mut prepared = Prepared {
            operation: "order".into(),
            intent: "polymarket.order.poly1271".into(),
            owner: signer,
            signing_hash: B256::ZERO,
            signing_preimage_hex: String::new(),
            preimage: json!({"chain_id":137,"owner":signer,
                "funder":"0x6c625c75652cf2cdf2bfe94ad59cb6f79b899a18","token_id":"7496871387824498705150337097986995704782987980926026827618928384721521953608",
                "salt":"479249096354","maker_amount":"11782400","taker_amount":"21040000","side":0,"signature_type":3,
                "timestamp_ms":"1765432100000","neg_risk":false}),
        };
        for (neg_risk, expected) in [
            (
                false,
                "ef5ec6a9a480c3a4f7bdf0b8a5dbf06c9fa11d7ad6a7b3273901528378fc0c36",
            ),
            (
                true,
                "3f23a9ec3d94ca14672fa676310a174d8c1e2d43828754173c9c992d8ae3593e",
            ),
        ] {
            prepared.preimage["neg_risk"] = json!(neg_risk);
            let envelope = json!({"schema":super::super::SCHEMA,"kind":"eip712","typed_data":typed(&prepared,&prepared.intent).unwrap()});
            let (preimage, _) =
                super::super::decode(&serde_json::to_vec(&envelope).unwrap(), signer).unwrap();
            assert_eq!(hex::encode(keccak256(preimage)), expected);
        }
    }

    fn prepared_order() -> (Prepared, Address) {
        let signer = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            .parse()
            .unwrap();
        let mut prepared = Prepared {
            operation: "order".into(),
            intent: "polymarket.order.poly1271".into(),
            owner: signer,
            signing_hash: B256::ZERO,
            signing_preimage_hex: String::new(),
            preimage: json!({"chain_id":137,"owner":signer,
                "funder":"0x6c625c75652cf2cdf2bfe94ad59cb6f79b899a18","token_id":"7496871387824498705150337097986995704782987980926026827618928384721521953608",
                "salt":"479249096354","maker_amount":"11782400","taker_amount":"21040000","side":0,"signature_type":3,
                "timestamp_ms":"1765432100000","neg_risk":false,"draft_id":"unsigned-draft-label"}),
        };
        let envelope = json!({"schema":super::super::SCHEMA,"kind":"eip712","typed_data":typed(&prepared,&prepared.intent).unwrap()});
        let (preimage, _) =
            super::super::decode(&serde_json::to_vec(&envelope).unwrap(), signer).unwrap();
        prepared.signing_preimage_hex = hex::encode(&preimage);
        prepared.signing_hash = keccak256(preimage);
        (prepared, signer)
    }

    #[test]
    fn prepared_order_review_is_bound_to_exact_approval_and_rejects_claim_overrides() {
        use bloom_broker_api::{
            ApprovalSelector, Base64UrlBytes, ClaimAssurance, DeclaredFee, Digest32, PetalUseClaim,
            RequestNonce, Token,
        };
        use sha2::{Digest as _, Sha256};
        let (prepared, signer) = prepared_order();
        let typed_envelope = serde_json::to_vec(&json!({"schema":super::super::SCHEMA,
            "kind":"eip712","typed_data":typed(&prepared,&prepared.intent).unwrap()}))
        .unwrap();
        let mut request = super::super::tests::request(typed_envelope);
        request.message_review_payloads = vec![Base64UrlBytes::from_bytes(
            &serde_json::to_vec(&vec![&prepared]).unwrap(),
        )];
        request.petal_use_claim = Some(PetalUseClaim {
            package_hash: Digest32::from_bytes([1; 32]),
            route: "payment/a/0/confirm".into(),
            operation_class: Token::new(&prepared.intent).unwrap(),
            crypto_suite: bloom_broker_api::CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: Digest32::from_bytes([9; 32]),
            ordered_hashes: vec![],
            declared_debits: vec![],
            declared_destinations: vec![],
            declared_fee: DeclaredFee::None,
            nonce: RequestNonce::from_bytes([4; 16]),
            claim_assurance: ClaimAssurance::MachineAsserted,
        });
        let raw = hex::decode(&prepared.signing_preimage_hex).unwrap();
        request.terms.selector = ApprovalSelector::Exact {
            ordered_payload_digests: vec![Digest32::from_bytes(Sha256::digest(&raw).into())],
            ordered_hashes: vec![Digest32::from_bytes(keccak256(&raw).into())],
        };
        let review = super::super::review(&request, signer).unwrap().unwrap();
        assert_eq!(review.kind, "polymarket_exact");
        let mut changed = request.clone();
        if let ApprovalSelector::Exact { ordered_hashes, .. } = &mut changed.terms.selector {
            ordered_hashes[0] = Digest32::from_bytes([7; 32]);
        }
        assert!(super::super::review(&changed, signer).is_err());
        let mut changed = request.clone();
        changed.petal_use_claim.as_mut().unwrap().declared_fee = DeclaredFee::Fee {
            chain: Token::new("polygon").unwrap(),
            asset: "pusd".into(),
            amount: bloom_broker_api::DecimalU256::parse("1").unwrap(),
        };
        assert!(super::super::review(&changed, signer).is_err());
        let mut changed = request;
        changed
            .message_review_payloads
            .push(changed.message_review_payloads[0].clone());
        assert!(super::super::review(&changed, signer).is_err());
    }

    #[test]
    fn prepared_order_binds_every_signed_field_without_promoting_unsigned_labels() {
        let (prepared, signer) = prepared_order();
        let record = serde_json::to_value(&prepared).unwrap();
        let (_, review) = decode(
            &serde_json::to_vec(&vec![&record]).unwrap(),
            signer,
            &prepared.intent,
        )
        .unwrap();
        assert!(review.title.contains("buy order"));
        let collateral = review.collateral_asset.as_ref().unwrap();
        assert_eq!(collateral.chain_id, 137);
        assert_eq!(collateral.token.symbol, "pUSD");
        assert_eq!(collateral.amount_display, "11.7824 pUSD");
        if let Some(directory) = std::env::var_os("BLOOM_UI_FIXTURE_DIR") {
            std::fs::write(
                std::path::Path::new(&directory).join("polymarket-order.json"),
                serde_json::to_vec_pretty(&review).unwrap(),
            )
            .unwrap();
        }
        assert!(review.fields.iter().any(|field| field.value == "11782400"));
        assert!(
            !review
                .fields
                .iter()
                .any(|field| field.value.contains("unsigned-draft"))
        );
        for (field, value) in [
            ("maker_amount", json!("11782401")),
            ("neg_risk", json!(true)),
            (
                "funder",
                json!("0x0000000000000000000000000000000000000009"),
            ),
            ("builder", json!("0xdead")),
        ] {
            let mut changed = record.clone();
            changed["preimage"][field] = value;
            assert!(
                decode(
                    &serde_json::to_vec(&vec![changed]).unwrap(),
                    signer,
                    &prepared.intent
                )
                .is_err(),
                "{field}"
            );
        }
        assert!(
            decode(
                &serde_json::to_vec(&vec![&record]).unwrap(),
                Address::ZERO,
                &prepared.intent
            )
            .is_err()
        );
        assert!(
            decode(
                &serde_json::to_vec(&vec![&record, &record]).unwrap(),
                signer,
                &prepared.intent
            )
            .is_err()
        );
        let mut hexadecimal = record.clone();
        hexadecimal["preimage"]["maker_amount"] =
            json!(format!("0x{:x}", alloy::primitives::U256::from(11_782_400)));
        let (_, normalized) = decode(
            &serde_json::to_vec(&vec![hexadecimal]).unwrap(),
            signer,
            &prepared.intent,
        )
        .unwrap();
        assert_eq!(review, normalized);
        let mut changed = record;
        changed["preimage"]["draft_id"] = json!("a different unsigned label");
        let (_, changed) = decode(
            &serde_json::to_vec(&vec![changed]).unwrap(),
            signer,
            &prepared.intent,
        )
        .unwrap();
        assert_eq!(review, changed);
    }

    #[test]
    fn exact_wallet_batch_rebuilds_calls_and_keeps_unknown_calls_explicit() {
        let signer = Address::with_last_byte(1);
        let wallet = Address::with_last_byte(2);
        let recipient = Address::with_last_byte(3);
        let mut data = hex::decode("a9059cbb").unwrap();
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(recipient.as_slice());
        data.extend_from_slice(&alloy::primitives::U256::from(2_500_000).to_be_bytes::<32>());
        let mut prepared = Prepared {
            operation: "withdraw-pusd".into(),
            intent: "polymarket.relayer_batch".into(),
            owner: signer,
            signing_hash: B256::ZERO,
            signing_preimage_hex: String::new(),
            preimage: json!({"chain_id":137,"deposit_wallet":wallet,
                "nonce":7,"deadline":1900000000u64,"calls":[{"target":"0x2791bca1f2de4661ed88a30c99a7a9449aa84174","value":"0","data":format!("0x{}",hex::encode(data))},
                {"target":recipient,"value":"9","data":"0xdeadbeef"}]}),
        };
        let envelope = json!({"schema":super::super::SCHEMA,"kind":"eip712","typed_data":typed(&prepared,&prepared.intent).unwrap()});
        let (preimage, _) =
            super::super::decode(&serde_json::to_vec(&envelope).unwrap(), signer).unwrap();
        prepared.signing_hash = keccak256(&preimage);
        prepared.signing_preimage_hex = hex::encode(preimage);
        let record = serde_json::to_value(&prepared).unwrap();
        let (_, review) = decode(
            &serde_json::to_vec(&vec![&record]).unwrap(),
            signer,
            &prepared.intent,
        )
        .unwrap();
        assert!(
            review
                .fields
                .iter()
                .any(|field| field.path == "Call 1 · Amount" && field.value.contains("2.5"))
        );
        assert!(
            review
                .warnings
                .iter()
                .any(|warning| warning.contains("Call 2 is not independently decoded"))
        );
        let mut changed = record.clone();
        changed["preimage"]["calls"][0]["value"] = json!("1");
        assert!(
            decode(
                &serde_json::to_vec(&vec![changed]).unwrap(),
                signer,
                &prepared.intent
            )
            .is_err()
        );
        let mut changed = record;
        changed["preimage"]["calls"][0]["data"] = json!("0xdeadbeef");
        assert!(
            decode(
                &serde_json::to_vec(&vec![changed]).unwrap(),
                signer,
                &prepared.intent
            )
            .is_err()
        );
    }
}
