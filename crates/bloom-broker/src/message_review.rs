//! Rebuild message preimages before displaying independently bound fields.
//! Petal labels and unused JSON members never become review facts.
use alloy::primitives::{Address, keccak256};
use alloy_dyn_abi::{DynSolValue, eip712::TypedData};
use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalSelector, ApprovalSubject, CryptoSuite, Digest32,
    ProtocolError, ProtocolErrorCode,
};
use bloom_evm_clear_signing::{TokenIdentity, format_base_units};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const SCHEMA: &str = "bloom.message.review.v1";
const MAX_FIELDS: usize = 256;
const MAX_DEPTH: usize = 12;

mod hyperliquid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageReview {
    pub kind: String,
    pub title: String,
    pub signer: String,
    pub payload_keccak: String,
    pub domain: Vec<MessageField>,
    pub fields: Vec<MessageField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<PaymentReview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub venue_asset: Option<VenueAssetReview>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VenueAssetReview {
    pub asset_id: String,
    pub name: String,
    pub symbol: String,
    pub environment: String,
    pub amount_display: String,
    pub base_units: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageField {
    pub path: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentReview {
    pub chain_id: String,
    pub token_address: String,
    pub from: String,
    pub recipient: String,
    pub amount: String,
    pub amount_display: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenIdentity>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Envelope {
    Eip712 {
        schema: String,
        typed_data: Value,
    },
    Personal {
        schema: String,
        message: String,
    },
    HyperliquidL1 {
        schema: String,
        network: String,
        action: Value,
        nonce: u64,
        vault_address: Option<String>,
        expires_after: Option<u64>,
    },
}

fn invalid(message: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::SelectorMismatch, message)
}

fn bounded(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), ProtocolError> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > 4096 {
        return Err(invalid("message review exceeds its structural bounds"));
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if key.is_empty()
                    || key.len() > 128
                    || !key
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b':')
                {
                    return Err(invalid("message review has an invalid property name"));
                }
                bounded(value, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_FIELDS {
                return Err(invalid("message review array exceeds its bound"));
            }
            for value in values {
                bounded(value, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.len() > 8192 => {
            return Err(invalid("message review string exceeds its bound"));
        }
        _ => {}
    }
    Ok(())
}

fn type_graph(types: &Value, name: &str, stack: &mut Vec<String>) -> Result<usize, ProtocolError> {
    let Some(properties) = types.get(name) else {
        return Ok(1);
    };
    if stack.len() >= MAX_DEPTH || stack.iter().any(|seen| seen == name) {
        return Err(invalid(
            "message types are recursive or exceed the depth bound",
        ));
    }
    let properties = properties
        .as_array()
        .ok_or_else(|| invalid("message type is not a field list"))?;
    if properties.len() > 64 {
        return Err(invalid("message type has too many fields"));
    }
    stack.push(name.to_owned());
    let mut names = std::collections::BTreeSet::new();
    let mut size = 1usize;
    for property in properties {
        let property = property
            .as_object()
            .ok_or_else(|| invalid("invalid typed field"))?;
        if property.len() != 2 {
            return Err(invalid("typed fields require only name and type"));
        }
        let field = property
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("typed field has no name"))?;
        if field.is_empty()
            || !field
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
            || !names.insert(field)
        {
            return Err(invalid("typed field names are invalid or duplicated"));
        }
        let ty = property
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("typed field has no type"))?;
        let base = ty.split('[').next().unwrap_or(ty);
        size = size.saturating_add(type_graph(types, base, stack)?);
        if size > 1024 {
            return Err(invalid("expanded message type exceeds its bound"));
        }
    }
    stack.pop();
    Ok(size)
}

/// Only walk the typed, coerced values. Extra unsigned JSON fields are errors,
/// not extra words the caller can place beside a legitimate signature hash.
fn fields(
    value: &DynSolValue,
    raw: &Value,
    path: &str,
    output: &mut Vec<MessageField>,
    depth: usize,
) -> Result<(), ProtocolError> {
    if depth > MAX_DEPTH || output.len() >= MAX_FIELDS {
        return Err(invalid("decoded message exceeds its display bound"));
    }
    match value {
        DynSolValue::CustomStruct {
            prop_names, tuple, ..
        } => {
            let object = raw
                .as_object()
                .ok_or_else(|| invalid("typed struct is not an object"))?;
            if object.len() != prop_names.len() {
                return Err(invalid("message carries unsigned or missing struct fields"));
            }
            for (name, value) in prop_names.iter().zip(tuple) {
                let raw = object
                    .get(name)
                    .ok_or_else(|| invalid("message is missing a typed field"))?;
                let child = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                fields(value, raw, &child, output, depth + 1)?;
            }
        }
        DynSolValue::Array(values) | DynSolValue::FixedArray(values) => {
            let raw = raw
                .as_array()
                .ok_or_else(|| invalid("typed array is not an array"))?;
            if raw.len() != values.len() {
                return Err(invalid("typed array length mismatch"));
            }
            if values.is_empty() {
                output.push(MessageField {
                    path: path.into(),
                    value: "[]".into(),
                });
            }
            for (index, (value, raw)) in values.iter().zip(raw).enumerate() {
                fields(value, raw, &format!("{path}[{index}]"), output, depth + 1)?;
            }
        }
        value => {
            let value = match value {
                DynSolValue::Address(value) => format!("{value:#x}"),
                DynSolValue::Uint(value, _) => value.to_string(),
                DynSolValue::Int(value, _) => value.to_string(),
                DynSolValue::Bool(value) => value.to_string(),
                DynSolValue::FixedBytes(value, width) => {
                    format!("0x{}", hex::encode(&value[..*width]))
                }
                DynSolValue::Bytes(value) => format!("0x{}", hex::encode(value)),
                DynSolValue::String(value) => escaped(value),
                _ => return Err(invalid("unsupported message value")),
            };
            output.push(MessageField {
                path: path.into(),
                value,
            });
        }
    }
    Ok(())
}

fn escaped(text: &str) -> String {
    text.chars().map(|c| {
        if c.is_control() || matches!(c, '\u{00ad}' | '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}') {
            format!("\\u{{{:04x}}}", c as u32)
        } else { c.to_string() }
    }).collect()
}

// A structured reading of the signed text, not a claim that a website owns
// the named domain. Anything outside this grammar stays a complete message.
fn login_fields(
    message: &str,
    signer: Address,
) -> Result<Option<Vec<MessageField>>, ProtocolError> {
    let lines: Vec<_> = message.split('\n').collect();
    let Some(domain) = lines[0].strip_suffix(" wants you to sign in with your Ethereum account:")
    else {
        return Ok(None);
    };
    if lines.len() < 10
        || domain.is_empty()
        || !domain.is_ascii()
        || domain.contains(char::is_whitespace)
        || !lines[2].is_empty()
    {
        return Ok(None);
    }
    let account = lines[1]
        .parse::<Address>()
        .map_err(|_| invalid("login message has an invalid account"))?;
    if account != signer {
        return Err(invalid(
            "login account differs from the approved signing account",
        ));
    }
    let Some(start) = lines.iter().position(|line| line.starts_with("URI: ")) else {
        return Ok(None);
    };
    if start < 3 || !lines[start - 1].is_empty() {
        return Ok(None);
    }
    let mut output = vec![
        MessageField {
            path: "Website named in message".into(),
            value: escaped(domain),
        },
        MessageField {
            path: "Account".into(),
            value: format!("{account:#x}"),
        },
    ];
    if start > 4 {
        output.push(MessageField {
            path: "Statement".into(),
            value: escaped(&lines[3..start - 1].join("\n")),
        });
    }
    let required = ["URI", "Version", "Chain ID", "Nonce", "Issued At"];
    let optional = ["Expiration Time", "Not Before", "Request ID"];
    let mut index = start;
    for name in required {
        let Some(value) = lines
            .get(index)
            .and_then(|line| line.strip_prefix(&format!("{name}: ")))
        else {
            return Ok(None);
        };
        if value.is_empty()
            || (name == "Version" && value != "1")
            || (name == "Chain ID" && value.parse::<u64>().is_err())
            || (name == "Nonce"
                && (value.len() < 8 || !value.bytes().all(|b| b.is_ascii_alphanumeric())))
        {
            return Ok(None);
        }
        output.push(MessageField {
            path: name.into(),
            value: escaped(value),
        });
        index += 1;
    }
    for name in optional {
        if let Some(value) = lines
            .get(index)
            .and_then(|line| line.strip_prefix(&format!("{name}: ")))
        {
            output.push(MessageField {
                path: name.into(),
                value: escaped(value),
            });
            index += 1;
        }
    }
    if lines.get(index) == Some(&"Resources:") {
        index += 1;
        for line in &lines[index..] {
            let Some(value) = line.strip_prefix("- ") else {
                return Ok(None);
            };
            output.push(MessageField {
                path: "Resource".into(),
                value: escaped(value),
            });
            index += 1;
        }
    }
    if index != lines.len() || output.len() > MAX_FIELDS {
        return Ok(None);
    }
    Ok(Some(output))
}

fn decode(bytes: &[u8], signer: Address) -> Result<(Vec<u8>, MessageReview), ProtocolError> {
    if bytes.len() > bloom_broker_api::SINGLE_PAYLOAD_MAX_BYTES {
        return Err(invalid("message review envelope exceeds its size bound"));
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid message review envelope"))?;
    let mut review = MessageReview { kind: String::new(), title: String::new(), signer: format!("{signer:#x}"),
        payload_keccak: String::new(), domain: Vec::new(), fields: Vec::new(), payment: None, venue_asset: None,
        warnings: vec!["Bloom verified the signed fields, not their execution effects or the identity of an unlisted application.".into()] };
    let preimage = match envelope {
        Envelope::HyperliquidL1 {
            schema,
            network,
            action,
            nonce,
            vault_address,
            expires_after,
        } => {
            if schema != SCHEMA {
                return Err(invalid("unsupported message review schema"));
            }
            bounded(&action, 0, &mut 0)?;
            let (typed_data, fields, title) = hyperliquid::rebuild(
                &network,
                action,
                nonce,
                vault_address.as_deref(),
                expires_after,
            )?;
            let nested = serde_json::to_vec(
                &serde_json::json!({"schema":SCHEMA,"kind":"eip712","typed_data":typed_data}),
            )
            .map_err(|_| invalid("cannot encode reconstructed exchange message"))?;
            let (preimage, mut review) = decode(&nested, signer)?;
            review.kind = "hyperliquid_l1".into();
            review.title = title;
            review.fields = fields;
            review.warnings.push("Bloom rebuilt the exchange action's MessagePack commitment. Market IDs, order bounds and fees are signed; Bloom has not checked market identity, available balance, fills or venue execution.".into());
            return Ok((preimage, review));
        }
        Envelope::Eip712 { schema, typed_data } => {
            if schema != SCHEMA {
                return Err(invalid("unsupported message review schema"));
            }
            bounded(&typed_data, 0, &mut 0)?;
            let root = typed_data
                .as_object()
                .ok_or_else(|| invalid("typed data must be an object"))?;
            if root.len() != 4
                || !["domain", "types", "primaryType", "message"]
                    .iter()
                    .all(|key| root.contains_key(*key))
            {
                return Err(invalid(
                    "typed data requires only domain, types, primaryType and message",
                ));
            }
            let types = root["types"]
                .as_object()
                .ok_or_else(|| invalid("message types must be an object"))?;
            if types.len() > 32 {
                return Err(invalid("too many message types"));
            }
            for name in types.keys() {
                type_graph(&root["types"], name, &mut Vec::new())?;
            }
            let domain = root["domain"]
                .as_object()
                .ok_or_else(|| invalid("message domain must be an object"))?;
            if domain.keys().any(|key| {
                !["name", "version", "chainId", "verifyingContract", "salt"].contains(&key.as_str())
            }) {
                return Err(invalid("domain carries unsigned fields"));
            }
            let typed: TypedData = serde_json::from_value(typed_data.clone())
                .map_err(|_| invalid("invalid EIP-712 typed data"))?;
            if typed.domain.chain_id.is_none() {
                review.warnings.push("The signing domain contains no chain ID; this signature is not bound to one network.".into());
            }
            review.kind = "eip712".into();
            review.title = "Sign typed data".into();
            review.domain.push(MessageField {
                path: "primaryType".into(),
                value: typed.primary_type.clone(),
            });
            let normalized = serde_json::to_value(&typed.domain)
                .map_err(|_| invalid("invalid EIP-712 domain"))?;
            for (key, value) in normalized
                .as_object()
                .ok_or_else(|| invalid("invalid EIP-712 domain"))?
            {
                review.domain.push(MessageField {
                    path: key.clone(),
                    value: escaped(
                        value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string())
                            .as_str(),
                    ),
                });
            }
            let mut preimage = vec![0x19, 0x01];
            preimage.extend_from_slice(typed.domain.separator().as_slice());
            if typed.primary_type == "EIP712Domain" {
                if root["message"]
                    .as_object()
                    .is_none_or(|message| !message.is_empty())
                {
                    return Err(invalid("domain-only signing cannot carry message fields"));
                }
            } else {
                let value = typed
                    .coerce()
                    .map_err(|_| invalid("message does not match its declared type"))?;
                fields(&value, &root["message"], "", &mut review.fields, 0)?;
                preimage.extend_from_slice(
                    typed
                        .hash_struct()
                        .map_err(|_| invalid("cannot hash typed message"))?
                        .as_slice(),
                );
                review.payment = payment(&typed, &value, signer)?;
                if review.payment.is_some() {
                    review.title = "Authorize a token payment".into();
                }
                hyperliquid::decorate(&typed, &mut review);
            }
            preimage
        }
        Envelope::Personal { schema, message } => {
            if schema != SCHEMA || message.len() > 8192 {
                return Err(invalid("invalid personal-message envelope"));
            }
            review.kind = "personal".into();
            review.title = "Sign a personal message".into();
            review.fields.push(MessageField {
                path: "message".into(),
                value: escaped(&message),
            });
            if let Some(fields) = login_fields(&message, signer)? {
                review.kind = "siwe".into();
                review.title = "Sign a login request".into();
                review.fields = fields;
                review.warnings.push("The website and URI are statements in the signed message; Bloom has not authenticated the website or established this session's permissions.".into());
            }
            let mut preimage =
                format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
            preimage.extend_from_slice(message.as_bytes());
            preimage
        }
    };
    review.payload_keccak = format!("0x{}", hex::encode(keccak256(&preimage)));
    Ok((preimage, review))
}

fn payment(
    typed: &TypedData,
    value: &DynSolValue,
    signer: Address,
) -> Result<Option<PaymentReview>, ProtocolError> {
    if !matches!(
        typed.primary_type.as_str(),
        "TransferWithAuthorization" | "ReceiveWithAuthorization"
    ) {
        return Ok(None);
    }
    let expected = format!(
        "{}(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
        typed.primary_type
    );
    if typed
        .encode_type()
        .map_err(|_| invalid("invalid payment type"))?
        != expected
    {
        return Ok(None);
    }
    let DynSolValue::CustomStruct { tuple, .. } = value else {
        return Err(invalid("payment must be a typed struct"));
    };
    let [
        DynSolValue::Address(from),
        DynSolValue::Address(to),
        DynSolValue::Uint(amount, _),
        DynSolValue::Uint(after, _),
        DynSolValue::Uint(before, _),
        DynSolValue::FixedBytes(nonce, 32),
    ] = tuple.as_slice()
    else {
        return Err(invalid("invalid payment fields"));
    };
    if *from != signer {
        return Err(invalid(
            "payment authorizer differs from the approved signing account",
        ));
    }
    let Some(chain) = typed
        .domain
        .chain_id
        .and_then(|chain| u64::try_from(chain).ok())
    else {
        return Ok(None);
    };
    let Some(contract) = typed.domain.verifying_contract else {
        return Ok(None);
    };
    let address = format!("{contract:#x}");
    let token = bloom_broker_api::tokens_on(chain)
        .find(|token| token.address == address)
        .map(|token| TokenIdentity {
            address: token.address.clone(),
            symbol: token.symbol.clone(),
            name: token.name.clone(),
            decimals: token.decimals,
        });
    let display = token
        .as_ref()
        .map(|token| {
            format!(
                "{} {}",
                format_base_units(&amount.to_string(), token.decimals),
                token.symbol
            )
        })
        .unwrap_or_else(|| format!("{amount} raw units"));
    if *before <= *after {
        return Err(invalid("payment validity interval is empty"));
    }
    Ok(Some(PaymentReview {
        chain_id: chain.to_string(),
        token_address: address,
        from: format!("{from:#x}"),
        recipient: format!("{to:#x}"),
        amount: amount.to_string(),
        amount_display: display,
        valid_after: after.to_string(),
        valid_before: before.to_string(),
        nonce: format!("{nonce:#x}"),
        token,
    }))
}

pub(crate) fn review(
    request: &ApprovalPrepareRequest,
    signer: Address,
) -> Result<Option<MessageReview>, ProtocolError> {
    if request.message_review_payloads.is_empty() {
        return Ok(None);
    }
    if !matches!(request.terms.subject, ApprovalSubject::Petal { .. })
        || !request.evm_review_payloads.is_empty()
        || !request.safe_review_payloads.is_empty()
    {
        return Err(invalid(
            "message review requires its own exact Petal approval",
        ));
    }
    let ApprovalSelector::Exact {
        ordered_payload_digests,
        ordered_hashes,
    } = &request.terms.selector
    else {
        return Err(invalid("message review requires an exact selector"));
    };
    if request.terms.allowed_crypto_suites != [CryptoSuite::Secp256k1Keccak256Recoverable]
        || request.message_review_payloads.len() != 1
        || ordered_payload_digests.len() != 1
        || ordered_hashes.len() != 1
    {
        return Err(invalid(
            "message review requires one recoverable secp256k1 payload",
        ));
    }
    let (preimage, review) = decode(&request.message_review_payloads[0].decode(), signer)?;
    if Digest32::from_bytes(Sha256::digest(&preimage).into()) != ordered_payload_digests[0]
        || Digest32::from_bytes(keccak256(&preimage).0) != ordered_hashes[0]
    {
        return Err(invalid(
            "message review differs from the exact approved payload",
        ));
    }
    validate_petal_profile(request, &review)?;
    Ok(Some(review))
}

fn validate_petal_profile(
    request: &ApprovalPrepareRequest,
    review: &MessageReview,
) -> Result<(), ProtocolError> {
    let Some(claim) = &request.petal_use_claim else {
        return Ok(());
    };
    let class = claim.operation_class.as_str();
    if let Some(primary) = match class {
        "hyperliquid.approve_agent" => Some("HyperliquidTransaction:ApproveAgent"),
        "hyperliquid.usd_send" => Some("HyperliquidTransaction:UsdSend"),
        "hyperliquid.usd_class_transfer" => Some("HyperliquidTransaction:UsdClassTransfer"),
        "hyperliquid.withdraw" => Some("HyperliquidTransaction:Withdraw"),
        _ => None,
    } {
        if review.kind != "hyperliquid_user"
            || !review
                .domain
                .iter()
                .any(|field| field.path == "primaryType" && field.value == primary)
        {
            return Err(invalid(
                "Hyperliquid operation differs from the independently read signed message",
            ));
        }
        hyperliquid::validate_payment(request, review, class)?;
    }
    if let Some(action) = match class {
        "hyperliquid.order" => Some("order"),
        "hyperliquid.cancel" => Some("cancel"),
        "hyperliquid.cancel_by_cloid" => Some("cancelByCloid"),
        "hyperliquid.schedule_cancel" => Some("scheduleCancel"),
        "hyperliquid.update_leverage" => Some("updateLeverage"),
        _ => None,
    } {
        if review.kind != "hyperliquid_l1"
            || !review
                .fields
                .iter()
                .any(|field| field.path == "Action" && field.value == action)
        {
            return Err(invalid(
                "Hyperliquid operation differs from its MessagePack action",
            ));
        }
    }
    let needs_payment = match class {
        "gasless.relay" => true,
        "venice-x402.topup" => review.kind != "siwe",
        "venice-x402.chat" | "venice-x402.balance" => {
            if review.kind != "siwe" {
                return Err(invalid("Venice login requires a signed login message"));
            }
            false
        }
        _ => false,
    };
    if !needs_payment {
        return Ok(());
    }
    let payment = review.payment.as_ref().ok_or_else(|| {
        invalid("This payment operation requires a canonical ERC-3009 authorization")
    })?;
    let chain: u64 = payment
        .chain_id
        .parse()
        .map_err(|_| invalid("invalid payment chain"))?;
    let matches_chain = |name: &str| {
        name == format!("evm-{chain}")
            || name == crate::evm_review::chain_name(chain)
            || (chain == 43114 && name == "avalanche")
    };
    let [debit] = claim.declared_debits.as_slice() else {
        return Err(invalid("Payment claim must declare its exact token debit"));
    };
    if !matches_chain(debit.asset.chain.as_str())
        || !debit
            .asset
            .asset
            .eq_ignore_ascii_case(&payment.token_address)
        || debit.amount.as_str() != payment.amount
    {
        return Err(invalid(
            "Payment claim debit differs from the signed authorization",
        ));
    }
    if !request
        .terms
        .limits
        .value_limits
        .iter()
        .any(|limit| limit.asset == debit.asset && limit.lifetime.as_str() == payment.amount)
    {
        return Err(invalid(
            "Payment approval must account for its exact signed token amount",
        ));
    }
    if class == "venice-x402.topup"
        && (claim.declared_destinations.len() != 1
            || !matches_chain(claim.declared_destinations[0].chain.as_str())
            || !claim.declared_destinations[0]
                .destination
                .eq_ignore_ascii_case(&payment.recipient))
    {
        return Err(invalid(
            "Payment claim recipient differs from the signed authorization",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::{
        ActivationMode, ApprovalLimits, Base64UrlBytes, DecimalU64, KeyRef, KeySpec, OperationId,
        RequestNonce, SealedApprovalTerms, Token,
    };
    use serde_json::json;

    fn signer() -> Address {
        Address::with_last_byte(7)
    }

    fn payment_data() -> Value {
        json!({
            "types": {
                "EIP712Domain": [{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
                "TransferWithAuthorization": [{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"validAfter","type":"uint256"},{"name":"validBefore","type":"uint256"},{"name":"nonce","type":"bytes32"}]
            },
            "primaryType":"TransferWithAuthorization",
            "domain":{"name":"USD Coin","version":"2","chainId":8453,"verifyingContract":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"},
            "message":{"from":format!("{:#x}",signer()),"to":"0x0000000000000000000000000000000000000008","value":"2500000","validAfter":"0","validBefore":"2000000000","nonce":format!("0x{}","11".repeat(32))}
        })
    }

    fn envelope(data: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema":SCHEMA,"kind":"eip712","typed_data":data})).unwrap()
    }

    fn request(bytes: Vec<u8>) -> ApprovalPrepareRequest {
        let (preimage, _) = decode(&bytes, signer()).unwrap();
        let digest = Digest32::from_bytes([1; 32]);
        let token = |name: &str| Token::new(name).unwrap();
        ApprovalPrepareRequest {
            operation_id: OperationId::from_bytes([2; 32]),
            surface_selection: bloom_broker_api::CeremonySurfaceSelection::Default,
            canonical_plan_facts_digest: digest.clone(),
            message_review_payloads: vec![Base64UrlBytes::from_bytes(&bytes)],
            evm_review_payloads: vec![],
            safe_review_payloads: vec![],
            evm_reported_token: None,
            petal_use_claim: None,
            system_use_claim: None,
            terms: SealedApprovalTerms {
                subject: ApprovalSubject::Petal {
                    package_hash: digest.clone(),
                    route: "payment/a/0/confirm".into(),
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

    #[test]
    fn payment_units_and_identity_come_from_the_exact_domain_contract() {
        let (_, review) = decode(&envelope(payment_data()), signer()).unwrap();
        let payment = review.payment.unwrap();
        assert_eq!(payment.amount_display, "2.5 USDC");
        assert_eq!(
            payment.token.unwrap().address,
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        );
        let mut unknown = payment_data();
        unknown["domain"]["verifyingContract"] =
            json!("0x0000000000000000000000000000000000000009");
        let (_, review) = decode(&envelope(unknown), signer()).unwrap();
        let payment = review.payment.unwrap();
        assert!(payment.token.is_none());
        assert_eq!(payment.amount_display, "2500000 raw units");
    }

    #[test]
    fn payment_owner_and_validity_cannot_be_relabelled() {
        let mut wrong = payment_data();
        wrong["message"]["from"] = json!("0x0000000000000000000000000000000000000009");
        assert!(decode(&envelope(wrong), signer()).is_err());
        let mut wrong = payment_data();
        wrong["message"]["validBefore"] = json!("0");
        assert!(decode(&envelope(wrong), signer()).is_err());
    }

    #[test]
    fn known_payment_claims_must_account_for_the_signed_amount_and_recipient() {
        use bloom_broker_api::{
            AssetId, ClaimAssurance, DecimalU256, DeclaredDebit, DeclaredDestination, DeclaredFee,
            PetalUseClaim, ValueLimit,
        };
        let mut request = request(envelope(payment_data()));
        let asset = AssetId {
            chain: Token::new("base").unwrap(),
            asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
        };
        let amount = DecimalU256::parse("2500000").unwrap();
        request.terms.limits.value_limits = vec![ValueLimit {
            asset: asset.clone(),
            lifetime: amount.clone(),
            rolling_windows: vec![],
        }];
        request.petal_use_claim = Some(PetalUseClaim {
            package_hash: Digest32::from_bytes([1; 32]),
            route: "payment/a/0/confirm".into(),
            operation_class: Token::new("venice-x402.topup").unwrap(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: Digest32::from_bytes([2; 32]),
            ordered_hashes: vec![],
            declared_debits: vec![DeclaredDebit { asset, amount }],
            declared_destinations: vec![DeclaredDestination {
                chain: Token::new("base").unwrap(),
                destination: "0x0000000000000000000000000000000000000008".into(),
            }],
            declared_fee: DeclaredFee::None,
            nonce: RequestNonce::from_bytes([3; 16]),
            claim_assurance: ClaimAssurance::MachineAsserted,
        });
        assert!(review(&request, signer()).unwrap().is_some());
        let mut wrong = request.clone();
        wrong
            .petal_use_claim
            .as_mut()
            .unwrap()
            .declared_debits
            .clear();
        assert!(review(&wrong, signer()).is_err());
        let mut wrong = request.clone();
        wrong.petal_use_claim.as_mut().unwrap().declared_debits[0].amount =
            DecimalU256::parse("1").unwrap();
        assert!(review(&wrong, signer()).is_err());
        let mut wrong = request.clone();
        wrong
            .petal_use_claim
            .as_mut()
            .unwrap()
            .declared_destinations[0]
            .destination = format!("{:#x}", Address::ZERO);
        assert!(review(&wrong, signer()).is_err());
        let mut wrong = request.clone();
        wrong.terms.limits.value_limits.clear();
        assert!(review(&wrong, signer()).is_err());
        request.petal_use_claim.as_mut().unwrap().operation_class =
            Token::new("venice-x402.chat").unwrap();
        assert!(review(&request, signer()).is_err());
    }

    #[test]
    fn unsigned_extra_message_and_domain_fields_are_rejected() {
        for section in ["message", "domain"] {
            let mut wrong = payment_data();
            wrong[section]["displayAmount"] = json!("0.01 USDC");
            assert!(decode(&envelope(wrong), signer()).is_err());
        }
    }

    #[test]
    fn changed_amount_nonce_or_domain_does_not_match_the_exact_selector() {
        let original = request(envelope(payment_data()));
        assert!(review(&original, signer()).unwrap().is_some());
        for (section, key, value) in [
            ("message", "value", json!("2500001")),
            ("message", "nonce", json!(format!("0x{}", "22".repeat(32)))),
            ("domain", "chainId", json!(1)),
        ] {
            let mut altered = payment_data();
            altered[section][key] = value;
            let mut request = original.clone();
            request.message_review_payloads = vec![Base64UrlBytes::from_bytes(&envelope(altered))];
            assert!(review(&request, signer()).is_err());
        }
    }

    #[test]
    fn duplicate_or_recursive_types_are_not_displayable_messages() {
        let mut duplicate = payment_data();
        duplicate["types"]["TransferWithAuthorization"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"value","type":"uint256"}));
        assert!(decode(&envelope(duplicate), signer()).is_err());
        let mut cycle = payment_data();
        cycle["types"]["Loop"] = json!([{"name":"next","type":"Loop"}]);
        assert!(decode(&envelope(cycle), signer()).is_err());
    }

    #[test]
    fn exchange_action_review_binds_every_order_and_envelope_parameter() {
        let envelope = json!({"schema":SCHEMA,"kind":"hyperliquid_l1","network":"mainnet", "nonce":123,
            "vault_address":"0x0000000000000000000000000000000000000003", "expires_after":999999,
            "action":{"type":"order","orders":[{"a":0,"b":true,"p":"100","s":"0.01","r":false,"t":{"limit":{"tif":"Gtc"}}}],"grouping":"na"}});
        let original = request(serde_json::to_vec(&envelope).unwrap());
        let reading = review(&original, signer()).unwrap().unwrap();
        assert_eq!(reading.kind, "hyperliquid_l1");
        assert_eq!(
            reading.payload_keccak,
            "0xd1d31414c406d9f99e01134e80157b5ef8ff36b0e554935a6a526134ac111438"
        );
        for (path, value) in [
            ("/nonce", json!(124)),
            ("/expires_after", json!(999998)),
            ("/network", json!("testnet")),
            (
                "/vault_address",
                json!("0x0000000000000000000000000000000000000004"),
            ),
            ("/action/orders/0/b", json!(false)),
            ("/action/orders/0/p", json!("101")),
        ] {
            let mut changed = envelope.clone();
            *changed.pointer_mut(path).unwrap() = value;
            let mut request = original.clone();
            request.message_review_payloads = vec![Base64UrlBytes::from_bytes(
                &serde_json::to_vec(&changed).unwrap(),
            )];
            assert!(review(&request, signer()).is_err(), "{path}");
        }
    }

    #[test]
    fn agent_permissions_are_read_only_for_the_exact_hyperliquid_domain_and_type() {
        let data = json!({"types":{
            "EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
            "HyperliquidTransaction:ApproveAgent":[{"name":"hyperliquidChain","type":"string"},{"name":"agentAddress","type":"address"},{"name":"agentName","type":"string"},{"name":"nonce","type":"uint64"}]},
            "primaryType":"HyperliquidTransaction:ApproveAgent", "domain":{"name":"HyperliquidSignTransaction","version":"1","chainId":421614,"verifyingContract":format!("{:#x}",Address::ZERO)},
            "message":{"hyperliquidChain":"Mainnet","agentAddress":format!("{:#x}",Address::with_last_byte(8)),"agentName":"My agent","nonce":123}});
        let (_, reading) = decode(&envelope(data.clone()), signer()).unwrap();
        assert_eq!(reading.kind, "hyperliquid_user");
        assert!(
            reading
                .fields
                .iter()
                .any(|field| field.path == "Venue permission"
                    && field.value.contains("no spending ceiling"))
        );
        for (key, value) in [
            ("chainId", json!(1)),
            ("name", json!("Lookalike application")),
        ] {
            let mut altered = data.clone();
            altered["domain"][key] = value;
            let (_, reading) = decode(&envelope(altered), signer()).unwrap();
            assert_eq!(reading.kind, "eip712");
        }
    }

    #[test]
    fn personal_message_prefix_counts_utf8_bytes_and_direction_controls_are_visible() {
        let bytes =
            serde_json::to_vec(&json!({"schema":SCHEMA,"kind":"personal","message":"é\u{202e}"}))
                .unwrap();
        let (preimage, review) = decode(&bytes, signer()).unwrap();
        assert!(preimage.starts_with(b"\x19Ethereum Signed Message:\n5"));
        assert_eq!(review.fields[0].value, "é\\u{202e}");
    }

    #[test]
    fn login_fields_are_signed_and_wrong_account_is_refused() {
        let message = format!(
            "api.venice.ai wants you to sign in with your Ethereum account:\n{:#x}\n\nSign in to Venice AI\n\nURI: https://api.venice.ai/api/v1/chat/completions\nVersion: 1\nChain ID: 8453\nNonce: 1234abcd\nIssued At: 2026-10-18T12:00:00Z\nExpiration Time: 2026-10-18T12:05:00Z",
            signer()
        );
        let envelope = |message| {
            serde_json::to_vec(&json!({"schema":SCHEMA,"kind":"personal","message":message}))
                .unwrap()
        };
        let original = request(envelope(message.clone()));
        let result = review(&original, signer()).unwrap().unwrap();
        assert_eq!(result.kind, "siwe");
        assert!(
            result
                .fields
                .iter()
                .any(|field| field.path == "Nonce" && field.value == "1234abcd")
        );
        let mut changed = original;
        changed.message_review_payloads = vec![Base64UrlBytes::from_bytes(&envelope(
            message.replace("1234abcd", "1234abce"),
        ))];
        assert!(review(&changed, signer()).is_err());
        assert!(
            decode(
                &envelope(message.replace(
                    &format!("{:#x}", signer()),
                    &format!("{:#x}", Address::with_last_byte(8))
                )),
                signer()
            )
            .is_err()
        );
        let (_, fallback) = decode(
            &envelope(format!("{message}\nUnsigned-looking extra text")),
            signer(),
        )
        .unwrap();
        assert_eq!(fallback.kind, "personal");
        assert!(
            fallback.fields[0]
                .value
                .ends_with("Unsigned-looking extra text")
        );
    }

    #[test]
    fn message_reviews_cannot_be_reused_for_batches_other_suites_or_other_payloads() {
        let original = request(envelope(payment_data()));
        let mut mixed = original.clone();
        mixed
            .evm_review_payloads
            .push(Base64UrlBytes::from_bytes(b"transaction"));
        assert!(review(&mixed, signer()).is_err());
        let mut batch = original.clone();
        batch
            .message_review_payloads
            .push(batch.message_review_payloads[0].clone());
        assert!(review(&batch, signer()).is_err());
        let mut suite = original.clone();
        suite.terms.allowed_crypto_suites = vec![CryptoSuite::Ed25519Message];
        assert!(review(&suite, signer()).is_err());
        let mut digest = original;
        let ApprovalSelector::Exact {
            ordered_payload_digests,
            ..
        } = &mut digest.terms.selector
        else {
            unreachable!()
        };
        ordered_payload_digests[0] = Digest32::from_bytes([0; 32]);
        assert!(review(&digest, signer()).is_err());
    }

    #[test]
    fn published_eip712_mail_vector_matches_and_nested_fields_are_bound() {
        let data = json!({"types":{
            "EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
            "Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],
            "Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},
            "primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
            "message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}});
        let (_, review) = decode(&envelope(data.clone()), signer()).unwrap();
        assert_eq!(
            review.payload_keccak,
            "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
        assert!(
            review
                .fields
                .iter()
                .any(|field| field.path == "from.wallet")
        );
        let mut wrong = data;
        wrong["message"]["from"]["pretend"] = json!("Unsigned text");
        assert!(decode(&envelope(wrong), signer()).is_err());
    }
}
