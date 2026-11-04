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
mod tempo;

/// Bind the generic review artifact to the actual bytes, without interpreting
/// or independently verifying the package's economic declaration.
pub(crate) fn verify_declared_use(
    request: &bloom_broker_api::MachineSignRequest,
    signer: Address,
) -> Result<(), ProtocolError> {
    if request.crypto_suite != CryptoSuite::Secp256k1Keccak256Recoverable {
        return Err(invalid(
            "generic typed review requires recoverable secp256k1",
        ));
    }
    let evidence = request
        .claim_assurance_evidence
        .as_ref()
        .ok_or_else(|| invalid("automatic signing requires the complete generic review artifact"))?
        .decode();
    let envelope: Envelope = serde_json::from_slice(&evidence)
        .map_err(|_| invalid("invalid generic review artifact"))?;
    if !matches!(
        envelope,
        Envelope::Eip712 { .. } | Envelope::Personal { .. }
    ) {
        return Err(invalid(
            "automatic signing requires a generic typed or personal message",
        ));
    }
    let (preimage, _) = decode(&evidence, signer)?;
    let payload = match &request.payloads {
        bloom_broker_api::SigningPayloads::Single { payload } => payload,
        bloom_broker_api::SigningPayloads::Batch { children } if children.len() == 1 => {
            &children[0]
        }
        _ => return Err(invalid("generic review binds exactly one signing payload")),
    };
    if payload.decode() != preimage {
        return Err(invalid("review artifact differs from actual signing bytes"));
    }
    Ok(())
}

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
    TempoTransaction {
        schema: String,
        transaction: String,
    },
    TempoVoucher {
        schema: String,
        chain_id: u64,
        escrow: String,
        channel_id: String,
        cumulative_amount: String,
        channel: Option<tempo::Channel>,
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
    decode_with_exchange_limit(bytes, signer, MAX_FIELDS)
}

fn decode_with_exchange_limit(
    bytes: &[u8],
    signer: Address,
    exchange_field_limit: usize,
) -> Result<(Vec<u8>, MessageReview), ProtocolError> {
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
                exchange_field_limit,
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
        Envelope::TempoTransaction {
            schema,
            transaction,
        } => {
            if schema != SCHEMA {
                return Err(invalid("unsupported message review schema"));
            }
            tempo::transaction(&transaction, signer, &mut review)?
        }
        Envelope::TempoVoucher {
            schema,
            chain_id,
            escrow,
            channel_id,
            cumulative_amount,
            channel,
        } => {
            if schema != SCHEMA {
                return Err(invalid("unsupported message review schema"));
            }
            tempo::voucher(
                chain_id,
                &escrow,
                &channel_id,
                &cumulative_amount,
                channel,
                signer,
                &mut review,
            )?
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
                    if typed.primary_type == PERMIT2_PRIMARY {
                        review.warnings.push("Permit2 collects this payment only if the wallet has already approved Permit2 to spend this token.".into());
                    }
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

const PERMIT2: Address = alloy::primitives::address!("000000000022D473030F116dDEE9F6B43aC78BA3");
/// The x402 exact Permit2 proxy. Its `settle` pays only `witness.to`, so
/// the witness recipient is the payee; any other spender could pay anyone.
const X402_PERMIT2_PROXY: Address =
    alloy::primitives::address!("402085c248EeA27D92E8b30b2C58ed07f9E20001");
const PERMIT2_PRIMARY: &str = "PermitWitnessTransferFrom";
const PERMIT2_TYPE: &str = "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)";

fn payment(
    typed: &TypedData,
    value: &DynSolValue,
    signer: Address,
) -> Result<Option<PaymentReview>, ProtocolError> {
    let primary = typed.primary_type.as_str();
    if !matches!(
        primary,
        "TransferWithAuthorization" | "ReceiveWithAuthorization" | PERMIT2_PRIMARY
    ) {
        return Ok(None);
    }
    let expected = if primary == PERMIT2_PRIMARY {
        PERMIT2_TYPE.to_owned()
    } else {
        format!(
            "{primary}(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        )
    };
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
    let chain = typed
        .domain
        .chain_id
        .and_then(|chain| u64::try_from(chain).ok());
    if primary == PERMIT2_PRIMARY {
        let [
            DynSolValue::CustomStruct {
                tuple: permitted, ..
            },
            DynSolValue::Address(spender),
            DynSolValue::Uint(nonce, _),
            DynSolValue::Uint(deadline, _),
            DynSolValue::CustomStruct { tuple: witness, .. },
        ] = tuple.as_slice()
        else {
            return Err(invalid("invalid Permit2 payment fields"));
        };
        let (
            [DynSolValue::Address(token), DynSolValue::Uint(amount, _)],
            [DynSolValue::Address(to), DynSolValue::Uint(after, _)],
        ) = (permitted.as_slice(), witness.as_slice())
        else {
            return Err(invalid("invalid Permit2 payment fields"));
        };
        let domain = &typed.domain;
        let Some(chain) = chain.filter(|_| {
            domain.name.as_deref() == Some("Permit2")
                && domain.version.is_none()
                && domain.salt.is_none()
                && domain.verifying_contract == Some(PERMIT2)
                && *spender == X402_PERMIT2_PROXY
        }) else {
            return Ok(None);
        };
        // Permit2 pulls the tokens from the signing account.
        return payment_review(
            chain,
            *token,
            signer,
            *to,
            *amount,
            (*after, *deadline),
            nonce.to_string(),
        )
        .map(Some);
    }
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
    let (Some(chain), Some(contract)) = (chain, typed.domain.verifying_contract) else {
        return Ok(None);
    };
    payment_review(
        chain,
        contract,
        *from,
        *to,
        *amount,
        (*after, *before),
        format!("{nonce:#x}"),
    )
    .map(Some)
}

fn payment_review(
    chain: u64,
    token_address: Address,
    from: Address,
    to: Address,
    amount: alloy::primitives::U256,
    (after, before): (alloy::primitives::U256, alloy::primitives::U256),
    nonce: String,
) -> Result<PaymentReview, ProtocolError> {
    if before <= after {
        return Err(invalid("payment validity interval is empty"));
    }
    let token = known_token(chain, token_address);
    Ok(PaymentReview {
        chain_id: chain.to_string(),
        token_address: format!("{token_address:#x}"),
        from: format!("{from:#x}"),
        recipient: format!("{to:#x}"),
        amount: amount.to_string(),
        amount_display: display_amount(&amount.to_string(), token.as_ref()),
        valid_after: after.to_string(),
        valid_before: before.to_string(),
        nonce,
        token,
    })
}

fn known_token(chain: u64, address: Address) -> Option<TokenIdentity> {
    let address = format!("{address:#x}");
    bloom_broker_api::tokens_on(chain)
        .find(|token| token.address == address)
        .map(|token| TokenIdentity {
            address: token.address.clone(),
            symbol: token.symbol.clone(),
            name: token.name.clone(),
            decimals: token.decimals,
        })
}

fn display_amount(base_units: &str, token: Option<&TokenIdentity>) -> String {
    token
        .map(|token| {
            format!(
                "{} {}",
                format_base_units(base_units, token.decimals),
                token.symbol
            )
        })
        .unwrap_or_else(|| format!("{base_units} raw units"))
}

pub(crate) fn review(
    request: &ApprovalPrepareRequest,
    signer: Address,
) -> Result<Option<MessageReview>, ProtocolError> {
    if request.message_review_payloads.is_empty() {
        return Ok(None);
    }
    let system_x402 = is_system_x402(&request.terms.subject);
    let system_mpp = is_system_mpp(&request.terms.subject);
    if !(system_x402
        || system_mpp
        || matches!(request.terms.subject, ApprovalSubject::Petal { .. }))
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
    let (preimage, mut review) = decode(&request.message_review_payloads[0].decode(), signer)?;
    if Digest32::from_bytes(Sha256::digest(&preimage).into()) != ordered_payload_digests[0]
        || Digest32::from_bytes(keccak256(&preimage).0) != ordered_hashes[0]
    {
        return Err(invalid(
            "message review differs from the exact approved payload",
        ));
    }
    if system_x402 && review.payment.is_none() {
        return Err(invalid(
            "Machine x402 approval requires an EIP-3009 payment authorization or a Permit2 transfer through the x402 Permit2 proxy; Broker cannot review other x402 payment forms",
        ));
    }
    // The approval subject, not the message, establishes that this is
    // Bloom Machine paying an x402 request, so the heading can say so.
    if system_x402 {
        review.title = "Authorize an x402 payment".into();
    }
    if system_mpp != review.kind.starts_with("tempo_") {
        return Err(invalid(if system_mpp {
            "Machine MPP approval requires a Tempo transaction or voucher review"
        } else {
            "Tempo payment reviews are only for Machine MPP approvals"
        }));
    }
    Ok(Some(review))
}

pub(crate) fn is_system_x402(subject: &ApprovalSubject) -> bool {
    matches!(subject, ApprovalSubject::System { operation_class, .. }
        if operation_class.as_str() == bloom_broker_api::SYSTEM_X402_OPERATION_CLASS)
}

pub(crate) fn is_system_mpp(subject: &ApprovalSubject) -> bool {
    matches!(subject, ApprovalSubject::System { operation_class, .. }
        if operation_class.as_str() == bloom_broker_api::SYSTEM_MPP_OPERATION_CLASS)
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

    pub(super) fn payment_data() -> Value {
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

    pub(super) fn envelope(data: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema":SCHEMA,"kind":"eip712","typed_data":data})).unwrap()
    }

    pub(super) fn request(bytes: Vec<u8>) -> ApprovalPrepareRequest {
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
                session_budget: None,
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
    fn generic_erc7739_typed_data_sign_matches_known_answers() {
        let fields = |signature: &str| {
            Value::Array(
                signature
                    .split(',')
                    .map(|field| {
                        let (kind, name) = field.split_once(' ').unwrap();
                        json!({"name":name,"type":kind})
                    })
                    .collect(),
            )
        };
        let wallet = "0x6c625c75652cf2cdf2bfe94ad59cb6f79b899a18";
        for (contract, expected) in [
            (
                "0xe111180000d2663c0091e4f400237545b87b996b",
                "ef5ec6a9a480c3a4f7bdf0b8a5dbf06c9fa11d7ad6a7b3273901528378fc0c36",
            ),
            (
                "0xe2222d279d744050d28e00520010520000310f59",
                "3f23a9ec3d94ca14672fa676310a174d8c1e2d43828754173c9c992d8ae3593e",
            ),
        ] {
            let data = json!({"domain":{"name":"Polymarket CTF Exchange","version":"2","chainId":137,"verifyingContract":contract},
            "types":{"EIP712Domain":fields("string name,string version,uint256 chainId,address verifyingContract"),
            "Order":fields("uint256 salt,address maker,address signer,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder"),
            "TypedDataSign":fields("Order contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt")},
            "primaryType":"TypedDataSign","message":{"contents":{"salt":"479249096354","maker":wallet,"signer":wallet,"tokenId":"7496871387824498705150337097986995704782987980926026827618928384721521953608","makerAmount":"11782400","takerAmount":"21040000","side":0,"signatureType":3,"timestamp":"1765432100000","metadata":format!("0x{}","00".repeat(32)),"builder":format!("0x{}","00".repeat(32))},"name":"DepositWallet","version":"1","chainId":137,"verifyingContract":wallet,"salt":format!("0x{}","00".repeat(32))}});
            let bytes = envelope(data.clone());
            let (preimage, _) = decode(&bytes, signer()).unwrap();
            assert_eq!(hex::encode(keccak256(preimage)), expected);
            review(&request(bytes.clone()), signer()).unwrap().unwrap();
            let mut changed = request(bytes);
            let mut changed_data = data;
            changed_data["message"]["contents"]["makerAmount"] = json!("11782401");
            changed.message_review_payloads =
                vec![Base64UrlBytes::from_bytes(&envelope(changed_data))];
            assert!(review(&changed, signer()).is_err());
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
    fn machine_x402_shows_the_signed_payment_and_refuses_relabels() {
        let system = |data: Value| {
            let mut request = request(envelope(data));
            request.terms.subject = ApprovalSubject::System {
                component_id: Token::new("bloom-machine").unwrap(),
                operation_class: Token::new(bloom_broker_api::SYSTEM_X402_OPERATION_CLASS).unwrap(),
            };
            request
        };
        let approved = system(payment_data());
        let reading = review(&approved, signer()).unwrap().unwrap();
        assert_eq!(reading.title, "Authorize an x402 payment");
        let payment = reading.payment.unwrap();
        assert_eq!(payment.amount_display, "2.5 USDC");
        assert_eq!(
            payment.recipient,
            "0x0000000000000000000000000000000000000008"
        );
        assert_eq!(payment.valid_before, "2000000000");
        for (section, key, value) in [
            ("message", "value", json!("2500001")),
            (
                "message",
                "to",
                json!("0x0000000000000000000000000000000000000009"),
            ),
            (
                "domain",
                "verifyingContract",
                json!("0x0000000000000000000000000000000000000009"),
            ),
            ("message", "validBefore", json!("2000000001")),
        ] {
            let mut relabelled = payment_data();
            relabelled[section][key] = value;
            let mut wrong = approved.clone();
            wrong.message_review_payloads = vec![Base64UrlBytes::from_bytes(&envelope(relabelled))];
            assert!(review(&wrong, signer()).is_err(), "{key}");
        }
        let mut other = payment_data();
        other["primaryType"] = json!("EIP712Domain");
        other["message"] = json!({});
        let error = review(&system(other), signer()).unwrap_err();
        assert!(error.message.contains("EIP-3009"), "{}", error.message);
    }

    fn system(bytes: Vec<u8>, class: &str) -> ApprovalPrepareRequest {
        let mut request = request(bytes);
        request.terms.subject = ApprovalSubject::System {
            component_id: Token::new("bloom-machine").unwrap(),
            operation_class: Token::new(class).unwrap(),
        };
        request
    }

    fn permit2_data() -> Value {
        json!({
            "types": {
                "EIP712Domain": [{"name":"name","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
                "PermitWitnessTransferFrom": [{"name":"permitted","type":"TokenPermissions"},{"name":"spender","type":"address"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"},{"name":"witness","type":"Witness"}],
                "TokenPermissions": [{"name":"token","type":"address"},{"name":"amount","type":"uint256"}],
                "Witness": [{"name":"to","type":"address"},{"name":"validAfter","type":"uint256"}]
            },
            "primaryType":"PermitWitnessTransferFrom",
            "domain":{"name":"Permit2","chainId":8453,"verifyingContract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"},
            "message":{"permitted":{"token":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","amount":"2500000"},
                "spender":"0x402085c248EeA27D92E8b30b2C58ed07f9E20001","nonce":"77","deadline":"2000000000",
                "witness":{"to":"0x0000000000000000000000000000000000000008","validAfter":"0"}}
        })
    }

    #[test]
    fn machine_x402_permit2_through_the_proxy_shows_the_witness_recipient() {
        let class = bloom_broker_api::SYSTEM_X402_OPERATION_CLASS;
        let approved = system(envelope(permit2_data()), class);
        let reading = review(&approved, signer()).unwrap().unwrap();
        let payment = reading.payment.as_ref().unwrap();
        assert_eq!(payment.amount_display, "2.5 USDC");
        assert_eq!(
            payment.recipient,
            "0x0000000000000000000000000000000000000008"
        );
        assert_eq!(payment.from, format!("{:#x}", signer()));
        assert_eq!(payment.valid_before, "2000000000");
        assert_eq!(payment.nonce, "77");
        assert!(
            reading
                .warnings
                .iter()
                .any(|w| w.contains("already approved Permit2"))
        );
        // Changed signed values no longer match the approved digests.
        for (path, value) in [
            ("/message/permitted/amount", json!("2500001")),
            (
                "/message/witness/to",
                json!("0x0000000000000000000000000000000000000009"),
            ),
            ("/message/deadline", json!("2000000001")),
        ] {
            let mut changed = permit2_data();
            *changed.pointer_mut(path).unwrap() = value;
            let mut wrong = approved.clone();
            wrong.message_review_payloads = vec![Base64UrlBytes::from_bytes(&envelope(changed))];
            assert!(review(&wrong, signer()).is_err(), "{path}");
        }
        // Not the canonical Permit2 payment: not a payment, so refused.
        let mut version = permit2_data();
        version["types"]["EIP712Domain"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"version","type":"string"}));
        version["domain"]["version"] = json!("1");
        let mut other_name = permit2_data();
        other_name["domain"]["name"] = json!("Permit3");
        for (path, value) in [
            (
                "/message/spender",
                json!("0x0000000000000000000000000000000000000009"),
            ),
            (
                "/domain/verifyingContract",
                json!("0x0000000000000000000000000000000000000009"),
            ),
        ] {
            let mut changed = permit2_data();
            *changed.pointer_mut(path).unwrap() = value;
            let error = review(&system(envelope(changed), class), signer()).unwrap_err();
            assert!(
                error.message.contains("Permit2 proxy"),
                "{path}: {}",
                error.message
            );
        }
        for changed in [version, other_name] {
            assert!(review(&system(envelope(changed), class), signer()).is_err());
        }
        let mut empty = permit2_data();
        empty["message"]["witness"]["validAfter"] = json!("2000000000");
        assert!(decode(&envelope(empty), signer()).is_err());
    }

    #[test]
    fn tempo_reviews_belong_only_to_machine_mpp_approvals() {
        let class = bloom_broker_api::SYSTEM_MPP_OPERATION_CLASS;
        let charge = serde_json::to_vec(&json!({"schema":SCHEMA,"kind":"tempo_transaction",
            "transaction":tempo::tests::CHARGE_UNSPONSORED_MEMO}))
        .unwrap();
        let reading = review(&system(charge.clone(), class), signer())
            .unwrap()
            .unwrap();
        assert_eq!(reading.kind, "tempo_transaction");
        let voucher = serde_json::to_vec(
            &json!({"schema":SCHEMA,"kind":"tempo_voucher","chain_id":4217,
            "escrow":"0x33b901018174ddabe4841042ab76ba85d4e24f25",
            "channel_id":format!("0x{}", "12".repeat(32)),"cumulative_amount":"5"}),
        )
        .unwrap();
        assert!(review(&system(voucher, class), signer()).unwrap().is_some());
        // A Petal, or Machine x402, cannot present a Tempo review.
        assert!(review(&request(charge.clone()), signer()).is_err());
        assert!(
            review(
                &system(
                    charge.clone(),
                    bloom_broker_api::SYSTEM_X402_OPERATION_CLASS
                ),
                signer()
            )
            .is_err()
        );
        // Machine MPP cannot present some other message as its payment.
        let error = review(&system(envelope(payment_data()), class), signer()).unwrap_err();
        assert!(error.message.contains("Tempo"), "{}", error.message);
        // The envelope must be the approved transaction.
        let mut other = system(charge, class);
        let mut bytes = hex::decode(&tempo::tests::CHARGE_UNSPONSORED_MEMO[2..]).unwrap();
        let last = bytes.len() - 5;
        bytes[last] ^= 1;
        other.message_review_payloads = vec![Base64UrlBytes::from_bytes(
            &serde_json::to_vec(&json!({"schema":SCHEMA,"kind":"tempo_transaction",
                "transaction":format!("0x{}", hex::encode(bytes))}))
            .unwrap(),
        )];
        assert!(review(&other, signer()).is_err());
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
