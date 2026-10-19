//! Hyperliquid L1 actions commit ordered MessagePack, not JSON text. The
//! field order below follows hyperliquid-python-sdk signing.py and matches
//! the Petal's official-SDK vectors. JSON map ordering is never used to hash.
use super::{MessageField, MessageReview, ProtocolError, VenueAssetReview, escaped, invalid};
use alloy::primitives::{Address, keccak256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Action {
    #[serde(rename = "order")]
    Order {
        orders: Vec<Order>,
        grouping: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        builder: Option<Builder>,
    },
    #[serde(rename = "cancel")]
    Cancel {
        cancels: Vec<Cancel>,
        #[serde(rename = "f", skip_serializing_if = "Option::is_none")]
        fast: Option<bool>,
    },
    #[serde(rename = "cancelByCloid")]
    CancelByCloid {
        cancels: Vec<CancelByCloid>,
        #[serde(rename = "f", skip_serializing_if = "Option::is_none")]
        fast: Option<bool>,
    },
    #[serde(rename = "scheduleCancel")]
    ScheduleCancel {
        #[serde(skip_serializing_if = "Option::is_none")]
        time: Option<u64>,
    },
    #[serde(rename = "updateLeverage")]
    UpdateLeverage {
        asset: u32,
        #[serde(rename = "isCross")]
        is_cross: bool,
        leverage: u32,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Order {
    a: u32,
    b: bool,
    p: String,
    s: String,
    r: bool,
    t: OrderType,
    #[serde(skip_serializing_if = "Option::is_none")]
    c: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OrderType {
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<Limit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger: Option<Trigger>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limit {
    tif: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Trigger {
    #[serde(rename = "isMarket")]
    is_market: bool,
    #[serde(rename = "triggerPx")]
    trigger_px: String,
    tpsl: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Builder {
    b: String,
    f: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cancel {
    a: u32,
    o: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CancelByCloid {
    asset: u32,
    cloid: String,
}

fn field(path: impl Into<String>, value: impl ToString) -> MessageField {
    MessageField {
        path: path.into(),
        value: escaped(&value.to_string()),
    }
}

fn collect(
    value: &Value,
    path: &str,
    fields: &mut Vec<MessageField>,
    limit: usize,
) -> Result<(), ProtocolError> {
    if fields.len() >= limit {
        return Err(invalid("exchange action exceeds its display bound"));
    }
    match value {
        Value::Object(values) => {
            if values.is_empty() {
                fields.push(field(path, "{}"));
            }
            for (name, value) in values {
                collect(value, &format!("{path}.{name}"), fields, limit)?;
            }
        }
        Value::Array(values) => {
            if values.is_empty() {
                fields.push(field(path, "[]"));
            }
            for (index, value) in values.iter().enumerate() {
                collect(value, &format!("{path}[{}]", index + 1), fields, limit)?;
            }
        }
        value => {
            let label = match path {
                "action.type" => "Action".into(),
                "action.asset" => "Market ID (identity unverified)".into(),
                "action.isCross" => "Cross margin".into(),
                "action.leverage" => "Leverage".into(),
                "action.time" => "Scheduled cancellation (Unix milliseconds)".into(),
                "action.grouping" => "Order grouping".into(),
                "action.builder.b" => "Builder fee recipient".into(),
                "action.builder.f" => "Builder fee rate (tenths of a basis point)".into(),
                _ if path.starts_with("action.orders[") => {
                    let (order, suffix) = path
                        .split_once(']')
                        .ok_or_else(|| invalid("invalid order path"))?;
                    let name = match suffix {
                        ".a" => "Market ID (identity unverified)",
                        ".b" => "Buy side (false means sell)",
                        ".p" => "Limit price (venue quote units)",
                        ".s" => "Size (venue base units)",
                        ".r" => "Reduce only",
                        ".c" => "Client order ID",
                        ".t.limit.tif" => "Time in force",
                        ".t.trigger.isMarket" => "Market trigger",
                        ".t.trigger.triggerPx" => "Trigger price",
                        ".t.trigger.tpsl" => "Take-profit / stop-loss type",
                        _ => suffix,
                    };
                    format!("{}] · {name}", order.trim_start_matches("action."))
                }
                _ => path.trim_start_matches("action.").into(),
            };
            fields.push(field(
                label,
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            ));
        }
    }
    Ok(())
}

pub(super) fn rebuild(
    network: &str,
    raw: Value,
    nonce: u64,
    vault: Option<&str>,
    expires: Option<u64>,
    field_limit: usize,
) -> Result<(Value, Vec<MessageField>, String), ProtocolError> {
    let source = match network {
        "mainnet" => "a",
        "testnet" => "b",
        _ => return Err(invalid("unknown Hyperliquid environment")),
    };
    let action: Action = serde_json::from_value(raw.clone())
        .map_err(|_| invalid("unsupported or malformed exchange action"))?;
    let canonical =
        serde_json::to_value(&action).map_err(|_| invalid("cannot encode exchange action"))?;
    if canonical != raw {
        return Err(invalid(
            "exchange action carries unused or noncanonical fields",
        ));
    }
    if let Action::Order {
        orders, grouping, ..
    } = &action
    {
        if orders.is_empty()
            || !matches!(grouping.as_str(), "na" | "normalTpsl" | "positionTpsl")
            || orders
                .iter()
                .any(|order| order.t.limit.is_some() == order.t.trigger.is_some())
        {
            return Err(invalid("unsupported exchange order grouping or type"));
        }
    }
    let vault = vault
        .map(str::parse::<Address>)
        .transpose()
        .map_err(|_| invalid("invalid exchange vault address"))?;
    let mut bytes =
        rmp_serde::to_vec_named(&action).map_err(|_| invalid("cannot encode exchange action"))?;
    bytes.extend_from_slice(&nonce.to_be_bytes());
    if let Some(vault) = vault {
        bytes.push(1);
        bytes.extend_from_slice(vault.as_slice());
    } else {
        bytes.push(0);
    }
    if let Some(expires) = expires {
        bytes.push(0);
        bytes.extend_from_slice(&expires.to_be_bytes());
    }
    let connection = format!("{:#x}", keccak256(bytes));
    let typed = json!({"types":{
        "EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
        "Agent":[{"name":"source","type":"string"},{"name":"connectionId","type":"bytes32"}]},
        "primaryType":"Agent", "domain":{"name":"Exchange","version":"1","chainId":1337,"verifyingContract":"0x0000000000000000000000000000000000000000"},
        "message":{"source":source,"connectionId":connection}});
    let mut fields = vec![
        field("Hyperliquid environment", network),
        field("Nonce (Unix milliseconds)", nonce),
        field(
            "Vault account",
            vault
                .map(|address| format!("{address:#x}"))
                .unwrap_or_else(|| "None; signing account".into()),
        ),
        field(
            "Expires after (Unix milliseconds)",
            expires
                .map(|value| value.to_string())
                .unwrap_or_else(|| "No expiry included".into()),
        ),
    ];
    collect(&canonical, "action", &mut fields, field_limit)?;
    let title = match action {
        Action::Order { .. } => "Sign exchange orders",
        Action::Cancel { .. } | Action::CancelByCloid { .. } => "Cancel exchange orders",
        Action::ScheduleCancel { time: Some(_) } => "Schedule exchange cancellation",
        Action::ScheduleCancel { time: None } => "Remove scheduled exchange cancellation",
        Action::UpdateLeverage { .. } => "Change exchange leverage",
    };
    Ok((typed, fields, title.into()))
}

pub(super) fn decorate(typed: &alloy_dyn_abi::eip712::TypedData, review: &mut MessageReview) {
    let domain = &typed.domain;
    if domain.name.as_deref() != Some("HyperliquidSignTransaction")
        || domain.version.as_deref() != Some("1")
        || domain.chain_id != Some(alloy::primitives::U256::from(0x66eee_u64))
        || domain.verifying_contract != Some(Address::ZERO)
    {
        return;
    }
    let (name, fields, title) = match typed.primary_type.as_str() {
        "HyperliquidTransaction:ApproveAgent" => (
            "ApproveAgent",
            "string hyperliquidChain,address agentAddress,string agentName,uint64 nonce",
            "Authorize a trading agent",
        ),
        "HyperliquidTransaction:UsdSend" => (
            "UsdSend",
            "string hyperliquidChain,string destination,string amount,uint64 time",
            "Send USDC on HyperCore",
        ),
        "HyperliquidTransaction:Withdraw" => (
            "Withdraw",
            "string hyperliquidChain,string destination,string amount,uint64 time",
            "Request a USDC withdrawal",
        ),
        "HyperliquidTransaction:UsdClassTransfer" => (
            "UsdClassTransfer",
            "string hyperliquidChain,string amount,bool toPerp,uint64 nonce",
            "Move USDC between spot and perps",
        ),
        _ => return,
    };
    if typed.encode_type().ok().as_deref()
        != Some(format!("HyperliquidTransaction:{name}({fields})").as_str())
        || !review.fields.iter().any(|field| {
            field.path == "hyperliquidChain"
                && matches!(field.value.as_str(), "Mainnet" | "Testnet")
        })
    {
        return;
    }
    review.kind = "hyperliquid_user".into();
    review.title = title.into();
    if name == "ApproveAgent" {
        review.fields.push(field("Venue permission", "Trading agent authority; no spending ceiling or duration is included in this signature"));
        review.warnings.push("The venue grants trading authority to this agent. Petal session limits are separate local claims; this signature does not make the venue enforce those limits.".into());
    } else {
        if let Some(amount) = review
            .fields
            .iter_mut()
            .find(|field| field.path == "amount")
        {
            amount.path = "USDC amount (HyperCore venue units)".into();
            if let Ok(base_units) = usdc_base_units(&amount.value) {
                let mainnet = typed.message["hyperliquidChain"] == "Mainnet";
                review.venue_asset = Some(VenueAssetReview {
                    asset_id: if mainnet {
                        "hyperliquid:mainnet:usdc"
                    } else {
                        "hyperliquid:testnet:usdc"
                    }
                    .into(),
                    name: if mainnet {
                        "USDC balance on HyperCore"
                    } else {
                        "USDC test collateral on HyperCore"
                    }
                    .into(),
                    symbol: "USDC".into(),
                    environment: if mainnet { "Mainnet" } else { "Testnet" }.into(),
                    amount_display: format!("{} USDC", amount.value),
                    base_units,
                });
            }
        }
        review.warnings.push("This authorizes a HyperCore venue action. Venue fees, available balance, acceptance and settlement have not been verified; a withdrawal's destination receives the amount less the venue fee.".into());
    }
}

fn usdc_base_units(value: &str) -> Result<String, ProtocolError> {
    use alloy::primitives::U256;
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (fraction.len() > 6 && fraction[6..].bytes().any(|byte| byte != b'0'))
    {
        return Err(invalid("HyperCore amount is not an exact USDC quantity"));
    }
    let whole =
        U256::from_str_radix(whole, 10).map_err(|_| invalid("HyperCore amount is too large"))?;
    let fraction = format!("{fraction:0<6}");
    let fraction =
        U256::from_str_radix(&fraction[..6], 10).map_err(|_| invalid("invalid USDC fraction"))?;
    whole
        .checked_mul(U256::from(1_000_000))
        .and_then(|value| value.checked_add(fraction))
        .map(|value| value.to_string())
        .ok_or_else(|| invalid("HyperCore amount is too large"))
}

pub(super) fn validate_payment(
    request: &bloom_broker_api::ApprovalPrepareRequest,
    review: &MessageReview,
    class: &str,
) -> Result<(), ProtocolError> {
    if !matches!(class, "hyperliquid.usd_send" | "hyperliquid.withdraw") {
        return Ok(());
    }
    let value = |name: &str| {
        review
            .fields
            .iter()
            .find(|field| field.path == name)
            .map(|field| field.value.as_str())
            .ok_or_else(|| invalid("HyperCore payment field is missing"))
    };
    let amount = usdc_base_units(value("USDC amount (HyperCore venue units)")?)?;
    let recipient = value("destination")?
        .parse::<Address>()
        .map_err(|_| invalid("invalid HyperCore payment destination"))?;
    let claim = request
        .petal_use_claim
        .as_ref()
        .ok_or_else(|| invalid("HyperCore payment claim is missing"))?;
    let [debit] = claim.declared_debits.as_slice() else {
        return Err(invalid(
            "HyperCore payment must declare its exact USDC debit",
        ));
    };
    if debit.asset.chain.as_str() != "hyperliquid"
        || debit.asset.asset != "usdc"
        || debit.amount.as_str() != amount
        || !request
            .terms
            .limits
            .value_limits
            .iter()
            .any(|limit| limit.asset == debit.asset && limit.lifetime.as_str() == amount)
    {
        return Err(invalid(
            "HyperCore payment claim or approval differs from the signed debit",
        ));
    }
    let expected_chain = if class == "hyperliquid.withdraw" {
        "arbitrum"
    } else {
        "hyperliquid"
    };
    let [destination] = claim.declared_destinations.as_slice() else {
        return Err(invalid(
            "HyperCore payment must declare its signed destination",
        ));
    };
    if destination.chain.as_str() != expected_chain
        || destination.destination.parse::<Address>().ok() != Some(recipient)
    {
        return Err(invalid(
            "HyperCore payment claim differs from the signed destination",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn venue_usdc_quantities_are_exact_and_never_rounded() {
        assert_eq!(usdc_base_units("1.234567").unwrap(), "1234567");
        assert_eq!(usdc_base_units("1.234567000").unwrap(), "1234567");
        assert_eq!(usdc_base_units("2").unwrap(), "2000000");
        for value in ["1.2345678", "1e3", "-1", "+1", ".1", "1.2.3", "NaN"] {
            assert!(usdc_base_units(value).is_err(), "{value}");
        }
    }
    #[test]
    fn ordered_messagepack_matches_official_sdk_vault_and_expiry_vector() {
        let action = json!({"type":"order","orders":[{"a":0,"b":true,"p":"100","s":"0.01","r":false,"t":{"limit":{"tif":"Gtc"}}}],"grouping":"na"});
        let (typed, fields, _) = rebuild(
            "mainnet",
            action.clone(),
            123,
            Some("0x0000000000000000000000000000000000000003"),
            Some(999999),
            super::super::MAX_FIELDS,
        )
        .unwrap();
        let td: alloy_dyn_abi::eip712::TypedData = serde_json::from_value(typed).unwrap();
        assert_eq!(
            format!("{:#x}", td.eip712_signing_hash().unwrap()),
            "0xd1d31414c406d9f99e01134e80157b5ef8ff36b0e554935a6a526134ac111438"
        );
        assert!(
            fields
                .iter()
                .any(|field| field.path.contains("Limit price") && field.value == "100")
        );
        let mut extra = action;
        extra["orders"][0]["displayAmount"] = json!("fake");
        assert!(rebuild("mainnet", extra, 123, None, None, super::super::MAX_FIELDS).is_err());
        assert!(
            rebuild(
                "unknown",
                json!({"type":"scheduleCancel"}),
                123,
                None,
                None,
                super::super::MAX_FIELDS
            )
            .is_err()
        );
    }
}
