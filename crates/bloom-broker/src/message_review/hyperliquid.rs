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

/// The review field holding Broker's own bound on an order's builder fee, in
/// micro-USDC, rounded up. Present exactly when the order carries a builder.
pub(super) const BUILDER_FEE_FIELD: &str = "Maximum builder fee (micro-USDC, rounded up)";
/// The operation class every builder-bearing order must sign under.
pub(crate) const BUILDER_ORDER_CLASS: &str = "hyperliquid.builder_order";
/// Asset IDs from here on are spot, builder-deployed (HIP-3) or outcome
/// markets, whose builder fee may not be paid in USDC.
const SPOT_ASSET_ID_OFFSET: u32 = 10_000;

/// Broker's own upper bound on the builder fee `orders` can pay at `rate`
/// tenths of a basis point of notional, from the signed prices and sizes.
/// Only legs Broker can bound in USDC are accepted: core-perp limit orders.
/// A buy fills at or below its limit; a sell must be post-only (`Alo`), so it
/// fills at exactly its limit rather than at a lower resting bid.
fn builder_fee_bound(orders: &[Order], rate: u32) -> Result<u64, ProtocolError> {
    let mut total = 0_u64;
    for order in orders {
        let Some(limit) = &order.t.limit else {
            return Err(invalid(
                "a trigger order fills at the market, so its builder fee cannot be bounded",
            ));
        };
        if order.a >= SPOT_ASSET_ID_OFFSET {
            return Err(invalid(
                "Bloom bounds builder fees only on core perpetual orders, which pay them in USDC",
            ));
        }
        if !order.b && limit.tif != "Alo" {
            return Err(invalid(
                "a sell carrying a builder fee must be post-only (Alo) so it fills at its limit",
            ));
        }
        total = total
            .checked_add(leg_fee_micros(&order.p, &order.s, rate)?)
            .ok_or_else(|| invalid("builder fee exceeds the supported USDC amount"))?;
    }
    Ok(total)
}

/// `price * size * rate / 10^5` in micro-USDC, rounded up, from the exact
/// signed decimals.
fn leg_fee_micros(price: &str, size: &str, rate: u32) -> Result<u64, ProtocolError> {
    use alloy::primitives::U256;
    let decimal = |raw: &str| -> Result<(U256, usize), ProtocolError> {
        let (whole, fraction) = raw.split_once('.').unwrap_or((raw, ""));
        if whole.is_empty()
            || !format!("{whole}{fraction}")
                .bytes()
                .all(|b| b.is_ascii_digit())
        {
            return Err(invalid("order price or size is not a plain decimal"));
        }
        let mantissa = U256::from_str_radix(&format!("{whole}{fraction}"), 10)
            .map_err(|_| invalid("order price or size is too large"))?;
        Ok((mantissa, fraction.len()))
    };
    let overflow = || invalid("builder fee exceeds the supported USDC amount");
    let (price, price_scale) = decimal(price)?;
    let (size, size_scale) = decimal(size)?;
    // 1 USDC is 10^6 micros and a tenth of a basis point is 1/10^5.
    let numerator = price
        .checked_mul(size)
        .and_then(|value| value.checked_mul(U256::from(rate)))
        .and_then(|value| value.checked_mul(U256::from(10)))
        .ok_or_else(overflow)?;
    let denominator = U256::from(10)
        .checked_pow(U256::from(price_scale + size_scale))
        .ok_or_else(overflow)?;
    let mut bound = numerator / denominator;
    if numerator % denominator != U256::ZERO {
        bound += U256::from(1);
    }
    bound.try_into().map_err(|_| overflow())
}

/// A builder fee needs [`BUILDER_ORDER_CLASS`], and that class needs a builder
/// fee declared in HyperCore USDC at no less than Broker's own bound. Every
/// other class must declare no fee for a builder to be paid.
pub(super) fn validate_builder_fee(
    claim: &bloom_broker_api::PetalUseClaim,
    review: &MessageReview,
) -> Result<(), ProtocolError> {
    let bound = review.builder_fee_bound;
    let builder_class = claim.operation_class.as_str() == BUILDER_ORDER_CLASS;
    match (bound, builder_class) {
        (None, false) => Ok(()),
        (Some(_), false) => Err(invalid(
            "an order carrying a builder fee must sign under hyperliquid.builder_order",
        )),
        (None, true) => Err(invalid(
            "hyperliquid.builder_order requires an order carrying a builder fee",
        )),
        (Some(bound), true) => match &claim.declared_fee {
            bloom_broker_api::DeclaredFee::Fee {
                chain,
                asset,
                amount,
            } if chain.as_str() == "hyperliquid"
                && asset == "usdc"
                && amount
                    .as_str()
                    .parse::<alloy::primitives::U256>()
                    .is_ok_and(|amount| amount >= alloy::primitives::U256::from(bound)) =>
            {
                Ok(())
            }
            _ => Err(invalid(&format!(
                "the declared builder fee must be HyperCore USDC of at least {bound} micro-USDC, Bloom's bound from the signed order"
            ))),
        },
    }
}

#[derive(Deserialize)]
struct Markets {
    perps: Vec<String>,
    spot: std::collections::BTreeMap<String, [String; 2]>,
}
/// Mainnet market names from `scripts/bundle-hyperliquid-markets.py`. Perp
/// IDs are universe positions (delisted perps keep their slot); spot IDs are
/// 10000 + the pair index. A market listed later has no name here.
static MARKETS: std::sync::LazyLock<Markets> = std::sync::LazyLock::new(|| {
    serde_json::from_str(include_str!("hyperliquid-markets.json"))
        .expect("bundled Hyperliquid market list is valid JSON")
});
const MARKET_ID: &str = "Market ID (identity unverified)";
const LIMIT_PRICE: &str = "Limit price";
const TRIGGER_PRICE: &str = "Trigger price";

/// The coin and quote asset for a mainnet asset ID, plus whether it is spot.
fn market(network: &str, id: u32) -> Option<(&'static str, &'static str, bool)> {
    if network != "mainnet" {
        return None;
    }
    if let Some(name) = MARKETS.perps.get(usize::try_from(id).ok()?) {
        return Some((name, "USDC", false));
    }
    let [base, quote] = MARKETS.spot.get(&id.to_string())?;
    Some((base, quote, true))
}
fn market_label(network: &str, id: u32) -> String {
    match market(network, id) {
        Some((base, quote, true)) => format!("{base}/{quote} spot (market {id})"),
        Some((base, _, false)) => format!("{base} perpetual (market {id})"),
        None if network == "mainnet" => {
            format!("Market {id} (not in this Bloom release's market list)")
        }
        None => format!("Market {id} (testnet; Bloom has no testnet market names)"),
    }
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
            let raw = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            let yes_no = |v: &Value| match v.as_bool() {
                Some(true) => "Yes".to_owned(),
                Some(false) => "No".to_owned(),
                None => raw.clone(),
            };
            let mut shown = raw.clone();
            let label = match path {
                "action.type" => "Action".into(),
                "action.asset" => "Market ID (identity unverified)".into(),
                "action.isCross" => {
                    shown = yes_no(value);
                    "Cross margin".into()
                }
                "action.leverage" => "Leverage".into(),
                "action.time" => "Scheduled cancellation (Unix milliseconds)".into(),
                "action.f" => {
                    shown = yes_no(value);
                    "Fast cancellation".into()
                }
                "action.grouping" => {
                    shown = match raw.as_str() {
                        "na" => "None".into(),
                        "normalTpsl" => "Take-profit/stop-loss for these orders".into(),
                        "positionTpsl" => "Take-profit/stop-loss for the whole position".into(),
                        _ => raw.clone(),
                    };
                    "Linked orders".into()
                }
                "action.builder.b" => "Builder fee recipient".into(),
                "action.builder.f" => "Builder fee rate (tenths of a basis point)".into(),
                _ if path.starts_with("action.orders[") => {
                    let (order, suffix) = path
                        .split_once(']')
                        .ok_or_else(|| invalid("invalid order path"))?;
                    match suffix {
                        ".b" => {
                            shown = if value.as_bool() == Some(true) {
                                "Buy"
                            } else {
                                "Sell"
                            }
                            .into()
                        }
                        ".r" => shown = yes_no(value),
                        ".t.trigger.isMarket" => {
                            shown = match value.as_bool() {
                                Some(true) => "Market order".into(),
                                Some(false) => "Limit order".into(),
                                None => raw.clone(),
                            }
                        }
                        ".t.trigger.tpsl" => {
                            shown = match raw.as_str() {
                                "tp" => "Take profit".into(),
                                "sl" => "Stop loss".into(),
                                _ => raw.clone(),
                            }
                        }
                        ".t.limit.tif" => {
                            shown = match raw.as_str() {
                                "Ioc" => "Immediate or cancel (unfilled size is cancelled)".into(),
                                "Gtc" => "Good until cancelled".into(),
                                "Alo" => "Post only (rejected if it would fill immediately)".into(),
                                _ => raw.clone(),
                            }
                        }
                        _ => {}
                    }
                    let name = match suffix {
                        ".a" => "Market ID (identity unverified)",
                        ".b" => "Side",
                        ".p" => LIMIT_PRICE,
                        ".s" => "Size",
                        ".r" => "Reduce only",
                        ".c" => "Client order ID",
                        ".t.limit.tif" => "Time in force",
                        ".t.trigger.isMarket" => "Execution after trigger",
                        ".t.trigger.triggerPx" => TRIGGER_PRICE,
                        ".t.trigger.tpsl" => "Trigger type",
                        _ => suffix,
                    };
                    let index = order.trim_start_matches("action.orders[");
                    format!("Order {index} · {name}")
                }
                _ if path.starts_with("action.cancels[") => {
                    let (cancel, suffix) = path
                        .split_once(']')
                        .ok_or_else(|| invalid("invalid cancellation path"))?;
                    let name = match suffix {
                        ".a" | ".asset" => "Market ID (identity unverified)",
                        ".o" => "Order ID",
                        ".cloid" => "Client order ID",
                        _ => suffix,
                    };
                    format!("{}] · {name}", cancel.trim_start_matches("action."))
                }
                _ => path.trim_start_matches("action.").into(),
            };
            fields.push(field(label, shown));
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
) -> Result<(Value, Vec<MessageField>, String, Option<u64>), ProtocolError> {
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
        && (orders.is_empty()
            || !matches!(grouping.as_str(), "na" | "normalTpsl" | "positionTpsl")
            || orders
                .iter()
                .any(|order| order.t.limit.is_some() == order.t.trigger.is_some()))
    {
        return Err(invalid("unsupported exchange order grouping or type"));
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
                .unwrap_or_else(|| "None (trades as the signing account)".into()),
        ),
        field(
            "Expires after (Unix milliseconds)",
            expires
                .map(|value| value.to_string())
                .unwrap_or_else(|| "No expiry included".into()),
        ),
    ];
    collect(&canonical, "action", &mut fields, field_limit)?;
    let fee_bound = match &action {
        Action::Order {
            orders,
            builder: Some(builder),
            ..
        } => Some(builder_fee_bound(orders, builder.f)?),
        _ => None,
    };
    if let Some(bound) = fee_bound {
        fields.push(field(BUILDER_FEE_FIELD, bound));
    }
    for field in &mut fields {
        if let Some(prefix) = field.path.strip_suffix(MARKET_ID)
            && let Ok(id) = field.value.parse::<u32>()
        {
            field.path = format!("{prefix}Market");
            field.value = escaped(&market_label(network, id));
        }
    }
    // Prices are in the market's quote asset; an unlisted market shows no unit.
    if let Action::Order { orders, .. } = &action {
        for (index, order) in orders.iter().enumerate() {
            let Some((_, quote, _)) = market(network, order.a) else {
                continue;
            };
            for name in [LIMIT_PRICE, TRIGGER_PRICE] {
                let path = format!("Order {} · {name}", index + 1);
                if let Some(field) = fields.iter_mut().find(|field| field.path == path) {
                    field.path = format!("{path} ({quote})");
                }
            }
        }
    }
    let order_title = match &action {
        Action::Order { orders, .. } if orders.len() == 1 => {
            let order = &orders[0];
            let side = if order.b { "Buy" } else { "Sell" };
            let bound = if order.b { "for up to" } else { "for at least" };
            Some(match market(network, order.a) {
                Some((base, quote, _)) => {
                    format!("{side} {} {base} {bound} {} {quote} each", order.s, order.p)
                }
                None => format!(
                    "{side} {} on market {} {bound} {} each",
                    order.s, order.a, order.p
                ),
            })
        }
        _ => None,
    };
    let title = match action {
        Action::Order { .. } => order_title.as_deref().unwrap_or("Sign exchange orders"),
        Action::Cancel { .. } | Action::CancelByCloid { .. } => "Cancel exchange orders",
        Action::ScheduleCancel { time: Some(_) } => "Schedule exchange cancellation",
        Action::ScheduleCancel { time: None } => "Remove scheduled exchange cancellation",
        Action::UpdateLeverage { .. } => "Change exchange leverage",
    };
    Ok((typed, fields, title.into(), fee_bound))
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
    fn shared_signing_vectors_freeze_ordered_bytes_and_hashes() {
        // Identical to bloom-petal-hyperliquid/route/tests/fixtures/hyperliquid-signing.json.
        let vectors: Vec<Value> = serde_json::from_str(include_str!(
            "../../tests/fixtures/hyperliquid-signing.json"
        ))
        .unwrap();
        assert_eq!(vectors.len(), 40);
        for vector in vectors {
            let action: Action = serde_json::from_value(vector["action"].clone()).unwrap();
            assert_eq!(
                hex::encode(rmp_serde::to_vec_named(&action).unwrap()),
                vector["messagepack"],
                "{vector}"
            );
            let (typed, _, _, _) = rebuild(
                vector["network"].as_str().unwrap(),
                vector["action"].clone(),
                vector["nonce"].as_u64().unwrap(),
                vector["vault_address"].as_str(),
                vector["expires_after"].as_u64(),
                super::super::MAX_FIELDS,
            )
            .unwrap();
            assert_eq!(
                typed["message"]["connectionId"], vector["action_hash"],
                "{vector}"
            );
            let td: alloy_dyn_abi::eip712::TypedData = serde_json::from_value(typed).unwrap();
            let mut preimage = vec![0x19, 0x01];
            preimage.extend_from_slice(td.domain().separator().as_slice());
            preimage.extend_from_slice(td.hash_struct().unwrap().as_slice());
            assert_eq!(hex::encode(preimage), vector["preimage"], "{vector}");
            assert_eq!(
                format!("{:#x}", td.eip712_signing_hash().unwrap()),
                vector["hash"],
                "{vector}"
            );
        }
    }
    #[test]
    fn owner_batch_boundaries_match_the_petal_preflight() {
        for (item, accepted) in [
            (
                json!({"a":0,"b":true,"p":"100","s":"0.01","r":false,"t":{"limit":{"tif":"Gtc"}}}),
                41,
            ),
            (
                json!({"a":0,"b":true,"p":"100","s":"0.01","r":false,"t":{"limit":{"tif":"Gtc"}},"c":"0x00000000000000000000000000000001"}),
                35,
            ),
            (
                json!({"a":0,"b":true,"p":"100","s":"0.01","r":false,"t":{"trigger":{"isMarket":true,"triggerPx":"110","tpsl":"tp"}},"c":"0x00000000000000000000000000000001"}),
                27,
            ),
        ] {
            for count in [accepted, accepted + 1] {
                let action =
                    json!({"type":"order","orders":vec![item.clone(); count],"grouping":"na"});
                let result = rebuild(
                    "mainnet",
                    action.clone(),
                    123,
                    None,
                    None,
                    super::super::MAX_FIELDS,
                );
                assert_eq!(result.is_ok(), count == accepted);
                assert!(rebuild("mainnet", action, 123, None, None, 4096).is_ok());
            }
        }
        for fast in [false, true] {
            for count in [125, 126] {
                let mut action =
                    json!({"type":"cancel","cancels":vec![json!({"a":0,"o":42}); count]});
                if fast {
                    action["f"] = json!(true);
                }
                let result = rebuild("mainnet", action, 123, None, None, super::super::MAX_FIELDS);
                assert_eq!(result.is_ok(), count == 125);
                if fast && count == 125 {
                    assert_eq!(result.unwrap().1.len(), 256);
                }
            }
        }
    }
    #[test]
    fn cancellations_label_identifiers_without_claiming_market_identity() {
        for (action, label, value) in [
            (
                json!({"type":"cancel","cancels":[{"a":7,"o":123}],"f":true}),
                "Order ID",
                "123",
            ),
            (
                json!({"type":"cancelByCloid","cancels":[{"asset":7,"cloid":"0x00000000000000000000000000000001"}],"f":true}),
                "Client order ID",
                "0x00000000000000000000000000000001",
            ),
        ] {
            let (_, fields, _, _) =
                rebuild("mainnet", action, 123, None, None, super::super::MAX_FIELDS).unwrap();
            assert!(
                fields
                    .iter()
                    .any(|f| f.path == "cancels[1] · Market"
                        && f.value == "BNB perpetual (market 7)")
            );
            assert!(
                fields
                    .iter()
                    .any(|f| f.path == format!("cancels[1] · {label}") && f.value == value)
            );
            assert!(
                fields
                    .iter()
                    .any(|f| f.path == "Fast cancellation" && f.value == "Yes")
            );
        }
    }
    #[test]
    fn orders_read_in_plain_words() {
        let action = json!({"type":"order","orders":[{"a":1,"b":true,"p":"2260","s":"0.0045","r":false,"t":{"limit":{"tif":"Ioc"}}}],"grouping":"na"});
        let (_, fields, title, _) =
            rebuild("mainnet", action, 1, None, None, super::super::MAX_FIELDS).unwrap();
        let shown = |path: &str| {
            fields
                .iter()
                .find(|f| f.path == path)
                .map(|f| f.value.as_str())
        };
        assert_eq!(shown("Order 1 · Side"), Some("Buy"));
        assert_eq!(shown("Order 1 · Reduce only"), Some("No"));
        assert_eq!(shown("Order 1 · Size"), Some("0.0045"));
        assert_eq!(shown("Order 1 · Limit price (USDC)"), Some("2260"));
        // Wording follows the Hyperliquid Petal's order.json `t` description.
        for (tif, meaning) in [
            ("Gtc", "Good until cancelled"),
            ("Ioc", "Immediate or cancel (unfilled size is cancelled)"),
            ("Alo", "Post only (rejected if it would fill immediately)"),
        ] {
            let action = json!({"type":"order","orders":[{"a":1,"b":true,"p":"2260","s":"0.0045","r":false,"t":{"limit":{"tif":tif}}}],"grouping":"na"});
            let (_, fields, _, _) =
                rebuild("mainnet", action, 1, None, None, super::super::MAX_FIELDS).unwrap();
            assert!(
                fields
                    .iter()
                    .any(|f| f.path == "Order 1 · Time in force" && f.value == meaning),
                "{tif}"
            );
        }
        assert_eq!(shown("Linked orders"), Some("None"));
        assert_eq!(shown("Order 1 · Market"), Some("ETH perpetual (market 1)"));
        assert_eq!(title, "Buy 0.0045 ETH for up to 2260 USDC each");
        let spot = json!({"type":"order","orders":[{"a":10107,"b":false,"p":"40","s":"2","r":false,"t":{"limit":{"tif":"Gtc"}}}],"grouping":"na"});
        let (_, _, title, _) =
            rebuild("mainnet", spot, 1, None, None, super::super::MAX_FIELDS).unwrap();
        assert_eq!(title, "Sell 2 HYPE for at least 40 USDC each");
        let batch = json!({"type":"order","orders":[
            {"a":10207,"b":true,"p":"40","s":"1","r":false,"t":{"limit":{"tif":"Gtc"}}},
            {"a":1,"b":false,"p":"2000","s":"1","r":true,"t":{"trigger":{"isMarket":true,"triggerPx":"2100","tpsl":"tp"}}},
            {"a":9999,"b":false,"p":"1","s":"1","r":true,"t":{"trigger":{"isMarket":false,"triggerPx":"2","tpsl":"sl"}}}
        ],"grouping":"normalTpsl"});
        let (_, fields, title, _) =
            rebuild("mainnet", batch, 1, None, None, super::super::MAX_FIELDS).unwrap();
        let shown = |path: &str| {
            fields
                .iter()
                .find(|f| f.path == path)
                .map(|f| f.value.as_str())
        };
        assert_eq!(title, "Sign exchange orders");
        assert_eq!(
            shown("Order 1 · Market"),
            Some("HYPE/USDT0 spot (market 10207)")
        );
        assert_eq!(shown("Order 1 · Limit price (USDT0)"), Some("40"));
        assert_eq!(shown("Order 2 · Limit price (USDC)"), Some("2000"));
        assert_eq!(shown("Order 2 · Trigger price (USDC)"), Some("2100"));
        assert_eq!(
            shown("Order 2 · Execution after trigger"),
            Some("Market order")
        );
        assert_eq!(shown("Order 2 · Trigger type"), Some("Take profit"));
        assert_eq!(shown("Order 3 · Limit price"), Some("1"));
        assert_eq!(shown("Order 3 · Trigger price"), Some("2"));
        assert_eq!(
            shown("Order 3 · Execution after trigger"),
            Some("Limit order")
        );
        assert_eq!(shown("Order 3 · Trigger type"), Some("Stop loss"));
        let unknown = json!({"type":"order","orders":[{"a":9999,"b":true,"p":"1","s":"1","r":false,"t":{"limit":{"tif":"Gtc"}}}],"grouping":"na"});
        let (_, fields, _, _) =
            rebuild("testnet", unknown, 1, None, None, super::super::MAX_FIELDS).unwrap();
        assert!(
            fields
                .iter()
                .any(|f| f.value == "Market 9999 (testnet; Bloom has no testnet market names)")
        );
    }
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
        let (typed, fields, _, _) = rebuild(
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
