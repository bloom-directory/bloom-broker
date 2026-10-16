//! Strict decode, bounded formatting and the wallet safety rules.
//!
//! One generic decoder serves every admitted function; there is no
//! selector-specific parser and no executable plugin. The transfer and
//! allowance rules below *inspect* that generic result — they do not select a
//! different decoder — so adding a contract is catalog data, while changing
//! what Bloom promises about a call is code.

use std::collections::BTreeSet;

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_primitives::{Address, U256, keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    ActionClass, AdmittedFormat, CalleeSource, Catalog, CatalogEntry, LeafType, ReviewError,
    ReviewReason, array_of,
};

pub const TRANSFER_SIGNATURE: &str = "transfer(address,uint256)";
pub const APPROVE_SIGNATURE: &str = "approve(address,uint256)";
const SAFE_EXEC_SIGNATURE: &str =
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";
/// Latest timestamp rendered as a date: 23:59:59 UTC, 31 December 9999.
const MAX_TIMESTAMP_SECONDS: u64 = 253_402_300_799;
/// Calls carried inside calls: a Safe executing a Safe's call is two.
pub const MAX_NESTED_CALLS: usize = 2;
/// Elements one array argument may show.
pub const MAX_ARRAY_ITEMS: usize = 64;
/// `bytes` longer than this are shown by length and hash; `raw` keeps them.
const MAX_SHOWN_BYTES: usize = 128;

/// Native currency units, taken from Bloom's own authenticated chain table
/// rather than from anything a descriptor or catalog says.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeUnits {
    pub decimals: u8,
    pub symbol: String,
}

#[derive(Clone, Debug)]
pub struct CallContext<'a> {
    pub chain_id: u64,
    pub to: Address,
    pub value: U256,
    pub calldata: &'a [u8],
    pub native: Option<NativeUnits>,
    pub unlimited_allowance_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayField {
    pub label: String,
    pub format: String,
    /// What the owner reads.
    pub value: String,
    /// The decoded argument exactly as it was signed, always retained beside
    /// the formatted value.
    pub raw: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenIdentity {
    /// The token contract. This, not the symbol, is the token's identity.
    pub address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
}

/// What clear signing establishes, and what it does not. One sentence, the
/// same for every call, stated once per review.
pub fn standing_assurance() -> String {
    "Interpreted using Bloom's description of this contract. Contract behavior has not been verified."
        .to_owned()
}

/// The sentence for a call Bloom read by the standard ERC-20 calldata shape
/// alone, with no catalog description of the contract.
pub const STRUCTURAL_ERC20_ASSURANCE: &str = "Decoded from the standard ERC-20 calldata shape. Bloom verified the exact arguments, but not that this contract is a token or follows ERC-20 behavior.";

/// Exact canonical `transfer(address,uint256)` or `approve(address,uint256)`
/// calldata: its class, counterparty and amount. Anything else, including
/// dirty address padding or a wrong length, is `None`. A selector match is not
/// deployment evidence: any contract can implement these four bytes.
pub fn canonical_erc20(calldata: &[u8]) -> Option<(ActionClass, Address, U256)> {
    if calldata.len() != 68 || calldata[4..16].iter().any(|byte| *byte != 0) {
        return None;
    }
    let class = match calldata[..4] {
        [0xa9, 0x05, 0x9c, 0xbb] => ActionClass::Transfer,
        [0x09, 0x5e, 0xa7, 0xb3] => ActionClass::Allowance,
        _ => return None,
    };
    Some((
        class,
        Address::from_slice(&calldata[16..36]),
        U256::from_be_slice(&calldata[36..]),
    ))
}

/// The assurance of a call that names a contract no signed entry lists: an
/// instance read by its contract type, or an embedded ERC-20 call read by its
/// shape. The reading is exact; what that contract is, is not established.
pub fn structural_assurance() -> String {
    "Interpreted using Bloom's contract descriptions, but this call reaches a contract Bloom has not identified. Bloom has not verified what that contract is or what it does."
        .to_owned()
}

/// The decoded instruction, typed.
///
/// The page states what the owner is deciding from this, never from a
/// publisher's label, the order the fields happen to be in, or the wording of
/// a warning. It is a projection of the same strictly decoded arguments the
/// safety rules already ran on: not a second decoding, and not a new
/// authority over what a call means. Only the two canonical ERC-20 actions
/// get one; everything else stays generic rather than guessed at, and a
/// record written before this existed renders generically too.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallIntent {
    /// `transfer` or `allowance`.
    pub action: String,
    /// `recipient` for a transfer, `spender` for an allowance. They are not
    /// interchangeable and must never share one label on the page.
    pub counterparty_role: String,
    pub counterparty: String,
    /// Exact base units, as decoded. `amount_display` is derived from this;
    /// nothing reads the display string back.
    pub amount: String,
    pub amount_display: String,
    /// `zero`, `finite` or `unlimited`, decided on the decoded integer rather
    /// than on its rendering.
    pub magnitude: String,
    pub token: TokenIdentity,
}

/// The reviewed contract call, as it is frozen into the manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSignedCall {
    pub contract: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_name: Option<String>,
    pub function_signature: String,
    pub selector: String,
    pub action: String,
    /// Supplemental publisher text, never the heading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    pub fields: Vec<DisplayField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenIdentity>,
    /// Present only for the canonical ERC-20 actions; see [`CallIntent`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_summary: Option<CallIntent>,
    /// What reading this call against a catalog description does and does not
    /// establish. Identical for every clear-signed call, so a review states
    /// it once; it is not a property of this call and never a warning.
    #[serde(default = "standing_assurance")]
    pub assurance: String,
    /// Some part of this reading rests on no listed deployment: an instance
    /// entry, or an embedded ERC-20 call read by its shape alone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub structural: bool,
    /// Risks specific to this call: upgradeability, and what an allowance
    /// grants. Never the standing assurance.
    pub warnings: Vec<String>,
}

/// A catalog entry a review used, as the page shows it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedEntry {
    pub chain_id: String,
    pub contract_address: String,
    pub upgradeable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenIdentity>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub applies_to_instances: bool,
    /// The unlisted address this entry was read for, when it was matched as
    /// an instance rather than by its own address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl SelectedEntry {
    pub fn of(entry: &CatalogEntry) -> Self {
        Self {
            chain_id: entry.chain_id.to_string(),
            contract_address: entry.contract_address.clone(),
            upgradeable: entry.upgradeable,
            token: entry.token_metadata.as_ref().map(|metadata| TokenIdentity {
                address: checksum(&entry.contract_address),
                symbol: metadata.symbol.clone(),
                name: metadata.name.clone(),
                decimals: metadata.decimals,
            }),
            applies_to_instances: entry.applies_to_instances,
            instance: None,
        }
    }
}

fn unsupported(message: impl Into<String>) -> ReviewError {
    ReviewError::new(ReviewReason::UnsupportedCall, message)
}

fn invalid(message: impl Into<String>) -> ReviewError {
    ReviewError::new(ReviewReason::InvalidPayload, message)
}

/// Review one contract call against the accepted catalog.
///
/// Returns every catalog entry the reading depended on, in selection order:
/// the called contract first, then any token an argument named. All of them
/// become frozen evidence, so withdrawing or changing a token entry
/// invalidates the review exactly as changing the contract's own entry does.
pub fn review_call(
    catalog: &Catalog,
    context: &CallContext<'_>,
) -> Result<(ClearSignedCall, Vec<SelectedEntry>), ReviewError> {
    review_at(catalog, context, 0)
}

fn review_at(
    catalog: &Catalog,
    context: &CallContext<'_>,
    depth: usize,
) -> Result<(ClearSignedCall, Vec<SelectedEntry>), ReviewError> {
    if depth > MAX_NESTED_CALLS {
        return Err(ReviewError::new(
            ReviewReason::LimitExceeded,
            format!("calls are nested more than {MAX_NESTED_CALLS} deep"),
        ));
    }
    let address = format!("{:x}", context.to);
    let address = format!("0x{address}");
    let listed = catalog.entry(context.chain_id, &address);
    let selector = context.calldata.get(..4);
    let Some((entry, admitted, instance)) =
        selector.and_then(|selector| catalog.resolve(context.chain_id, &address, selector))
    else {
        return Err(match (listed, selector) {
            (None, _) => unsupported(format!(
                "no description of {address} on chain {}",
                context.chain_id
            )),
            (Some(_), None) => invalid("contract call has no complete selector"),
            (Some(_), Some(_)) => unsupported("no admitted description for this function selector"),
        });
    };
    let call = admitted
        .call(&context.calldata[..4])
        .ok_or_else(|| unsupported("no admitted description for this function selector"))?;
    if !context.value.is_zero() {
        return Err(invalid(
            "admitted contract calls must carry zero native value",
        ));
    }

    // One strict decoder. Re-encoding must reproduce the exact bytes, which
    // is what rejects trailing words, dirty address padding, noncanonical
    // booleans and short calldata in one place. Narrow-integer width is the
    // one thing it cannot see; `check_leaf` below covers that.
    let function = crate::parse_function(&call.signature)?;
    let decoded = function
        .abi_decode_input(&context.calldata[4..])
        .map_err(|error| {
            invalid(format!(
                "calldata does not decode as `{}`: {error}",
                call.signature
            ))
        })?;
    let reencoded = function
        .abi_encode_input(&decoded)
        .map_err(|error| invalid(format!("decoded arguments do not re-encode: {error}")))?;
    if reencoded != context.calldata {
        return Err(invalid(
            "calldata is noncanonical, truncated, or carries trailing bytes",
        ));
    }

    let mut leaves = Vec::new();
    flatten(&decoded, &mut leaves);
    if leaves.len() != call.leaves.len() {
        return Err(invalid(
            "decoded argument count differs from the description",
        ));
    }
    for ((path, declared), value) in call.leaves.iter().zip(&leaves) {
        check_leaf(path, declared, value)?;
    }
    // The decoded value at a field path; in element `index` when the path
    // reaches into an array. Admission and `check_leaf` proved the shapes.
    let top = |path: &str| {
        let name = array_of(path).unwrap_or(path);
        let index = call
            .leaves
            .iter()
            .position(|(leaf, _)| leaf == name)
            .expect("admission proved every path is a decoded leaf");
        (&call.leaves[index].1, &leaves[index])
    };
    let value_at = |path: &str, index: usize| -> &DynSolValue {
        let (kind, value) = top(path);
        let (Some((_, rest)), DynSolValue::Array(items)) = (path.split_once(".[]"), value) else {
            return value;
        };
        let item = &items[index];
        match (kind, item, rest.strip_prefix('.')) {
            (LeafType::Array(element), DynSolValue::Tuple(values), Some(component)) => {
                let LeafType::Tuple(components) = element.as_ref() else {
                    unreachable!("a component path is admitted only on a tuple array")
                };
                let position = components
                    .iter()
                    .position(|(name, _)| name == component)
                    .expect("admission proved the component exists");
                &values[position]
            }
            _ => item,
        }
    };
    let length = |path: &str| match top(path).1 {
        DynSolValue::Array(items) if array_of(path).is_some() => items.len(),
        _ => 1,
    };
    // A Safe's delegatecall runs another contract's code as the Safe, with
    // its storage and owners. The one contract allowed to is the batch
    // library, which only makes plain calls.
    if crate::parse_function(&call.signature)?.signature() == SAFE_EXEC_SIGNATURE
        && let (DynSolValue::Uint(operation, _), DynSolValue::Address(to)) =
            (value_at("operation", 0), value_at("to", 0))
        && !operation.is_zero()
        && !catalog.is_safe_batch(context.chain_id, &format!("0x{to:x}"))
    {
        return Err(unsupported(
            "a Safe may delegatecall only Safe's MultiSendCallOnly batch library",
        ));
    }
    for (path, allowed) in &call.constraints {
        for index in 0..length(path) {
            let value = match_key(value_at(path, index));
            if !allowed.contains(&value) {
                return Err(unsupported(format!(
                    "`{path}` is {value}, and the description admits only {}",
                    allowed.join(", ")
                )));
            }
        }
    }

    let mut selected = SelectedEntry::of(entry);
    if instance {
        selected.instance = Some(address.clone());
    }
    let mut used = vec![selected];
    // Upgradeability is a property of a contract, not of a call: it reaches
    // the page on every selected entry as `upgradeable` beside the
    // publisher's observation, so it is not repeated here as a warning.
    let mut warnings: Vec<String> = Vec::new();
    if instance {
        let kind = admitted
            .contract_name
            .as_deref()
            .map_or("the contract it appears to be".to_owned(), |name| {
                format!("a {name}")
            });
        warnings.push(if entry.chain_id == 0 {
            format!(
                "Bloom has not verified that {} is {kind}. It is read by that standard's functions.",
                checksum(&address)
            )
        } else {
            format!(
                "Bloom has not verified that {} is {kind}. It is read with Bloom's description of {}, the contract such addresses are expected to run.",
                checksum(&address),
                checksum(&entry.contract_address)
            )
        });
    }
    // Fields in order; an array's fields are shown element by element, each
    // labelled with its position, so a list of calls reads call by call.
    let mut jobs = Vec::new();
    let mut shown_arrays = BTreeSet::new();
    for field in &call.fields {
        match array_of(&field.path) {
            None => jobs.push((field, field.label.clone(), 0)),
            Some(array) if shown_arrays.insert(array) => {
                for index in 0..length(&field.path) {
                    for member in call
                        .fields
                        .iter()
                        .filter(|member| array_of(&member.path) == Some(array))
                    {
                        jobs.push((member, format!("{} {}", member.label, index + 1), index));
                    }
                }
            }
            Some(_) => {}
        }
    }
    let mut structural = instance;
    let mut fields = Vec::with_capacity(jobs.len());
    for (field, label, index) in jobs {
        let value = value_at(&field.path, index);
        match (&field.format, value) {
            (AdmittedFormat::Calldata { callee, amount }, DynSolValue::Bytes(data)) => {
                let callee = match callee {
                    CalleeSource::TargetContract => context.to,
                    CalleeSource::Argument(path) => match value_at(path, index) {
                        DynSolValue::Address(address) => *address,
                        _ => return Err(invalid("callee path did not decode as an address")),
                    },
                };
                let value = match amount.as_deref().map(|path| value_at(path, index)) {
                    Some(DynSolValue::Uint(value, _)) => *value,
                    Some(_) => return Err(invalid("amount path did not decode as an integer")),
                    None => U256::ZERO,
                };
                let inner = CallContext {
                    to: callee,
                    value,
                    calldata: data,
                    ..context.clone()
                };
                structural |= render_embedded(
                    catalog,
                    &inner,
                    &label,
                    depth,
                    &mut fields,
                    &mut used,
                    &mut warnings,
                )?;
            }
            (AdmittedFormat::SafeBatch, DynSolValue::Bytes(packed)) => {
                for (number, (to, value, data)) in safe_batch(packed)?.into_iter().enumerate() {
                    let inner = CallContext {
                        to,
                        value,
                        calldata: data,
                        ..context.clone()
                    };
                    structural |= render_embedded(
                        catalog,
                        &inner,
                        &format!("{label} {}", number + 1),
                        depth,
                        &mut fields,
                        &mut used,
                        &mut warnings,
                    )?;
                }
            }
            (AdmittedFormat::TokenAmount(source), DynSolValue::Uint(amount, _))
                if let Err(token) =
                    resolve_token(source, call, &leaves, entry, catalog, context)? =>
            {
                structural = true;
                fields.push(DisplayField {
                    label,
                    format: "raw".to_owned(),
                    value: format!("{amount} raw units of {token}"),
                    raw: amount.to_string(),
                });
            }
            _ => {
                let token = match &field.format {
                    AdmittedFormat::TokenAmount(source) => Some(
                        resolve_token(source, call, &leaves, entry, catalog, context)?
                            .expect("an unlisted token was shown in raw units above"),
                    ),
                    _ => None,
                };
                if let Some(token) = &token
                    && !used.iter().any(|selected| selected == &token.entry)
                {
                    used.push(token.entry.clone());
                }
                let mut shown = render_field(field, value, token.as_ref(), context)?;
                shown.label = label;
                fields.push(shown);
            }
        }
    }

    // The standing assurance is not a warning about this call: it is the same
    // sentence for every clear-signed call, and it was sitting at index 0 of
    // `warnings` where the only way to tell it apart was to match its text.
    // Typed, a page can state it once per review and keep `warnings` for the
    // risks that actually differ between calls.
    let (action, intent_summary) =
        apply_safety_rules(call, &leaves, entry, context, &mut warnings)?;

    Ok((
        ClearSignedCall {
            contract: checksum(&address),
            contract_name: admitted.contract_name.clone().or_else(|| {
                entry
                    .token_metadata
                    .as_ref()
                    .map(|token| token.name.clone())
            }),
            function_signature: call.signature.clone(),
            selector: format!("0x{}", hex_lower(&call.selector)),
            action: action.as_str().to_owned(),
            intent: call.intent.clone(),
            fields,
            token: SelectedEntry::of(entry).token,
            intent_summary,
            assurance: if structural {
                structural_assurance()
            } else {
                standing_assurance()
            },
            structural,
            warnings,
        },
        used,
    ))
}

/// The calls in Safe's packed MultiSend encoding: operation, address, value,
/// data length and data, back to back. Only plain calls to a nonzero address
/// are accepted; MultiSendCallOnly reverts on any other operation, and Safe
/// 1.5.0 reads a zero address as the Safe itself.
/// One call of a Safe batch: address, native value and calldata.
type BatchCall<'a> = (Address, U256, &'a [u8]);

fn safe_batch(packed: &[u8]) -> Result<Vec<BatchCall<'_>>, ReviewError> {
    let mut calls = Vec::new();
    let mut rest = packed;
    while !rest.is_empty() {
        if rest.len() < 85 || calls.len() == MAX_ARRAY_ITEMS {
            return Err(invalid("Safe batch is truncated or has too many calls"));
        }
        let to = Address::from_slice(&rest[1..21]);
        if rest[0] != 0 || to.is_zero() {
            return Err(invalid(
                "a Safe batch call must be a plain call to a nonzero address",
            ));
        }
        let length = usize::try_from(U256::from_be_slice(&rest[53..85]))
            .ok()
            .filter(|length| *length <= rest.len() - 85)
            .ok_or_else(|| invalid("Safe batch call data is truncated"))?;
        calls.push((
            to,
            U256::from_be_slice(&rest[21..53]),
            &rest[85..85 + length],
        ));
        rest = &rest[85 + length..];
    }
    if calls.is_empty() {
        return Err(invalid("Safe batch is empty"));
    }
    Ok(calls)
}

/// An embedded call, shown as one heading line and then its own fields, each
/// labelled under the heading. It is reviewed exactly as a top-level call
/// would be, so its entries become evidence and its refusals refuse. Returns
/// whether the reading is structural.
fn render_embedded(
    catalog: &Catalog,
    inner: &CallContext<'_>,
    label: &str,
    depth: usize,
    fields: &mut Vec<DisplayField>,
    used: &mut Vec<SelectedEntry>,
    warnings: &mut Vec<String>,
) -> Result<bool, ReviewError> {
    let raw = format!("0x{}", hex_lower(inner.calldata));
    let callee = checksum(&format!("0x{:x}", inner.to));
    if inner.calldata.is_empty() {
        let value = if inner.value.is_zero() {
            format!("No call (empty calldata to {callee})")
        } else {
            let native = inner.native.as_ref().ok_or_else(|| {
                unsupported("Bloom has no authenticated native units for this chain")
            })?;
            format!(
                "Send {} {} to {callee}",
                format_base_units(&inner.value.to_string(), native.decimals),
                native.symbol
            )
        };
        fields.push(DisplayField {
            label: label.to_owned(),
            format: "calldata".to_owned(),
            value,
            raw,
        });
        return Ok(false);
    }
    let address = format!("0x{:x}", inner.to);
    if catalog.entry(inner.chain_id, &address).is_none()
        && let Some(reading) = canonical_erc20(inner.calldata)
    {
        // No deployment is listed for the callee, so the instance entries
        // are not consulted: the ERC-20 shape is the only thing to read.
        return render_shaped_erc20(inner, label, reading, &raw, fields, warnings).map(|()| true);
    }
    let (call, entries) = review_at(catalog, inner, depth + 1)?;
    // Named by its function, as a top-level call is: publisher intent text
    // is never a heading.
    let action = call
        .function_signature
        .split('(')
        .next()
        .unwrap_or_default();
    fields.push(DisplayField {
        label: label.to_owned(),
        format: "calldata".to_owned(),
        value: match &call.contract_name {
            Some(name) => format!("{action} on {name} {}", call.contract),
            None => format!("{action} on {}", call.contract),
        },
        raw,
    });
    for field in call.fields {
        fields.push(DisplayField {
            label: format!("{label} · {}", field.label),
            ..field
        });
    }
    // A Safe calling itself would otherwise repeat the outer call's warning.
    for warning in call.warnings {
        if !warnings.contains(&warning) {
            warnings.push(format!("{label}: {warning}"));
        }
    }
    for entry in entries {
        if !used.contains(&entry) {
            used.push(entry);
        }
    }
    Ok(call.structural)
}

/// An embedded transfer or approval to a contract the catalog does not list:
/// the exact arguments, in raw units, under the same allowance policy as a
/// catalogued token.
fn render_shaped_erc20(
    inner: &CallContext<'_>,
    label: &str,
    (class, counterparty, amount): (ActionClass, Address, U256),
    raw: &str,
    fields: &mut Vec<DisplayField>,
    warnings: &mut Vec<String>,
) -> Result<(), ReviewError> {
    if !inner.value.is_zero() {
        return Err(invalid(
            "admitted contract calls must carry zero native value",
        ));
    }
    let callee = checksum(&format!("0x{:x}", inner.to));
    let counterparty = checksum(&format!("0x{counterparty:x}"));
    let (action, role, amount_label) = match class {
        ActionClass::Transfer => ("transfer", "Recipient", "Raw token amount"),
        _ => ("approve", "Spender", "Raw total allowance"),
    };
    let mut shown = vec![format!(
        "{label}: Bloom decoded an ERC-20-shaped call to {callee}, but has not verified that this contract is a token or follows ERC-20 behavior."
    )];
    if class == ActionClass::Allowance {
        if amount == U256::MAX {
            if !inner.unlimited_allowance_allowed {
                return Err(ReviewError::new(
                    ReviewReason::PolicyDenied,
                    "wallet policy denies unlimited allowances; enable them in a policy ceremony first",
                ));
            }
            shown.push(format!(
                "{label}: The allowance is the maximum uint256. If {callee} behaves as ERC-20, the spender can use all current and future tokens without asking again."
            ));
        } else if !amount.is_zero() {
            shown.push(format!(
                "{label}: If {callee} behaves as ERC-20, the spender can move tokens later without another approval."
            ));
        }
    }
    let amount = amount.to_string();
    fields.push(DisplayField {
        label: label.to_owned(),
        format: "calldata".to_owned(),
        value: format!("{action} on {callee}"),
        raw: raw.to_owned(),
    });
    fields.push(DisplayField {
        label: format!("{label} · {role}"),
        format: "addressName".to_owned(),
        value: counterparty.clone(),
        raw: counterparty,
    });
    fields.push(DisplayField {
        label: format!("{label} · {amount_label}"),
        format: "raw".to_owned(),
        value: amount.clone(),
        raw: amount,
    });
    warnings.extend(shown);
    Ok(())
}

/// The token a `tokenAmount` field is denominated in, and the catalog entry
/// that authenticated it.
struct ResolvedToken {
    identity: TokenIdentity,
    entry: SelectedEntry,
}

/// Resolve a field's token from the signed catalog.
///
/// For an argument token path, the address that was actually decoded is what
/// is looked up. A token the catalog does not list comes back as its
/// address, and its amount is shown in raw units rather than with borrowed
/// decimals.
fn resolve_token(
    source: &crate::TokenSource,
    call: &crate::AdmittedCall,
    leaves: &[DynSolValue],
    entry: &CatalogEntry,
    catalog: &Catalog,
    context: &CallContext<'_>,
) -> Result<Result<ResolvedToken, String>, ReviewError> {
    let token_entry = match source {
        crate::TokenSource::TargetContract => entry,
        crate::TokenSource::Argument(path) => {
            let index = call
                .leaves
                .iter()
                .position(|(name, _)| name == path)
                .expect("admission proved the token path is a decoded argument");
            let DynSolValue::Address(address) = &leaves[index] else {
                return Err(invalid("token path did not decode as an address"));
            };
            let address = format!("0x{address:x}");
            match catalog.entry(context.chain_id, &address) {
                Some(entry) if entry.token_metadata.is_some() => entry,
                _ => return Ok(Err(checksum(&address))),
            }
        }
    };
    let metadata = token_entry.token_metadata.as_ref().ok_or_else(|| {
        unsupported(format!(
            "the catalog has no decimals for {}, so its amount cannot be shown",
            checksum(&token_entry.contract_address)
        ))
    })?;
    Ok(Ok(ResolvedToken {
        identity: TokenIdentity {
            address: checksum(&token_entry.contract_address),
            symbol: metadata.symbol.clone(),
            name: metadata.name.clone(),
            decimals: metadata.decimals,
        },
        entry: SelectedEntry::of(token_entry),
    }))
}

/// The transfer and allowance rules. They read the generic decoded result and
/// cannot be turned off by a descriptor: a signed class must match the
/// canonical ERC-20 signature in both directions, so neither renaming
/// `approve` nor reclassifying it as `other` escapes allowance policy.
fn apply_safety_rules(
    call: &crate::AdmittedCall,
    leaves: &[DynSolValue],
    entry: &CatalogEntry,
    context: &CallContext<'_>,
    warnings: &mut Vec<String>,
) -> Result<(ActionClass, Option<CallIntent>), ReviewError> {
    let canonical = crate::parse_function(&call.signature)?.signature();
    let expected = match canonical.as_str() {
        TRANSFER_SIGNATURE => Some(ActionClass::Transfer),
        APPROVE_SIGNATURE => Some(ActionClass::Allowance),
        _ => None,
    };
    match (expected, call.action_class) {
        (Some(canonical_class), signed) if canonical_class != signed => {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                format!(
                    "`{canonical}` is signed as `{}` rather than `{}`",
                    signed.as_str(),
                    canonical_class.as_str()
                ),
            ));
        }
        (None, ActionClass::Transfer | ActionClass::Allowance) => {
            return Err(ReviewError::new(
                ReviewReason::CatalogRejected,
                format!(
                    "`{canonical}` is not the canonical ERC-20 signature for `{}`",
                    call.action_class.as_str()
                ),
            ));
        }
        _ => {}
    }
    if call.action_class == ActionClass::Other {
        return Ok((ActionClass::Other, None));
    }
    let (DynSolValue::Address(counterparty), DynSolValue::Uint(amount, _)) =
        (&leaves[0], &leaves[1])
    else {
        return Err(invalid(
            "ERC-20 arguments did not decode as an address and an amount",
        ));
    };
    if counterparty.is_zero() {
        return Err(invalid(match call.action_class {
            ActionClass::Transfer => "transfer to the zero address is refused",
            _ => "allowance for the zero address is refused",
        }));
    }
    if entry.token_metadata.is_none() {
        return Err(unsupported(
            "the catalog has no decimals for this token, so its amount cannot be shown",
        ));
    }
    // The identity every typed intent is denominated in. `token_metadata` was
    // just proved present, and for these two calls the target contract is the
    // token, so this is the same identity the fields were rendered against.
    let identity = SelectedEntry::of(entry)
        .token
        .expect("ERC-20 rules already required the catalog's token metadata");
    let summary = |action: &str, role: &str, magnitude: &str| CallIntent {
        action: action.to_owned(),
        counterparty_role: role.to_owned(),
        counterparty: checksum(&format!("0x{counterparty:x}")),
        amount: amount.to_string(),
        amount_display: format!(
            "{} {}",
            format_base_units(&amount.to_string(), identity.decimals),
            identity.symbol
        ),
        magnitude: magnitude.to_owned(),
        token: identity.clone(),
    };
    if call.action_class == ActionClass::Transfer {
        if format!("0x{:x}", counterparty) == entry.contract_address {
            return Err(invalid(
                "the token contract is not a valid recipient of its own transfer",
            ));
        }
        return Ok((
            ActionClass::Transfer,
            Some(summary("transfer", "recipient", "finite")),
        ));
    }
    let magnitude = if amount.is_zero() {
        warnings.push("This sets the spender's allowance to zero, clearing it.".to_owned());
        "zero"
    } else if *amount == U256::MAX {
        if !context.unlimited_allowance_allowed {
            return Err(ReviewError::new(
                ReviewReason::PolicyDenied,
                "wallet policy denies unlimited allowances; enable them in a policy ceremony first",
            ));
        }
        warnings.push(format!(
            "If executed, this spender can use all your current and future {} without asking again. This permission has no expiry; changing it requires another transaction.",
            identity.symbol
        ));
        "unlimited"
    } else {
        warnings.push(
            "This spender can move your tokens later without another approval. The permission does not expire with this review."
                .to_owned(),
        );
        warnings.push(
            "This sets the spender's total allowance to the amount shown. It is not added to any existing allowance."
                .to_owned(),
        );
        "finite"
    };
    let _ = context.chain_id;
    Ok((
        ActionClass::Allowance,
        Some(summary("allowance", "spender", magnitude)),
    ))
}

fn render_field(
    field: &crate::AdmittedField,
    value: &DynSolValue,
    token: Option<&ResolvedToken>,
    context: &CallContext<'_>,
) -> Result<DisplayField, ReviewError> {
    let raw = raw_value(value)?;
    let display = match &field.format {
        AdmittedFormat::Raw => match value {
            DynSolValue::Bytes(bytes) if bytes.len() > MAX_SHOWN_BYTES => {
                format!("{} bytes, keccak256 {:#x}", bytes.len(), keccak256(bytes))
            }
            _ => raw.clone(),
        },
        AdmittedFormat::AddressName => raw.clone(),
        AdmittedFormat::TokenAmount(_) => {
            let token = &token
                .expect("a tokenAmount field is always resolved before rendering")
                .identity;
            format!(
                "{} {}",
                format_base_units(&raw, token.decimals),
                token.symbol
            )
        }
        AdmittedFormat::Amount => {
            let native = context.native.as_ref().ok_or_else(|| {
                unsupported("Bloom has no authenticated native units for this chain")
            })?;
            format!(
                "{} {}",
                format_base_units(&raw, native.decimals),
                native.symbol
            )
        }
        AdmittedFormat::Date => {
            let seconds: u64 = raw
                .parse()
                .map_err(|_| unsupported("date value is outside the representable range"))?;
            if seconds > MAX_TIMESTAMP_SECONDS {
                return Err(unsupported("date value is outside the representable range"));
            }
            format!(
                "{} ({raw})",
                format_timestamp_ms(seconds.saturating_mul(1000))
            )
        }
        AdmittedFormat::Enum(map) => {
            let label = map.get(&raw).ok_or_else(|| {
                unsupported(format!("value {raw} has no label in the signed enum map"))
            })?;
            format!("{label} ({raw})")
        }
        AdmittedFormat::Calldata { .. } | AdmittedFormat::SafeBatch => {
            return Err(invalid(
                "an embedded call is rendered as a call, not a value",
            ));
        }
    };
    Ok(DisplayField {
        label: field.label.clone(),
        format: field.format.name().to_owned(),
        value: display,
        raw,
    })
}

/// A decoded value in the form `mustMatch` values are admitted in.
fn match_key(value: &DynSolValue) -> String {
    match value {
        DynSolValue::Address(address) => format!("0x{address:x}"),
        other => raw_value(other).unwrap_or_default(),
    }
}

fn raw_value(value: &DynSolValue) -> Result<String, ReviewError> {
    Ok(match value {
        DynSolValue::Address(address) => checksum(&format!("0x{address:x}")),
        DynSolValue::Uint(value, _) => value.to_string(),
        DynSolValue::Bool(value) => value.to_string(),
        DynSolValue::FixedBytes(bytes, size) => format!("0x{}", hex_lower(&bytes.0[..*size])),
        DynSolValue::Bytes(bytes) => format!("0x{}", hex_lower(bytes)),
        other => {
            return Err(invalid(format!(
                "argument decoded as an unsupported type: {other:?}"
            )));
        }
    })
}

/// The one check the re-encode round trip does not make.
///
/// Alloy keeps a narrow integer's full 32-byte word, so `uint64` carrying
/// 2^64 decodes and re-encodes to the identical bytes. Such a word is not a
/// canonical ABI encoding of a `uint64`: the high bits are required to be
/// zero and are not. What a given contract does with one is its own
/// business — Solidity's decoder reverts, hand-written assembly may mask,
/// and neither is something Bloom can determine offline. What Bloom can say
/// is that the value is not a valid encoding of the declared type, so it is
/// refused rather than displayed as the low 64 bits.
///
/// A `bytesN` word is the same story from the other end. Alloy detokenizes
/// every fixed-bytes leaf as the full 32-byte word and tokenizes the same word
/// back, so a `bytes4` carrying 28 trailing nonzero bytes round-trips
/// byte-identically while `raw_value` displays only the declared prefix. Those
/// bytes are part of what the passkey signs and would appear nowhere on screen,
/// which is exactly the invariant this crate exists to hold, so the tail is
/// required to be zero.
///
/// Address padding and noncanonical booleans do not survive the round trip, so
/// they are refused before this point.
fn check_leaf(path: &str, declared: &LeafType, value: &DynSolValue) -> Result<(), ReviewError> {
    match (declared, value) {
        (LeafType::Uint(bits), DynSolValue::Uint(value, width)) => {
            if width != bits || value.bit_len() > *bits {
                return Err(invalid(format!(
                    "argument `{path}` does not fit the declared uint{bits}"
                )));
            }
            Ok(())
        }
        (LeafType::Address, DynSolValue::Address(_)) | (LeafType::Bool, DynSolValue::Bool(_)) => {
            Ok(())
        }
        (LeafType::Bytes, DynSolValue::Bytes(_)) => Ok(()),
        (LeafType::Tuple(components), DynSolValue::Tuple(values))
            if components.len() == values.len() =>
        {
            components
                .iter()
                .zip(values)
                .try_for_each(|((name, kind), value)| {
                    check_leaf(&format!("{path}.[].{name}"), kind, value)
                })
        }
        (LeafType::Array(element), DynSolValue::Array(items)) => {
            if items.len() > MAX_ARRAY_ITEMS {
                return Err(ReviewError::new(
                    ReviewReason::LimitExceeded,
                    format!("argument `{path}` has more than {MAX_ARRAY_ITEMS} elements"),
                ));
            }
            items
                .iter()
                .try_for_each(|item| check_leaf(path, element, item))
        }
        (LeafType::FixedBytes(size), DynSolValue::FixedBytes(word, width)) if width == size => {
            if word.0[*size..].iter().any(|byte| *byte != 0) {
                return Err(invalid(format!(
                    "argument `{path}` is a bytes{size} word with nonzero trailing bytes"
                )));
            }
            Ok(())
        }
        _ => Err(invalid(format!(
            "argument `{path}` decoded as a different type than the description declares"
        ))),
    }
}

fn flatten(values: &[DynSolValue], out: &mut Vec<DynSolValue>) {
    for value in values {
        match value {
            DynSolValue::Tuple(children) => flatten(children, out),
            other => out.push(other.clone()),
        }
    }
}

/// Exact integer formatting: the base-units string is shifted by `decimals`
/// with no floating point, no rounding and no invented precision.
pub fn format_base_units(base_units: &str, decimals: u8) -> String {
    let decimals = usize::from(decimals);
    if decimals == 0 {
        return base_units.to_owned();
    }
    let padded = format!("{base_units:0>width$}", width = decimals + 1);
    let split = padded.len() - decimals;
    let fraction = padded[split..].trim_end_matches('0');
    if fraction.is_empty() {
        padded[..split].to_owned()
    } else {
        format!("{}.{fraction}", &padded[..split])
    }
}

/// `YYYY-MM-DD HH:MM:SS UTC` from milliseconds, by civil-date arithmetic.
/// A date library would be a dependency whose behaviour the verifier digest
/// would then have to cover without being able to see it.
pub fn format_timestamp_ms(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let time = seconds % 86_400;
    // Howard Hinnant's civil_from_days, shifted to an era starting 0000-03-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// EIP-55 mixed-case checksum over a lowercase `0x` address.
pub fn checksum(address: &str) -> String {
    address
        .parse::<Address>()
        .map(|address| address.to_checksum(None))
        .unwrap_or_else(|_| address.to_owned())
}
