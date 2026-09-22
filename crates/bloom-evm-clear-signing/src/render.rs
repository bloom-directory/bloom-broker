//! Strict decode, bounded formatting and the wallet safety rules.
//!
//! One generic decoder serves every admitted function; there is no
//! selector-specific parser and no executable plugin. The transfer and
//! allowance rules below *inspect* that generic result — they do not select a
//! different decoder — so adding a contract is catalog data, while changing
//! what Bloom promises about a call is code.

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::Function;
use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use crate::{
    AcceptedCatalog, ActionClass, AdmittedFormat, CatalogEntry, LeafType, ReviewError, ReviewReason,
};

pub const TRANSFER_SIGNATURE: &str = "transfer(address,uint256)";
pub const APPROVE_SIGNATURE: &str = "approve(address,uint256)";
/// Latest timestamp rendered as a date: 23:59:59 UTC, 31 December 9999.
const MAX_TIMESTAMP_SECONDS: u64 = 253_402_300_799;

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
    "Interpreted using a trusted signed description. Contract behavior has not been verified."
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
    /// What reading this call against a signed description does and does not
    /// establish. Identical for every clear-signed call, so a review states
    /// it once; it is not a property of this call and never a warning.
    #[serde(default = "standing_assurance")]
    pub assurance: String,
    /// Risks specific to this call: upgradeability, and what an allowance
    /// grants. Never the standing assurance.
    pub warnings: Vec<String>,
}

/// The complete signed entry a review selected, kept so activation and
/// signing can tell whether the catalog still says the same thing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedEntry {
    pub chain_id: String,
    pub contract_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_code_hash: Option<String>,
    pub observed_at_ms: String,
    pub upgradeable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenIdentity>,
}

impl SelectedEntry {
    pub fn of(entry: &CatalogEntry) -> Self {
        Self {
            chain_id: entry.chain_id.as_str().to_owned(),
            contract_address: entry.contract_address.clone(),
            descriptor_digest: entry
                .descriptor_digest
                .as_ref()
                .map(|digest| digest.as_str().to_owned()),
            runtime_code_hash: entry
                .runtime_code_hash
                .as_ref()
                .map(|digest| digest.as_str().to_owned()),
            observed_at_ms: entry.observed_at_ms.as_str().to_owned(),
            upgradeable: entry.upgradeable,
            implementation_hash: entry
                .implementation_hash
                .as_ref()
                .map(|digest| digest.as_str().to_owned()),
            token: entry.token_metadata.as_ref().map(|metadata| TokenIdentity {
                address: checksum(&entry.contract_address),
                symbol: metadata.symbol.clone(),
                name: metadata.name.clone(),
                decimals: metadata.decimals,
            }),
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
    catalog: &AcceptedCatalog,
    context: &CallContext<'_>,
) -> Result<(ClearSignedCall, Vec<SelectedEntry>), ReviewError> {
    let address = format!("{:x}", context.to);
    let address = format!("0x{address}");
    let entry = catalog.entry(context.chain_id, &address).ok_or_else(|| {
        unsupported(format!(
            "no signed description for {address} on chain {}",
            context.chain_id
        ))
    })?;
    let admitted = catalog
        .descriptor(context.chain_id, &entry.contract_address)
        .ok_or_else(|| unsupported("catalog entry carries token metadata but no descriptor"))?;
    if context.calldata.len() < 4 {
        return Err(invalid("contract call has no complete selector"));
    }
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
    let function = Function::parse(&call.signature)
        .map_err(|error| invalid(format!("admitted signature no longer parses: {error}")))?;
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

    let mut used = vec![SelectedEntry::of(entry)];
    let mut fields = Vec::with_capacity(call.fields.len());
    for field in &call.fields {
        let index = call
            .leaves
            .iter()
            .position(|(path, _)| path == &field.path)
            .expect("admission proved every field path is a decoded leaf");
        let token = match &field.format {
            AdmittedFormat::TokenAmount(source) => Some(resolve_token(
                source, call, &leaves, entry, catalog, context,
            )?),
            _ => None,
        };
        if let Some(token) = &token
            && !used.iter().any(|selected| selected == &token.entry)
        {
            used.push(token.entry.clone());
        }
        fields.push(render_field(
            field,
            &leaves[index],
            token.as_ref(),
            context,
        )?);
    }

    // The standing assurance is not a warning about this call: it is the same
    // sentence for every clear-signed call, and it was sitting at index 0 of
    // `warnings` where the only way to tell it apart was to match its text.
    // Typed, a page can state it once per review and keep `warnings` for the
    // risks that actually differ between calls.
    let mut warnings: Vec<String> = Vec::new();
    if entry.upgradeable {
        warnings.push(format!(
            "This contract can be upgraded. The publisher observed it at {}; its code may have changed since.",
            format_timestamp_ms(entry.observed_at_ms.get())
        ));
    }
    let (action, intent_summary) =
        apply_safety_rules(call, &leaves, entry, context, &mut warnings)?;

    Ok((
        ClearSignedCall {
            contract: checksum(&entry.contract_address),
            contract_name: admitted.contract_name.clone(),
            function_signature: call.signature.clone(),
            selector: format!("0x{}", hex_lower(&call.selector)),
            action: action.as_str().to_owned(),
            intent: call.intent.clone(),
            fields,
            token: SelectedEntry::of(entry).token,
            intent_summary,
            assurance: standing_assurance(),
            warnings,
        },
        used,
    ))
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
/// is looked up — so a call naming a token the catalog does not describe is
/// unsupported rather than shown with borrowed decimals.
fn resolve_token(
    source: &crate::TokenSource,
    call: &crate::AdmittedCall,
    leaves: &[DynSolValue],
    entry: &CatalogEntry,
    catalog: &AcceptedCatalog,
    context: &CallContext<'_>,
) -> Result<ResolvedToken, ReviewError> {
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
            catalog.entry(context.chain_id, &address).ok_or_else(|| {
                unsupported(format!(
                    "no signed description of the token {address} this call names"
                ))
            })?
        }
    };
    let metadata = token_entry.token_metadata.as_ref().ok_or_else(|| {
        unsupported(format!(
            "the catalog has no decimals for {}, so its amount cannot be shown",
            checksum(&token_entry.contract_address)
        ))
    })?;
    Ok(ResolvedToken {
        identity: TokenIdentity {
            address: checksum(&token_entry.contract_address),
            symbol: metadata.symbol.clone(),
            name: metadata.name.clone(),
            decimals: metadata.decimals,
        },
        entry: SelectedEntry::of(token_entry),
    })
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
    let canonical = Function::parse(&call.signature)
        .map_err(|error| invalid(error.to_string()))?
        .signature();
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
    warnings.push(
        "An allowance lets this spender move your tokens later, with no further Bloom approval. It does not expire when this approval expires."
            .to_owned(),
    );
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
        warnings.push(
            "UNLIMITED ALLOWANCE. This spender may move every token of this kind you now hold or later receive."
                .to_owned(),
        );
        "unlimited"
    } else {
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
        AdmittedFormat::Raw => raw.clone(),
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
    };
    Ok(DisplayField {
        label: field.label.clone(),
        format: field.format.name().to_owned(),
        value: display,
        raw,
    })
}

fn raw_value(value: &DynSolValue) -> Result<String, ReviewError> {
    Ok(match value {
        DynSolValue::Address(address) => checksum(&format!("0x{address:x}")),
        DynSolValue::Uint(value, _) => value.to_string(),
        DynSolValue::Bool(value) => value.to_string(),
        DynSolValue::FixedBytes(bytes, size) => format!("0x{}", hex_lower(&bytes.0[..*size])),
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
/// Address padding, noncanonical booleans and oversized `bytesN` do not
/// survive the round trip, so they are refused before this point.
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
        (LeafType::FixedBytes(size), DynSolValue::FixedBytes(_, width)) if width == size => Ok(()),
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
