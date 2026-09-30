//! The admitted ERC-7730 subset.
//!
//! This is deliberately a *reader*, not an interpreter. It accepts flattened
//! v2 documents pinned at `ethereum/ERCs@2528d6a0cd463d7309464a33889774368ab52df3`,
//! restricted to named static ABI scalars, direct named paths and six field
//! formats.
//!
//! Tuple arguments are deferred from this milestone. The limitation is
//! specific and was measured against the pinned parser, not assumed: a
//! format key is a human-readable signature, and `alloy_json_abi::Function`
//! at the pinned revision rejects `f((address beneficiary) terms)` outright
//! and parses `f((address) terms)` with its components unnamed. A field path
//! such as `terms.beneficiary` therefore has no name to resolve against
//! *through a signature key*. How to carry component names — a richer key,
//! the contract's JSON ABI as a second signed input, or positional paths —
//! is an open representation decision, deliberately left to the slice that
//! first needs it. Nothing here forecloses any of them.
//!
//! Anything outside the admitted subset makes the descriptor unusable rather
//! than partly rendered, and no instruction in a descriptor can suppress
//! Bloom's own headings or safety rules.
//!
//! This is a published subset. It is not full ERC-7730 conformance.

use std::collections::{BTreeMap, BTreeSet};

use alloy_json_abi::{Function, Param};
use serde_json::Value;

use crate::{
    ActionClass, AdmittedFunction, ReviewError, ReviewReason, catalog::is_control_or_bidi,
};

/// The released v2 schema this subset is taken from. Publisher tooling
/// validates source documents against it; Broker validates the subset.
pub const PINNED_SCHEMA_COMMIT: &str = "2528d6a0cd463d7309464a33889774368ab52df3";
pub const PINNED_SCHEMA_SHA256: &str =
    "53c0fe0ed07c3e032fc3bfabb105585b6648b2adae4858fbf45b3a09dfe691f5";

pub const DESCRIPTOR_MAX_BYTES: usize = 64 * 1024;
pub const MAX_ADMITTED_FORMATS: usize = 16;
pub const MAX_LEAVES_PER_FORMAT: usize = 32;
pub const MAX_TEXT_SCALARS: usize = 256;
pub const MAX_ENUM_ENTRIES: usize = 64;

/// The six admitted field formats. Each carries only what Bloom can honour
/// from authenticated data; name hints, thresholds and messages do not
/// survive admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmittedFormat {
    Raw,
    /// The raw address, always. Name sources are inert: no ENS request, no
    /// account-type assertion, no sentinel substitution.
    AddressName,
    /// An amount in a token, formatted with that token's authenticated
    /// decimals from the same signed catalog. Where the token comes from is
    /// fixed at admission; see [`TokenSource`].
    TokenAmount(TokenSource),
    /// An amount in the chain's native currency.
    Amount,
    /// A Unix timestamp in seconds. Block heights are not convertible offline.
    Date,
    /// A bounded local value-to-label map from `$.metadata.enums`.
    Enum(BTreeMap<String, String>),
}

/// Where a `tokenAmount` field's token comes from.
///
/// Both are resolved against the signed catalog and nothing else. An amount
/// is never formatted with decimals the descriptor supplied, and never with
/// decimals read from the chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenSource {
    /// `@.to`: the contract being called is itself the token.
    TargetContract,
    /// A named address argument of the same call. The address that was
    /// actually signed is looked up in the catalog, so the decimals and
    /// symbol shown belong to the token the calldata names — not to one the
    /// publisher assumed.
    Argument(String),
}

impl AdmittedFormat {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::AddressName => "addressName",
            Self::TokenAmount(_) => "tokenAmount",
            Self::Amount => "amount",
            Self::Date => "date",
            Self::Enum(_) => "enum",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedField {
    pub path: String,
    pub label: String,
    pub format: AdmittedFormat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeafType {
    Address,
    Uint(usize),
    Bool,
    FixedBytes(usize),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedCall {
    pub signature: String,
    pub selector: [u8; 4],
    pub action_class: ActionClass,
    /// Supplemental publisher text. Never the heading, never policy input.
    pub intent: Option<String>,
    pub fields: Vec<AdmittedField>,
    pub leaves: Vec<(String, LeafType)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedDescriptor {
    pub contract_name: Option<String>,
    pub calls: Vec<AdmittedCall>,
}

impl AdmittedDescriptor {
    pub fn call(&self, selector: &[u8]) -> Option<&AdmittedCall> {
        self.calls
            .iter()
            .find(|call| call.selector.as_slice() == selector)
    }
}

/// Parse a human-readable function signature the way an ERC-7730 format key
/// spells it. Exposed so a caller can derive the same selector this reader
/// derives, rather than deriving one of its own.
pub fn parse_function(signature: &str) -> Result<Function, ReviewError> {
    Function::parse(signature).map_err(|error| {
        rejected(format!(
            "`{signature}` is not a function signature: {error}"
        ))
    })
}

fn rejected(message: impl Into<String>) -> ReviewError {
    ReviewError::new(ReviewReason::CatalogRejected, message)
}

fn object<'a>(
    value: &'a Value,
    what: &str,
) -> Result<&'a serde_json::Map<String, Value>, ReviewError> {
    value
        .as_object()
        .ok_or_else(|| rejected(format!("{what} must be a JSON object")))
}

/// Reject any key outside the admitted set, naming it. Silently ignoring an
/// unknown instruction is how a descriptor would hide meaning from review.
fn only_keys(
    map: &serde_json::Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), ReviewError> {
    if let Some(unexpected) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(rejected(format!(
            "{what} carries unsupported instruction `{unexpected}`"
        )));
    }
    Ok(())
}

fn text(value: &Value, what: &str) -> Result<String, ReviewError> {
    let value = value
        .as_str()
        .ok_or_else(|| rejected(format!("{what} must be a string")))?;
    if value.is_empty()
        || value.chars().count() > MAX_TEXT_SCALARS
        || value.chars().any(is_control_or_bidi)
    {
        return Err(rejected(format!(
            "{what} must be 1-{MAX_TEXT_SCALARS} scalar values without control or bidi characters"
        )));
    }
    Ok(value.to_owned())
}

/// Admit one flattened descriptor for one catalog entry.
///
/// `chain_id`/`address` come from the signed entry, not the document: the
/// descriptor must agree with the binding it was signed under, and a document
/// that describes some other deployment is rejected rather than reused.
pub fn admit(
    descriptor: &Value,
    chain_id: u64,
    address: &str,
    admitted_functions: &[AdmittedFunction],
) -> Result<AdmittedDescriptor, ReviewError> {
    let encoded = serde_jcs::to_vec(descriptor)
        .map_err(|error| rejected(format!("descriptor canonicalization failed: {error}")))?;
    if encoded.len() > DESCRIPTOR_MAX_BYTES {
        return Err(ReviewError::new(
            ReviewReason::LimitExceeded,
            format!("descriptor exceeds {DESCRIPTOR_MAX_BYTES} bytes"),
        ));
    }
    if admitted_functions.len() > MAX_ADMITTED_FORMATS {
        return Err(ReviewError::new(
            ReviewReason::LimitExceeded,
            format!("entry admits more than {MAX_ADMITTED_FORMATS} functions"),
        ));
    }
    let root = object(descriptor, "descriptor")?;
    if root.contains_key("includes") {
        return Err(rejected(
            "descriptor carries an unresolved include; publisher tooling must flatten it",
        ));
    }
    only_keys(
        root,
        &["$schema", "$comment", "context", "metadata", "display"],
        "descriptor",
    )?;

    check_binding(root, chain_id, address)?;
    let (contract_name, enums) = read_metadata(root)?;

    let display = object(
        root.get("display")
            .ok_or_else(|| rejected("descriptor has no display section"))?,
        "display",
    )?;
    only_keys(display, &["formats"], "display")?;
    let formats = object(
        display
            .get("formats")
            .ok_or_else(|| rejected("display has no formats"))?,
        "display.formats",
    )?;

    // Every format key in the document contributes a selector, whether or not
    // it was admitted. Two keys sharing a selector make the match ambiguous,
    // so the document is unusable even if only one of them was admitted.
    let mut selectors: BTreeMap<[u8; 4], String> = BTreeMap::new();
    for key in formats.keys() {
        let function = parse_function(key)?;
        if let Some(existing) = selectors.insert(function.selector().0, key.clone()) {
            return Err(rejected(format!(
                "format keys `{existing}` and `{key}` select the same function"
            )));
        }
    }

    let mut calls = Vec::with_capacity(admitted_functions.len());
    for admitted in admitted_functions {
        let format = formats.get(&admitted.signature).ok_or_else(|| {
            rejected(format!(
                "entry admits `{}`, which the descriptor does not describe",
                admitted.signature
            ))
        })?;
        calls.push(admit_call(
            &admitted.signature,
            admitted.action_class,
            format,
            &enums,
        )?);
    }
    Ok(AdmittedDescriptor {
        contract_name,
        calls,
    })
}

fn check_binding(
    root: &serde_json::Map<String, Value>,
    chain_id: u64,
    address: &str,
) -> Result<(), ReviewError> {
    let context = object(
        root.get("context")
            .ok_or_else(|| rejected("descriptor has no context section"))?,
        "context",
    )?;
    only_keys(context, &["$id", "contract"], "context")?;
    let contract = object(
        context
            .get("contract")
            .ok_or_else(|| rejected("only contract binding contexts are supported"))?,
        "context.contract",
    )?;
    // `abi` is deprecated upstream and `factory` would make the binding
    // depend on a deployment event Broker cannot observe.
    only_keys(contract, &["deployments"], "context.contract")?;
    let deployments = contract
        .get("deployments")
        .and_then(Value::as_array)
        .ok_or_else(|| rejected("context.contract.deployments must be an array"))?;
    let bound = deployments.iter().any(|deployment| {
        deployment.get("chainId").and_then(Value::as_u64) == Some(chain_id)
            && deployment
                .get("address")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(address))
    });
    if !bound {
        return Err(rejected(
            "descriptor deployments do not include this catalog entry's chain and address",
        ));
    }
    Ok(())
}

type EnumMaps = BTreeMap<String, BTreeMap<String, String>>;

fn read_metadata(
    root: &serde_json::Map<String, Value>,
) -> Result<(Option<String>, EnumMaps), ReviewError> {
    let Some(metadata) = root.get("metadata") else {
        return Ok((None, EnumMaps::new()));
    };
    let metadata = object(metadata, "metadata")?;
    // `token`, `constants` and `maps` would let the document supply units and
    // substitutions Broker must take from the signed catalog instead.
    only_keys(metadata, &["owner", "contractName", "enums"], "metadata")?;
    let contract_name = metadata
        .get("contractName")
        .map(|value| text(value, "metadata.contractName"))
        .transpose()?;
    let mut enums = EnumMaps::new();
    if let Some(declared) = metadata.get("enums") {
        for (name, map) in object(declared, "metadata.enums")? {
            let map = object(map, "metadata.enums entry")?;
            if map.is_empty() || map.len() > MAX_ENUM_ENTRIES {
                return Err(ReviewError::new(
                    ReviewReason::LimitExceeded,
                    format!("enum `{name}` must hold 1-{MAX_ENUM_ENTRIES} labels"),
                ));
            }
            let mut values = BTreeMap::new();
            for (value, label) in map {
                values.insert(value.clone(), text(label, "enum label")?);
            }
            enums.insert(name.clone(), values);
        }
    }
    Ok((contract_name, enums))
}

fn admit_call(
    signature: &str,
    action_class: ActionClass,
    format: &Value,
    enums: &EnumMaps,
) -> Result<AdmittedCall, ReviewError> {
    let format = object(format, "format")?;
    // `interpolatedIntent` would let the publisher compose a sentence out of
    // decoded values; Bloom owns the sentence.
    only_keys(format, &["$id", "intent", "fields"], "format")?;
    let intent = format
        .get("intent")
        .map(|value| text(value, "format.intent"))
        .transpose()?;

    let function = parse_function(signature)?;
    let mut leaves = Vec::new();
    collect_leaves(&function.inputs, &mut leaves)?;
    if leaves.is_empty() || leaves.len() > MAX_LEAVES_PER_FORMAT {
        return Err(ReviewError::new(
            ReviewReason::LimitExceeded,
            format!("`{signature}` must decode 1-{MAX_LEAVES_PER_FORMAT} static arguments"),
        ));
    }
    let leaf_types: BTreeMap<&str, &LeafType> = leaves
        .iter()
        .map(|(path, kind)| (path.as_str(), kind))
        .collect();

    let declared = format
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| rejected(format!("`{signature}` has no fields array")))?;
    if declared.len() > MAX_LEAVES_PER_FORMAT {
        return Err(ReviewError::new(
            ReviewReason::LimitExceeded,
            format!("`{signature}` declares more than {MAX_LEAVES_PER_FORMAT} fields"),
        ));
    }
    let mut fields = Vec::with_capacity(declared.len());
    let mut covered = BTreeSet::new();
    for field in declared {
        let field = object(field, "field")?;
        // A reference, a value constant, a field group or an encrypted field
        // would each display something other than the argument at a path.
        only_keys(
            field,
            &["$id", "path", "label", "format", "params", "visible"],
            "field",
        )?;
        if let Some(visible) = field.get("visible")
            && visible.as_str() != Some("always")
        {
            return Err(rejected(
                "only always-visible fields are supported; hidden and conditional rules are not",
            ));
        }
        let path = normalize_path(&text(
            field
                .get("path")
                .ok_or_else(|| rejected("field has no path"))?,
            "field.path",
        )?)?;
        let label = text(
            field
                .get("label")
                .ok_or_else(|| rejected("field has no label"))?,
            "field.label",
        )?;
        let kind = leaf_types.get(path.as_str()).ok_or_else(|| {
            rejected(format!(
                "field path `{path}` is not a decoded argument of `{signature}`"
            ))
        })?;
        if !covered.insert(path.clone()) {
            return Err(rejected(format!("argument `{path}` is displayed twice")));
        }
        let format_name = field
            .get("format")
            .ok_or_else(|| rejected(format!("field `{path}` has no format")))?
            .as_str()
            .ok_or_else(|| rejected("field format must be a string"))?;
        let params = field.get("params");
        fields.push(AdmittedField {
            format: admit_format(format_name, params, kind, &path, enums, &leaf_types)?,
            path,
            label,
        });
    }
    // Every decoded leaf must be on screen. A descriptor that simply omits an
    // argument is the quiet failure this rule exists to prevent.
    if covered.len() != leaves.len() {
        let missing = leaves
            .iter()
            .map(|(path, _)| path.as_str())
            .find(|path| !covered.contains(*path))
            .unwrap_or("?");
        return Err(rejected(format!(
            "`{signature}` decodes argument `{missing}` without displaying it"
        )));
    }
    Ok(AdmittedCall {
        signature: signature.to_owned(),
        selector: function.selector().0,
        action_class,
        intent,
        fields,
        leaves,
    })
}

fn admit_format(
    name: &str,
    params: Option<&Value>,
    kind: &LeafType,
    path: &str,
    enums: &EnumMaps,
    leaf_types: &BTreeMap<&str, &LeafType>,
) -> Result<AdmittedFormat, ReviewError> {
    let params_map = match params {
        Some(value) => object(value, "field.params")?.clone(),
        None => serde_json::Map::new(),
    };
    let mismatched = |expected: &str| {
        rejected(format!(
            "format `{name}` on `{path}` requires a {expected} argument"
        ))
    };
    match name {
        "raw" => {
            only_keys(&params_map, &[], "raw params")?;
            Ok(AdmittedFormat::Raw)
        }
        "addressName" => {
            // Name sources and address types are retained upstream but inert
            // here: the review shows the address that was signed.
            only_keys(&params_map, &["types", "sources"], "addressName params")?;
            matches!(kind, LeafType::Address)
                .then_some(AdmittedFormat::AddressName)
                .ok_or_else(|| mismatched("address"))
        }
        "tokenAmount" => {
            // `token`, `threshold`, `message`, `nativeCurrencyAddress` and
            // `chainId` each substitute or relabel a value. Bloom's own
            // maximum-U256 rule owns the unlimited warning, so a descriptor
            // cannot call a large finite allowance unlimited.
            only_keys(&params_map, &["tokenPath"], "tokenAmount params")?;
            let token_path = params_map
                .get("tokenPath")
                .and_then(Value::as_str)
                .ok_or_else(|| rejected("tokenAmount requires a tokenPath"))?;
            let source = if token_path == "@.to" {
                TokenSource::TargetContract
            } else {
                // A token path may name an address argument of the same call,
                // and nothing else. A container path, a path into another
                // call, or a path to a non-address argument has no address to
                // resolve and is refused rather than guessed at.
                let named = normalize_path(token_path)?;
                match leaf_types.get(named.as_str()) {
                    Some(LeafType::Address) => TokenSource::Argument(named),
                    Some(_) => {
                        return Err(rejected(format!(
                            "tokenPath `{named}` names an argument that is not an address"
                        )));
                    }
                    None => {
                        return Err(rejected(format!(
                            "tokenPath `{named}` is not `@.to` and is not a decoded argument of this call"
                        )));
                    }
                }
            };
            matches!(kind, LeafType::Uint(_))
                .then_some(AdmittedFormat::TokenAmount(source))
                .ok_or_else(|| mismatched("unsigned integer"))
        }
        "amount" => {
            only_keys(&params_map, &[], "amount params")?;
            matches!(kind, LeafType::Uint(_))
                .then_some(AdmittedFormat::Amount)
                .ok_or_else(|| mismatched("unsigned integer"))
        }
        "date" => {
            only_keys(&params_map, &["encoding"], "date params")?;
            if params_map.get("encoding").and_then(Value::as_str) != Some("timestamp") {
                return Err(rejected(
                    "date accepts only timestamp encoding; block height cannot be converted offline",
                ));
            }
            matches!(kind, LeafType::Uint(_))
                .then_some(AdmittedFormat::Date)
                .ok_or_else(|| mismatched("unsigned integer"))
        }
        "enum" => {
            only_keys(&params_map, &["$ref"], "enum params")?;
            let reference = params_map
                .get("$ref")
                .and_then(Value::as_str)
                .ok_or_else(|| rejected("enum requires a $ref to a local metadata map"))?;
            let key = reference
                .strip_prefix("$.metadata.enums.")
                .ok_or_else(|| rejected("enum $ref must name a local $.metadata.enums map"))?;
            let map = enums
                .get(key)
                .ok_or_else(|| rejected(format!("enum map `{key}` is not defined")))?;
            matches!(
                kind,
                LeafType::Uint(_) | LeafType::Bool | LeafType::FixedBytes(_)
            )
            .then(|| AdmittedFormat::Enum(map.clone()))
            .ok_or_else(|| mismatched("integer, boolean or fixed-bytes"))
        }
        other => Err(rejected(format!(
            "field format `{other}` is outside the supported subset"
        ))),
    }
}

/// `#.` is the upstream spelling for "relative to this structure". Nothing
/// else is accepted: no slices, container roots, maps or expressions, and no
/// dotted descent while tuples are unsupported.
fn normalize_path(path: &str) -> Result<String, ReviewError> {
    let path = path.strip_prefix("#.").unwrap_or(path);
    let valid = !path.is_empty()
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !path.as_bytes()[0].is_ascii_digit();
    if !valid {
        return Err(rejected(format!(
            "field path `{path}` is not a direct named argument path"
        )));
    }
    Ok(path.to_owned())
}

fn collect_leaves(params: &[Param], out: &mut Vec<(String, LeafType)>) -> Result<(), ReviewError> {
    for param in params {
        if param.name.is_empty() {
            return Err(rejected(
                "every argument must be named so a field path can reference it",
            ));
        }
        if !param.components.is_empty() || param.ty.starts_with("tuple") {
            return Err(rejected(format!(
                "argument `{}` is a tuple; component names do not survive a signature key, so no field path can reach it",
                param.name
            )));
        }
        out.push((param.name.clone(), static_leaf_type(&param.ty)?));
        if out.len() > MAX_LEAVES_PER_FORMAT {
            return Err(ReviewError::new(
                ReviewReason::LimitExceeded,
                format!("more than {MAX_LEAVES_PER_FORMAT} decoded arguments"),
            ));
        }
    }
    Ok(())
}

/// Canonical static scalars only. `uint`/`int` aliases, signed integers,
/// dynamic `bytes`/`string` and every array form are refused, so a decoded
/// value always has one fixed width and one unambiguous spelling.
fn static_leaf_type(ty: &str) -> Result<LeafType, ReviewError> {
    if ty == "address" {
        return Ok(LeafType::Address);
    }
    if ty == "bool" {
        return Ok(LeafType::Bool);
    }
    if let Some(bits) = ty.strip_prefix("uint")
        && let Ok(bits) = bits.parse::<usize>()
        && bits > 0
        && bits <= 256
        && bits % 8 == 0
    {
        return Ok(LeafType::Uint(bits));
    }
    if let Some(size) = ty.strip_prefix("bytes")
        && let Ok(size) = size.parse::<usize>()
        && (1..=32).contains(&size)
    {
        return Ok(LeafType::FixedBytes(size));
    }
    Err(rejected(format!(
        "argument type `{ty}` is outside the supported static subset"
    )))
}
