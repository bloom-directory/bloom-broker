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
/// Values one `mustMatch` rule may list.
pub const MAX_MATCH_VALUES: usize = 64;

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
    /// A call carried inside this one, read against the same catalog as a
    /// call of its own: an undescribed inner call makes the whole call
    /// unsupported, and its policy refusals still refuse.
    Calldata {
        callee: CalleeSource,
        /// A named uint argument carrying the native value the inner call
        /// sends, when there is one.
        amount: Option<String>,
    },
    /// Safe's packed `MultiSend` transactions, each read as an embedded call.
    /// Only the built-in Safe batch description uses it; no descriptor can.
    SafeBatch,
}

/// Which contract an embedded call is made to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalleeSource {
    /// `@.to`: the contract being called calls itself.
    TargetContract,
    /// A named address argument of the same call.
    Argument(String),
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
            Self::Calldata { .. } => "calldata",
            Self::SafeBatch => "safeBatch",
        }
    }
}

/// A displayed argument. For an array argument the format applies to each
/// element, and each element is shown on its own line.
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
    /// Dynamic `bytes`: shown raw, or read as an embedded call.
    Bytes,
    /// A dynamic array of one static scalar type, or of a tuple.
    Array(Box<LeafType>),
    /// The named components of an array element: static scalars or `bytes`.
    Tuple(Vec<(String, LeafType)>),
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
    /// `mustMatch` rules: the argument at the path must equal one of the
    /// values, in the form `match_key` gives a decoded value. A constrained
    /// argument is not shown, because the description fixes it.
    pub constraints: Vec<(String, Vec<String>)>,
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
    let parse_error = |error: String| {
        rejected(format!(
            "`{signature}` is not a function signature: {error}"
        ))
    };
    // ERC-7730 names tuple components in the key, which the alloy parser
    // refuses, so they are lifted out here and put back on the parsed inputs.
    let open = signature
        .find('(')
        .ok_or_else(|| parse_error("no argument list".into()))?;
    let mut names = Vec::new();
    let mut rest = &signature[open + 1..];
    let stripped = strip_component_names(&mut rest, true, &mut names).map_err(parse_error)?;
    if !rest.is_empty() {
        return Err(parse_error("text after the argument list".into()));
    }
    let mut function = Function::parse(&format!("{}({stripped})", &signature[..open]))
        .map_err(|error| parse_error(error.to_string()))?;
    let mut names = names.into_iter();
    for input in &mut function.inputs {
        name_components(input, &mut names).map_err(parse_error)?;
    }
    Ok(function)
}

/// Read one argument list up to and including its `)`, returning it without
/// the names of tuple components (top-level names stay). The component names
/// are collected per tuple, outer tuples first.
fn strip_component_names(
    rest: &mut &str,
    top: bool,
    names: &mut Vec<Vec<String>>,
) -> Result<String, String> {
    let mut out = Vec::new();
    let mut own = Vec::new();
    let slot = names.len();
    if !top {
        names.push(Vec::new());
    }
    loop {
        *rest = rest.trim_start();
        let mut ty = String::new();
        if let Some(inner) = rest.strip_prefix('(') {
            *rest = inner;
            ty = format!("({})", strip_component_names(rest, false, names)?);
        } else if let Some(after) = rest.strip_prefix(')') {
            if !out.is_empty() {
                return Err("empty argument".into());
            }
            *rest = after;
            return Ok(String::new());
        }
        let end = rest
            .find([',', ')', ' '])
            .ok_or("unterminated argument list")?;
        ty.push_str(&rest[..end]);
        *rest = rest[end..].trim_start();
        let end = rest.find([',', ')']).ok_or("unterminated argument list")?;
        let name = rest[..end].trim();
        *rest = &rest[end..];
        if top {
            out.push(if name.is_empty() {
                ty
            } else {
                format!("{ty} {name}")
            });
        } else {
            out.push(ty);
            own.push(name.to_owned());
        }
        let close = rest.starts_with(')');
        *rest = &rest[1..];
        if close {
            break;
        }
    }
    if !top {
        names[slot] = own;
    }
    Ok(out.join(","))
}

fn name_components(
    param: &mut Param,
    names: &mut impl Iterator<Item = Vec<String>>,
) -> Result<(), String> {
    if param.components.is_empty() {
        return Ok(());
    }
    let own = names
        .next()
        .ok_or("tuple names do not match the tuple types")?;
    if own.len() != param.components.len() {
        return Err("tuple names do not match the tuple types".into());
    }
    for (component, name) in param.components.iter_mut().zip(own) {
        component.name = name;
        name_components(component, names)?;
    }
    Ok(())
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

/// The transfer and approval description every listed token is read by. It
/// is compiled in, so it is covered by the verifier digest, and a token is
/// listed by its metadata alone.
pub fn erc20_profile() -> (Value, Vec<AdmittedFunction>) {
    let descriptor = serde_json::json!({
        "display": {"formats": {
            "transfer(address to, uint256 amount)": {"fields": [
                {"path": "to", "label": "To", "format": "addressName"},
                {"path": "amount", "label": "Amount", "format": "tokenAmount",
                 "params": {"tokenPath": "@.to"}}
            ]},
            "approve(address spender, uint256 amount)": {"fields": [
                {"path": "spender", "label": "Spender", "format": "addressName"},
                {"path": "amount", "label": "Amount", "format": "tokenAmount",
                 "params": {"tokenPath": "@.to"}}
            ]}
        }}
    });
    let functions = vec![
        AdmittedFunction {
            signature: "transfer(address to, uint256 amount)".to_owned(),
            action_class: ActionClass::Transfer,
        },
        AdmittedFunction {
            signature: "approve(address spender, uint256 amount)".to_owned(),
            action_class: ActionClass::Allowance,
        },
    ];
    (descriptor, functions)
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
    admit_document(descriptor, Some((chain_id, address)), admitted_functions)
}

/// Every `(chain, address)` a descriptor binds itself to, lowercased.
pub fn deployments(descriptor: &Value) -> Result<Vec<(u64, String)>, ReviewError> {
    descriptor
        .pointer("/context/contract/deployments")
        .and_then(Value::as_array)
        .ok_or_else(|| rejected("context.contract.deployments must be an array"))?
        .iter()
        .map(|deployment| {
            let chain_id = deployment.get("chainId").and_then(Value::as_u64);
            let address = deployment.get("address").and_then(Value::as_str);
            match (chain_id, address) {
                (Some(chain_id), Some(address)) => Ok((chain_id, address.to_ascii_lowercase())),
                _ => Err(rejected("a deployment needs a chainId and an address")),
            }
        })
        .collect()
}

/// `binding` is `None` only for the built-in ERC-20 profile, which describes
/// every listed token rather than one deployment.
pub(crate) fn admit_document(
    descriptor: &Value,
    binding: Option<(u64, &str)>,
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

    if let Some((chain_id, address)) = binding {
        check_binding(root, chain_id, address)?;
    }
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
            format!("`{signature}` must decode 1-{MAX_LEAVES_PER_FORMAT} arguments"),
        ));
    }
    let paths = addressable(&leaves);

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
    let mut constraints = Vec::new();
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
        // `mustMatch` is the one hidden rule admitted: it does not hide a
        // value, it fixes it, and any other value refuses the call.
        let allowed = match field.get("visible") {
            None => None,
            Some(visible) if visible.as_str() == Some("always") => None,
            Some(Value::Object(rule)) if rule.len() == 1 && rule.contains_key("mustMatch") => {
                Some(&rule["mustMatch"])
            }
            Some(_) => {
                return Err(rejected(
                    "a field is always visible or carries a mustMatch rule; hidden and conditional rules are not supported",
                ));
            }
        };
        let path = normalize_path(&text(
            field
                .get("path")
                .ok_or_else(|| rejected("field has no path"))?,
            "field.path",
        )?)?;
        let kind = *paths.get(path.as_str()).ok_or_else(|| {
            rejected(format!(
                "field path `{path}` is not a decoded argument of `{signature}`"
            ))
        })?;
        if !covered.insert(path.clone()) {
            return Err(rejected(format!("argument `{path}` is displayed twice")));
        }
        if let Some(allowed) = allowed {
            only_keys(
                field,
                &["$id", "path", "label", "visible"],
                "mustMatch field",
            )?;
            constraints.push((path.clone(), match_values(allowed, kind, &path)?));
            continue;
        }
        let label = text(
            field
                .get("label")
                .ok_or_else(|| rejected("field has no label"))?,
            "field.label",
        )?;
        let format_name = field
            .get("format")
            .ok_or_else(|| rejected(format!("field `{path}` has no format")))?
            .as_str()
            .ok_or_else(|| rejected("field format must be a string"))?;
        let params = field.get("params");
        let format = admit_format(format_name, params, kind, &path, enums, &paths)?;
        if array_of(&path).is_some() && matches!(format, AdmittedFormat::TokenAmount(_)) {
            return Err(rejected(format!(
                "`{path}` cannot be a token amount: each element would need its own token"
            )));
        }
        fields.push(AdmittedField {
            format,
            path,
            label,
        });
    }
    // Every decoded leaf must be on screen. A descriptor that simply omits an
    // argument is the quiet failure this rule exists to prevent.
    if covered.len() != paths.len() {
        let missing = paths
            .keys()
            .find(|path| !covered.contains(*path))
            .map_or("?", String::as_str);
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
        constraints,
    })
}

/// The values a `mustMatch` rule admits, in `match_key` form.
fn match_values(values: &Value, kind: &LeafType, path: &str) -> Result<Vec<String>, ReviewError> {
    let values = values
        .as_array()
        .filter(|values| !values.is_empty() && values.len() <= MAX_MATCH_VALUES)
        .ok_or_else(|| {
            rejected(format!(
                "mustMatch on `{path}` must list 1-{MAX_MATCH_VALUES} values"
            ))
        })?;
    let bad = || {
        rejected(format!(
            "a mustMatch value on `{path}` does not fit its type"
        ))
    };
    values
        .iter()
        .map(|value| match kind {
            LeafType::Address => value
                .as_str()
                .map(str::to_ascii_lowercase)
                .filter(|address| crate::is_canonical_address(address))
                .ok_or_else(bad),
            LeafType::Uint(_) => match value {
                Value::Number(number) => number.as_u64().map(|number| number.to_string()),
                Value::String(text) => alloy_primitives::U256::from_str_radix(text, 10)
                    .ok()
                    .map(|number| number.to_string()),
                _ => None,
            }
            .ok_or_else(bad),
            LeafType::Bool => value.as_bool().map(|flag| flag.to_string()).ok_or_else(bad),
            LeafType::FixedBytes(_) | LeafType::Bytes => value
                .as_str()
                .map(str::to_ascii_lowercase)
                .filter(|hex| {
                    let digits = hex.strip_prefix("0x").unwrap_or("-");
                    digits.len() % 2 == 0
                        && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                        && match kind {
                            LeafType::FixedBytes(size) => digits.len() == size * 2,
                            _ => true,
                        }
                })
                .ok_or_else(bad),
            LeafType::Array(_) | LeafType::Tuple(_) => Err(rejected(format!(
                "mustMatch on `{path}` would fix a whole array; it is not supported"
            ))),
        })
        .collect()
}

fn admit_format(
    name: &str,
    params: Option<&Value>,
    kind: &LeafType,
    path: &str,
    enums: &EnumMaps,
    paths: &BTreeMap<String, &LeafType>,
) -> Result<AdmittedFormat, ReviewError> {
    // A callee or amount must come from the same place as the field: a
    // top-level argument for a top-level field, the same element otherwise.
    let sibling = |other: &str, want: &LeafType| {
        paths.get(other).is_some_and(|kind| *kind == want) && array_of(other) == array_of(path)
    };
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
                match paths
                    .get(named.as_str())
                    .filter(|_| array_of(&named).is_none())
                {
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
        "calldata" => {
            // `selector`, `spender` and `chainId` parameters each redirect how
            // the inner call is read; the inner call is read as it is signed.
            only_keys(
                &params_map,
                &["calleePath", "amountPath"],
                "calldata params",
            )?;
            if !matches!(kind, LeafType::Bytes) {
                return Err(mismatched("bytes"));
            }
            let callee = match params_map.get("calleePath").and_then(Value::as_str) {
                Some("@.to") => CalleeSource::TargetContract,
                Some(callee) => {
                    let callee = normalize_path(callee)?;
                    if !sibling(&callee, &LeafType::Address) {
                        return Err(rejected(format!(
                            "calleePath `{callee}` is not `@.to` or an address argument of this call"
                        )));
                    }
                    CalleeSource::Argument(callee)
                }
                None => return Err(rejected("calldata requires a calleePath")),
            };
            let amount = params_map
                .get("amountPath")
                .map(|amount| {
                    let amount = normalize_path(
                        amount
                            .as_str()
                            .ok_or_else(|| rejected("amountPath must be a string"))?,
                    )?;
                    match paths.get(amount.as_str()) {
                        Some(LeafType::Uint(_)) if array_of(&amount) == array_of(path) => {
                            Ok(amount)
                        }
                        _ => Err(rejected(format!(
                            "amountPath `{amount}` is not an unsigned integer argument of this call"
                        ))),
                    }
                })
                .transpose()?;
            Ok(AdmittedFormat::Calldata { callee, amount })
        }
        other => Err(rejected(format!(
            "field format `{other}` is outside the supported subset"
        ))),
    }
}

/// `#.` is the upstream spelling for "relative to this structure". Accepted:
/// `name`, `name.[]` and `name.[].component`, nothing else: no slices,
/// container roots, maps or expressions.
fn normalize_path(path: &str) -> Result<String, ReviewError> {
    let path = path.strip_prefix("#.").unwrap_or(path);
    let ident = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && !part.as_bytes()[0].is_ascii_digit()
    };
    let valid = match path.split_once(".[]") {
        None => ident(path),
        Some((array, "")) => ident(array),
        Some((array, rest)) => ident(array) && rest.strip_prefix('.').is_some_and(ident),
    };
    if !valid {
        return Err(rejected(format!(
            "field path `{path}` is not a named argument path"
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
        let kind = if param.ty == "tuple[]" {
            // A list of calls or orders: each element's named components.
            let components = param
                .components
                .iter()
                .map(|component| {
                    if component.name.is_empty() || !component.components.is_empty() {
                        return Err(rejected(format!(
                            "a component of `{}` is unnamed or nested",
                            param.name
                        )));
                    }
                    match leaf_type(&component.ty)? {
                        LeafType::Array(_) => Err(rejected(format!(
                            "`{}.[].{}` is an array inside an array",
                            param.name, component.name
                        ))),
                        kind => Ok((component.name.clone(), kind)),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            LeafType::Array(Box::new(LeafType::Tuple(components)))
        } else if !param.components.is_empty() || param.ty.starts_with("tuple") {
            return Err(rejected(format!(
                "argument `{}` is a tuple; only a dynamic array of tuples is supported",
                param.name
            )));
        } else {
            leaf_type(&param.ty)?
        };
        out.push((param.name.clone(), kind));
        if out.len() > MAX_LEAVES_PER_FORMAT {
            return Err(ReviewError::new(
                ReviewReason::LimitExceeded,
                format!("more than {MAX_LEAVES_PER_FORMAT} decoded arguments"),
            ));
        }
    }
    Ok(())
}

/// Every path a field can address, with the type it addresses: `name` for a
/// scalar or `bytes`, `name.[]` for each element of a scalar array, and
/// `name.[].component` for a component of each element of a tuple array.
pub(crate) fn addressable(leaves: &[(String, LeafType)]) -> BTreeMap<String, &LeafType> {
    let mut paths = BTreeMap::new();
    for (name, kind) in leaves {
        match kind {
            LeafType::Array(element) => match element.as_ref() {
                LeafType::Tuple(components) => {
                    for (component, kind) in components {
                        paths.insert(format!("{name}.[].{component}"), kind);
                    }
                }
                scalar => {
                    paths.insert(format!("{name}.[]"), scalar);
                }
            },
            other => {
                paths.insert(name.clone(), other);
            }
        }
    }
    paths
}

/// The array a path reaches into, if any: `calls` for `calls.[].to`.
pub(crate) fn array_of(path: &str) -> Option<&str> {
    path.split_once(".[]").map(|(array, _)| array)
}

/// A static scalar, dynamic `bytes`, or a dynamic array of one static scalar.
fn leaf_type(ty: &str) -> Result<LeafType, ReviewError> {
    if ty == "bytes" {
        return Ok(LeafType::Bytes);
    }
    if let Some(element) = ty.strip_suffix("[]") {
        return Ok(LeafType::Array(Box::new(static_leaf_type(element)?)));
    }
    static_leaf_type(ty)
}

/// Canonical static scalars only. Signed integers, `string`, fixed-size and
/// nested arrays are refused, so a decoded value always has one fixed width
/// and one unambiguous spelling. The parser has already turned a `uint` alias
/// into `uint256`, which is the same type and the same selector.
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
