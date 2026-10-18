//! The catalog: which contracts Broker can describe, and how.
//!
//! It is compiled into Broker from `catalogs/`, so it is trusted exactly as
//! far as the Broker release is, and it is covered by the verifier digest. A
//! new contract is a descriptor file and one line in [`DESCRIPTORS`]; a new
//! token is a row in `bloom-broker-api/tokens/tokens.json`, the list Machine
//! also compiles in. Broker never fetches anything.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

pub use bloom_broker_api::KnownToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AdmittedCall, AdmittedDescriptor, AdmittedField, AdmittedFormat, LeafType, ReviewError,
    ReviewReason, admit, admit_document, deployments, erc20_profile, parse_function,
};

pub const TOKEN_SYMBOL_MAX_BYTES: usize = 16;
pub const TOKEN_NAME_MAX_SCALARS: usize = 64;
pub const TOKEN_NAME_MAX_BYTES: usize = 256;

/// How a compiled-in description applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Binding {
    /// To the deployments it lists.
    Listed,
    /// Listed deployments whose implementation can change.
    ListedUpgradeable,
    /// Also, by selector, to addresses no entry lists, on the chains where it
    /// lists this deployment: per-user proxies such as Safes, which all run
    /// one singleton.
    Instances(&'static str),
    /// By selector, to addresses no entry lists, on every chain: a contract
    /// standard such as ERC-4626, whose deployments cannot all be listed.
    Standard,
}

/// The compiled-in descriptor files: path, contents and binding.
pub const DESCRIPTORS: [(&str, &str, Binding); 11] = [
    (
        "safe/safe.json",
        include_str!("../catalogs/safe/safe.json"),
        Binding::Instances("0x41675c099f32341bf84bfc5382af534df5c7461a"),
    ),
    (
        "safe/safe-proxy-factory.json",
        include_str!("../catalogs/safe/safe-proxy-factory.json"),
        Binding::Listed,
    ),
    (
        "safe/create-call.json",
        include_str!("../catalogs/safe/create-call.json"),
        Binding::Listed,
    ),
    (
        "morpho/bundler3.json",
        include_str!("../catalogs/morpho/bundler3.json"),
        Binding::Listed,
    ),
    (
        "morpho/general-adapter1.json",
        include_str!("../catalogs/morpho/general-adapter1.json"),
        Binding::Listed,
    ),
    (
        "standards/erc4626.json",
        include_str!("../catalogs/standards/erc4626.json"),
        Binding::Standard,
    ),
    (
        "privacy-pools/entrypoint.json",
        include_str!("../catalogs/privacy-pools/entrypoint.json"),
        Binding::ListedUpgradeable,
    ),
    (
        "privacy-pools/eth-pool.json",
        include_str!("../catalogs/privacy-pools/eth-pool.json"),
        Binding::Listed,
    ),
    (
        "enso/router-v2.json",
        include_str!("../catalogs/enso/router-v2.json"),
        Binding::Listed,
    ),
    (
        "standards/erc721-erc1155-operator.json",
        include_str!("../catalogs/standards/erc721-erc1155-operator.json"),
        Binding::Standard,
    ),
    (
        "standards/conditional-tokens.json",
        include_str!("../catalogs/standards/conditional-tokens.json"),
        Binding::Standard,
    ),
];

/// Safe's MultiSendCallOnly (1.3.0 twice, 1.4.1, 1.5.0): the only contract a
/// Safe may delegatecall, and only to run a batch of plain calls. Its packed
/// format is not ERC-7730, so it is described in code. The runtime code at
/// each address was checked on each chain listed.
pub const SAFE_BATCH: [&str; 4] = [
    "0x40a2accbd92bca938b02010e17a5b8929b49130d",
    "0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b",
    "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
    "0xa83c336b20401af773b6219ba5027174338d1836",
];
pub const SAFE_BATCH_CHAINS: [u64; 6] = [1, 10, 100, 137, 8453, 42161];
/// Safe's CreateCall, described in `catalogs/safe/create-call.json`.
const SAFE_CREATE_CALL: [&str; 4] = [
    "0x7cbb62eaa69f79e6873cd1ecb2392971036cfaa4",
    "0xb19d6ffc2182150f8eb585b79d4abcd7c5640a9d",
    "0x9b35af71d77eaf8d7e40252370304687390a1a52",
    "0x2ef5ecfbea521449e4de05edb1ce63b75eda90b4",
];

/// What a reviewed function is permitted to mean. It is derived from the
/// signature: only the canonical ERC-20 `transfer` and `approve` get the
/// transfer and allowance rules, and nothing can rename its way out of them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    Transfer,
    Allowance,
    Other,
}

impl ActionClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Allowance => "allowance",
            Self::Other => "other",
        }
    }

    pub fn of(signature: &str) -> Result<Self, ReviewError> {
        Ok(match parse_function(signature)?.signature().as_str() {
            crate::TRANSFER_SIGNATURE => Self::Transfer,
            crate::APPROVE_SIGNATURE => Self::Allowance,
            _ => Self::Other,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedFunction {
    /// A descriptor format key: a full function signature with parameter
    /// names. The selector is derived from it, never supplied.
    pub signature: String,
    pub action_class: ActionClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMetadata {
    pub decimals: u8,
    pub symbol: String,
    pub name: String,
}

/// One describable deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub chain_id: u64,
    /// Lowercase `0x`-prefixed 20-byte address.
    pub contract_address: String,
    pub token_metadata: Option<TokenMetadata>,
    pub upgradeable: bool,
    /// Calls to an address with no entry of its own are also read by this
    /// entry's functions, and Broker says it did not verify the address runs
    /// this contract.
    pub applies_to_instances: bool,
    descriptor: usize,
}

/// The admitted catalog.
#[derive(Debug)]
pub struct Catalog {
    descriptors: Vec<AdmittedDescriptor>,
    entries: BTreeMap<(u64, String), CatalogEntry>,
    /// One entry per standard description, at the zero address on chain 0:
    /// it describes no deployment.
    standards: Vec<CatalogEntry>,
    vault_assets: BTreeMap<(u64, String), String>,
}

static BUILT_IN: LazyLock<Result<Catalog, ReviewError>> = LazyLock::new(|| {
    let descriptors = DESCRIPTORS
        .iter()
        .map(|(path, text, binding)| {
            let value = serde_json::from_str(text).map_err(|error| {
                ReviewError::new(ReviewReason::CatalogRejected, format!("{path}: {error}"))
            })?;
            Ok((value, *binding))
        })
        .collect::<Result<Vec<_>, ReviewError>>()?;
    let mut catalog = Catalog::build(&descriptors, bloom_broker_api::known_tokens().to_vec())?;
    catalog.admit_vault_assets(include_str!("../catalogs/vault-assets.json"))?;
    Ok(catalog)
});

impl Catalog {
    fn admit_vault_assets(&mut self, document: &str) -> Result<(), ReviewError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Bindings {
            schema: String,
            bindings: Vec<BindingRow>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BindingRow {
            chain_id: u64,
            vault: String,
            asset: String,
            #[serde(rename = "observation")]
            _observation: Value,
        }
        let document: Bindings = serde_json::from_str(document)
            .map_err(|error| rejected(format!("vault asset bindings: {error}")))?;
        if document.schema != "bloom.vault-asset-bindings.v1" || document.bindings.len() > 256 {
            return Err(rejected("unsupported or oversized vault asset bindings"));
        }
        for binding in document.bindings {
            if binding.chain_id == 0
                || !crate::is_canonical_address(&binding.vault)
                || !crate::is_canonical_address(&binding.asset)
                || binding.vault == format!("0x{}", "0".repeat(40))
                || !self
                    .entry(binding.chain_id, &binding.asset)
                    .is_some_and(|entry| entry.token_metadata.is_some())
            {
                return Err(rejected(
                    "vault binding requires a canonical vault and catalogued underlying token",
                ));
            }
            if self
                .vault_assets
                .insert((binding.chain_id, binding.vault), binding.asset)
                .is_some()
            {
                return Err(rejected("duplicate vault asset binding"));
            }
        }
        Ok(())
    }

    pub fn vault_asset(&self, chain_id: u64, vault: &str) -> Option<&CatalogEntry> {
        self.vault_assets
            .get(&(chain_id, vault.to_owned()))
            .and_then(|asset| self.entry(chain_id, asset))
    }
    /// The catalog compiled into this build. A test proves it admits, so the
    /// error is reachable only through a broken build.
    pub fn built_in() -> Result<&'static Catalog, ReviewError> {
        BUILT_IN.as_ref().map_err(Clone::clone)
    }

    /// Admit descriptors and token rows. Every function a descriptor formats
    /// is admitted. A token without a descriptor of its own is read by the
    /// built-in ERC-20 profile.
    pub fn build(
        descriptors: &[(Value, Binding)],
        tokens: Vec<KnownToken>,
    ) -> Result<Self, ReviewError> {
        let (profile, functions) = erc20_profile();
        let mut catalog = Catalog {
            descriptors: vec![
                admit_document(&profile, None, &functions)?,
                safe_batch_description(),
            ],
            entries: BTreeMap::new(),
            standards: Vec::new(),
            vault_assets: BTreeMap::new(),
        };
        for chain_id in SAFE_BATCH_CHAINS {
            for address in SAFE_BATCH {
                catalog.insert(CatalogEntry {
                    chain_id,
                    contract_address: address.to_owned(),
                    token_metadata: None,
                    upgradeable: false,
                    applies_to_instances: false,
                    descriptor: SAFE_BATCH_DESCRIPTOR,
                })?;
            }
        }
        let mut instance_selectors = BTreeSet::new();
        for (descriptor, binding) in descriptors {
            let functions = descriptor
                .pointer("/display/formats")
                .and_then(Value::as_object)
                .ok_or_else(|| rejected("display has no formats"))?
                .keys()
                .map(|signature| {
                    Ok(AdmittedFunction {
                        signature: signature.clone(),
                        action_class: ActionClass::of(signature)?,
                    })
                })
                .collect::<Result<Vec<_>, ReviewError>>()?;
            let index = catalog.descriptors.len();
            if *binding == Binding::Standard {
                let admitted = admit_document(descriptor, None, &functions)?;
                check_unlisted_reading(&admitted)?;
                for call in &admitted.calls {
                    if !instance_selectors.insert((0, call.selector)) {
                        return Err(rejected(format!(
                            "two standard descriptions admit the selector of `{}`",
                            call.signature
                        )));
                    }
                }
                catalog.standards.push(CatalogEntry {
                    chain_id: 0,
                    contract_address: format!("0x{}", "0".repeat(40)),
                    token_metadata: None,
                    upgradeable: false,
                    applies_to_instances: true,
                    descriptor: index,
                });
                catalog.descriptors.push(admitted);
                continue;
            }
            let bound = deployments(descriptor)?;
            let (chain_id, address) = bound
                .first()
                .ok_or_else(|| rejected("a descriptor lists no deployments"))?;
            let admitted = admit(descriptor, *chain_id, address, &functions)?;
            let instance = match binding {
                Binding::Instances(address) => {
                    check_unlisted_reading(&admitted)?;
                    Some(*address)
                }
                _ => None,
            };
            for (chain_id, address) in bound {
                let applies_to_instances = instance == Some(address.as_str());
                if applies_to_instances {
                    for call in &admitted.calls {
                        if !instance_selectors.insert((chain_id, call.selector)) {
                            return Err(rejected(format!(
                                "two instance descriptions on chain {chain_id} admit the selector of `{}`, so an unlisted address would be ambiguous",
                                call.signature
                            )));
                        }
                    }
                }
                catalog.insert(CatalogEntry {
                    chain_id,
                    contract_address: address,
                    token_metadata: None,
                    upgradeable: *binding == Binding::ListedUpgradeable,
                    applies_to_instances,
                    descriptor: index,
                })?;
            }
            catalog.descriptors.push(admitted);
        }
        for token in tokens {
            let metadata = TokenMetadata {
                decimals: token.decimals,
                symbol: token.symbol,
                name: token.name,
            };
            metadata.validate_shape()?;
            // A described deployment that is also a token (one with `permit`,
            // say) is read by its own descriptor, with these units.
            if let Some(described) = catalog
                .entries
                .get_mut(&(token.chain_id, token.address.clone()))
            {
                if described.applies_to_instances || described.token_metadata.is_some() {
                    return Err(rejected(format!(
                        "token {} on chain {} is listed twice or is an instance description",
                        token.address, token.chain_id
                    )));
                }
                described.token_metadata = Some(metadata);
                described.upgradeable |= token.upgradeable;
                continue;
            }
            catalog.insert(CatalogEntry {
                chain_id: token.chain_id,
                contract_address: token.address,
                token_metadata: Some(metadata),
                upgradeable: token.upgradeable,
                applies_to_instances: false,
                descriptor: 0,
            })?;
        }
        Ok(catalog)
    }

    fn insert(&mut self, entry: CatalogEntry) -> Result<(), ReviewError> {
        if !is_canonical_address(&entry.contract_address) || entry.chain_id == 0 {
            return Err(rejected(format!(
                "`{}` on chain {} is not a lowercase 0x-prefixed address on a nonzero chain",
                entry.contract_address, entry.chain_id
            )));
        }
        let key = (entry.chain_id, entry.contract_address.clone());
        if self.entries.insert(key, entry).is_some() {
            return Err(rejected("the catalog lists one deployment twice"));
        }
        Ok(())
    }

    /// Whether a Safe may delegatecall this address: one of Safe's own
    /// libraries, MultiSendCallOnly or CreateCall, which act only as the
    /// Safe's batch or deployment.
    pub fn is_safe_library(&self, chain_id: u64, address: &str) -> bool {
        self.entry(chain_id, address).is_some_and(|entry| {
            entry.descriptor == SAFE_BATCH_DESCRIPTOR || SAFE_CREATE_CALL.contains(&address)
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entry(&self, chain_id: u64, address: &str) -> Option<&CatalogEntry> {
        self.entries.get(&(chain_id, address.to_owned()))
    }

    pub fn descriptor(&self, chain_id: u64, address: &str) -> Option<&AdmittedDescriptor> {
        self.entry(chain_id, address)
            .map(|entry| &self.descriptors[entry.descriptor])
    }

    /// The entry that describes a call to `address` with `selector`, and
    /// whether it was matched as an unverified instance.
    ///
    /// An address with its own entry is read by that entry alone: a listed
    /// token is never read as a Safe because it lacks the selector. Only an
    /// unlisted address falls through to the instance entries.
    pub fn resolve(
        &self,
        chain_id: u64,
        address: &str,
        selector: &[u8],
    ) -> Option<(&CatalogEntry, &AdmittedDescriptor, bool)> {
        if let Some(entry) = self.entry(chain_id, address) {
            return Some((entry, &self.descriptors[entry.descriptor], false));
        }
        self.entries
            .range((chain_id, String::new())..(chain_id + 1, String::new()))
            .map(|(_, entry)| entry)
            .filter(|entry| entry.applies_to_instances)
            .chain(&self.standards)
            .find_map(|entry| {
                let descriptor = &self.descriptors[entry.descriptor];
                descriptor.call(selector).map(|_| (entry, descriptor, true))
            })
    }
}

impl TokenMetadata {
    fn validate_shape(&self) -> Result<(), ReviewError> {
        let symbol_ok = !self.symbol.is_empty()
            && self.symbol.len() <= TOKEN_SYMBOL_MAX_BYTES
            && self
                .symbol
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'<' && byte != b'>');
        let name_scalars = self.name.chars().count();
        let name_ok = !self.name.is_empty()
            && name_scalars <= TOKEN_NAME_MAX_SCALARS
            && self.name.len() <= TOKEN_NAME_MAX_BYTES
            && !self.name.chars().any(is_control_or_bidi);
        if !symbol_ok || !name_ok {
            return Err(rejected(format!(
                "token `{}` has an empty, oversized or unsafe symbol or name",
                self.symbol
            )));
        }
        Ok(())
    }
}

const SAFE_BATCH_DESCRIPTOR: usize = 1;

/// A description read for addresses nobody listed may not admit ERC-20
/// calls: token units or the transfer class there would lend one token's
/// identity to every such address.
fn check_unlisted_reading(admitted: &AdmittedDescriptor) -> Result<(), ReviewError> {
    if admitted.calls.iter().any(|call| call.native_value) {
        return Err(rejected(
            "native value requires a listed deployment, not an instance or standard binding",
        ));
    }
    if admitted
        .calls
        .iter()
        .any(|call| call.action_class != ActionClass::Other)
    {
        return Err(rejected(
            "an instance or standard description may not admit ERC-20 calls",
        ));
    }
    Ok(())
}

fn safe_batch_description() -> AdmittedDescriptor {
    let signature = "multiSend(bytes transactions)";
    AdmittedDescriptor {
        contract_name: Some("Safe batch".to_owned()),
        calls: vec![AdmittedCall {
            signature: signature.to_owned(),
            selector: parse_function(signature)
                .expect("the batch signature parses")
                .selector()
                .0,
            action_class: ActionClass::Other,
            intent: None,
            fields: vec![AdmittedField {
                path: "transactions".to_owned(),
                label: "Transaction".to_owned(),
                format: AdmittedFormat::SafeBatch,
            }],
            native_value: false,
            leaves: vec![("transactions".to_owned(), LeafType::Bytes)],
            constraints: Vec::new(),
        }],
    }
}

fn rejected(message: impl Into<String>) -> ReviewError {
    ReviewError::new(ReviewReason::CatalogRejected, message)
}

pub fn is_canonical_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Characters a signed label or token name may not carry, because they change
/// what the approval screen reads without changing what it says.
///
/// `char::is_control` covers Cc only, so it misses the line and paragraph
/// separators (Zl, Zp) — which break a label across lines exactly as a control
/// character would — and the format characters (Cf), which include the
/// bidirectional overrides already listed here plus the zero-width and
/// invisible ones that let two different names render identically. These
/// strings are short, human-readable labels, so none of this range has an
/// honest use in one.
pub(crate) fn is_control_or_bidi(character: char) -> bool {
    character.is_control()
        || matches!(character,
            // Zl and Zp: line and paragraph separators.
            '\u{2028}' | '\u{2029}'
            // Cf: soft hyphen, Arabic letter mark, the zero-width and
            // bidirectional formatting range, the invisible operators, the
            // deprecated and interlinear annotation marks, and the BOM.
            | '\u{00ad}' | '\u{0600}'..='\u{0605}' | '\u{061c}' | '\u{06dd}'
            | '\u{070f}' | '\u{08e2}' | '\u{180e}'
            | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}'
            | '\u{feff}' | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}' | '\u{110cd}' | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}' | '\u{e0020}'..='\u{e007f}')
}
