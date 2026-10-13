//! Publisher tooling: flatten, admit, and sign a clear-signing catalog.
//!
//! Everything that needs a file, a network or a private key happens here, so
//! Broker can stay offline. The tool runs the *same* admission Broker runs,
//! which is the point: a catalog that builds here is one Broker can read, and
//! a descriptor instruction outside the supported subset fails at publication
//! rather than in front of an owner.
//!
//! Schema conformance of the *source* documents is a separate, required
//! step, run by `publish/validate-descriptors.sh` with upstream JSON Schema
//! tooling against the pinned ERC-7730 v2 schema. `build` will not publish
//! without its report: the report has to name the pinned schema commit and
//! digest, and to cover every descriptor file this build reads — including
//! every file reached through `includes` — by SHA-256. That makes the check
//! reproducible (re-run the script, get the same report) and impossible to
//! skip, without putting a JSON Schema implementation inside Bloom.
//!
//! Subset admission still runs here too, and is strictly stronger than the
//! schema for everything Bloom will display.
//!
//! ```text
//! publish/validate-descriptors.sh <schema.json> <descriptor.json>... > report.json
//! bloom-clear-signing-catalog build <source.json> --key <seed.hex> --key-id <id> \
//!     --schema-report <report.json> --out <catalog.json>
//! bloom-clear-signing-catalog verify <catalog.json> --key-id <id> --public-key <hex> [--threshold N]
//! bloom-clear-signing-catalog schema-pin
//! ```

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::ExitCode,
};

use bloom_broker_api::{Base64UrlBytes, DecimalU64, Digest32, Token};
use bloom_evm_clear_signing::*;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::Digest as _;

/// One entry as a publisher writes it: descriptors by path, everything else
/// the observation the publisher is asserting.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEntry {
    chain_id: u64,
    contract_address: String,
    #[serde(default)]
    descriptor: Option<PathBuf>,
    #[serde(default)]
    admitted_functions: Vec<AdmittedFunction>,
    #[serde(default)]
    runtime_code_hash: Option<String>,
    #[serde(default)]
    token_metadata: Option<TokenMetadata>,
    #[serde(default)]
    upgradeable: bool,
    #[serde(default)]
    implementation_hash: Option<String>,
    observed_at_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    catalog_id: String,
    sequence: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    entries: Vec<SourceEntry>,
}

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let options = parse_options(&arguments[1.min(arguments.len())..]);
    match arguments.first().map(String::as_str) {
        Some("build") => build(
            Path::new(arguments.get(1).ok_or("build needs a source file")?),
            &options,
        ),
        Some("verify") => verify(
            Path::new(arguments.get(1).ok_or("verify needs a catalog file")?),
            &options,
        ),
        Some("schema-pin") => Ok(format!(
            "ERC-7730 v2 schema pinned at ethereum/ERCs@{PINNED_SCHEMA_COMMIT}\n\
             assets/erc-7730/erc7730-v2.schema.json sha256 {PINNED_SCHEMA_SHA256}"
        )),
        _ => Err(
            "usage: build <source.json> | verify <catalog.json> | schema-pin (see module docs)"
                .into(),
        ),
    }
}

fn parse_options(arguments: &[String]) -> BTreeMap<String, String> {
    let mut options = BTreeMap::new();
    let mut index = 0;
    while index + 1 < arguments.len() {
        if let Some(name) = arguments[index].strip_prefix("--") {
            options.insert(name.to_owned(), arguments[index + 1].clone());
            index += 2;
        } else {
            index += 1;
        }
    }
    options
}

fn digest(value: &Option<String>, what: &str) -> Result<Option<Digest32>, String> {
    value
        .as_ref()
        .map(|value| Digest32::new(value.clone()).map_err(|error| format!("{what}: {error}")))
        .transpose()
}

/// The record `publish/validate-descriptors.sh` writes: which schema it
/// validated against, and every descriptor file it validated, by digest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaReport {
    schema_commit: String,
    schema_sha256: String,
    validator: String,
    /// SHA-256 of each descriptor file the validator accepted. Paths are the
    /// publisher's own; only the digests are matched, so the report stays
    /// valid if the tree moves.
    validated: BTreeMap<String, String>,
}

impl SchemaReport {
    fn read(path: &Path) -> Result<Self, String> {
        let report: Self = serde_json::from_slice(
            &std::fs::read(path).map_err(|error| format!("read schema report: {error}"))?,
        )
        .map_err(|error| format!("parse schema report: {error}"))?;
        if report.schema_commit != PINNED_SCHEMA_COMMIT
            || report.schema_sha256 != PINNED_SCHEMA_SHA256
        {
            return Err(format!(
                "the schema report was produced against ethereum/ERCs@{} sha256 {}, not the pinned \
                 ethereum/ERCs@{PINNED_SCHEMA_COMMIT} sha256 {PINNED_SCHEMA_SHA256}",
                report.schema_commit, report.schema_sha256
            ));
        }
        Ok(report)
    }

    /// Every file that contributed bytes to a published descriptor must have
    /// been validated. Reporting only the top document would leave whatever
    /// an `includes` chain merged in unchecked.
    fn require(&self, sources: &[(PathBuf, String)]) -> Result<(), String> {
        for (path, digest) in sources {
            if !self.validated.values().any(|validated| validated == digest) {
                return Err(format!(
                    "{} (sha256 {digest}) is not in the schema report; run \
                     publish/validate-descriptors.sh over every descriptor this build reads",
                    path.display()
                ));
            }
        }
        Ok(())
    }
}

fn build(source_path: &Path, options: &BTreeMap<String, String>) -> Result<String, String> {
    let source: Source = serde_json::from_slice(
        &std::fs::read(source_path).map_err(|error| format!("read source: {error}"))?,
    )
    .map_err(|error| format!("parse source: {error}"))?;
    let base = source_path.parent().unwrap_or(Path::new("."));
    let report =
        SchemaReport::read(Path::new(options.get("schema-report").ok_or(
            "build needs --schema-report; see publish/validate-descriptors.sh",
        )?))?;

    let mut entries = Vec::with_capacity(source.entries.len());
    let mut validated_files = 0;
    for entry in source.entries {
        let descriptor = match &entry.descriptor {
            None => None,
            Some(path) => {
                let flattened = flatten(&base.join(path))?;
                report.require(&flattened.sources)?;
                validated_files += flattened.sources.len();
                Some(flattened.document)
            }
        };
        entries.push(CatalogEntry {
            chain_id: DecimalU64::new(entry.chain_id),
            contract_address: entry.contract_address.to_lowercase(),
            admitted_functions: entry.admitted_functions,
            descriptor_digest: descriptor
                .as_ref()
                .map(|value| descriptor_digest(value).map_err(|error| error.to_string()))
                .transpose()?,
            flattened_descriptor: descriptor,
            runtime_code_hash: digest(&entry.runtime_code_hash, "runtime_code_hash")?,
            token_metadata: entry.token_metadata,
            upgradeable: entry.upgradeable,
            implementation_hash: digest(&entry.implementation_hash, "implementation_hash")?,
            observed_at_ms: DecimalU64::new(entry.observed_at_ms),
        });
    }
    // The signed snapshot has one deterministic order, so the publisher never
    // has to get the sort right by hand.
    entries.sort_by(|left, right| {
        (left.chain_id.get(), &left.contract_address)
            .cmp(&(right.chain_id.get(), &right.contract_address))
    });

    let mut catalog = ClearSigningCatalog {
        schema: CATALOG_SCHEMA.to_owned(),
        catalog_id: Token::new(source.catalog_id).map_err(|error| error.to_string())?,
        sequence: DecimalU64::new(source.sequence),
        issued_at_ms: DecimalU64::new(source.issued_at_ms),
        expires_at_ms: DecimalU64::new(source.expires_at_ms),
        entries,
        signatures: Vec::new(),
    };

    let key_id = Token::new(options.get("key-id").ok_or("build needs --key-id")?.clone())
        .map_err(|error| error.to_string())?;
    let seed = read_seed(Path::new(options.get("key").ok_or("build needs --key")?))?;
    let signing_key = SigningKey::from_bytes(&seed);

    let mut message = CATALOG_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(
        &catalog
            .unsigned_canonical_bytes()
            .map_err(|error| error.to_string())?,
    );
    catalog.signatures = vec![CatalogSignature {
        key_id: key_id.clone(),
        signature: Base64UrlBytes::from_bytes(&signing_key.sign(&message).to_bytes()),
    }];

    let encoded = serde_jcs::to_vec(&catalog).map_err(|error| error.to_string())?;
    // Refuse to publish what Broker would refuse to read.
    let accepted = catalog
        .accept(
            encoded.len(),
            &[TrustedCatalogKey {
                key_id,
                verifying_key: signing_key.verifying_key(),
            }],
            1,
        )
        .map_err(|error| format!("this catalog would be refused by Broker: {error}"))?;

    let out = options.get("out").ok_or("build needs --out")?;
    std::fs::write(out, &encoded).map_err(|error| format!("write catalog: {error}"))?;
    Ok(format!(
        "wrote {out}: {} entries, sequence {}, content digest {}\n\
         {validated_files} descriptor files validated against ethereum/ERCs@{PINNED_SCHEMA_COMMIT} \
         by {}\n\
         publisher verifying key {}",
        catalog.entries.len(),
        catalog.sequence.as_str(),
        accepted.content_digest.as_str(),
        report.validator,
        hex::encode(signing_key.verifying_key().to_bytes()),
    ))
}

fn verify(path: &Path, options: &BTreeMap<String, String>) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read catalog: {error}"))?;
    let catalog: ClearSigningCatalog =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse catalog: {error}"))?;
    let key_id = Token::new(
        options
            .get("key-id")
            .ok_or("verify needs --key-id")?
            .clone(),
    )
    .map_err(|error| error.to_string())?;
    let raw = hex::decode(
        options
            .get("public-key")
            .ok_or("verify needs --public-key")?,
    )
    .map_err(|error| format!("parse public key: {error}"))?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_owned())?;
    let threshold = options
        .get("threshold")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| format!("parse threshold: {error}"))?
        .unwrap_or(1);
    let accepted = catalog
        .accept(
            bytes.len(),
            &[TrustedCatalogKey {
                key_id,
                verifying_key: VerifyingKey::from_bytes(&raw)
                    .map_err(|_| "public key is not a valid Ed25519 key".to_owned())?,
            }],
            threshold,
        )
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "accepted: catalog {} sequence {} digest {} with {} entries",
        accepted.catalog.catalog_id,
        accepted.catalog.sequence.as_str(),
        accepted.content_digest.as_str(),
        accepted.catalog.entries.len()
    ))
}

/// The longest `includes` chain a descriptor may use, and the most source
/// bytes one descriptor may draw in across that chain.
const MAX_INCLUDE_DEPTH: usize = 4;
const MAX_INCLUDE_TOTAL_BYTES: usize = 256 * 1024;

/// What one descriptor's resolution consumed, so the caller can bind every
/// file that contributed to the published bytes.
struct Flattened {
    document: Value,
    /// Each file read, in resolution order, with the SHA-256 of its bytes.
    sources: Vec<(PathBuf, String)>,
}

/// Resolve `includes` by merging the referenced local document underneath
/// this one. Broker never sees an unresolved include, and never fetches.
///
/// Bounded before it reads: a chain longer than [`MAX_INCLUDE_DEPTH`], a
/// cycle, or more than [`MAX_INCLUDE_TOTAL_BYTES`] of source is refused
/// rather than followed. A cycle is detected by canonical path, so two names
/// for the same file do not read as two files.
fn flatten(path: &Path) -> Result<Flattened, String> {
    let mut visited = Vec::new();
    let mut sources = Vec::new();
    let mut total = 0;
    let document = flatten_into(path, &mut visited, &mut sources, &mut total)?;
    Ok(Flattened { document, sources })
}

fn flatten_into(
    path: &Path,
    visited: &mut Vec<PathBuf>,
    sources: &mut Vec<(PathBuf, String)>,
    total: &mut usize,
) -> Result<Value, String> {
    if visited.len() >= MAX_INCLUDE_DEPTH {
        return Err(format!(
            "{} exceeds the {MAX_INCLUDE_DEPTH}-document include limit",
            path.display()
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("resolve {}: {error}", path.display()))?;
    if visited.contains(&canonical) {
        return Err(format!(
            "{} is included by a document it already includes; the chain is a cycle",
            canonical.display()
        ));
    }
    let bytes = std::fs::read(&canonical)
        .map_err(|error| format!("read {}: {error}", canonical.display()))?;
    *total = total.saturating_add(bytes.len());
    if *total > MAX_INCLUDE_TOTAL_BYTES {
        return Err(format!(
            "the include chain reaching {} reads more than {MAX_INCLUDE_TOTAL_BYTES} bytes",
            canonical.display()
        ));
    }
    visited.push(canonical.clone());
    sources.push((canonical.clone(), hex::encode(sha2::Sha256::digest(&bytes))));

    let mut document =
        strict_json(&bytes).map_err(|error| format!("parse {}: {error}", canonical.display()))?;
    let Some(include) = document
        .get("includes")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        visited.pop();
        return Ok(document);
    };
    if include.contains("://") {
        return Err(format!(
            "{} includes a remote document; fetch and vendor it before publishing",
            canonical.display()
        ));
    }
    let base = flatten_into(
        &canonical.parent().unwrap_or(Path::new(".")).join(&include),
        visited,
        sources,
        total,
    )?;
    document
        .as_object_mut()
        .ok_or("descriptor must be an object")?
        .remove("includes");
    let mut merged = base;
    merge(&mut merged, &document);
    visited.pop();
    Ok(merged)
}

/// Parse JSON with no silent loss.
///
/// Two ordinary JSON behaviours would each change a published descriptor
/// without saying so, and both are refused here rather than at the digest:
/// a repeated object key (last one quietly wins) and a number that is not an
/// exact integer (`serde_json` widens it to `f64`). Descriptors in the
/// admitted subset use integers only, so refusing the rest costs nothing.
fn strict_json(bytes: &[u8]) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| error.to_string())?
        .0;
    deserializer
        .end()
        .map_err(|error| format!("trailing content: {error}"))?;
    Ok(value)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON with unique keys and exact integers")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::from(value)))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Err(E::custom(format!(
            "`{value}` is not an exact integer; a descriptor number that does not fit a 64-bit integer would be published with a different value than it was written with"
        )))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut access: A,
    ) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = access.next_element()? {
            items.push(item);
        }
        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut access: A,
    ) -> Result<Self::Value, A::Error> {
        let mut map = serde_json::Map::new();
        while let Some(key) = access.next_key::<String>()? {
            let StrictValue(value) = access.next_value()?;
            if map.insert(key.clone(), value).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "key `{key}` appears twice in the same object; which one applies is not decidable from the document"
                )));
            }
        }
        Ok(StrictValue(Value::Object(map)))
    }
}

/// Objects merge key by key with the including document winning; anything
/// else is replaced outright.
fn merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                merge(base.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

fn read_seed(path: &Path) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("read key: {error}"))?;
    let bytes = hex::decode(text.trim()).map_err(|error| format!("parse key: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "signing key must be a 32-byte hex seed".to_owned())
}
