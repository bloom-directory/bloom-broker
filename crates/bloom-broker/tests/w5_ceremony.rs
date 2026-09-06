use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use bloom_audit_checkpoint::{AppendOutcome, CheckpointError, CheckpointSink};
use bloom_broker::{
    authority::{AssuranceRegistry, BrokerAuthority, canonical_policy_authority_diff},
    ceremony::{
        CEREMONY_ADDR, CEREMONY_OWNER_HEADER, CEREMONY_OWNER_VALUE, CeremonyBroker,
        CeremonyCompletionObserver, CeremonyLimits, CeremonySigner, ReviewManifestContext,
    },
    clock::BrokerClock,
    journal::{AuditSigner, BrokerJournal},
    service::BrokerRpcService,
    signer_client::BrokerSignerClient,
};
use bloom_broker_api::{
    ActivationMode, ApprovalLimits, ApprovalPrepareRequest, ApprovalSelector, ApprovalSubject,
    AssetId, Base64UrlBytes, BootEpoch, CanonicalWalletPolicy, CeremonyState, ClaimAssurance,
    ClaimAssuranceLevel, CryptoSuite, CustodyPrepareResponse, DecimalU64, DecimalU256,
    DeclaredDebit, DeclaredDestination, DeclaredFee, Digest32, KeyRef, KeySpec,
    MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, MachineSignRequest,
    OperationId, OperationRequest, PROVENANCE_RECORD_SIGNATURE_DOMAIN, PetalKeyScope,
    PetalLineageMembership, PetalUseClaim, PolicyCommitUpdateRequest, PolicyDestination,
    PolicyUpdateRequest, ProtocolError, ProtocolErrorCode, ProvenanceOperationClass,
    ProvenanceRecord, ProvenanceSubject, RateLimitDetails, RequestNonce, RevokeRequest,
    SealedApprovalTerms, SignedJournalHead, SignedPolicySnapshot, SigningPayloads, Token,
    WalletRequest,
};
use bloom_broker_debug_driver::{VirtualAuthenticator, seal_hpke};
use bloom_signer::{
    ceremony::SignerCeremonyService,
    clock::SignerClock,
    engine::{SignerAuditKeys, SignerEngine},
    hpke::{CUSTODY_OUTPUT_INFO, HpkeRecipient},
    registry::BackendRegistry,
    service::SignerRpcService,
};
use bloom_signer_api::{
    BrokerSignerRequest, BrokerSignerResponse, BrokerSignerService, CeremonyChallenge,
    CeremonyCompleteRequest, CeremonyKind, CeremonyPhase, CeremonyPrepareRequest,
    CeremonyWebAuthnOptions, ControlRequest, ControlResponse, CustodyCompleteRequest,
    CustodyHpkeAad, CustodyOutputHpkeAad, CustodyPrepareRequest, CustodyResult,
    CustodySignerContribution, LegacyPasskeyMigrationPublic, LocalPrfHpkeAad,
    PolicyUpdateCeremonyCompleteRequest, PolicyUpdateCeremonyPrepareRequest,
    RevocationControlService, SignerActivationReceipt, SignerCeremonyContribution,
    SignerCeremonyStatus, SignerPreparedApproval, SignerPreparedCustody, WalletOperationRequest,
    WebAuthnCeremonyProof,
};
use bloom_triad_local_transport::{EndpointQuota, JournalExchange, LocalIdentity, PeerAcl};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use http_body_util::BodyExt as _;
use sha2::Digest as _;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tower::ServiceExt as _;

fn test_time_source() -> &'static str {
    #[cfg(target_os = "linux")]
    return "linux-system-clock";
    #[cfg(target_os = "macos")]
    return "macos-managed-timed";
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    panic!("W5 ceremony tests require a reviewed trusted-time platform");
}

#[derive(Clone)]
struct ServiceTestAuditSigner;

impl AuditSigner for ServiceTestAuditSigner {
    fn key_id(&self) -> Token {
        Token::new("broker-audit-key").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        Ok(Base64UrlBytes::from_bytes(&sha2::Sha256::digest(message)))
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id == &self.key_id()
            && signature.decode() == sha2::Sha256::digest(message).as_slice()
        {
            Ok(())
        } else {
            Err("audit signature mismatch".into())
        }
    }
}

struct AcceptingCheckpointSink;

impl CheckpointSink for AcceptingCheckpointSink {
    fn append_peer_head(
        &self,
        _peer_head: &SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        Ok(AppendOutcome::Appended)
    }
}

struct SwitchableAuditSigner(Arc<AtomicBool>);

struct TestSignerJournalExchange(Arc<SignerEngine>);

impl JournalExchange<bloom_signer_api::ProtocolError> for TestSignerJournalExchange {
    fn checkpoint_request_head(
        &self,
        _method: &Token,
        _peer_head: &SignedJournalHead,
    ) -> Result<(), bloom_signer_api::ProtocolError> {
        Ok(())
    }

    fn local_journal_head(
        &self,
        _method: &Token,
    ) -> Result<(u64, Digest32), bloom_signer_api::ProtocolError> {
        self.0.verified_audit_head()
    }
}

impl AuditSigner for SwitchableAuditSigner {
    fn key_id(&self) -> Token {
        Token::new("broker-audit-key").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<Base64UrlBytes, String> {
        if self.0.load(Ordering::SeqCst) {
            Err("forced ceremony audit failure".into())
        } else {
            Ok(Base64UrlBytes::from_bytes(&sha2::Sha256::digest(message)))
        }
    }

    fn verify(
        &self,
        key_id: &Token,
        message: &[u8],
        signature: &Base64UrlBytes,
    ) -> Result<(), String> {
        if key_id == &self.key_id()
            && signature.decode() == sha2::Sha256::digest(message).as_slice()
        {
            Ok(())
        } else {
            Err("audit signature mismatch".into())
        }
    }
}

/// Every custody ceremony the Broker can prepare must be completable in the
/// shipped page.
///
/// `account_allocate` and `account_retire` were missing from the page's kind
/// handling while the Broker, Signer, and Machine CLI all supported them, so
/// `bloom wallet account-allocate` produced a ceremony URL that could never be
/// completed: the page sent no custody input and the Broker rejected the
/// completion while parsing it. Nothing caught that, because every test
/// completed these ceremonies through the API rather than the page.
#[test]
fn the_shipped_page_handles_every_custody_ceremony_kind() {
    let asset = include_str!("../src/ceremony_assets/app.js");

    // Kinds whose completion is PRF plus a typed effect, with no operator
    // input. The page must list them, or it sends nothing at all.
    for kind in [
        "wallet_export",
        "wallet_delete",
        "backend_enrollment",
        "key_derive",
        "policy_update",
        "account_allocate",
        "account_retire",
    ] {
        assert!(
            asset.contains(&format!("\"{kind}\"")),
            "the ceremony page does not handle the {kind} ceremony, so it cannot be completed"
        );
    }

    // Kinds the page handles through their own branches.
    for kind in [
        "sealed_approval",
        "wallet_registration",
        "wallet_import",
        "wallet_recovery",
        "credential_add",
        "credential_replace",
    ] {
        assert!(
            asset.contains(&format!("\"{kind}\"")),
            "the ceremony page does not mention the {kind} ceremony"
        );
    }
}

#[test]
fn browser_crypto_self_test_executes_the_shipped_asset() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let script = format!(
        r#"
globalThis.crypto = require("node:crypto").webcrypto;
globalThis.document = {{getElementById: () => ({{}})}};
globalThis.location = {{hash: "", search: "", pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
{executable}
cryptoSelfTest().then(
  () => process.stdout.write("browser-crypto-ok"),
  error => {{ console.error(error); process.exit(1); }}
);
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate the shipped ceremony asset");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "browser-crypto-ok");
}

#[test]
fn custody_manifest_is_rendered_on_the_primary_review_surface() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let script = format!(
        r#"
class Node {{
  constructor(name) {{ this.name = name; this.children = []; this.textContent = ""; this.innerHTML = ""; }}
  setAttribute() {{}}
  append(...children) {{ this.children.push(...children); }}
  replaceChildren(...children) {{ this.children = children; }}
}}
const nodes = {{}};
globalThis.document = {{
  getElementById: id => nodes[id] ||= new Node(id),
  createElement: name => new Node(name),
  createTextNode: text => String(text)
}};
globalThis.location = {{hash: "", search: "", pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
globalThis.setInterval = () => 1;
globalThis.clearInterval = () => {{}};
{executable}
function allText(node) {{
  if (typeof node === "string") return node;
  return `${{node.textContent}} ${{node.innerHTML}} ${{node.children.map(allText).join(" ")}}`;
}}
const operation = "op_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
renderReview({{
  ceremony_kind: "credential_remove",
  expires_at_ms: Date.now() + 60000,
  signer_contribution: {{wallet_id: "wallet-primary"}},
  review_manifest: {{
    schema: "bloom.custody_ceremony_review.v1",
    title: "Remove a passkey from a wallet",
    summary: "This credential stops being an authority for this wallet.",
    canonical_plan: `Remove a passkey\n\nOperation     ${{operation}}`
  }}
}});
const rendered = allText(nodes.review);
if (nodes["page-title"].textContent !== "Remove a passkey from a wallet" ||
    !rendered.includes("This credential stops being an authority") ||
    !rendered.includes(operation)) {{
  throw new Error(`custody manifest was not rendered: ${{rendered}}`);
}}
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate the shipped ceremony asset");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn key_derive_primary_review_explains_the_session_without_internal_scope_json() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let script = format!(
        r#"
class Node {{
  constructor(name) {{ this.name = name; this.children = []; this.textContent = ""; this.innerHTML = ""; }}
  setAttribute() {{}}
  append(...children) {{ this.children.push(...children); }}
  replaceChildren(...children) {{ this.children = children; }}
}}
const nodes = {{}};
globalThis.document = {{
  getElementById: id => nodes[id] ||= new Node(id),
  createElement: name => new Node(name),
  createTextNode: text => String(text)
}};
globalThis.location = {{hash: "", search: "", pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
globalThis.setInterval = () => 1;
globalThis.clearInterval = () => {{}};
{executable}
function allText(node) {{
  if (typeof node === "string") return node;
  return `${{node.textContent}} ${{node.innerHTML}} ${{node.children.map(allText).join(" ")}}`;
}}
const scope = {{
  allowed_operation_classes: ["pumpfun.buy", "pumpfun.sell", "pumpfun.sweep"],
  allowed_routes: ["r000010", "r000011", "r000020"],
  custody_operation_id: "internal-operation-id",
  maximum_lifetime_ms: "3600000",
  package_hash: "b868911206a002dd48c11fb59e8aaa8bd8b4716f70b671e10be18bd24bf7c738"
}};
renderReview({{
  ceremony_kind: "key_derive",
  expires_at_ms: Date.now() + 300000,
  signer_contribution: {{
    wallet_id: "main",
    key_ref: {{key_spec: "ed25519", derivation: {{path: "m/44'/501'/0'/0'"}}}},
    petal_key_scope: scope
  }},
  review_manifest: {{
    schema: "bloom.custody_ceremony_review.v1",
    title: "Create a temporary Petal key",
    summary: "technical fallback",
    canonical_plan: "internal-operation-id",
    petal_key_scope: scope
  }}
}});
const primary = allText({{textContent: "", innerHTML: "", children:
  nodes.review.children.filter(child => child?.name !== "details")}});
const technical = allText(nodes.review.children.find(child => child?.name === "details"));
for (const phrase of ["Pump.fun", "No funds move", "buy tokens", "sell tokens",
                      "return unused SOL", "main wallet key stays inside Bloom", "Up to 1h 0m"]) {{
  if (!primary.includes(phrase)) throw new Error(`primary review omitted ${{phrase}}: ${{primary}}`);
}}
for (const internal of ["allowed_routes", "custody_operation_id", "package_hash", "r000010"]) {{
  if (primary.includes(internal)) throw new Error(`primary review exposed ${{internal}}: ${{primary}}`);
}}
if (!technical.includes(scope.package_hash) || !technical.includes("allowed_routes")) {{
  throw new Error(`technical details omitted the exact signed scope: ${{technical}}`);
}}
if (nodes.approve.textContent !== "Create Pump.fun session key") {{
  throw new Error(`unexpected approval label: ${{nodes.approve.textContent}}`);
}}
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate the shipped ceremony asset");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn reusable_pumpfun_approval_is_plain_language_with_raw_grants_collapsed() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let script = format!(
        r#"
class Node {{
  constructor(name) {{ this.name = name; this.children = []; this.textContent = ""; this.innerHTML = ""; }}
  setAttribute() {{}}
  append(...children) {{ this.children.push(...children); }}
  replaceChildren(...children) {{ this.children = children; }}
}}
const nodes = {{}};
globalThis.document = {{
  getElementById: id => nodes[id] ||= new Node(id),
  createElement: name => new Node(name),
  createTextNode: text => String(text)
}};
globalThis.location = {{hash: "", search: "", pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
globalThis.setInterval = () => 1;
globalThis.clearInterval = () => {{}};
{executable}
function allText(node) {{
  if (typeof node === "string") return node;
  return `${{node.textContent}} ${{node.innerHTML}} ${{node.children.map(allText).join(" ")}}`;
}}
const packageHash = "b868911206a002dd48c11fb59e8aaa8bd8b4716f70b671e10be18bd24bf7c738";
const plan = {{
  security_disclosures: ["The displayed limits are asserted by the named Petal."],
  terms: {{
    wallet_id: "main",
    limits: {{max_operations: "256", max_signatures: "256"}},
    selector: {{
      kind: "petal",
      package_hash: packageHash,
      route: "r000007",
      allowed_operation_classes: ["pumpfun.buy", "pumpfun.sell", "pumpfun.sweep"],
      required_claim_assurance: "machine_asserted",
      route_grants: [{{route: "r000010", allowed_operation_classes: ["pumpfun.buy"]}}]
    }}
  }}
}};
renderReview({{
  ceremony_kind: "sealed_approval",
  expires_at_ms: Date.now() + 300000,
  signer_contribution: {{wallet_id: "main"}},
  review_manifest: {{
    wallet_id: "main",
    canonical_plan: JSON.stringify(plan),
    approval_id: "internal-approval-id"
  }}
}});
const primary = allText({{textContent: "", innerHTML: "", children:
  nodes.review.children.filter(child => child?.name !== "details")}});
const technical = allText(nodes.review.children.find(child => child?.name === "details"));
for (const phrase of ["Finish setting up", "Pump.fun", "buy tokens", "sell tokens",
                      "return unused SOL", "Up to 256 signed actions",
                      "main wallet key stays inside Bloom"]) {{
  if (!primary.includes(phrase)) throw new Error(`primary review omitted ${{phrase}}: ${{primary}}`);
}}
for (const internal of [packageHash, "route_grants", "machine_asserted", "r000010",
                        "limits are asserted by the named Petal"]) {{
  if (primary.includes(internal)) throw new Error(`primary review exposed ${{internal}}: ${{primary}}`);
}}
if (!technical.includes(packageHash) || !technical.includes("route_grants")) {{
  throw new Error(`technical details omitted the exact signed plan: ${{technical}}`);
}}
if (nodes["page-title"].textContent !== "Finish Pump.fun session setup" ||
    nodes.approve.textContent !== "Finish Pump.fun setup") {{
  throw new Error(`unexpected title or button: ${{nodes["page-title"].textContent}} / ${{nodes.approve.textContent}}`);
}}
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate the shipped ceremony asset");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Owners hold imported secp256k1 scalars as hex; Signer decodes base64url.
/// The shipped page must normalize every realistic hex spelling itself —
/// asking an owner to hand-convert a private key is both hostile and
/// error-prone (the mismatch previously surfaced as an opaque
/// `MALFORMED_FRAME: Invalid last symbol` from deep inside Signer).
#[test]
fn browser_page_accepts_hex_private_keys_and_converts_them_to_base64url() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let script = format!(
        r#"
globalThis.crypto = require("node:crypto").webcrypto;
globalThis.document = {{getElementById: () => ({{}})}};
globalThis.location = {{hash: "", search: "", pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
{executable}
const scalar = "01".repeat(32);
const expected = Buffer.from(scalar, "hex").toString("base64url");
const cases = [
  ["0x" + scalar, expected],
  [scalar, expected],
  ["0x" + scalar.toUpperCase(), expected],
  [expected, expected],
];
for (const [input, want] of cases) {{
  const got = normalizePrivateKey(input);
  if (got !== want) {{
    console.error("normalizePrivateKey(" + JSON.stringify(input) + ") => " + got + ", wanted " + want);
    process.exit(1);
  }}
}}
for (const bad of ["", "0x1234", "zz".repeat(32), "0x" + "0".repeat(63)]) {{
  try {{
    normalizePrivateKey(bad);
    console.error("normalizePrivateKey accepted invalid input " + JSON.stringify(bad));
    process.exit(1);
  }} catch (error) {{ /* rejected by name: expected */ }}
}}
process.stdout.write("hex-normalization-ok");
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate the shipped ceremony asset");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "hex-normalization-ok"
    );
}

#[test]
fn browser_ceremony_state_survives_reload_and_reuses_one_output_key() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    for required in [
        "tokenFromPath || readSessionToken()",
        "writeSessionToken(tokenFromPath)",
        "bloom-ceremony-browser-state-v1",
        "database.transaction(browserStateStore, \"readwrite\")",
        "store.get(session.ceremony_id)",
        "{name: \"X25519\"}, false, [\"deriveBits\"]",
        "await purgeExpiredBrowserState()",
        "await clearBrowserState(ceremonyId)",
    ] {
        assert!(
            asset.contains(required),
            "browser state flow omitted {required}"
        );
    }
    let persisted_key_flow = asset
        .split_once("async function outputRecipientFor(session)")
        .expect("asset must define persisted browser output-key state")
        .1
        .split_once("async function clearBrowserState(id)")
        .expect("asset must bound persisted browser output-key state")
        .0;
    assert!(
        !persisted_key_flow.contains("{name: \"X25519\"}, true, [\"deriveBits\"]"),
        "the persisted browser private key must be non-extractable"
    );
}

#[test]
fn browser_reload_recovers_the_ceremony_token_from_tab_storage() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let encoded_token = serde_json::to_value(Base64UrlBytes::from_bytes(&[31; 32])).unwrap();
    let token = encoded_token.as_str().unwrap();
    let script = format!(
        r#"
globalThis.crypto = require("node:crypto").webcrypto;
globalThis.document = {{getElementById: () => ({{}})}};
globalThis.location = {{pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
const stored = new Map([["bloom.ceremony.token.v1", {token:?}]]);
globalThis.sessionStorage = {{
  getItem: key => stored.get(key) || null,
  setItem: (key, value) => stored.set(key, value),
  removeItem: key => stored.delete(key)
}};
{executable}
if (token !== {token:?} || authHeaders["x-bloom-ceremony-token"] !== {token:?}) {{
  throw new Error("reload did not recover the ceremony token");
}}
process.stdout.write("browser-reload-ok");
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate ceremony reload state");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "browser-reload-ok");
}

#[test]
fn browser_approval_failure_is_logged_displayed_and_retryable() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let executable = asset
        .split_once("\nload().catch")
        .expect("asset must invoke load")
        .0;
    let script = format!(
        r#"
globalThis.crypto = require("node:crypto").webcrypto;
const elements = new Map();
globalThis.document = {{getElementById: id => {{
  if (!elements.has(id)) elements.set(id, {{disabled: true}});
  return elements.get(id);
}}}};
globalThis.location = {{pathname: "/"}};
globalThis.history = {{replaceState: () => {{}}}};
const logged = [];
globalThis.console = {{error: (...args) => logged.push(args)}};
{executable}
const failure = new Error("Signer rejected completion");
reportApprovalFailure(failure);
if (statusNode.textContent !== "Passkey verification failed. Please try again.") {{
  throw new Error(`failure was not displayed: ${{statusNode.textContent}}`);
}}
if (approve.disabled) throw new Error("approval retry was not enabled");
if (logged.length !== 1 || logged[0][0] !== "Bloom ceremony failed" ||
    logged[0][1] !== failure) {{
  throw new Error("full ceremony failure was not logged");
}}
const cancellationFailure = new Error("internal cancellation detail");
reportCeremonyError(cancellationFailure, "Cancellation failed. Please try again.");
if (statusNode.textContent !== "Cancellation failed. Please try again.") {{
  throw new Error("safe cancellation failure was not displayed");
}}
if (logged.length !== 2 || logged[1][1] !== cancellationFailure) {{
  throw new Error("full cancellation failure was not logged");
}}
process.stdout.write("browser-error-feedback-ok");
"#
    );
    let output = Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("Node.js is required to validate ceremony error feedback");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "browser-error-feedback-ok"
    );
    assert!(asset.contains("approve.onclick = () => run(session).catch(reportApprovalFailure)"));
    assert!(asset.contains("Cancellation failed. Please try again."));
    assert!(asset.contains("Ceremony failed to load. Please refresh and try again."));
}

#[test]
fn transfer_review_promises_later_verification_without_claiming_it_already_happened() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    assert!(asset.contains("Estimated network fee"));
    assert!(asset.contains("Required before signing"));
    assert!(asset.contains("Bloom will decode the transaction"));
    assert!(!asset.contains("Bloom decoded the transaction and it matches this summary"));
    assert!(!asset.contains("transfer.verified"));
}

#[test]
fn ceremony_shell_preserves_bloom_review_layout_and_required_controls() {
    let shell = include_str!("../src/ceremony_assets/index.html");
    for required in [
        "href=\"/assets/style.css\"",
        "href=\"/assets/bloom-primary.svg\"",
        "src=\"/assets/bloom-primary.svg\"",
        "Signed local review",
        "Review before continuing",
        "id=\"status\"",
        "id=\"review\"",
        "id=\"approve\"",
        "id=\"cancel\"",
        "id=\"recovery-fields\"",
        "id=\"generic-fields\"",
    ] {
        assert!(
            shell.contains(required),
            "ceremony shell omitted {required}"
        );
    }
    assert!(
        !shell.contains("<style>"),
        "the ceremony shell must not contain CSP-blocked inline styles"
    );

    let stylesheet = include_str!("../src/ceremony_assets/style.css");
    for required in [
        "--paper:#f4efe6",
        ".layout{display:grid",
        "@media(max-width:560px)",
    ] {
        assert!(
            stylesheet.contains(required),
            "ceremony stylesheet omitted {required}"
        );
    }

    let logo = include_str!("../src/ceremony_assets/bloom-primary.svg");
    assert_eq!(logo.matches("<path ").count(), 7);
    assert!(logo.contains("fill=\"#9d2d3f\""));
    assert!(logo.contains("stroke=\"#7a2230\""));
}

#[test]
fn scoped_petal_key_browser_flow_never_collects_a_namespace_grant() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    assert!(asset.contains("session.signer_contribution?.petal_key_scope"));
    assert!(asset.contains("&& !scopedPetalKey"));
    assert!(asset.contains("Boolean(scopedPetalKey)"));
    assert!(asset.contains("if (!scopedPetalKey && !genericFields.hidden)"));
    let run = asset
        .split_once("async function run(session)")
        .expect("asset must define the ceremony runner")
        .1;
    let definition = run
        .find("const scopedPetalKey")
        .expect("the runner must derive its own scoped-petal-key state");
    let use_site = run
        .find("if (!scopedPetalKey && !genericFields.hidden)")
        .expect("the runner must guard generic input");
    assert!(
        definition < use_site,
        "runner state must be defined before use"
    );
}

#[test]
fn legacy_passkey_browser_flow_uses_assertion_prf_and_hides_raw_key_input() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    assert!(asset.contains("legacy_passkey_v1_prf"));
    assert!(asset.contains("const assertion = await getCredential(session, 0)"));
    assert!(asset.contains("credential_prf: encodeUrl(credentialPrf)"));
    assert!(asset.contains(
        "importFields.hidden = !(session.ceremony_kind === \"wallet_import\" && !legacyPasskeyImport)"
    ));
    assert!(asset.contains("wallet_import\" && !legacyPasskeyImport"));
}

#[test]
fn bip39_browser_import_uses_profile_to_control_serialization() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let html = include_str!("../src/ceremony_assets/index.html");
    let css = include_str!("../src/ceremony_assets/style.css");
    let load = asset
        .split_once("async function load() {")
        .expect("browser asset must define load")
        .1
        .split_once("\nfunction fromHex")
        .expect("load must end before the crypto helpers")
        .0;
    let run = asset
        .split_once("async function run(session) {")
        .expect("browser asset must define run")
        .1;

    // Both browser phases must make their decision from the signed Signer
    // contribution. Keeping these assertions scoped catches a declaration in
    // run() that leaves load() with an undefined variable.
    for scope in [load, run] {
        assert!(scope.contains("const bip39Import = "));
        assert!(scope.contains("wallet_seed_profile === \"bip39-multicurve-v1\""));
    }
    assert!(load.contains("document.getElementById(\"mnemonic-label\").hidden = !bip39Import"));
    assert!(load.contains("document.getElementById(\"raw-key-label\").hidden = bip39Import"));

    // The serialization branch follows the profile; it never infers the
    // profile from whichever property the operator supplied.
    assert!(run.contains("if (bip39Import)"));
    assert!(run.contains("const mnemonic = mnemonicInput.value"));
    assert!(run.contains("[12, 15, 18, 21, 24].includes(count)"));
    assert!(run.contains("Enter a 12, 15, 18, 21, or 24 word recovery phrase"));
    assert!(run.contains("credential_prf: encodeUrl(prf.prf),\n          mnemonic\n"));
    assert!(!run.contains("passphrase:"));
    assert!(!run.contains("passphraseInput"));
    assert!(!run.contains("supplied.passphrase"));
    assert!(!load.contains("passphrase"));
    assert!(run.contains("normalizePrivateKey(rawKeyInput.value.trim())"));
    assert!(run.contains("raw_private_key: rawKey"));
    assert!(!run.contains("if (supplied.mnemonic)"));
    assert!(!run.contains("if (supplied.raw_private_key)"));

    // v1 has no BIP-39 passphrase input. The ceremony must not ask the
    // operator for an unsupported second secret, and fields for the other
    // import profile must stay hidden despite label styling.
    assert!(!html.contains("passphrase-input"));
    assert!(!html.contains("passphrase-label"));
    assert!(css.contains("[hidden]{display:none!important}"));
}

#[test]
fn bip39_browser_export_uses_the_length_neutral_signer_format() {
    let html = include_str!("../src/ceremony_assets/index.html");

    // This value is encrypted into GenericCustodyEffect and parsed by Signer.
    // Imported roots retain their original 12/15/18/21/24-word length, so the
    // browser must use Signer's length-neutral token instead of the obsolete
    // 24-word-only spelling.
    assert!(html.contains("value=\"bip39_mnemonic\""));
    assert!(!html.contains("bip39_mnemonic24"));
    assert!(!html.contains("the 24 words that restore this wallet"));
}

fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

fn signer_audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: Token::new("signer-audit-key").unwrap(),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

fn operation(byte: &str) -> OperationId {
    OperationId::new(byte.repeat(32)).unwrap()
}

#[derive(serde::Serialize)]
struct MachineSignOperationIdentity {
    operation_id: OperationId,
    approval_id: Digest32,
    key_ref: KeyRef,
    crypto_suite: CryptoSuite,
    ordered_payload_digests: Vec<Digest32>,
    ordered_hashes: Vec<Digest32>,
    petal_use_claim_digest: Option<Digest32>,
    claim_assurance_digest: Option<Digest32>,
    policy_version: DecimalU64,
    policy_digest: Digest32,
}

impl MachineSignOperationIdentity {
    fn digest(&self) -> Digest32 {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"bloom-sign-operation/v1");
        hasher.update(serde_jcs::to_vec(self).unwrap());
        Digest32::from_bytes(hasher.finalize().into())
    }
}

fn sign_provenance(record: &mut ProvenanceRecord, key: &SigningKey) {
    let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&record.unsigned_canonical_bytes().unwrap());
    record.installer_signature = Base64UrlBytes::from_bytes(&key.sign(&message).to_bytes());
}

fn petal_sign_request(
    terms: &SealedApprovalTerms,
    operation_id: OperationId,
    package_hash: Digest32,
    route: &str,
    payload: &[u8],
) -> MachineSignRequest {
    let payload_digest = Digest32::from_bytes(sha2::Sha256::digest(payload).into());
    let mut claim_payload_digest = sha2::Sha256::new();
    claim_payload_digest.update(b"bloom.petal.payload-batch.v1\0");
    claim_payload_digest.update(1u64.to_be_bytes());
    claim_payload_digest.update((payload.len() as u64).to_be_bytes());
    claim_payload_digest.update(payload);
    let claim = PetalUseClaim {
        package_hash: package_hash.clone(),
        route: route.into(),
        operation_class: Token::new("exchange-order").unwrap(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        payload_digest: Digest32::from_bytes(claim_payload_digest.finalize().into()),
        ordered_hashes: vec![payload_digest.clone()],
        declared_debits: Vec::new(),
        declared_destinations: Vec::new(),
        declared_fee: DeclaredFee::None,
        nonce: RequestNonce::from_bytes([operation_id.to_bytes()[31]; 16]),
        claim_assurance: ClaimAssurance::MachineAsserted,
    };
    let claim_digest =
        Digest32::from_bytes(sha2::Sha256::digest(serde_jcs::to_vec(&claim).unwrap()).into());
    let assurance_digest = Digest32::from_bytes(
        sha2::Sha256::digest(serde_jcs::to_vec(&claim.claim_assurance).unwrap()).into(),
    );
    let identity = MachineSignOperationIdentity {
        operation_id: operation_id.clone(),
        approval_id: terms.approval_id().unwrap(),
        key_ref: terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        ordered_payload_digests: vec![payload_digest.clone()],
        ordered_hashes: vec![payload_digest],
        petal_use_claim_digest: Some(claim_digest),
        claim_assurance_digest: Some(assurance_digest),
        policy_version: terms.policy_version.clone(),
        policy_digest: terms.policy_digest.clone(),
    };
    MachineSignRequest {
        operation_id,
        operation_digest: identity.digest(),
        approval_id: terms.approval_id().unwrap(),
        key_ref: terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        payloads: SigningPayloads::Single {
            payload: Base64UrlBytes::from_bytes(payload),
        },
        petal_use_claim: Some(claim),
        system_use_claim: None,
        claim_assurance_evidence: None,
        provenance: ProvenanceSubject::Petal {
            package_hash,
            route: route.into(),
        },
    }
}

fn exact_petal_sign_request(
    terms: &SealedApprovalTerms,
    operation_id: OperationId,
    package_hash: Digest32,
    route: &str,
    payload: &[u8],
) -> MachineSignRequest {
    let payload_digest = Digest32::from_bytes(sha2::Sha256::digest(payload).into());
    let identity = MachineSignOperationIdentity {
        operation_id: operation_id.clone(),
        approval_id: terms.approval_id().unwrap(),
        key_ref: terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        ordered_payload_digests: vec![payload_digest.clone()],
        ordered_hashes: vec![payload_digest],
        petal_use_claim_digest: None,
        claim_assurance_digest: None,
        policy_version: terms.policy_version.clone(),
        policy_digest: terms.policy_digest.clone(),
    };
    MachineSignRequest {
        operation_id,
        operation_digest: identity.digest(),
        approval_id: terms.approval_id().unwrap(),
        key_ref: terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        payloads: SigningPayloads::Single {
            payload: Base64UrlBytes::from_bytes(payload),
        },
        petal_use_claim: None,
        system_use_claim: None,
        claim_assurance_evidence: None,
        provenance: ProvenanceSubject::Petal {
            package_hash,
            route: route.into(),
        },
    }
}

fn approval_request() -> CeremonyPrepareRequest {
    let key_ref = bloom_signer_api::KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("local-default").unwrap(),
        key_spec: bloom_signer_api::KeySpec::Secp256k1,
        locator: "root-key".into(),
        derivation: None,
        public_key_fingerprint: digest("11"),
    };
    let terms = bloom_signer_api::SealedApprovalTerms {
        subject: bloom_signer_api::ApprovalSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet-sign").unwrap(),
        },
        wallet_id: Token::new("wallet-review").unwrap(),
        key_ref,
        allowed_crypto_suites: vec![bloom_signer_api::CryptoSuite::Secp256k1Sha256Recoverable],
        selector: bloom_signer_api::ApprovalSelector::Exact {
            ordered_payload_digests: vec![digest("12")],
            ordered_hashes: vec![digest("13")],
        },
        limits: bloom_signer_api::ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: bloom_signer_api::ActivationMode::BackendManaged,
        wallet_revocation_epoch: DecimalU64::new(1),
        policy_version: DecimalU64::new(1),
        policy_digest: digest("14"),
        provenance_digest: digest("15"),
        request_nonce: RequestNonce::new("16".repeat(16)).unwrap(),
        issued_at_ms: DecimalU64::new(1_000),
        not_before_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(u64::MAX - 1),
        renewal_of: None,
    };
    CeremonyPrepareRequest {
        activation_operation_id: operation("17"),
        terms,
        review_manifest_digest: digest("00"),
        exact_ordered_payload_digests: vec![digest("12")],
        exact_ordered_hashes: vec![digest("13")],
        replacement_approval_id: None,
    }
}

struct MockSigner {
    completions: AtomicUsize,
    cancellations: AtomicUsize,
    custody_preparations: AtomicUsize,
    custody_prepare_events: Option<std::sync::mpsc::Sender<usize>>,
    first_custody_release: parking_lot::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    pending: parking_lot::Mutex<HashSet<OperationId>>,
    reject_completion: bool,
    sensitive_result: bool,
    cancellation_fails: AtomicBool,
}

struct RealSigner {
    service: Arc<SignerCeremonyService>,
}

fn real_ceremony_signer() -> Arc<RealSigner> {
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    let engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            signer_audit_keys(),
            registry,
        )
        .unwrap(),
    );
    let service = Arc::new(
        SignerCeremonyService::new(
            engine,
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    Arc::new(RealSigner { service })
}

struct FailOnceAdoptionObserver {
    authority: Arc<BrokerAuthority>,
    custody_attempts: AtomicUsize,
}

fn custody_result_to_machine(value: &CustodyResult) -> bloom_broker_api::CustodyResult {
    fn kind(value: CeremonyKind) -> bloom_broker_api::CeremonyKind {
        match value {
            CeremonyKind::SealedApproval => bloom_broker_api::CeremonyKind::SealedApproval,
            CeremonyKind::WalletRegistration => bloom_broker_api::CeremonyKind::WalletRegistration,
            CeremonyKind::WalletImport => bloom_broker_api::CeremonyKind::WalletImport,
            CeremonyKind::WalletExport => bloom_broker_api::CeremonyKind::WalletExport,
            CeremonyKind::WalletDelete => bloom_broker_api::CeremonyKind::WalletDelete,
            CeremonyKind::WalletRecovery => bloom_broker_api::CeremonyKind::WalletRecovery,
            CeremonyKind::CredentialAdd => bloom_broker_api::CeremonyKind::CredentialAdd,
            CeremonyKind::CredentialReplace => bloom_broker_api::CeremonyKind::CredentialReplace,
            CeremonyKind::CredentialRemove => bloom_broker_api::CeremonyKind::CredentialRemove,
            CeremonyKind::BackendEnrollment => bloom_broker_api::CeremonyKind::BackendEnrollment,
            CeremonyKind::KeyDerive => bloom_broker_api::CeremonyKind::KeyDerive,
            CeremonyKind::AccountAllocate => bloom_broker_api::CeremonyKind::AccountAllocate,
            CeremonyKind::AccountRetire => bloom_broker_api::CeremonyKind::AccountRetire,
            CeremonyKind::PolicyUpdate => bloom_broker_api::CeremonyKind::PolicyUpdate,
        }
    }
    fn state(value: bloom_signer_api::CeremonyState) -> CeremonyState {
        match value {
            bloom_signer_api::CeremonyState::Prepared => CeremonyState::Prepared,
            bloom_signer_api::CeremonyState::AwaitingUser => CeremonyState::AwaitingUser,
            bloom_signer_api::CeremonyState::Verifying => CeremonyState::Verifying,
            bloom_signer_api::CeremonyState::WalletCommitted => CeremonyState::WalletCommitted,
            bloom_signer_api::CeremonyState::AwaitingRecoveryAck => {
                CeremonyState::AwaitingRecoveryAck
            }
            bloom_signer_api::CeremonyState::Completed => CeremonyState::Completed,
            bloom_signer_api::CeremonyState::ApprovingRootChange => {
                CeremonyState::ApprovingRootChange
            }
            bloom_signer_api::CeremonyState::CreatingCredential => {
                CeremonyState::CreatingCredential
            }
            bloom_signer_api::CeremonyState::Committing => CeremonyState::Committing,
            bloom_signer_api::CeremonyState::Succeeded => CeremonyState::Succeeded,
            bloom_signer_api::CeremonyState::Cancelled => CeremonyState::Cancelled,
            bloom_signer_api::CeremonyState::Expired => CeremonyState::Expired,
            bloom_signer_api::CeremonyState::Failed => CeremonyState::Failed,
        }
    }
    fn key(value: &bloom_signer_api::KeyRef) -> KeyRef {
        KeyRef {
            backend: value.backend.clone(),
            backend_instance: value.backend_instance.clone(),
            locator: value.locator.clone(),
            key_spec: match value.key_spec {
                bloom_signer_api::KeySpec::Secp256k1 => KeySpec::Secp256k1,
                bloom_signer_api::KeySpec::Ed25519 => KeySpec::Ed25519,
            },
            public_key_fingerprint: value.public_key_fingerprint.clone(),
            derivation: value
                .derivation
                .as_ref()
                .map(|derivation| match derivation {
                    bloom_signer_api::DerivationRef::Bip32Secp256k1 { root_key_id, path } => {
                        bloom_broker_api::DerivationRef::Bip32Secp256k1 {
                            root_key_id: root_key_id.clone(),
                            path: path.clone(),
                        }
                    }
                    bloom_signer_api::DerivationRef::Bip39Multicurve {
                        wallet_seed_ref,
                        profile,
                        path,
                    } => bloom_broker_api::DerivationRef::Bip39Multicurve {
                        wallet_seed_ref: wallet_seed_ref.clone(),
                        profile: match profile {
                            bloom_signer_api::DerivationProfile::Bip44EvmSecp256k1V1 => {
                                bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1
                            }
                            bloom_signer_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
                                bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1
                            }
                        },
                        path: path.clone(),
                    },
                }),
        }
    }
    bloom_broker_api::CustodyResult {
        ceremony_kind: kind(value.ceremony_kind),
        custody_operation_id: value.custody_operation_id.clone(),
        public_status: state(value.public_status),
        wallet_id: value.wallet_id.clone(),
        public_key_refs: value.public_key_refs.iter().map(key).collect(),
        credential_summaries: value
            .credential_summaries
            .iter()
            .map(|credential| bloom_broker_api::CredentialSummary {
                credential_id: credential.credential_id.clone(),
                rp_id: credential.rp_id.clone(),
                active: credential.active,
            })
            .collect(),
        initial_policy: value
            .initial_policy
            .as_ref()
            .map(|policy| SignedPolicySnapshot {
                wallet_id: policy.wallet_id.clone(),
                version: policy.version.clone(),
                canonical_policy: policy.canonical_policy.clone(),
                policy_digest: policy.policy_digest.clone(),
                policy_signing_key_id: policy.policy_signing_key_id.clone(),
                policy_verifying_key: policy.policy_verifying_key.clone(),
                signer_signature: policy.signer_signature.clone(),
            }),
        receipt_digest: value.receipt_digest.clone(),
        encrypted_browser_result: value.encrypted_browser_result.as_ref().map(|encrypted| {
            bloom_broker_api::EncryptedBrowserResult {
                kem_output: encrypted.kem_output.clone(),
                ciphertext: encrypted.ciphertext.clone(),
            }
        }),
        signer_key_id: value.signer_key_id.clone(),
        signer_signature: value.signer_signature.clone(),
    }
}

fn key_to_signer(value: &KeyRef) -> bloom_signer_api::KeyRef {
    bloom_signer_api::KeyRef {
        backend: value.backend.clone(),
        backend_instance: value.backend_instance.clone(),
        locator: value.locator.clone(),
        key_spec: match value.key_spec {
            KeySpec::Secp256k1 => bloom_signer_api::KeySpec::Secp256k1,
            KeySpec::Ed25519 => bloom_signer_api::KeySpec::Ed25519,
        },
        public_key_fingerprint: value.public_key_fingerprint.clone(),
        derivation: value
            .derivation
            .as_ref()
            .map(|derivation| match derivation {
                bloom_broker_api::DerivationRef::Bip32Secp256k1 { root_key_id, path } => {
                    bloom_signer_api::DerivationRef::Bip32Secp256k1 {
                        root_key_id: root_key_id.clone(),
                        path: path.clone(),
                    }
                }
                bloom_broker_api::DerivationRef::Bip39Multicurve {
                    wallet_seed_ref,
                    profile,
                    path,
                } => bloom_signer_api::DerivationRef::Bip39Multicurve {
                    wallet_seed_ref: wallet_seed_ref.clone(),
                    profile: match profile {
                        bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1 => {
                            bloom_signer_api::DerivationProfile::Bip44EvmSecp256k1V1
                        }
                        bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
                            bloom_signer_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1
                        }
                    },
                    path: path.clone(),
                },
            }),
    }
}

fn crypto_suite_to_signer(value: CryptoSuite) -> bloom_signer_api::CryptoSuite {
    match value {
        CryptoSuite::Secp256k1Sha256Recoverable => {
            bloom_signer_api::CryptoSuite::Secp256k1Sha256Recoverable
        }
        CryptoSuite::Secp256k1Keccak256Recoverable => {
            bloom_signer_api::CryptoSuite::Secp256k1Keccak256Recoverable
        }
        CryptoSuite::Ed25519Message => bloom_signer_api::CryptoSuite::Ed25519Message,
    }
}

fn activation_mode_to_signer(value: ActivationMode) -> bloom_signer_api::ActivationMode {
    match value {
        ActivationMode::BootBound => bloom_signer_api::ActivationMode::BootBound,
        ActivationMode::DurableLocal {
            provider_tier,
            maximum_rearm_until_ms,
        } => bloom_signer_api::ActivationMode::DurableLocal {
            provider_tier,
            maximum_rearm_until_ms,
        },
        ActivationMode::BackendManaged => bloom_signer_api::ActivationMode::BackendManaged,
    }
}

fn petal_scope_to_signer(value: &PetalKeyScope) -> bloom_signer_api::PetalKeyScope {
    bloom_signer_api::PetalKeyScope {
        wallet_id: value.wallet_id.clone(),
        parent_key_ref: key_to_signer(&value.parent_key_ref),
        package_hash: value.package_hash.clone(),
        route: value.route.clone(),
        lineage_id: value.lineage_id.clone(),
        key_slot: value.key_slot.clone(),
        allowed_routes: value.allowed_routes.clone(),
        allowed_operation_classes: value.allowed_operation_classes.clone(),
        allowed_crypto_suites: value
            .allowed_crypto_suites
            .iter()
            .cloned()
            .map(crypto_suite_to_signer)
            .collect(),
        maximum_lifetime_ms: value.maximum_lifetime_ms.clone(),
        custody_operation_id: value.custody_operation_id.clone(),
    }
}

impl CeremonyCompletionObserver for FailOnceAdoptionObserver {
    fn approval_completed(
        &self,
        receipt: &SignerActivationReceipt,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.authority
            .activate_signer_receipt(receipt, now_ms)
            .map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, error.to_string())
            })
    }

    fn custody_completed(&self, receipt: &CustodyResult, now_ms: u64) -> Result<(), ProtocolError> {
        if self.custody_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "injected transient initial-policy storage failure",
            ));
        }
        self.authority
            .adopt_custody_receipt(&custody_result_to_machine(receipt), now_ms)
            .map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, error.to_string())
            })
    }
}

impl CeremonySigner for RealSigner {
    fn prepare_approval(
        &self,
        request: CeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedApproval, bloom_signer_api::ProtocolError> {
        let wallet_id = request.terms.wallet_id.clone();
        let prepared = self.service.prepare_approval(request, now_ms)?;
        let verification_credentials = prepared
            .webauthn_options
            .allowed_credentials
            .iter()
            .map(|allowed| self.service.credential(&wallet_id, &allowed.credential_id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SignerPreparedApproval {
            contribution: prepared.contribution,
            challenges: prepared.challenges,
            webauthn_options: prepared.webauthn_options,
            verification_credentials,
        })
    }

    fn complete_approval(
        &self,
        request: CeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<SignerActivationReceipt, bloom_signer_api::ProtocolError> {
        futures::executor::block_on(self.service.complete_approval(request, now_ms))
    }

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
        let prepared = self.service.prepare_custody(request, now_ms)?;
        let verification_credentials = prepared
            .contribution
            .wallet_id
            .as_ref()
            .map(|wallet_id| {
                prepared
                    .webauthn_options
                    .allowed_credentials
                    .iter()
                    .map(|allowed| self.service.credential(wallet_id, &allowed.credential_id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(SignerPreparedCustody {
            contribution: prepared.contribution,
            challenges: prepared.challenges,
            webauthn_options: prepared.webauthn_options,
            verification_credentials,
        })
    }

    fn complete_custody(
        &self,
        request: CustodyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, bloom_signer_api::ProtocolError> {
        self.service.complete_custody(request, now_ms)
    }

    fn cancel(&self, operation_id: &OperationId) -> Result<(), bloom_signer_api::ProtocolError> {
        self.service.cancel(operation_id)
    }

    fn bind_custody_output_recipient(
        &self,
        operation_id: &OperationId,
        recipient_key: Base64UrlBytes,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
        let prepared =
            self.service
                .bind_custody_output_recipient(operation_id, recipient_key, now_ms)?;
        let verification_credentials = prepared
            .contribution
            .wallet_id
            .as_ref()
            .map(|wallet_id| {
                prepared
                    .webauthn_options
                    .allowed_credentials
                    .iter()
                    .map(|allowed| self.service.credential(wallet_id, &allowed.credential_id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(SignerPreparedCustody {
            contribution: prepared.contribution,
            challenges: prepared.challenges,
            webauthn_options: prepared.webauthn_options,
            verification_credentials,
        })
    }

    fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
        let prepared = self.service.prepare_policy_update(request, now_ms)?;
        let verification_credentials = prepared
            .contribution
            .wallet_id
            .as_ref()
            .map(|wallet_id| {
                prepared
                    .webauthn_options
                    .allowed_credentials
                    .iter()
                    .map(|allowed| self.service.credential(wallet_id, &allowed.credential_id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(SignerPreparedCustody {
            contribution: prepared.contribution,
            challenges: prepared.challenges,
            webauthn_options: prepared.webauthn_options,
            verification_credentials,
        })
    }

    fn complete_policy_update(
        &self,
        request: PolicyUpdateCeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, bloom_signer_api::ProtocolError> {
        self.service.complete_policy_update(request, now_ms)
    }

    fn status(
        &self,
        operation_id: &OperationId,
    ) -> Result<SignerCeremonyStatus, bloom_signer_api::ProtocolError> {
        Ok(match self.service.status(operation_id)? {
            bloom_signer::ceremony::SignerCeremonyStatus::Pending => SignerCeremonyStatus::Pending,
            bloom_signer::ceremony::SignerCeremonyStatus::CompletedApproval(receipt) => {
                SignerCeremonyStatus::CompletedApproval(receipt)
            }
            bloom_signer::ceremony::SignerCeremonyStatus::CompletedCustody(result) => {
                SignerCeremonyStatus::CompletedCustody(result)
            }
            bloom_signer::ceremony::SignerCeremonyStatus::Terminal(state) => {
                SignerCeremonyStatus::Terminal(state)
            }
            bloom_signer::ceremony::SignerCeremonyStatus::Missing => SignerCeremonyStatus::Missing,
        })
    }
}

impl MockSigner {
    fn new() -> Self {
        Self {
            completions: AtomicUsize::new(0),
            cancellations: AtomicUsize::new(0),
            custody_preparations: AtomicUsize::new(0),
            custody_prepare_events: None,
            first_custody_release: parking_lot::Mutex::new(None),
            pending: parking_lot::Mutex::new(HashSet::new()),
            reject_completion: false,
            sensitive_result: false,
            cancellation_fails: AtomicBool::new(false),
        }
    }

    fn with_sensitive_result() -> Self {
        Self {
            sensitive_result: true,
            ..Self::new()
        }
    }

    /// A Signer that refuses the browser proof with `UnauthenticatedPeer`, the
    /// stale-signature-counter rejection that leaves its operation pending.
    fn rejecting_proof(cancellation_fails: bool) -> Self {
        Self {
            reject_completion: true,
            cancellation_fails: AtomicBool::new(cancellation_fails),
            ..Self::new()
        }
    }

    fn blocking_first_custody() -> (
        Self,
        std::sync::mpsc::Receiver<usize>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut signer = Self::new();
        signer.custody_prepare_events = Some(events_tx);
        *signer.first_custody_release.lock() = Some(release_rx);
        (signer, events_rx, release_tx)
    }

    /// End a transient cancellation outage so the next reconciliation attempt
    /// releases the still-pending Signer operation.
    fn restore_cancellation(&self) {
        self.cancellation_fails.store(false, Ordering::SeqCst);
    }
}

impl CeremonySigner for MockSigner {
    fn prepare_approval(
        &self,
        request: CeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedApproval, bloom_signer_api::ProtocolError> {
        self.pending
            .lock()
            .insert(request.activation_operation_id.clone());
        let mut contribution = SignerCeremonyContribution {
            ceremony_id: Digest32::from_bytes(
                sha2::Sha256::digest(request.activation_operation_id.to_bytes()).into(),
            ),
            signer_nonce: digest("21"),
            approval_digest: request.terms.approval_digest()?,
            review_manifest_digest: request.review_manifest_digest.clone(),
            key_ref: request.terms.key_ref.clone(),
            allowed_crypto_suites: request.terms.allowed_crypto_suites.clone(),
            activation_mode: request.terms.activation_mode.clone(),
            wallet_revocation_epoch: request.terms.wallet_revocation_epoch.clone(),
            required_user_verification: true,
            ephemeral_encryption_public_key: None,
            expires_at_ms: DecimalU64::new(now_ms + 10_000),
            signer_key_id: Token::new("mock-signer").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        contribution.signer_signature = Base64UrlBytes::from_bytes(&[8; 64]);
        let challenge = CeremonyChallenge {
            schema: Token::new("bloom.ceremony.challenge.v1").unwrap(),
            ceremony_id: contribution.ceremony_id.clone(),
            ceremony_kind: bloom_signer_api::CeremonyKind::SealedApproval,
            operation_id: request.activation_operation_id,
            signer_nonce: contribution.signer_nonce.clone(),
            review_manifest_digest: request.review_manifest_digest,
            signer_contribution_digest: contribution.digest()?,
            exact_terms_digest: request.terms.approval_digest()?,
            phase: CeremonyPhase::Approve,
        };
        Ok(SignerPreparedApproval {
            contribution,
            challenges: vec![challenge],
            webauthn_options: CeremonyWebAuthnOptions {
                allowed_credentials: vec![],
                registration_user_handle: None,
                registration_prf_salt: None,
            },
            verification_credentials: Vec::new(),
        })
    }

    fn complete_approval(
        &self,
        _request: CeremonyCompleteRequest,
        _now_ms: u64,
    ) -> Result<SignerActivationReceipt, bloom_signer_api::ProtocolError> {
        Err(bloom_signer_api::ProtocolError::new(
            bloom_signer_api::ProtocolErrorCode::BackendUnsupported,
            "mock exposes only the custody path used by this test",
        ))
    }

    fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
        let preparation = self.custody_preparations.fetch_add(1, Ordering::SeqCst);
        if let Some(events) = &self.custody_prepare_events {
            events.send(preparation).unwrap();
        }
        if preparation == 0
            && let Some(release) = self.first_custody_release.lock().take()
        {
            release.recv().unwrap();
        }
        let effective_wallet_id = request.wallet_id.clone().or_else(|| {
            request
                .legacy_passkey_migration
                .as_ref()
                .map(|migration| migration.wallet_name.clone())
        });
        self.pending
            .lock()
            .insert(request.custody_operation_id.clone());
        let ceremony_id = Digest32::from_bytes(
            sha2::Sha256::digest(request.custody_operation_id.to_bytes()).into(),
        );
        let mut contribution = CustodySignerContribution {
            ceremony_id: ceremony_id.clone(),
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id.clone(),
            signer_nonce: digest("22"),
            review_manifest_digest: request.exact_terms_digest.clone(),
            wallet_id: effective_wallet_id,
            key_ref: request.key_ref,
            expected_input_class: request.expected_input_class,
            required_user_verification: true,
            hpke_recipient_key: Base64UrlBytes::from_bytes(&[7; 32]),
            browser_output_recipient_key: request.browser_output_recipient_key,
            petal_key_scope: request.petal_key_scope,
            wallet_seed_profile: request.wallet_seed_profile,
            expires_at_ms: DecimalU64::new(now_ms + 10_000),
            signer_key_id: Token::new("mock-signer").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        // A signature is opaque to Broker. Non-empty bytes make accidental
        // dropping or reconstruction observable in the relay test.
        contribution.signer_signature = Base64UrlBytes::from_bytes(&[9; 64]);
        let challenge = CeremonyChallenge {
            schema: Token::new("bloom.ceremony.challenge.v1").unwrap(),
            ceremony_id,
            ceremony_kind: request.ceremony_kind,
            operation_id: request.custody_operation_id,
            signer_nonce: digest("22"),
            review_manifest_digest: request.exact_terms_digest.clone(),
            signer_contribution_digest: contribution.digest().unwrap(),
            exact_terms_digest: request.exact_terms_digest,
            phase: CeremonyPhase::Approve,
        };
        Ok(SignerPreparedCustody {
            contribution,
            challenges: vec![challenge],
            webauthn_options: CeremonyWebAuthnOptions {
                allowed_credentials: vec![],
                registration_user_handle: None,
                registration_prf_salt: None,
            },
            verification_credentials: Vec::new(),
        })
    }

    fn complete_custody(
        &self,
        request: CustodyCompleteRequest,
        _now_ms: u64,
    ) -> Result<CustodyResult, bloom_signer_api::ProtocolError> {
        if self.reject_completion {
            return Err(bloom_signer_api::ProtocolError::new(
                bloom_signer_api::ProtocolErrorCode::UnauthenticatedPeer,
                "stale webauthn signature counter",
            ));
        }
        self.completions.fetch_add(1, Ordering::SeqCst);
        Ok(CustodyResult {
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id,
            public_status: request.ceremony_kind.successful_terminal_state().unwrap(),
            wallet_id: None,
            public_key_refs: Vec::new(),
            credential_summaries: Vec::new(),
            initial_policy: None,
            receipt_digest: digest("44"),
            encrypted_browser_result: self.sensitive_result.then(|| {
                serde_json::from_value(serde_json::json!({
                    "kem_output": "a2Vt",
                    "ciphertext": "Y2lwaGVydGV4dA"
                }))
                .unwrap()
            }),
            signer_key_id: Token::new("mock-signer-key").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[0; 64]),
        })
    }

    fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
        let review_manifest_digest = request
            .broker_validation_receipt
            .review_manifest_digest
            .clone();
        let mut prepared = self.prepare_custody(request.custody, now_ms)?;
        prepared.contribution.review_manifest_digest = review_manifest_digest.clone();
        prepared.contribution.signer_signature = Base64UrlBytes::from_bytes(&[9; 64]);
        let contribution_digest = prepared.contribution.digest()?;
        for challenge in &mut prepared.challenges {
            challenge.review_manifest_digest = review_manifest_digest.clone();
            challenge.signer_contribution_digest = contribution_digest.clone();
        }
        Ok(prepared)
    }

    fn complete_policy_update(
        &self,
        request: PolicyUpdateCeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, bloom_signer_api::ProtocolError> {
        self.complete_custody(request.custody, now_ms)
    }

    fn cancel(&self, operation_id: &OperationId) -> Result<(), bloom_signer_api::ProtocolError> {
        self.cancellations.fetch_add(1, Ordering::SeqCst);
        if self.cancellation_fails.load(Ordering::SeqCst) {
            // The operation stays pending: the Signer still holds the wallet's
            // concurrency quota until a later cancel succeeds.
            return Err(bloom_signer_api::ProtocolError::new(
                bloom_signer_api::ProtocolErrorCode::ServiceUnavailable,
                "mock cancellation is unavailable",
            ));
        }
        self.pending.lock().remove(operation_id);
        Ok(())
    }

    fn bind_custody_output_recipient(
        &self,
        _operation_id: &OperationId,
        _recipient_key: Base64UrlBytes,
        _now_ms: u64,
    ) -> Result<SignerPreparedCustody, bloom_signer_api::ProtocolError> {
        Err(bloom_signer_api::ProtocolError::new(
            bloom_signer_api::ProtocolErrorCode::BackendUnsupported,
            "mock does not expose output-key binding",
        ))
    }

    fn status(
        &self,
        operation_id: &OperationId,
    ) -> Result<SignerCeremonyStatus, bloom_signer_api::ProtocolError> {
        Ok(if self.pending.lock().contains(operation_id) {
            SignerCeremonyStatus::Pending
        } else {
            SignerCeremonyStatus::Missing
        })
    }
}

fn try_prepare(
    broker: &CeremonyBroker,
    operation_id: OperationId,
    wallet_id: Option<Token>,
    now_ms: u64,
) -> Result<CustodyPrepareResponse, ProtocolError> {
    broker.prepare_custody(
        CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::WalletDelete,
            custody_operation_id: operation_id,
            wallet_id,
            key_ref: None,
            exact_terms_digest: digest("33"),
            expected_input_class: Token::new("policy-document").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
            wallet_seed_profile: None,
            derivation_request: None,
        },
        now_ms,
    )
}

fn prepare(
    broker: &CeremonyBroker,
    operation_id: OperationId,
    wallet_id: Option<Token>,
    now_ms: u64,
) -> CustodyPrepareResponse {
    try_prepare(broker, operation_id, wallet_id, now_ms).unwrap()
}

/// An anonymous registration: the quota class that is unauthenticated by any
/// existing wallet credential, so it is counted separately from the wallet
/// rolling quota that also judges it.
fn try_register(
    broker: &CeremonyBroker,
    operation_id: OperationId,
    wallet_id: Token,
    now_ms: u64,
) -> Result<CustodyPrepareResponse, ProtocolError> {
    broker.prepare_custody(
        CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::WalletRegistration,
            custody_operation_id: operation_id,
            wallet_id: Some(wallet_id),
            key_ref: None,
            exact_terms_digest: digest("34"),
            expected_input_class: Token::new("passkey-prf").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
            wallet_seed_profile: Some(bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1),
            derivation_request: None,
        },
        now_ms,
    )
}

/// Assert the structured retry contract on a rolling-quota rejection: callers
/// act on these values, never on the human-readable message.
fn assert_retry_contract(error: &ProtocolError, retry_after_ms: u64, limit: u64, window_ms: u64) {
    assert_eq!(error.code, ProtocolErrorCode::CeremonyRateLimited);
    assert!(error.has_valid_contract());
    let details = error
        .rate_limit
        .expect("a rolling-quota rejection must carry structured retry metadata");
    assert_eq!(
        details,
        RateLimitDetails::new(retry_after_ms, limit, window_ms).unwrap(),
        "unexpected retry contract in {}",
        error.message
    );
}

fn url_token(url: &str) -> String {
    url.strip_prefix("http://localhost:18734/ceremony/")
        .unwrap()
        .to_owned()
}

fn local_identity(service_id: &str, seed: [u8; 32], epoch: &str) -> LocalIdentity {
    LocalIdentity {
        service_id: Token::new(service_id).unwrap(),
        boot_epoch: BootEpoch::new(epoch.repeat(16)).unwrap(),
        application_key_id: Token::new(format!("{service_id}-app")).unwrap(),
        signing_key: Arc::new(SigningKey::from_bytes(&seed)),
    }
}

fn peer_acl(identity: &LocalIdentity, effective_uid: u32) -> PeerAcl {
    PeerAcl {
        effective_uid,
        service_id: identity.service_id.clone(),
        boot_epoch: identity.boot_epoch.clone(),
        application_key_id: identity.application_key_id.clone(),
        application_public_key: identity.signing_key.verifying_key().to_bytes(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_service_requires_completion_then_commits_and_replays_over_authenticated_rpc() {
    let authenticator = VirtualAuthenticator::generate();
    let directory = tempfile::tempdir().unwrap();
    let signer_database = directory.path().join("signer.sqlite");
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    let signer_engine = Arc::new(
        SignerEngine::open(
            &signer_database,
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            signer_audit_keys(),
            registry,
        )
        .unwrap(),
    );
    let signer_ceremony = Arc::new(
        SignerCeremonyService::new(
            signer_engine.clone(),
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let socket_path = directory.path().join("signer.sock");
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let effective_uid = fs::metadata(directory.path()).unwrap().uid();
    let broker_identity = local_identity("bloom-broker", [0x31; 32], "31");
    let signer_identity = local_identity("bloom-signer", [0x32; 32], "32");
    let signer_acl = peer_acl(&signer_identity, effective_uid);
    let broker_acl = peer_acl(&broker_identity, effective_uid);
    let broker_journal_path = directory.path().join("broker-journal.sqlite");
    let broker_authority_path = directory.path().join("broker-authority.sqlite");
    let journal = Arc::new(
        BrokerJournal::open(&broker_journal_path, Arc::new(ServiceTestAuditSigner)).unwrap(),
    );
    let signer_rpc = Arc::new(SignerRpcService::new(
        signer_engine.clone(),
        signer_ceremony.clone(),
        Arc::new(
            SignerClock::new(
                signer_engine.clone(),
                test_time_source(),
                signer_identity.boot_epoch.clone(),
            )
            .unwrap(),
        ),
        signer_identity.boot_epoch.clone(),
        digest("e2"),
        "test",
    ));
    let signer_server = tokio::spawn({
        let signer_identity = signer_identity.clone();
        let signer_rpc = signer_rpc.clone();
        let signer_journals = TestSignerJournalExchange(signer_engine.clone());
        async move {
            let quota = EndpointQuota::new(16, 1_000, 60_000, 1_000, 60_000).unwrap();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                bloom_triad_local_transport::dispatch_connection_with_journal_heads::<
                    BrokerSignerRequest,
                    BrokerSignerResponse,
                    bloom_signer_api::ProtocolError,
                    _,
                    _,
                >(
                    &mut stream,
                    &signer_identity,
                    &broker_acl,
                    bloom_signer_api::SIGNER_API_CURRENT,
                    bloom_signer_api::SIGNER_API_RANGE,
                    &quota,
                    &signer_journals,
                    |request| BrokerSignerService::dispatch(signer_rpc.as_ref(), request),
                )
                .await
                .unwrap();
            }
        }
    });
    let signer_client = BrokerSignerClient::connect_unix(
        &socket_path,
        broker_identity.clone(),
        signer_acl.clone(),
        journal.clone(),
        Arc::new(AcceptingCheckpointSink),
    )
    .unwrap();
    let authority = Arc::new(
        BrokerAuthority::open(
            &broker_authority_path,
            journal.clone(),
            BTreeMap::new(),
            Token::new("installer-key").unwrap(),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            AssuranceRegistry::compiled(Vec::new()).unwrap(),
        )
        .unwrap(),
    );
    let ceremony = CeremonyBroker::open_with_manifest_signer(
        directory.path().join("ceremony.sqlite"),
        Arc::new(signer_client.clone()),
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        journal.clone(),
    )
    .unwrap();
    let broker = BrokerRpcService::new(
        authority.clone(),
        journal.clone(),
        Arc::new(
            BrokerClock::new(
                journal.clone(),
                test_time_source(),
                broker_identity.boot_epoch.clone(),
            )
            .unwrap(),
        ),
        ceremony,
        signer_client.clone(),
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        broker_identity.boot_epoch.clone(),
        digest("e3"),
        "test",
    )
    .unwrap();
    let adoption_observer = Arc::new(FailOnceAdoptionObserver {
        authority: authority.clone(),
        custody_attempts: AtomicUsize::new(0),
    });
    broker
        .ceremony()
        .set_completion_observer(adoption_observer.clone(), now_ms)
        .unwrap();

    let registration_operation = operation("e1");
    let registration = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::WalletRegistrationPrepare(bloom_broker_api::CustodyPrepareRequest {
            ceremony_kind: bloom_broker_api::CeremonyKind::WalletRegistration,
            custody_operation_id: registration_operation.clone(),
            wallet_id: Some(Token::new("quiet-lilac").unwrap()),
            key_ref: None,
            exact_terms_digest: digest("a1"),
            expected_input_class: Token::new("passkey-prf").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
            wallet_seed_profile: None,
            derivation_request: None,
            account_terms: None,
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::WalletRegistrationPrepare(prepared) => prepared,
        response => panic!("unexpected response: {response:?}"),
    };
    let registration_token = url_token(&registration.ceremony_url);
    let registration_status = broker
        .ceremony()
        .public_status(&registration_operation)
        .unwrap();
    assert_eq!(
        registration_status.ceremony_url.as_deref(),
        Some(registration.ceremony_url.as_str())
    );
    let registration_id = registration_status.ceremony_id.to_string();
    let registration_app = broker.ceremony().router();
    let session_response = registration_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &registration_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session: serde_json::Value = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let first_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let second_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][1]["binding"].clone()).unwrap();
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let attestation = authenticator.attestation(&first_challenge.canonical_bytes().unwrap());
    let assertion = authenticator.assertion(&second_challenge.canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: registration_operation,
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("passkey-prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_input = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let registration_request = || {
        Request::builder()
            .method("POST")
            .uri(format!("/api/session/{registration_id}/complete"))
            .header(header::HOST, "localhost:18734")
            .header(header::ORIGIN, "http://localhost:18734")
            .header("x-bloom-ceremony-token", &registration_token)
            .header(header::CONTENT_TYPE, "application/json")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "proof": {
                        "kind": "registration",
                        "attestation": attestation,
                        "prf_assertion": assertion
                    },
                    "encrypted_input": encrypted_input,
                    "public_binding_digest": digest("a1")
                }))
                .unwrap(),
            ))
            .unwrap()
    };
    let first_registration_response = registration_app
        .clone()
        .oneshot(registration_request())
        .await
        .unwrap();
    assert_eq!(
        first_registration_response.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        broker.ceremony().status(&operation("e1")),
        Some(CeremonyState::WalletCommitted)
    );
    assert_eq!(adoption_observer.custody_attempts.load(Ordering::SeqCst), 1);

    let restarted_ceremony = CeremonyBroker::open(
        directory.path().join("ceremony.sqlite"),
        Arc::new(signer_client.clone()),
        journal.clone(),
    )
    .unwrap();
    restarted_ceremony
        .set_completion_observer(adoption_observer.clone(), now_ms)
        .unwrap();
    assert_eq!(
        restarted_ceremony.status(&operation("e1")),
        Some(CeremonyState::Completed)
    );
    assert!(
        restarted_ceremony
            .public_status(&operation("e1"))
            .unwrap()
            .ceremony_url
            .is_none()
    );
    assert_eq!(adoption_observer.custody_attempts.load(Ordering::SeqCst), 2);

    let registration_response = registration_app
        .oneshot(registration_request())
        .await
        .unwrap();
    assert_eq!(registration_response.status(), StatusCode::OK);
    assert_eq!(adoption_observer.custody_attempts.load(Ordering::SeqCst), 3);
    let registration_result: CustodyResult = serde_json::from_slice(
        &registration_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let machine_registration_result = custody_result_to_machine(&registration_result);
    let wallet_id = machine_registration_result.wallet_id.clone().unwrap();
    let baseline = machine_registration_result.initial_policy.clone().unwrap();
    assert_eq!(authority.policy_snapshot(&wallet_id).unwrap(), baseline);

    let baseline_policy: CanonicalWalletPolicy =
        serde_json::from_slice(&baseline.canonical_policy.decode()).unwrap();
    let petal_package = digest("d1");
    let petal_route = "/petals/fixture/sign";
    let mut proposed_policy = baseline_policy.clone();
    proposed_policy.maximum_approval_lifetime_ms += 1;
    proposed_policy
        .allowed_petal_packages
        .push(petal_package.clone());
    proposed_policy
        .allowed_destinations
        .push(PolicyDestination {
            chain: Token::new("ethereum").unwrap(),
            destination: "0xexpanded-authority".into(),
        });
    let proposed_bytes = serde_jcs::to_vec(&proposed_policy).unwrap();
    let authority_diff = canonical_policy_authority_diff(&baseline_policy, &proposed_policy);
    let update = PolicyUpdateRequest {
        operation_id: operation("e4"),
        wallet_id: wallet_id.clone(),
        baseline_version: baseline.version.clone(),
        baseline_digest: baseline.policy_digest.clone(),
        proposed_canonical_policy: Base64UrlBytes::from_bytes(&proposed_bytes),
        proposed_policy_digest: Digest32::from_bytes(sha2::Sha256::digest(&proposed_bytes).into()),
        authority_diff_digest: authority_diff.digest().unwrap(),
        assurance_level: Token::new("user_verified").unwrap(),
    };
    let prepared = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::PolicyValidateUpdate(update.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::PolicyValidateUpdate(prepared) => prepared,
        response => panic!("unexpected response: {response:?}"),
    };
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let retried = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::PolicyValidateUpdate(update.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::PolicyValidateUpdate(prepared) => prepared,
        response => panic!("unexpected response: {response:?}"),
    };
    assert_eq!(
        retried, prepared,
        "exact retries must recover the durable prepare response"
    );

    let mut conflicting_update = update.clone();
    conflicting_update.proposed_policy_digest = digest("ef");
    assert_eq!(
        MachineBrokerService::dispatch(
            &broker,
            MachineBrokerRequest::PolicyValidateUpdate(conflicting_update),
        )
        .await
        .unwrap_err()
        .code,
        ProtocolErrorCode::OperationIdConflict
    );
    let premature = CustodyResult {
        ceremony_kind: CeremonyKind::PolicyUpdate,
        custody_operation_id: update.operation_id.clone(),
        public_status: bloom_signer_api::CeremonyState::Succeeded,
        wallet_id: Some(wallet_id.clone()),
        public_key_refs: Vec::new(),
        credential_summaries: Vec::new(),
        initial_policy: None,
        receipt_digest: digest("e5"),
        encrypted_browser_result: None,
        signer_key_id: Token::new("signer-ceremony-key").unwrap(),
        signer_signature: Base64UrlBytes::from_bytes(&[0; 64]),
    };
    assert!(
        MachineBrokerService::dispatch(
            &broker,
            MachineBrokerRequest::PolicyCommitUpdate(PolicyCommitUpdateRequest {
                operation_id: update.operation_id.clone(),
                ceremony_receipt: custody_result_to_machine(&premature),
            }),
        )
        .await
        .is_err()
    );

    let token = url_token(&prepared.ceremony_url);
    let session_response = broker
        .ceremony()
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session: serde_json::Value = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(
        session["review_manifest"]["authority_diff"],
        serde_json::to_value(&authority_diff).unwrap()
    );
    let challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let assertion = authenticator.assertion(&challenge.canonical_bytes().unwrap(), 2);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::PolicyUpdate,
        custody_operation_id: update.operation_id.clone(),
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: Some(wallet_id.clone()),
        key_ref: None,
        credential_id: Some(assertion.credential_id.clone()),
        expected_input_class: Token::new("policy_update_credential_prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let plaintext = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "effect": {"kind": "policy_update"},
    }))
    .unwrap();
    let encrypted_input = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &plaintext,
    )
    .unwrap();
    let completed = signer_ceremony
        .complete_policy_update(
            PolicyUpdateCeremonyCompleteRequest {
                custody: CustodyCompleteRequest {
                    ceremony_kind: CeremonyKind::PolicyUpdate,
                    custody_operation_id: update.operation_id.clone(),
                    ceremony_id: contribution.ceremony_id,
                    proof: WebAuthnCeremonyProof::Assertion { assertion },
                    encrypted_input: Some(encrypted_input),
                    public_binding_digest: update.terms_digest().unwrap(),
                },
            },
            now_ms + 1_000,
        )
        .unwrap();
    broker
        .ceremony()
        .expire_sessions(contribution.expires_at_ms.get() + 1)
        .unwrap();
    let commit_request = PolicyCommitUpdateRequest {
        operation_id: update.operation_id,
        ceremony_receipt: custody_result_to_machine(&completed),
    };
    let expected_policy_ceremony_receipt_digest =
        commit_request.ceremony_receipt.receipt_digest.clone();
    let committed = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::PolicyCommitUpdate(commit_request.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::PolicyCommitUpdate(receipt) => receipt,
        response => panic!("unexpected response: {response:?}"),
    };
    let replay = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::PolicyCommitUpdate(commit_request),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::PolicyCommitUpdate(receipt) => receipt,
        response => panic!("unexpected response: {response:?}"),
    };
    assert_eq!(replay, committed);
    assert_eq!(committed.committed.version.get(), 2);
    assert_eq!(
        authority.policy_snapshot(&wallet_id).unwrap(),
        committed.committed
    );

    // Exercise the complete generic Petal sub-key path over the production
    // Broker and Signer services. No venue-specific derivation or signing
    // branch participates in this flow.
    let installer_key = SigningKey::from_bytes(&[5; 32]);
    let mut petal_provenance = ProvenanceRecord {
        subject: ProvenanceSubject::Petal {
            package_hash: petal_package.clone(),
            route: petal_route.into(),
        },
        publisher: Token::new("fixture-publisher").unwrap(),
        petal_lineage: Some(PetalLineageMembership {
            lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            release_sequence: DecimalU64::new(1),
            predecessor_package_hashes: vec![],
            controller_key_id: Token::new("controller-key").unwrap(),
            controller_signature: Base64UrlBytes::from_bytes(&[1]),
            active: true,
        }),
        operation_classes: vec![ProvenanceOperationClass {
            operation_class: Token::new("exchange-order").unwrap(),
            fee_asset: None,
        }],
        installer_key_id: Token::new("installer-key").unwrap(),
        installer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    sign_provenance(&mut petal_provenance, &installer_key);
    authority.install_provenance(&petal_provenance).unwrap();

    let parent_key = machine_registration_result.public_key_refs[0].clone();
    let derive_operation = operation("d2");
    let scope_lifetime_ms = 60_000;
    let approval_lifetime_ms = 30_000;
    let scope = PetalKeyScope {
        wallet_id: wallet_id.clone(),
        parent_key_ref: parent_key.clone(),
        package_hash: petal_package.clone(),
        route: petal_route.into(),
        lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        key_slot: Token::new("fixture-instance").unwrap(),
        allowed_routes: vec![petal_route.into()],
        allowed_operation_classes: vec![Token::new("exchange-order").unwrap()],
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
        maximum_lifetime_ms: DecimalU64::new(scope_lifetime_ms),
        custody_operation_id: derive_operation.clone(),
    };
    let derive_prepared = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::KeyDerivePrepare(bloom_broker_api::CustodyPrepareRequest {
            ceremony_kind: bloom_broker_api::CeremonyKind::KeyDerive,
            custody_operation_id: derive_operation.clone(),
            wallet_id: Some(wallet_id.clone()),
            key_ref: Some(parent_key.clone()),
            exact_terms_digest: scope.request_digest().unwrap(),
            expected_input_class: Token::new("petal-key-scope-v1").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: Some(scope.clone()),
            legacy_passkey_migration: None,
            wallet_seed_profile: None,
            derivation_request: None,
            account_terms: None,
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::KeyDerivePrepare(prepared) => prepared,
        response => panic!("unexpected response: {response:?}"),
    };
    let derive_token = url_token(&derive_prepared.ceremony_url);
    let derive_status = broker.ceremony().public_status(&derive_operation).unwrap();
    let derive_id = derive_status.ceremony_id.to_string();
    let derive_app = broker.ceremony().router();
    let derive_session_response = derive_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &derive_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let derive_session: serde_json::Value = serde_json::from_slice(
        &derive_session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    // The scope is still carried verbatim, but it is no longer the whole
    // manifest: a key derivation now also renders a title, a sentence naming
    // the consequence, and a `canonical_plan` the page shows as prose, so the
    // owner is not authorizing against a bare object.
    assert_eq!(
        derive_session["review_manifest"]["petal_key_scope"],
        serde_json::to_value(&scope).unwrap()
    );
    assert_eq!(
        derive_session["review_manifest"]["ceremony_kind"],
        "key_derive"
    );
    assert_eq!(
        derive_session["review_manifest"]["title"],
        "Create a temporary Petal key"
    );
    assert!(
        derive_session["review_manifest"]["canonical_plan"]
            .as_str()
            .is_some_and(|plan| plan.contains("Petal scope")),
        "the plan must name what the derived key is bound to"
    );
    let derive_challenge: CeremonyChallenge =
        serde_json::from_value(derive_session["challenges"][0]["binding"].clone()).unwrap();
    let derive_contribution: CustodySignerContribution =
        serde_json::from_value(derive_session["signer_contribution"].clone()).unwrap();
    let derive_assertion = authenticator.assertion(&derive_challenge.canonical_bytes().unwrap(), 3);
    let derive_aad = CustodyHpkeAad {
        ceremony_id: derive_contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::KeyDerive,
        custody_operation_id: derive_operation.clone(),
        signer_nonce: derive_contribution.signer_nonce.clone(),
        signer_contribution_digest: derive_contribution.digest().unwrap(),
        wallet_id: Some(wallet_id.clone()),
        key_ref: Some(key_to_signer(&parent_key)),
        credential_id: Some(derive_assertion.credential_id.clone()),
        expected_input_class: Token::new("petal-key-scope-v1").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let derive_plaintext = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "effect": {"kind": "key_derive"}
    }))
    .unwrap();
    let derive_encrypted = seal_hpke(
        &derive_contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &derive_aad,
        &derive_plaintext,
    )
    .unwrap();
    let scope_started_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let derive_complete_response = derive_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{derive_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &derive_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "proof": {"kind": "assertion", "assertion": derive_assertion},
                        "encrypted_input": derive_encrypted,
                        "public_binding_digest": scope.request_digest().unwrap()
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(derive_complete_response.status(), StatusCode::OK);
    let derive_result: CustodyResult = serde_json::from_slice(
        &derive_complete_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert!(derive_result.encrypted_browser_result.is_none());
    assert_eq!(derive_result.public_key_refs.len(), 1);
    let child_key = derive_result.public_key_refs[0].clone();
    assert!(child_key.derivation.is_some());
    let projected_result = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::CustodyResult(OperationRequest {
            operation_id: derive_operation.clone(),
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::CustodyResult(result) => result,
        response => panic!("unexpected response: {response:?}"),
    };
    assert_eq!(projected_result, custody_result_to_machine(&derive_result));
    let projected_key = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::KeyGetPublic(bloom_broker_api::KeyRequest {
            key_ref: projected_result.public_key_refs[0].clone(),
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::KeyGetPublic(key) => key,
        response => panic!("unexpected response: {response:?}"),
    };
    assert_eq!(projected_key.key_ref, projected_result.public_key_refs[0]);
    assert!(
        projected_key
            .petal_scope_expires_at_ms
            .is_some_and(|expires_at_ms| {
                expires_at_ms.get() >= scope_started_ms + scope_lifetime_ms
            }),
        "Machine must receive the absolute Petal key expiry recorded by Broker"
    );

    let approval_now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let approval_expires_at_ms = scope_started_ms + approval_lifetime_ms;
    let approval_terms = SealedApprovalTerms {
        subject: ApprovalSubject::Petal {
            package_hash: petal_package.clone(),
            route: petal_route.into(),
            agent_id: Some(scope.key_slot.as_str().into()),
        },
        wallet_id: wallet_id.clone(),
        key_ref: custody_result_to_machine(&derive_result).public_key_refs[0].clone(),
        allowed_crypto_suites: scope.allowed_crypto_suites.clone(),
        selector: ApprovalSelector::Petal {
            package_hash: petal_package.clone(),
            route: petal_route.into(),
            allowed_operation_classes: scope.allowed_operation_classes.clone(),
            route_grants: Vec::new(),
            required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(8),
            max_signatures: DecimalU64::new(8),
            operation_rate_limits: Vec::new(),
            signature_rate_limits: Vec::new(),
            value_limits: Vec::new(),
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(authority.wallet_epoch(&wallet_id).unwrap()),
        policy_version: committed.committed.version.clone(),
        policy_digest: committed.committed.policy_digest.clone(),
        provenance_digest: petal_provenance.digest().unwrap(),
        request_nonce: RequestNonce::from_bytes([0xd3; 16]),
        issued_at_ms: DecimalU64::new(approval_now_ms),
        not_before_ms: DecimalU64::new(approval_now_ms),
        expires_at_ms: DecimalU64::new(approval_expires_at_ms),
        renewal_of: None,
    };
    let approval_operation = operation("d3");
    let approval_prepared = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::SealedApprovalPrepare(ApprovalPrepareRequest {
            operation_id: approval_operation.clone(),
            terms: approval_terms.clone(),
            canonical_plan_facts_digest: digest("d4"),
            petal_use_claim: None,
            system_use_claim: None,
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::SealedApprovalPrepare(prepared) => prepared,
        response => panic!("unexpected response: {response:?}"),
    };
    let approval_token = url_token(&approval_prepared.ceremony_url);
    let approval_status = broker
        .ceremony()
        .public_status(&approval_operation)
        .unwrap();
    let approval_id = approval_status.ceremony_id.to_string();
    let approval_app = broker.ceremony().router();
    let approval_session_response = approval_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &approval_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let approval_session: serde_json::Value = serde_json::from_slice(
        &approval_session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let approval_challenge: CeremonyChallenge =
        serde_json::from_value(approval_session["challenges"][0]["binding"].clone()).unwrap();
    let approval_contribution: SignerCeremonyContribution =
        serde_json::from_value(approval_session["signer_contribution"].clone()).unwrap();
    let approval_assertion =
        authenticator.assertion(&approval_challenge.canonical_bytes().unwrap(), 4);
    let approval_aad = LocalPrfHpkeAad {
        ceremony_id: approval_contribution.ceremony_id.clone(),
        signer_nonce: approval_contribution.signer_nonce.clone(),
        approval_id: approval_terms.approval_id().unwrap(),
        approval_digest: approval_terms.approval_digest().unwrap(),
        review_manifest_digest: approval_prepared.review_manifest_digest.clone(),
        key_ref: child_key.clone(),
        allowed_crypto_suites: approval_terms
            .allowed_crypto_suites
            .iter()
            .cloned()
            .map(crypto_suite_to_signer)
            .collect(),
        credential_id: approval_assertion.credential_id.clone(),
        activation_mode: activation_mode_to_signer(approval_terms.activation_mode.clone()),
        wallet_revocation_epoch: approval_terms.wallet_revocation_epoch.clone(),
    }
    .canonical_bytes()
    .unwrap();
    let approval_encrypted = seal_hpke(
        approval_contribution
            .ephemeral_encryption_public_key
            .as_ref()
            .unwrap(),
        b"bloom-local-prf/v1",
        &approval_aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let approval_complete_response = approval_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{approval_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &approval_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "proof": {"kind": "assertion", "assertion": approval_assertion},
                        "encrypted_input": approval_encrypted,
                        "public_binding_digest": approval_terms.approval_digest().unwrap()
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(approval_complete_response.status(), StatusCode::OK);
    let approval_receipt: SignerActivationReceipt = serde_json::from_slice(
        &approval_complete_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(
        approval_receipt.approval_id,
        approval_terms.approval_id().unwrap()
    );

    // An exact one-shot selector may use the same scoped child under its
    // pinned Petal subject. Exact requests intentionally carry no reusable
    // PetalUseClaim or assurance evidence.
    let exact_payload = b"fixture-exact-petal-action";
    let exact_payload_digest = Digest32::from_bytes(sha2::Sha256::digest(exact_payload).into());
    let mut exact_terms = approval_terms.clone();
    exact_terms.expires_at_ms = DecimalU64::new(scope_started_ms + scope_lifetime_ms);
    exact_terms.selector = ApprovalSelector::Exact {
        ordered_payload_digests: vec![exact_payload_digest.clone()],
        ordered_hashes: vec![exact_payload_digest],
    };
    exact_terms.limits.max_operations = DecimalU64::new(1);
    exact_terms.limits.max_signatures = DecimalU64::new(1);
    exact_terms.request_nonce = RequestNonce::from_bytes([0xe0; 16]);
    let exact_approval_operation = operation("e0");
    let exact_prepared = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::SealedApprovalPrepare(ApprovalPrepareRequest {
            operation_id: exact_approval_operation.clone(),
            terms: exact_terms.clone(),
            canonical_plan_facts_digest: digest("e7"),
            petal_use_claim: None,
            system_use_claim: None,
        }),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::SealedApprovalPrepare(prepared) => prepared,
        response => panic!("unexpected response: {response:?}"),
    };
    let exact_token = url_token(&exact_prepared.ceremony_url);
    let exact_status = broker
        .ceremony()
        .public_status(&exact_approval_operation)
        .unwrap();
    let exact_ceremony_id = exact_status.ceremony_id.to_string();
    let exact_app = broker.ceremony().router();
    let exact_session_response = exact_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &exact_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let exact_session: serde_json::Value = serde_json::from_slice(
        &exact_session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let exact_challenge: CeremonyChallenge =
        serde_json::from_value(exact_session["challenges"][0]["binding"].clone()).unwrap();
    let exact_contribution: SignerCeremonyContribution =
        serde_json::from_value(exact_session["signer_contribution"].clone()).unwrap();
    let exact_assertion = authenticator.assertion(&exact_challenge.canonical_bytes().unwrap(), 5);
    let exact_aad = LocalPrfHpkeAad {
        ceremony_id: exact_contribution.ceremony_id.clone(),
        signer_nonce: exact_contribution.signer_nonce.clone(),
        approval_id: exact_terms.approval_id().unwrap(),
        approval_digest: exact_terms.approval_digest().unwrap(),
        review_manifest_digest: exact_prepared.review_manifest_digest.clone(),
        key_ref: child_key.clone(),
        allowed_crypto_suites: exact_terms
            .allowed_crypto_suites
            .iter()
            .cloned()
            .map(crypto_suite_to_signer)
            .collect(),
        credential_id: exact_assertion.credential_id.clone(),
        activation_mode: activation_mode_to_signer(exact_terms.activation_mode.clone()),
        wallet_revocation_epoch: exact_terms.wallet_revocation_epoch.clone(),
    }
    .canonical_bytes()
    .unwrap();
    let exact_encrypted = seal_hpke(
        exact_contribution
            .ephemeral_encryption_public_key
            .as_ref()
            .unwrap(),
        b"bloom-local-prf/v1",
        &exact_aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let exact_complete_response = exact_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{exact_ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &exact_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "proof": {"kind": "assertion", "assertion": exact_assertion},
                        "encrypted_input": exact_encrypted,
                        "public_binding_digest": exact_terms.approval_digest().unwrap()
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let exact_complete_status = exact_complete_response.status();
    let exact_complete_body = exact_complete_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        exact_complete_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&exact_complete_body)
    );
    let exact_receipt: SignerActivationReceipt =
        serde_json::from_slice(&exact_complete_body).unwrap();
    assert_eq!(
        exact_receipt.approval_id,
        exact_terms.approval_id().unwrap()
    );

    let exact_sign = exact_petal_sign_request(
        &exact_terms,
        operation("e8"),
        petal_package.clone(),
        petal_route,
        exact_payload,
    );
    assert!(exact_sign.petal_use_claim.is_none());
    assert!(exact_sign.claim_assurance_evidence.is_none());
    let exact_result = MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::SigningSign(exact_sign.clone()),
    )
    .await
    .unwrap();
    assert!(matches!(
        exact_result,
        MachineBrokerResponse::SigningSign(_)
    ));
    assert!(
        MachineBrokerService::dispatch(
            &broker,
            MachineBrokerRequest::SigningSign(exact_sign.clone()),
        )
        .await
        .is_err()
    );
    let changed_exact = exact_petal_sign_request(
        &exact_terms,
        exact_sign.operation_id,
        petal_package.clone(),
        petal_route,
        b"changed-exact-payload",
    );
    assert!(
        MachineBrokerService::dispatch(&broker, MachineBrokerRequest::SigningSign(changed_exact),)
            .await
            .is_err()
    );

    for (index, mut denied_terms) in [
        {
            let mut terms = approval_terms.clone();
            terms.subject = ApprovalSubject::Petal {
                package_hash: digest("c1"),
                route: petal_route.into(),
                agent_id: Some(scope.key_slot.as_str().into()),
            };
            if let ApprovalSelector::Petal { package_hash, .. } = &mut terms.selector {
                *package_hash = digest("c1");
            }
            terms
        },
        {
            let mut terms = approval_terms.clone();
            let route = "/petals/other/sign";
            terms.subject = ApprovalSubject::Petal {
                package_hash: petal_package.clone(),
                route: route.into(),
                agent_id: Some(scope.key_slot.as_str().into()),
            };
            if let ApprovalSelector::Petal {
                route: selector_route,
                ..
            } = &mut terms.selector
            {
                *selector_route = route.into();
            }
            terms
        },
        {
            let mut terms = approval_terms.clone();
            terms.wallet_id = Token::new("another-wallet").unwrap();
            terms
        },
        {
            let mut terms = approval_terms.clone();
            terms.subject = ApprovalSubject::System {
                component_id: Token::new("machine").unwrap(),
                operation_class: Token::new("sign").unwrap(),
            };
            terms.selector = ApprovalSelector::Exact {
                ordered_payload_digests: vec![digest("c2")],
                ordered_hashes: vec![digest("c3")],
            };
            terms.limits.max_operations = DecimalU64::new(1);
            terms.limits.max_signatures = DecimalU64::new(1);
            terms
        },
        {
            let mut terms = approval_terms.clone();
            terms.subject = ApprovalSubject::Cli {
                client_id: Token::new("bloom-cli").unwrap(),
                command_class: Token::new("wallet-sign").unwrap(),
            };
            terms.selector = ApprovalSelector::Exact {
                ordered_payload_digests: vec![digest("c4")],
                ordered_hashes: vec![digest("c5")],
            };
            terms.limits.max_operations = DecimalU64::new(1);
            terms.limits.max_signatures = DecimalU64::new(1);
            terms
        },
    ]
    .into_iter()
    .enumerate()
    {
        denied_terms.request_nonce = RequestNonce::from_bytes([0xc0 + index as u8; 16]);
        assert!(
            MachineBrokerService::dispatch(
                &broker,
                MachineBrokerRequest::SealedApprovalPrepare(ApprovalPrepareRequest {
                    operation_id: operation(&format!("{:02x}", 0xc0 + index)),
                    terms: denied_terms,
                    canonical_plan_facts_digest: digest("c9"),
                    petal_use_claim: None,
                    system_use_claim: None,
                }),
            )
            .await
            .is_err()
        );
    }

    let first_sign = petal_sign_request(
        &approval_terms,
        operation("d5"),
        petal_package.clone(),
        petal_route,
        b"fixture-petal-action-1",
    );
    let first_result = match MachineBrokerService::dispatch(
        &broker,
        MachineBrokerRequest::SigningSign(first_sign.clone()),
    )
    .await
    .unwrap()
    {
        MachineBrokerResponse::SigningSign(result) => result,
        response => panic!("unexpected response: {response:?}"),
    };
    assert_eq!(first_result.signatures.len(), 1);
    assert_eq!(first_result.signatures[0].bytes.decode().len(), 65);
    let validation_receipt = journal
        .validation_receipt(&first_sign.operation_id)
        .unwrap()
        .expect("production sign flow must retain its signed validation receipt");
    assert_eq!(validation_receipt.approval_id, first_sign.approval_id);
    assert_eq!(
        validation_receipt.operation_digest,
        first_result.operation_digest
    );
    assert!(!validation_receipt.reservation_ids.is_empty());
    assert_eq!(validation_receipt.broker_key_id.as_str(), "broker-app-1");
    let validation_signature: [u8; 64] = validation_receipt
        .broker_signature
        .decode()
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .verify(
            &validation_receipt.signature_message().unwrap(),
            &ed25519_dalek::Signature::from_bytes(&validation_signature),
        )
        .unwrap();

    // A consumed operation cannot issue another signature; a changed replay,
    // cross-Petal provenance, and first-party provenance fail closed too.
    assert!(
        MachineBrokerService::dispatch(
            &broker,
            MachineBrokerRequest::SigningSign(first_sign.clone()),
        )
        .await
        .is_err()
    );
    let mut changed_replay = petal_sign_request(
        &approval_terms,
        operation("d5"),
        petal_package.clone(),
        petal_route,
        b"changed-replay",
    );
    assert_eq!(
        MachineBrokerService::dispatch(
            &broker,
            MachineBrokerRequest::SigningSign(changed_replay.clone()),
        )
        .await
        .unwrap_err()
        .code,
        ProtocolErrorCode::OperationIdConflict
    );
    changed_replay.operation_id = operation("d6");
    changed_replay.operation_digest = petal_sign_request(
        &approval_terms,
        operation("d6"),
        digest("d7"),
        petal_route,
        b"changed-replay",
    )
    .operation_digest;
    changed_replay.provenance = ProvenanceSubject::Petal {
        package_hash: digest("d7"),
        route: petal_route.into(),
    };
    if let Some(claim) = &mut changed_replay.petal_use_claim {
        claim.package_hash = digest("d7");
    }
    assert!(
        MachineBrokerService::dispatch(&broker, MachineBrokerRequest::SigningSign(changed_replay),)
            .await
            .is_err()
    );
    let cross_route = petal_sign_request(
        &approval_terms,
        operation("d7"),
        petal_package.clone(),
        "/petals/other/sign",
        b"cross-route",
    );
    assert!(
        MachineBrokerService::dispatch(&broker, MachineBrokerRequest::SigningSign(cross_route),)
            .await
            .is_err()
    );
    for provenance in [
        ProvenanceSubject::System {
            component_id: Token::new("machine").unwrap(),
            operation_class: Token::new("sign").unwrap(),
        },
        ProvenanceSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet-sign").unwrap(),
        },
    ] {
        let mut denied = petal_sign_request(
            &approval_terms,
            operation("d8"),
            petal_package.clone(),
            petal_route,
            b"first-party-reuse",
        );
        denied.provenance = provenance;
        assert!(
            MachineBrokerService::dispatch(&broker, MachineBrokerRequest::SigningSign(denied))
                .await
                .is_err()
        );
    }

    // Reopen Signer from its durable database and use a fresh authenticated
    // transport and Broker service. The restored process retains the public
    // child and immutable scope, but correctly starts with private signing
    // inactive until an unlock ceremony; Machine owns neither state.
    let restarted_signer_engine = Arc::new(
        SignerEngine::open(
            &signer_database,
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            signer_audit_keys(),
            Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
        )
        .unwrap(),
    );
    let restarted_signer_ceremony = Arc::new(
        SignerCeremonyService::new(
            restarted_signer_engine.clone(),
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    let restarted_signer_rpc = Arc::new(SignerRpcService::new(
        restarted_signer_engine.clone(),
        restarted_signer_ceremony,
        Arc::new(
            SignerClock::new(
                restarted_signer_engine.clone(),
                test_time_source(),
                signer_identity.boot_epoch.clone(),
            )
            .unwrap(),
        ),
        signer_identity.boot_epoch.clone(),
        digest("e2"),
        "test-restarted",
    ));
    let restarted_signer_socket = directory.path().join("signer-restarted.sock");
    let restarted_signer_listener =
        tokio::net::UnixListener::bind(&restarted_signer_socket).unwrap();
    let restarted_broker_acl = peer_acl(&broker_identity, effective_uid);
    let restarted_signer_server = tokio::spawn({
        let signer_identity = signer_identity.clone();
        let signer_rpc = restarted_signer_rpc;
        let signer_journals = TestSignerJournalExchange(restarted_signer_engine.clone());
        async move {
            let quota = EndpointQuota::new(16, 1_000, 60_000, 1_000, 60_000).unwrap();
            loop {
                let (mut stream, _) = restarted_signer_listener.accept().await.unwrap();
                bloom_triad_local_transport::dispatch_connection_with_journal_heads::<
                    BrokerSignerRequest,
                    BrokerSignerResponse,
                    bloom_signer_api::ProtocolError,
                    _,
                    _,
                >(
                    &mut stream,
                    &signer_identity,
                    &restarted_broker_acl,
                    bloom_signer_api::SIGNER_API_CURRENT,
                    bloom_signer_api::SIGNER_API_RANGE,
                    &quota,
                    &signer_journals,
                    |request| BrokerSignerService::dispatch(signer_rpc.as_ref(), request),
                )
                .await
                .unwrap();
            }
        }
    });
    let restarted_journal = Arc::new(
        BrokerJournal::open(&broker_journal_path, Arc::new(ServiceTestAuditSigner)).unwrap(),
    );
    let restarted_signer_client = BrokerSignerClient::connect_unix(
        &restarted_signer_socket,
        broker_identity.clone(),
        signer_acl.clone(),
        restarted_journal.clone(),
        Arc::new(AcceptingCheckpointSink),
    )
    .unwrap();
    let policy_key_bytes: [u8; 32] = committed
        .committed
        .policy_verifying_key
        .decode()
        .try_into()
        .unwrap();
    let mut restarted_policy_keys = BTreeMap::new();
    restarted_policy_keys.insert(
        wallet_id.as_str().to_owned(),
        (
            committed.committed.policy_signing_key_id.clone(),
            VerifyingKey::from_bytes(&policy_key_bytes).unwrap(),
        ),
    );
    let restarted_authority = Arc::new(
        BrokerAuthority::open(
            &broker_authority_path,
            restarted_journal.clone(),
            restarted_policy_keys,
            Token::new("installer-key").unwrap(),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            AssuranceRegistry::compiled(Vec::new()).unwrap(),
        )
        .unwrap(),
    );
    let restarted_scoped_broker = BrokerRpcService::new(
        restarted_authority,
        restarted_journal.clone(),
        Arc::new(
            BrokerClock::new(
                restarted_journal.clone(),
                test_time_source(),
                broker_identity.boot_epoch.clone(),
            )
            .unwrap(),
        ),
        CeremonyBroker::open_with_manifest_signer(
            directory.path().join("scoped-restart-ceremony.sqlite"),
            Arc::new(restarted_signer_client.clone()),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]),
            restarted_journal.clone(),
        )
        .unwrap(),
        restarted_signer_client,
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        broker_identity.boot_epoch.clone(),
        digest("e3"),
        "test",
    )
    .unwrap();
    let restored_backup = restarted_signer_engine
        .export_backup(&wallet_id, None, Vec::new())
        .unwrap();
    assert!(restored_backup.petal_key_scopes.iter().any(|stored| {
        stored.key_ref == child_key && stored.scope == petal_scope_to_signer(&scope)
    }));
    let restarted_sign = petal_sign_request(
        &approval_terms,
        operation("d9"),
        petal_package.clone(),
        petal_route,
        b"fixture-petal-action-after-restart",
    );
    assert!(
        MachineBrokerService::dispatch(
            &restarted_scoped_broker,
            MachineBrokerRequest::SigningSign(restarted_sign),
        )
        .await
        .is_err()
    );
    let revoked = MachineBrokerService::dispatch(
        &restarted_scoped_broker,
        MachineBrokerRequest::SealedApprovalRevoke(RevokeRequest {
            operation_id: operation("da"),
            approval_id: approval_terms.approval_id().unwrap(),
            wallet_id: wallet_id.clone(),
            reason: "fixture Petal teardown".into(),
        }),
    )
    .await
    .unwrap();
    assert!(matches!(
        revoked,
        MachineBrokerResponse::SealedApprovalRevoke(_)
    ));
    let after_revoke = petal_sign_request(
        &approval_terms,
        operation("db"),
        petal_package.clone(),
        petal_route,
        b"after-revoke",
    );
    assert!(
        MachineBrokerService::dispatch(
            &restarted_scoped_broker,
            MachineBrokerRequest::SigningSign(after_revoke),
        )
        .await
        .is_err()
    );

    let now_after_scope_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    if now_after_scope_ms <= approval_expires_at_ms {
        tokio::time::sleep(std::time::Duration::from_millis(
            approval_expires_at_ms - now_after_scope_ms + 25,
        ))
        .await;
    }
    let mut expired_terms = approval_terms.clone();
    expired_terms.request_nonce = RequestNonce::from_bytes([0xdc; 16]);
    assert!(
        MachineBrokerService::dispatch(
            &restarted_scoped_broker,
            MachineBrokerRequest::SealedApprovalPrepare(ApprovalPrepareRequest {
                operation_id: operation("dc"),
                terms: expired_terms,
                canonical_plan_facts_digest: digest("dd"),
                petal_use_claim: None,
                system_use_claim: None,
            }),
        )
        .await
        .is_err()
    );

    // Stop Broker before panic-revoking through Signer's independently
    // authenticated control socket. Recreate Broker afterwards and prove its
    // first reconciliation adopts the higher Signer epoch.
    drop(broker);
    drop(restarted_ceremony);
    let control_socket_path = directory.path().join("signer-control.sock");
    let control_listener = tokio::net::UnixListener::bind(&control_socket_path).unwrap();
    let revoke_identity = local_identity("bloom-revoke-client", [0x33; 32], "33");
    let revoke_acl = peer_acl(&revoke_identity, effective_uid);
    let control_server = tokio::spawn({
        let signer_identity = signer_identity.clone();
        let signer_rpc = signer_rpc.clone();
        async move {
            let (mut stream, _) = control_listener.accept().await.unwrap();
            let quota = EndpointQuota::new(16, 1_000, 60_000, 1_000, 60_000).unwrap();
            bloom_triad_local_transport::dispatch_connection::<
                ControlRequest,
                ControlResponse,
                bloom_signer_api::ProtocolError,
                _,
                _,
            >(
                &mut stream,
                &signer_identity,
                &revoke_acl,
                bloom_signer_api::SIGNER_CONTROL_CURRENT,
                bloom_signer_api::SIGNER_CONTROL_RANGE,
                &quota,
                |request| RevocationControlService::dispatch(signer_rpc.as_ref(), request),
            )
            .await
            .unwrap();
        }
    });
    let mut control_stream = tokio::net::UnixStream::connect(&control_socket_path)
        .await
        .unwrap();
    let signer_only_revoke: ControlResponse = bloom_triad_local_transport::call::<
        ControlRequest,
        ControlResponse,
        bloom_signer_api::ProtocolError,
    >(
        &mut control_stream,
        &revoke_identity,
        &signer_acl,
        bloom_signer_api::SIGNER_CONTROL_CURRENT,
        bloom_signer_api::SIGNER_CONTROL_RANGE,
        ControlRequest::RevokeAll(WalletOperationRequest {
            operation_id: operation("e6"),
            wallet_id: wallet_id.clone(),
        }),
        5_000,
    )
    .await
    .unwrap();
    control_server.await.unwrap();
    let ControlResponse::RevokeAll(signer_only_state) = signer_only_revoke else {
        panic!("unexpected Signer control response");
    };
    assert_eq!(signer_only_state.wallet_revocation_epoch.get(), 1);
    assert_eq!(authority.wallet_epoch(&wallet_id).unwrap(), 0);

    let restarted_broker = BrokerRpcService::new(
        authority.clone(),
        journal.clone(),
        Arc::new(
            BrokerClock::new(
                journal.clone(),
                test_time_source(),
                broker_identity.boot_epoch.clone(),
            )
            .unwrap(),
        ),
        CeremonyBroker::open(
            directory.path().join("restarted-ceremony.sqlite"),
            Arc::new(signer_client.clone()),
            journal.clone(),
        )
        .unwrap(),
        signer_client,
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        broker_identity.boot_epoch,
        digest("e3"),
        "test",
    )
    .unwrap();
    restarted_broker.reconcile_all().await.unwrap();
    assert_eq!(authority.wallet_epoch(&wallet_id).unwrap(), 1);
    assert_eq!(
        signer_engine
            .revocation_state(&wallet_id, now_ms + 2_000)
            .unwrap()
            .wallet_revocation_epoch
            .get(),
        1
    );

    authority.advance_local_epoch(&wallet_id, 1, 2).unwrap();
    restarted_broker.reconcile_all().await.unwrap();
    assert_eq!(authority.wallet_epoch(&wallet_id).unwrap(), 2);
    assert_eq!(
        signer_engine
            .revocation_state(&wallet_id, now_ms + 3_000)
            .unwrap()
            .wallet_revocation_epoch
            .get(),
        2
    );

    let policy_install = journal
        .audit_entries()
        .unwrap()
        .into_iter()
        .rev()
        .find(|entry| {
            entry.event_type == "policy.installed"
                && serde_json::from_str::<serde_json::Value>(&entry.payload_jcs)
                    .is_ok_and(|payload| payload["version"] == serde_json::json!("2"))
        })
        .expect("policy commit must have a correlated install audit record");
    let policy_install: serde_json::Value =
        serde_json::from_str(&policy_install.payload_jcs).unwrap();
    assert_eq!(
        policy_install["operation_id"],
        serde_json::json!(operation("e4"))
    );
    assert_eq!(
        policy_install["ceremony_receipt_digest"],
        serde_json::json!(expected_policy_ceremony_receipt_digest)
    );
    assert!(!policy_install["validation_receipt_digest"].is_null());
    assert!(!policy_install["commit_receipt_digest"].is_null());

    journal.latch_audit_degradation();
    let read_policy = MachineBrokerService::dispatch(
        &restarted_broker,
        MachineBrokerRequest::PolicyRead(WalletRequest {
            wallet_id: wallet_id.clone(),
        }),
    )
    .await
    .unwrap();
    assert!(matches!(read_policy, MachineBrokerResponse::PolicyRead(_)));
    let read_wallet = MachineBrokerService::dispatch(
        &restarted_broker,
        MachineBrokerRequest::WalletGetPublic(WalletRequest { wallet_id }),
    )
    .await
    .unwrap();
    let MachineBrokerResponse::WalletGetPublic(read_wallet) = read_wallet else {
        panic!("wrong wallet projection response");
    };
    assert!(
        read_wallet.root_key_ref.is_none(),
        "a BIP-39 seed is not a signable root key"
    );
    assert!(
        !read_wallet.key_refs.is_empty()
            && read_wallet
                .key_refs
                .iter()
                .all(|key_ref| key_ref.derivation.is_some()),
        "BIP-39 wallet projection must contain only derived account keys"
    );
    restarted_signer_server.abort();
    signer_server.abort();
}

#[test]
fn stable_url_single_live_wallet_and_cancellation_backoff_hold() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let first = prepare(
        &broker,
        operation("01"),
        Some(Token::new("wallet-1").unwrap()),
        1_000,
    );
    let retry = prepare(
        &broker,
        operation("01"),
        Some(Token::new("wallet-1").unwrap()),
        1_001,
    );
    assert_eq!(first, retry);
    let conflicting = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("01"),
                wallet_id: Some(Token::new("wallet-1").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("99"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            1_001,
        )
        .unwrap_err();
    assert_eq!(conflicting.code, ProtocolErrorCode::OperationIdConflict);
    assert_eq!(
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletDelete,
                    custody_operation_id: operation("02"),
                    wallet_id: Some(Token::new("wallet-1").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("33"),
                    expected_input_class: Token::new("policy-document").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
                },
                1_001,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::QuotaExceeded
    );
    assert_eq!(
        broker.status(&operation("01")),
        Some(CeremonyState::AwaitingUser)
    );
    broker.cancel(&operation("01"), 1_100).unwrap();
    assert_eq!(
        broker.status(&operation("01")),
        Some(CeremonyState::Cancelled)
    );
    assert_eq!(
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletDelete,
                    custody_operation_id: operation("03"),
                    wallet_id: Some(Token::new("wallet-1").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("33"),
                    expected_input_class: Token::new("policy-document").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
                },
                1_101,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyRateLimited
    );
}

#[tokio::test]
async fn legacy_passkey_prepare_renders_only_digest_bound_public_migration_terms() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let operation_id = operation("81");
    let migration = LegacyPasskeyMigrationPublic {
        schema: Token::new("bloom.legacy_passkey_migration_receipt.v1").unwrap(),
        wallet_name: Token::new("wallet").unwrap(),
        address: "0x1111111111111111111111111111111111111111".into(),
        public_key_fingerprint: digest("82"),
        credential_id_fingerprint: digest("83"),
        legacy_format_version: 1,
        bundle_digest: digest("84"),
        policy_mode: Token::new("restrictive_current_policy").unwrap(),
    };
    let exact_terms_digest = migration.terms_digest(&operation_id).unwrap();
    let response = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletImport,
                custody_operation_id: operation_id,
                wallet_id: None,
                key_ref: None,
                exact_terms_digest,
                expected_input_class: Token::new("legacy_passkey_v1_prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: Some(migration),
                wallet_seed_profile: None,
                derivation_request: None,
            },
            now_ms,
        )
        .unwrap();
    let session = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", url_token(&response.ceremony_url))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let projection: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        projection["review_manifest"]["schema"],
        "bloom.legacy_passkey_migration_review.v1"
    );
    assert_eq!(projection["review_manifest"]["wallet_name"], "wallet");
    assert_eq!(
        projection["review_manifest"]["creates_current_wkek_custody"],
        true
    );
    assert!(
        projection["review_manifest"]
            .get("raw_private_key")
            .is_none()
    );
}

#[tokio::test]
async fn broker_constructs_and_signs_the_review_plan_from_immutable_terms() {
    let signer = Arc::new(MockSigner::new());
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let broker = CeremonyBroker::new_with_manifest_signer(
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[31; 32]),
    );
    let response = broker
        .prepare_approval(
            approval_request(),
            ReviewManifestContext {
                attributed_advisory_items: vec![
                    "machine supplied descriptions are advisory".into(),
                ],
                ..ReviewManifestContext::default()
            },
            now_ms,
        )
        .unwrap();
    assert_ne!(response.review_manifest_digest, digest("00"));
    let token = url_token(&response.ceremony_url);
    let session = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let projection: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let manifest = projection["review_manifest"].clone();
    let canonical_plan = manifest["canonical_plan"].as_str().unwrap();
    assert!(canonical_plan.to_lowercase().contains("sha256"));
    assert!(canonical_plan.contains("max_operations"));
    assert!(canonical_plan.contains("root-key"));
    assert!(canonical_plan.contains("Bloom has not established the execution effects"));
    let broker_signature: Base64UrlBytes =
        serde_json::from_value(manifest["broker_signature"].clone()).unwrap();
    assert_eq!(broker_signature.decode().len(), 64);
    assert_eq!(
        Digest32::from_bytes(sha2::Sha256::digest(serde_jcs::to_vec(&manifest).unwrap()).into()),
        response.review_manifest_digest
    );
}

#[tokio::test]
async fn an_approval_whose_only_ceremony_expired_is_reported_unreachable() {
    let signer = Arc::new(MockSigner::new());
    let now_ms: u64 = 1_700_000_000_000;
    let broker = CeremonyBroker::new_with_manifest_signer(
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[33; 32]),
    );
    let response = broker
        .prepare_approval(approval_request(), ReviewManifestContext::default(), now_ms)
        .unwrap();
    let approval_id = response.approval_id.clone();

    assert!(
        broker
            .pending_approval_ceremony(&approval_id, now_ms)
            .unwrap()
            .is_some(),
        "a live ceremony hands the owner a URL to complete"
    );
    assert!(
        !broker.approval_ceremony_unreachable(&approval_id),
        "an approval the owner can still complete is not unreachable"
    );

    assert!(
        broker
            .pending_approval_ceremony(&approval_id, now_ms + 10_001)
            .unwrap()
            .is_none(),
        "an expired ceremony must not hand out a URL"
    );
    assert!(
        broker.approval_ceremony_unreachable(&approval_id),
        "once the ceremony expires the owner has no way to reach this approval, so the caller \
         must be told to start a fresh lineage rather than poll AwaitingCeremony with no URL"
    );
}

#[tokio::test]
async fn cancelling_a_ceremony_that_already_died_succeeds_instead_of_stranding_the_caller() {
    let signer = Arc::new(MockSigner::new());
    let now_ms: u64 = 1_700_000_000_000;
    let broker = CeremonyBroker::new_with_manifest_signer(
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[34; 32]),
    );
    broker
        .prepare_approval(approval_request(), ReviewManifestContext::default(), now_ms)
        .unwrap();
    let operation_id = operation("17");

    broker.expire_sessions(now_ms + 10_001).unwrap();
    assert_eq!(
        broker.status(&operation_id),
        Some(CeremonyState::Expired),
        "the ceremony lapsed without ever reaching the wallet"
    );

    // Regression: this returned OPERATION_ID_CONFLICT. The operation could then
    // be neither completed nor abandoned, and the only way out was editing
    // durable state by hand.
    broker
        .cancel(&operation_id, now_ms + 10_002)
        .expect("cancelling an already-dead ceremony is what the caller asked for");

    assert_eq!(
        broker.status(&operation_id),
        Some(CeremonyState::Expired),
        "cancel is a no-op here and must not relabel how the ceremony actually ended"
    );
}

#[tokio::test]
async fn cancelling_a_failed_session_with_a_committed_sensitive_result_is_rejected() {
    let signer = Arc::new(MockSigner::with_sensitive_result());
    let broker = CeremonyBroker::new(signer);
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let operation_id = operation("18");
    let prepared = prepare(
        &broker,
        operation_id.clone(),
        Some(Token::new("wallet-sensitive-result").unwrap()),
        now_ms,
    );
    let status = broker.public_status(&operation_id).unwrap();
    let ceremony_id = status.ceremony_id.to_string();
    let token = url_token(&prepared.ceremony_url);
    let completed = broker
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "proof": {
                            "kind": "assertion",
                            "assertion": {
                                "credential_id": "Y3JlZGVudGlhbA",
                                "authenticator_data": "YXV0aA",
                                "client_data_json": "e30",
                                "signature": "c2ln",
                                "user_handle": null
                            }
                        },
                        "encrypted_input": null,
                        "public_binding_digest": digest("33")
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let awaiting_ack = broker.public_status(&operation_id).unwrap();
    assert_eq!(awaiting_ack.state, CeremonyState::AwaitingRecoveryAck);

    broker
        .expire_sessions(awaiting_ack.expires_at_ms.get() + 1)
        .unwrap();
    let failed = broker.public_status(&operation_id).unwrap();
    assert_eq!(failed.state, CeremonyState::Failed);
    assert!(
        failed.receipt_digest.is_some(),
        "the committed wallet result must survive acknowledgement expiry"
    );
    let error = broker
        .cancel(&operation_id, awaiting_ack.expires_at_ms.get() + 2)
        .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::OperationIdConflict);
}

#[tokio::test]
async fn review_plan_formats_known_asset_base_units_without_hiding_raw_authority_amount() {
    let signer = Arc::new(MockSigner::new());
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let broker = CeremonyBroker::new_with_manifest_signer(
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[32; 32]),
    );
    let claim = PetalUseClaim {
        package_hash: digest("91"),
        route: "/mainnet/exchange/wallet/usd_send.json".into(),
        operation_class: Token::new("hyperliquid.usd_send").unwrap(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        payload_digest: digest("92"),
        ordered_hashes: vec![digest("93")],
        declared_debits: vec![DeclaredDebit {
            asset: AssetId {
                chain: Token::new("hyperliquid").unwrap(),
                asset: "usdc".into(),
            },
            amount: DecimalU256::parse("10000").unwrap(),
        }],
        declared_destinations: vec![DeclaredDestination {
            chain: Token::new("hyperliquid").unwrap(),
            destination: "0xe2b000d7650543f5df13183c089e02d6d8b2145c".into(),
        }],
        declared_fee: DeclaredFee::None,
        nonce: RequestNonce::from_bytes([94; 16]),
        claim_assurance: ClaimAssurance::MachineAsserted,
    };
    let response = broker
        .prepare_approval(
            approval_request(),
            ReviewManifestContext {
                petal_use_claim: Some(claim),
                claim_assurance: Some(ClaimAssurance::MachineAsserted),
                ..ReviewManifestContext::default()
            },
            now_ms,
        )
        .unwrap();
    let session = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", url_token(&response.ceremony_url))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let projection: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let plan = projection["review_manifest"]["canonical_plan"]
        .as_str()
        .unwrap();
    let plan: serde_json::Value = serde_json::from_str(plan).unwrap();
    assert_eq!(plan["asset_amounts"][0]["display"], "0.01 USDC");
    assert_eq!(plan["asset_amounts"][0]["base_units"], "10000");
    assert_eq!(plan["asset_amounts"][0]["decimals"], 6);
}

#[tokio::test]
async fn petal_key_scope_is_the_exact_human_review_and_tampering_fails_closed() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let parent = approval_request().terms.key_ref;
    let scope = bloom_signer_api::PetalKeyScope {
        wallet_id: Token::new("wallet-review").unwrap(),
        parent_key_ref: parent.clone(),
        package_hash: digest("91"),
        route: "/petals/exchange/sign".into(),
        lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        key_slot: Token::new("account-a").unwrap(),
        allowed_routes: vec!["/petals/exchange/sign".into()],
        allowed_operation_classes: vec![Token::new("exchange-order").unwrap()],
        allowed_crypto_suites: vec![bloom_signer_api::CryptoSuite::Secp256k1Sha256Recoverable],
        maximum_lifetime_ms: DecimalU64::new(60_000),
        custody_operation_id: operation("92"),
    };
    let request = CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::KeyDerive,
        custody_operation_id: scope.custody_operation_id.clone(),
        wallet_id: Some(scope.wallet_id.clone()),
        key_ref: Some(parent),
        exact_terms_digest: scope.request_digest().unwrap(),
        expected_input_class: Token::new("petal-key-scope-v1").unwrap(),
        browser_output_recipient_key: None,
        petal_key_scope: Some(scope.clone()),
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_request: None,
    };
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let prepared = broker.prepare_custody(request.clone(), now_ms).unwrap();
    let token = url_token(&prepared.ceremony_url);
    let response = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let projection: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        projection["review_manifest"]["petal_key_scope"],
        serde_json::to_value(&scope).unwrap()
    );
    assert_eq!(projection["review_manifest"]["ceremony_kind"], "key_derive");
    assert!(
        projection["review_manifest"]["canonical_plan"]
            .as_str()
            .is_some_and(|plan| plan.contains("Petal scope")),
        "the exact human review must describe the scope, not just carry it"
    );
    assert_eq!(
        projection["signer_contribution"]["petal_key_scope"],
        serde_json::to_value(&scope).unwrap()
    );
    assert!(projection["signer_contribution"]["browser_output_recipient_key"].is_null());

    let mut tampered = request.clone();
    tampered.custody_operation_id = operation("93");
    assert_eq!(
        broker
            .prepare_custody(tampered, now_ms + 1)
            .unwrap_err()
            .code,
        ProtocolErrorCode::OperationIdConflict
    );

    let mut wrong_kind = request;
    wrong_kind.custody_operation_id = operation("94");
    wrong_kind.ceremony_kind = CeremonyKind::WalletDelete;
    assert_eq!(
        broker
            .prepare_custody(wrong_kind, now_ms + 2)
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyKindMismatch
    );
}

#[tokio::test]
async fn machine_asserted_reusable_plan_carries_primary_surface_warning() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new_with_manifest_signer(
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[31; 32]),
    );
    let mut request = approval_request();
    request.activation_operation_id = operation("18");
    request.terms.subject = bloom_signer_api::ApprovalSubject::Petal {
        package_hash: digest("19"),
        route: "wallet/send".into(),
        agent_id: None,
    };
    request.terms.selector = bloom_signer_api::ApprovalSelector::Petal {
        package_hash: digest("19"),
        route: "wallet/send".into(),
        allowed_operation_classes: vec![Token::new("transfer").unwrap()],
        route_grants: Vec::new(),
        required_claim_assurance: bloom_signer_api::ClaimAssuranceLevel::MachineAsserted,
    };
    request.exact_ordered_payload_digests.clear();
    request.exact_ordered_hashes.clear();
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let response = broker
        .prepare_approval(
            request,
            ReviewManifestContext {
                claim_assurance: Some(ClaimAssurance::MachineAsserted),
                ..ReviewManifestContext::default()
            },
            now_ms,
        )
        .unwrap();
    let token = url_token(&response.ceremony_url);
    let session = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let projection: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let plan = projection["review_manifest"]["canonical_plan"]
        .as_str()
        .unwrap();
    assert!(plan.contains("limits are asserted by the named Petal"));
    assert!(plan.contains("compromised Petal or Machine"));
    assert!(plan.contains("full remaining capacity"));
}

#[tokio::test]
async fn assets_headers_host_origin_token_and_opaque_relay_are_enforced() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer.clone());
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let prepared = prepare(
        &broker,
        operation("11"),
        Some(Token::new("wallet-2").unwrap()),
        now_ms,
    );
    let ceremony_id = broker
        .public_status(&operation("11"))
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&prepared.ceremony_url);
    assert_eq!(token.len(), 43);
    assert!(!prepared.ceremony_url.contains(['?', '#']));
    let app = broker.router();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ceremony/{token}"))
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert_eq!(
        response.headers()[CEREMONY_OWNER_HEADER],
        CEREMONY_OWNER_VALUE
    );
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY)
    );
    let stylesheet = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/style.css")
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stylesheet.status(), StatusCode::OK);
    assert_eq!(
        stylesheet.headers()[header::CONTENT_TYPE],
        "text/css; charset=utf-8"
    );
    let stylesheet_body = stylesheet.into_body().collect().await.unwrap().to_bytes();
    assert!(stylesheet_body.starts_with(b":root{"));
    let logo = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/bloom-primary.svg")
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logo.status(), StatusCode::OK);
    assert_eq!(
        logo.headers()[header::CONTENT_TYPE],
        "image/svg+xml; charset=utf-8"
    );
    let logo_body = logo.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        logo_body.as_ref(),
        include_bytes!("../src/ceremony_assets/bloom-primary.svg")
    );
    let unknown_token = Base64UrlBytes::from_bytes(&[99; 32]);
    let unknown = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ceremony/{}", unknown_token.encoded()))
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        unknown.status(),
        StatusCode::NOT_FOUND,
        "another local user cannot discover a ceremony without its 256-bit token"
    );

    let wrong_host = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::HOST, "127.0.0.1:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_host.status(), StatusCode::FORBIDDEN);

    let no_token = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{ceremony_id}"))
                .header(header::HOST, "localhost:18734")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_token.status(), StatusCode::FORBIDDEN);

    let session_by_launch_token = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_by_launch_token.status(), StatusCode::OK);

    let session = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{ceremony_id}"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    let session_json: serde_json::Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(session_json["ceremony_kind"], "wallet_delete");
    assert!(session_json["challenges"][0]["challenge"].is_string());

    let body = serde_json::json!({
        "proof": {
            "kind": "assertion",
            "assertion": {
                "credential_id": "Y3JlZGVudGlhbA",
                "authenticator_data": "YXV0aA",
                "client_data_json": "e30",
                "signature": "c2ln",
                "user_handle": null
            }
        },
        "encrypted_input": {
            "kem_output": "a2Vt",
            "ciphertext": "Y2lwaGVydGV4dA"
        },
        "public_binding_digest": digest("33")
    });
    let missing_origin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

    let completed = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    assert_eq!(signer.completions.load(Ordering::SeqCst), 1);
    assert_eq!(signer.cancellations.load(Ordering::SeqCst), 0);
}

#[test]
fn prebound_canonical_listener_is_a_fatal_no_fallback_failure() {
    let listener = match std::net::TcpListener::bind(CEREMONY_ADDR) {
        Ok(listener) => Some(listener),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => None,
        Err(error) => panic!("cannot establish canonical-listener precondition: {error}"),
    };
    let error = CeremonyBroker::bind_canonical().unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);
    assert!(error.message.contains("18734"));
    drop(listener);
}

#[test]
fn login_session_disconnect_terminalizes_every_live_browser_session() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer.clone());
    let operation_id = operation("af");
    let wallet = Token::new("wallet-logout").unwrap();
    prepare(&broker, operation_id.clone(), Some(wallet.clone()), 10_000);

    broker.terminate_live_sessions(10_001).unwrap();

    let status = broker.public_status(&operation_id).unwrap();
    assert_eq!(status.state, CeremonyState::Cancelled);
    assert!(status.ceremony_url.is_none());
    assert_eq!(signer.cancellations.load(Ordering::SeqCst), 1);
    prepare(&broker, operation("b0"), Some(wallet), 10_002);
}

#[tokio::test]
async fn inherited_listener_handover_rejects_every_noncanonical_socket() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    assert_eq!(
        broker.serve_listener(listener).await.unwrap_err().code,
        ProtocolErrorCode::ServiceUnavailable
    );
}

#[test]
fn ac18_forced_ceremony_audit_write_failure_rolls_back_session() {
    let directory = tempfile::tempdir().unwrap();
    let fail = Arc::new(AtomicBool::new(false));
    let journal = Arc::new(
        BrokerJournal::open(
            directory.path().join("journal.sqlite"),
            Arc::new(SwitchableAuditSigner(fail.clone())),
        )
        .unwrap(),
    );
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::open_with_manifest_signer_audited(
        directory.path().join("ceremonies.sqlite"),
        signer,
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        journal.clone(),
        CeremonyLimits::default(),
    )
    .unwrap();
    let operation_id = operation("30");
    let request = CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::WalletDelete,
        custody_operation_id: operation_id.clone(),
        wallet_id: Some(Token::new("wallet-audit-rollback").unwrap()),
        key_ref: None,
        exact_terms_digest: digest("33"),
        expected_input_class: Token::new("policy-document").unwrap(),
        browser_output_recipient_key: None,
        petal_key_scope: None,
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_request: None,
    };

    fail.store(true, Ordering::SeqCst);
    assert!(broker.prepare_custody(request.clone(), 40_000).is_err());
    assert_eq!(broker.status(&operation_id), None);
    assert!(journal.audit_entries().unwrap().is_empty());

    fail.store(false, Ordering::SeqCst);
    broker.prepare_custody(request, 40_001).unwrap();
    assert_eq!(
        broker.status(&operation_id),
        Some(CeremonyState::AwaitingUser)
    );
    assert_eq!(journal.audit_entries().unwrap().len(), 1);

    fail.store(true, Ordering::SeqCst);
    assert!(broker.cancel(&operation_id, 40_002).is_err());
    assert_eq!(
        broker.status(&operation_id),
        Some(CeremonyState::AwaitingUser),
        "a failed session+journal transaction must not publish cancellation in memory"
    );
    assert_eq!(journal.audit_entries().unwrap().len(), 1);
}

#[test]
fn ac18_populated_ceremony_migration_is_atomic_idempotent_and_retains_source() {
    let directory = tempfile::tempdir().unwrap();
    let legacy_path = directory.path().join("legacy-ceremony.sqlite");
    let legacy_journal =
        Arc::new(BrokerJournal::open(&legacy_path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let operation_id = operation("39");
    let legacy_broker = CeremonyBroker::open_with_manifest_signer_audited(
        &legacy_path,
        Arc::new(MockSigner::new()),
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        legacy_journal,
        CeremonyLimits::default(),
    )
    .unwrap();
    legacy_broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation_id.clone(),
                wallet_id: Some(Token::new("wallet-migrated").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("39"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            50_000,
        )
        .unwrap();
    legacy_broker.cancel(&operation_id, 50_001).unwrap();
    drop(legacy_broker);
    let source = rusqlite::Connection::open(&legacy_path).unwrap();
    let source_jcs: String = source
        .query_row(
            "SELECT session_jcs FROM ceremony_sessions WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    drop(source);

    let failed_target_path = directory.path().join("failed-target-journal.sqlite");
    let fail = Arc::new(AtomicBool::new(false));
    let failed_journal = Arc::new(
        BrokerJournal::open(
            &failed_target_path,
            Arc::new(SwitchableAuditSigner(fail.clone())),
        )
        .unwrap(),
    );
    fail.store(true, Ordering::SeqCst);
    assert!(
        CeremonyBroker::open(
            &legacy_path,
            Arc::new(MockSigner::new()),
            failed_journal.clone(),
        )
        .is_err()
    );
    let failed_target = rusqlite::Connection::open(&failed_target_path).unwrap();
    assert_eq!(
        failed_target
            .query_row("SELECT COUNT(*) FROM ceremony_sessions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        failed_target
            .query_row("SELECT COUNT(*) FROM broker_store_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert!(failed_journal.audit_entries().unwrap().is_empty());
    let source = rusqlite::Connection::open(&legacy_path).unwrap();
    assert_eq!(
        source
            .query_row(
                "SELECT session_jcs FROM ceremony_sessions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        source_jcs
    );
    drop(source);
    drop(failed_target);
    drop(failed_journal);

    let target_path = directory.path().join("target-journal.sqlite");
    let target_journal =
        Arc::new(BrokerJournal::open(&target_path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let migrated = CeremonyBroker::open(
        &legacy_path,
        Arc::new(MockSigner::new()),
        target_journal.clone(),
    )
    .unwrap();
    assert_eq!(
        migrated.status(&operation_id),
        Some(CeremonyState::Cancelled)
    );
    assert_eq!(
        target_journal
            .audit_entries()
            .unwrap()
            .iter()
            .filter(|entry| entry.event_type == "storage.ceremony_migrated")
            .count(),
        1
    );
    drop(migrated);
    let reopened = CeremonyBroker::open(
        &legacy_path,
        Arc::new(MockSigner::new()),
        target_journal.clone(),
    )
    .unwrap();
    assert_eq!(
        reopened.status(&operation_id),
        Some(CeremonyState::Cancelled)
    );
    assert_eq!(
        target_journal
            .audit_entries()
            .unwrap()
            .iter()
            .filter(|entry| entry.event_type == "storage.ceremony_migrated")
            .count(),
        1
    );
    let source = rusqlite::Connection::open(&legacy_path).unwrap();
    assert_eq!(
        source
            .query_row(
                "SELECT session_jcs FROM ceremony_sessions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        source_jcs
    );
    drop(source);

    let conflict_path = directory.path().join("conflict-ceremony.sqlite");
    std::fs::copy(&legacy_path, &conflict_path).unwrap();
    assert!(
        CeremonyBroker::open(
            &conflict_path,
            Arc::new(MockSigner::new()),
            target_journal.clone(),
        )
        .is_err()
    );
    let target = rusqlite::Connection::open(&target_path).unwrap();
    let marker: i64 = target
        .query_row(
            "SELECT COUNT(*) FROM broker_store_migrations WHERE source_kind='ceremony' AND source_path=?1",
            [conflict_path.to_string_lossy().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, 0);
}

#[test]
fn ac18_ceremony_status_survives_latched_audit_tamper_while_new_sessions_fail() {
    let directory = tempfile::tempdir().unwrap();
    let journal_path = directory.path().join("journal.sqlite");
    let ceremony_path = directory.path().join("ceremonies.sqlite");
    let journal =
        Arc::new(BrokerJournal::open(&journal_path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let broker = CeremonyBroker::open_with_manifest_signer_audited(
        &ceremony_path,
        Arc::new(MockSigner::new()),
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        journal,
        CeremonyLimits::default(),
    )
    .unwrap();
    let existing_operation = operation("39");
    prepare(
        &broker,
        existing_operation.clone(),
        Some(Token::new("wallet-audit-status").unwrap()),
        41_000,
    );
    drop(broker);

    rusqlite::Connection::open(&journal_path)
        .unwrap()
        .execute(
            "UPDATE audit_chain SET payload_jcs='{}' WHERE sequence=0",
            [],
        )
        .unwrap();
    let degraded_journal =
        Arc::new(BrokerJournal::open(&journal_path, Arc::new(ServiceTestAuditSigner)).unwrap());
    assert!(degraded_journal.audit_degraded());
    let restarted = CeremonyBroker::open_with_manifest_signer_audited(
        &ceremony_path,
        Arc::new(MockSigner::new()),
        Token::new("broker-review-key").unwrap(),
        SigningKey::from_bytes(&[7; 32]),
        degraded_journal,
        CeremonyLimits::default(),
    )
    .unwrap();
    assert_eq!(
        restarted.status(&existing_operation),
        Some(CeremonyState::AwaitingUser)
    );
    assert!(
        restarted
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletDelete,
                    custody_operation_id: operation("3a"),
                    wallet_id: Some(Token::new("wallet-audit-new").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("33"),
                    expected_input_class: Token::new("policy-document").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: None,
                    derivation_request: None,
                },
                41_001,
            )
            .is_err()
    );
}

#[test]
fn restart_expires_nonterminal_session_and_persists_only_token_hash() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ceremonies.sqlite");
    let signer = Arc::new(MockSigner::new());
    let journal = Arc::new(BrokerJournal::open(&path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let broker = CeremonyBroker::open(&path, signer.clone(), journal.clone()).unwrap();
    let prepared = prepare(
        &broker,
        operation("31"),
        Some(Token::new("wallet-restart").unwrap()),
        50_000,
    );
    let token = url_token(&prepared.ceremony_url);
    drop(broker);

    let bytes = std::fs::read(&path).unwrap();
    assert!(
        !bytes
            .windows(token.len())
            .any(|window| window == token.as_bytes()),
        "launch token plaintext must not be durable"
    );

    let restarted = CeremonyBroker::open(&path, signer.clone(), journal).unwrap();
    assert_eq!(signer.cancellations.load(Ordering::SeqCst), 1);
    assert_eq!(
        restarted.status(&operation("31")),
        Some(CeremonyState::Expired)
    );
    let error = restarted
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("31"),
                wallet_id: Some(Token::new("wallet-restart").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("33"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            50_001,
        )
        .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::CeremonyReplay);
}

/// A stale WebAuthn signature counter is rejected as `UnauthenticatedPeer`
/// while the Signer keeps its operation pending, so Broker must cancel that
/// operation before the session may become terminal. When the cancel itself
/// fails the browser still gets the structured rejection, the session stays
/// nonterminal so a later sweep or restart retries the cancel, and only the
/// successful retry burns the launch token and frees the wallet.
#[tokio::test]
async fn rejected_proof_stays_verifying_until_a_retried_cancel_releases_the_signer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ceremonies.sqlite");
    let signer = Arc::new(MockSigner::rejecting_proof(true));
    let journal = Arc::new(BrokerJournal::open(&path, Arc::new(ServiceTestAuditSigner)).unwrap());
    let broker = CeremonyBroker::open(&path, signer.clone(), journal.clone()).unwrap();
    let wallet = Token::new("wallet-stale-counter").unwrap();
    // The browser completion path stamps itself from the real clock, so the
    // session has to be staged against it to still be live when it posts.
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let prepared = prepare(&broker, operation("41"), Some(wallet.clone()), now_ms);
    let ceremony_id = broker
        .public_status(&operation("41"))
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&prepared.ceremony_url);
    let app = broker.router();
    let body = serde_json::json!({
        "proof": {
            "kind": "assertion",
            "assertion": {
                "credential_id": "Y3JlZGVudGlhbA",
                "authenticator_data": "YXV0aA",
                "client_data_json": "e30",
                "signature": "c2ln",
                "user_handle": null
            }
        },
        "encrypted_input": {
            "kem_output": "a2Vt",
            "ciphertext": "Y2lwaGVydGV4dA"
        },
        "public_binding_digest": digest("33")
    });

    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    // Deserialising through `ProtocolError` also proves the rejection kept its
    // real retry and durable-effect contract rather than an empty failure.
    let error: ProtocolError =
        serde_json::from_slice(&rejected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error.code, ProtocolErrorCode::UnauthenticatedPeer);
    assert_eq!(error.message, "stale webauthn signature counter");
    assert_eq!(signer.completions.load(Ordering::SeqCst), 0);
    assert_eq!(
        signer.cancellations.load(Ordering::SeqCst),
        1,
        "the rejected proof has to release the still-pending Signer operation"
    );
    assert_eq!(
        broker.status(&operation("41")),
        Some(CeremonyState::Verifying),
        "a failed cancel must leave the session nonterminal so the cancel is retried"
    );
    let live = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        live.status(),
        StatusCode::OK,
        "a nonterminal session keeps its launch token usable"
    );

    let sweep = broker.expire_sessions(now_ms + 10_001).unwrap_err();
    assert_eq!(sweep.code, ProtocolErrorCode::ServiceUnavailable);
    assert_eq!(signer.cancellations.load(Ordering::SeqCst), 2);
    assert_eq!(
        broker.status(&operation("41")),
        Some(CeremonyState::Verifying),
        "an expiry sweep that cannot reach the Signer must not strand the operation"
    );

    signer.restore_cancellation();
    drop(app);
    drop(broker);
    let restarted = CeremonyBroker::open(&path, signer.clone(), journal).unwrap();
    assert_eq!(
        signer.cancellations.load(Ordering::SeqCst),
        3,
        "restart reconciliation retries the cancel the browser path could not complete"
    );
    assert_eq!(
        restarted.status(&operation("41")),
        Some(CeremonyState::Expired)
    );
    let public = restarted.public_status(&operation("41")).unwrap();
    assert_eq!(public.state, CeremonyState::Expired);
    assert!(
        public.ceremony_url.is_none(),
        "a terminal session must not hand out a ceremony URL"
    );
    let burned = restarted
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        burned.status(),
        StatusCode::FORBIDDEN,
        "terminalising burns the token hash, so the launch token stops authorising"
    );
    assert!(
        !std::fs::read(&path)
            .unwrap()
            .windows(token.len())
            .any(|window| window == token.as_bytes()),
        "launch token plaintext must not be durable"
    );

    // The released Signer operation no longer holds the wallet, so the owner
    // can stage a fresh ceremony with a token unrelated to the burned one.
    let fresh = prepare(&restarted, operation("42"), Some(wallet), now_ms + 13_000);
    assert_eq!(
        restarted.status(&operation("42")),
        Some(CeremonyState::AwaitingUser)
    );
    assert_ne!(url_token(&fresh.ceremony_url), token);
}

#[test]
fn rolling_creation_limits_survive_terminal_sessions_and_bound_anonymous_registration() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let wallet = Token::new("wallet-rate-bound").unwrap();
    // Twelve creations spread across the compiled five-minute window, each
    // cancelled at once: a terminal session keeps occupying the slot it
    // consumed, so cancelling cannot be used to mint extra creations.
    for index in 0..12_u8 {
        let now_ms = 1_000 + u64::from(index) * 20_000;
        let operation_id = operation(&format!("{index:02x}"));
        prepare(&broker, operation_id.clone(), Some(wallet.clone()), now_ms);
        broker.cancel(&operation_id, now_ms).unwrap();
    }
    let error = try_prepare(&broker, operation("f1"), Some(wallet.clone()), 240_000).unwrap_err();
    // The oldest counted creation is at 1_000, so a wallet slot frees at
    // 301_000: 61_000 ms after the rejected attempt.
    assert_retry_contract(&error, 61_000, 12, 300_000);

    for index in 0..4_u8 {
        let operation_id = operation(&format!("a{index}"));
        try_register(
            &broker,
            operation_id.clone(),
            Token::new(format!("wallet-a{index}")).unwrap(),
            500_000 + u64::from(index),
        )
        .unwrap();
        broker
            .cancel(&operation_id, 500_000 + u64::from(index))
            .unwrap();
    }
    let error = try_register(
        &broker,
        operation("af"),
        Token::new("wallet-af").unwrap(),
        500_010,
    )
    .unwrap_err();
    // The anonymous class has its own tighter quota and its own hint, taken
    // from the oldest of the four registrations rather than from the wallet
    // creations that preceded them.
    assert_retry_contract(&error, 299_990, 4, 300_000);

    // The wallet quota is unchanged by the anonymous traffic: once the window
    // has rolled past all twelve creations, the same wallet is admitted again.
    prepare(&broker, operation("f2"), Some(wallet), 522_000);
}

#[test]
fn configured_ceremony_limits_replace_the_defaults_for_every_admission_class() {
    let limits = CeremonyLimits::new(2, 60_000, 3, 2).unwrap();
    let broker = CeremonyBroker::new_with_limits(Arc::new(MockSigner::new()), limits);
    assert_eq!(broker.limits(), limits);

    // Concurrency is the configured 2, not the compiled 16, and it carries no
    // retry hint: nothing ages out on a schedule, only when a ceremony ends.
    prepare(
        &broker,
        operation("e0"),
        Some(Token::new("wallet-live-0").unwrap()),
        1_000,
    );
    prepare(
        &broker,
        operation("e1"),
        Some(Token::new("wallet-live-1").unwrap()),
        2_000,
    );
    let error = try_prepare(
        &broker,
        operation("e2"),
        Some(Token::new("wallet-live-2").unwrap()),
        3_000,
    )
    .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::QuotaExceeded);
    assert_eq!(
        error.message,
        "Broker ceremony concurrency quota is exhausted"
    );
    assert!(error.rate_limit.is_none());
    broker.cancel(&operation("e0"), 3_000).unwrap();
    broker.cancel(&operation("e1"), 3_000).unwrap();

    // The configured per-wallet quota of 3 in a 60-second window binds well
    // before the compiled default of 12 in five minutes would.
    let wallet = Token::new("wallet-configured").unwrap();
    for (index, now_ms) in [10_000_u64, 25_000, 41_000].into_iter().enumerate() {
        let operation_id = operation(&format!("f{index}"));
        prepare(&broker, operation_id.clone(), Some(wallet.clone()), now_ms);
        broker.cancel(&operation_id, now_ms).unwrap();
    }
    let error = try_prepare(&broker, operation("fa"), Some(wallet.clone()), 50_000).unwrap_err();
    assert_retry_contract(&error, 20_000, 3, 60_000);

    // The configured anonymous quota of 2 is tighter still, and reports its
    // own limit and window rather than the wallet quota's.
    for index in 0..2_u8 {
        let operation_id = operation(&format!("c{index}"));
        try_register(
            &broker,
            operation_id.clone(),
            Token::new(format!("wallet-anon-{index}")).unwrap(),
            51_000 + u64::from(index) * 1_000,
        )
        .unwrap();
        broker
            .cancel(&operation_id, 51_000 + u64::from(index) * 1_000)
            .unwrap();
    }
    let error = try_register(
        &broker,
        operation("cf"),
        Token::new("wallet-anon-f").unwrap(),
        53_000,
    )
    .unwrap_err();
    assert_retry_contract(&error, 58_000, 2, 60_000);
}

#[test]
fn concurrent_prepares_cannot_oversubscribe_the_configured_session_limit() {
    let (signer, events, release_first) = MockSigner::blocking_first_custody();
    let signer = Arc::new(signer);
    let limits = CeremonyLimits::new(1, 60_000, 12, 4).unwrap();
    let broker = CeremonyBroker::new_with_limits(signer.clone(), limits);

    let first_broker = broker.clone();
    let first = std::thread::spawn(move || {
        try_prepare(
            &first_broker,
            operation("d0"),
            Some(Token::new("wallet-concurrent-0").unwrap()),
            1_000,
        )
    });
    assert_eq!(
        events
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap(),
        0
    );

    let second_broker = broker.clone();
    let second = std::thread::spawn(move || {
        try_prepare(
            &second_broker,
            operation("d1"),
            Some(Token::new("wallet-concurrent-1").unwrap()),
            1_000,
        )
    });

    // While the first prepare is blocked inside Signer, the second must remain
    // behind Broker's admission decision rather than reaching Signer too.
    let second_reached_signer = events
        .recv_timeout(std::time::Duration::from_secs(1))
        .is_ok();
    release_first.send(()).unwrap();

    assert!(first.join().unwrap().is_ok());
    let second_error = second.join().unwrap().unwrap_err();
    assert_eq!(second_error.code, ProtocolErrorCode::QuotaExceeded);
    assert!(!second_reached_signer);
    assert_eq!(signer.custody_preparations.load(Ordering::SeqCst), 1);
}

#[test]
fn rolling_quota_retry_hint_names_the_blocking_creation_and_clears_at_the_boundary() {
    let defaults = CeremonyLimits::default();
    let limits = CeremonyLimits::new(
        defaults.maximum_concurrent_sessions(),
        60_000,
        3,
        defaults.maximum_anonymous_registrations(),
    )
    .unwrap();
    let broker = CeremonyBroker::new_with_limits(Arc::new(MockSigner::new()), limits);
    let wallet = Token::new("wallet-boundary").unwrap();
    // Three creations at distinct, unevenly spaced timestamps: the hint must
    // track the creation whose expiry frees the next slot — here, with the
    // quota exactly at capacity, the oldest — not the newest and not an
    // average.
    for (index, now_ms) in [10_000_u64, 25_000, 41_000].into_iter().enumerate() {
        let operation_id = operation(&format!("{index:02x}"));
        prepare(&broker, operation_id.clone(), Some(wallet.clone()), now_ms);
        broker.cancel(&operation_id, now_ms).unwrap();
    }

    // The blocking creation is the one at 10_000, so the slot frees at 70_000
    // however late in the window the caller asks.
    let error = try_prepare(&broker, operation("b1"), Some(wallet.clone()), 50_000).unwrap_err();
    assert_retry_contract(&error, 20_000, 3, 60_000);
    let error = try_prepare(&broker, operation("b2"), Some(wallet.clone()), 69_999).unwrap_err();
    assert_retry_contract(&error, 1, 3, 60_000);

    // Waiting exactly the advertised hint is enough: the contract is exact,
    // so an honest caller never has to guess an extra margin.
    prepare(&broker, operation("b3"), Some(wallet.clone()), 70_000);
    broker.cancel(&operation("b3"), 70_000).unwrap();

    // That admission consumed the freed slot, and the quota is now held by the
    // creation at 25_000, which frees at 85_000.
    let error = try_prepare(&broker, operation("b4"), Some(wallet), 71_000).unwrap_err();
    assert_retry_contract(&error, 14_000, 3, 60_000);
}

#[test]
fn zero_effective_time_fails_closed_before_anonymous_creation_quota() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    for index in 0..4_u8 {
        let operation_id = operation(&format!("b{index}"));
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletRegistration,
                    custody_operation_id: operation_id.clone(),
                    wallet_id: Some(Token::new(format!("wallet-b{index}")).unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("34"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: Some(
                        bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1,
                    ),
                    derivation_request: None,
                },
                1 + u64::from(index),
            )
            .unwrap();
        broker.cancel(&operation_id, 1 + u64::from(index)).unwrap();
    }

    let error = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletRegistration,
                custody_operation_id: operation("bf"),
                wallet_id: Some(Token::new("wallet-bf").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("34"),
                expected_input_class: Token::new("passkey-prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: Some(bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1),
                derivation_request: None,
            },
            0,
        )
        .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::ClockUntrusted);
    assert_eq!(
        error.message,
        "trusted platform time is required to create a ceremony"
    );
}

#[test]
fn cancellation_backoff_reports_remaining_cooldown_and_resets_after_expiry() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let wallet = Token::new("wallet-cancellation-backoff").unwrap();
    let first_operation = operation("c1");
    prepare(
        &broker,
        first_operation.clone(),
        Some(wallet.clone()),
        10_000,
    );
    broker.cancel(&first_operation, 10_000).unwrap();

    let error = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("c2"),
                wallet_id: Some(wallet.clone()),
                key_ref: None,
                exact_terms_digest: digest("35"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            10_001,
        )
        .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::CeremonyRateLimited);
    assert_eq!(
        error.message,
        "wallet ceremony is in cancellation backoff; retry after 1999 ms"
    );

    prepare(&broker, operation("c3"), Some(wallet), 12_000);
}

#[test]
fn automatic_expiry_does_not_impose_cancellation_backoff() {
    let signer = Arc::new(MockSigner::new());
    let broker = CeremonyBroker::new(signer);
    let wallet = Token::new("wallet-expired-review").unwrap();
    prepare(&broker, operation("e1"), Some(wallet.clone()), 10_000);

    broker.expire_sessions(20_001).unwrap();

    prepare(&broker, operation("e2"), Some(wallet), 20_002);
}

#[test]
fn requested_wallet_ids_still_count_as_new_registration_attempts() {
    let registry = Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap());
    let engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            signer_audit_keys(),
            registry,
        )
        .unwrap(),
    );
    let service = Arc::new(
        SignerCeremonyService::new(
            engine,
            Token::new("signer-ceremony-key").unwrap(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap(),
    );
    let broker = CeremonyBroker::new(Arc::new(RealSigner { service }));
    for index in 0..4_u8 {
        let operation_id = operation(&format!("d{index}"));
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletRegistration,
                    custody_operation_id: operation_id.clone(),
                    wallet_id: Some(Token::new(format!("wallet-d{index}")).unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("d8"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: Some(
                        bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1,
                    ),
                    derivation_request: None,
                },
                100_000 + u64::from(index),
            )
            .unwrap();
        broker
            .cancel(&operation_id, 100_000 + u64::from(index))
            .unwrap();
    }
    assert_eq!(
        broker
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::WalletRegistration,
                    custody_operation_id: operation("df"),
                    wallet_id: Some(Token::new("wallet-df").unwrap()),
                    key_ref: None,
                    exact_terms_digest: digest("d8"),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: Some(
                        bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1,
                    ),
                    derivation_request: None,
                },
                100_010,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyRateLimited
    );
}

#[tokio::test]
async fn bip39_import_session_projects_the_authoritative_signer_profile() {
    let broker = CeremonyBroker::new(real_ceremony_signer());
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let response = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletImport,
                custody_operation_id: operation("40"),
                wallet_id: Some(Token::new("imported-wallet").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("50"),
                expected_input_class: Token::new("passkey-prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: Some(bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1),
                derivation_request: None,
            },
            now_ms,
        )
        .unwrap();
    let session_response = broker
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", url_token(&response.ceremony_url))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_response.status(), StatusCode::OK);
    let session: serde_json::Value = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();

    assert_eq!(
        session["signer_contribution"]["wallet_seed_profile"],
        "bip39-multicurve-v1"
    );
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    assert_eq!(
        contribution.wallet_seed_profile,
        Some(bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1)
    );
}

#[tokio::test]
async fn browser_to_broker_to_signer_registration_keeps_prf_ciphertext_opaque() {
    let broker = CeremonyBroker::new(real_ceremony_signer());
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let operation_id = operation("41");
    let prepared = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletRegistration,
                custody_operation_id: operation_id.clone(),
                wallet_id: Some(Token::new("quiet-lilac").unwrap()),
                key_ref: None,
                exact_terms_digest: digest("51"),
                expected_input_class: Token::new("passkey-prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: Some(bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1),
                derivation_request: None,
            },
            now_ms,
        )
        .unwrap();
    let ceremony_id = broker
        .public_status(&operation_id)
        .unwrap()
        .ceremony_id
        .to_string();
    let token = url_token(&prepared.ceremony_url);
    let app = broker.router();
    let session_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{ceremony_id}"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session: serde_json::Value = serde_json::from_slice(
        &session_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let first_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][0]["binding"].clone()).unwrap();
    let second_challenge: CeremonyChallenge =
        serde_json::from_value(session["challenges"][1]["binding"].clone()).unwrap();
    let contribution: CustodySignerContribution =
        serde_json::from_value(session["signer_contribution"].clone()).unwrap();
    let authenticator = VirtualAuthenticator::generate();
    let attestation = authenticator.attestation(&first_challenge.canonical_bytes().unwrap());
    let assertion = authenticator.assertion(&second_challenge.canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation_id,
        signer_nonce: contribution.signer_nonce.clone(),
        signer_contribution_digest: contribution.digest().unwrap(),
        wallet_id: contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("passkey-prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let prf = authenticator.deterministic_prf();
    let envelope = seal_hpke(
        &contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &prf,
    )
    .unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "proof": {
            "kind": "registration",
            "attestation": attestation,
            "prf_assertion": assertion
        },
        "encrypted_input": envelope,
        "public_binding_digest": digest("51")
    }))
    .unwrap();
    assert!(
        !body
            .windows(prf.len())
            .any(|window| window == prf.as_slice()),
        "Broker request body must never contain plaintext PRF"
    );
    let completed = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{ceremony_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);

    let export_operation = operation("42");
    let export = broker
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletExport,
                custody_operation_id: export_operation.clone(),
                wallet_id: contribution.wallet_id.clone(),
                key_ref: None,
                exact_terms_digest: digest("52"),
                expected_input_class: Token::new("generic-custody-v1").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            now_ms + 1_000,
        )
        .unwrap();
    let export_id = broker
        .public_status(&export_operation)
        .unwrap()
        .ceremony_id
        .to_string();
    let export_token = url_token(&export.ceremony_url);
    let output_recipient = HpkeRecipient::generate();
    let export_app = broker.router();
    let bound = export_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{export_id}/output-key"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &export_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "recipient_key": output_recipient.public_key()
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bound.status(), StatusCode::OK);
    let projection: serde_json::Value =
        serde_json::from_slice(&bound.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let export_contribution: CustodySignerContribution =
        serde_json::from_value(projection["signer_contribution"].clone()).unwrap();
    assert_eq!(
        export_contribution.browser_output_recipient_key.as_ref(),
        Some(output_recipient.public_key())
    );
    let export_challenge: CeremonyChallenge =
        serde_json::from_value(projection["challenges"][0]["binding"].clone()).unwrap();
    let export_assertion = authenticator.assertion(&export_challenge.canonical_bytes().unwrap(), 2);
    let export_aad = CustodyHpkeAad {
        ceremony_id: export_contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletExport,
        custody_operation_id: export_operation.clone(),
        signer_nonce: export_contribution.signer_nonce.clone(),
        signer_contribution_digest: export_contribution.digest().unwrap(),
        wallet_id: export_contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(export_assertion.credential_id.clone()),
        expected_input_class: Token::new("generic-custody-v1").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let export_html = include_str!("../src/ceremony_assets/index.html");
    let export_format = export_html
        .split_once("name=\"export-format\" value=\"")
        .expect("the shipped browser must offer an export format")
        .1
        .split_once('"')
        .expect("the shipped export format must be quoted")
        .0;
    let export_input = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&prf),
        "effect": {"kind": "wallet_export", "format": export_format}
    }))
    .unwrap();
    let export_envelope = seal_hpke(
        &export_contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &export_aad,
        &export_input,
    )
    .unwrap();
    let exported = export_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{export_id}/complete"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &export_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "proof": {
                            "kind": "assertion",
                            "assertion": export_assertion
                        },
                        "encrypted_input": export_envelope,
                        "public_binding_digest": digest("52")
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exported.status(), StatusCode::OK);
    let export_result: CustodyResult =
        serde_json::from_slice(&exported.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let recovered = export_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{export_id}/result"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", &export_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered_result: CustodyResult =
        serde_json::from_slice(&recovered.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(recovered_result, export_result);
    let export_contribution_digest = export_contribution.digest().unwrap();
    let output_aad = CustodyOutputHpkeAad {
        ceremony_id: export_contribution.ceremony_id,
        ceremony_kind: CeremonyKind::WalletExport,
        custody_operation_id: export_operation,
        signer_contribution_digest: export_contribution_digest,
        public_binding_digest: digest("52"),
    }
    .canonical_bytes()
    .unwrap();
    let plaintext = output_recipient
        .open(
            export_result.encrypted_browser_result.as_ref().unwrap(),
            CUSTODY_OUTPUT_INFO,
            &output_aad,
        )
        .unwrap();
    let exported_mnemonic = std::str::from_utf8(plaintext.expose_to_backend()).unwrap();
    assert_eq!(export_format, "bip39_mnemonic");
    assert_eq!(exported_mnemonic.split_whitespace().count(), 24);
    let acknowledged = export_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/session/{export_id}/ack"))
                .header(header::HOST, "localhost:18734")
                .header(header::ORIGIN, "http://localhost:18734")
                .header("x-bloom-ceremony-token", &export_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::NO_CONTENT);
    let replay_after_ack = export_app
        .oneshot(
            Request::builder()
                .uri(format!("/api/session/{export_id}/result"))
                .header(header::HOST, "localhost:18734")
                .header("x-bloom-ceremony-token", export_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_after_ack.status(), StatusCode::FORBIDDEN);
}
