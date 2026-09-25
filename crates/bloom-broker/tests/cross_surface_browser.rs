//! Browser/native HPKE interoperability and paired-enrollment bindings.
use bloom_signer::hpke::HpkeRecipient;
use bloom_signer_api::{CrossSurfaceHpkeAad, HpkeEnvelope};
use serde_json::json;
use std::process::Command;

fn browser_script(body: &str) -> String {
    let asset = include_str!("../src/ceremony_assets/app.js")
        .split_once("\nload().catch")
        .unwrap()
        .0;
    format!(
        r#"
globalThis.crypto = require("node:crypto").webcrypto;
globalThis.document = {{getElementById: () => ({{}})}};
globalThis.location = {{pathname: "/", protocol: "https:", hostname: "abcdefghijklmnopqrstuvwxyz.relay.bloom.directory", origin: "https://abcdefghijklmnopqrstuvwxyz.relay.bloom.directory", hash: ""}};
globalThis.history = {{replaceState: () => {{}}}};
{asset}
(async () => {{ {body} }})().catch(error => {{ console.error(error); process.exit(1); }});
"#
    )
}

fn run_browser(body: &str) -> serde_json::Value {
    let output = Command::new("node")
        .args(["-e", &browser_script(body)])
        .output()
        .expect("Node.js is required for shipped browser asset tests");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn prepared() -> serde_json::Value {
    json!({
        "wallet_id": "main",
        "source_surface": {"surface_id": "local", "identity_digest": "11".repeat(32)},
        "pairing": {
            "pairing_id": "22".repeat(32), "operation_id": "33".repeat(32),
            "destination_surface": {"surface_id": "remote", "identity_digest": "44".repeat(32)},
            "exact_terms_digest": "55".repeat(32), "destination_challenge": "66".repeat(32),
            "confirmation_code": "123456", "expires_at_ms": "9999999999999"
        },
        "source_challenge": {"challenge": "YQ"},
        "destination_challenges": [{"challenge": "Yg"}, {"challenge": "Yw"}],
        "source_prf_inputs": [{"credential_id": "ZA", "prf_salt": "ZQ"}],
        "destination_user_handle": "Zg", "destination_prf_salt": "Zw"
    })
}

#[test]
fn both_browser_prf_legs_decrypt_with_native_signer_hpke_and_canonical_aad() {
    for phase in ["source_prf", "destination_prf"] {
        let recipient = HpkeRecipient::generate();
        let prepared = prepared();
        let info = if phase == "source_prf" {
            "bloom-cross-surface-source-prf/v1"
        } else {
            "bloom-cross-surface-destination-prf/v1"
        };
        let output = run_browser(&format!(
            r#"
const prepared = {prepared};
const aad = crossSurfaceAad(prepared, {phase:?});
const envelope = await hpkeSeal(decodeUrl({key}), te.encode({info:?}),
  te.encode(canonicalJson(aad)), new Uint8Array(32).fill(19));
process.stdout.write(JSON.stringify({{aad, envelope, canonical: canonicalJson(aad)}}));
"#,
            key = serde_json::to_string(recipient.public_key()).unwrap(),
        ));
        let aad: CrossSurfaceHpkeAad = serde_json::from_value(output["aad"].clone()).unwrap();
        let canonical = aad.canonical_bytes().unwrap();
        assert_eq!(canonical, output["canonical"].as_str().unwrap().as_bytes());
        let envelope: HpkeEnvelope = serde_json::from_value(output["envelope"].clone()).unwrap();
        let secret = recipient
            .open(&envelope, info.as_bytes(), &canonical)
            .unwrap();
        assert_eq!(secret.expose_to_backend(), &[19; 32]);
    }
}

#[test]
fn browser_pairing_rejects_substitution_and_requires_fresh_destination_assertion() {
    let output = run_browser(&format!(
        r#"
const assert = require("node:assert/strict");
const prepared = {prepared};
const session = {{operation_id: prepared.pairing.operation_id, cross_surface: {{wallet_id: "main"}}}};
validateCrossPrepared(session, prepared, prepared.pairing.pairing_id);
for (const change of [
  p => p.wallet_id = "other", p => p.pairing.operation_id = "77".repeat(32),
  p => p.pairing.confirmation_code = "12345", p => p.pairing.expires_at_ms = "0",
  p => p.pairing.pairing_id = "88".repeat(32),
]) {{
  const changed = structuredClone(prepared); change(changed);
  assert.throws(() => validateCrossPrepared(session, changed, prepared.pairing.pairing_id));
}}
const options = crossSurfaceOptions(prepared, false);
assert.equal(requestOptions(options, 0).rpId, location.hostname);
assert.equal(requestOptions(options, 0).allowCredentials.length, 1);
const creationPrf = new Uint8Array(32).fill(3);
let asserted = 0;
Object.defineProperty(globalThis, "navigator", {{value: {{credentials: {{get: async request => {{
  asserted++;
  assert.equal(request.publicKey.rpId, location.hostname);
  assert.deepEqual(new Uint8Array(request.publicKey.challenge), te.encode(canonicalJson(prepared.destination_challenges[1])));
  return {{rawId: new Uint8Array([1]), response: {{authenticatorData: new Uint8Array([2]),
    clientDataJSON: new Uint8Array([3]), signature: new Uint8Array([4]), userHandle: null}},
    getClientExtensionResults: () => ({{prf: {{results: {{first: new Uint8Array(32).fill(5)}}}}}})}};
}}}}}}}});
const created = {{rawId: new Uint8Array([1]), getClientExtensionResults: () => ({{prf: {{results: {{first: creationPrf}}}}}})}};
const result = await ensureNewCredentialPrf(crossSurfaceOptions(prepared, true), created, 1, true);
assert.equal(asserted, 1); assert.ok(result.assertion); assert.equal(result.prf[0], 5);
const keys = await crypto.subtle.generateKey({{name: "X25519"}}, false, ["deriveBits"]);
const wrong = await crypto.subtle.generateKey({{name: "X25519"}}, false, ["deriveBits"]);
const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
const wrongPublic = new Uint8Array(await crypto.subtle.exportKey("raw", wrong.publicKey));
const aad = te.encode(canonicalJson(crossSurfaceAad(prepared, "handoff")));
const info = te.encode("bloom-cross-surface-handoff/v1");
const sealed = await hpkeSeal(publicKey, info, aad, new Uint8Array(32).fill(9));
await assert.rejects(hpkeOpen({{privateKey: wrong.privateKey, publicKey: wrongPublic}}, info, aad, sealed));
const opened = await hpkeOpen({{privateKey: keys.privateKey, publicKey}}, info, aad, sealed);
assert.equal(opened[0], 9);
const state = {{capability: opened, recipient: keys, expiresAt: Date.now()+1000}};
crossSurfaceState = state; stopCrossSurface();
assert.equal(opened[0], 0); assert.equal(state.recipient, null); assert.throws(() => requireCrossSurface(state));
process.stdout.write(JSON.stringify({{ok: true}}));
"#,
        prepared = prepared(),
    ));
    assert_eq!(output, json!({"ok": true}));
}

#[test]
fn destination_registration_excludes_the_wallets_existing_passkeys() {
    let output = run_browser(&format!(
        r#"
const assert = require("node:assert/strict");
const prepared = {prepared};
prepared.destination_existing_credentials = ["AQID", "BAUG"];
const session = {{operation_id: prepared.pairing.operation_id, cross_surface: {{wallet_id: "main"}}}};
validateCrossPrepared(session, prepared, prepared.pairing.pairing_id);
for (const bad of [["not base64!"], "AQID", [7]]) {{
  const changed = structuredClone(prepared);
  changed.destination_existing_credentials = bad;
  assert.throws(() => validateCrossPrepared(session, changed, prepared.pairing.pairing_id));
}}
assert.deepEqual(crossSurfaceOptions(prepared, false).webauthn_options.exclude_credentials, []);
let excluded = null;
Object.defineProperty(globalThis, "navigator", {{value: {{credentials: {{create: async request => {{
  excluded = request.publicKey.excludeCredentials.map(item => [item.type, [...new Uint8Array(item.id)]]);
  throw new DOMException("already registered", "InvalidStateError");
}}}}}}}});
await assert.rejects(createCredential(crossSurfaceOptions(prepared, true), 0), {{name: "InvalidStateError"}});
process.stdout.write(JSON.stringify({{excluded}}));
"#,
        prepared = prepared(),
    ));
    assert_eq!(
        output,
        json!({"excluded": [["public-key", [1, 2, 3]], ["public-key", [4, 5, 6]]]})
    );
}

#[test]
fn remote_reload_uses_scoped_cookie_reference_without_reexchanging_capability() {
    let output = run_browser(
        r#"
const assert = require("node:assert/strict");
class Node {
  constructor() { this.classList = {add: () => {}}; }
  setAttribute() {} append() {} replaceChildren() {}
}
globalThis.document = {getElementById: () => new Node(),
  createElement: () => new Node(), createTextNode: text => text};
reviewNode.replaceChildren = () => {};
const session = {ceremony_id: "11".repeat(32), operation_id: "22".repeat(32),
  ceremony_kind: "credential_add", expires_at_ms: Date.now() + 1000};
const reference = {ceremony_id: session.ceremony_id, csrf: "a".repeat(43), expires_at: Date.now()+60000};
const stored = new Map([["bloom.ceremony.remote-session.v1", JSON.stringify(reference)]]);
globalThis.sessionStorage = {getItem: key => stored.get(key),
  setItem: (key, value) => stored.set(key,value), removeItem: key => stored.delete(key)};
const calls = [];
globalThis.fetch = async (url, options) => {
  calls.push(url);
  assert.equal(options.credentials, "same-origin");
  assert.equal(options.headers["x-bloom-csrf"], reference.csrf);
  if (url === `/api/session/${session.ceremony_id}`) return {ok:true, json:async()=>session};
  if (url.endsWith("/result")) return {ok:true, json:async()=>({receipt_digest: "33".repeat(32)})};
  throw new Error("unexpected request " + url);
};
await load();
assert.deepEqual(calls, [`/api/session/${session.ceremony_id}`, `/api/session/${session.ceremony_id}/result`]);
assert.equal(stored.size, 0);
stored.set("bloom.ceremony.remote-session.v1", JSON.stringify({...reference, expires_at: 0}));
await assert.rejects(load(), /expired/);
assert.equal(calls.length, 2);
process.stdout.write(JSON.stringify({ok:true}));
"#,
    );
    assert_eq!(output, json!({"ok": true}));
}

#[test]
fn ceremony_asset_has_no_public_recovery_initiation() {
    let asset = include_str!("../src/ceremony_assets/app.js");
    let html = include_str!("../src/ceremony_assets/index.html");
    assert!(!asset.contains("/api/recovery/bootstrap"));
    assert!(!html.contains("recovery-bootstrap"));
}

#[test]
fn launch_failures_show_one_neutral_page_and_hide_all_stale_controls() {
    let html = include_str!("../src/ceremony_assets/index.html");
    for id in [
        "ceremony-page",
        "ceremony-panel",
        "ceremony-eyebrow",
        "ceremony-trust",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")));
    }
    let output = run_browser(
        r#"
const assert = require("node:assert/strict");
const nodes = new Map();
const pageClasses = new Set();
const node = id => {
  if (!nodes.has(id)) nodes.set(id, {hidden:false, textContent:"", classList:{add: name => pageClasses.add(name)}});
  return nodes.get(id);
};
globalThis.document = {getElementById: node, querySelectorAll: () => inputs};
const inputs = [{value:"wallet-secret"}, {value:"recovery-secret"}];
const stored = new Map([["bloom.ceremony.remote-session.v1", "saved-session"]]);
globalThis.sessionStorage = {getItem: key => stored.get(key), removeItem: key => stored.delete(key)};
let reviewClears = 0;
reviewNode.replaceChildren = () => { reviewClears += 1; };
const logged = [];
console.error = (...args) => logged.push(args);
const results = [];
for (const message of ["expired wallet alpha", "already used operation beta", "network failed with secret gamma"]) {
  const retainedOutput = {privateKey:"saved-browser-result-key"};
  outputRecipient = retainedOutput;
  expiryTimer = setInterval(() => {}, 1000);
  const capability = new Uint8Array([7]);
  crossSurfaceState = {poll:null, expiry:null, capability, recipient:{}};
  approve.disabled = false; cancel.disabled = false;
  approve.onclick = () => {}; cancel.onclick = () => {};
  for (const fields of [recoveryFields, exportFields, importFields, genericFields]) fields.hidden = false;
  for (const input of inputs) input.value = "stale-secret";
  statusNode.textContent = "wallet alpha operation beta";
  reportLoadFailure(new Error(message));
  results.push({
    title: node("page-title").textContent,
    lede: node("page-lede").textContent,
    panelHidden: node("ceremony-panel").hidden,
    eyebrowHidden: node("ceremony-eyebrow").hidden,
    trustHidden: node("ceremony-trust").hidden,
    pageClass: pageClasses.has("link-unavailable"),
    actionsDisabled: approve.disabled && cancel.disabled && approve.onclick === null && cancel.onclick === null,
    fieldsHidden: [recoveryFields, exportFields, importFields, genericFields].every(field => field.hidden),
    inputsCleared: inputs.every(input => input.value === ""),
    statusCleared: statusNode.textContent === "",
    pairingStopped: crossSurfaceState === null && capability[0] === 0,
    outputRetained: outputRecipient === retainedOutput,
    sessionRetained: stored.get("bloom.ceremony.remote-session.v1") === "saved-session",
    timerStopped: expiryTimer === null
  });
}
assert.deepEqual(results[0], results[1]);
assert.deepEqual(results[1], results[2]);
assert.equal(results[0].title, "This link couldn’t be opened");
assert.equal(results[0].lede, "It may have expired or already been used. Generate a new link in Bloom, or ask your agent to generate one.");
for (const [key, value] of Object.entries(results[0])) {
  if (typeof value === "boolean") assert.equal(value, true, key);
}
assert.equal(reviewClears, 3);
assert.deepEqual(logged, []);
process.stdout.write(JSON.stringify({ok:true}));
"#,
    );
    assert_eq!(output, json!({"ok": true}));
}

#[test]
fn unstorable_output_key_stays_in_the_page_without_weakening_it() {
    let output = run_browser(
        r#"
const assert = require("node:assert/strict");
const records = new Map();
let putFailure = null;
const pending = result => {
  const request = {result};
  queueMicrotask(() => request.onsuccess?.());
  return request;
};
const store = {
  get: id => pending(records.get(id)),
  put: record => {
    if (putFailure) throw Object.assign(new Error("cannot store record"), {name: putFailure});
    records.set(record.ceremonyId, record);
    return pending(record.ceremonyId);
  }
};
const database = {
  objectStoreNames: {contains: () => true},
  close: () => {},
  transaction: () => {
    const transaction = {objectStore: () => store};
    setTimeout(() => transaction.oncomplete?.(), 0);
    return transaction;
  }
};
globalThis.indexedDB = {open: () => pending(database)};
const session = {ceremony_id: "ab".repeat(32), expires_at_ms: String(Date.now() + 60_000)};

// iOS Safari 27 throws while cloning an X25519 CryptoKey into IndexedDB.
putFailure = "DataError";
const memory = await outputRecipientFor(session);
assert.equal(records.size, 0);
assert.equal(memory.privateKey.extractable, false);
assert.equal(memory.publicKey.length, 32);
const peer = await crypto.subtle.generateKey({name: "X25519"}, false, ["deriveBits"]);
const shared = await crypto.subtle.deriveBits(
  {name: "X25519", public: await crypto.subtle.importKey("raw", memory.publicKey, {name: "X25519"}, true, [])},
  peer.privateKey, 256
);
assert.equal(shared.byteLength, 32);
await assert.rejects(outputRecipientFor(session, true), /original result recipient is unavailable/);

// Browsers that can store the key keep reusing the one bound key.
putFailure = null;
const bound = await outputRecipientFor(session);
assert.equal(records.size, 1);
assert.equal((await outputRecipientFor(session, true)).privateKey, bound.privateKey);

// Storage failures unrelated to cloning the key still fail the ceremony.
records.clear();
putFailure = "QuotaExceededError";
await assert.rejects(outputRecipientFor(session), {name: "QuotaExceededError"});
process.stdout.write(JSON.stringify({ok:true}));
"#,
    );
    assert_eq!(output, json!({"ok": true}));
}
