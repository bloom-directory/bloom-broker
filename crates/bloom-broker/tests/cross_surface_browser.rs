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
await load();
assert.equal(approve.textContent, "Start recovery");
assert.match(statusNode.textContent, /expired/);
assert.equal(calls.length, 2);
process.stdout.write(JSON.stringify({ok:true}));
"#,
    );
    assert_eq!(output, json!({"ok": true}));
}

#[test]
fn public_recovery_landing_collects_only_identifiers_and_refuses_foreign_redirect() {
    let output = run_browser(
        r#"
const assert = require("node:assert/strict");
const nodes = new Map();
globalThis.document = {getElementById: id => {
  if (!nodes.has(id)) nodes.set(id, {value:"",hidden:true});
  return nodes.get(id);
}};
reviewNode.replaceChildren = () => {};
renderRecoveryBootstrap();
document.getElementById("recovery-wallet-id").value = "wallet-test";
document.getElementById("recovery-bootstrap-id").value = "recovery-test";
let destination;
location.assign = value => {destination=value;};
const expected = location.origin + "/#cap=" + "b".repeat(43);
globalThis.fetch = async (url, options) => {
  assert.equal(url, "/api/recovery/bootstrap");
  assert.deepEqual(JSON.parse(options.body), {wallet_id:"wallet-test",recovery_id:"recovery-test"});
  assert.equal(options.credentials,"same-origin");
  return {ok:true,json:async()=>({ceremony_url:expected})};
};
await approve.onclick();
assert.equal(destination, expected);
assert.equal(destination.includes("wallet-test"), false);
assert.equal(destination.includes("recovery-test"), false);
destination = undefined;
globalThis.fetch = async () => ({ok:true,json:async()=>({ceremony_url:"https://foreign.test/#cap="+"b".repeat(43)})});
await approve.onclick();
assert.equal(destination, undefined);
assert.equal(approve.disabled,false);
assert.match(statusNode.textContent,/could not start/);
assert.equal(recoveryFields.hidden,true);
process.stdout.write(JSON.stringify({ok:true}));
"#,
    );
    assert_eq!(output, json!({"ok": true}));
}

#[test]
fn boot_failure_replaces_initial_loading_heading() {
    let output = run_browser(
        r#"
const assert = require("node:assert/strict");
const heading = {textContent: "One moment…"};
globalThis.document = {getElementById: id => id === "page-title" ? heading : {}};
reportLoadFailure(new Error("unavailable"));
assert.equal(heading.textContent, "Ceremony could not load");
assert.match(statusNode.textContent, /Ceremony failed to load/);
process.stdout.write(JSON.stringify({ok:true}));
"#,
    );
    assert_eq!(output, json!({"ok": true}));
}
