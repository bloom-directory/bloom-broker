"use strict";
const statusNode = document.getElementById("status");
const reviewNode = document.getElementById("review");
const approve = document.getElementById("approve");
const cancel = document.getElementById("cancel");
const recoveryFields = document.getElementById("recovery-fields");
const genericFields = document.getElementById("generic-fields");
const genericInput = document.getElementById("generic-input");
const token = location.pathname.startsWith("/ceremony/")
  ? location.pathname.slice("/ceremony/".length) : "";
let ceremonyId = null;
history.replaceState(null, "", "/");
const authHeaders = {"x-bloom-ceremony-token": token};
const te = new TextEncoder();
let outputRecipient = null;

function concat(...parts) {
  const size = parts.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function decodeUrl(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") +
    "===".slice((value.length + 3) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
function encodeUrl(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function assertionJson(credential) {
  return {
    credential_id: encodeUrl(credential.rawId),
    authenticator_data: encodeUrl(credential.response.authenticatorData),
    client_data_json: encodeUrl(credential.response.clientDataJSON),
    signature: encodeUrl(credential.response.signature),
    user_handle: credential.response.userHandle
      ? encodeUrl(credential.response.userHandle) : null
  };
}
function attestationJson(credential) {
  return {
    credential_id: encodeUrl(credential.rawId),
    client_data_json: encodeUrl(credential.response.clientDataJSON),
    attestation_object: encodeUrl(credential.response.attestationObject),
    transports: typeof credential.response.getTransports === "function"
      ? credential.response.getTransports() : []
  };
}
function prfResult(credential) {
  const first = credential.getClientExtensionResults()?.prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}
function requestOptions(session, phase, restrictTo) {
  const options = session.webauthn_options;
  const allowed = options.allowed_credentials
    .filter(item => !restrictTo || item.credential_id === restrictTo);
  const evalByCredential = {};
  for (const item of allowed) {
    evalByCredential[item.credential_id] = {first: decodeUrl(item.prf_salt)};
  }
  return {
    challenge: decodeUrl(session.challenges[phase].challenge),
    rpId: "localhost",
    userVerification: "required",
    allowCredentials: allowed.map(item => ({
      type: "public-key", id: decodeUrl(item.credential_id)
    })),
    extensions: {prf: {evalByCredential}}
  };
}
async function getCredential(session, phase, restrictTo) {
  return navigator.credentials.get({
    publicKey: requestOptions(session, phase, restrictTo)
  });
}
async function createCredential(session, phase) {
  const options = session.webauthn_options;
  const credential = await navigator.credentials.create({publicKey: {
    challenge: decodeUrl(session.challenges[phase].challenge),
    rp: {id: "localhost", name: "Bloom"},
    user: {
      id: decodeUrl(options.registration_user_handle),
      name: `bloom-${session.operation_id.slice(0, 12)}`,
      displayName: "Bloom wallet"
    },
    pubKeyCredParams: [{type: "public-key", alg: -7}],
    timeout: 120000,
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required"
    },
    attestation: "none",
    extensions: {
      credProps: true,
      prf: {eval: {first: decodeUrl(options.registration_prf_salt)}}
    }
  }});
  return credential;
}
async function ensureNewCredentialPrf(session, credential, confirmPhase) {
  const creationPrf = prfResult(credential);
  if (creationPrf) return {prf: creationPrf, assertion: null};
  const confirmation = await navigator.credentials.get({publicKey: {
    challenge: decodeUrl(session.challenges[confirmPhase].challenge),
    rpId: "localhost",
    userVerification: "required",
    allowCredentials: [{type: "public-key", id: credential.rawId}],
    extensions: {prf: {eval: {
      first: decodeUrl(session.webauthn_options.registration_prf_salt)
    }}}
  }});
  const result = prfResult(confirmation);
  if (!result) throw new Error("This passkey did not return required PRF output");
  return {prf: result, assertion: assertionJson(confirmation)};
}

async function load() {
  await cryptoSelfTest();
  if (token.length !== 43) {
    throw new Error("Invalid ceremony URL");
  }
  const response = await fetch("/api/session", {headers: authHeaders});
  if (!response.ok) throw new Error("Ceremony is unavailable");
  let session = await response.json();
  ceremonyId = session.ceremony_id;
  if (!/^[0-9a-f]{64}$/.test(ceremonyId)) {
    throw new Error("Ceremony returned an invalid identity");
  }
  if ([
    "wallet_registration", "wallet_import", "wallet_export",
    "key_derive"
  ].includes(
    session.ceremony_kind
  )) {
    const keyPair = await crypto.subtle.generateKey(
      {name: "X25519"}, true, ["deriveBits"]
    );
    const publicKey = new Uint8Array(
      await crypto.subtle.exportKey("raw", keyPair.publicKey)
    );
    session = await mutate(`/api/session/${ceremonyId}/output-key`, {
      recipient_key: encodeUrl(publicKey)
    });
    outputRecipient = {privateKey: keyPair.privateKey, publicKey};
  }
  statusNode.textContent = "Review every item before continuing.";
  const pre = document.createElement("pre");
  pre.textContent = session.review_manifest?.canonical_plan ||
    (session.review_manifest
      ? canonicalJson(session.review_manifest)
      : canonicalJson({
          ceremony_kind: session.ceremony_kind,
          signer_contribution: session.signer_contribution
        }));
  reviewNode.replaceChildren(pre);
  recoveryFields.hidden = session.ceremony_kind !== "wallet_recovery";
  const typedInputKinds = new Set([
    "wallet_import", "key_derive"
  ]);
  genericFields.hidden = !typedInputKinds.has(session.ceremony_kind);
  if (session.ceremony_kind === "wallet_import") {
    genericInput.placeholder = '{"raw_private_key":"base64url-encoded-key"}';
  } else if (session.ceremony_kind === "key_derive") {
    genericInput.placeholder =
      '{"namespace_id":"...","grant":{...},"authority_signature":"..."}';
  }
  approve.disabled = false;
  approve.onclick = () => run(session);
  cancel.onclick = () => mutate(`/api/session/${ceremonyId}/cancel`, {});
}

function fromHex(value) {
  if (value.length % 2) throw new Error("Invalid crypto test vector");
  return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
}
async function cryptoSelfTest() {
  const key = fromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const nonce = fromHex("070000004041424344454647");
  const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
  const plaintext = te.encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  );
  const expected = fromHex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
  );
  const actual = chacha20Poly1305Seal(key, nonce, aad, plaintext);
  if (actual.length !== expected.length ||
      actual.some((byte, index) => byte !== expected[index])) {
    throw new Error("Browser cryptography self-test failed");
  }
  const keyPair = await crypto.subtle.generateKey(
    {name: "X25519"}, true, ["deriveBits"]
  );
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey)
  );
  const info = te.encode("bloom-browser-hpke-self-test/v1");
  const hpkeAad = te.encode('{"self_test":true}');
  const hpkePlaintext = te.encode("bloom-hpke-round-trip");
  const envelope = await hpkeSeal(publicKey, info, hpkeAad, hpkePlaintext);
  const opened = await hpkeOpen(
    {privateKey: keyPair.privateKey, publicKey}, info, hpkeAad, envelope
  );
  if (opened.length !== hpkePlaintext.length ||
      opened.some((byte, index) => byte !== hpkePlaintext[index])) {
    throw new Error("Browser HPKE self-test failed");
  }
}

async function run(session) {
  approve.disabled = true;
  statusNode.textContent = "Waiting for passkey verification…";
  const kind = session.ceremony_kind;
  let proof;
  let secret = null;
  let credentialId = null;

  if (kind === "wallet_registration" || kind === "wallet_import") {
    const created = await createCredential(session, 0);
    const prf = await ensureNewCredentialPrf(session, created, 1);
    credentialId = encodeUrl(created.rawId);
    if (kind === "wallet_import") {
      const supplied = JSON.parse(genericInput.value);
      if (!supplied || Array.isArray(supplied) ||
          typeof supplied.raw_private_key !== "string") {
        throw new Error("Raw private key input is required");
      }
      secret = te.encode(canonicalJson({
        credential_prf: encodeUrl(prf.prf),
        raw_private_key: supplied.raw_private_key
      }));
    } else {
      secret = prf.prf;
    }
    proof = {kind: "registration", attestation: attestationJson(created),
      prf_assertion: prf.assertion};
  } else if (kind === "wallet_recovery") {
    const created = await createCredential(session, 0);
    const newPrf = await ensureNewCredentialPrf(session, created, 1);
    credentialId = encodeUrl(created.rawId);
    const recoveryId = document.getElementById("recovery-id").value.trim();
    const recoverySecret = document.getElementById("recovery-secret").value.trim();
    if (!recoveryId || !recoverySecret) throw new Error("Recovery factor is required");
    secret = te.encode(canonicalJson({
      new_credential_prf: encodeUrl(newPrf.prf),
      recovery_id: recoveryId,
      recovery_secret: recoverySecret
    }));
    proof = {kind: "recovery_credential_change",
      new_credential_attestation: attestationJson(created),
      new_credential_prf_assertion: newPrf.assertion};
  } else if (kind === "credential_add" || kind === "credential_replace") {
    const authority = await getCredential(session, 0);
    const authorityPrf = prfResult(authority);
    if (!authorityPrf) throw new Error("Existing passkey did not return PRF output");
    const created = await createCredential(session, 1);
    const newPrf = await ensureNewCredentialPrf(session, created, 2);
    credentialId = encodeUrl(created.rawId);
    secret = te.encode(JSON.stringify({
      authority_prf: encodeUrl(authorityPrf),
      new_credential_prf: encodeUrl(newPrf.prf)
    }));
    proof = {kind: "authority_credential_change",
      authority_assertion: assertionJson(authority),
      new_credential_attestation: attestationJson(created),
      new_credential_prf_assertion: newPrf.assertion};
  } else {
    const assertion = await getCredential(session, 0);
    credentialId = encodeUrl(assertion.rawId);
    const credentialPrf = prfResult(assertion);
    if (!credentialPrf) throw new Error("This passkey did not return required PRF output");
    const genericKinds = new Set([
      "wallet_export", "wallet_delete",
      "backend_enrollment", "key_derive", "policy_update"
    ]);
    if (genericKinds.has(kind)) {
      let effect = {kind};
      if (!genericFields.hidden) {
        const supplied = JSON.parse(genericInput.value);
        if (!supplied || Array.isArray(supplied) || typeof supplied !== "object") {
          throw new Error("Custody input must be a JSON object");
        }
        effect = {...supplied, kind};
      }
      secret = te.encode(canonicalJson({
        credential_prf: encodeUrl(credentialPrf),
        effect
      }));
    } else {
      secret = credentialPrf;
    }
    proof = {kind: "assertion", assertion: assertionJson(assertion)};
  }

  const contribution = session.signer_contribution;
  const recipient = contribution.ephemeral_encryption_public_key ||
    contribution.hpke_recipient_key;
  let encryptedInput = null;
  if (recipient && secret) {
    const aad = hpkeAad(session, contribution, credentialId);
    const info = kind === "sealed_approval"
      ? "bloom-local-prf/v1" : "bloom-custody-input/v1";
    encryptedInput = await hpkeSeal(
      decodeUrl(recipient), te.encode(info), te.encode(canonicalJson(aad)), secret
    );
  }
  let result;
  try {
    result = await mutate(`/api/session/${ceremonyId}/complete`, {
      proof,
      encrypted_input: encryptedInput,
      public_binding_digest: session.challenges[0].binding.exact_terms_digest
    });
  } catch (error) {
    const recovered = await fetch(`/api/session/${ceremonyId}/result`, {
      headers: authHeaders
    });
    if (!recovered.ok) throw error;
    result = await recovered.json();
  }
  statusNode.textContent = "Completed. You may close this tab.";
  if (result.encrypted_browser_result) {
    if (!outputRecipient) throw new Error("Browser output key is unavailable");
    const outputAad = canonicalJson({
      ceremony_id: contribution.ceremony_id,
      ceremony_kind: contribution.ceremony_kind,
      custody_operation_id: contribution.custody_operation_id,
      public_binding_digest: session.challenges[0].binding.exact_terms_digest,
      signer_contribution_digest:
        session.challenges[0].binding.signer_contribution_digest
    });
    const plaintext = await hpkeOpen(
      outputRecipient,
      te.encode("bloom-custody-output/v1"),
      te.encode(outputAad),
      result.encrypted_browser_result
    );
    reviewNode.textContent = new TextDecoder().decode(plaintext);
    await mutate(`/api/session/${ceremonyId}/ack`, {});
  } else {
    reviewNode.textContent = result.receipt_digest || result.approval_id || "";
  }
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map(
    key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  ).join(",")}}`;
}

function hpkeAad(session, contribution, credentialId) {
  if (session.ceremony_kind === "sealed_approval") {
    return {
      activation_mode: contribution.activation_mode,
      allowed_crypto_suites: contribution.allowed_crypto_suites,
      approval_digest: contribution.approval_digest,
      approval_id: session.review_manifest.approval_id,
      ceremony_id: contribution.ceremony_id,
      credential_id: credentialId,
      key_ref: contribution.key_ref,
      review_manifest_digest: contribution.review_manifest_digest,
      signer_nonce: contribution.signer_nonce,
      wallet_revocation_epoch: contribution.wallet_revocation_epoch
    };
  }
  return {
    ceremony_id: contribution.ceremony_id,
    ceremony_kind: contribution.ceremony_kind,
    credential_id: credentialId,
    custody_operation_id: contribution.custody_operation_id,
    expected_input_class: contribution.expected_input_class,
    key_ref: contribution.key_ref,
    signer_contribution_digest: session.challenges[0].binding.signer_contribution_digest,
    signer_nonce: contribution.signer_nonce,
    wallet_id: contribution.wallet_id
  };
}

async function mutate(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: {...authHeaders, "content-type": "application/json"},
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error("Ceremony request failed");
  return response.status === 204 ? null : response.json();
}

// RFC 9180 base mode:
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
async function hpkeSeal(recipientRaw, info, aad, plaintext) {
  const recipient = await crypto.subtle.importKey(
    "raw", recipientRaw, {name: "X25519"}, false, []
  );
  const ephemeral = await crypto.subtle.generateKey(
    {name: "X25519"}, true, ["deriveBits"]
  );
  const enc = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const dh = new Uint8Array(await crypto.subtle.deriveBits(
    {name: "X25519", public: recipient}, ephemeral.privateKey, 256
  ));
  const kemSuite = concat(te.encode("KEM"), u16(0x0020));
  const eaePrk = await labeledExtract(new Uint8Array(), kemSuite, "eae_prk", dh);
  const sharedSecret = await labeledExpand(
    eaePrk, kemSuite, "shared_secret", concat(enc, recipientRaw), 32
  );
  const suite = concat(te.encode("HPKE"), u16(0x0020), u16(0x0001), u16(0x0003));
  const pskIdHash = await labeledExtract(new Uint8Array(), suite, "psk_id_hash", new Uint8Array());
  const infoHash = await labeledExtract(new Uint8Array(), suite, "info_hash", info);
  const context = concat(new Uint8Array([0]), pskIdHash, infoHash);
  const secret = await labeledExtract(sharedSecret, suite, "secret", new Uint8Array());
  const key = await labeledExpand(secret, suite, "key", context, 32);
  const nonce = await labeledExpand(secret, suite, "base_nonce", context, 12);
  const ciphertext = chacha20Poly1305Seal(key, nonce, aad, plaintext);
  return {kem_output: encodeUrl(enc), ciphertext: encodeUrl(ciphertext)};
}
async function hpkeOpen(recipient, info, aad, envelope) {
  const enc = decodeUrl(envelope.kem_output);
  const sender = await crypto.subtle.importKey(
    "raw", enc, {name: "X25519"}, false, []
  );
  const dh = new Uint8Array(await crypto.subtle.deriveBits(
    {name: "X25519", public: sender}, recipient.privateKey, 256
  ));
  const kemSuite = concat(te.encode("KEM"), u16(0x0020));
  const eaePrk = await labeledExtract(new Uint8Array(), kemSuite, "eae_prk", dh);
  const sharedSecret = await labeledExpand(
    eaePrk, kemSuite, "shared_secret", concat(enc, recipient.publicKey), 32
  );
  const suite = concat(te.encode("HPKE"), u16(0x0020), u16(0x0001), u16(0x0003));
  const pskIdHash = await labeledExtract(
    new Uint8Array(), suite, "psk_id_hash", new Uint8Array()
  );
  const infoHash = await labeledExtract(new Uint8Array(), suite, "info_hash", info);
  const context = concat(new Uint8Array([0]), pskIdHash, infoHash);
  const secret = await labeledExtract(sharedSecret, suite, "secret", new Uint8Array());
  const key = await labeledExpand(secret, suite, "key", context, 32);
  const nonce = await labeledExpand(secret, suite, "base_nonce", context, 12);
  return chacha20Poly1305Open(key, nonce, aad, decodeUrl(envelope.ciphertext));
}
async function hmac(key, data) {
  const actualKey = key.length ? key : new Uint8Array(32);
  const imported = await crypto.subtle.importKey(
    "raw", actualKey, {name: "HMAC", hash: "SHA-256"}, false, ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, data));
}
async function labeledExtract(salt, suite, label, ikm) {
  return hmac(salt, concat(te.encode("HPKE-v1"), suite, te.encode(label), ikm));
}
async function labeledExpand(prk, suite, label, info, length) {
  return hkdfExpand(prk, concat(
    u16(length), te.encode("HPKE-v1"), suite, te.encode(label), info
  ), length);
}
async function hkdfExpand(prk, info, length) {
  let previous = new Uint8Array();
  let output = new Uint8Array();
  for (let counter = 1; output.length < length; counter++) {
    previous = await hmac(prk, concat(previous, info, new Uint8Array([counter])));
    output = concat(output, previous);
  }
  return output.slice(0, length);
}
function u16(value) {
  return new Uint8Array([value >>> 8, value & 255]);
}
function u64le(value) {
  let n = BigInt(value);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { out[i] = Number(n & 255n); n >>= 8n; }
  return out;
}
function read32le(bytes, offset) {
  return (bytes[offset] | bytes[offset + 1] << 8 |
    bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
}
function write32le(out, offset, value) {
  out[offset] = value; out[offset + 1] = value >>> 8;
  out[offset + 2] = value >>> 16; out[offset + 3] = value >>> 24;
}
function rotl(value, shift) {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}
function quarter(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl(state[b] ^ state[c], 7);
}
function chachaBlock(key, counter, nonce) {
  const initial = new Uint32Array(16);
  initial.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let i = 0; i < 8; i++) initial[4 + i] = read32le(key, i * 4);
  initial[12] = counter;
  initial[13] = read32le(nonce, 0);
  initial[14] = read32le(nonce, 4);
  initial[15] = read32le(nonce, 8);
  const state = new Uint32Array(initial);
  for (let i = 0; i < 10; i++) {
    quarter(state, 0, 4, 8, 12); quarter(state, 1, 5, 9, 13);
    quarter(state, 2, 6, 10, 14); quarter(state, 3, 7, 11, 15);
    quarter(state, 0, 5, 10, 15); quarter(state, 1, 6, 11, 12);
    quarter(state, 2, 7, 8, 13); quarter(state, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) write32le(out, i * 4, (state[i] + initial[i]) >>> 0);
  return out;
}
function chachaXor(key, nonce, plaintext) {
  const out = new Uint8Array(plaintext.length);
  for (let offset = 0, counter = 1; offset < plaintext.length; offset += 64, counter++) {
    const block = chachaBlock(key, counter, nonce);
    for (let i = 0; i < Math.min(64, plaintext.length - offset); i++) {
      out[offset + i] = plaintext[offset + i] ^ block[i];
    }
  }
  return out;
}
function littleBigInt(bytes) {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) out = (out << 8n) | BigInt(bytes[i]);
  return out;
}
function bigintLittle(value, length) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) { out[i] = Number(value & 255n); value >>= 8n; }
  return out;
}
function pad16(bytes) {
  const remainder = bytes.length % 16;
  return remainder ? new Uint8Array(16 - remainder) : new Uint8Array();
}
function poly1305(message, oneTimeKey) {
  const r = littleBigInt(oneTimeKey.slice(0, 16)) &
    0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const s = littleBigInt(oneTimeKey.slice(16, 32));
  const modulus = (1n << 130n) - 5n;
  let accumulator = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const block = message.slice(offset, offset + 16);
    const n = littleBigInt(block) + (1n << BigInt(block.length * 8));
    accumulator = ((accumulator + n) * r) % modulus;
  }
  return bigintLittle((accumulator + s) & ((1n << 128n) - 1n), 16);
}
function chacha20Poly1305Seal(key, nonce, aad, plaintext) {
  const oneTimeKey = chachaBlock(key, 0, nonce).slice(0, 32);
  const ciphertext = chachaXor(key, nonce, plaintext);
  const macInput = concat(
    aad, pad16(aad), ciphertext, pad16(ciphertext),
    u64le(aad.length), u64le(ciphertext.length)
  );
  return concat(ciphertext, poly1305(macInput, oneTimeKey));
}
function chacha20Poly1305Open(key, nonce, aad, sealed) {
  if (sealed.length < 16) throw new Error("Encrypted Browser result is truncated");
  const ciphertext = sealed.slice(0, -16);
  const suppliedTag = sealed.slice(-16);
  const oneTimeKey = chachaBlock(key, 0, nonce).slice(0, 32);
  const macInput = concat(
    aad, pad16(aad), ciphertext, pad16(ciphertext),
    u64le(aad.length), u64le(ciphertext.length)
  );
  const expectedTag = poly1305(macInput, oneTimeKey);
  let difference = 0;
  for (let i = 0; i < 16; i++) difference |= suppliedTag[i] ^ expectedTag[i];
  if (difference !== 0) throw new Error("Encrypted Browser result authentication failed");
  return chachaXor(key, nonce, ciphertext);
}

load().catch(error => {
  statusNode.textContent = error instanceof Error ? error.message : "Ceremony failed";
});
