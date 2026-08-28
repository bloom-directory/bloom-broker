"use strict";
const statusNode = document.getElementById("status");
const reviewNode = document.getElementById("review");
const approve = document.getElementById("approve");
const cancel = document.getElementById("cancel");
const recoveryFields = document.getElementById("recovery-fields");
const genericFields = document.getElementById("generic-fields");
const genericInput = document.getElementById("generic-input");
const exportFields = document.getElementById("export-fields");
const importFields = document.getElementById("import-fields");
const mnemonicInput = document.getElementById("mnemonic-input");
const passphraseInput = document.getElementById("passphrase-input");
const rawKeyInput = document.getElementById("raw-key-input");
const panelTitle = document.getElementById("panel-title");
const panelKicker = document.getElementById("panel-kicker");

// Human-readable framing for every ceremony kind. Nothing here changes what
// is signed or bound; the exact signed material stays available under
// "Signed details" and is what the passkey attests to.
const KINDS = {
  wallet_registration: {
    title: "Create a new wallet",
    summary: "A new wallet will be created on this computer. You will set up a <strong>new passkey</strong> for it now — that passkey is what approves anything this wallet does.",
    button: "Create wallet with passkey"
  },
  wallet_import: {
    title: "Import a wallet",
    summary: "The wallet you enter below will be imported and protected by a <strong>new passkey</strong> that you register now.",
    button: "Import with passkey"
  },
  wallet_export: {
    title: "Export recovery phrase",
    summary: "Reveal the recovery material for wallet <strong>{wallet}</strong>. Anyone holding it controls the wallet's funds.",
    button: "Reveal with passkey",
    warn: "Only continue on a device and screen you trust. Write the words down; do not screenshot or paste them anywhere."
  },
  wallet_delete: {
    title: "Delete wallet",
    summary: "Remove wallet <strong>{wallet}</strong> from this computer. Funds are not moved; if you have no backup, they become unreachable.",
    button: "Delete with passkey",
    warn: "This cannot be undone."
  },
  wallet_recovery: {
    title: "Recover wallet access",
    summary: "Replace the passkey for wallet <strong>{wallet}</strong> using your recovery record. You will register a new passkey now.",
    button: "Recover with passkey"
  },
  credential_add: {
    title: "Add a passkey",
    summary: "Authorize an additional passkey for wallet <strong>{wallet}</strong>. Confirm with an existing passkey, then register the new one.",
    button: "Add passkey"
  },
  credential_replace: {
    title: "Replace a passkey",
    summary: "Replace a passkey on wallet <strong>{wallet}</strong>. Confirm with an existing passkey, then register the replacement.",
    button: "Replace passkey"
  },
  account_allocate: {
    title: "Allocate a new account",
    summary: "Derive the next account for wallet <strong>{wallet}</strong> from its recovery phrase. No funds move.",
    button: "Allocate with passkey"
  },
  account_retire: {
    title: "Retire an account",
    summary: "Stop using an account of wallet <strong>{wallet}</strong> for new activity. Its address and any funds on it are unchanged.",
    button: "Retire with passkey"
  },
  policy_update: {
    title: "Change wallet rules",
    summary: "Update the policy for wallet <strong>{wallet}</strong>. This does not move money; after approval Bloom uses the new rules to decide what is allowed.",
    button: "Approve rules with passkey"
  },
  key_derive: {
    title: "Derive a key",
    summary: "Derive a scoped key from wallet <strong>{wallet}</strong>.",
    button: "Derive with passkey"
  },
  backend_enrollment: {
    title: "Enrol a signing backend",
    summary: "Bind an external signing backend to wallet <strong>{wallet}</strong>.",
    button: "Enrol with passkey"
  },
  sealed_approval: {
    title: "Approve transaction",
    summary: "Approve exactly the operation described below for wallet <strong>{wallet}</strong>. Nothing outside this plan is authorized.",
    button: "Approve with passkey"
  }
};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "html") node.innerHTML = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child == null) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  })[c]);
}
function shortDigest(value) {
  return typeof value === "string" && value.length > 16
    ? `${value.slice(0, 8)}…${value.slice(-6)}` : (value || "");
}
function fmtRemaining(ms) {
  if (ms <= 0) return "expired";
  const s = Math.ceil(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ${s % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}
let expiryTimer = null;
function startExpiry(session, node) {
  const expiresAt = Number(session.expires_at_ms ||
    session.signer_contribution?.expires_at_ms ||
    session.review_manifest?.expires_at_ms);
  if (!Number.isFinite(expiresAt) || !node) return;
  const tick = () => {
    const left = expiresAt - Date.now();
    node.textContent = left <= 0 ? "Expired — ask Bloom to start this again"
      : `Time left: ${fmtRemaining(left)}`;
    node.className = left <= 0 ? "expired" : (left < 60000 ? "expiry soon" : "expiry");
    if (left <= 0) {
      approve.disabled = true;
      statusNode.textContent = "This ceremony has expired. Nothing was changed.";
      clearInterval(expiryTimer);
    }
  };
  tick();
  expiryTimer = setInterval(tick, 1000);
}

// Amount formatting for the assets Bloom currently moves. Anything unknown is
// shown as the raw integer plus its asset name rather than guessed.
const NATIVE_UNITS = {
  solana: ["SOL", 9], ethereum: ["ETH", 18], mainnet: ["ETH", 18], base: ["ETH", 18],
  arbitrum: ["ETH", 18], optimism: ["ETH", 18], polygon: ["POL", 18], bsc: ["BNB", 18],
  avalanche: ["AVAX", 18], gnosis: ["xDAI", 18], anvil: ["ETH", 18]
};
function fmtAmount(chain, asset, raw) {
  const unit = asset === "native" ? NATIVE_UNITS[chain] : null;
  if (!unit) return `${raw} ${asset === "native" ? chain : asset}`;
  const [symbol, decimals] = unit;
  const digits = String(raw).padStart(decimals + 1, "0");
  const whole = digits.slice(0, -decimals);
  const frac = digits.slice(-decimals).replace(/0+$/, "");
  return `${whole}${frac ? "." + frac : ""} ${symbol}`;
}
function chainLabel(chain, ctx) {
  if (chain === "solana") {
    return ctx?.genesis_hash === "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
      ? "Solana mainnet" : "Solana";
  }
  return {ethereum: "Ethereum", mainnet: "Ethereum", base: "Base", arbitrum: "Arbitrum",
    optimism: "Optimism", polygon: "Polygon", anvil: "local test chain"}[chain] || chain;
}
function describeTransfer(manifest) {
  const claim = manifest?.system_use_claim || manifest?.petal_use_claim;
  if (!claim) return null;
  const debits = claim.declared_debits || [];
  const dests = claim.declared_destinations || [];
  const fee = claim.declared_fee;
  const ctx = claim.chain_context;
  const chain = debits[0]?.asset?.chain || dests[0]?.chain || ctx?.chain_family || "";
  const amounts = debits.map(d => fmtAmount(d.asset.chain, d.asset.asset, d.amount));
  const to = dests.map(d => d.destination);
  let sentence;
  if (amounts.length && to.length) {
    sentence = `Send <strong>${escapeHtml(amounts.join(" + "))}</strong> to <strong>${escapeHtml(to.join(", "))}</strong> on ${escapeHtml(chainLabel(chain, ctx))}.`;
  } else if (amounts.length) {
    sentence = `Spend up to <strong>${escapeHtml(amounts.join(" + "))}</strong> on ${escapeHtml(chainLabel(chain, ctx))}.`;
  } else {
    sentence = `Sign one operation on ${escapeHtml(chainLabel(chain, ctx))}.`;
  }
  const facts = [];
  if (amounts.length) facts.push(["Amount", amounts.join(" + ")]);
  if (to.length) facts.push(["To", to.join(", "), true]);
  if (fee && fee.kind === "fee") facts.push(["Network fee", fmtAmount(fee.chain, fee.asset, fee.amount)]);
  else if (fee && fee.amount) facts.push(["Network fee", fmtAmount(fee.chain, fee.asset, fee.amount)]);
  facts.push(["Network", chainLabel(chain, ctx)]);
  if (claim.route) facts.push(["Requested by", `Petal ${claim.route}`]);
  const assurance = claim.claim_assurance?.kind || manifest?.claim_assurance?.kind;
  if (assurance) {
    facts.push(["Checked by Bloom", assurance === "proof_verified"
      ? "yes — the transaction bytes were decoded and match this summary"
      : "no — these figures are claimed, not verified"]);
  }
  return {sentence, facts};
}
function planDisclosures(manifest) {
  try {
    const plan = JSON.parse(manifest?.canonical_plan || "{}");
    return Array.isArray(plan.security_disclosures) ? plan.security_disclosures : [];
  } catch (_) { return []; }
}

function renderReview(session) {
  const kind = session.ceremony_kind;
  const meta = KINDS[kind] || {title: kind.replace(/_/g, " "), summary: "", button: "Continue with passkey"};
  const contribution = session.signer_contribution || {};
  const wallet = contribution.wallet_id || session.review_manifest?.wallet_id || "";
  panelKicker.textContent = "Step 1 of 2 · Check";
  panelTitle.textContent = "What will happen";
  approve.textContent = meta.button;
  const pageTitle = document.getElementById("page-title");
  const pageLede = document.getElementById("page-lede");
  if (pageTitle) pageTitle.textContent = meta.title;
  if (pageLede) {
    pageLede.textContent = meta.lede ||
      "Read what will happen, then press the button. Your device will ask for your fingerprint, face, or PIN.";
  }

  const facts = el("dl", {class: "facts"});
  const fact = (label, value, mono) => {
    if (value == null || value === "") return;
    facts.append(el("dt", {}, label), el("dd", {}, mono ? el("code", {}, value) : value));
  };
  fact("Wallet", wallet);
  if (session.signer_contribution?.wallet_seed_profile === "bip39-multicurve-v1") {
    fact("Wallet type", "BIP-39 recovery phrase (multi-chain)");
  }
  if (contribution.key_ref) {
    const ref = contribution.key_ref;
    fact("Key", typeof ref === "string" ? ref : (ref.fingerprint || ref.key_id || canonicalJson(ref)), true);
  }
  if (contribution.petal_key_scope) {
    fact("Scope", canonicalJson(contribution.petal_key_scope), true);
  }
  const expiry = el("span", {class: "expiry"});
  facts.append(el("dt", {}, "Expires"), el("dd", {}, expiry));

  let summaryHtml = meta.summary.replace("{wallet}", escapeHtml(wallet || "this wallet"));
  const warns = [];
  if (kind === "sealed_approval") {
    const transfer = describeTransfer(session.review_manifest);
    if (transfer) {
      summaryHtml = transfer.sentence;
      for (const [label, value, mono] of transfer.facts) fact(label, value, mono);
    }
    for (const item of session.review_manifest?.attributed_advisory_items || []) warns.push(item);
    for (const item of planDisclosures(session.review_manifest)) warns.push(item);
  }
  const parts = [
    el("p", {class: "summary", html: summaryHtml}),
    facts
  ];
  if (meta.warn) warns.unshift(meta.warn);
  for (const w of warns) parts.push(el("p", {class: "warn"}, w));

  const signed = session.review_manifest || {
    ceremony_kind: kind, signer_contribution: session.signer_contribution
  };
  parts.push(el("details", {class: "signed"},
    el("summary", {}, "Technical details (what your passkey signs)"),
    el("pre", {}, canonicalJson(signed).replace(/,"/g, ',\n"'))));
  reviewNode.replaceChildren(...parts);
  startExpiry(session, expiry);
}

function markDone(title) {
  panelKicker.textContent = "Done";
  panelTitle.textContent = title;
  const pageTitle = document.getElementById("page-title");
  const pageLede = document.getElementById("page-lede");
  if (pageTitle) pageTitle.textContent = "All done.";
  if (pageLede) pageLede.textContent = "You can close this tab and go back to Bloom.";
}

function renderResult(session, plaintext) {
  const kind = session.ceremony_kind;
  const text = new TextDecoder().decode(plaintext).trim();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch (_) {}
  const words = text.split(/\s+/);
  const isMnemonic = !parsed && (words.length === 12 || words.length === 24) &&
    words.every(w => /^[a-z]+$/.test(w));
  const parts = [];
  markDone(isMnemonic ? "Your recovery phrase" : "Result");
  if (isMnemonic) {
    parts.push(el("p", {class: "summary"},
      `Write these ${words.length} words down, in order, and keep them offline. ` +
      "They restore this wallet on any device. Anyone who has them controls the funds."));
    parts.push(el("ol", {class: "words"}, ...words.map(w => el("li", {}, w))));
    const copy = el("button", {type: "button", class: "secondary"}, "Copy to clipboard");
    copy.onclick = async () => {
      try { await navigator.clipboard.writeText(words.join(" ")); copy.textContent = "Copied"; }
      catch (_) { copy.textContent = "Copy failed — select the words instead"; }
    };
    parts.push(el("p", {class: "warn"},
      "Clipboard contents can be read by other apps. Prefer writing the words down."));
    parts.push(el("div", {class: "result-actions"}, copy));
  } else if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    parts.push(el("h3", {class: "result-title"}, kind === "key_derive" ? "Key derived" : "Result"));
    const facts = el("dl", {class: "facts"});
    for (const [key, value] of Object.entries(parsed)) {
      const shown = typeof value === "string" ? value : canonicalJson(value);
      facts.append(el("dt", {}, key.replace(/_/g, " ")), el("dd", {}, el("code", {}, shown)));
    }
    parts.push(facts);
    parts.push(el("details", {class: "signed"},
      el("summary", {}, "Raw output"), el("pre", {}, text)));
  } else {
    parts.push(el("h3", {class: "result-title"}, "Result"));
    parts.push(el("pre", {}, text));
  }
  reviewNode.replaceChildren(...parts);
}

function renderDone(session, result) {
  const meta = KINDS[session.ceremony_kind] || {};
  const receipt = result?.receipt_digest || result?.approval_id || "";
  markDone(`${meta.title || "Ceremony"} — done`);
  reviewNode.replaceChildren(
    el("h3", {class: "result-title ok"}, `${meta.title || "Ceremony"} — done`),
    el("p", {class: "summary"}, "Your passkey approved exactly the operation shown. You can close this tab."),
    receipt ? el("dl", {class: "facts"}, el("dt", {}, "Receipt"), el("dd", {}, el("code", {}, receipt))) : null
  );
}
const tokenFromPath = location.pathname.startsWith("/ceremony/")
  ? location.pathname.slice("/ceremony/".length) : "";
const sessionTokenKey = "bloom.ceremony.token.v1";
const token = tokenFromPath || readSessionToken();
let ceremonyId = null;
if (tokenFromPath) writeSessionToken(tokenFromPath);
if (token) history.replaceState(null, "", "/");
const authHeaders = {"x-bloom-ceremony-token": token};
const te = new TextEncoder();
let outputRecipient = null;

function browserSessionStorage() {
  try { return globalThis.sessionStorage || null; } catch (_) { return null; }
}
function readSessionToken() {
  try { return browserSessionStorage()?.getItem(sessionTokenKey) || ""; }
  catch (_) { return ""; }
}
function writeSessionToken(value) {
  try { browserSessionStorage()?.setItem(sessionTokenKey, value); }
  catch (_) {}
}
function clearSessionToken() {
  try { browserSessionStorage()?.removeItem(sessionTokenKey); }
  catch (_) {}
}

function reportCeremonyError(error, fallback = "Ceremony failed") {
  console.error("Bloom ceremony failed", error);
  statusNode.textContent = fallback;
}

function reportApprovalFailure(error) {
  reportCeremonyError(error, "Passkey verification failed. Please try again.");
  approve.disabled = false;
}

const browserStateDatabase = "bloom-ceremony-browser-state-v1";
const browserStateStore = "output-recipients";

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Browser storage request failed"));
  });
}
function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(
      transaction.error || new Error("Browser storage transaction failed")
    );
    transaction.onabort = transaction.onerror;
  });
}
async function openBrowserState() {
  if (!globalThis.indexedDB) {
    throw new Error("Browser storage is unavailable; keep this ceremony in one tab");
  }
  const request = indexedDB.open(browserStateDatabase, 1);
  request.onupgradeneeded = () => {
    if (!request.result.objectStoreNames.contains(browserStateStore)) {
      request.result.createObjectStore(browserStateStore, {keyPath: "ceremonyId"});
    }
  };
  return requestResult(request);
}
async function purgeExpiredBrowserState() {
  if (!globalThis.indexedDB) return;
  let database;
  try {
    database = await openBrowserState();
    const transaction = database.transaction(browserStateStore, "readwrite");
    const done = transactionDone(transaction);
    const request = transaction.objectStore(browserStateStore).openCursor();
    await new Promise((resolve, reject) => {
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return resolve();
        if (!Number.isFinite(cursor.value.expiresAtMs) ||
            cursor.value.expiresAtMs <= Date.now()) {
          cursor.delete();
        }
        cursor.continue();
      };
      request.onerror = () => reject(
        request.error || new Error("Browser storage cleanup failed")
      );
    });
    await done;
  } catch (_) {
    // Expiry cleanup must not make an otherwise valid ceremony unavailable.
  } finally {
    database?.close();
  }
}
async function outputRecipientFor(session) {
  const keyPair = await crypto.subtle.generateKey(
    {name: "X25519"}, false, ["deriveBits"]
  );
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey)
  );
  const candidate = {
    ceremonyId: session.ceremony_id,
    expiresAtMs: Number(session.expires_at_ms),
    privateKey: keyPair.privateKey,
    publicKey: publicKey.buffer
  };
  const database = await openBrowserState();
  try {
    const transaction = database.transaction(browserStateStore, "readwrite");
    const done = transactionDone(transaction);
    const store = transaction.objectStore(browserStateStore);
    let stored = await requestResult(store.get(session.ceremony_id));
    if (!stored || !Number.isFinite(stored.expiresAtMs) ||
        stored.expiresAtMs <= Date.now()) {
      await requestResult(store.put(candidate));
      stored = candidate;
    }
    await done;
    const storedPublicKey = new Uint8Array(stored.publicKey);
    if (!stored.privateKey || storedPublicKey.length !== 32) {
      throw new Error("Stored ceremony browser key is invalid");
    }
    return {privateKey: stored.privateKey, publicKey: storedPublicKey};
  } finally {
    database.close();
  }
}
async function clearBrowserState(id) {
  clearSessionToken();
  if (!id || !globalThis.indexedDB) return;
  let database;
  try {
    database = await openBrowserState();
    const transaction = database.transaction(browserStateStore, "readwrite");
    const done = transactionDone(transaction);
    transaction.objectStore(browserStateStore).delete(id);
    await done;
  } catch (_) {
    // The ceremony is already terminal; storage cleanup is best effort.
  } finally {
    database?.close();
  }
}

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
  await purgeExpiredBrowserState();
  if (token.length !== 43) {
    throw new Error("Invalid ceremony URL");
  }
  const response = await fetch("/api/session", {headers: authHeaders});
  if (!response.ok) throw new Error("Ceremony is unavailable");
  let session = await response.json();
  ceremonyId = session.ceremony_id;
  const legacyPasskeyImport = session.ceremony_kind === "wallet_import" &&
    session.signer_contribution?.expected_input_class === "legacy_passkey_v1_prf";
  const bip39Import = session.ceremony_kind === "wallet_import" &&
    session.signer_contribution?.wallet_seed_profile === "bip39-multicurve-v1";
  if (!/^[0-9a-f]{64}$/.test(ceremonyId)) {
    throw new Error("Ceremony returned an invalid identity");
  }
  const scopedPetalKey = session.ceremony_kind === "key_derive" &&
    session.signer_contribution?.petal_key_scope;
  if ([
    "wallet_registration", "wallet_import", "wallet_export",
    "key_derive"
  ].includes(
    session.ceremony_kind
  ) && !scopedPetalKey) {
    outputRecipient = await outputRecipientFor(session);
    session = await mutate(`/api/session/${ceremonyId}/output-key`, {
      recipient_key: encodeUrl(outputRecipient.publicKey)
    });
  }
  statusNode.textContent = "Check the details, then continue with your passkey.";
  renderReview(session);
  recoveryFields.hidden = session.ceremony_kind !== "wallet_recovery";
  exportFields.hidden = session.ceremony_kind !== "wallet_export";
  importFields.hidden = !(session.ceremony_kind === "wallet_import" && !legacyPasskeyImport);
  if (!importFields.hidden) {
    document.getElementById("mnemonic-label").hidden = !bip39Import;
    document.getElementById("passphrase-label").hidden = !bip39Import;
    document.getElementById("raw-key-label").hidden = bip39Import;
  }
  // Only key derivation still takes free-form JSON; it is an operator flow.
  genericFields.hidden = session.ceremony_kind !== "key_derive" || Boolean(scopedPetalKey);
  if (!genericFields.hidden) {
    genericInput.placeholder =
      '{"namespace_id":"...","grant":{...},"authority_signature":"..."}';
  }
  approve.disabled = false;
  approve.onclick = () => run(session).catch(reportApprovalFailure);
  cancel.onclick = async () => {
    cancel.disabled = true;
    try {
      await mutate(`/api/session/${ceremonyId}/cancel`, {});
      await clearBrowserState(ceremonyId);
      statusNode.textContent = "Cancelled. You may close this tab.";
      approve.disabled = true;
    } catch (error) {
      cancel.disabled = false;
      reportCeremonyError(error, "Cancellation failed. Please try again.");
    }
  };
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
  const legacyPasskeyImport = kind === "wallet_import" &&
    session.signer_contribution?.expected_input_class === "legacy_passkey_v1_prf";
  const bip39Import = kind === "wallet_import" &&
    session.signer_contribution?.wallet_seed_profile === "bip39-multicurve-v1";
  const scopedPetalKey = kind === "key_derive" &&
    session.signer_contribution?.petal_key_scope;
  let proof;
  let secret = null;
  let credentialId = null;

  if (kind === "wallet_registration" || (kind === "wallet_import" && !legacyPasskeyImport)) {
    const created = await createCredential(session, 0);
    const prf = await ensureNewCredentialPrf(session, created, 1);
    credentialId = encodeUrl(created.rawId);
    if (kind === "wallet_import") {
      if (bip39Import) {
        const mnemonic = mnemonicInput.value.trim().toLowerCase().split(/\s+/).join(" ");
        const count = mnemonic ? mnemonic.split(" ").length : 0;
        if (count !== 12 && count !== 24) {
          throw new Error("Enter your 12 or 24 word recovery phrase");
        }
        secret = te.encode(canonicalJson({
          credential_prf: encodeUrl(prf.prf),
          mnemonic,
          passphrase: passphraseInput.value || ""
        }));
      } else {
        const rawKey = rawKeyInput.value.trim();
        if (!rawKey) throw new Error("Enter the private key to import");
        secret = te.encode(canonicalJson({
          credential_prf: encodeUrl(prf.prf),
          raw_private_key: rawKey
        }));
      }
    } else {
      secret = prf.prf;
    }
    proof = {kind: "registration", attestation: attestationJson(created),
      prf_assertion: prf.assertion};
  } else if (legacyPasskeyImport) {
    const assertion = await getCredential(session, 0);
    credentialId = encodeUrl(assertion.rawId);
    const credentialPrf = prfResult(assertion);
    if (!credentialPrf) throw new Error("This passkey did not return required PRF output");
    secret = te.encode(canonicalJson({
      credential_prf: encodeUrl(credentialPrf)
    }));
    proof = {kind: "assertion", assertion: assertionJson(assertion)};
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
    // Every custody kind whose input is just the PRF plus a typed effect.
    // The account kinds belong here: the Broker builds their exact terms from
    // the prepare request, so the browser supplies no operator input for them
    // and `genericFields` stays hidden. Omitting them left
    // `bloom wallet account-allocate` and `account-retire` unusable — the page
    // sent no custody input at all and the Broker rejected the completion.
    const genericKinds = new Set([
      "wallet_export", "wallet_delete",
      "backend_enrollment", "key_derive", "policy_update",
      "account_allocate", "account_retire"
    ]);
    if (genericKinds.has(kind)) {
      let effect = {kind};
      if (kind === "wallet_export") {
        const format = document.querySelector('input[name="export-format"]:checked')?.value;
        if (!format) throw new Error("Choose what to export");
        effect = {format, kind};
      } else if (!scopedPetalKey && !genericFields.hidden) {
        let supplied;
        try { supplied = JSON.parse(genericInput.value); }
        catch (_) { throw new Error("Advanced input must be valid JSON"); }
        if (!supplied || Array.isArray(supplied) || typeof supplied !== "object") {
          throw new Error("Advanced input must be a JSON object");
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
  statusNode.textContent = "Completed.";
  clearInterval(expiryTimer);
  for (const fields of [recoveryFields, exportFields, importFields, genericFields]) fields.hidden = true;
  cancel.hidden = true;
  approve.hidden = true;
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
    renderResult(session, plaintext);
    await mutate(`/api/session/${ceremonyId}/ack`, {});
  } else {
    renderDone(session, result);
  }
  await clearBrowserState(ceremonyId);
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
  if (!response.ok) {
    let detail = "";
    try {
      const failure = await response.json();
      detail = typeof failure?.message === "string" ? failure.message : "";
    } catch (_) {}
    throw new Error(detail || `Ceremony request failed (${response.status})`);
  }
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

load().catch(error => reportCeremonyError(
  error, "Ceremony failed to load. Please refresh and try again."
));
