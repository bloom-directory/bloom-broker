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
const rawKeyInput = document.getElementById("raw-key-input");
const panelTitle = document.getElementById("panel-title");
const panelKicker = document.getElementById("panel-kicker");

// Every standard English BIP-39 recovery-phrase length. Import and export
// must agree on the same set.
const MNEMONIC_WORD_COUNTS = [12, 15, 18, 21, 24];

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
    title: "Create a temporary app key",
    summary: "Allow an installed Petal to use a temporary key from wallet <strong>{wallet}</strong>.",
    button: "Create temporary key"
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

function chainLabel(chain, ctx) {
  if (chain === "solana") {
    return ctx?.genesis_hash === "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
      ? "Solana mainnet" : "Solana";
  }
  return {ethereum: "Ethereum", mainnet: "Ethereum", base: "Base", arbitrum: "Arbitrum",
    optimism: "Optimism", polygon: "Polygon", anvil: "local test chain"}[chain] || chain;
}
// Bloom's heading, never the descriptor's. A publisher can describe an
// argument; it cannot decide what the owner is told they are approving.
//
// Every value below comes from the typed intent Broker froze into the review
// (`intent_summary`), which the verifier derived from the decoded arguments
// under the same safety rules that produced the warnings. Nothing here reads
// a descriptor label, a field position, a publisher's intent string, a
// formatted amount or the text of a warning, and nothing decodes calldata a
// second time. A call without a typed intent stays generic rather than
// guessed at.
function shortAddress(value) {
  const text = String(value || "");
  return /^0x[0-9a-fA-F]{40}$/.test(text) ? `${text.slice(0, 6)}…${text.slice(-4)}` : text;
}
// Headings describe the requested call. None of them promise an outcome:
// Bloom has not executed anything, and a passkey response is an approval,
// not a settlement.
function callIntent(call) {
  const summary = call?.intent_summary;
  if (!summary) {
    return {
      action: "call",
      eyebrow: "Contract call",
      heading: `Call ${String(call?.function_signature || "").split("(")[0] || "this contract"}`,
      detail: "Bloom read this call against a signed description of the contract. " +
        "It has not executed the call and does not verify what the contract does.",
      relation: "calls"
    };
  }
  const who = shortAddress(summary.counterparty);
  const symbol = summary.token?.symbol || "tokens";
  if (summary.action === "transfer") {
    return {
      action: "transfer", magnitude: summary.magnitude,
      eyebrow: "Token transfer",
      heading: `Send ${summary.amount_display}`,
      detail: "",
      relation: `sends ${summary.amount_display} to`
    };
  }
  if (summary.magnitude === "unlimited") {
    return {
      action: "allowance", magnitude: "unlimited",
      eyebrow: "Token allowance",
      heading: `Allow unlimited ${symbol} spending`,
      detail: "",
      relation: `may spend any amount of ${symbol} held by`
    };
  }
  if (summary.magnitude === "zero") {
    return {
      action: "allowance", magnitude: "zero",
      eyebrow: "Token allowance",
      heading: `Set ${who}'s ${symbol} allowance to zero`,
      detail: `If this transaction executes successfully, this spender's ${symbol} allowance ` +
        "becomes zero. Nothing has been revoked yet, and no other permission this spender " +
        "holds — for another token, or granted another way — is affected.",
      relation: `loses its ${symbol} allowance from`
    };
  }
  return {
    action: "allowance", magnitude: "finite",
    eyebrow: "Token allowance",
    heading: `Allow ${who} to spend up to ${summary.amount_display}`,
    detail: "This sets the total allowance to that amount — it is not added to any allowance " +
      "already in place. The spender can use it without a new approval for each transfer.",
    relation: `may spend up to ${summary.amount_display} of`
  };
}
function formatObserved(milliseconds) {
  const value = Number(milliseconds);
  return Number.isFinite(value) ? new Date(value).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "an unknown time";
}
function describeTransfer(manifest) {
  const claim = manifest?.system_use_claim || manifest?.petal_use_claim;
  let plan = {};
  try { plan = JSON.parse(manifest?.canonical_plan || "{}"); } catch (_) {}
  const evmPayloads = Array.isArray(plan.evm_review?.payloads) ? plan.evm_review.payloads : [];
  // Primary facts state the operation a person is accountable for; technical
  // facts (identities of the exact bytes, gas pricing, ordering) stay
  // available under "Technical details" without competing for attention.
  const appendEnvelopeFacts = (facts, technical, payload, prefix) => {
    const label = name => prefix ? `${prefix} ${name.toLowerCase()}` : name;
    // The heading states the amount and the identity rows state every
    // address, so the envelope's own "to" and "amount" are the same facts a
    // second time. They stay in technical details, where the exact bytes are.
    // The one exception is native value riding along with a contract call:
    // that is a second thing being moved and nothing else says so.
    const decoded = Boolean(payload.contract_call);
    const movesNative = !/^0(\.0+)?(\s|$)/.test(String(payload.value_display || "0"));
    technical.push([label(payload.destination ? "Transaction to" : "Action"),
      payload.destination || "Deploy contract (CREATE)", Boolean(payload.destination)]);
    if (decoded && movesNative) facts.push([label("Native value sent"), payload.value_display]);
    else technical.push([label("Native value sent"), payload.value_display]);
    facts.push([label("Network"), chainLabel(payload.chain)]);
    // A ceiling on execution gas, computed by Broker from the envelope's own
    // gas limit and price in the chain's authenticated units. It is a maximum
    // for that charge, not an estimate and not a cap on every network charge.
    // When the chain's units are unknown the page says so: a missing cost
    // must not read as no cost.
    facts.push([label("Maximum execution fee"),
      payload.maximum_execution_gas_fee_display
        ? `${payload.maximum_execution_gas_fee_display} at most`
        : "Cannot be shown — Bloom has no authenticated units for this chain"]);
    if (decoded) {
      technical.push([label("Data"), `${Number(payload.calldata_bytes).toLocaleString("en-US")} bytes`]);
    } else {
      facts.push([label("Data"), payload.calldata_keccak
        ? `${payload.destination ? "Contract call" : "Initcode"}, ${Number(payload.calldata_bytes).toLocaleString("en-US")} bytes — meaning not verified`
        : "None — plain transfer"]);
    }
    technical.push([label("Sender"), payload.sender, true]);
    technical.push([label("Nonce"), payload.nonce]);
    technical.push([label("Gas limit"), payload.gas_limit]);
    if (payload.calldata_keccak) {
      technical.push([label(payload.destination ? "Calldata hash" : "Initcode hash"),
        payload.calldata_keccak, true]);
    }
    if (payload.fee?.kind === "legacy") {
      technical.push([label("Gas price"), payload.fee.gas_price_display]);
    } else if (payload.fee?.kind === "eip1559") {
      technical.push([label("Maximum fee rate"), payload.fee.max_fee_per_gas_display]);
      technical.push([label("Priority fee cap"), payload.fee.max_priority_fee_per_gas_display]);
    }
    technical.push([label("Payload commitment"), payload.payload_keccak, true]);
  };
  // A clear-signed call puts the contract's own reading first: what moves,
  // to whom, in which token. The envelope facts stay underneath — they are
  // what was actually signed, and the description never replaces them.
  const appendCallFacts = (facts, technical, payload, prefix) => {
    const call = payload.contract_call;
    const label = name => prefix ? `${prefix} ${name.toLowerCase()}` : name;
    // Complete argument coverage is a property of the review, so every
    // decoded argument is still listed even when the heading already named
    // the two that matter. The publisher's label names the argument; it does
    // not decide what the argument means.
    const summary = call.intent_summary;
    // The heading states the amount and the identity rows state the
    // counterparty, so repeating them in a table below is noise. Every other
    // decoded argument is still listed: complete coverage is a property of
    // the review, and only the two the typed intent already named are
    // dropped — never a field whose meaning is unsupported.
    for (const field of call.fields || []) {
      if (summary && field.format === "tokenAmount" && field.raw === summary.amount) continue;
      if (summary && field.raw === summary.counterparty) continue;
      facts.push([label(field.label), field.value, field.format === "addressName"]);
    }
    if (call.intent) facts.push([label("Publisher description"), call.intent]);
    technical.push([label("Function"), call.function_signature, true]);
    technical.push([label("Selector"), call.selector, true]);
    if (summary) technical.push([label("Exact amount"), summary.amount, true]);
  };
  if (evmPayloads.length) {
    const facts = [];
    const technical = [];
    const clear = plan.evm_review?.clear_signing;
    const calls = evmPayloads.filter(payload => payload.contract_call);
    for (const [index, payload] of evmPayloads.entries()) {
      const prefix = evmPayloads.length > 1 ? `Transaction ${index + 1}` : "";
      if (payload.contract_call) appendCallFacts(facts, technical, payload, prefix);
      appendEnvelopeFacts(facts, technical, payload, prefix);
    }
    // Every mandatory warning, in the order the verifier produced it, kept
    // visible rather than folded into the fact list or the details section.
    const warnings = [];
    for (const payload of calls) {
      for (const warning of payload.contract_call.warnings || []) warnings.push(warning);
    }
    const interpretation = [];
    if (clear) {
      for (const entry of clear.entries || []) {
        if (!entry.upgradeable) continue;
        warnings.push(`${entry.contract_address} can be upgraded. The publisher observed it at ` +
          `${formatObserved(entry.observed_at_ms)}; its code may have changed since.`);
      }
    }
    const first = evmPayloads[0];
    const network = chainLabel(first.chain);
    // One approval covers the whole batch, so a batch never collapses into one
    // member's heading: it says how many actions it carries and lists them in
    // order, each with its own intent.
    const intent = evmPayloads.length > 1
      ? {
          action: "batch", eyebrow: `${evmPayloads.length} transactions, in order`,
          heading: `Approve ${evmPayloads.length} transactions on ${network}`,
          detail: "One approval covers every transaction listed below. They are signed in the " +
            "order shown and there is no way to approve only part of the batch.",
          cards: evmPayloads.map((payload, index) => ({
            position: index + 1,
            intent: payload.contract_call
              ? callIntent(payload.contract_call)
              : {action: payload.destination ? "send" : "deploy",
                 eyebrow: payload.destination ? "Native transfer" : "Contract creation",
                 heading: payload.destination
                   ? `Send ${payload.value_display}` : "Deploy a contract",
                 detail: payload.destination
                   ? "Bloom checked the envelope: destination and value come from the transaction bytes."
                   : "This creates a new contract. Bloom does not verify what its code does.",
                 relation: payload.destination ? `sends ${payload.value_display} to` : "creates"},
            counterparty: payload.contract_call?.intent_summary?.counterparty || payload.destination
          }))
        }
      : first.contract_call
        ? callIntent(first.contract_call)
        : first.destination
          ? (first.calldata_keccak
            ? {action: "opaque", eyebrow: "Contract call", heading: "Approve a call Bloom cannot read",
               detail: "There is no signed description of this contract, so Bloom cannot say what " +
                 "the call does. It checked the envelope only: the destination, the value and the " +
                 "exact bytes shown below are what your passkey approves.",
               relation: "calls"}
            : {action: "send", eyebrow: "Native transfer",
               heading: `Send ${first.value_display}`,
               detail: "Bloom checked the envelope: the destination and value come from the " +
                 "transaction bytes. It has not executed anything.",
               relation: `sends ${first.value_display} to`})
          : {action: "deploy", eyebrow: "Contract creation", heading: "Deploy a contract",
             detail: "This creates a new contract from the initcode below. Bloom does not verify " +
               "what that code does.", relation: "creates"};
    const summary = first.contract_call?.intent_summary;
    const counterparty = summary?.counterparty ||
      (first.contract_call ? null : first.destination);
    const parties = [{role: "source", label: "From this wallet", value: first.sender}];
    if (counterparty) {
      parties.push({
        role: intent.action === "allowance" ? "spender"
          : intent.action === "transfer" || intent.action === "send" ? "recipient" : "contract",
        label: intent.action === "allowance" ? "Spender"
          : intent.action === "transfer" || intent.action === "send" ? "Recipient"
          : "Contract being called",
        value: counterparty
      });
    }
    // For the canonical ERC-20 actions the token is the contract being
    // called, and showing the same address twice under two headings invites
    // the reader to check it twice. One row, labelled for both. Different
    // addresses keep both roles, whatever their names say.
    if (summary?.token) {
      const sameAddress = summary.token.address.toLowerCase() ===
        String(first.contract_call.contract).toLowerCase();
      parties.push({
        role: "token",
        label: sameAddress ? "Token contract — the contract being called"
          : "Token contract",
        name: `${summary.token.symbol} — ${summary.token.name}`,
        value: summary.token.address
      });
      if (!sameAddress) {
        parties.push({role: "contract", label: "Contract being called",
          name: first.contract_call.contract_name || null,
          value: first.contract_call.contract});
      }
    } else if (first.contract_call) {
      parties.push({role: "contract", label: "Contract being called",
        name: first.contract_call.contract_name || null,
        value: first.contract_call.contract});
    }
    // One sentence, from the review rather than from matching warning text.
    const assurance = first.contract_call?.assurance ||
      (clear ? "Interpreted using a trusted signed description. Contract behavior has not been verified."
             : "Only the transaction envelope was checked: the destination, the value and the exact " +
               "bytes below. What the contract does has not been verified.");
    if (clear) {
      interpretation.push(["Catalog", `${clear.catalog_id}, sequence ${clear.catalog_sequence}`]);
      interpretation.push(["Assurance class", clear.assurance]);
      interpretation.push(["Verifier", `${clear.verifier_id} (${shortDigest(clear.verifier_digest)})`]);
      technical.push(["Catalog commitment", clear.catalog_digest, true]);
    }
    return {intent, parties, assurance, interpretation, facts, technical, warnings,
            willVerify: true};
  }
  if (!claim) return null;
  const debits = claim.declared_debits || [];
  const dests = claim.declared_destinations || [];
  const fee = claim.declared_fee;
  const ctx = claim.chain_context;
  const chain = debits[0]?.asset?.chain || dests[0]?.chain || ctx?.chain_family || "";

  // Amounts come from the server's signed review plan, never from a page-side
  // table, so the page cannot promise a unit or decimals the plan lacks. The
  // server already renders unknown assets as raw units.
  const reviewed = plan.asset_amounts || [];
  const reviewedDebits = reviewed.filter(a => a.kind === "declared_debit");
  const amounts = debits.map((d, i) => reviewedDebits[i]?.display || `${d.amount} ${d.asset.asset}`);
  const to = dests.map(d => d.destination);
  const network = chainLabel(chain, ctx);
  let sentence;
  if (amounts.length && to.length) {
    sentence = `Send <strong>${escapeHtml(amounts.join(" + "))}</strong> on ${escapeHtml(network)} to the address below.`;
  } else if (amounts.length) {
    sentence = `Spend up to <strong>${escapeHtml(amounts.join(" + "))}</strong> on ${escapeHtml(network)}.`;
  } else {
    sentence = `Sign one operation on ${escapeHtml(network)}.`;
  }
  const facts = [];
  if (to.length) facts.push(["To", to.join(", "), true]);
  if (amounts.length) facts.push(["Amount", amounts.join(" + ")]);
  if (fee && fee.amount) {
    const reviewedFee = reviewed.find(a => a.kind === "declared_fee");
    facts.push(["Estimated network fee", reviewedFee?.display || `${fee.amount} ${fee.asset}`]);
  }
  facts.push(["Network", network]);
  if (claim.route) facts.push(["Requested by", `Petal ${claim.route}`]);
  const assurance = claim.claim_assurance?.kind || manifest?.claim_assurance?.kind;
  const willVerify = assurance === "proof_verified";
  if (assurance) {
    facts.push(["Bloom verification", willVerify
      ? "Required before signing — Bloom will decode the transaction and require it to match this summary"
      : "No — these figures are claimed, not verified"]);
  }
  return {sentence, facts, willVerify};
}
// Turn a Signer key reference into "Solana account 0 (m/44'/501'/0'/0')".
function describeKey(ref) {
  if (!ref || typeof ref !== "object") return {wallet: "", account: ""};
  const wallet = ref.derivation?.wallet_seed_ref || ref.backend_instance || "";
  const path = ref.derivation?.path || "";
  let account = "";
  let m;
  if ((m = path.match(/^m\/44'\/501'\/(\d+)'/))) account = `Solana account ${m[1]} (${path})`;
  else if ((m = path.match(/^m\/44'\/60'\/(\d+)'\/0\/(\d+)/))) account = `EVM account ${m[2]} (${path})`;
  else if (path) account = path;
  else if (ref.key_spec) account = `${ref.key_spec} key ${shortDigest(ref.public_key_fingerprint || ref.locator || "")}`;
  return {wallet, account};
}
const PETAL_ACTIONS = {
  create: "create tokens",
  buy: "buy tokens",
  sell: "sell tokens",
  collect_fees: "collect fees",
  sharing_config: "manage fee sharing",
  close_token_account: "close empty token accounts",
  sweep: "return unused SOL"
};
function naturalList(items) {
  if (items.length < 2) return items[0] || "";
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items.at(-1)}`;
}
function describePetalScope(scope) {
  if (!scope || typeof scope !== "object") return null;
  const classes = Array.isArray(scope.allowed_operation_classes)
    ? scope.allowed_operation_classes.map(String) : [];
  const app = "this Petal";
  const actions = [...new Set(classes.map(value => {
    const action = value.includes(".") ? value.slice(value.indexOf(".") + 1) : value;
    return PETAL_ACTIONS[action] || action.replace(/[_-]/g, " ");
  }))];
  const lifetime = Number(scope.maximum_lifetime_ms);
  const duration = Number.isFinite(lifetime) && lifetime > 0 ? fmtRemaining(lifetime) : "a limited time";
  return {
    sentence: `Allow <strong>${app}</strong> to use a temporary Solana session key for up to <strong>${duration}</strong>. No funds move in this step, and your main wallet key stays inside Bloom.`,
    facts: [
      ["App", app],
      ["Package", scope.package_hash, true],
      ["Can", naturalList(actions)],
      ["Session lasts", `Up to ${duration}`],
      ["Main wallet key", "Stays inside Bloom"]
    ],
    button: "Create temporary key"
  };
}
function describePetalApproval(manifest) {
  let plan;
  try { plan = JSON.parse(manifest?.canonical_plan || "{}"); } catch (_) { return null; }
  const terms = plan?.terms;
  const selector = terms?.selector;
  if (selector?.kind !== "petal") return null;
  const classes = Array.isArray(selector.allowed_operation_classes)
    ? selector.allowed_operation_classes.map(String) : [];
  const app = "this Petal";
  const packageHash = terms?.subject?.package_hash || selector.package_hash || "";
  const actions = [...new Set(classes.map(value => {
    const action = value.includes(".") ? value.slice(value.indexOf(".") + 1) : value;
    return PETAL_ACTIONS[action] || action.replace(/[_-]/g, " ");
  }))];
  const operations = Number(terms?.limits?.max_operations);
  const operationLimit = Number.isSafeInteger(operations) && operations > 0
    ? `Up to ${operations} signed actions` : "Limited by the session rules";
  // The Broker sums every debit and fee per asset against these ceilings and
  // refuses any asset without one, so "none" means nothing can be spent.
  const ceilings = (Array.isArray(plan.asset_amounts) ? plan.asset_amounts : [])
    .filter(amount => amount.kind === "value_limit")
    .map(amount => amount.display);
  const spending = ceilings.length
    ? `Up to ${naturalList(ceilings)} in total across the whole session, counting fees and any funds sent back to your wallet`
    : "None — Bloom will refuse any action that spends funds or pays a fee";
  return {
    sentence: `Finish setting up a temporary <strong>${app}</strong> session. It can sign only the actions listed below until the timer expires. No funds move in this step, and your main wallet key stays inside Bloom.`,
    facts: [
      ["App", app],
      ["Package", packageHash, true],
      ["Can", naturalList(actions)],
      ["Limit", operationLimit],
      ["Spending ceiling", spending],
      ["Main wallet key", "Stays inside Bloom"]
    ],
    title: "Finish temporary session setup",
    button: "Finish session setup",
    warning: `${app} creates transactions within these permissions. If the app is compromised, it could use the remaining session capacity before the timer expires.`
  };
}
// Policy updates: say what changes, in the order a person cares about.
function describePolicy(manifest) {
  const diff = manifest?.authority_diff;
  if (!diff) return null;
  const lines = [];
  const dest = d => `${d.destination || d.address || canonicalJson(d)} (${chainLabel(d.chain)})`;
  // The "exact" sentinel on a numeric EVM chain is a contract-deployment
  // opt-in, not a destination: saying "sending to" inverts what is granted.
  const isDeployGrant = d => d.destination === "exact" && String(d.chain || "").startsWith("evm-");
  for (const d of diff.added_destinations || []) {
    if (isDeployGrant(d)) lines.push([`Allow exact transactions on ${chainLabel(d.chain)}`,
      "any address through the deployment workflow, including contract creation; every transaction still needs its own approval"]);
    else lines.push(["Allow sending to", dest(d), true]);
  }
  for (const d of diff.removed_destinations || []) {
    if (isDeployGrant(d)) lines.push([`Stop allowing exact transactions on ${chainLabel(d.chain)}`,
      "deployment transactions need listed recipients again and contract creation is refused"]);
    else lines.push(["Stop allowing sending to", dest(d), true]);
  }
  for (const p of diff.added_petal_packages || []) lines.push(["Allow app (petal)", shortDigest(p), true]);
  for (const p of diff.removed_petal_packages || []) lines.push(["Remove app (petal)", shortDigest(p), true]);
  for (const v of diff.added_required_verifiers || []) lines.push(["Require verifier", v.verifier_id || canonicalJson(v), true]);
  for (const v of diff.removed_required_verifiers || []) lines.push(["Drop verifier", v.verifier_id || canonicalJson(v), true]);
  const before = Number(diff.maximum_approval_lifetime_ms_before);
  const after = Number(diff.maximum_approval_lifetime_ms_after);
  if (Number.isFinite(before) && Number.isFinite(after) && before !== after) {
    lines.push(["Max approval lifetime", `${fmtRemaining(before)} → ${fmtRemaining(after)}`]);
  }
  // Clear-signing settings are authority, so a change to them is shown as
  // current → proposed rather than left to an empty diff. Each one says what
  // it permits: none of them grants anyone an allowance by itself.
  const CLEAR_SIGNING_SETTINGS = [
    ["unlimited_allowance_allowed", "Unlimited-allowance requests",
     "A request with no spending cap is refused outright.",
     "Each request will still need your approval. This setting does not move tokens or grant a spender an allowance."],
    ["opaque_exact_allowed", "Requests Bloom cannot describe",
     "A call with no signed description is refused.",
     "A call with no signed description can be approved as exact bytes, carrying the " +
     "inability-to-explain warning."]
  ];
  const clearBefore = diff.clear_signing?.before || null;
  const clearAfter = diff.clear_signing?.after || null;
  const intentLines = [];
  if (clearBefore || clearAfter) {
    for (const [key, title, whenOff, whenOn] of CLEAR_SIGNING_SETTINGS) {
      const was = Boolean(clearBefore?.[key]);
      const now = Boolean(clearAfter?.[key]);
      if (was === now) continue;
      lines.push([title, `${was ? "allowed" : "blocked"} → ${now ? "allowed" : "blocked"}`]);
      intentLines.push([title, now ? whenOn : whenOff]);
    }
    for (const [key, title] of [["catalog_id", "Descriptions come from catalog"],
                                ["signature_threshold", "Publisher signatures required"],
                                ["maximum_observation_age_ms", "Oldest usable observation"]]) {
      const was = clearBefore?.[key];
      const now = clearAfter?.[key];
      if (was === now || (was == null && now == null)) continue;
      lines.push([title, `${was == null ? "none" : was} → ${now == null ? "none" : now}`]);
    }
    const wasVerifier = clearBefore?.verifier?.verifier_digest;
    const nowVerifier = clearAfter?.verifier?.verifier_digest;
    if (wasVerifier !== nowVerifier) {
      lines.push(["Pinned verifier", `${shortDigest(wasVerifier) || "none"} → ${shortDigest(nowVerifier) || "none"}`, true]);
      intentLines.push(["Pinned verifier",
        "Reviews are accepted only from the build whose verifier sources hash to the new value. " +
        "A different build stops being able to describe calls for this wallet."]);
    }
  }
  const n = lines.length;
  const sentence = n === 0
    ? "No rule changes are proposed."
    : `Change <strong>${n} rule${n === 1 ? "" : "s"}</strong> for this wallet. Nothing moves; after approval Bloom applies the new rules to future transactions.`;
  const intent = n === 0 ? null : {
    action: "policy", eyebrow: "Wallet policy change",
    heading: n === 1 && intentLines.length === 1 && intentLines[0][0] === "Unlimited-allowance requests"
      ? (clearAfter?.unlimited_allowance_allowed
          ? "Allow requests for unlimited token spending"
          : "Block requests for unlimited token spending")
      : `Change ${n} wallet rule${n === 1 ? "" : "s"}`,
    detail: (intentLines.map(([, text]) => text).join(" ") ||
      "These rules apply to future requests. Approving them moves no funds.")
  };
  return {sentence, intent, facts: lines};
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
  const manifest = session.review_manifest;
  const custodyManifest = manifest?.schema === "bloom.custody_ceremony_review.v1";
  const contribution = session.signer_contribution || {};
  const wallet = contribution.wallet_id || manifest?.wallet_name || manifest?.wallet_id || "";
  panelKicker.textContent = "Step 1 of 2 · Check";
  panelTitle.textContent = "Requested action";
  panelTitle.setAttribute("data-action", "");
  panelTitle.setAttribute("data-magnitude", "");
  approve.textContent = meta.button;
  const pageTitle = document.getElementById("page-title");
  const pageLede = document.getElementById("page-lede");
  if (pageTitle) pageTitle.textContent = custodyManifest && manifest.title
    ? manifest.title : meta.title;
  if (pageLede) {
    pageLede.textContent = meta.lede ||
      "Read what will happen, then press the button. Your device will ask for your fingerprint, face, or PIN.";
  }

  const facts = el("dl", {class: "facts"});
  const fact = (label, value, mono) => {
    if (value == null || value === "") return;
    facts.append(el("dt", {}, label), el("dd", {}, mono ? el("code", {}, value) : value));
  };
  const ref = contribution.key_ref;
  const keyInfo = describeKey(ref);
  const walletName = wallet || keyInfo.wallet || "";
  let summaryHtml = custodyManifest && manifest.summary
    ? escapeHtml(manifest.summary)
    : meta.summary.replace("{wallet}", escapeHtml(walletName || "this wallet"));
  const warns = [];
  let transfer = null;
  let petalScope = null;
  let petalApproval = null;
  if (kind === "sealed_approval") {
    transfer = describeTransfer(session.review_manifest);
    if (transfer) {
      if (transfer.sentence) summaryHtml = transfer.sentence;
      // The button names what is being approved. A passkey response means
      // approved — not signed, broadcast or confirmed.
      if (transfer.intent) {
        approve.textContent = transfer.intent.action === "allowance" ? "Approve allowance"
          : transfer.intent.action === "transfer" || transfer.intent.action === "send" ? "Approve transfer"
          : transfer.intent.action === "batch" ? "Approve all transactions"
          : transfer.intent.action === "deploy" ? "Approve contract creation"
          : "Approve call";
      }
    } else {
      petalApproval = describePetalApproval(session.review_manifest);
      if (petalApproval) {
        transfer = petalApproval;
        summaryHtml = petalApproval.sentence;
        approve.textContent = petalApproval.button;
        if (pageTitle) pageTitle.textContent = petalApproval.title;
      }
    }
  } else if (kind === "policy_update") {
    transfer = describePolicy(session.review_manifest);
    if (transfer) {
      summaryHtml = transfer.sentence;
      approve.textContent = "Approve policy change";
    }
  } else if (kind === "key_derive" && contribution.petal_key_scope) {
    petalScope = describePetalScope(contribution.petal_key_scope);
    if (petalScope) {
      summaryHtml = petalScope.sentence;
      approve.textContent = petalScope.button;
    }
  }
  const contextualFacts = transfer?.intent ? new Set(["Network"]) : new Set();
  if (transfer?.intent && pageTitle) {
    const network = transfer.facts.find(([label]) => label === "Network")?.[1];
    pageTitle.textContent = [kind === "policy_update" ? "Wallet settings" : null,
      walletName, network].filter(Boolean).join(" · ");
  } else fact("Wallet", walletName);
  if (kind !== "sealed_approval" &&
      session.signer_contribution?.wallet_seed_profile === "bip39-multicurve-v1") {
    fact("Wallet type", "BIP-39 recovery phrase (multi-chain)");
  }
  if (transfer) {
    if (keyInfo.account) fact("From", keyInfo.account);
    for (const [label, value, mono] of transfer.facts) {
      if (!contextualFacts.has(label)) fact(label, value, mono);
    }
  } else if (keyInfo.account) {
    fact("Account", keyInfo.account);
  }
  if (petalScope) {
    for (const [label, value, mono] of petalScope.facts) fact(label, value, mono);
  } else if (contribution.petal_key_scope) {
    fact("Scope", canonicalJson(contribution.petal_key_scope), true);
  }
  const expiry = el("span", {class: "expiry"});
  const expiryHost = document.getElementById("action-expiry");
  if (expiryHost) expiryHost.replaceChildren(el("span", {}, "Expires "), expiry);
  else facts.append(el("dt", {}, "Expires"), el("dd", {}, expiry));
  if (kind === "sealed_approval") {
    for (const item of session.review_manifest?.attributed_advisory_items || []) warns.push(item);
    // Proof verification occurs during authorization, after this review.
    // Never suppress the plan's present-tense disclosure merely because the
    // Machine requested proof verification for the later signing step.
    if (petalApproval) warns.push(petalApproval.warning);
    else for (const item of planDisclosures(session.review_manifest)) warns.push(item);
  }
  // Reading order: what this is, who it moves value or permission to, the
  // consequences, then the supporting facts. Byte-level identity is the last
  // thing on the page and never the first.
  const partyRow = party => {
    const row = el("div", {class: "ceremony-party", "data-role": party.role},
      el("p", {class: "ceremony-party-label"}, party.label));
    if (party.name) row.append(el("p", {class: "ceremony-party-name"}, party.name));
    const address = el("code", {}, party.value);
    const copy = el("button", {type: "button", class: "ceremony-copy"}, "Copy");
    // Copies the exact address that is displayed, never a shortened form.
    copy.onclick = async () => {
      try { await navigator.clipboard.writeText(party.value); copy.textContent = "Copied"; }
      catch (_) { copy.textContent = "Select it instead"; }
    };
    row.append(el("p", {class: "ceremony-party-address"}, address, copy));
    return row;
  };
  const intentBlock = (intent, nested = false) => {
    const block = el("section", {class: "ceremony-intent", "data-action": intent.action});
    if (intent.magnitude) block.setAttribute("data-magnitude", intent.magnitude);
    if (nested) block.append(el("h2", {class: "ceremony-heading"}, intent.heading));
    if (intent.detail) block.append(el("p", {class: "ceremony-detail"}, intent.detail));
    return block;
  };
  const parts = [];
  if (transfer?.intent) {
    panelTitle.textContent = transfer.intent.heading;
    panelTitle.setAttribute("data-action", transfer.intent.action);
    panelTitle.setAttribute("data-magnitude", transfer.intent.magnitude || "");
    if (transfer.intent.detail) parts.push(intentBlock(transfer.intent));
    if (transfer.warnings?.length) {
      const warningGroup = el("aside", {class: "ceremony-warning", "aria-label": "Risks and consequences"});
      if (transfer.intent.magnitude === "unlimited") {
        warningGroup.setAttribute("data-severity", "danger");
        warningGroup.append(el("p", {class: "ceremony-warning-title"}, "If this transaction succeeds"));
      }
      for (const warning of transfer.warnings) warningGroup.append(el("p", {}, warning));
      if (transfer.intent.magnitude === "unlimited") {
        warningGroup.append(el("p", {}, "You can later request a lower allowance or set it to zero."));
      }
      parts.push(warningGroup);
    }
    for (const card of transfer.intent.cards || []) {
      const wrapper = el("section", {class: "ceremony-card"},
        el("p", {class: "ceremony-card-position"}, `Transaction ${card.position}`),
        intentBlock(card.intent, true));
      if (card.counterparty) {
        wrapper.append(el("div", {class: "ceremony-identity"},
          partyRow({role: "counterparty", label: "To", value: card.counterparty})));
      }
      parts.push(wrapper);
    }
    if (transfer.parties?.length) {
      parts.push(el("div", {class: "ceremony-identity"},
        ...[...transfer.parties].sort((a, b) =>
          Number(b.role === "spender") - Number(a.role === "spender")).map(partyRow)));
    }
  } else {
    parts.push(el("p", {class: "summary", html: summaryHtml}));
  }
  parts.push(facts);
  if (transfer?.assurance) {
    parts.push(el("p", {class: "ceremony-assurance"}, transfer.assurance));
  }
  if (meta.warn) warns.unshift(meta.warn);
  for (const w of warns) parts.push(el("p", {class: "warn"}, w));

  if (transfer?.interpretation?.length) {
    const rows = el("dl", {class: "facts"});
    for (const [label, value, mono] of transfer.interpretation) {
      rows.append(el("dt", {}, label), el("dd", {}, mono ? el("code", {}, value) : value));
    }
    parts.push(el("details", {class: "ceremony-details"},
      el("summary", {}, "How this was interpreted"),
      el("p", {}, "The catalog publisher is trusted to describe this deployment accurately, and a " +
        "signature authenticates that claim. It is not proof of what the contract does, and Bloom " +
        "did not execute anything."),
      rows));
  }
  if (transfer?.technical?.length) {
    const technical = el("dl", {class: "facts technical"});
    for (const [label, value, mono] of transfer.technical) {
      technical.append(el("dt", {}, label), el("dd", {}, mono ? el("code", {}, value) : value));
    }
    parts.push(el("details", {class: "signed technical"},
      el("summary", {}, "Technical details — nonce, fees, exact byte commitments"),
      technical));
  }
  if (kind !== "key_derive" && custodyManifest && typeof manifest.canonical_plan === "string" &&
      manifest.canonical_plan.trim()) {
    parts.push(el("details", {class: "signed ceremony-details"},
      el("summary", {}, "The exact plan that was reviewed"),
      el("pre", {}, manifest.canonical_plan)));
  }
  const signed = session.review_manifest || {
    ceremony_kind: kind, signer_contribution: session.signer_contribution
  };
  parts.push(el("details", {class: "signed"},
    el("summary", {}, "What your passkey signs (signed manifest)"),
    el("pre", {}, canonicalJson(signed).replace(/,"/g, ',\n"'))));
  const disclosures = parts.filter(node => node.tagName === "DETAILS");
  reviewNode.replaceChildren(...parts.filter(node => node.tagName !== "DETAILS"),
    el("details", {class: "ceremony-details ceremony-evidence"},
      el("summary", {}, "Verification and technical details"), ...disclosures));
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
  const isMnemonic = !parsed && MNEMONIC_WORD_COUNTS.includes(words.length) &&
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
/// Signer's raw_private_key field decodes base64url, but owners hold secp256k1
/// scalars as hex. Accept both spellings a human will realistically paste —
/// 0x-prefixed or bare, either case — and reject anything else by name.
function normalizePrivateKey(value) {
  if (!value) throw new Error("Enter the private key to import");
  const hex = /^(?:0x)?([0-9a-fA-F]{64})$/.exec(value);
  if (hex) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(hex[1].slice(2 * i, 2 * i + 2), 16);
    }
    return encodeUrl(bytes);
  }
  if (/^[A-Za-z0-9_-]{43}$/.test(value)) return value;
  throw new Error(
    "Private key must be a 32-byte secp256k1 scalar as hex (0x… or bare) or base64url"
  );
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

// Preview fixtures. Shapes match what Broker freezes into a review manifest,
// including the typed intent; nothing here is a hand-drawn mockup.
const PREVIEW_WALLET = "0x252aF4bf35C95d7d9AB3De1eB0Ee40D38DD3e5B4";
const PREVIEW_SPENDER = "0x9fE46736679d2d9a65F0992F2272dE9f3c7fa6e0";
const PREVIEW_TOKEN = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const PREVIEW_TOKEN_IDENTITY =
  {address: PREVIEW_TOKEN, symbol: "BDT", name: "Bloom Demo Token", decimals: 6};
const PREVIEW_ASSURANCE =
  "Interpreted using a trusted signed description. Contract behavior has not been verified.";
const PREVIEW_ALLOWANCE_ADVISORY =
  "An allowance lets this spender move your tokens later, with no further Bloom approval. " +
  "It does not expire when this approval expires.";
function previewPayload(extra) {
  return Object.assign({
    chain_id: "31337", chain: "anvil", sender: PREVIEW_WALLET, destination: PREVIEW_TOKEN,
    value: "0", value_display: "0 ETH", nonce: "7", gas_limit: "65410",
    fee: {kind: "eip1559", max_fee_per_gas: "3034880652", max_fee_per_gas_display: "3.03 gwei",
          max_priority_fee_per_gas: "151744032", max_priority_fee_per_gas_display: "0.15 gwei"},
    payload_keccak: "5f2a1c6b8d4e0937ab55c1e8d0f34721aa9c6b5e4d3f2a1908b7c6d5e4f302915",
    maximum_execution_gas_fee_display: "0.000198510751634520 ETH",
    calldata_bytes: "68",
    calldata_keccak: "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
  }, extra);
}
function previewClearSigning() {
  return {
    assurance: "trusted_description", verifier_id: "evm-clear-signing-v1",
    verifier_digest: "e12e0cbb6873ab1c2ef89cb2e7e41333d0238b574a4629f36ba6b16f21b38beb",
    catalog_id: "bloom-demo-tokens", catalog_sequence: "5",
    catalog_digest: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    catalog_expires_at_ms: String(Date.now() + 86400000),
    entries: [{chain_id: "31337", contract_address: PREVIEW_TOKEN,
               observed_at_ms: String(Date.now() - 3600000), upgradeable: false}]
  };
}
function previewCall(action, amount, amountDisplay, magnitude, warnings) {
  const role = action === "transfer" ? "recipient" : "spender";
  return {
    contract: PREVIEW_TOKEN, contract_name: "Bloom Demo Token",
    function_signature: action === "transfer"
      ? "transfer(address to, uint256 amount)" : "approve(address spender, uint256 amount)",
    selector: action === "transfer" ? "0xa9059cbb" : "0x095ea7b3",
    action, token: PREVIEW_TOKEN_IDENTITY, assurance: PREVIEW_ASSURANCE,
    fields: [
      {label: action === "transfer" ? "To" : "Spender", format: "addressName",
       value: PREVIEW_SPENDER, raw: PREVIEW_SPENDER},
      {label: "Amount", format: "tokenAmount", value: amountDisplay, raw: amount}
    ],
    intent_summary: {
      action, counterparty_role: role, counterparty: PREVIEW_SPENDER,
      amount, amount_display: amountDisplay, magnitude, token: PREVIEW_TOKEN_IDENTITY
    },
    warnings
  };
}
function previewApproval(payloads, clear) {
  return {
    ceremony_kind: "sealed_approval", expires_at_ms: Date.now() + 9 * 60 * 1000,
    signer_contribution: {wallet_id: "clearsign-owner"},
    review_manifest: {
      schema: "bloom.custody_ceremony_review.v1", title: "Approve a transaction",
      summary: "Review the transaction below.",
      canonical_plan: JSON.stringify({evm_review: {payloads, clear_signing: clear}})
    }
  };
}
const PREVIEWS = {
  transfer: () => previewApproval([previewPayload({
    contract_call: previewCall("transfer", "250000000", "250 BDT", "finite", [])
  })], previewClearSigning()),
  "allowance-finite": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance", "100000000", "100 BDT", "finite", [
      PREVIEW_ALLOWANCE_ADVISORY,
      "This sets the spender's total allowance to the amount shown. It is not added to any existing allowance."])
  })], previewClearSigning()),
  "allowance-zero": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance", "0", "0 BDT", "zero", [
      PREVIEW_ALLOWANCE_ADVISORY,
      "This sets the spender's allowance to zero, clearing it."])
  })], previewClearSigning()),
  "allowance-unlimited": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance",
      "115792089237316195423570985008687907853269984665640564039457584007913129639935",
      "115792089237316195423570985008687907853269984665640564039457584007913129639.935935 BDT",
      "unlimited", [
        PREVIEW_ALLOWANCE_ADVISORY,
        "UNLIMITED ALLOWANCE. This spender may move every token of this kind you now hold or later receive."])
  })], previewClearSigning()),
  "opaque-call": () => previewApproval([previewPayload({})], null),
  "native-send": () => previewApproval([previewPayload({
    destination: PREVIEW_SPENDER, value: "10000000000000000", value_display: "0.01 ETH",
    calldata_bytes: "0", calldata_keccak: undefined
  })], null),
  batch: () => previewApproval([
    previewPayload({contract_call: previewCall("allowance", "100000000", "100 BDT", "finite", [
      PREVIEW_ALLOWANCE_ADVISORY,
      "This sets the spender's total allowance to the amount shown. It is not added to any existing allowance."])}),
    previewPayload({nonce: "8",
      contract_call: previewCall("transfer", "250000000", "250 BDT", "finite", [])})
  ], previewClearSigning()),
  "long-identity": () => previewApproval([previewPayload({
    contract_call: Object.assign(
      previewCall("transfer", "1", "0.000001 BDT", "finite", []),
      {contract_name: "<script>alert(1)</script> Extremely Long Token Name That Should Wrap Rather Than Overflow",
       token: Object.assign({}, PREVIEW_TOKEN_IDENTITY,
         {name: "<b>Bloom</b> Demo Token With An Unusually Long Descriptive Name"})})
  })], previewClearSigning()),
  "policy-unlimited": () => ({
    ceremony_kind: "policy_update", expires_at_ms: Date.now() + 9 * 60 * 1000,
    signer_contribution: {wallet_id: "clearsign-owner"},
    review_manifest: {
      schema: "bloom.custody_ceremony_review.v1", title: "Approve a policy change",
      summary: "Review the policy change below.",
      authority_diff: {
        clear_signing: {
          before: {unlimited_allowance_allowed: false},
          after: {unlimited_allowance_allowed: true}
        }
      }
    }
  }),
  expiring: () => {
    const session = PREVIEWS.transfer();
    session.expires_at_ms = Date.now() + 25 * 1000;
    session.preview_status = "Preview of a ceremony close to expiry";
    session.preview_expiry = "Simulated state: expires in under a minute. Previews do not count down.";
    return session;
  },
  cancelled: () => {
    const session = PREVIEWS.transfer();
    session.preview_terminal = "cancelled";
    session.preview_status = "Cancelled";
    return session;
  }
};

// Design previews. They render through this renderer — the one the Broker
// actually serves — so what is reviewed here is what an owner sees. They
// carry no ceremony token, never reach the session API, and the approve and
// cancel controls are removed rather than disabled, so a preview cannot
// authorise anything.
function previewSession(name) {
  const fixture = PREVIEWS[name];
  if (!fixture) throw new Error(`Unknown preview: ${name}`);
  return fixture();
}
function renderPreview(name) {
  const banner = document.getElementById("preview-banner");
  if (banner) {
    banner.hidden = false;
    banner.textContent = `Preview — “${name}”. Nothing here can be approved; no ceremony exists.`;
  }
  const pageTitle = document.getElementById("page-title");
  if (pageTitle) pageTitle.textContent = "Preview";
  const pageLede = document.getElementById("page-lede");
  if (pageLede) {
    pageLede.textContent = "A rendering of the review page, drawn by the same code the Broker " +
      "serves. It authorises nothing.";
  }
  const session = previewSession(name);
  if (session.preview_terminal === "cancelled") {
    panelKicker.textContent = "Done";
    panelTitle.textContent = "Cancelled — nothing was signed";
    reviewNode.replaceChildren(el("p", {class: "summary"},
      "You cancelled this ceremony. No signature was created and nothing was broadcast."));
  } else {
    renderReview(session);
  }
  approve.hidden = true;
  cancel.hidden = true;
  // No live countdown on a page that cannot be approved. A fixture whose
  // subject is expiry states its simulated state in words instead.
  const expiryHost = document.getElementById("action-expiry");
  if (expiryHost) expiryHost.textContent = session.preview_expiry || "";
  statusNode.textContent = session.preview_status || "";
  if (pageLede) pageLede.textContent = "Review preview";
  const actions = document.querySelector(".ceremony-actions");
  if (actions) actions.hidden = !session.preview_expiry;
}

async function load() {
  if (location.pathname.startsWith("/preview")) {
    const name = location.pathname.slice("/preview".length).replace(/^\//, "") || "index";
    if (name === "index") {
      const pageTitle = document.getElementById("page-title");
      if (pageTitle) pageTitle.textContent = "Previews";
      statusNode.textContent = "Choose a preview";
      reviewNode.replaceChildren(el("ul", {class: "words"},
        ...Object.keys(PREVIEWS).map(key =>
          el("li", {}, el("a", {href: `/preview/${key}`}, key)))));
      approve.hidden = true;
      cancel.hidden = true;
      return;
    }
    renderPreview(name);
    return;
  }
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
    // Both buttons stop accepting input immediately; a slow cancel response
    // must not leave an approve button clickable beside a dead ceremony.
    cancel.disabled = true;
    approve.disabled = true;
    statusNode.textContent = "Cancelling…";
    try {
      await mutate(`/api/session/${ceremonyId}/cancel`, {});
      await clearBrowserState(ceremonyId);
      clearInterval(expiryTimer);
      panelKicker.textContent = "Done";
      panelTitle.textContent = "Cancelled — nothing was signed";
      const pageTitle = document.getElementById("page-title");
      const pageLede = document.getElementById("page-lede");
      if (pageTitle) pageTitle.textContent = "Cancelled.";
      if (pageLede) pageLede.textContent = "Nothing was signed or sent. You can close this tab.";
      reviewNode.replaceChildren(el("p", {class: "summary"},
        "You cancelled this ceremony. No signature was created and nothing was broadcast."));
      cancel.hidden = true;
      approve.hidden = true;
    } catch (error) {
      cancel.disabled = false;
      approve.disabled = false;
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
        if (!MNEMONIC_WORD_COUNTS.includes(count)) {
          throw new Error("Enter a 12, 15, 18, 21, or 24 word recovery phrase");
        }
        secret = te.encode(canonicalJson({
          credential_prf: encodeUrl(prf.prf),
          mnemonic
        }));
      } else {
        const rawKey = normalizePrivateKey(rawKeyInput.value.trim());
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
