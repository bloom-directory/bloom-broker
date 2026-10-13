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
const cardFields = document.getElementById("card-fields");
const cardCvcFields = document.getElementById("card-cvc-fields");
const formError = document.getElementById("form-error");
const panelTitle = document.getElementById("panel-title");
const panelKicker = document.getElementById("panel-kicker");

// Every standard English BIP-39 recovery-phrase length. Import and export
// must agree on the same set.
const MNEMONIC_WORD_COUNTS = [12, 15, 18, 21, 24];

// Human-readable framing for every ceremony kind. Nothing here changes what
// is signed or bound; the exact signed material stays available under
// "Signed details" and is what the passkey attests to.
const KINDS = {
  card_add: {title: "Save a card", summary: "Save this card encrypted in Signer. It replaces any saved card with the same ID. CVC is never saved.", button: "Save with passkey"},
  card_delete: {title: "Delete a card", summary: "Remove the saved card. Your card container remains enrolled.", button: "Delete with passkey"},
  card_checkout: {title: "Approve a purchase", summary: "Fill and submit this checkout once. Bloom cannot cap the merchant's actual charge.", button: "Approve purchase with passkey"},
  wallet_registration: {
    title: "Create a new wallet",
    summary: "A new wallet will be created on your Bloom host. You will set up a <strong>new passkey</strong> for it now — that passkey is what approves anything this wallet does.",
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
    summary: "Remove wallet <strong>{wallet}</strong> from your Bloom host. Funds are not moved; if you have no backup, they become unreachable.",
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
  const node = ["svg", "path", "circle", "rect"].includes(tag)
    ? document.createElementNS("http://www.w3.org/2000/svg", tag)
    : document.createElement(tag);
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

// Bundled geometric symbols, never images fetched by ticker. Network marks
// are selected by numeric chain ID. Unknown tokens use a neutral coin.
function reviewIcon(kind) {
  const svg = el("svg", {viewBox: "0 0 32 32", "aria-hidden": "true", focusable: "false"});
  if (kind === "ethereum") {
    svg.append(el("path", {d: "M16 2 7 17l9 5 9-5ZM7 19l9 11 9-11-9 5Z", fill: "currentColor"}));
  } else if (kind === "base") {
    svg.append(el("circle", {cx: "16", cy: "16", r: "14", fill: "#0052ff"}),
      el("path", {d: "M2 16h19", stroke: "white", "stroke-width": "3"}));
  } else if (kind === "test") {
    svg.append(el("path", {d: "M12 3h8M14 3v10L6 26q-1 3 3 3h14q4 0 3-3l-8-13V3M10 20h12", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linejoin": "round"}));
  } else {
    svg.append(el("circle", {cx: "16", cy: "16", r: "12", fill: "none", stroke: "currentColor", "stroke-width": "2"}),
      el("circle", {cx: "16", cy: "16", r: "8", fill: "none", stroke: "currentColor", "stroke-width": "1"}));
  }
  return svg;
}

// Reviewed, bundled artwork. Never select a logo by publisher-supplied text.
function tokenReviewIcon(chainId, address) {
  const logos = {
    "1:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "usdc",
    "1:0x6b175474e89094c44da98b954eedeac495271d0f": "dai"
  };
  const name = logos[`${chainId}:${String(address).toLowerCase()}`];
  if (!name) return reviewIcon("token");
  const image = el("img", {src: `/assets/tokens/${name}.svg`, alt: "", width: "40", height: "40"});
  image.onerror = () => image.replaceWith(reviewIcon("token"));
  return image;
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
// Once this page observes a terminal outcome, late async failures cannot
// reopen approval. The server remains authoritative for all mutations.
let approvalTerminal = false;
function startExpiry(session, node) {
  clearInterval(expiryTimer);
  const expiresAt = Number(session.expires_at_ms ||
    session.signer_contribution?.expires_at_ms ||
    session.review_manifest?.expires_at_ms);
  const deadline = document.getElementById("review-deadline");
  const counting = !session.is_preview || session.preview_countdown;
  if (!counting || !Number.isFinite(new Date(expiresAt).getTime()) || !node) {
    if (deadline) deadline.textContent = "";
    return;
  }
  const absolute = new Date(expiresAt).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit", timeZoneName: "short"
  });
  const countdown = el("span", {class: "review-countdown"});
  if (deadline) {
    deadline.replaceChildren(el("span", {}, `${session.is_preview ? "Example deadline" : "Approve by"}: ${absolute}`));
    if (counting) deadline.append(" · ", countdown);
    deadline.setAttribute("title", new Date(expiresAt).toISOString());
  }
  const tick = () => {
    const left = expiresAt - Date.now();
    node.textContent = left <= 0 ? "Expired — ask Bloom to start this again"
      : `Time left: ${fmtRemaining(left)}`;
    node.className = left <= 0 ? "expired" : (left < 60000 ? "expiry soon" : "expiry");
    countdown.textContent = left <= 0
      ? (session.is_preview ? "Demo expired — reload to replay" : "Expired")
      : `${session.is_preview ? "Demo: " : ""}${fmtRemaining(left)} left`;
    countdown.className = `review-countdown ${left <= 0 ? "expired" : left < 60000 ? "expiry soon" : "expiry"}`;
    if (left <= 0) {
      approvalTerminal = true;
      approve.disabled = true;
      statusNode.textContent = session.is_preview ? "Preview only — nothing can be approved."
        : "This ceremony has expired. Nothing was changed.";
      clearInterval(expiryTimer);
    }
  };
  tick();
  if (counting && expiresAt > Date.now()) expiryTimer = setInterval(tick, 1000);
}

function chainLabel(chain, ctx) {
  if (chain === "solana") {
    return ctx?.genesis_hash === "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
      ? "Solana mainnet" : "Solana";
  }
  return {ethereum: "Ethereum", mainnet: "Ethereum", base: "Base", arbitrum: "Arbitrum",
    optimism: "Optimism", polygon: "Polygon", "evm-56": "BNB Chain",
    "evm-43114": "Avalanche", "evm-999": "HyperEVM", anvil: "local test chain"}[chain] || chain;
}

function addressExplorer(chainId, address) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return null;
  // Etherscan public chainlist snapshot, 2026-09-22: https://api.etherscan.io/v2/chainlist
  const explorers = {
    "1": ["etherscan.io", "https://etherscan.io"],
    "11155111": ["sepolia.etherscan.io", "https://sepolia.etherscan.io"],
    "560048": ["hoodi.etherscan.io", "https://hoodi.etherscan.io"],
    "56": ["bscscan.com", "https://bscscan.com"],
    "97": ["testnet.bscscan.com", "https://testnet.bscscan.com"],
    "137": ["polygonscan.com", "https://polygonscan.com"],
    "80002": ["amoy.polygonscan.com", "https://amoy.polygonscan.com"],
    "8453": ["basescan.org", "https://basescan.org"],
    "84532": ["sepolia.basescan.org", "https://sepolia.basescan.org"],
    "42161": ["arbiscan.io", "https://arbiscan.io"],
    "421614": ["sepolia.arbiscan.io", "https://sepolia.arbiscan.io"],
    "59144": ["lineascan.build", "https://lineascan.build"],
    "59141": ["sepolia.lineascan.build", "https://sepolia.lineascan.build"],
    "81457": ["blastscan.io", "https://blastscan.io"],
    "168587773": ["sepolia.blastscan.io", "https://sepolia.blastscan.io"],
    "10": ["optimistic.etherscan.io", "https://optimistic.etherscan.io"],
    "11155420": ["sepolia-optimism.etherscan.io", "https://sepolia-optimism.etherscan.io"],
    "43114": ["snowscan.xyz", "https://snowscan.xyz"],
    "43113": ["testnet.snowscan.xyz", "https://testnet.snowscan.xyz"],
    "199": ["bttcscan.com", "https://bttcscan.com"],
    "1029": ["testnet.bttcscan.com", "https://testnet.bttcscan.com"],
    "42220": ["celoscan.io", "https://celoscan.io"],
    "11142220": ["sepolia.celoscan.io", "https://sepolia.celoscan.io"],
    "252": ["fraxscan.com", "https://fraxscan.com"],
    "2523": ["hoodi.fraxscan.com", "https://hoodi.fraxscan.com"],
    "100": ["gnosisscan.io", "https://gnosisscan.io"],
    "5000": ["mantlescan.xyz", "https://mantlescan.xyz"],
    "5003": ["sepolia.mantlescan.xyz", "https://sepolia.mantlescan.xyz"],
    "4352": ["memecorescan.io", "https://memecorescan.io"],
    "43522": ["testnet.memecorescan.io", "https://testnet.memecorescan.io"],
    "204": ["opbnb.bscscan.com", "https://opbnb.bscscan.com"],
    "5611": ["opbnb-testnet.bscscan.com", "https://opbnb-testnet.bscscan.com"],
    "167000": ["taikoscan.io", "https://taikoscan.io"],
    "167013": ["hoodi.taikoscan.io", "https://hoodi.taikoscan.io"],
    "50": ["xdcscan.com", "https://xdcscan.com"],
    "51": ["testnet.xdcscan.com", "https://testnet.xdcscan.com"],
    "33139": ["apescan.io", "https://apescan.io"],
    "33111": ["curtis.apescan.io", "https://curtis.apescan.io"],
    "480": ["worldscan.org", "https://worldscan.org"],
    "4801": ["sepolia.worldscan.org", "https://sepolia.worldscan.org"],
    "146": ["sonicscan.org", "https://sonicscan.org"],
    "14601": ["testnet.sonicscan.org", "https://testnet.sonicscan.org"],
    "130": ["uniscan.xyz", "https://uniscan.xyz"],
    "1301": ["sepolia.uniscan.xyz", "https://sepolia.uniscan.xyz"],
    "2741": ["abscan.org", "https://abscan.org"],
    "11124": ["sepolia.abscan.org", "https://sepolia.abscan.org"],
    "80094": ["berascan.com", "https://berascan.com"],
    "80069": ["testnet.berascan.com", "https://testnet.berascan.com"],
    "143": ["monadscan.com", "https://monadscan.com"],
    "10143": ["testnet.monadscan.com", "https://testnet.monadscan.com"],
    "999": ["hyperevmscan.io", "https://hyperevmscan.io"],
    "747474": ["katanascan.com", "https://katanascan.com"],
    "737373": ["bokuto.katanascan.com", "https://bokuto.katanascan.com"],
    "1329": ["seiscan.io", "https://seiscan.io"],
    "1328": ["testnet.seiscan.io", "https://testnet.seiscan.io"],
    "988": ["stablescan.xyz", "https://stablescan.xyz"],
    "2201": ["testnet.stablescan.xyz", "https://testnet.stablescan.xyz"],
    "9745": ["plasmascan.to", "https://plasmascan.to"],
    "9746": ["testnet.plasmascan.to", "https://testnet.plasmascan.to"],
    "4326": ["mega.etherscan.io", "https://mega.etherscan.io"],
    "6343": ["testnet-mega.etherscan.io", "https://testnet-mega.etherscan.io"],
    "4663": ["robin.etherscan.io", "https://robin.etherscan.io"],
    "5042": ["arc.etherscan.io", "https://arc.etherscan.io"]
  };
  const explorer = explorers[String(chainId)];
  return Array.isArray(explorer) ? {name: explorer[0], url: `${explorer[1]}/address/${address}`} : null;
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
      detail: "",
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
      detail: `Only this spender's ${symbol} allowance changes, if the transaction succeeds. ` +
        "Other tokens and permissions are unaffected.",
      relation: `loses its ${symbol} allowance from`
    };
  }
  return {
    action: "allowance", magnitude: "finite",
    eyebrow: "Token allowance",
    heading: `Allow ${who} to spend up to ${summary.amount_display}`,
    detail: "",
    relation: `may spend up to ${summary.amount_display} of`
  };
}
function formatObserved(milliseconds) {
  const value = Number(milliseconds);
  return Number.isFinite(value) ? new Date(value).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "an unknown time";
}
// Round a displayed upper bound upwards using decimal integers. Floating
// point rounding must never turn a maximum into an understated charge.
function compactFeeCap(value) {
  const match = /^(\d+)(?:\.(\d+))? (.+)$/.exec(String(value));
  if (!match) return value;
  const fraction = match[2] || "";
  if (fraction.length <= 6) return value;
  let units = BigInt(match[1]) * 1000000n + BigInt(fraction.slice(0, 6));
  if (/[1-9]/.test(fraction.slice(6))) units += 1n;
  const decimals = (units % 1000000n).toString().padStart(6, "0").replace(/0+$/, "");
  return `${units / 1000000n}${decimals ? `.${decimals}` : ""} ${match[3]}`;
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
    if (movesNative && (decoded || payload.calldata_keccak || !payload.destination)) {
      facts.push([label("Native value sent"), payload.value_display]);
    }
    else technical.push([label("Native value sent"), payload.value_display]);
    facts.push([label("Network"), chainLabel(payload.chain)]);
    // A ceiling on execution gas, computed by Broker from the envelope's own
    // gas limit and price in the chain's authenticated units. It is a maximum
    // for that charge, not an estimate and not a cap on every network charge.
    // When the chain's units are unknown the page says so: a missing cost
    // must not read as no cost.
    if (payload.maximum_execution_gas_fee_display) technical.push([
      label("Exact execution gas cap"), payload.maximum_execution_gas_fee_display]);
    if (decoded) {
      technical.push([label("Data"), `${Number(payload.calldata_bytes).toLocaleString("en-US")} bytes`]);
    } else if (!payload.calldata_hex) {
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
    // Payload commitments remain in the complete signed manifest below.
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
      if (summary) facts.push([label(field.label), field.value, field.format === "addressName"]);
    }
    if (call.intent) technical.push([label("Publisher description"), call.intent]);
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
      const factStart = facts.length;
      const technicalStart = technical.length;
      const prefix = evmPayloads.length > 1 ? `Transaction ${index + 1}` : "";
      if (payload.contract_call) appendCallFacts(facts, technical, payload, prefix);
      appendEnvelopeFacts(facts, technical, payload, prefix);
      for (const row of facts.slice(factStart)) row[3] = payload.chain_id;
      for (const row of technical.slice(technicalStart)) row[3] = payload.chain_id;
    }
    // Every mandatory warning, in the order the verifier produced it, kept
    // visible rather than folded into the fact list or the details section.
    const warnings = [];
    for (const payload of calls) {
      for (const warning of payload.contract_call.warnings || []) warnings.push(warning);
    }
    const interpretation = [];
    // Upgradeability belongs to a contract, so it is stated once per affected
    // contract and taken only from the selected catalog entries — the one
    // place that already lists every contract the review depended on, each
    // exactly once. The consequence is the whole warning; when the review
    // touches a single upgradeable contract the identity is already on the
    // page, and when it touches more than one the address distinguishes them.
    // Which deployment was observed, and when, is a detail and lives in the
    // details section rather than beside the decision.
    const upgradeable = clear ? (clear.entries || []).filter(entry => entry.upgradeable) : [];
    for (const entry of upgradeable) {
      warnings.push(upgradeable.length > 1
        ? `Upgradeable contract ${shortAddress(entry.contract_address)} — its behavior can change.`
        : "Upgradeable contract — its behavior can change.");
      interpretation.push(["Upgradeable contract",
        `${entry.contract_address} — the publisher observed this deployment at ` +
        `${formatObserved(entry.observed_at_ms)}; its code may have changed since.`]);
    }
    const first = evmPayloads[0];
    const oneNetwork = evmPayloads.every(payload => String(payload.chain_id) === String(first.chain_id));
    const network = oneNetwork ? chainLabel(first.chain) : "more than one network";
    // One approval covers the whole batch, so a batch never collapses into one
    // member's heading: it says how many actions it carries and lists them in
    // order, each with its own intent.
    const intent = evmPayloads.length > 1
      ? {
          action: "batch", eyebrow: `${evmPayloads.length} transactions, in order`,
          heading: `Approve ${evmPayloads.length} transactions on ${network}`,
          detail: "One approval covers every transaction listed below. They are signed in the " +
            "order shown and there is no way to approve only part of the batch. " +
            "Execution is not atomic: an earlier transaction can succeed even if a later one fails.",
          cards: evmPayloads.map((payload, index) => ({
            position: index + 1,
            chainId: payload.chain_id,
            intent: payload.contract_call
              ? callIntent(payload.contract_call)
              : payload.destination && payload.calldata_keccak
              ? {action: "opaque", eyebrow: "Contract call", heading: "Approve a call Bloom cannot read",
                 detail: "No signed description is available. Bloom cannot say what this call does.",
                 relation: "calls"}
              : {action: payload.destination ? "send" : "deploy",
                 eyebrow: payload.destination ? "Native transfer" : "Contract creation",
                 heading: payload.destination
                   ? `Send ${payload.value_display}` : "Deploy a contract",
                 detail: payload.destination
                   ? "Bloom checked the envelope: destination and value come from the transaction bytes."
                   : "This creates a new contract. Bloom does not verify what its code does.",
                 relation: payload.destination ? `sends ${payload.value_display} to` : "creates"},
            counterparty: payload.contract_call?.intent_summary?.counterparty || payload.destination,
            counterpartyRole: payload.contract_call?.intent_summary?.counterparty_role ||
              (payload.contract_call || payload.calldata_keccak ? "contract" : "recipient"),
            contract: payload.contract_call?.contract,
            contractName: payload.contract_call?.intent_summary?.token
              ? `${payload.contract_call.intent_summary.token.symbol} — ${payload.contract_call.intent_summary.token.name}`
              : payload.contract_call?.contract_name
          }))
        }
      : first.contract_call
        ? callIntent(first.contract_call)
        : first.destination
          ? (first.calldata_keccak
            ? {action: "opaque", eyebrow: "Contract call", heading: "Approve a call Bloom cannot read",
               detail: "No signed description is available. Bloom cannot say what this call does.",
               relation: "calls"}
            : {action: "send", eyebrow: "Native transfer",
               heading: `Send ${first.value_display}`,
               detail: "",
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
             : "Transaction destination, value and bytes checked. Contract behavior not verified.");
    if (clear) {
      interpretation.push(["Catalog", `${clear.catalog_id}, sequence ${clear.catalog_sequence}`]);
      interpretation.push(["Assurance class", clear.assurance]);
      interpretation.push(["Verifier", `${clear.verifier_id} (${shortDigest(clear.verifier_digest)})`]);
      // The catalog commitment is already in the complete signed manifest.
    }
    const networkIdentity = oneNetwork
      ? `EVM · ${network} · Chain ID ${first.chain_id}` : "EVM · Multiple networks";
    return {intent, payloads: evmPayloads, parties: parties.map(party => ({...party, chainId: first.chain_id})), assurance, interpretation, facts, technical, warnings, networkIdentity,
            chainId: evmPayloads.length === 1 ? first.chain_id : null,
            assetSummary: evmPayloads.length === 1 ? summary : null,
            networkIcon: oneNetwork ? ({"1": "ethereum", "8453": "base", "31337": "test"}[first.chain_id] || "unknown") : "unknown",
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
     "A request to approve the maximum possible amount is refused. A large finite amount is still shown with its exact value.",
     "This wallet setting applies to all supported tokens. Each request will still need your approval " +
     "and will name its token and spender. This setting does not move tokens or grant a spender an allowance."],
    ["opaque_exact_allowed", "Requests Bloom cannot describe",
     "A call with no signed description is refused.",
     "A call with no signed description can be approved as exact bytes, carrying the " +
     "inability-to-explain warning."]
  ];
  const clearBefore = diff.clear_signing?.before || null;
  const clearAfter = diff.clear_signing?.after || null;
  const intentLines = [];
  // A wallet without clear signing reads no calldata and refuses nothing for
  // it, so for the two refusals "off" means allowed, not blocked.
  if (clearBefore && !clearAfter) {
    lines.push(["Clear signing", "on → off"]);
    intentLines.push(["Clear signing",
      "Bloom stops reading contract calls for this wallet. Unlimited allowances and calls with no " +
      "signed description are no longer refused: each is shown only as exact bytes for you to approve."]);
  } else if (clearAfter) {
    if (!clearBefore) lines.push(["Clear signing", "off → on"]);
    for (const [key, title, whenOff, whenOn] of CLEAR_SIGNING_SETTINGS) {
      const was = clearBefore ? Boolean(clearBefore[key]) : true;
      const now = Boolean(clearAfter[key]);
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
    // The trusted publisher keys are the root of trust for every description
    // Bloom will later read calldata against, so a rotation is the largest
    // authority change this diff can carry and has to be named key by key.
    const keyLabel = k => `${k?.key_id || "unnamed"} (${shortDigest(k?.verifying_key) || "no key"})`;
    const keyIdentity = k => `${k?.key_id || ""}\u0000${k?.verifying_key || ""}`;
    const keysBefore = Array.isArray(clearBefore?.trusted_keys) ? clearBefore.trusted_keys : [];
    const keysAfter = Array.isArray(clearAfter?.trusted_keys) ? clearAfter.trusted_keys : [];
    const idsBefore = new Set(keysBefore.map(keyIdentity));
    const idsAfter = new Set(keysAfter.map(keyIdentity));
    const addedKeys = keysAfter.filter(k => !idsBefore.has(keyIdentity(k)));
    const removedKeys = keysBefore.filter(k => !idsAfter.has(keyIdentity(k)));
    for (const k of addedKeys) lines.push(["Trust descriptions signed by", keyLabel(k), true]);
    for (const k of removedKeys) lines.push(["Stop trusting descriptions signed by", keyLabel(k), true]);
    if (addedKeys.length) {
      intentLines.push(["Trusted publisher",
        "A new publisher becomes able to describe any contract call for this wallet. " +
        "Every future approval screen for a contract call is written from descriptions it signs."]);
    }
    if (removedKeys.length && !addedKeys.length) {
      intentLines.push(["Trusted publisher",
        "Descriptions signed by the named publisher stop being accepted. Contract calls that only " +
        "it described can no longer be read, and will be refused rather than approved unread."]);
    }
  }
  // A clear-signing change that produced no line is a change this page cannot
  // describe. Saying nothing changed would be a lie, so say that instead.
  const clearSigningUndescribed = Boolean(diff.clear_signing) && lines.length === 0;
  const n = lines.length;
  const sentence = clearSigningUndescribed
    ? "This updates the clear-signing settings in a way this page cannot describe. " +
      "Do not approve it; check \"What your passkey signs\" below and report it."
    : n === 0
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

function renderCardReview(session) {
  const meta = KINDS[session.ceremony_kind];
  document.getElementById("page-title").textContent = meta.title;
  document.getElementById("page-lede").textContent = meta.summary;
  panelTitle.textContent = "Check this request";
  approve.textContent = meta.button;
  const manifest = session.review_manifest;
  const effect = manifest.card_effect;
  const facts = el("dl", {class: "facts"});
  const fact = (name, value) => facts.append(el("dt", {}, name), el("dd", {}, value));
  if (manifest.card) fact("Card", `${manifest.card.label} · ${manifest.card.brand} ••${manifest.card.last4}`);
  if (effect.kind === "add") fact("Label", effect.label);
  if (effect.kind === "checkout" || effect.kind === "site_checkout") {
    const payment = effect.facts;
    const website = el("span");
    const domain = manifest.registrable_domain;
    const index = domain ? payment.origin.lastIndexOf(domain) : -1;
    if (index >= 0) website.append(payment.origin.slice(0, index), el("strong", {}, domain), payment.origin.slice(index + domain.length));
    else website.textContent = payment.origin;
    fact("Website", website);
    if (effect.kind === "site_checkout") {
      document.getElementById("page-lede").textContent = "Bloom clicks this shop's pay button once. The shop charges the payment method saved in your account there; no Bloom card is used. Bloom cannot cap the shop's actual charge.";
      fact("Payment", "Your saved payment method at this shop");
    } else fact("Payment frames", payment.payment_frame_origins.join(", ") || "Main document");
    const scale = new Intl.NumberFormat("en", {style: "currency", currency: payment.currency}).resolvedOptions().maximumFractionDigits;
    const amount = payment.total_minor / (10 ** scale);
    const money = value => new Intl.NumberFormat("en", {style: "currency", currency: payment.currency}).format(value);
    fact("Total", `${money(amount)} (${payment.currency})`);
    fact("Installments", payment.total_minor % payment.installments === 0
      ? `${payment.installments} × ${money(amount / payment.installments)} = ${money(amount)}`
      : `${payment.installments} payments totaling ${money(amount)}; individual installment amounts were not verified`);
    fact("Recurring charge", payment.recurring ? "Yes" : "No");
    // The merchant's page as checkout saw it, so items, quantity and delivery
    // details can be checked. Only the total above is bound to the approval.
    const image = el("img", {alt: "Merchant checkout page"});
    const preview = el("figure", {class: "order-preview", hidden: ""},
      el("figcaption", {}, "Merchant's page as Bloom saw it. Check the items, quantity and delivery details."),
      el("div", {class: "order-preview-frame"}, image));
    fetch(`/api/session/${session.ceremony_id}/order-preview`, {headers: authHeaders, credentials: "same-origin"})
      .then(response => response.ok ? response.blob() : null)
      .then(blob => { if (blob?.type === "image/jpeg") { image.src = URL.createObjectURL(blob); preview.hidden = false; } })
      .catch(() => {});
    reviewNode.replaceChildren(facts, preview, el("h3", {}, "Described by agent — not verified"), el("p", {}, effect.agent_description), el("p", {}, "Bloom reports the merchant's confirmation; it does not verify your bank charge."));
  } else if (effect.kind === "manual_checkout" && !effect.card_id) {
    document.getElementById("page-title").textContent = "Take over Bloom's browser";
    approve.textContent = "Open Bloom's browser with passkey";
    document.getElementById("page-lede").textContent = "The agent needs you in Bloom's browser, for example to log in, enter a code or pass a check. This approval buys nothing and releases no card. Click Done there to hand the browser back.";
    reviewNode.replaceChildren(facts, el("h3", {}, "Described by agent — not verified"), el("p", {}, effect.agent_description));
  } else if (effect.kind === "manual_checkout") {
    approve.textContent = "Open private view with passkey";
    document.getElementById("page-lede").textContent = "Payment facts could not be verified. Open the private view to finish yourself. No saved card will be released and no automated payment is approved.";
    reviewNode.replaceChildren(facts, el("h3", {}, "Described by agent — not verified"), el("p", {}, effect.agent_description));
  } else reviewNode.replaceChildren(facts);
  const expiry = el("p", {class: "expiry"});
  reviewNode.append(expiry);
  startExpiry(session, expiry);
}

const explorerAnchor = (explorer, value, label) =>
  el("a", {href: explorer.url, class: "ceremony-address-link", target: "_blank",
    rel: "noopener noreferrer", referrerpolicy: "no-referrer",
    title: `View on ${explorer.name} (opens a new tab)`,
    "aria-label": `${label}: ${value}. View on ${explorer.name} (opens a new tab)`},
    el("code", {}, value));

function renderReview(session) {
  if (session.ceremony_kind.startsWith("card_")) return renderCardReview(session);
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
      "Passkey approval";
  }

  const facts = el("dl", {class: "facts"});
  const fact = (label, value, mono, chainId = transfer?.chainId) => {
    if (value == null || value === "") return;
    const explorer = addressExplorer(chainId, String(value));
    const shown = explorer ? explorerAnchor(explorer, value, label)
      : mono ? el("code", {}, value) : value;
    facts.append(el("dt", {}, label), el("dd", {}, shown));
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
    const network = transfer.networkIdentity || transfer.facts.find(([label]) => label === "Network")?.[1];
    pageTitle.textContent = network || ["Wallet settings", walletName].filter(Boolean).join(" · ");
    if (transfer.networkIdentity) pageTitle.replaceChildren(reviewIcon(transfer.networkIcon),
      el("span", {}, network));
  } else fact("Wallet", walletName);
  if (kind !== "sealed_approval" &&
      session.signer_contribution?.wallet_seed_profile === "bip39-multicurve-v1") {
    fact("Wallet type", "BIP-39 recovery phrase (multi-chain)");
  }
  if (transfer) {
    if (keyInfo.account) fact("From", keyInfo.account);
    for (const [label, value, mono, chainId] of transfer.facts) {
      if (!contextualFacts.has(label)) fact(label, value, mono, chainId);
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
  if (expiryHost) expiryHost.replaceChildren(expiry);
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
    if (party.change) row.append(el("span", {class: `ceremony-balance-change ${party.role === "source" ? "outgoing" : "incoming"}`}, party.change));
    const address = el("code", {}, party.value);
    const explorer = addressExplorer(party.chainId || transfer?.chainId, party.value);
    const identity = explorer ? el("a", {class: "ceremony-address-link", href: explorer.url,
      target: "_blank", rel: "noopener noreferrer", referrerpolicy: "no-referrer",
      title: `View on ${explorer.name} (opens a new tab)`,
      "aria-label": `${party.label}: ${party.value}. View on ${explorer.name} (opens a new tab)`}, address) : address;
    row.append(el("p", {class: "ceremony-party-address"}, identity));
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
    const token = transfer.parties?.find(party => party.role === "token");
    if (token && transfer.intent.action !== "batch") {
      // Keep the full contract identity visible beside the decorative logo.
      const asset = partyRow({...token, label: "Token contract"});
      asset.className = "ceremony-party ceremony-asset-identity";
      const icon = el("span", {class: "ceremony-token-icon", "aria-hidden": "true"},
        tokenReviewIcon(token.chainId, token.value));
      const summary = transfer.assetSummary;
      const sending = summary?.action === "transfer";
      if (sending) panelTitle.textContent = "Requested transfer";
      const amount = summary && !sending ? el("div", {class: "ceremony-asset-amount permission"},
        el("span", {class: "ceremony-amount-label"}, sending ? "You send · requested" : "Spending limit"),
        el("strong", {}, sending ? `−${summary.amount_display}`
          : summary.magnitude === "unlimited" ? "Unlimited" : summary.amount_display)) : null;
      parts.push(el("section", {class: "ceremony-asset", "aria-label": "Token being transferred or approved"}, icon, asset, amount));
    }
    if (transfer.intent.detail) parts.push(intentBlock(transfer.intent));
    for (const [index, payload] of (transfer.payloads || []).entries()) {
      const call = payload.contract_call;
      if (!call || call.intent_summary) continue;
      const argumentsList = el("dl", {class: "facts"});
      for (const field of call.fields || []) {
        const explorer = addressExplorer(payload.chain_id, field.value);
        const value = explorer ? explorerAnchor(explorer, field.value, field.label)
          : el("code", {}, field.value);
        argumentsList.append(el("dt", {}, field.label), el("dd", {}, value));
      }
      parts.push(el("section", {class: "ceremony-call-arguments"},
        el("h2", {class: "ceremony-section-title"}, transfer.payloads.length > 1 ? `Transaction ${index + 1} arguments` : "Function arguments"),
        el("code", {class: "ceremony-function"}, call.function_signature),
        argumentsList));
    }
    const warningParts = [];
    if (transfer.warnings?.length) {
      const warningGroup = el("aside", {class: "ceremony-warning", "aria-label": "Risks and consequences"});
      if (transfer.intent.magnitude === "unlimited") {
        warningGroup.setAttribute("data-severity", "danger");
      }
      for (const warning of transfer.warnings) warningGroup.append(el("p", {}, warning));
      warningParts.push(warningGroup);
    }
    for (const card of transfer.intent.cards || []) {
      const wrapper = el("section", {class: "ceremony-card"},
        el("p", {class: "ceremony-card-position"}, `Transaction ${card.position}`),
        intentBlock(card.intent, true));
      if (card.counterparty) {
        wrapper.append(el("div", {class: "ceremony-identity"},
          partyRow({role: card.counterpartyRole,
            label: card.counterpartyRole === "spender" ? "Spender"
              : card.counterpartyRole === "recipient" ? "Recipient" : "Contract called",
            value: card.counterparty, chainId: card.chainId})));
      }
      if (card.contract && card.contract !== card.counterparty) {
        wrapper.append(el("div", {class: "ceremony-identity"},
          partyRow({role: "contract", label: "Contract called", name: card.contractName,
            value: card.contract, chainId: card.chainId})));
      }
      parts.push(wrapper);
    }
    if (transfer.parties?.length) {
      const isTransfer = ["transfer", "send"].includes(transfer.intent.action);
      const parties = [...transfer.parties].filter(party =>
        transfer.intent.action === "batch" ? party.role === "source" : party !== token).sort((a, b) =>
          Number(b.role === "spender") - Number(a.role === "spender"));
      const flow = el("div", {class: `ceremony-identity ${isTransfer ? "ceremony-transfer-path" : "ceremony-permission"}`});
      const movement = transfer.assetSummary?.action === "transfer" ? transfer.assetSummary.amount_display : null;
      for (const party of parties) {
        if (isTransfer && party.role === "recipient") {
          flow.append(el("div", {class: "ceremony-flow-arrow", "aria-hidden": "true"}, "↓"));
        }
        const change = movement && ["source", "recipient"].includes(party.role)
          ? `${party.role === "source" ? "−" : "+"}${movement}` : null;
        flow.append(partyRow({...party, change,
          ...(party.role === "source" ? {label: isTransfer ? "Sender" : "Your wallet", name: walletName} : {})}));
      }
      parts.push(flow);
    }
    parts.push(...warningParts);
    for (const [index, payload] of (transfer.payloads || []).entries()) {
      if (!payload.calldata_keccak) continue;
      const name = payload.destination ? "Calldata" : "Initcode";
      const prefix = transfer.payloads.length > 1 ? `Transaction ${index + 1} · ` : "";
      const raw = el("details", {class: "ceremony-details ceremony-calldata"},
        el("summary", {}, `${prefix}${name} · ${payload.calldata_bytes} bytes`),
        payload.calldata_hex ? el("pre", {}, payload.calldata_hex)
          : el("p", {class: "ceremony-assurance"}, "This older review records only the data length and hash. Prepare a new review to see the bytes."));
      if (!payload.contract_call) raw.setAttribute("open", "");
      parts.push(payload.contract_call ? raw : el("section", {class: "ceremony-raw"}, raw));
    }
  } else {
    parts.push(el("p", {class: "summary", html: summaryHtml}));
  }
  parts.push(facts);
  for (const [index, payload] of (transfer?.payloads || []).entries()) {
    const exact = payload.maximum_execution_gas_fee_display;
    const label = transfer.payloads.length > 1 ? `Transaction ${index + 1} gas fee` : "Gas fee";
    const amount = exact ? el("span", {class: "ceremony-fee-amount"},
      reviewIcon(exact.endsWith(" ETH") ? "ethereum" : "token"),
      el("span", {}, `Up to ${compactFeeCap(exact)}`))
      : el("span", {}, "Cannot be shown for this network");
    parts.push(el("div", {class: "ceremony-fee", "aria-label": "Execution gas only; other network charges may apply"},
      el("span", {class: "ceremony-fee-label"}, label), amount));
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
    for (const [label, value, mono, chainId] of transfer.technical) {
      const explorer = addressExplorer(chainId, String(value));
      const shown = explorer ? explorerAnchor(explorer, value, label)
        : mono ? el("code", {}, value) : value;
      technical.append(el("dt", {}, label), el("dd", {}, shown));
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
      el("summary", {}, "Verification and technical details"),
      transfer?.assurance ? el("p", {class: "ceremony-assurance"}, transfer.assurance) : null,
      ...disclosures));
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
// Read before anything rewrites the URL below. A preview is decided by the
// path it was opened at, never by what the tab happens to still hold.
const previewPath = location.pathname.startsWith("/preview") ? location.pathname : "";
const tokenFromPath = location.pathname.startsWith("/ceremony/")
  ? location.pathname.slice("/ceremony/".length) : "";
const remoteCeremony = location.protocol === "https:";
const remoteFragment = remoteCeremony && location.hash.startsWith("#cap=")
  ? location.hash.slice("#cap=".length) : "";
const sessionTokenKey = "bloom.ceremony.token.v1";
let token = remoteCeremony ? remoteFragment : (tokenFromPath || readSessionToken());
let ceremonyId = null;
if (!remoteCeremony && tokenFromPath) writeSessionToken(tokenFromPath);
if ((remoteCeremony || token) && !previewPath) history.replaceState(null, "", "/ceremony/");
const authHeaders = remoteCeremony ? {} : {"x-bloom-ceremony-token": token};
const ceremonyRpId = remoteCeremony ? location.hostname : "localhost";
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
  try {
    browserSessionStorage()?.removeItem(sessionTokenKey);
    browserSessionStorage()?.removeItem("bloom.ceremony.remote-session.v1");
  }
  catch (_) {}
}

function reportCeremonyError(error, fallback = "Ceremony failed") {
  console.error("Bloom ceremony failed", error);
  statusNode.textContent = fallback;
}

// Raised before any passkey prompt, so the link stays usable.
class CardFieldError extends Error {}

const CARD_BRANDS = [
  {name: "Amex", pattern: /^3[47]/, lengths: [15], cvc: 4},
  {name: "Visa", pattern: /^4/, lengths: [13, 16, 19], cvc: 3},
  {name: "Mastercard", pattern: /^(5[1-5]|222[1-9]|22[3-9]|2[3-6]|27[01]|2720)/, lengths: [16], cvc: 3},
  {name: "Discover", pattern: /^(6011|64[4-9]|65)/, lengths: [16, 17, 18, 19], cvc: 3},
  {name: "Diners Club", pattern: /^(36|38|30[0-5])/, lengths: [14, 15, 16, 17, 18, 19], cvc: 3},
  {name: "JCB", pattern: /^35(2[89]|[3-8])/, lengths: [16, 17, 18, 19], cvc: 3}
];

function luhnValid(number) {
  let sum = 0;
  [...number].reverse().forEach((digit, i) => {
    const n = Number(digit) * (i % 2 ? 2 : 1);
    sum += n > 9 ? n - 9 : n;
  });
  return sum % 10 === 0;
}

// Returns {value} or {error} per field; checked before any passkey prompt.
const CARD_CHECKS = {
  "card-number": raw => {
    const number = raw.replace(/\D/g, "");
    if (!number) return {error: "Enter the card number."};
    const brand = CARD_BRANDS.find(b => b.pattern.test(number));
    const lengths = brand ? brand.lengths : [12, 13, 14, 15, 16, 17, 18, 19];
    if (!lengths.includes(number.length)) {
      return {error: `${brand ? brand.name : "Card"} numbers are ${lengths.length > 1 ? `${lengths[0]} to ${lengths.at(-1)}` : lengths[0]} digits.`};
    }
    if (!luhnValid(number)) return {error: "This card number has a typo. Check the digits."};
    return {value: number};
  },
  "card-expiry": raw => {
    const match = /^(\d{2})\/(\d{2})$/.exec(raw);
    if (!match) return {error: "Enter the expiry as MM/YY, for example 08/29."};
    const month = Number(match[1]), year = 2000 + Number(match[2]);
    if (month < 1 || month > 12) return {error: "The month must be 01 to 12."};
    const now = new Date();
    if (year * 12 + month < now.getFullYear() * 12 + now.getMonth() + 1) return {error: "This card has expired."};
    if (year > now.getFullYear() + 20) return {error: "Check the year. It is too far ahead."};
    return {value: {month, year}};
  },
  "card-name": raw => raw ? {value: raw} : {error: "Enter the name as printed on the card."},
  "card-cvc": raw => /^\d{3,4}$/.test(raw) ? {value: raw} : {error: "Enter the 3 or 4 digit security code."}
};

function checkCardField(id) {
  const input = document.getElementById(id);
  const result = CARD_CHECKS[id](input.value.trim());
  input.setAttribute("aria-invalid", result.error ? "true" : "false");
  document.getElementById(`${id}-error`).textContent = result.error || "";
  return result;
}

function setupCardFields() {
  const number = document.getElementById("card-number");
  const expiry = document.getElementById("card-expiry");
  number.addEventListener("input", () => {
    const digits = number.value.replace(/\D/g, "").slice(0, 19);
    const groups = /^3[47]/.test(digits) ? [4, 6, 5] : [4, 4, 4, 4, 3];
    const parts = [];
    let rest = digits;
    for (const size of groups) if (rest) { parts.push(rest.slice(0, size)); rest = rest.slice(size); }
    number.value = parts.join(" ");
  });
  expiry.addEventListener("input", event => {
    let digits = expiry.value.replace(/\D/g, "").slice(0, 4);
    if (digits.length === 1 && digits > "1") digits = `0${digits}`;
    const deleting = event.inputType?.startsWith("delete");
    expiry.value = digits.length > 2 || (digits.length === 2 && !deleting) ? `${digits.slice(0, 2)}/${digits.slice(2)}` : digits;
  });
  for (const id of Object.keys(CARD_CHECKS)) {
    const input = document.getElementById(id);
    input.addEventListener("blur", () => { if (input.value) checkCardField(id); });
    input.addEventListener("input", () => {
      if (input.getAttribute("aria-invalid") === "true") checkCardField(id);
      formError.hidden = true;
    });
  }
}

function cardFieldsInput(session) {
  const ids = session.ceremony_kind === "card_add" ? ["card-number", "card-expiry", "card-name"]
    : session.review_manifest.card_effect.kind === "checkout" ? ["card-cvc"] : [];
  const results = Object.fromEntries(ids.map(id => [id, checkCardField(id)]));
  const invalid = ids.find(id => results[id].error);
  if (invalid) {
    document.getElementById(invalid).focus();
    throw new CardFieldError("Fix the highlighted field to continue.");
  }
  if (session.ceremony_kind === "card_add") {
    const {month, year} = results["card-expiry"].value;
    return {card: {number: results["card-number"].value, expiry_month: month, expiry_year: year, name: results["card-name"].value}};
  }
  return ids.length ? {cvc: results["card-cvc"].value} : {};
}

// After the passkey approves a card request, Signer has consumed the link.
function reportCardFailure(session, error) {
  console.error("Bloom card ceremony failed", error);
  const action = session.ceremony_kind === "card_add" ? "Card not saved"
    : session.ceremony_kind === "card_delete" ? "Card not deleted" : "Not approved";
  const reason = error?.message === "invalid card details"
    ? "Signer rejected the card details." : (error?.message || "Signer refused the request.");
  statusNode.textContent = `${action}.`;
  formError.textContent = `${action}. ${reason} This link is used up; ask your agent for a new one.`;
  formError.hidden = false;
  clearInterval(expiryTimer);
  for (const node of [approve, cancel, cardFields, cardCvcFields]) node.hidden = true;
}

function reportApprovalFailure(error) {
  if (approvalTerminal) return;
  if (error instanceof CardFieldError) {
    formError.textContent = error.message;
    formError.hidden = false;
    statusNode.textContent = "Not sent. Nothing was saved or charged.";
    approve.disabled = false;
    return;
  }
  const missingPrf = error?.name === "NotSupportedError" ||
    (typeof error?.message === "string" && error.message.includes("required PRF output"));
  const message = missingPrf
    ? "This browser or passkey does not support the required PRF extension. Use a supported browser and passkey."
    : error?.name === "NotAllowedError"
      ? "The passkey prompt was cancelled or timed out. Nothing was sent. Try again."
      : "Passkey verification failed. Please try again.";
  reportCeremonyError(error, message);
  formError.textContent = message;
  formError.hidden = false;
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
function unstorableBrowserKey(error) {
  return ["DataCloneError", "DataError", "NotSupportedError"].includes(error?.name);
}
async function outputRecipientFor(session, existingOnly = false) {
  const keyPair = await crypto.subtle.generateKey(
    {name: "X25519"}, false, ["deriveBits"]
  );
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey)
  );
  const candidate = {
    ceremonyId: session.ceremony_id,
    expiresAtMs: Number(session.expires_at_ms) + 15 * 60 * 1000,
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
      if (existingOnly) throw new Error("The original result recipient is unavailable in this browser");
      let request = null;
      try {
        request = store.put(candidate);
      } catch (error) {
        // Some browsers (iOS Safari 27) cannot persist an X25519 CryptoKey
        // and throw while cloning the record. Keep the non-extractable key
        // in this page only; a reload then loses the result instead of
        // weakening the key to make it storable.
        if (!unstorableBrowserKey(error)) throw error;
      }
      if (request) await requestResult(request);
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
    rpId: ceremonyRpId,
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
    rp: {id: ceremonyRpId, name: "Bloom"},
    user: {
      id: decodeUrl(options.registration_user_handle),
      name: `bloom-${session.operation_id.slice(0, 12)}`,
      displayName: "Bloom wallet"
    },
    pubKeyCredParams: [{type: "public-key", alg: -7}],
    // A provider that already holds one of these refuses with
    // InvalidStateError instead of overwriting it under the shared user handle.
    excludeCredentials: (options.exclude_credentials || []).map(id => ({
      type: "public-key", id: decodeUrl(id)
    })),
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
async function ensureNewCredentialPrf(session, credential, confirmPhase, forceAssertion = false) {
  const creationPrf = prfResult(credential);
  if (creationPrf && !forceAssertion) return {prf: creationPrf, assertion: null};
  if (forceAssertion) creationPrf?.fill(0);
  const confirmation = await navigator.credentials.get({publicKey: {
    challenge: decodeUrl(session.challenges[confirmPhase].challenge),
    rpId: ceremonyRpId,
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

// Pairing retains its recipient only in this tab. Refresh/expiry/cancel loses it;
// neither origin stores an intermediate wallet secret or a reusable handoff.
let crossSurfaceState = null;
globalThis.addEventListener?.("pagehide", () => {
  if (!crossSurfaceState) return;
  stopCrossSurface();
  void mutate(`/api/session/${ceremonyId}/cancel`, {}).catch(() => {});
});
function crossSurfaceAad(prepared, phase) {
  return {
    pairing_id: prepared.pairing.pairing_id,
    operation_id: prepared.pairing.operation_id,
    wallet_id: prepared.wallet_id,
    source_surface: prepared.source_surface,
    destination_surface: prepared.pairing.destination_surface,
    exact_terms_digest: prepared.pairing.exact_terms_digest,
    destination_challenge: prepared.pairing.destination_challenge,
    phase
  };
}
function crossSurfaceOptions(prepared, destination) {
  return {
    operation_id: prepared.pairing.operation_id,
    challenges: (destination ? prepared.destination_challenges : [prepared.source_challenge])
      .map(binding => ({binding, challenge: encodeUrl(te.encode(canonicalJson(binding)))})),
    webauthn_options: {
      allowed_credentials: destination ? [] : prepared.source_prf_inputs,
      exclude_credentials: destination ? (prepared.destination_existing_credentials || []) : [],
      registration_user_handle: prepared.destination_user_handle,
      registration_prf_salt: prepared.destination_prf_salt
    }
  };
}
function stopCrossSurface() {
  if (!crossSurfaceState) return;
  clearTimeout(crossSurfaceState.poll);
  clearTimeout(crossSurfaceState.expiry);
  crossSurfaceState.capability?.fill(0);
  crossSurfaceState.recipient = null;
  crossSurfaceState = null;
}
function requireCrossSurface(state) {
  if (crossSurfaceState !== state || Date.now() >= state.expiresAt) {
    throw new Error("Paired enrollment expired. Start again from Bloom.");
  }
}
function validateCrossPrepared(session, prepared, pairingId) {
  const cross = session.cross_surface;
  if (!prepared || prepared.wallet_id !== cross.wallet_id ||
      prepared.pairing?.operation_id !== session.operation_id ||
      (pairingId && prepared.pairing.pairing_id !== pairingId) ||
      !/^[0-9a-f]{64}$/.test(prepared.pairing?.pairing_id || "") ||
      !/^[0-9]{6}$/.test(prepared.pairing?.confirmation_code || "") ||
      !Number.isFinite(Number(prepared.pairing.expires_at_ms)) ||
      Number(prepared.pairing.expires_at_ms) <= Date.now() ||
      (prepared.destination_existing_credentials !== undefined &&
        (!Array.isArray(prepared.destination_existing_credentials) ||
          !prepared.destination_existing_credentials.every(id =>
            typeof id === "string" && /^[A-Za-z0-9_-]{1,1366}$/.test(id))))) {
    throw new Error("Paired enrollment binding changed");
  }
}
async function finishAlreadyRegistered(session, state) {
  const wallet = session.cross_surface.wallet_id;
  try {
    await mutate(`/api/cross/${ceremonyId}/already-registered`, {
      capability: encodeUrl(state.capability)
    });
  } catch (_) {
    // The browser reported a wallet passkey on this device either way. If Bloom did
    // not record it, its request simply expires with nothing enrolled.
  }
  if (crossSurfaceState === state) stopCrossSurface();
  clearInterval(expiryTimer);
  clearSessionToken();
  approve.hidden = true;
  cancel.hidden = true;
  markDone(`This device can already approve for ${wallet}`);
  statusNode.textContent = "Nothing to add.";
  reviewNode.replaceChildren(
    el("h3", {class: "result-title ok"}, `This device can already approve for ${wallet}`),
    el("p", {class: "summary"}, `Your passkey provider already has a passkey for ${wallet}, so there's nothing to add. This usually means your passkeys sync between your devices (for example through iCloud Keychain, Google Password Manager or 1Password), or you registered this device earlier.`),
    el("p", {class: "summary"}, "You can close this page. Nothing has changed.")
  );
}
async function loadCrossSurface(session) {
  const cross = session.cross_surface;
  if (!["source", "destination"].includes(cross.role) ||
      (cross.role === "source" ? cross.source_origin : cross.destination_origin) !== location.origin) {
    throw new Error("Paired enrollment has the wrong origin");
  }
  stopCrossSurface();
  const state = {expiresAt: Number(session.expires_at_ms), recipient: null,
    capability: null, poll: null, expiry: null};
  if (!Number.isFinite(state.expiresAt) || state.expiresAt <= Date.now()) {
    throw new Error("Paired enrollment expired");
  }
  crossSurfaceState = state;
  const terminate = message => {
    if (crossSurfaceState !== state) return;
    stopCrossSurface();
    approve.disabled = true;
    cancel.disabled = true;
    clearInterval(expiryTimer);
    statusNode.textContent = message;
  };
  state.expiry = setTimeout(() => terminate("Paired enrollment expired. Start again from Bloom."),
    Math.min(state.expiresAt - Date.now(), 10 * 60 * 1000));
  for (const fields of [recoveryFields, exportFields, importFields, genericFields]) fields.hidden = true;
  document.getElementById("page-title").textContent = "Add a wallet passkey";
  document.getElementById("page-lede").textContent = "Approve with a passkey this wallet already has, then create one on the new device.";
  panelTitle.textContent = cross.role === "source" ? "Approve the new device" : "Prepare this device";
  panelKicker.textContent = "Paired enrollment";
  const sameSite = cross.source_origin === cross.destination_origin;
  const facts = el("dl", {class: "facts"},
    el("dt", {}, "Wallet"), el("dd", {}, cross.wallet_id),
    ...(sameSite
      ? [el("dt", {}, "Site"), el("dd", {}, cross.destination_origin)]
      : [el("dt", {}, "Existing passkey"), el("dd", {}, cross.source_origin),
        el("dt", {}, "New passkey"), el("dd", {}, cross.destination_origin)]));
  const instructions = el("p", {class: "summary"});
  const step = el("div");
  const expiry = el("p", {class: "expiry"});
  reviewNode.replaceChildren(facts, instructions, step, expiry);
  startExpiry(session, expiry);
  cancel.onclick = async () => {
    // Discard the local recipient immediately even if cancellation cannot reach Broker.
    terminate("Cancelled. You may close this tab.");
    try { await mutate(`/api/session/${ceremonyId}/cancel`, {}); }
    catch (_) { statusNode.textContent = "This tab is cancelled. The server will also expire the request."; }
  };
  const fail = error => {
    terminate("Paired enrollment could not finish. Start again from Bloom.");
    // Never log request bodies, capabilities or passkey extension output.
    if (error?.name === "NotSupportedError") {
      statusNode.textContent = "This browser or passkey does not support the required PRF extension. Use a supported browser and passkey.";
    }
    void mutate(`/api/session/${ceremonyId}/cancel`, {}).catch(() => {});
  };
  if (cross.role === "source") {
    const prepared = cross.source_prepared;
    validateCrossPrepared(session, prepared);
    instructions.textContent = "Compare this code with the one on the new device. Continue only if you started this there and the codes match.";
    step.append(el("p", {}, el("strong", {}, prepared.pairing.confirmation_code)));
    const confirmed = el("input", {type: "checkbox"});
    step.append(el("label", {}, confirmed, " I started this on the new device and the code matches"));
    approve.textContent = "Approve with existing passkey";
    approve.disabled = true;
    confirmed.onchange = () => { approve.disabled = !confirmed.checked || crossSurfaceState !== state; };
    statusNode.textContent = "Check the code on the new device before approving.";
    approve.onclick = async () => {
      if (!confirmed.checked) return;
      approve.disabled = true;
      let prf;
      try {
        requireCrossSurface(state);
        const credential = await getCredential(crossSurfaceOptions(prepared, false), 0);
        prf = prfResult(credential);
        if (!prf || prf.length !== 32) {
          throw new DOMException("Passkey PRF is required", "NotSupportedError");
        }
        const encrypted = await hpkeSeal(decodeUrl(prepared.source_hpke_recipient_key),
          te.encode("bloom-cross-surface-source-prf/v1"),
          te.encode(canonicalJson(crossSurfaceAad(prepared, "source_prf"))), prf);
        requireCrossSurface(state);
        await mutate(`/api/cross/${ceremonyId}/authorize`, {
          authority_assertion: assertionJson(credential), encrypted_authority_prf: encrypted
        });
        terminate("Approved. Finish on the new device, where its passkey is created. Nothing is active until then.");
      } catch (error) { fail(error); }
      finally { prf?.fill(0); }
    };
    return;
  }
  instructions.textContent = "Keep this page open. Next you get a link to approve with a passkey this wallet already has.";
  statusNode.textContent = "Prepare this device to receive the approval.";
  approve.textContent = "Prepare enrollment";
  approve.disabled = false;
  approve.onclick = async () => {
    approve.disabled = true;
    try {
      requireCrossSurface(state);
      const pair = await crypto.subtle.generateKey({name: "X25519"}, false, ["deriveBits"]);
      state.recipient = {privateKey: pair.privateKey,
        publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))};
      const started = await mutate(`/api/cross/${ceremonyId}/pair`, {
        destination_hpke_public_key: encodeUrl(state.recipient.publicKey)
      });
      requireCrossSurface(state);
      const sourceUrl = new URL(started.source_url);
      if (sourceUrl.origin !== cross.source_origin || sourceUrl.username || sourceUrl.password ||
          !/^[0-9]{6}$/.test(started.confirmation_code) ||
          !/^[0-9a-f]{64}$/.test(started.pairing_id)) {
        throw new Error("Invalid pairing response");
      }
      state.expiresAt = Math.min(state.expiresAt, Number(started.expires_at_ms));
      if (!Number.isFinite(state.expiresAt)) throw new Error("Invalid pairing expiry");
      const hostOnly = cross.source_origin.startsWith("http://localhost:");
      const linkActions = el("div", {class: "result-actions"});
      if (typeof navigator.share === "function") {
        const share = el("button", {type: "button"}, "Share link");
        share.onclick = () => { navigator.share({url: sourceUrl.href}).catch(() => {}); };
        linkActions.append(share);
      }
      if (navigator.clipboard?.writeText) {
        const copy = el("button", {type: "button"}, "Copy link");
        copy.onclick = () => {
          navigator.clipboard.writeText(sourceUrl.href)
            .then(() => { copy.textContent = "Copied"; })
            .catch(() => {});
        };
        linkActions.append(copy);
      }
      step.replaceChildren(el("p", {}, el("strong", {}, started.confirmation_code)),
        el("a", {href: sourceUrl.href, target: "_blank", rel: "noopener noreferrer"}, "Open approval link"),
        linkActions,
        el("p", {}, hostOnly
          ? "Open this link in a browser on your Bloom host. Compare the code before approving."
          : `Open this link on a device that already has a passkey for ${cross.wallet_id}, such as the one you first set it up on. Compare the code before approving.`));
      statusNode.textContent = "Waiting for your existing passkey approval…";
      const poll = async () => {
        try {
          requireCrossSurface(state);
          const response = await fetch(`/api/cross/${ceremonyId}/handoff`, {
            headers: authHeaders, credentials: "same-origin", cache: "no-store"
          });
          if (!response.ok) throw new Error("Pairing is unavailable");
          const handoff = await response.json();
          requireCrossSurface(state);
          if (handoff.state === "waiting") {
            state.poll = setTimeout(poll, 2000);
            return;
          }
          if (handoff.state !== "ready") throw new Error("Pairing is terminal");
          const prepared = handoff.source_prepared;
          validateCrossPrepared(session, prepared, started.pairing_id);
          if (prepared.pairing.destination_hpke_public_key !== encodeUrl(state.recipient.publicKey) ||
              prepared.pairing.confirmation_code !== started.confirmation_code) {
            throw new Error("Destination recipient changed");
          }
          state.capability = await hpkeOpen(state.recipient,
            te.encode("bloom-cross-surface-handoff/v1"),
            te.encode(canonicalJson(crossSurfaceAad(prepared, "handoff"))), handoff.encrypted_capability);
          requireCrossSurface(state);
          if (state.capability.length !== 32) throw new Error("Invalid handoff");
          step.replaceChildren(el("p", {}, "The existing passkey authorized this destination. Create the new passkey here to finish."));
          statusNode.textContent = "Ready to enroll. Your wallet's addresses stay the same.";
          approve.textContent = "Create destination passkey";
          approve.disabled = false;
          approve.onclick = async () => {
            approve.disabled = true;
            let newPrf;
            try {
              requireCrossSurface(state);
              const options = crossSurfaceOptions(prepared, true);
              let created;
              try {
                created = await createCredential(options, 0);
              } catch (error) {
                // WebAuthn's signal that this provider already holds one of
                // the excluded wallet passkeys. That is a finished outcome,
                // not a failure: this device can already approve.
                if (error?.name === "InvalidStateError" &&
                    options.webauthn_options.exclude_credentials.length > 0) {
                  await finishAlreadyRegistered(session, state);
                  return;
                }
                throw error;
              }
              // Both attestation and a fresh assertion are mandatory on this leg.
              newPrf = await ensureNewCredentialPrf(options, created, 1, true);
              if (newPrf.prf.length !== 32) throw new Error("Invalid passkey PRF");
              const encrypted = await hpkeSeal(decodeUrl(prepared.destination_hpke_recipient_key),
                te.encode("bloom-cross-surface-destination-prf/v1"),
                te.encode(canonicalJson(crossSurfaceAad(prepared, "destination_prf"))), newPrf.prf);
              requireCrossSurface(state);
              let result;
              try {
                result = await mutate(`/api/cross/${ceremonyId}/finish`, {
                  capability: encodeUrl(state.capability), attestation: attestationJson(created),
                  prf_assertion: newPrf.assertion, encrypted_new_prf: encrypted
                });
              } catch (error) {
                // A lost response does not mean the atomic enrollment failed.
                const recovered = await fetch(`/api/session/${ceremonyId}/result`, {
                  headers: authHeaders, credentials: "same-origin", cache: "no-store"
                });
                if (!recovered.ok) throw error;
                result = await recovered.json();
              }
              terminate("New passkey enrolled.");
              renderDone(session, result);
              clearSessionToken();
              approve.hidden = true;
              cancel.hidden = true;
            } catch (error) { fail(error); }
            finally { newPrf?.prf.fill(0); }
          };
        } catch (error) { fail(error); }
      };
      await poll();
    } catch (error) { fail(error); }
  };
}

function requireLiveApproval(session) {
  const expiresAt = Number(session.expires_at_ms ||
    session.signer_contribution?.expires_at_ms ||
    session.review_manifest?.expires_at_ms);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    approvalTerminal = true;
  }
  if (approvalTerminal) {
    approve.disabled = true;
    throw new Error("This ceremony is no longer available. Open a fresh link from Bloom.");
  }
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
  "This spender can move your tokens later without another approval. The permission does not expire with this review.";
function previewPayload(extra) {
  const payload = Object.assign({
    chain_id: "31337", chain: "anvil", sender: PREVIEW_WALLET, destination: PREVIEW_TOKEN,
    value: "0", value_display: "0 ETH", nonce: "7", gas_limit: "65410",
    fee: {kind: "eip1559", max_fee_per_gas: "3034880652", max_fee_per_gas_display: "3.03 gwei",
          max_priority_fee_per_gas: "151744032", max_priority_fee_per_gas_display: "0.15 gwei"},
    payload_keccak: "5f2a1c6b8d4e0937ab55c1e8d0f34721aa9c6b5e4d3f2a1908b7c6d5e4f302915",
    maximum_execution_gas_fee_display: "0.000198510751634520 ETH",
    calldata_bytes: "68",
    calldata_keccak: "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
  }, extra);
  const summary = payload.contract_call?.intent_summary;
  if (summary) payload.calldata_hex = (summary.action === "transfer" ? "0xa9059cbb" : "0x095ea7b3") +
    summary.counterparty.slice(2).toLowerCase().padStart(64, "0") + BigInt(summary.amount).toString(16).padStart(64, "0");
  return payload;
}
function previewClearSigning() {
  return {
    assurance: "trusted_description", verifier_id: "evm-clear-signing-v1",
    verifier_digest: "2c75ec2390991c0bbab6e17694525cd46ef65614fa31e62cadac6aab58751a15",
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
// Generated by tests/protocol_shapes.rs from synthetic signed catalogs.
const PREVIEW_PROTOCOL_CALLS = {
  "deposit-static": {
    "contract": "0x3333333333333333333333333333333333333333",
    "contract_name": "Example Vault",
    "function_signature": "deposit(address token, uint256 amount, address beneficiary)",
    "selector": "0xf45346dc",
    "action": "other",
    "intent": "Deposit",
    "fields": [
      {
        "label": "Token",
        "format": "addressName",
        "value": "0x1111111111111111111111111111111111111111",
        "raw": "0x1111111111111111111111111111111111111111"
      },
      {
        "label": "Amount",
        "format": "tokenAmount",
        "value": "250 EXA",
        "raw": "250000000"
      },
      {
        "label": "Credited to",
        "format": "addressName",
        "value": "0x2222222222222222222222222222222222222222",
        "raw": "0x2222222222222222222222222222222222222222"
      }
    ],
    "assurance": "Interpreted using a trusted signed description. Contract behavior has not been verified.",
    "warnings": []
  },
  "operator-approval": {
    "contract": "0x1111111111111111111111111111111111111111",
    "contract_name": "Example contract",
    "function_signature": "setApprovalForAll(address operator, bool approved)",
    "selector": "0xa22cb465",
    "action": "other",
    "fields": [
      {
        "label": "Operator",
        "format": "addressName",
        "value": "0x2222222222222222222222222222222222222222",
        "raw": "0x2222222222222222222222222222222222222222"
      },
      {
        "label": "Approved",
        "format": "raw",
        "value": "true",
        "raw": "true"
      }
    ],
    "assurance": "Interpreted using a trusted signed description. Contract behavior has not been verified.",
    "warnings": []
  },
  "stake-static": {
    "contract": "0x1111111111111111111111111111111111111111",
    "contract_name": "Example contract",
    "function_signature": "stake(uint256 amount)",
    "selector": "0xa694fc3a",
    "action": "other",
    "fields": [
      {
        "label": "Amount (raw units)",
        "format": "raw",
        "value": "250000000",
        "raw": "250000000"
      }
    ],
    "assurance": "Interpreted using a trusted signed description. Contract behavior has not been verified.",
    "warnings": []
  }
};
function previewProtocolCall(name) {
  const call = PREVIEW_PROTOCOL_CALLS[name];
  const clear = {...previewClearSigning(), catalog_id: "synthetic-protocol-fixtures", entries: []};
  const session = previewApproval([previewPayload({chain_id: "1", chain: "ethereum",
    destination: call.contract, contract_call: call})], clear);
  session.preview_status = "Synthetic descriptor test — not a deployed protocol integration";
  return session;
}
const PREVIEWS = {
  "deposit-static": () => previewProtocolCall("deposit-static"),
  "stake-static": () => previewProtocolCall("stake-static"),
  "operator-approval": () => previewProtocolCall("operator-approval"),
  "deposit-native-opaque": () => {
    const session = previewApproval([previewPayload({chain_id: "1", chain: "ethereum",
      value: "1000000000000000000", value_display: "1 ETH", calldata_bytes: "4", calldata_hex: "0xd0e30db0"})], null);
    session.preview_status = "Synthetic deposit() example — zero-argument descriptors are unsupported; explicit opaque review only";
    return session;
  },
  transfer: () => previewApproval([previewPayload({
    contract_call: previewCall("transfer", "250000000", "250 BDT", "finite", [])
  })], previewClearSigning()),
  "transfer-ethereum": () => {
    const session = previewApproval([previewPayload({chain_id: "1", chain: "ethereum",
      contract_call: previewCall("transfer", "250000000", "250 BDT", "finite", [])
    })], previewClearSigning());
    session.preview_status = "Synthetic Ethereum example — addresses are for layout testing only";
    return session;
  },
  "allowance-finite": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance", "100000000", "100 BDT", "finite", [
      PREVIEW_ALLOWANCE_ADVISORY,
      "This sets the spender's total allowance to the amount shown. It is not added to any existing allowance."])
  })], previewClearSigning()),
  "allowance-zero": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance", "0", "0 BDT", "zero", [
      "This sets the spender's allowance to zero, clearing it."])
  })], previewClearSigning()),
  "allowance-unlimited": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance",
      "115792089237316195423570985008687907853269984665640564039457584007913129639935",
      "115792089237316195423570985008687907853269984665640564039457584007913129639.935935 BDT",
      "unlimited", [
        "If executed, this spender can use all your current and future BDT without asking again. This permission has no expiry; changing it requires another transaction."])
  })], previewClearSigning()),
  "opaque-call": () => previewApproval([previewPayload({calldata_hex:
    "0xa9059cbb" + PREVIEW_SPENDER.slice(2).toLowerCase().padStart(64, "0") +
    (250000000n).toString(16).padStart(64, "0")})], null),
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
    session.preview_status = "Demo countdown — no approval is possible";
    session.preview_countdown = true;
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
  return {...fixture(), is_preview: true};
}
function renderPreview(name) {
  clearInterval(expiryTimer);
  document.getElementById("review-deadline")?.replaceChildren();
  const banner = document.getElementById("preview-banner");
  if (banner) {
    banner.hidden = false;
    banner.textContent = "Preview only · No transactions can be approved.";
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
  // The expiry demo counts down in the header, without approval controls.
  const expiryHost = document.getElementById("action-expiry");
  if (expiryHost) expiryHost.replaceChildren();
  statusNode.textContent = session.preview_status || "";
  if (pageLede) pageLede.textContent = "Review preview";
  const actions = document.querySelector(".ceremony-actions");
  if (actions) actions.hidden = true;
}

async function load() {
  if (previewPath) {
    const name = previewPath.slice("/preview".length).replace(/^\//, "") || "index";
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
  let sessionPath = "/api/session";
  let session;
  if (remoteCeremony) {
    let exchanged;
    if (token) {
      if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error("Invalid ceremony URL");
      const exchange = await fetch("/api/session/exchange", {
        method: "POST", credentials: "same-origin",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({capability: token})
      });
      token = "";
      if (!exchange.ok) throw new Error("Ceremony is unavailable");
      exchanged = await exchange.json();
      // Only a fresh, authenticated exchange supplies this projection. Never
      // reuse a stored projection on reload; it may describe a completed flow.
      session = exchanged.session;
      exchanged.expires_at = Date.now() + 25 * 60 * 1000;
    } else {
      try { exchanged = JSON.parse(browserSessionStorage()?.getItem("bloom.ceremony.remote-session.v1") || "null"); }
      catch (_) {}
    }
    if (!exchanged) throw new Error("Open a fresh ceremony link from Bloom.");
    if (!/^[0-9a-f]{64}$/.test(exchanged.ceremony_id) ||
        !/^[A-Za-z0-9_-]{43}$/.test(exchanged.csrf) ||
        !Number.isFinite(exchanged.expires_at) || exchanged.expires_at <= Date.now()) {
      clearSessionToken();
      throw new Error("This ceremony session expired. Open a fresh link from Bloom.");
    }
    ceremonyId = exchanged.ceremony_id;
    authHeaders["x-bloom-csrf"] = exchanged.csrf;
    // This reference grants nothing without the scoped HttpOnly cookie. Never
    // persist the launch capability or an exported private key.
    try { browserSessionStorage()?.setItem("bloom.ceremony.remote-session.v1", JSON.stringify({
      ceremony_id: ceremonyId, csrf: exchanged.csrf, expires_at: exchanged.expires_at
    })); } catch (_) {}
    sessionPath = `/api/session/${ceremonyId}`;
  } else if (!token) {
    throw new Error("Open a fresh ceremony link from Bloom.");
  } else if (token.length !== 43) {
    throw new Error("Invalid ceremony URL");
  }
  if (!session) {
    const response = await fetch(sessionPath, {headers: authHeaders, credentials: "same-origin"});
    if (!response.ok) throw new Error("Ceremony is unavailable");
    session = await response.json();
  }
  if (ceremonyId && ceremonyId !== session.ceremony_id) {
    throw new Error("Ceremony identity changed");
  }
  ceremonyId = session.ceremony_id;
  if (!/^[0-9a-f]{64}$/.test(ceremonyId)) throw new Error("Invalid ceremony identity");
  const priorResult = await fetch(`/api/session/${ceremonyId}/result`, {
    headers: authHeaders, credentials: "same-origin", cache: "no-store"
  });
  if (priorResult.ok) {
    const result = await priorResult.json();
    if (result.encrypted_browser_result) outputRecipient = await outputRecipientFor(session, true);
    return finishBrowserResult(session, result);
  }
  if (priorResult.status !== 409) throw new Error("Ceremony is unavailable");
  if (session.cross_surface) return loadCrossSurface(session);
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
    "wallet_registration", "wallet_import", "wallet_export", "wallet_recovery",
    "key_derive"
  ].includes(
    session.ceremony_kind
  ) && !scopedPetalKey) {
    outputRecipient = await outputRecipientFor(session);
    session = await mutate(`/api/session/${ceremonyId}/output-key`, {
      recipient_key: encodeUrl(outputRecipient.publicKey)
    });
  }
  statusNode.textContent = "";
  // Rendering applies the deadline and must have the final say on whether
  // approval is enabled, including a page first opened after its deadline.
  approve.disabled = false;
  setupCardFields();
  cardFields.hidden = session.ceremony_kind !== "card_add";
  cardCvcFields.hidden = session.review_manifest?.card_effect?.kind !== "checkout";
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
  requireLiveApproval(session);
  approve.onclick = () => run(session).catch(error => {
    // Timers can be throttled while the authenticator is open.
    try { requireLiveApproval(session); }
    catch (_) { return; }
    reportApprovalFailure(error);
  });
  cancel.onclick = async () => {
    // Both buttons stop accepting input immediately; a slow cancel response
    // must not leave an approve button clickable beside a dead ceremony.
    cancel.disabled = true;
    approve.disabled = true;
    statusNode.textContent = "Cancelling…";
    try {
      await mutate(`/api/session/${ceremonyId}/cancel`, {});
      approvalTerminal = true;
      approve.disabled = true;
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
      // An expiry that landed while cancelling stays terminal: its message
      // stands and no control comes back.
      if (approvalTerminal) return;
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
  requireLiveApproval(session);
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

  if (kind.startsWith("card_")) {
    const cardInput = cardFieldsInput(session);
    let prf;
    if (session.webauthn_options.registration_user_handle) {
      const created = await createCredential(session, 0);
      // Signer requires the second assertion, even when creation returns PRF.
      const confirmed = await ensureNewCredentialPrf(session, created, 1, true);
      credentialId = encodeUrl(created.rawId);
      prf = confirmed.prf;
      proof = {kind: "registration", attestation: attestationJson(created), prf_assertion: confirmed.assertion};
    } else {
      const assertion = await getCredential(session, 0);
      credentialId = encodeUrl(assertion.rawId);
      prf = prfResult(assertion);
      if (!prf) throw new Error("This passkey did not return required PRF output");
      proof = {kind: "assertion", assertion: assertionJson(assertion)};
    }
    const input = {credential_prf: encodeUrl(prf), ...cardInput};
    secret = te.encode(canonicalJson(input));
    prf.fill(0);
    for (const field of [...cardFields.querySelectorAll("input"), ...cardCvcFields.querySelectorAll("input")]) field.value = "";
  } else if (kind === "wallet_registration" || (kind === "wallet_import" && !legacyPasskeyImport)) {
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
  requireLiveApproval(session);
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
    if (!recovered.ok) {
      if (kind.startsWith("card_")) return reportCardFailure(session, error);
      throw error;
    }
    result = await recovered.json();
  }
  try {
    return await finishBrowserResult(session, result);
  } catch (error) {
    // Completion is terminal for approval, not proof that output recovery or
    // acknowledgement succeeded. Keep the saved recipient and report failure
    // here: the late-passkey guard must not hide this distinct result error.
    reportCeremonyError(error,
      "Ceremony completed, but the result could not be recovered or acknowledged. Keep this tab open.");
  }
}

function browserResultAad(session, contribution) {
  // Completed pre-surface receipts retain their original encrypted AAD.
  return {
    ...(contribution.surface ? {surface: contribution.surface} : {}),
    ceremony_id: contribution.ceremony_id,
    ceremony_kind: contribution.ceremony_kind,
    custody_operation_id: contribution.custody_operation_id,
    public_binding_digest: session.challenges[0].binding.exact_terms_digest,
    signer_contribution_digest: session.challenges[0].binding.signer_contribution_digest
  };
}
async function finishBrowserResult(session, result) {
  approvalTerminal = true;
  approve.disabled = true;
  if (session.ceremony_kind.startsWith("card_")) {
    const effect = session.review_manifest.card_effect;
    statusNode.textContent = effect.kind === "manual_checkout" ? (effect.card_id ? "Private view authorized. No saved card was released." : "Bloom's browser is yours. Click Done there to hand it back.") : effect.kind === "site_checkout" ? "Approved. Bloom is placing the order with your saved payment method; the outcome is reported by the shop." : session.ceremony_kind === "card_checkout" ? "Approved. Checkout is continuing; the outcome is reported by the merchant." : session.ceremony_kind === "card_add" ? "Card saved. You can close this page." : "Card deleted. You can close this page.";
    clearInterval(expiryTimer);
    cardFields.hidden = true;
    cardCvcFields.hidden = true;
    approve.hidden = true;
    cancel.hidden = true;
    if (result.challenge_url) {
      const link = el("a", {href: result.challenge_url, target: "_blank", rel: "noopener noreferrer"}, effect.kind === "manual_checkout" && !effect.card_id ? "Open Bloom's browser" : "Open private checkout view");
      reviewNode.append(el("p", {}, link));
      window.open(result.challenge_url, "_blank", "noopener,noreferrer");
    }
    await clearBrowserState(ceremonyId);
    return;
  }
  const contribution = session.signer_contribution;
  statusNode.textContent = "Completed.";
  clearInterval(expiryTimer);
  for (const fields of [recoveryFields, exportFields, importFields, genericFields]) fields.hidden = true;
  cancel.hidden = true;
  approve.hidden = true;
  if (result.encrypted_browser_result) {
    if (!outputRecipient) throw new Error("Browser output key is unavailable");
    const outputAad = canonicalJson(browserResultAad(session, contribution));
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
      surface: contribution.surface,
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
    surface: contribution.surface,
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

function reportLoadFailure(_error) {
  clearInterval(expiryTimer);
  expiryTimer = null;
  stopCrossSurface();
  approve.disabled = true;
  cancel.disabled = true;
  approve.onclick = null;
  cancel.onclick = null;
  reviewNode.replaceChildren();
  for (const field of document.querySelectorAll("#ceremony-panel input, #ceremony-panel textarea")) {
    field.value = "";
  }
  for (const fields of [recoveryFields, exportFields, importFields, genericFields]) fields.hidden = true;
  // The panel stays as the message card; only its review and actions go.
  for (const id of ["preview-banner", "review-deadline", "action-expiry"]) {
    const node = document.getElementById(id);
    if (node) node.hidden = true;
  }
  const actions = document.querySelector(".ceremony-actions");
  if (actions) actions.hidden = true;
  document.getElementById("ceremony-page").classList.add("link-unavailable");
  document.getElementById("page-title").textContent = "";
  document.getElementById("page-lede").textContent = "Link unavailable";
  document.getElementById("panel-kicker").hidden = true;
  const title = document.getElementById("panel-title");
  title.textContent = "This link couldn’t be opened";
  title.setAttribute("data-action", "");
  title.setAttribute("data-magnitude", "");
  statusNode.textContent =
    "It may have expired or already been used. Generate a new link in Bloom, or ask your agent to generate one.";
}

load().catch(reportLoadFailure);
