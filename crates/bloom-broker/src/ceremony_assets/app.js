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
    summary: "Approve exactly this operation for wallet <strong>{wallet}</strong>; nothing outside this plan is authorized.",
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
    // The public Ethereum mark: blue disc, white diamond. Drawn here so a
    // native send does not depend on a second asset request.
    svg.append(el("circle", {cx: "16", cy: "16", r: "16", fill: "#627EEA"}),
      el("path", {fill: "#fff", "fill-opacity": ".602", d: "M16.498 4v8.87l7.497 3.35z"}),
      el("path", {fill: "#fff", d: "M16.498 4 9 16.22l7.498-3.35z"}),
      el("path", {fill: "#fff", "fill-opacity": ".602", d: "M16.498 21.968v6.027L24 17.616z"}),
      el("path", {fill: "#fff", d: "M16.498 27.995v-6.028L9 17.616z"}),
      el("path", {fill: "#fff", "fill-opacity": ".2", d: "M16.498 20.573l7.497-4.353-7.497-3.348z"}),
      el("path", {fill: "#fff", "fill-opacity": ".602", d: "M9 16.22l7.498 4.353v-7.701z"}));
  } else if (kind === "base") {
    // Exact Square path from base/brand-kit, logo/TheSquare/Digital/Base_square_blue.svg.
    svg.setAttribute("viewBox", "0 0 1280 1280");
    svg.append(el("path", {fill: "#0000ff", d: "M0,101.12c0-34.64,0-51.95,6.53-65.28,6.25-12.76,16.56-23.07,29.32-29.32C49.17,0,66.48,0,101.12,0h1077.76c34.63,0,51.96,0,65.28,6.53,12.75,6.25,23.06,16.56,29.32,29.32,6.52,13.32,6.52,30.64,6.52,65.28v1077.76c0,34.63,0,51.96-6.52,65.28-6.26,12.75-16.57,23.06-29.32,29.32-13.32,6.52-30.65,6.52-65.28,6.52H101.12c-34.64,0-51.95,0-65.28-6.52-12.76-6.26-23.07-16.57-29.32-29.32-6.53-13.32-6.53-30.65-6.53-65.28V101.12Z"}));
  } else if (kind === "test") {
    svg.append(el("path", {d: "M12 3h8M14 3v10L6 26q-1 3 3 3h14q4 0 3-3l-8-13V3M10 20h12", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linejoin": "round"}));
  } else {
    svg.append(el("circle", {cx: "16", cy: "16", r: "12", fill: "none", stroke: "currentColor", "stroke-width": "2"}),
      el("circle", {cx: "16", cy: "16", r: "8", fill: "none", stroke: "currentColor", "stroke-width": "1"}));
  }
  return svg;
}

function chainIcon(chainId) {
  return {1: "ethereum", 8453: "base", 31337: "test"}[Number(chainId)] || "unknown";
}

// Reviewed, bundled artwork is generated from exact catalog identities.
// Never select an image by publisher-supplied ticker or name.
function tokenArt(chainId, address) {
  const key = `${chainId}:${String(address || "").toLowerCase()}`;
  const art = typeof REVIEWED_TOKEN_ARTWORK === "undefined" ? null : REVIEWED_TOKEN_ARTWORK[key];
  return art && typeof art.file === "string" ? art : null;
}
function tokenReviewIcon(chainId, address) {
  return artworkIcon(tokenArt(chainId, address));
}
function venueTokenArt(assetId) {
  // Exact protocol/asset binding. Test collateral keeps a neutral mark.
  return assetId === "hyperliquid:mainnet:usdc" ? {file: "usdc.svg", name: "USD Coin", symbol: "USDC"} : null;
}
function artworkIcon(art) {
  if (!art) return reviewIcon("token");
  const image = el("img", {src: `/assets/tokens/${art.file}`, alt: "", width: "56", height: "56"});
  image.onerror = () => image.replaceWith(reviewIcon("token"));
  return image;
}
// The mark sits with the amount. The address is its own row, so a label and
// the amount cannot share a line. A logo is chosen only by chain and address.
function assetCard({chainId, address, venueAsset, native, title, subtitle, amount, amountLabel, tone}) {
  const art = venueAsset ? venueTokenArt(venueAsset) : address ? tokenArt(chainId, address) : null;
  const mark = native ? reviewIcon(native) : artworkIcon(art);
  const icon = el("span", {
    class: `ceremony-token-icon${art || native === "ethereum" || native === "base" ? " has-artwork" : ""}`,
    "aria-hidden": "true"
  }, mark);
  const copy = el("div", {class: "ceremony-asset-copy"},
    el("p", {class: "ceremony-party-name"}, title || art?.name || "Token"),
    (subtitle || art?.symbol) ? el("p", {class: "ceremony-party-label"}, subtitle || art?.symbol) : null);
  const amountNode = amount ? el("div", {class: `ceremony-asset-amount ${tone || ""}`},
    amountLabel ? el("span", {class: "ceremony-amount-label"}, amountLabel) : null,
    el("strong", {}, amount)) : null;
  let addressRow = null;
  if (address && /^0x[0-9a-fA-F]{40}$/.test(address)) {
    const explorer = addressExplorer(chainId, address);
    addressRow = el("p", {class: "ceremony-party-address ceremony-asset-address"},
      explorer ? explorerAnchor(explorer, address, "Token contract") : el("code", {}, address));
  }
  return el("section", {class: "ceremony-asset", "aria-label": "Token"}, icon, copy, amountNode, addressRow);
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
// Why Bloom could not read a call, so the owner can judge it.
function unreadDetail(payload) {
  const reason = payload?.unread_reason ? ` Reason: ${payload.unread_reason}.` : "";
  return `Bloom cannot say what this call does.${reason}`;
}
function reviewedContractCall(payload) {
  return payload?.contract_call || null;
}
function technicalCallField(call, field) {
  return field.format === "raw" && (call.contract_name?.startsWith("Privacy Pools") ||
    call.contract_name === "Enso Router V2");
}
function reviewCallFields(call) {
  return (call?.fields || []).filter(field =>
    !field.label.startsWith("Owner signatures") &&
    !(field.raw === "0" && ["Safe gas limit", "Base gas"].includes(field.label)));
}
// A transfer or approval read by its ERC-20 shape alone: the amount is raw
// units of a contract Bloom has not identified, so there is no token.
function shapeOnly(call) {
  return Boolean(call?.intent_summary && !call.intent_summary.token);
}
// Headings describe the requested call. None of them promise an outcome:
// Bloom has not executed anything, and a passkey response is an approval,
// not a settlement.
function callIntent(call) {
  const summary = call?.intent_summary;
  if (!summary) {
    const fields = Object.fromEntries((call?.fields || []).map(field => [field.label, field.value]));
    const signature = String(call?.function_signature || "");
    if (call.contract_name === "Enso Router V2") {
      return {action: "call", eyebrow: "Enso route inputs", heading: "Review Enso route inputs",
        detail: "Source amounts are decoded. The shortcut's effects and quoted outputs remain unverified.", relation: "calls"};
    }
    if (call.contract_name?.startsWith("Privacy Pools")) {
      return {action: "call", eyebrow: "Privacy Pools", heading: signature.startsWith("withdraw(")
        ? "Review a direct ETH withdrawal" : "Review an ETH pool deposit",
        detail: "Proof validity, pool fees and settlement are not verified by this reading.", relation: "calls"};
    }
    if (signature.startsWith("createProxyWithNonce(")) {
      const owners = (call.fields || [])
        .filter(field => /^New Safe · Owner \d+$/.test(field.label))
        .map(field => field.value);
      const threshold = fields["New Safe · Signatures required"];
      const ownerText = owners.length === 1 ? owners[0] : naturalList(owners);
      return {
        action: "call", eyebrow: "Safe creation",
        heading: ownerText && threshold
          ? `Create a Safe owned by ${ownerText}; ${threshold} signature${threshold === "1" ? "" : "s"} required`
          : "Create a Safe",
        detail: "", relation: "creates"
      };
    }
    if (signature.startsWith("execTransaction(")) {
      const inner = fields["Safe transaction"];
      return {
        action: "call", eyebrow: "Safe execution",
        heading: inner || "Execute a Safe transaction",
        detail: "", relation: "calls"
      };
    }
    return {
      action: "call",
      eyebrow: "Contract call",
      heading: `Call ${signature.split("(")[0] || "this contract"}`,
      detail: "",
      relation: "calls"
    };
  }
  const who = shortAddress(summary.counterparty);
  const symbol = summary.token?.symbol || "tokens";
  const structural = shapeOnly(call);
  if (structural && summary.action === "transfer") {
    return {
      action: "call", magnitude: summary.magnitude,
      eyebrow: "ERC-20-shaped call",
      heading: `Review transfer-shaped call for ${summary.amount_display}`,
      detail: "The calldata names a recipient and raw amount. It does not prove that the contract will transfer tokens.",
      relation: "calls"
    };
  }
  if (structural) {
    const amount = summary.magnitude === "unlimited" ? "maximum uint256"
      : summary.magnitude === "zero" ? "zero" : summary.amount_display;
    return {
      action: "call", magnitude: summary.magnitude,
      eyebrow: "ERC-20-shaped call",
      heading: `Review approval-shaped call for ${amount}`,
      detail: "The calldata names a spender and raw total. It does not prove that the contract will change a token allowance.",
      relation: "calls"
    };
  }
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
// Safe reviews arrive as flat "Label: value" lines. The page turns those into
// a heading, one sentence, and separate rows. Function names, adapters, raw
// units, and hashes stay in a second disclosure.
function parseSafeAction(lines) {
  const warnings = [];
  const rows = [];
  let rawAction = "";
  for (const line of lines) {
    if (line.startsWith("Warning: ")) {
      warnings.push(line.slice(9));
      continue;
    }
    if (line.startsWith("Action: ") && !rawAction) {
      rawAction = line.slice(8);
      continue;
    }
    const separator = line.indexOf(": ");
    if (separator < 0) {
      rows.push({label: line.replace(/^Safe transaction · /, ""), value: ""});
      continue;
    }
    rows.push({
      label: line.slice(0, separator).replace(/^Safe transaction · /, ""),
      value: line.slice(separator + 2)
    });
  }
  return {rawAction, rows, warnings};
}
function safeRowValue(rows, label) {
  return rows.find(row => row.label === label)?.value || "";
}
function safeTechnical(row) {
  if (!row.value) return true;
  if (/^Action( \d+)?$/.test(row.label)) return true;
  if (/^Action contract \d+$/.test(row.label)) return true;
  if (/^Action sends \d+$/.test(row.label)) return true;
  if (/^Transaction \d+$/.test(row.label) && !row.value.startsWith("Send ")) return true;
  if (row.label === "Safe calls" || row.label === "Safe gas limit" || row.label === "Base gas") return true;
  if (/raw units|Contract code|Highest share price|Callback|Skip on failure/i.test(row.label)) return true;
  if (row.label.endsWith(" asset")) return true;
  if (row.label === "Sent to" || row.label.endsWith(" · Sent to")) return true;
  if ((row.label === "Safe sends" || row.label === "Value" || row.label === "Sends to the new contract")
      && /^0(?:\.0+)? ETH$/.test(row.value)) return true;
  return false;
}
function safeDecisionLabel(label) {
  const nested = label.match(/^(Transaction \d+|Action \d+) · (.+)$/);
  const name = nested ? nested[2] : label;
  const prefix = nested && nested[1].startsWith("Transaction") ? `${nested[1]} ` : "";
  if (name === "Shares go to") return `${prefix}Shares recipient`.trim();
  if (name === "To" || name === "Recipient") return `${prefix}Recipient`.trim();
  if (name === "Amount") return prefix ? `${nested[1]} amount` : "Amount";
  if (name === "Value") return "Native value";
  if (name === "Sends to the new contract") return "Value sent to the new contract";
  return prefix ? `${nested[1]} ${name}` : name;
}
// Morpho records a maximum assets-per-share price, scaled by 1e27. Turning
// that into a share count needs the vault's share decimals, which this review
// does not carry.
function safeShareBound(raw) {
  if (!/^\d+$/.test(raw)) return "Bloom cannot read this share-price bound.";
  return `The deposit reverts if one vault share would cost more than ${raw} asset units on a 1e27 scale. Bloom cannot show that as a minimum number of shares, because this review does not include the vault's share decimals.`;
}
function safeIdentityRisk(warning) {
  const match = String(warning).match(/^(?:Bloom cannot check that |Bloom has not verified that )(0x[0-9a-fA-F]{40}) is a Safe\b/);
  if (!match) return null;
  return `Bloom has not checked that ${shortAddress(match[1])} is a Safe. This signature authorizes the transaction hash for that address, and a different contract there could accept it for another effect.`;
}
function safeAmount(rows) {
  const named = rows.find(row => /(?:^|· )(Amount|Assets)$/.test(row.label) &&
    /[A-Za-z]/.test(row.value) && !row.value.includes("raw units"));
  if (named) return named.value;
  const raw = rows.find(row => ["Token amount (base units)", "Raw token amount", "Raw total allowance"].includes(row.label));
  return raw ? `${raw.value} base units` : "";
}
function safeUnlimitedAmount(amount) {
  const numeric = String(amount).match(/^(\d+)(?:\.(\d+))?(?:\s|$)/);
  return Boolean(numeric && BigInt(numeric[1] + (numeric[2] || "")) === (1n << 256n) - 1n);
}
function safeMovements(rows, rawAction) {
  const bits = [];
  for (const row of rows) {
    if (/(?:^|· )Amount$/.test(row.label) && /[A-Za-z]/.test(row.value)) {
      const prefix = row.label.replace(/Amount$/, "");
      const action = prefix ? rows.find(other => other.label === prefix.replace(/ · $/, ""))?.value : rawAction;
      // An allowance or a token pull inside a vault bundle is not a payment.
      if (!String(action || "").startsWith("transfer on ")) continue;
      const to = rows.find(other => other.label === `${prefix}To` || other.label === `${prefix}Recipient`);
      bits.push(to ? `${row.value} to ${shortAddress(to.value)}` : row.value);
    } else if (/^Transaction \d+$/.test(row.label) && /^Send .+ to 0x[0-9a-fA-F]{40}$/.test(row.value)) {
      bits.push(row.value.replace(/^Send /, "").replace(/0x[0-9a-fA-F]{40}/g, match => shortAddress(match)));
    }
  }
  return bits;
}
function describeTransfer(manifest) {
  const claim = manifest?.system_use_claim || manifest?.petal_use_claim;
  let plan = {};
  try { plan = JSON.parse(manifest?.canonical_plan || "{}"); } catch (_) {}
  const message = plan.message_review;
  if (message) {
    const payment = message.payment;
    const domain = Array.isArray(message.domain) ? message.domain : [];
    const fields = Array.isArray(message.fields) ? message.fields : [];
    const labels = {primaryType: "Message type", name: "Application named in domain", version: "Version",
      chainId: "Chain ID", verifyingContract: "Verifying contract", salt: "Domain salt"};
    const domainChain = domain.find(field => field.path === "chainId")?.value
      || fields.find(field => field.path === "Chain ID")?.value;
    let chainId = payment?.chain_id || null;
    if (!chainId && domainChain) {
      try { chainId = BigInt(domainChain).toString(); } catch (_) {}
    }
    const hyperliquid = String(message.kind).startsWith("hyperliquid_");
    const polymarket = message.kind === "polymarket_exact";
    const authenticationScope = message.kind === "polymarket_auth_scope";
    const signingChain = chainId;
    const venueNetwork = fields.find(field => ["hyperliquidChain", "Hyperliquid environment"].includes(field.path))?.value;
    if (hyperliquid) chainId = null;
    const messageType = domain.find(field => field.path === "primaryType")?.value;
    const agent = hyperliquid && messageType === "HyperliquidTransaction:ApproveAgent";
    const messageLabels = {hyperliquidChain: "Environment", destination: "Recipient",
      agentAddress: "Trading agent", agentName: "Agent name in signature", nonce: "Nonce", time: "Nonce",
      toPerp: "Move to perpetuals (false means spot)"};
    const extraTechnical = [];
    const time = value => {
      try {
        const seconds = BigInt(value);
        if (seconds === 0n) return "Immediately (0 Unix seconds)";
        if (seconds <= 253402300799n) return `${new Date(Number(seconds) * 1000).toISOString()} (${value} Unix seconds)`;
      } catch (_) {}
      return `${value} Unix seconds`;
    };
    const primary = [];
    for (const field of domain) {
      const row = [field.path === "chainId" && hyperliquid ? "Signing domain chain ID" : labels[field.path] || field.path,
        field.path === "chainId" && signingChain ? signingChain : field.value, true];
      if (hyperliquid || (polymarket && ["primaryType", "version", "salt", "chainId"].includes(field.path))
        || (payment && ["primaryType", "version", "salt"].includes(field.path))) extraTechnical.push(row);
      else primary.push(row);
    }
    if (payment) primary.push(["Valid from", time(payment.valid_after)], ["Valid until", time(payment.valid_before)]);
    else for (const field of fields) {
      const row = [hyperliquid ? messageLabels[field.path] || field.path : field.path, field.value, true];
      if (polymarket) {
        const labels = {"contents.maker": "Deposit wallet", "contents.signer": "Order signer",
          wallet: "Deposit wallet", deadline: "Signed deadline", "Side (0 buy, 1 sell)": "Order side"};
        row[0] = labels[field.path] || field.path;
        if (field.path === "Side (0 buy, 1 sell)") row[1] = field.value === "0" ? "Buy" : field.value === "1" ? "Sell" : field.value;
        if (field.path === "deadline") row[1] = time(field.value);
        if (["contents.salt", "contents.signer", "contents.signatureType", "contents.timestamp",
          "contents.metadata", "contents.builder", "name", "version", "chainId", "verifyingContract", "salt", "nonce"].includes(field.path)
          || /^calls\..*\.data$/.test(field.path)) {
          extraTechnical.push(row); continue;
        }
      }
      if (hyperliquid && (["nonce", "time", "Nonce (Unix milliseconds)"].includes(field.path)
        || (message.venue_asset && field.path === "USDC amount (HyperCore venue units)"))) extraTechnical.push(row);
      else primary.push(row);
    }
    for (const destination of claim?.declared_destinations || []) {
      primary.push([`Petal-reported destination (${chainLabel(destination.chain)})`, destination.destination, true]);
    }
    for (const amount of plan.asset_amounts || []) {
      const label = {declared_debit: "Petal-reported debit", declared_fee: "Petal-reported fee", value_limit: "Approval value limit"}[amount.kind];
      if (label) primary.push([`${label} (${chainLabel(amount.chain)})`, amount.display]);
    }
    const claimWarnings = claim?.operation_class === "gasless.relay"
      ? ["Relay's final destination and quoted output are separate Petal claims. This signature authorizes the payment to the recipient shown above."]
      : claim && !["venice-x402.topup", "hyperliquid.usd_send", "hyperliquid.withdraw", "polymarket.clob_auth.v1"].includes(claim.operation_class)
        ? ["The Petal reports the destination and policy limits. These claims are not established by the message signature; review them separately from the signed authorization."] : [];
    return {
      intent: {action: "sign_message", heading: message.title || "Sign a message"},
      button: authenticationScope ? "Allow one authentication" : payment ? "Approve payment authorization" : agent ? "Authorize trading agent"
        : hyperliquid ? "Approve exchange action" : "Approve message signature",
      sentence: authenticationScope ? "Allow the fixed authentication profile below. Broker checks the fresh message when this permission is used."
        : payment ? "Authorize this exact token payment within the signed validity window." : "Review the exact fields bound to this message signature.",
      chainId, networkIdentity: hyperliquid ? `Hyperliquid · ${venueNetwork || "Unknown environment"}`
        : chainId ? `${({1:"Ethereum",10:"Optimism",56:"BNB Chain",100:"Gnosis",137:"Polygon",8453:"Base",42161:"Arbitrum",43114:"Avalanche",59144:"Linea",999:"HyperEVM",4663:"Robinhood",4217:"Tempo"})[chainId] || "EVM"} · Chain ID ${chainId}` : "Message signature",
      networkIcon: chainId ? chainIcon(chainId) : "unknown",
      facts: [], technical: [...(message.payload_keccak ? [["Signing hash", message.payload_keccak, true]] : []),
        ...extraTechnical, ...(message.venue_asset?.base_units ? [["USDC base units", message.venue_asset.base_units, true]] : []),
        ...(payment ? fields.map(field => [field.path, field.value, true]) : [])],
      messageFields: primary,
      parties: [{role: "source", label: "Signing account", value: message.signer, chainId},
        ...(payment ? [{role: "recipient", label: "Authorized recipient", value: payment.recipient, chainId}] : [])],
      warnings: [...(message.warnings || []), ...claimWarnings],
      tokenAsset: payment ? {chainId, address: payment.token_address,
        title: payment.token?.name || "Unverified token contract", subtitle: payment.token?.symbol,
        amount: payment.amount_display, amountLabel: "Authorized payment", tone: "outgoing"}
        : message.collateral_asset ? {chainId: message.collateral_asset.chain_id,
          address: message.collateral_asset.token.address, title: message.collateral_asset.token.name,
          subtitle: message.collateral_asset.token.symbol, amount: message.collateral_asset.amount_display,
          amountLabel: "Order collateral amount",
          tone: fields.some(field => field.path === "Side (0 buy, 1 sell)" && field.value === "1") ? "incoming" : "outgoing"}
        : message.venue_asset ? {venueAsset: message.venue_asset.asset_id,
          title: message.venue_asset.name, subtitle: `HyperCore · ${message.venue_asset.environment}`,
          amount: message.venue_asset.amount_display, amountLabel: "Signed amount", tone: "outgoing"} : null
    };
  }
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
    const decoded = Boolean(reviewedContractCall(payload));
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
    const call = reviewedContractCall(payload);
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
      if (summary && field.raw === summary.amount) continue;
      if (summary && field.raw === summary.counterparty) continue;
      if (summary) facts.push([label(field.label), field.value, field.format === "addressName"]);
      else if (technicalCallField(call, field)) technical.push([label(field.label), field.value, true]);
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
    const calls = evmPayloads.filter(payload => reviewedContractCall(payload));
    for (const [index, payload] of evmPayloads.entries()) {
      const factStart = facts.length;
      const technicalStart = technical.length;
      const prefix = evmPayloads.length > 1 ? `Transaction ${index + 1}` : "";
      if (reviewedContractCall(payload)) appendCallFacts(facts, technical, payload, prefix);
      appendEnvelopeFacts(facts, technical, payload, prefix);
      for (const row of facts.slice(factStart)) row[3] = payload.chain_id;
      for (const row of technical.slice(technicalStart)) row[3] = payload.chain_id;
    }
    // Every mandatory warning, in the order the verifier produced it, kept
    // visible rather than folded into the fact list or the details section.
    const warnings = [];
    for (const payload of calls) {
      for (const warning of reviewedContractCall(payload).warnings || []) warnings.push(warning);
    }
    const interpretation = [];
    // Upgradeability belongs to a contract, so it is stated once per affected
    // contract and taken only from the selected catalog entries — the one
    // place that already lists every contract the review depended on, each
    // exactly once. The consequence is the whole warning; when the review
    // touches a single upgradeable contract the identity is already on the
    // page, and when it touches more than one the address distinguishes them.
    const upgradeable = clear ? (clear.entries || []).filter(entry => entry.upgradeable) : [];
    for (const entry of upgradeable) {
      warnings.push(upgradeable.length > 1
        ? `Upgradeable contract ${shortAddress(entry.contract_address)} — its behavior can change.`
        : "Upgradeable contract — its behavior can change.");
      interpretation.push(["Upgradeable contract",
        `${entry.contract_address} — its code may have changed since this Bloom release described it.`]);
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
            intent: reviewedContractCall(payload)
              ? callIntent(reviewedContractCall(payload))
              : payload.destination && payload.calldata_keccak
              ? {action: "opaque", eyebrow: "Contract call", heading: "Approve a call Bloom cannot read",
                 detail: unreadDetail(payload),
                 relation: "calls"}
              : {action: payload.destination ? "send" : "deploy",
                 eyebrow: payload.destination ? "Native transfer" : "Contract creation",
                 heading: payload.destination
                   ? `Send ${payload.value_display}` : "Deploy a contract",
                 detail: payload.destination
                   ? "Bloom checked the envelope: destination and value come from the transaction bytes."
                   : "This creates a new contract. Bloom does not verify what its code does.",
                 relation: payload.destination ? `sends ${payload.value_display} to` : "creates"},
            counterparty: reviewedContractCall(payload)?.intent_summary?.counterparty || payload.destination,
            counterpartyRole: reviewedContractCall(payload)?.intent_summary?.counterparty_role ||
              (reviewedContractCall(payload) || payload.calldata_keccak ? "contract" : "recipient"),
            contract: reviewedContractCall(payload)?.contract,
            contractName: reviewedContractCall(payload)?.intent_summary?.token
              ? `${reviewedContractCall(payload).intent_summary.token.symbol} — ${reviewedContractCall(payload).intent_summary.token.name}`
              : reviewedContractCall(payload)?.contract_name,
            token: reviewedContractCall(payload)?.intent_summary?.token || null,
            amountDisplay: reviewedContractCall(payload)?.intent_summary?.amount_display || null,
            magnitude: reviewedContractCall(payload)?.intent_summary?.magnitude || null,
            tokenAction: reviewedContractCall(payload)?.intent_summary?.action || null
          }))
        }
      : reviewedContractCall(first)
        ? callIntent(reviewedContractCall(first))
        : first.destination
          ? (first.calldata_keccak
            ? {action: "opaque", eyebrow: "Contract call", heading: "Approve a call Bloom cannot read",
               detail: unreadDetail(first),
               relation: "calls"}
            : {action: "send", eyebrow: "Native transfer",
               heading: `Send ${first.value_display}`,
               detail: "",
               relation: `sends ${first.value_display} to`})
          : {action: "deploy", eyebrow: "Contract creation", heading: "Deploy a contract",
             detail: "This creates a new contract from the initcode below. Bloom does not verify " +
               "what that code does.", relation: "creates"};
    const firstCall = reviewedContractCall(first);
    const summary = firstCall?.intent_summary;
    const counterparty = summary?.counterparty ||
      (firstCall ? null : first.destination);
    const parties = [{role: "source", label: "From this wallet", value: first.sender}];
    if (counterparty) {
      parties.push({
        role: summary?.counterparty_role || (intent.action === "allowance" ? "spender"
          : intent.action === "transfer" || intent.action === "send" ? "recipient" : "contract"),
        label: summary?.counterparty_role === "spender" ? "Spender"
          : summary?.counterparty_role === "recipient" ? "Recipient"
          : intent.action === "allowance" ? "Spender"
          : intent.action === "transfer" || intent.action === "send" ? "Recipient" : "Contract being called",
        value: counterparty
      });
    }
    // For the canonical ERC-20 actions the token is the contract being
    // called, and showing the same address twice under two headings invites
    // the reader to check it twice. One row, labelled for both. Different
    // addresses keep both roles, whatever their names say.
    if (summary?.token) {
      const sameAddress = summary.token.address.toLowerCase() ===
        String(firstCall.contract).toLowerCase();
      parties.push({
        role: "token",
        label: sameAddress ? "Token contract — the contract being called"
          : "Token contract",
        name: `${summary.token.symbol} — ${summary.token.name}`,
        value: summary.token.address
      });
      if (!sameAddress) {
        parties.push({role: "contract", label: "Contract being called",
          name: firstCall.contract_name || null,
          value: firstCall.contract});
      }
    } else if (firstCall) {
      parties.push({role: "contract", label: "Contract being called",
        name: firstCall.contract_name || null,
        value: firstCall.contract});
    }
    // One sentence, from the review rather than from matching warning text.
    // A mixed batch never borrows the stronger assurance of its first member.
    const structuralCalls = evmPayloads.filter(payload => shapeOnly(payload.contract_call));
    const assurance = structuralCalls.length && clear
      ? "This batch mixes trusted catalog descriptions with structural calldata readings. Structural readings verify exact arguments, not contract or token behavior."
      : structuralCalls.length
        ? (structuralCalls.length === 1 ? structuralCalls[0].contract_call.assurance
          : "These calls match standard ERC-20 calldata shapes. Bloom verified their exact arguments, but not that the contracts are tokens or follow ERC-20 behavior.")
        : firstCall?.assurance ||
          (clear ? "Interpreted using Bloom's description of this contract. Contract behavior has not been verified."
                 : "Transaction destination, value and bytes checked. Contract behavior not verified.");
    if (clear) {
      interpretation.push(["Assurance class", clear.assurance]);
    }
    const networkIdentity = oneNetwork
      ? `EVM · ${network} · Chain ID ${first.chain_id}` : "EVM · Multiple networks";
    // The amount, the token mark, and the counterparties are on the page.
    // A sentence that points at a closed disclosure is how those disappeared.
    const sentence = intent.action === "batch"
      ? `One approval covers all ${evmPayloads.length} transactions on <strong>${escapeHtml(network)}</strong>, in the order below.`
      : "";
    return {intent, sentence, payloads: evmPayloads, parties: parties.map(party => ({...party, chainId: first.chain_id})), assurance, interpretation, mixedAssurance: Boolean(clear && structuralCalls.length), facts, technical, warnings, networkIdentity,
            chainId: evmPayloads.length === 1 ? first.chain_id : null,
            assetSummary: evmPayloads.length === 1 ? summary : null,
            networkIcon: oneNetwork ? chainIcon(first.chain_id) : "unknown",
            willVerify: true};
  }
  const safe = plan.safe_review;
  if (safe) {
    const network = chainLabel(safe.chain);
    // Warnings are lines inside `action`. The banner shows them; the other
    // lines become one row each. Joining those lines into one cell hides the
    // amount, the vault, and the recipient in a single unreadable string.
    const parsed = parseSafeAction(safe.action);
    const {rawAction, rows} = parsed;
    const threshold = safeRowValue(rows, "Signatures required");
    const thresholdText = threshold
      ? `${threshold} signature${threshold === "1" ? "" : "s"}` : "";
    const amount = safeAmount(rows);
    const vaults = rows.filter(row => /(?:^|· )Vault$/.test(row.label));
    const shareRecipients = rows.filter(row => /Shares go to$/.test(row.label));
    const vault = vaults.length === 1 ? vaults[0].value : "";
    const shares = shareRecipients.length === 1 ? shareRecipients[0].value : "";
    const morphoBundle = rawAction.startsWith("multicall on Morpho Bundler3");
    const nestedActions = rows.filter(row => /^Action \d+$/.test(row.label));
    const simpleMorphoDeposit = morphoBundle && vault && shares &&
      nestedActions.length === 2 &&
      nestedActions[0].value.startsWith("erc20TransferFrom on ") &&
      nestedActions[1].value.startsWith("erc4626Deposit on ") &&
      safeRowValue(rows, "Action 1 · Amount") === safeRowValue(rows, "Action 2 · Assets") &&
      /^0x[0-9a-fA-F]{40}$/.test(safeRowValue(rows, "Action 2 · Assets asset")) &&
      safeRowValue(rows, "Action 1 · Token").toLowerCase() === safeRowValue(rows, "Action 2 · Assets asset").toLowerCase();
    const recipient = safeRowValue(rows, "Recipient") || safeRowValue(rows, "To");
    const spender = safeRowValue(rows, "Spender");
    const permission = rawAction.startsWith("approve on ");
    const unlimited = permission && safeUnlimitedAmount(amount);
    const sendTo = rawAction.match(/^Send (.+) to (0x[0-9a-fA-F]{40})$/);
    const movements = safeMovements(rows, rawAction);
    const safeShort = shortAddress(safe.safe);
    let heading = rawAction.replace(/0x[0-9a-fA-F]{40}/g, match => shortAddress(match));
    let sentence = `On <strong>${escapeHtml(network)}</strong>, Safe <strong>${escapeHtml(safeShort)}</strong> requests this action. Amounts, parties, and the nonce are listed below.`;
    if (rawAction.startsWith("addOwnerWithThreshold")) {
      heading = `Add owner ${shortAddress(safeRowValue(rows, "New owner"))}; ${thresholdText} still required`;
      sentence = `Add <strong>${escapeHtml(shortAddress(safeRowValue(rows, "New owner")))}</strong> as an owner of Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>. ${escapeHtml(thresholdText)} will still be required.`;
    } else if (rawAction.startsWith("removeOwner")) {
      heading = `Remove owner ${shortAddress(safeRowValue(rows, "Removed owner"))}; ${thresholdText} still required`;
      sentence = `Remove owner <strong>${escapeHtml(shortAddress(safeRowValue(rows, "Removed owner")))}</strong> from Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>. ${escapeHtml(thresholdText)} will still be required.`;
    } else if (rawAction.startsWith("swapOwner")) {
      heading = `Replace owner ${shortAddress(safeRowValue(rows, "Removed owner"))} with ${shortAddress(safeRowValue(rows, "New owner"))}`;
      sentence = `Replace owner <strong>${escapeHtml(shortAddress(safeRowValue(rows, "Removed owner")))}</strong> with <strong>${escapeHtml(shortAddress(safeRowValue(rows, "New owner")))}</strong> on Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>.`;
    } else if (rawAction.startsWith("changeThreshold")) {
      heading = `Require ${thresholdText}`;
      sentence = `Require <strong>${escapeHtml(thresholdText)}</strong> on Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>.`;
    } else if (permission && amount && spender) {
      heading = unlimited ? `Allow unlimited spending by ${shortAddress(spender)}`
        : /^0(?:\.0+)?\s/.test(amount) ? `Clear spending permission for ${shortAddress(spender)}`
        : `Allow ${shortAddress(spender)} to spend up to ${amount}`;
      sentence = `Change this spender's permission to use tokens held by Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>.`;
    } else if (rawAction.startsWith("transfer on ") && amount && recipient) {
      heading = `Send ${amount} to ${shortAddress(recipient)}`;
      sentence = `Send <strong>${escapeHtml(amount)}</strong> from Safe <strong>${escapeHtml(safeShort)}</strong> to <strong>${escapeHtml(shortAddress(recipient))}</strong> on <strong>${escapeHtml(network)}</strong>.`;
    } else if (sendTo) {
      heading = `Send ${sendTo[1]} to ${shortAddress(sendTo[2])}`;
      sentence = `Send <strong>${escapeHtml(sendTo[1])}</strong> from Safe <strong>${escapeHtml(safeShort)}</strong> to <strong>${escapeHtml(shortAddress(sendTo[2]))}</strong> on <strong>${escapeHtml(network)}</strong>.`;
    } else if (rawAction.startsWith("performCreate2")) {
      heading = "Create a contract at a fixed address";
      sentence = `Create a contract at a fixed address from Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>.`;
    } else if (rawAction.startsWith("performCreate")) {
      heading = "Create a contract";
      sentence = `Create a contract from Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>.`;
    } else if (simpleMorphoDeposit || rawAction.startsWith("erc4626Deposit")) {
      const morpho = Boolean(simpleMorphoDeposit);
      const vaultName = morpho ? "a Morpho vault" : "a vault";
      heading = amount ? `Deposit ${amount} into ${vaultName}` : `Deposit into ${vaultName}`;
      const who = !shares ? "the recipient in details"
        : shares.toLowerCase() === String(safe.owner).toLowerCase() ? `your account ${shortAddress(shares)}`
        : shares.toLowerCase() === String(safe.safe).toLowerCase() ? `this Safe ${shortAddress(shares)}`
        : shortAddress(shares);
      const deposited = amount ? `<strong>${escapeHtml(amount)}</strong>` : "tokens";
      const into = vault ? `vault <strong>${escapeHtml(shortAddress(vault))}</strong>` : vaultName;
      sentence = `Deposit ${deposited} into ${into} on <strong>${escapeHtml(network)}</strong>. Vault shares go to <strong>${escapeHtml(who)}</strong>.`;
    } else if (morphoBundle) {
      heading = "Review calls through Morpho";
      sentence = `Review every call from Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong> in the details below.`;
    } else if (rawAction.startsWith("multiSend") || movements.length > 1) {
      const transactions = rows.filter(row => /^Transaction \d+$/.test(row.label));
      const onlyTransfers = transactions.length > 0 && transactions.every(row =>
        row.value.startsWith("transfer on ") || /^Send .+ to 0x[0-9a-fA-F]{40}$/.test(row.value));
      heading = onlyTransfers && movements.length
        ? `Send ${naturalList(movements.map(bit => bit.split(" to ")[0]))}`
        : transactions.length ? `Review ${transactions.length} Safe actions` : "Review Safe actions";
      sentence = onlyTransfers && movements.length
        ? `From Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>: ${escapeHtml(naturalList(movements))}.`
        : `One approval covers every action from Safe <strong>${escapeHtml(safeShort)}</strong> on <strong>${escapeHtml(network)}</strong>. Review each action below.`;
    } else if (amount && recipient) {
      heading = `Send ${amount} to ${shortAddress(recipient)}`;
      sentence = `Send <strong>${escapeHtml(amount)}</strong> from Safe <strong>${escapeHtml(safeShort)}</strong> to <strong>${escapeHtml(shortAddress(recipient))}</strong> on <strong>${escapeHtml(network)}</strong>.`;
    } else if (rawAction === "Contract call Bloom cannot read") {
      const reason = safeRowValue(rows, "Reason");
      heading = "Contract call Bloom cannot read";
      sentence = `Bloom cannot read this Safe transaction on <strong>${escapeHtml(network)}</strong> for Safe <strong>${escapeHtml(safeShort)}</strong>.${reason ? ` ${escapeHtml(reason)}.` : ""}`;
    }
    const share = rows.find(row => /Highest share price/i.test(row.label));
    const facts = rows
      .filter(row => !safeTechnical(row))
      .map(row => [safeDecisionLabel(row.label), row.value, /^0x[0-9a-fA-F]{40}$/.test(row.value)]);
    facts.push(["Safe", safe.safe, true], ["Network", network], ["Nonce", safe.nonce]);
    if (share) facts.push(["Share bound", safeShareBound(share.value)]);
    const technical = [["Described as", rawAction, false]];
    for (const row of rows.filter(safeTechnical)) {
      technical.push([row.label, row.value, /^0x[0-9a-fA-F]{40}$/.test(row.value) || row.label === "Contract code"]);
    }
    technical.push(["Signing owner", safe.owner, true]);
    if (safe.destination.toLowerCase() !== safe.safe.toLowerCase()) technical.push(["Calls", safe.destination, true]);
    if (safe.operation === "delegatecall") technical.push(["Operation", "delegatecall"]);
    technical.push(["Safe transaction hash", safe.safe_tx_hash, true]);
    for (const warning of parsed.warnings) {
      if (safeIdentityRisk(warning)) technical.push(["Safe identity check", warning, false]);
    }
    const warnings = parsed.warnings.map(warning => safeIdentityRisk(warning) || warning);
    const safeCards = rawAction.startsWith("multiSend") ? rows
      .filter(row => /^Transaction \d+$/.test(row.label))
      .map(row => {
        const value = name => safeRowValue(rows, `${row.label} · ${name}`);
        const tokenCall = row.value.match(/^(approve|transfer) on (?:.+ )?(0x[0-9a-fA-F]{40})$/);
        const morpho = row.value.startsWith("multicall on Morpho Bundler3 ");
        const native = row.value.match(/^Send (.+) to (0x[0-9a-fA-F]{40})$/);
        const address = tokenCall?.[2] || (morpho ? value("Action 1 · Token") : "");
        const amount = tokenCall ? value("Amount") : morpho ? value("Action 1 · Amount") : native?.[1];
        const permission = tokenCall?.[1] === "approve";
        const unlimited = permission && safeUnlimitedAmount(amount);
        return {
          position: row.label,
          title: permission ? "Token spending permission" : tokenCall ? "Token transfer"
            : morpho ? "Calls through Morpho" : native ? "Native transfer" : "Contract call",
          asset: address && amount ? {chainId: String(safe.chain_id), address, amount: unlimited ? "Unlimited" : amount,
            amountLabel: permission ? "Spending limit" : morpho ? "Tokens supplied" : "Amount",
            tone: unlimited ? "danger" : permission ? "permission" : "outgoing"}
            : native ? {native: / ETH$/.test(amount) ? "ethereum" : "token", amount, amountLabel: "Amount"} : null,
          parties: [
            [permission ? "Spender" : "Recipient", permission ? value("Spender") : value("To") || value("Recipient") || native?.[2]],
            ["Vault", morpho ? value("Action 2 · Vault") : ""],
            ["Shares recipient", morpho ? value("Action 2 · Shares go to") : ""]
          ].filter(([, address]) => /^0x[0-9a-fA-F]{40}$/.test(address || ""))
        };
      }) : [];
    const tokens = rows.filter(row =>
      /(?:^|· )Token$/.test(row.label) && /^0x[0-9a-fA-F]{40}$/.test(row.value));
    const directToken = rawAction.match(/^(?:approve|transfer) on (?:.+ )?(0x[0-9a-fA-F]{40})$/)?.[1];
    const amountAssets = [...new Set(rows.filter(row => /(?:Amount|Assets) asset$/.test(row.label))
      .map(row => row.value.toLowerCase()))];
    const tokenAddress = !rawAction.startsWith("multiSend") && movements.length <= 1
      ? tokens.length === 1 ? tokens[0].value : directToken || (amountAssets.length === 1 ? amountAssets[0] : "") : "";
    const tokenAsset = tokenAddress && amount
      ? {chainId: String(safe.chain_id), address: tokenAddress, amount: unlimited ? "Unlimited" : amount,
          amountLabel: permission ? "Spending limit" : "Amount",
          tone: unlimited ? "danger" : permission ? "permission" : "outgoing"}
      : sendTo ? {native: / ETH$/.test(sendTo[1]) ? "ethereum" : "token",
          title: / ETH$/.test(sendTo[1]) ? "Ether" : "Native asset", amount: sendTo[1],
          amountLabel: "Amount", tone: "outgoing"} : null;
    const safeRecipient = directToken ? recipient : sendTo?.[2];
    const safeParties = (permission && spender) ? [["Spender", spender]]
      : safeRecipient ? [["Recipient", safeRecipient]] : [];
    return {sentence, facts, technical, warnings, willVerify: true, heading,
      button: "Approve Safe signature", chainId: safe.chain_id, tokenAsset, safeCards, safeParties,
      networkIdentity: `EVM · ${network} · Chain ID ${safe.chain_id}`,
      networkIcon: chainIcon(safe.chain_id)};
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
    sentence: `Allow <strong>${app}</strong> to use a temporary Solana session key for up to <strong>${duration}</strong>; no funds move, and your main wallet key stays inside Bloom.`,
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
    sentence: `Finish setting up a temporary <strong>${app}</strong> session for only the actions in details; no funds move, and your main wallet key stays inside Bloom.`,
    facts: [
      ["App", app],
      ["Package", packageHash, true],
      ["Can", naturalList(actions)],
      ["Limit", operationLimit],
      ["Spending ceiling", spending],
      ["Main wallet key", "Stays inside Bloom"]
    ],
    title: "Finish temporary session setup",
    heading: "Create a temporary Petal session",
    button: "Finish session setup",
    warning: `${app} creates transactions within these permissions; if compromised, it could use the remaining session capacity before the timer expires.`
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
      "any address through the deployment workflow, including contract creation, and Safe owner signing; every transaction still needs its own approval"]);
    else lines.push(["Allow sending to", dest(d), true]);
  }
  for (const d of diff.removed_destinations || []) {
    if (isDeployGrant(d)) lines.push([`Stop allowing exact transactions on ${chainLabel(d.chain)}`,
      "deployment transactions need listed recipients again; contract creation and Safe owner signing are refused"]);
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
  const n = lines.length;
  const sentence = n === 0
    ? "No rule changes are proposed."
    : `Change <strong>${n} rule${n === 1 ? "" : "s"}</strong> for this wallet; nothing moves, and Bloom applies the new rules to future transactions.`;
  const intent = n === 0 ? null : {
    action: "policy", eyebrow: "Wallet policy change",
    heading: `Change ${n} wallet rule${n === 1 ? "" : "s"}`,
    detail: "These rules apply to future requests. Approving them moves no funds."
  };
  return {sentence, intent, facts: lines};
}
function planDisclosures(manifest) {
  try {
    const plan = JSON.parse(manifest?.canonical_plan || "{}");
    return Array.isArray(plan.security_disclosures) ? plan.security_disclosures : [];
  } catch (_) { return []; }
}

const explorerAnchor = (explorer, value, label) =>
  el("a", {href: explorer.url, class: "ceremony-address-link", target: "_blank",
    rel: "noopener noreferrer", referrerpolicy: "no-referrer",
    title: `View on ${explorer.name} (opens a new tab)`,
    "aria-label": `${label}: ${value}. View on ${explorer.name} (opens a new tab)`},
    el("code", {}, value));

function renderReview(session) {
  const kind = session.ceremony_kind;
  const meta = KINDS[kind] || {title: kind.replace(/_/g, " "), summary: "", button: "Continue with passkey"};
  const manifest = session.review_manifest;
  const custodyManifest = manifest?.schema === "bloom.custody_ceremony_review.v1";
  const contribution = session.signer_contribution || {};
  const wallet = contribution.wallet_id || manifest?.wallet_name || manifest?.wallet_id || "";
  panelKicker.textContent = "Step 1 of 2 · Check";
  panelTitle.textContent = meta.title;
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
  const primaryWarnings = [];
  const detailNotes = [];
  let transfer = null;
  let petalScope = null;
  let petalApproval = null;
  if (kind === "sealed_approval") {
    transfer = describeTransfer(session.review_manifest);
    if (transfer) {
      if (transfer.sentence != null) summaryHtml = transfer.sentence;
      // The button names what is being approved. A passkey response means
      // approved — not signed, broadcast or confirmed.
      if (transfer.intent) {
        approve.textContent = transfer.intent.action === "allowance" ? "Approve allowance"
          : transfer.intent.action === "transfer" || transfer.intent.action === "send" ? "Approve transfer"
          : transfer.intent.action === "batch" ? "Approve all transactions"
          : transfer.intent.action === "deploy" ? "Approve contract creation"
          : transfer.intent.action === "sign_message" ? transfer.button
          : "Approve call";
      }
    } else {
      petalApproval = describePetalApproval(session.review_manifest);
      if (petalApproval) {
        transfer = petalApproval;
        summaryHtml = petalApproval.sentence;
        approve.textContent = petalApproval.button;
        if (petalApproval.heading) panelTitle.textContent = petalApproval.heading;
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
  if (transfer?.heading) panelTitle.textContent = transfer.heading;
  if (transfer?.button) approve.textContent = transfer.button;
  const contextualFacts = transfer?.intent ? new Set(["Network"]) : new Set();
  if ((transfer?.intent || transfer?.networkIdentity) && pageTitle) {
    const network = transfer.networkIdentity || transfer.facts.find(([label]) => label === "Network")?.[1];
    pageTitle.textContent = network || ["Wallet settings", walletName].filter(Boolean).join(" · ");
    if (transfer.networkIdentity) pageTitle.replaceChildren(reviewIcon(transfer.networkIcon),
      el("span", {}, network));
  }
  if (!transfer?.intent) fact("Wallet", walletName);
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
    for (const item of session.review_manifest?.attributed_advisory_items || []) primaryWarnings.push(item);
    // Proof verification occurs during authorization, after this review.
    // Never suppress the plan's present-tense disclosure merely because the
    // Machine requested proof verification for the later signing step.
    if (petalApproval) primaryWarnings.push(petalApproval.warning);
    else for (const item of planDisclosures(session.review_manifest)) detailNotes.push(item);
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
  const decision = [];
  const evidence = [];
  if (transfer?.tokenAsset) {
    decision.push(assetCard(transfer.tokenAsset));
  }
  if (transfer?.messageFields?.length) {
    const fields = el("dl", {class: "facts ceremony-message-fields"});
    for (const [label, value, mono] of transfer.messageFields) {
      fields.append(el("dt", {}, label), el("dd", {}, mono ? el("code", {}, value) : value));
    }
    decision.push(fields);
  }
  for (const card of transfer?.safeCards || []) {
    const section = el("section", {class: "ceremony-card"},
      el("p", {class: "ceremony-card-position"}, card.position),
      el("h2", {class: "ceremony-section-title"}, card.title),
      card.asset ? assetCard(card.asset) : null);
    for (const [label, value] of card.parties) {
      section.append(partyRow({role: label.toLowerCase(), label, value, chainId: transfer.chainId}));
    }
    decision.push(section);
  }
  for (const [label, value] of transfer?.safeParties || []) {
    decision.push(partyRow({role: label.toLowerCase(), label, value, chainId: transfer.chainId}));
  }
  if (transfer?.intent) {
    panelTitle.textContent = transfer.intent.heading;
    panelTitle.setAttribute("data-action", transfer.intent.action);
    panelTitle.setAttribute("data-magnitude", transfer.intent.magnitude || "");
    const token = transfer.parties?.find(party => party.role === "token");
    const summary = transfer.assetSummary;
    if (token && transfer.intent.action !== "batch") {
      const identity = summary?.token;
      const unlimited = summary?.magnitude === "unlimited";
      const sending = summary?.action === "transfer";
      decision.push(assetCard({
        chainId: token.chainId,
        address: token.value,
        title: identity?.name || token.name,
        subtitle: identity?.symbol,
        amount: !summary ? null : unlimited ? "Unlimited" : summary.amount_display,
        amountLabel: sending ? "Amount" : "Spending limit",
        tone: unlimited ? "danger" : sending ? "outgoing" : "permission"
      }));
    } else if (transfer.intent.action === "send") {
      const display = String(transfer.payloads?.[0]?.value_display || "");
      const eth = / ETH$/.test(display);
      decision.push(assetCard({
        native: eth ? "ethereum" : "token",
        title: eth ? "Ether" : "Native asset",
        amount: display,
        amountLabel: "Amount",
        tone: "outgoing"
      }));
    }
    if (transfer.intent.detail) decision.push(intentBlock(transfer.intent));
    for (const [index, payload] of (transfer.payloads || []).entries()) {
      const call = reviewedContractCall(payload);
      if (!call || call.intent_summary) continue;
      const protocolDetails = call.contract_name?.startsWith("Privacy Pools") || call.contract_name === "Enso Router V2";
      const argumentsList = el("dl", {class: "facts"});
      for (const field of reviewCallFields(call)) {
        if (technicalCallField(call, field)) continue;
        if (field.asset?.token) {
          const asset = field.asset;
          decision.push(assetCard({chainId: String(asset.chain_id), address: asset.token.address,
            title: asset.token.name, subtitle: asset.token.symbol,
            amount: asset.amount_display, amountLabel: field.label,
            tone: call.contract_name === "Enso Router V2" ? "outgoing" : "neutral"}));
          continue;
        }
        const explorer = addressExplorer(payload.chain_id, field.value);
        const value = explorer ? explorerAnchor(explorer, field.value, field.label)
          : el("code", {}, field.value);
        argumentsList.append(el("dt", {}, field.label), el("dd", {}, value));
      }
      decision.push(el("section", {class: "ceremony-call-arguments"},
        el("h2", {class: "ceremony-section-title"}, transfer.payloads.length > 1 ? `Transaction ${index + 1} arguments` : protocolDetails ? "Call details" : "Function arguments"),
        protocolDetails ? null : el("code", {class: "ceremony-function"}, call.function_signature),
        argumentsList));
    }
    if (transfer.warnings?.length) {
      primaryWarnings.push(...transfer.warnings);
    }
    for (const card of transfer.intent.cards || []) {
      const unlimited = card.magnitude === "unlimited";
      const wrapper = el("section", {class: "ceremony-card"},
        el("p", {class: "ceremony-card-position"}, `Transaction ${card.position}`),
        card.token ? assetCard({
          chainId: card.chainId,
          address: card.token.address,
          title: card.token.name,
          subtitle: card.token.symbol,
          amount: unlimited ? "Unlimited" : card.amountDisplay,
          amountLabel: card.tokenAction === "transfer" ? "Amount" : "Spending limit",
          tone: unlimited ? "danger" : card.tokenAction === "transfer" ? "outgoing" : "permission"
        }) : null,
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
      decision.push(wrapper);
    }
    if (transfer.parties?.length) {
      const isTransfer = ["transfer", "send"].includes(transfer.intent.action);
      const parties = [...transfer.parties].filter(party =>
        transfer.intent.action === "batch" ? party.role === "source" : party !== token).sort((a, b) =>
          Number(b.role === "spender") - Number(a.role === "spender"));
      const flow = el("div", {class: `ceremony-identity ${isTransfer ? "ceremony-transfer-path" : "ceremony-permission"}`});
      const movement = isTransfer && transfer.assetSummary?.action === "transfer"
        ? transfer.assetSummary.amount_display : null;
      for (const party of parties) {
        if (isTransfer && party.role === "recipient") {
          flow.append(el("div", {class: "ceremony-flow-arrow", "aria-hidden": "true"}, "↓"));
        }
        const change = movement && ["source", "recipient"].includes(party.role)
          ? `${party.role === "source" ? "−" : "+"}${movement}` : null;
        flow.append(partyRow({...party, change,
          ...(party.role === "source" ? {label: isTransfer ? "Sender" : "Your wallet", name: walletName} : {})}));
      }
      decision.push(flow);
    }
    for (const [index, payload] of (transfer.payloads || []).entries()) {
      if (!payload.calldata_keccak) continue;
      const name = payload.destination ? "Calldata" : "Initcode";
      const prefix = transfer.payloads.length > 1 ? `Transaction ${index + 1} · ` : "";
      const raw = el("details", {class: "ceremony-details ceremony-calldata"},
        el("summary", {}, `${prefix}${name} · ${payload.calldata_bytes} bytes`),
        payload.calldata_hex ? el("pre", {}, payload.calldata_hex)
          : el("p", {class: "ceremony-assurance"}, "This older review records only the data length and hash. Prepare a new review to see the bytes."));
      if (!reviewedContractCall(payload)) raw.setAttribute("open", "");
      evidence.push(reviewedContractCall(payload) ? raw : el("section", {class: "ceremony-raw"}, raw));
    }
  } else {
    if (transfer?.warnings?.length) primaryWarnings.push(...transfer.warnings);
  }
  evidence.push(facts);
  for (const [index, payload] of (transfer?.payloads || []).entries()) {
    const exact = payload.maximum_execution_gas_fee_display;
    const label = transfer.payloads.length > 1 ? `Transaction ${index + 1} gas fee` : "Gas fee";
    const amount = exact ? el("span", {class: "ceremony-fee-amount"},
      reviewIcon(exact.endsWith(" ETH") ? "ethereum" : "token"),
      el("span", {}, `Up to ${compactFeeCap(exact)}`))
      : el("span", {}, "Cannot be shown for this network");
    decision.push(el("div", {class: "ceremony-fee", "aria-label": "Execution gas only; other network charges may apply"},
      el("span", {class: "ceremony-fee-label"}, label), amount));
  }
  if (meta.warn) primaryWarnings.unshift(meta.warn);
  for (const note of detailNotes) evidence.push(el("p", {class: "ceremony-assurance"}, note));

  if (transfer?.interpretation?.length) {
    const rows = el("dl", {class: "facts"});
    for (const [label, value, mono] of transfer.interpretation) {
      rows.append(el("dt", {}, label), el("dd", {}, mono ? el("code", {}, value) : value));
    }
    evidence.push(el("details", {class: "ceremony-details"},
      el("summary", {}, "How this was interpreted"),
      el("p", {}, transfer.mixedAssurance
        ? "Catalogued calls are read with descriptions built into this Bloom release. Structural calls are decoded from their exact calldata without trusting a deployment identity. Neither reading proves execution behavior."
        : "This call is read with a description of this deployment built into this Bloom release. " +
          "It is not proof of what the contract does, and Bloom did not execute anything."),
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
    evidence.push(el("details", {class: "signed technical"},
      el("summary", {}, "Raw values and byte commitments"),
      technical));
  }
  if (kind !== "key_derive" && custodyManifest && typeof manifest.canonical_plan === "string" &&
      manifest.canonical_plan.trim()) {
    evidence.push(el("details", {class: "signed ceremony-details"},
      el("summary", {}, "The exact plan that was reviewed"),
      el("pre", {}, manifest.canonical_plan)));
  }
  const signed = session.review_manifest || {
    ceremony_kind: kind, signer_contribution: session.signer_contribution
  };
  evidence.push(el("details", {class: "signed"},
    el("summary", {}, "What your passkey signs (signed manifest)"),
    el("pre", {}, canonicalJson(signed).replace(/,"/g, ',\n"'))));
  const warning = primaryWarnings.filter(Boolean).length
    ? el("aside", {class: "ceremony-warning", "aria-label": "Risk to review"},
        el("p", {}, [...new Set(primaryWarnings.filter(Boolean))].join(" ")))
    : null;
  const primary = [];
  if (summaryHtml) primary.push(el("p", {class: "summary", html: summaryHtml}));
  const hero = decision.filter(node => String(node.className || "").includes("ceremony-asset"));
  const rest = decision.filter(node => !String(node.className || "").includes("ceremony-asset"));
  primary.push(...hero, ...rest);
  if (warning) primary.push(warning);
  reviewNode.replaceChildren(...primary,
    el("details", {class: "ceremony-details ceremony-evidence"},
      el("summary", {}, "Verification and technical details"),
      transfer?.assurance ? el("p", {class: "ceremony-assurance"}, transfer.assurance) : null,
      ...evidence));
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

function reportApprovalFailure(error) {
  if (approvalTerminal) return;
  const missingPrf = error?.name === "NotSupportedError" ||
    (typeof error?.message === "string" && error.message.includes("required PRF output"));
  reportCeremonyError(error, missingPrf
    ? "This browser or passkey does not support the required PRF extension. Use a supported browser and passkey."
    : "Passkey verification failed. Please try again.");
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
const PREVIEW_TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PREVIEW_TOKEN_IDENTITY =
  {address: PREVIEW_TOKEN, symbol: "USDC", name: "USD Coin", decimals: 6};
const PREVIEW_ASSURANCE =
  "Interpreted using Bloom's description of this contract. Contract behavior has not been verified.";
const PREVIEW_ALLOWANCE_ADVISORY =
  "This spender can move your tokens later without another approval. The permission does not expire with this review.";
function previewPayload(extra) {
  const payload = Object.assign({
    chain_id: "8453", chain: "base", sender: PREVIEW_WALLET, destination: PREVIEW_TOKEN,
    value: "0", value_display: "0 ETH", nonce: "7", gas_limit: "65410",
    fee: {kind: "eip1559", max_fee_per_gas: "3034880652", max_fee_per_gas_display: "3.03 gwei",
          max_priority_fee_per_gas: "151744032", max_priority_fee_per_gas_display: "0.15 gwei"},
    payload_keccak: "5f2a1c6b8d4e0937ab55c1e8d0f34721aa9c6b5e4d3f2a1908b7c6d5e4f302915",
    maximum_execution_gas_fee_display: "0.000198510751634520 ETH",
    calldata_bytes: "68",
    calldata_keccak: "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
  }, extra);
  const summary = reviewedContractCall(payload)?.intent_summary;
  if (summary) payload.calldata_hex = (summary.action === "transfer" ? "0xa9059cbb" : "0x095ea7b3") +
    summary.counterparty.slice(2).toLowerCase().padStart(64, "0") + BigInt(summary.amount).toString(16).padStart(64, "0");
  return payload;
}
function previewClearSigning(chainId = "8453", token = PREVIEW_TOKEN) {
  return {
    assurance: "trusted_description",
    entries: [{chain_id: chainId, contract_address: token, upgradeable: false}]
  };
}
function previewCall(action, amount, amountDisplay, magnitude, warnings, token = PREVIEW_TOKEN_IDENTITY) {
  const role = action === "transfer" ? "recipient" : "spender";
  return {
    contract: token.address, contract_name: token.name,
    function_signature: action === "transfer"
      ? "transfer(address to, uint256 amount)" : "approve(address spender, uint256 amount)",
    selector: action === "transfer" ? "0xa9059cbb" : "0x095ea7b3",
    action, token, assurance: PREVIEW_ASSURANCE,
    fields: [
      {label: action === "transfer" ? "To" : "Spender", format: "addressName",
       value: PREVIEW_SPENDER, raw: PREVIEW_SPENDER},
      {label: "Amount", format: "tokenAmount", value: amountDisplay, raw: amount}
    ],
    intent_summary: {
      action, counterparty_role: role, counterparty: PREVIEW_SPENDER,
      amount, amount_display: amountDisplay, magnitude, token
    },
    warnings
  };
}
function previewStructuralCall(action, amount, magnitude, warnings, contract = PREVIEW_TOKEN) {
  const role = action === "transfer" ? "recipient" : "spender";
  const amountDisplay = `${amount} raw units`;
  return {
    contract,
    function_signature: action === "transfer"
      ? "transfer(address,uint256)" : "approve(address,uint256)",
    selector: action === "transfer" ? "0xa9059cbb" : "0x095ea7b3",
    action,
    fields: [
      {label: action === "transfer" ? "Recipient" : "Spender", format: "addressName",
       value: PREVIEW_SPENDER, raw: PREVIEW_SPENDER},
      {label: action === "transfer" ? "Raw token amount" : "Raw total allowance",
       format: "raw", value: amount, raw: amount}
    ],
    intent_summary: {
      action, counterparty_role: role, counterparty: PREVIEW_SPENDER,
      amount, amount_display: amountDisplay, magnitude
    },
    structural: true,
    assurance: "Decoded from the standard ERC-20 calldata shape. Bloom verified the exact arguments, but not that this contract is a token or follows ERC-20 behavior.",
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
    "assurance": "Interpreted using Bloom's description of this contract. Contract behavior has not been verified.",
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
    "assurance": "Interpreted using Bloom's description of this contract. Contract behavior has not been verified.",
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
    "assurance": "Interpreted using Bloom's description of this contract. Contract behavior has not been verified.",
    "warnings": []
  }
};
function previewProtocolCall(name) {
  const call = PREVIEW_PROTOCOL_CALLS[name];
  const clear = {...previewClearSigning(), entries: []};
  const session = previewApproval([previewPayload({chain_id: "1", chain: "ethereum",
    destination: call.contract, contract_call: call})], clear);
  session.preview_status = "Synthetic descriptor test — not a deployed protocol integration";
  return session;
}
function previewSafeTransaction(action, extra = {}) {
  const session = PREVIEWS.morpho();
  const plan = JSON.parse(session.review_manifest.canonical_plan);
  const warnings = plan.safe_review.action.filter(line => line.startsWith("Warning: "));
  Object.assign(plan.safe_review, {destination: PREVIEW_TOKEN, operation: "call",
    action: [...action, ...warnings]}, extra);
  session.review_manifest.canonical_plan = JSON.stringify(plan);
  return session;
}
const PREVIEWS = {
  "safe-token-transfer": () => previewSafeTransaction([
    `Action: transfer on USD Coin ${PREVIEW_TOKEN}`,
    `To: ${PREVIEW_SPENDER}`, "Amount: 25 USDC"
  ]),
  "safe-allowance-unlimited": () => previewSafeTransaction([
    `Action: approve on USD Coin ${PREVIEW_TOKEN}`,
    `Spender: ${PREVIEW_SPENDER}`,
    "Amount: 115792089237316195423570985008687907853269984665640564039457584007913129.639935 USDC",
    "Warning: This spender can use all current and future USDC held by the Safe without asking again."
  ]),
  "safe-native-send": () => previewSafeTransaction([
    `Action: Send 0.0001 ETH to ${PREVIEW_SPENDER}`
  ], {destination: PREVIEW_SPENDER, value: "100000000000000", value_display: "0.0001 ETH"}),
  "safe-morpho-batch": () => {
    const session = PREVIEWS.morpho();
    const plan = JSON.parse(session.review_manifest.canonical_plan);
    const action = plan.safe_review.action;
    plan.safe_review.destination = "0x9641d764fc13c8B624c04430C7356C1C7C8102e2";
    plan.safe_review.operation = "delegatecall";
    plan.safe_review.action = [
      "Action: multiSend on Safe batch 0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
      "Transaction 1: approve on USD Coin 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "Transaction 1 · Spender: 0xb98c948CFA24072e58935BC004a8A7b376AE746A",
      "Transaction 1 · Amount: 2.5 USDC",
      ...action.map(line => line.startsWith("Warning: ") ? line
        : line.startsWith("Action: ") ? line.replace("Action: ", "Transaction 2: ")
        : `Transaction 2 · ${line}`)
    ];
    session.review_manifest.canonical_plan = JSON.stringify(plan);
    return session;
  },
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
    contract_call: previewCall("transfer", "250000000", "250 USDC", "finite", [])
  })], previewClearSigning()),
  "structural-transfer": () => previewApproval([previewPayload({
    contract_call: previewStructuralCall("transfer", "250000000", "finite", [
      `Bloom decoded an ERC-20-shaped call to ${PREVIEW_TOKEN}, but has not verified that this contract is a token or follows ERC-20 behavior.`])
  })], null),
  "structural-allowance-unlimited": () => previewApproval([previewPayload({
    contract_call: previewStructuralCall("allowance",
      "115792089237316195423570985008687907853269984665640564039457584007913129639935",
      "unlimited", [
        `Bloom decoded an ERC-20-shaped call to ${PREVIEW_TOKEN}, but has not verified that this contract is a token or follows ERC-20 behavior.`,
        "The decoded allowance is the maximum uint256. If this contract behaves as ERC-20, the spender can use all current and future tokens without asking again, and the permission has no expiry."])
  })], null),
  "transfer-ethereum": () => {
    const token = {...PREVIEW_TOKEN_IDENTITY, address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"};
    const session = previewApproval([previewPayload({chain_id: "1", chain: "ethereum",
      destination: token.address,
      contract_call: previewCall("transfer", "250000000", "250 USDC", "finite", [], token)
    })], previewClearSigning("1", token.address));
    session.preview_status = "Example transaction using Ethereum USDC — nothing can be approved";
    return session;
  },
  "allowance-finite": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance", "100000000", "100 USDC", "finite", [
      PREVIEW_ALLOWANCE_ADVISORY,
      "This sets the spender's total allowance to the amount shown. It is not added to any existing allowance."])
  })], previewClearSigning()),
  "allowance-zero": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance", "0", "0 USDC", "zero", [
      "This sets the spender's allowance to zero, clearing it."])
  })], previewClearSigning()),
  "allowance-unlimited": () => previewApproval([previewPayload({
    contract_call: previewCall("allowance",
      "115792089237316195423570985008687907853269984665640564039457584007913129639935",
      "115792089237316195423570985008687907853269984665640564039457584007913129.639935 USDC",
      "unlimited", [
        "If executed, this spender can use all your current and future USDC without asking again. This permission has no expiry; changing it requires another transaction."])
  })], previewClearSigning()),
  "opaque-call": () => previewApproval([previewPayload({calldata_hex:
    "0xa9059cbb" + PREVIEW_SPENDER.slice(2).toLowerCase().padStart(64, "0") +
    (250000000n).toString(16).padStart(64, "0")})], null),
  "native-send": () => previewApproval([previewPayload({
    destination: PREVIEW_SPENDER, value: "10000000000000000", value_display: "0.01 ETH",
    calldata_bytes: "0", calldata_keccak: undefined
  })], null),
  batch: () => previewApproval([
    previewPayload({contract_call: previewCall("allowance", "100000000", "100 USDC", "finite", [
      PREVIEW_ALLOWANCE_ADVISORY,
      "This sets the spender's total allowance to the amount shown. It is not added to any existing allowance."])}),
    previewPayload({nonce: "8",
      contract_call: previewCall("transfer", "250000000", "250 USDC", "finite", [])})
  ], previewClearSigning()),
  "mixed-assurance": () => previewApproval([
    previewPayload({contract_call: previewCall("transfer", "250000000", "250 USDC", "finite", [])}),
    previewPayload({nonce: "8", destination: PREVIEW_SPENDER,
      contract_call: previewStructuralCall("transfer", "42", "finite", [
        `Bloom decoded an ERC-20-shaped call to ${PREVIEW_SPENDER}, but has not verified that this contract is a token or follows ERC-20 behavior.`], PREVIEW_SPENDER)})
  ], previewClearSigning()),
  "long-identity": () => previewApproval([previewPayload({
    contract_call: Object.assign(
      previewCall("transfer", "1", "0.000001 USDC", "finite", []),
      {contract_name: "<script>alert(1)</script> Extremely Long Token Name That Should Wrap Rather Than Overflow",
       token: Object.assign({}, PREVIEW_TOKEN_IDENTITY,
         {name: "<b>Bloom</b> Demo Token With An Unusually Long Descriptive Name"})})
  })], previewClearSigning()),
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
  },
  // The Safe review exercised by evm_manifest_is_rendered_as_primary_review_facts.
  // A preview name is not a ceremony token and this session cannot be approved.
  morpho: () => ({
    ceremony_kind: "sealed_approval",
    expires_at_ms: Date.now() + 9 * 60 * 1000,
    signer_contribution: {},
    review_manifest: {
      schema: "bloom.review-manifest.v1",
      canonical_plan: JSON.stringify({
        safe_review: {
          chain_id: "8453", chain: "base",
          safe: "0x032649E1cb74393A8cC9dA390Af43a5D1eebDF61",
          owner: "0x86dB2acbF74856fd3286Cb5B755A5a05Ba445864",
          nonce: "2", operation: "call",
          destination: "0x6BFd8137e702540E7A42B74178A4a49Ba43920C4",
          value: "0", value_display: "0 ETH",
          action: [
            "Action: multicall on Morpho Bundler3 0x6BFd8137e702540E7A42B74178A4a49Ba43920C4",
            "Action 1: erc20TransferFrom on Morpho GeneralAdapter1 0xb98c948CFA24072e58935BC004a8A7b376AE746A",
            "Action 1 · Amount: 2.5 USDC",
            "Action 1 · Token: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "Action 1 · Sent to: 0xb98c948CFA24072e58935BC004a8A7b376AE746A",
            "Action contract 1: 0xb98c948CFA24072e58935BC004a8A7b376AE746A",
            "Action sends 1: 0 ETH",
            "Action 2: erc4626Deposit on Morpho GeneralAdapter1 0xb98c948CFA24072e58935BC004a8A7b376AE746A",
            "Action 2 · Vault: 0xc1256Ae5FF1cf2719D4937adb3bbCCab2E00A2Ca",
            "Action 2 · Assets: 2.5 USDC",
            "Action 2 · Assets asset: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "Action 2 · Assets (raw units): 2500000",
            "Action 2 · Highest share price (1e27 scale): 1097016817869820",
            "Action 2 · Shares go to: 0x86dB2acbF74856fd3286Cb5B755A5a05Ba445864",
            "Action contract 2: 0xb98c948CFA24072e58935BC004a8A7b376AE746A",
            "Action sends 2: 0 ETH",
            "Warning: Bloom cannot check that 0x032649E1cb74393A8cC9dA390Af43a5D1eebDF61 is a Safe; it reads it as one."
          ],
          safe_tx_hash: "0x5160acd8c69384337afae5de65027a3fef41f5ba421060d78f9d0c87fa1b3d17"
        },
        security_disclosures: ["Bloom rebuilt the Safe transaction from the exact signing bytes."]
      }),
      attributed_advisory_items: []
    }
  })
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
    if (!recovered.ok) throw error;
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
