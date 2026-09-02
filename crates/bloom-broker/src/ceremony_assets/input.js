"use strict";
const statusNode = document.getElementById("status");
const reviewNode = document.getElementById("review");
const inputNode = document.getElementById("private-input");
const submitNode = document.getElementById("submit");
const pathToken = location.pathname.startsWith("/input/")
  ? location.pathname.slice("/input/".length) : "";
const storageKey = "bloom.private-input.token.v1";
const storage = (() => { try { return globalThis.sessionStorage || null; } catch (_) { return null; } })();
const token = pathToken || (() => { try { return storage?.getItem(storageKey) || ""; } catch (_) { return ""; } })();
if (pathToken) { try { storage?.setItem(storageKey, pathToken); } catch (_) {} }
if (token) history.replaceState(null, "", "/");
const headers = {"x-bloom-input-token": token};
let operationId = "";

async function load() {
  const response = await fetch("/api/input", {headers});
  if (!response.ok) throw new Error("Private-input request is unavailable or expired");
  const request = await response.json();
  operationId = request.operation_id;
  const context = request.context;
  const pre = document.createElement("pre");
  pre.textContent = [
    `Network: ${context.network}`,
    `Asset: ${context.asset}`,
    `Amount (base units): ${context.amount_base_units}`,
    `Decimals: ${context.decimals}`,
    `Source: ${context.source}`
  ].join("\n");
  reviewNode.replaceChildren(pre);
  statusNode.textContent = "Enter the destination. No passkey or signature is requested.";
  submitNode.disabled = false;
}

submitNode.onclick = async () => {
  const value = inputNode.value.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    statusNode.textContent = "Enter a 20-byte Ethereum address beginning with 0x.";
    return;
  }
  submitNode.disabled = true;
  const response = await fetch(`/api/input/${operationId}/complete`, {
    method: "POST",
    headers: {...headers, "content-type": "application/json"},
    body: JSON.stringify({value})
  });
  inputNode.value = "";
  if (!response.ok) {
    submitNode.disabled = false;
    throw new Error("Private input was not accepted");
  }
  try { storage?.removeItem(storageKey); } catch (_) {}
  statusNode.textContent = "Delivered. You may close this tab.";
  submitNode.hidden = true;
};

load().catch(error => {
  console.error("Bloom private-input form failed", error);
  statusNode.textContent = error.message;
});
