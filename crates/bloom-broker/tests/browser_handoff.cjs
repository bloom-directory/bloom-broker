const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class Node {
  constructor(name) {
    this.name = name;
    this.children = [];
    this.textContent = "";
    this.attributes = new Map();
    const classes = new Set();
    this.classList = {
      add: value => classes.add(value),
      remove: value => classes.delete(value),
      contains: value => classes.has(value),
      toggle: (value, enabled) => enabled ? classes.add(value) : classes.delete(value)
    };
  }
  setAttribute(key, value) { this.attributes.set(key, value); }
  removeAttribute(key) { this.attributes.delete(key); }
  append(...children) { this.children.push(...children); }
  prepend(...children) { this.children.unshift(...children); }
  replaceChildren(...children) { this.children = children; }
  querySelector() { return this.children.find(child => child?.className === "agent-instructions"); }
}
const nodes = {};
globalThis.document = {
  getElementById: id => nodes[id] ||= new Node(id),
  createElement: name => new Node(name),
  createTextNode: text => String(text)
};
globalThis.location = {hash: "", search: "", pathname: "/"};
globalThis.history = {replaceState() {}};
let now = 1_000_000;
Date.now = () => now;
let tick;
globalThis.setInterval = callback => { tick = callback; return 1; };
globalThis.clearInterval = () => {};
const source = fs.readFileSync(process.argv[2], "utf8").split("\nload().catch")[0];
vm.runInThisContext(source);
const session = {
  ceremony_kind: "card_checkout", expires_at_ms: now + 120000,
  review_manifest: {card_effect: {kind: "manual_checkout",
    agent_description: "Enter passenger details. STOP BEFORE PAYMENT.\n<script>untrusted</script>"}}
};
renderCardReview(session);
assert(nodes["ceremony-page"].classList.contains("browser-handoff"));
assert.match(nodes["page-lede"].textContent, /No payment is approved/);
assert.match(nodes["page-lede"].textContent, /no saved card is shared/);
const instructions = nodes.review.querySelector();
assert(instructions.attributes.has("open"));
const steps = instructions.children[1].children;
assert.equal(steps.length, 3);
assert.equal(steps[1].children[0], "STOP BEFORE PAYMENT.");
assert.equal(steps[2].children[0], "<script>untrusted</script>");
now += 121000;
tick();
assert.equal(nodes.approve.disabled, true);
assert.equal(nodes["panel-title"].textContent, "This request expired");
assert(!instructions.attributes.has("open"));
assert.match(nodes.status.textContent, /fresh link/);
// Loading an already expired request must not create a timer or an active action.
tick = null;
renderCardReview({...session, expires_at_ms: now - 1});
assert.equal(tick, null);
assert.equal(nodes.approve.disabled, true);
// A manual payment fallback is not represented as no-card browser access.
renderCardReview({...session, expires_at_ms: now + 120000,
  review_manifest: {card_effect: {kind: "manual_checkout", card_id: "saved",
    agent_description: "Finish this purchase yourself."}}});
assert(!nodes["ceremony-page"].classList.contains("browser-handoff"));
// Review ISO minor units rather than the browser's display precision. CLDR
// omits fractions for HUF/COP/IQD, but those currencies retain minor units.
globalThis.fetch = async () => ({ok: false});
for (const [currency, total_minor, installments, total, installment] of [
  ["HUF", 2882650, 2, "28,826.50", "14,413.25"],
  ["COP", 12345678, 2, "123,456.78", "61,728.39"],
  ["IQD", 1250125, 1, "1,250.125", "1,250.125"],
  ["VND", 18062176, 2, "18,062,176", "9,031,088"],
]) {
  renderCardReview({...session, expires_at_ms: now + 120000,
    review_manifest: {host: "example.com", card_effect: {kind: "checkout",
      facts: {origin: "https://example.com", payment_frame_origins: [],
        currency, total_minor, installments, recurring: false},
      agent_description: "Synthetic amount review"}}});
  const fields = nodes.review.children[0].children;
  const value = name => fields[fields.findIndex(field => field.children[0] === name) + 1].children.join("");
  assert(value("Total").includes(total), `${currency}: ${value("Total")}`);
  assert(value("Installments").includes(installment), `${currency}: ${value("Installments")}`);
}
// A trial price is not the price: the review states the ongoing charge, how
// often it recurs and the day it starts, and says so plainly when the page
// did not give one.
for (const [facts, expected] of [
  [{currency: "USD", total_minor: 100, installments: 1, recurring: true,
    renewal_minor: 1299, renewal_period: "month", renewal_starts_on: "2026-11-25"},
   "$12.99 every month, from 2026-11-25"],
  [{currency: "USD", total_minor: 1799, installments: 1, recurring: true,
    renewal_minor: 1799, renewal_period: "month"}, "$17.99 every month"],
  [{currency: "USD", total_minor: 100, installments: 1, recurring: true}, "could not read"],
  [{currency: "USD", total_minor: 100, installments: 1, recurring: false}, "No"],
]) {
  renderCardReview({...session, expires_at_ms: now + 120000,
    review_manifest: {host: "example.com", card_effect: {kind: "checkout",
      facts: {origin: "https://example.com", payment_frame_origins: [], ...facts},
      agent_description: "Synthetic subscription review"}}});
  const fields = nodes.review.children[0].children;
  const value = name => fields[fields.findIndex(field => field.children[0] === name) + 1].children.join("");
  assert(value("Recurring charge").includes(expected), `${JSON.stringify(facts)}: ${value("Recurring charge")}`);
}
console.log("browser-handoff-ok");
