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
assert.equal(nodes["ceremony-trust"].hidden, true);
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
assert.equal(nodes["ceremony-trust"].hidden, false);
assert.equal(nodes["ceremony-eyebrow"].textContent, "Signed wallet review");
console.log("browser-handoff-ok");
