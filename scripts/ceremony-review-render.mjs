// Render the shipped ceremony page in a real browser and assert what the
// owner sees for a Pump.fun trade.
//
// The Rust suite can only show that a review reaches the session projection.
// Whether the page puts it on the screen — as its own block rather than a
// warning, with the guaranteed minimum legible — is a question only a browser
// answers. Everything here is the shipped asset: index.html, app.js, style.css
// and a projection this Broker produced.
//
//   cargo test -p bloom-broker --test w5_ceremony a_pumpfun_trade_projection
//   BLOOM_CEREMONY_PROJECTION_OUT=/tmp/session.json  (set for that run)
//   node scripts/ceremony-review-render.mjs /tmp/session.json <out-prefix>
//
// Exits non-zero with a reason if the review is not on the page.

import { chromium } from "/home/user/.local/share/mise/installs/npm-playwright/1.63.0/node_modules/playwright/index.mjs";
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [projectionPath, outPrefix] = process.argv.slice(2);
if (!projectionPath || !outPrefix) {
  console.error("usage: ceremony-review-render.mjs <session.json> <out-prefix>");
  process.exit(2);
}

const assets = join(dirname(fileURLToPath(import.meta.url)), "..", "crates", "bloom-broker", "src", "ceremony_assets");
const read = name => readFileSync(join(assets, name));
const projection = readFileSync(projectionPath);
const token = readFileSync(`${projectionPath}.token`, "utf8").trim();

const routes = {
  "/assets/app.js": ["text/javascript", read("app.js")],
  "/assets/style.css": ["text/css", read("style.css")],
  "/assets/bloom-primary.svg": ["image/svg+xml", read("bloom-primary.svg")],
  "/api/session": ["application/json", projection],
};

const server = createServer((request, response) => {
  const path = request.url.split("?")[0];
  const hit = routes[path];
  if (hit) {
    response.writeHead(200, { "content-type": hit[0] });
    response.end(hit[1]);
    return;
  }
  // Any other path is the ceremony shell, as the Broker serves it.
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end(read("index.html"));
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const base = `http://localhost:${server.address().port}`;

const browser = await chromium.launch({
  executablePath: "/home/user/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
});
const failures = [];
const seen = {};
for (const [name, viewport] of [["desktop", { width: 1280, height: 900 }], ["narrow", { width: 390, height: 844 }]]) {
  const page = await browser.newPage({ viewport });
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  await page.goto(`${base}/ceremony/${token}`, { waitUntil: "networkidle" });
  await page.waitForSelector(".advisory", { timeout: 10_000 }).catch(() => {});

  const found = await page.evaluate(() => {
    const block = document.querySelector(".advisory");
    return {
      present: Boolean(block),
      note: block?.querySelector(".advisory-note")?.textContent ?? null,
      items: [...(block?.querySelectorAll("li") ?? [])].map(node => node.textContent),
      // The same strings must not also appear as red warnings.
      warnings: [...document.querySelectorAll(".warn")].map(node => node.textContent),
      bodyText: document.body.innerText,
      overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
    };
  });
  seen[name] = found;

  await page.screenshot({ path: `${outPrefix}-${name}.png`, fullPage: true });
  writeFileSync(`${outPrefix}-${name}.txt`, found.bodyText);

  if (errors.length) failures.push(`${name}: page errors ${JSON.stringify(errors)}`);
  if (!found.present) failures.push(`${name}: no .advisory block rendered`);
  if (!found.note?.includes("Bloom has not checked")) {
    failures.push(`${name}: the app's text is not attributed (note=${JSON.stringify(found.note)})`);
  }
  const floor = found.items.find(item => item.startsWith("Guaranteed minimum received:"));
  if (!floor) failures.push(`${name}: the guaranteed minimum is not on the page`);
  if (!found.items.some(item => item.startsWith("Trading account:"))) {
    failures.push(`${name}: the trading account is not on the page`);
  }
  if (!found.items.some(item => item.startsWith("Most this can cost in total:"))) {
    failures.push(`${name}: the worst-case total is not on the page`);
  }
  if (found.warnings.some(warning => warning.startsWith("Guaranteed minimum received:"))) {
    failures.push(`${name}: the review is rendered as a warning`);
  }
  if (found.overflow) failures.push(`${name}: the page scrolls horizontally`);
  await page.close();
}
await browser.close();
server.close();

writeFileSync(`${outPrefix}-result.json`, JSON.stringify({ failures, seen }, null, 2));
if (failures.length) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}
console.log(`ok — the review renders on the page. Artifacts at ${outPrefix}-*`);
for (const item of seen.desktop.items) console.log(`  • ${item}`);
