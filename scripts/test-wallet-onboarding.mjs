// Real local Triad + isolated Chromium virtual passkey. No human credentials,
// tracing, video, phrase screenshots, secret values or full DOM dumps.
import {spawnSync} from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || "playwright-core");
const base = new URL(process.env.BLOOM_CEREMONY_PREVIEW_URL || "http://localhost:28737");
if (!["localhost", "127.0.0.1"].includes(base.hostname) || base.protocol !== "http:") throw new Error("Use an isolated local Triad");
const output = process.env.BLOOM_UI_SCREENSHOT_DIR;
if (!output || !process.env.BLOOM_TEST_MACHINE_BIN || !process.env.BLOOM_TEST_MACHINE_HOME || !process.env.BLOOM_TEST_MACHINE_ENDPOINT) throw new Error("Set the isolated Machine and screenshot paths");
const name = "onboarding-test-" + Date.now();
function prepare(command, wallet) {
  const prepared = spawnSync(process.env.BLOOM_TEST_MACHINE_BIN, ["--home", process.env.BLOOM_TEST_MACHINE_HOME,
    "--connect", process.env.BLOOM_TEST_MACHINE_ENDPOINT, "wallet", command, wallet, "--local"], {encoding: "utf8"});
  const url = prepared.stdout?.match(/^ceremony_url: (.+)$/m)?.[1];
  if (prepared.status || !url || new URL(url).origin !== base.origin) throw new Error("Could not prepare isolated test " + command);
  return url;
}
const url = prepare("new", name);
await fs.mkdir(output, {recursive: true});
const browser = await chromium.launch({executablePath: "/usr/bin/chromium", headless: true, args: ["--no-sandbox"]});
let stage = "start", errors = 0, external = 0;
try {
  const context = await browser.newContext({viewport: {width: 1280, height: 1000}});
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", () => errors++);
  await page.route("**/*", route => {
    if (new URL(route.request().url()).origin !== base.origin) { external++; return route.abort(); }
    return route.continue();
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {options: {protocol: "ctap2", ctap2Version: "ctap2_1",
    transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
    automaticPresenceSimulation: true, hasPrf: true, hasHmacSecret: true}});
  stage = "create";
  await page.goto(url);
  await page.getByRole("button", {name: "Create wallet with passkey", exact: true}).click();
  await page.getByRole("heading", {name: "Wallet created", exact: true}).waitFor();
  if (await page.getByRole("button", {name: "Copy address", exact: true}).count() !== 2) throw new Error();
  if (await page.locator("#review-deadline").textContent() || await page.locator("#ceremony-actions").isVisible()) throw new Error();
  for (const width of [390, 1280]) {
    await page.setViewportSize({width, height: 1000});
    if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error();
    // Each whole address reads on one line.
    if (await page.evaluate(() => [...document.querySelectorAll(".wallet-address code")].some(c => c.getClientRects().length !== 1))) throw new Error();
    await page.screenshot({path: path.join(output, "wallet-created-" + width + ".png"), fullPage: true});
  }
  stage = "later and refresh";
  await page.getByRole("link", {name: "Later — return to wallet", exact: true}).click();
  await page.getByRole("heading", {name, exact: true}).waitFor();
  await page.reload();
  await page.getByRole("button", {name: "Back up wallet", exact: true}).waitFor();
  stage = "backup refresh and cancel";
  await page.getByRole("button", {name: "Back up wallet", exact: true}).click();
  await page.getByRole("heading", {name: "Export recovery phrase", exact: true}).waitFor();
  await page.reload();
  await page.getByRole("button", {name: "Reveal with passkey", exact: true}).waitFor();
  if (await page.locator("ol.words li").count()) throw new Error();
  await page.screenshot({path: path.join(output, "backup-review-no-secrets.png"), fullPage: true});
  await page.getByRole("button", {name: "Cancel", exact: true}).click();
  await page.getByRole("link", {name: "Return to wallet — backup was cancelled", exact: true}).click();
  await page.getByRole("button", {name: "Back up wallet", exact: true}).waitFor();
  await page.waitForTimeout(2100); // Existing owner-cancellation cooldown.
  stage = "fresh backup approval";
  await page.getByRole("button", {name: "Back up wallet", exact: true}).click();
  await page.getByRole("heading", {name: "Export recovery phrase", exact: true}).waitFor();
  await page.getByRole("button", {name: "Reveal with passkey", exact: true}).click();
  // Never screenshot, trace, read, print or persist the phrase.
  await page.getByRole("heading", {name: "Your recovery phrase", exact: true}).waitFor();
  if (await page.locator("ol.words li").count() !== 24) throw new Error();
  if (await page.locator("#review-deadline").textContent() || await page.locator("#action-expiry").textContent()) throw new Error();
  stage = "return after backup";
  await page.getByRole("link", {name: "Return to wallet", exact: true}).click();
  await page.getByRole("button", {name: "Back up wallet", exact: true}).waitFor();
  await page.reload();
  await page.getByRole("heading", {name, exact: true}).waitFor();
  if (await page.locator("ol.words li").count()) throw new Error();
  // The public BIP-39 test vector, never a real wallet. Import must end on the
  // same addresses-and-backup page as creation.
  stage = "import shows addresses and backup";
  await page.goto(prepare("import", name + "-imported"));
  await page.locator("#mnemonic-input").fill(Array(11).fill("abandon").concat("about").join(" "));
  await page.getByRole("button", {name: "Import with passkey", exact: true}).click();
  await page.getByRole("heading", {name: "Wallet imported", exact: true}).waitFor();
  if (await page.getByRole("button", {name: "Copy address", exact: true}).count() !== 2) throw new Error();
  if (!(await page.locator(".wallet-address").allTextContents()).some(a => a.toLowerCase() === "0x9858effd232b4033e47d90003d41ec34ecaeda94")) throw new Error();
  await page.getByRole("button", {name: "Back up wallet", exact: true}).waitFor();
  if (external || errors) throw new Error();
  await fs.writeFile(path.join(output, "results.json"), JSON.stringify({passed: true, virtualPasskey: true,
    create: true, addressCount: 2, later: true, refresh: true, cancelBackup: true, freshBackupApproval: true,
    returnedToWallet: true, importShowsWallet: true, externalRequests: external, browserErrors: errors, capturedSecrets: false}, null, 2));
  console.log("Create → addresses → Later/refresh → backup/cancel → fresh approval → return → import → addresses passed; no secret capture");
} catch (_) {
  throw new Error("Onboarding failed at: " + stage + " (no secret output captured)");
} finally { await browser.close(); }
