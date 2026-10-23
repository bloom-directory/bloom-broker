// Exercise the actual developer Broker, not a second HTML/asset fixture server.
// Requires playwright-core, Chromium, and an isolated running preview Broker.
import fs from "node:fs/promises";
import path from "node:path";

const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || "playwright-core");
const base = new URL(process.env.BLOOM_CEREMONY_PREVIEW_URL || "http://localhost:28737");
if (!["localhost", "127.0.0.1"].includes(base.hostname) || base.protocol !== "http:") {
  throw new Error("Use an isolated localhost preview Broker");
}
const output = process.env.BLOOM_UI_SCREENSHOT_DIR;
if (!output) throw new Error("Set BLOOM_UI_SCREENSHOT_DIR to a private evidence directory");
await fs.mkdir(output, {recursive: true});
const browser = await chromium.launch({executablePath: process.env.CHROMIUM_BIN || "/usr/bin/chromium", headless: true,
  args: ["--no-sandbox"]});
const reports = [];
try {
  for (const width of [390, 1280]) {
    const context = await browser.newContext({viewport: {width, height: 1000}});
    const page = await context.newPage();
    const external = [];
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/*", route => {
      const request = route.request();
      if (new URL(request.url()).origin !== base.origin) {
        external.push({url: request.url(), type: request.resourceType()});
        return route.abort();
      }
      return route.continue();
    });
    const cases = ["enso-swap", "enso-shortcut", "enso-output", "enso-allowance", "polymarket-order",
      "safe-token-transfer", "transfer-dai", "structural-transfer", "catalog-wbtc"];
    for (const name of cases) {
      await page.goto(new URL(`/preview/${name === "catalog-wbtc" ? "tokens" : name}`, base).href);
      if (name === "catalog-wbtc") {
        await page.getByRole("searchbox", {name: "Find a token"}).fill("WBTC");
        await page.getByRole("button", {name: "Preview 1 WBTC · Chain 1", exact: true}).click();
      }
      await page.locator("#preview-banner").waitFor({state: "visible"});
      await page.waitForFunction(() => document.querySelector("#status").textContent !== "Loading…");
      if (name === "enso-shortcut") {
        await page.getByRole("complementary", {name: "No output protection"}).waitFor();
        if (await page.getByText("Execution details", {exact: true}).isVisible()) {
          throw new Error("Execution mechanics escaped the collapsed technical section");
        }
      }
      if (name === "enso-swap") {
        await page.getByText("+2.985 USDC", {exact: true}).waitFor();
        if (await page.getByRole("complementary", {name: "No output protection"}).count()) {
          throw new Error("Positive protected minimum shown as unprotected");
        }
      }
      const images = await page.evaluate(async () => Promise.all([...document.images].map(async image => {
        try { await image.decode(); } catch (_) {}
        return {src: image.currentSrc || image.src, loaded: image.naturalWidth > 0};
      })));
      if (images.some(image => !image.loaded || new URL(image.src).origin !== base.origin)) {
        throw new Error(`${name}/${width}: missing or external image: ${JSON.stringify(images)}`);
      }
      const expectedLogo = name === "catalog-wbtc" ? "/assets/tokens/" : name === "transfer-dai" ? "/assets/tokens/dai.svg" : null;
      if (expectedLogo && !images.some(image => image.src.includes(expectedLogo)
          && (name !== "catalog-wbtc" || image.src.endsWith(".png")))) {
        throw new Error(`${name}/${width}: expected bundled token artwork`);
      }
      for (const expanded of [false, true]) {
        if (expanded) await page.locator("details").evaluateAll(nodes => nodes.forEach(node => { node.open = true; }));
        if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) {
          throw new Error(`${name}/${width}: horizontal overflow, expanded=${expanded}`);
        }
        const screenshot = `${name}-${width}-${expanded ? "expanded" : "collapsed"}.png`;
        await page.screenshot({path: path.join(output, screenshot), fullPage: true});
        reports.push({name, width, expanded, screenshot, images});
      }
      if (await page.locator("#approve").isVisible()) throw new Error("Preview exposes approval controls");
      if (await page.locator("#cancel").isVisible()) throw new Error("Preview exposes cancellation controls");
    }
    if (external.length || errors.length) throw new Error(JSON.stringify({external, errors}));
    await context.close();
  }
  await fs.writeFile(path.join(output, "results.json"), JSON.stringify({reports, externalRequests: [], errors: []}, null, 2));
  console.log(`${reports.length} preview captures; zero external requests or broken images`);
} finally {
  await browser.close();
}
