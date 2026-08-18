// Smoke test: load the committed UI bundle against the stub server and check
// that every route renders without a JS error and without hitting the ErrorBoundary.
import { chromium } from "playwright-core";
import { spawn } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

const stub = spawn("node", [join(here, "ui-stub.mjs")], { stdio: "ignore", detached: true });
stub.unref();

// Wait for the stub to answer before launching the browser — a detached child that
// exits before the first goto produces ERR_EMPTY_RESPONSE with no log to explain it.
for (let i = 0; i < 50; i += 1) {
  try {
    const r = await fetch("http://127.0.0.1:18282/api/stats");
    await r.arrayBuffer();
    break;
  } catch {
    await new Promise((done) => setTimeout(done, 100));
  }
}

const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
page.on("pageerror", (e) => errors.push("uncaught: " + e.message));

const routes = ["dashboard", "sitemap", "scope", "intercept", "history", "wshistory", "matchreplace", "intruder", "repeater", "sequencer", "decoder", "comparer", "logger", "organizer", "session", "settings", "scanner"];

let failed = 0;
for (const route of routes) {
  errors.length = 0;
  await page.goto(`http://127.0.0.1:18282/#${route}`, { waitUntil: "domcontentloaded" });
  const h1 = await page.locator("h1").first().textContent().catch(() => null);
  const hasError = await page.locator(".error-boundary, .error-notice").first().count();
  const ok = h1 && !hasError && errors.length === 0;
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} #${route} h1="${h1 ?? "(none)"}" errorBoundary=${hasError} consoleErrors=${errors.length}`);
}

await browser.close();
try { process.kill(-stub.pid, "SIGKILL"); } catch {}
process.exit(failed ? 1 : 0);
