// UAT for two PR 363 console fixes, driven in a real browser against the harness's built burpsy-go and
// its local origin (no external target):
//
//   1. Sequencer stop/pause/resume. The client gate resolver could not read "{rest...}" keys, so these
//      three calls were routed to the gated exact route, minted at the wrong URL and answered 400, and
//      the capture kept running. The failedRequests fixture records every >=400 response, so a 400
//      here fails the test by name.
//   2. Next/previous tool tab chords follow the saved tab order, not the default one.
//   3. Settings > Network: Revert restores a blanked number field. Screenshots of the form before and after
//      go to e2e/artifacts/uat-pr363 (uploaded by CI as uat-ui-artifacts) and onto the test report.

import * as http from "node:http";
import * as path from "node:path";
import { expect, gotoApp, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

/** One request through burpsy's proxy listener (absolute-form target), as curl -x sends it. */
function viaProxy(proxyPort: number, url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: proxyPort, method: "GET", path: url, headers: { Host: new URL(url).host } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end();
  });
}

const route = (id: string) => {
  const found = ROUTES.find((entry) => entry.id === id);
  if (!found) throw new Error(`no route ${id}`);
  return found;
};

test("UAT: Sequencer capture can be paused, resumed and stopped from the console", async ({ page, consoleErrors, failedRequests }) => {
  const { targetPort } = readHarness();
  const origin = `http://127.0.0.1:${targetPort}`;

  await gotoApp(page);
  // The real operator path: a request through the proxy lands in HTTP history, and its row menu hands it
  // to the Sequencer with its CRLF request line and its response (a request typed into the empty editor
  // would carry bare LFs, which the origin rejects). The harness origin sets E2E_SESSION on every response.
  const { proxyPort } = readHarness();
  const status = await viaProxy(proxyPort, `${origin}/uat-sequencer`);
  expect(status).toBe(200);
  await gotoRoute(page, route("history"));
  const row = page.locator("tr.data-row", { hasText: "/uat-sequencer" }).first();
  await expect(row).toBeVisible();
  await row.click({ button: "right" });
  await page.getByRole("menuitem", { name: "Send to Sequencer" }).click();
  await expect(page.locator("main h1")).toHaveText(/^Sequencer/);
  await page.getByRole("tab", { name: "Capture from a live exchange" }).click();
  // The name is a picker when the handed-off response carries cookies, and a typed field when it does not.
  const cookieName = page.getByLabel("Cookie name");
  if ((await cookieName.evaluate((el) => el.tagName)) === "SELECT") await cookieName.selectOption("E2E_SESSION");
  else await cookieName.fill("E2E_SESSION");
  // 100 requests 300 ms apart keeps the capture running for about 30 s, long enough to act on it.
  await page.getByLabel("Requests", { exact: true }).fill("100");
  await page.getByLabel("Delay (ms)").fill("300");
  await page.getByRole("button", { name: "Start capture" }).click();

  const stop = page.getByRole("button", { name: "Stop capture" });
  await expect(stop).toBeEnabled();
  await expect(page.getByText(/Capture \d+ running/)).toBeVisible();

  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(page.getByRole("button", { name: "Resume", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Resume", exact: true }).click();
  await expect(page.getByRole("button", { name: "Pause", exact: true })).toBeVisible();

  await page.screenshot({ path: path.join("artifacts", "uat-pr363", "sequencer-running.png") });
  await stop.click();
  // The capture really ended: the progress card says finished and Stop is disabled again.
  await expect(page.getByText(/Capture \d+ finished/)).toBeVisible();
  await expect(stop).toBeDisabled();
  await page.screenshot({ path: path.join("artifacts", "uat-pr363", "sequencer-stopped.png") });

  expect(consoleErrors, "the console logged errors during the flow").toEqual([]);
  expect(failedRequests, "the console made failing API requests during the flow").toEqual([]);
});

test("UAT: next and previous tool tab follow the saved tab order", async ({ page, consoleErrors, failedRequests }) => {
  // The saved order puts Sequencer, Repeater, Decoder first: from Repeater, next is Decoder and previous
  // is Sequencer. The default order would give Collaborator and Intruder, which is what the chords did
  // before the fix. (Dashboard is avoided: it asks /api/crawl?task=1 for the seeded task and gets a 404
  // the failedRequests fixture rejects, on the smoke spec too.)
  await page.addInitScript(() => window.localStorage.setItem("burpsy.tooltabs.order", JSON.stringify(["sequencer", "repeater", "decoder"])));
  await gotoApp(page, route("repeater"));
  await expect(page.locator("main h1")).toHaveText(/^Repeater/);
  const hash = () => page.evaluate(() => window.location.hash);

  await page.keyboard.press("ControlOrMeta+Alt+ArrowRight");
  await expect.poll(hash).toBe("#decoder");

  await gotoRoute(page, route("repeater"));
  await page.keyboard.press("ControlOrMeta+Alt+ArrowLeft");
  await expect.poll(hash).toBe("#sequencer");

  expect(consoleErrors, "the console logged errors during the flow").toEqual([]);
  expect(failedRequests, "the console made failing API requests during the flow").toEqual([]);
});

test("UAT: Network settings Revert restores a blanked number field", async ({ page }, testInfo) => {
  await gotoApp(page);
  await gotoRoute(page, route("settings"));
  const section = page.getByRole("region", { name: "Network" });
  await section.scrollIntoViewIfNeeded();
  const connect = section.getByLabel("Connect (ms)");
  await expect(connect).toBeVisible();
  const saved = await connect.inputValue();
  expect(saved).toMatch(/^\d+$/);

  const shot = async (name: string) => {
    const file = path.join("artifacts", "uat-pr363", `${name}.png`);
    await section.screenshot({ path: file });
    await testInfo.attach(name, { path: file, contentType: "image/png" });
  };

  // Blank a number (it never reaches the draft), and make the form dirty with an unrelated edit.
  await connect.fill("");
  await expect(connect).toHaveAttribute("aria-invalid", "true");
  await section.getByLabel("Default to HTTP/2 if the server supports it").click();
  await shot("network-blank-and-dirty");

  await section.getByRole("button", { name: "Revert" }).click();
  await expect(section.getByLabel("Connect (ms)")).toHaveValue(saved);
  await expect(section.getByLabel("Connect (ms)")).not.toHaveAttribute("aria-invalid", "true");
  await shot("network-after-revert");

  // Blank only (nothing else edited): Revert is still offered and restores the field.
  await section.getByLabel("Connect (ms)").fill("");
  await expect(section.getByRole("button", { name: "Revert" })).toBeEnabled();
  await section.getByRole("button", { name: "Revert" }).click();
  await expect(section.getByLabel("Connect (ms)")).toHaveValue(saved);
  // Nothing was saved: the form is clean again.
  await expect(section.getByRole("button", { name: "Save" })).toBeDisabled();
});
