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

import * as path from "node:path";
import { expect, gotoApp, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => {
  const found = ROUTES.find((entry) => entry.id === id);
  if (!found) throw new Error(`no route ${id}`);
  return found;
};

test("UAT: Sequencer capture can be paused, resumed and stopped from the console", async ({ page, consoleErrors, failedRequests }) => {
  const { targetPort } = readHarness();
  const origin = `http://127.0.0.1:${targetPort}`;

  await gotoApp(page);
  await gotoRoute(page, route("sequencer"));
  await page.getByRole("tab", { name: "Capture from a live exchange" }).click();

  // The harness origin sets E2E_SESSION=tokNNNN on every response, which is the token to capture.
  const raw = `GET /uat-sequencer HTTP/1.1\nHost: 127.0.0.1:${targetPort}\nConnection: close\n\n`;
  await page.getByRole("textbox", { name: "Request to repeat" }).click();
  await page.keyboard.press("ControlOrMeta+a");
  await page.keyboard.type(raw);
  await page.getByLabel("Target", { exact: true }).fill(origin);
  await page.getByLabel("Cookie name").fill("E2E_SESSION");
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

  await stop.click();
  // The capture really ended: the progress card says finished and Stop is disabled again.
  await expect(page.getByText(/Capture \d+ finished/)).toBeVisible();
  await expect(stop).toBeDisabled();

  expect(consoleErrors, "the console logged errors during the flow").toEqual([]);
  expect(failedRequests, "the console made failing API requests during the flow").toEqual([]);
});

test("UAT: next and previous tool tab follow the saved tab order", async ({ page, consoleErrors, failedRequests }) => {
  // The saved order puts Sequencer and Repeater first: from Repeater, next is Dashboard (the first
  // tab not named in the order) and previous is Sequencer. The default order would give Collaborator
  // and Intruder, which is what the chords did before the fix.
  await page.addInitScript(() => window.localStorage.setItem("burpsy.tooltabs.order", JSON.stringify(["sequencer", "repeater"])));
  await gotoApp(page, route("repeater"));
  await expect(page.locator("main h1")).toHaveText(/^Repeater/);
  const hash = () => page.evaluate(() => window.location.hash);

  await page.keyboard.press("ControlOrMeta+Alt+ArrowRight");
  await expect.poll(hash).toBe("#dashboard");

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
