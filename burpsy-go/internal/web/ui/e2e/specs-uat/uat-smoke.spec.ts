// UAT: browser UI smoke (burpsy-react-ui-uat2). One operator flow, driven in a real browser against
// a real burpsy-go the harness built and seeded: open the console, send a request from Repeater to
// the harness origin, and find that exchange where an operator looks for it afterwards.
//
// Deliberately NOT the 17-route / axe / screenshot suite in ../specs: this is the short, stable
// "does the product work for a user" gate a pipeline can run on every change. A failure here means
// the console cannot do its basic job.
//
// "View the exchange in history": the flow sends one real request THROUGH THE PROXY (a unique path) and
// finds that exchange in Proxy > HTTP history, and separately sends one from Repeater and finds it in the
// Tool log. A Repeater send is NOT proxy traffic, so it is recorded in the Tool
// log (Logger), never in Proxy > HTTP history (behaviour.spec.ts pins that split). The flow therefore
// checks both places for what each one owns: history lists the seeded proxy traffic, the Tool log
// lists the Repeater send, with the response the origin gave.

import { expect, gotoApp, gotoRoute, test } from "../harness/fixtures";
import http from "node:http";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => {
  const found = ROUTES.find((entry) => entry.id === id);
  if (!found) throw new Error(`no route ${id}`);
  return found;
};

const UAT_PATH = "/uat-smoke-send";
const PROXIED_PATH = "/uat-smoke-proxied";

/** One real request through burpsy's proxy listener (absolute-form target), as a browser or curl would send it. */
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

test("UAT: load the console, send from Repeater, see the exchange in history", async ({ page, consoleErrors, failedRequests }) => {
  const { targetPort } = readHarness();
  const origin = `http://127.0.0.1:${targetPort}`;

  await test.step("the console loads and names itself", async () => {
    await gotoApp(page);
    await expect(page.locator("header.toolbar-row .brand-name")).toHaveText("burpsy");
    await expect(page.getByRole("navigation", { name: "Tools" })).toBeVisible();
  });

  await test.step("Repeater sends a request and shows the origin's answer", async () => {
    await gotoRoute(page, route("repeater"));
    await page.getByRole("button", { name: "New request" }).first().click();
    await page.getByLabel("Target", { exact: true }).fill(origin);
    const requestEditor = page.locator(".editor-grid-inspected > *").first();
    await expect(requestEditor).toContainText("GET /");
    // Edit the request in the Raw editor itself: select all and type a whole new message. Each "\n" is a
    // real Enter key press: the editor keeps the message's own line endings (elam), so Enter writes the
    // template's CRLF. insertText of "\n" would write bare LF characters, which the origin rejects with
    // 400 Bad Request (the failure in CI run 40202947610).
    const raw = `GET ${UAT_PATH} HTTP/1.1\nHost: 127.0.0.1:${targetPort}\nConnection: close\n\n`;
    await requestEditor.locator(".cm-content").click();
    await page.keyboard.press("ControlOrMeta+a");
    await page.keyboard.type(raw);
    await expect(requestEditor).toContainText(`GET ${UAT_PATH} HTTP/1.1`);
    await page.getByRole("button", { name: "Send", exact: true }).click();
    // The origin echoes method and path, so this proves the bytes the operator typed are what arrived.
    await expect(page.locator(".editor-grid-inspected > *").nth(1)).toContainText(`ORIGIN-OK GET ${UAT_PATH}`);
  });

  await test.step("the Repeater send is in the Tool log", async () => {
    await gotoRoute(page, route("logger"));
    await expect(page.locator("tr.data-row", { hasText: UAT_PATH })).toHaveCount(1);
  });

  await test.step("a request sent through the proxy appears in HTTP history", async () => {
    const { proxyPort } = readHarness();
    expect(await viaProxy(proxyPort, `${origin}${PROXIED_PATH}`)).toBe(200);
    await gotoRoute(page, route("history"));
    await expect(page.locator("tr.data-row", { hasText: PROXIED_PATH })).toHaveCount(1);
    const proxied = page.locator("tr.data-row", { hasText: PROXIED_PATH });
    await proxied.click();
    await expect(proxied).toHaveAttribute("aria-selected", "true");
  });

  await test.step("HTTP history lists the proxied traffic and not the Repeater send", async () => {
    await gotoRoute(page, route("history"));
    await expect(page.locator("tr.data-row", { hasText: "/mango/deep/path" })).toBeVisible();
    await expect(page.locator("tr.data-row", { hasText: UAT_PATH })).toHaveCount(0);
    const row = page.locator("tr.data-row", { hasText: "/mango/deep/path" });
    await row.click();
    await expect(row).toHaveAttribute("aria-selected", "true");
  });

  expect(consoleErrors, "the console logged errors during the flow").toEqual([]);
  expect(failedRequests, "the console made failing API requests during the flow").toEqual([]);
});
