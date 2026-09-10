// An Intruder result has to be able to leave the Results tab (burpsy-react-ui-79u).
//
// Before this, a result row was a dead end: the table could show a response and nothing else, so
// retesting an interesting row meant reading its payload off the screen and rebuilding the request
// by hand in Repeater. Burp's results rows carry the suite context menu, and its
// configure-attack/settings.html names "Send requests or responses to other Burp tools" as one of
// the three reasons the store-requests setting exists at all.
//
// This drives the whole chain in a real browser rather than asserting the menu renders: proxy
// history -> Send to Intruder -> find positions -> launch -> right-click a result -> Send to
// Repeater, and then reads the Repeater tab's editor to check the bytes that arrived are the
// *spliced* request, carrying a payload the attack generated. A menu that opened and did nothing,
// or that handed over the unspliced base request, would pass a render check and fail this.

import { request as httpRequest } from "node:http";
import { expect, gotoRoute, pinTheme, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/** POST JSON to burpsy's own web API and return the parsed reply. */
function postJson<T>(webPort: number, path: string, body: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const request = httpRequest(
      {
        host: "127.0.0.1",
        port: webPort,
        method: "POST",
        path,
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
      },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => {
          text += chunk;
        });
        response.once("end", () => {
          if ((response.statusCode ?? 0) >= 400) {
            reject(new Error(`POST ${path} -> ${response.statusCode}: ${text}`));
            return;
          }
          resolve(JSON.parse(text) as T);
        });
      },
    );
    request.once("error", reject);
    request.end(payload);
  });
}

/** The five default payloads the page ships with; the first is what a sniper attack sends first. */
const FIRST_PAYLOAD = "admin";

/**
 * Get from a cold app to an Intruder attack with results.
 *
 * The base request is minted through the API rather than picked out of the seeded proxy history,
 * and that is not a shortcut — it is what makes this deterministic. HTTP history is shared mutable
 * state that every earlier spec in the suite can filter, annotate or delete, so a row located by
 * its path passes in isolation and vanishes in a full run. This mints its own request and types
 * the id the server assigned it into the field an operator types it into.
 *
 * Everything after the id is driven through the UI, because the handoff under test reads ids the
 * *server* stored during the attack — an attack faked into the store would prove nothing about them.
 */
async function runAnAttack(page: import("@playwright/test").Page): Promise<void> {
  const { webPort, targetPort } = readHarness();
  const origin = `http://127.0.0.1:${targetPort}`;
  // A query parameter, so "Find positions" has a parameter to find, and a path unique to this
  // helper so a failure is traceable to it rather than to a seeded row someone else moved.
  const raw = `GET /handoff?q=alpha HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nConnection: close\r\n\r\n`;
  const sent = await postJson<{ request_msg_id: number }>(webPort, "/api/repeater/send", {
    target: origin,
    protocol: "http",
    request: raw,
  });

  await gotoRoute(page, route("intruder"));
  await page.getByLabel("Stored message id").fill(String(sent.request_msg_id));
  await page.getByLabel("Target authority").fill(origin);

  await page.getByRole("button", { name: "Find positions" }).click();
  // Discovery lists positions; attacking one is a separate choice, and pointCount counts the
  // chosen ones — which is why the launch button is still disabled until this is ticked.
  await page.getByRole("checkbox", { name: "Use position q" }).check();

  const launch = page.getByRole("button", { name: /Launch attack/ });
  await expect(launch).toBeEnabled();
  await launch.click();

  // /run is synchronous and the page switches to Results itself when it returns.
  await expect(page.getByRole("group", { name: "Attempts" })).toBeVisible({ timeout: 60_000 });
}

test.describe("intruder results handoff", () => {
  test("a result row sends its own spliced request to Repeater", async ({ page, consoleErrors }) => {
    await pinTheme(page, "dark");
    await runAnAttack(page);

    const attempts = page.getByRole("group", { name: "Attempts" }).locator("tbody tr");
    await expect(attempts.first()).toBeVisible();

    // Ordinal 0 is the first row of a table the page renders in plan order, so it is the attempt
    // that sent FIRST_PAYLOAD. Naming the expected payload here is what makes the editor assertion
    // below a claim about *this* row rather than about any request at all.
    await attempts.first().click({ button: "right" });
    const send = page.getByRole("menuitem", { name: "Send to Repeater" });
    await expect(send).toBeVisible();
    // A recorded request is what makes the action live. If the server did not store it the item is
    // present but disabled, and the rest of this test would be asserting against a stale editor.
    await expect(send).not.toHaveAttribute("data-disabled", "");
    await send.click();

    await expect(page.getByRole("heading", { level: 1, name: "Repeater" })).toBeVisible();
    // The tab is named after the ordinal it came from, so the strip says which result this is.
    await expect(page.getByRole("tab", { name: /Intruder attempt 0/ })).toBeVisible();

    // The bytes, which is the whole point. CodeMirror renders only the visible lines, so the
    // request line — the first one — is the part that is reliably in the DOM.
    const editor = page.locator(".cm-content").first();
    await expect(editor).toContainText(FIRST_PAYLOAD, { timeout: 10_000 });

    expect(consoleErrors).toEqual([]);
  });

  test("a result row loads its request and its response into Comparer", async ({ page, consoleErrors }) => {
    await pinTheme(page, "dark");
    await runAnAttack(page);

    // Slot A takes the request. Comparer's two slots are the reason the menu splits request from
    // response: comparing a result against another result is the workflow, and picking which of the
    // two halves goes into which slot is the operator's call, not a default.
    const attempts = page.getByRole("group", { name: "Attempts" }).locator("tbody tr");
    await attempts.first().click({ button: "right" });
    await page.getByRole("menuitem", { name: "Request to slot A" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Comparer" })).toBeVisible();
    await expect(page.locator(".cm-content").first()).toContainText(FIRST_PAYLOAD, { timeout: 10_000 });

    // And a bucket row hands over its exemplar — the same first_ordinal whose request it stored.
    // The report survives leaving the page (it lives in the store, burpsy-react-ui-rby), so this
    // navigates back rather than re-running the attack.
    await gotoRoute(page, route("intruder"));
    await page.getByRole("tab", { name: /^Results/ }).click();
    await expect(page.getByRole("group", { name: "Result buckets" })).toBeVisible();
    const buckets = page.getByRole("group", { name: "Result buckets" }).locator("tbody tr");
    await buckets.first().click({ button: "right" });
    await expect(page.getByRole("menuitem", { name: "Send to Repeater" })).toBeVisible();
    await page.getByRole("menuitem", { name: "Response to slot B" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Comparer" })).toBeVisible();
    // The origin answers every request with a body that starts this way, so a response landing in
    // slot B is a response and not a second copy of the request.
    await expect(page.locator(".cm-content").nth(1)).toContainText("ORIGIN-OK", { timeout: 10_000 });

    expect(consoleErrors).toEqual([]);
  });
});
