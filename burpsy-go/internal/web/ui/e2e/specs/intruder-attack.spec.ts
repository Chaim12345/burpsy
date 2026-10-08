// Intruder attacks driven end to end, and their results read back (burpsy-react-ui-xixe.1).
//
// Each test launches a real attack through the console against the harness origin and then works the
// Results tab, so what is asserted is what an operator sees after a real /api/intruder/run — not a
// render of fixture JSON.

import { request as httpRequest } from "node:http";
import { expect, gotoRoute, pinTheme, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

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

/**
 * Mint a base request of our own (HTTP history is shared state other specs mutate), point the page at
 * it, select the q position and launch with the page's default payloads.
 */
async function launchAttack(
  page: import("@playwright/test").Page,
  path: string,
  configure?: (page: import("@playwright/test").Page) => Promise<void>,
): Promise<void> {
  const { webPort, targetPort } = readHarness();
  const origin = `http://127.0.0.1:${targetPort}`;
  const raw = `GET ${path}?q=alpha HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nConnection: close\r\n\r\n`;
  const sent = await postJson<{ request_msg_id: number }>(webPort, "/api/repeater/send", {
    target: origin,
    protocol: "http",
    request: raw,
  });
  await gotoRoute(page, route("intruder"));
  await page.getByLabel("Stored message id").fill(String(sent.request_msg_id));
  await page.getByLabel("Target authority").fill(origin);
  await page.getByRole("button", { name: "Find positions" }).click();
  await page.getByRole("checkbox", { name: "Use position q" }).check();
  if (configure) await configure(page);
  const launch = page.getByRole("button", { name: /Launch attack/ });
  await expect(launch).toBeEnabled();
  await launch.click();
  await expect(page.getByRole("group", { name: "Attempts" })).toBeVisible({ timeout: 60_000 });
}

test.describe("intruder attack results", () => {
  // Burp's "Define extract grep from response" (df8r): highlight a value in a result's stored
  // response and get a working Grep extract rule, previewed against that response before saving.
  test("an extract grep is defined by highlighting a response", async ({ page, consoleErrors }) => {
    await pinTheme(page, "dark");
    await launchAttack(page, "/extract-from-highlight");

    // Ordinal 0 opened its bucket, so it kept its response. Its body is the origin's
    // "ORIGIN-OK GET /extract-from-highlight?q=admin xxx…": the payload is the value to extract.
    const attempts = page.getByRole("group", { name: "Attempts" }).locator("tbody tr");
    await attempts.first().click({ button: "right" });
    const define = page.getByRole("menuitem", { name: "Define extract grep from response" });
    await expect(define).not.toHaveAttribute("data-disabled", "");
    await define.click();

    const dialog = page.getByRole("dialog", { name: "Define extract grep from response" });
    await expect(dialog).toBeVisible();
    const content = dialog.locator(".cm-content");
    await expect(content).toContainText("ORIGIN-OK", { timeout: 10_000 });
    const save = dialog.getByRole("button", { name: /grep extract/ });
    await expect(save).toBeDisabled();

    // Highlight "admin" in the body the way a mouse drag does: a DOM selection inside the focused
    // editor, which CodeMirror reads back into its own selection.
    await content.click();
    await page.evaluate(() => {
      const root = document.querySelector('[role="dialog"] .cm-content');
      if (!root) throw new Error("no editor in the dialog");
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const at = node.textContent?.indexOf("q=admin") ?? -1;
        if (at < 0) continue;
        const range = document.createRange();
        range.setStart(node, at + 2);
        range.setEnd(node, at + 2 + "admin".length);
        const selection = window.getSelection()!;
        selection.removeAllRanges();
        selection.addRange(range);
        return;
      }
      throw new Error('"q=admin" is not in the rendered response');
    });

    const rule = dialog.getByLabel("Grep extract rule (regular expression)");
    await expect(rule).toHaveValue(/\(\[\\s\\S\]\*\?\)/);
    await expect(dialog.getByText("the highlighted text", { exact: true })).toBeVisible();
    await expect(dialog.locator("code").first()).toHaveText("admin");
    await expect(save).toBeEnabled();
    const regex = await rule.inputValue();
    await save.click();
    await expect(dialog).toBeHidden();

    // The rule is the attack's Grep extract now, on the Settings tab where it is typed by hand.
    await page.getByRole("tab", { name: /^Settings/ }).click();
    await expect(page.getByLabel("Grep extract (regular expression)")).toHaveValue(regex);

    expect(consoleErrors).toEqual([]);
  });

  // Settings that decide what an attack keeps (ip2b, nqww) and how it reads reflections (7qc3), set on
  // the Settings tab and read back off the Results tab of a real run.
  test("the capture filter, storage switches and grep payloads shape the results", async ({ page, consoleErrors }) => {
    await pinTheme(page, "dark");
    await launchAttack(page, "/capture-and-store", async (p) => {
      await p.getByRole("tab", { name: /^Settings/ }).click();
      await p.getByRole("checkbox", { name: "Apply capture filter" }).check();
      // The origin echoes the request target, so only the row whose payload is "admin" contains it.
      await p.getByLabel("Capture by search term").fill("q=admin");
      // The attack-results switches sit with retries and the baseline request.
      await p.getByRole("tab", { name: /^Resource pool/ }).click();
      await p.getByRole("checkbox", { name: "Store responses" }).uncheck();
    });

    const caveats = page.locator(".notice-warn").filter({ hasText: "Bounds applied to this attack" });
    await expect(caveats).toContainText("Capture filter: Matching expression q=admin");
    await expect(caveats).toContainText("4 results discarded");
    await expect(caveats).toContainText("Not stored (attack setting): responses");
    // One row out of five is the filter's doing, not the row limit's, and the caveats must not say otherwise.
    await expect(caveats).not.toContainText("Per-attempt detail limited");

    const attempts = page.getByRole("group", { name: "Attempts" });
    await expect(attempts.locator("tbody tr")).toHaveCount(1);
    await expect(attempts.locator("tbody tr").first()).toContainText("admin");
    // Grep - Payloads is on by default: one count column for the one payload set, and the echoed
    // payload is counted.
    await expect(attempts.getByRole("columnheader", { name: "Payload reflections" })).toBeVisible();

    // The row's response was not stored, and the cell says it was the setting.
    await expect(attempts.locator('tbody tr [title^="Not stored (attack setting)"]').first()).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });
});
