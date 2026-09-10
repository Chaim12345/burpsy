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

import { expect, gotoRoute, pinTheme, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/** The five default payloads the page ships with; the first is what a sniper attack sends first. */
const FIRST_PAYLOAD = "admin";

/**
 * Get from a cold app to an Intruder attack with results, entirely through the UI.
 *
 * Driven rather than seeded on purpose: the handoff under test reads message ids the *server* stored
 * during the attack, so an attack faked into the store would prove nothing about them.
 */
async function runAnAttack(page: import("@playwright/test").Page): Promise<void> {
  // The seeded exchange with a query parameter, so "Find positions" has a parameter to find.
  await gotoRoute(page, route("history"));
  const seeded = page.locator(".data-row", { hasText: "/alpha" }).first();
  await expect(seeded).toBeVisible();
  await seeded.click({ button: "right" });
  await page.getByRole("menuitem", { name: "Send to Intruder" }).click();

  await expect(page.getByRole("heading", { level: 1, name: "Intruder" })).toBeVisible();
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
