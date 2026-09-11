// burpsy-react-ui-ldfk: Burp's Organizer names the originating tool on every row ("The Burp tool
// that originally generated the request... always reflects the request's origin") and lets an
// operator filter by it ("Show or hide items that were sent to Organizer from different tools").
// burpsy's OrganizerItem carried no such field and the table had no such column or filter.
//
// The harness seeds two exchanges with genuinely different origins: exchange 0 is proxy traffic
// (GET /zebra, seeded through the proxy listener) and the repeater send it also seeds
// (GET /repeated?x=9) goes through core.SourceRepeater (internal/web/api_tools.go's
// handleRepeaterSend sets it explicitly, not the unattributed zero value). Saving both into
// Organizer and reading the real Tool column back is what proves this reads an actual field on the
// exchange rather than a hand-typed label.

import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

async function saveExchange(page: import("@playwright/test").Page, id: string): Promise<void> {
  await page.getByLabel("Exchange id to save").fill(id);
  await page.getByRole("button", { name: "Save exchange" }).click();
  await expect(page.getByText(new RegExp(`^Saved exchange #${id}$`))).toBeVisible();
}

test.describe("Organizer Tool column and filter — burpsy-react-ui-ldfk", () => {
  test("the Tool column names each row's real origin, and Filter by tool narrows the table to match", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("organizer"));

    // Exchange 0: the harness's first proxied request.
    await saveExchange(page, "0");
    // The repeater send the harness also seeds. Its exchange id is not asserted anywhere else in
    // this repo (only its content, /repeated?x=9, is documented in harness/server.ts), so if the
    // harness's seed order ever changes, this test fails on the "Repeater" badge assertion below
    // rather than silently checking the wrong row.
    await saveExchange(page, "5");

    const rows = page.locator('table:has(th:text("Tool")) tbody tr.data-row');
    await expect(rows).toHaveCount(2);
    await expect(rows.filter({ hasText: "#0" }).locator("td").nth(2)).toContainText("Proxy");
    await expect(rows.filter({ hasText: "#5" }).locator("td").nth(2)).toContainText("Repeater");

    // Filter by tool: narrowing to Repeater must hide the proxy-sourced row and keep the other.
    await page.getByLabel("Tool", { exact: true }).selectOption("repeater");
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("#5");
    await expect(rows.first()).toContainText("Repeater");

    // Back to "Any tool" restores both rows — the filter narrows, it does not discard.
    await page.getByLabel("Tool", { exact: true }).selectOption("all");
    await expect(rows).toHaveCount(2);

    expect(consoleErrors).toEqual([]);
  });
});
