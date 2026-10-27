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

    // Organizer items persist across the run, and organizer-message-pane.spec.ts (which sorts first)
    // saves exchange 0 too, so the table may hold more than this test's two rows. The assertions are
    // about this test's rows and about the filter's effect, not about the table's total.
    const rows = page.locator('table:has(th:text("Tool")) tbody tr.data-row');
    const proxyRows = rows.filter({ hasText: "#0" });
    const repeaterRow = rows.filter({ hasText: "#5" });
    await expect(repeaterRow).toHaveCount(1);
    await expect(proxyRows.first()).toBeVisible();
    const total = await rows.count();
    await expect(proxyRows.first().locator("td").nth(2)).toContainText("Proxy");
    await expect(repeaterRow.locator("td").nth(2)).toContainText("Repeater");

    // Filter by tool: narrowing to Repeater must hide the proxy-sourced rows and keep the other.
    await page.getByLabel("Tool", { exact: true }).selectOption("repeater");
    await expect(proxyRows).toHaveCount(0);
    await expect(repeaterRow).toHaveCount(1);
    await expect(repeaterRow).toContainText("Repeater");
    await expect(rows.filter({ hasNotText: "Repeater" })).toHaveCount(0);

    // Back to "Any tool" restores every row — the filter narrows, it does not discard.
    await page.getByLabel("Tool", { exact: true }).selectOption("all");
    await expect(rows).toHaveCount(total);

    expect(consoleErrors).toEqual([]);
  });
});
