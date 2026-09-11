// burpsy-react-ui-mem3: Burp's own docs describe reordering a table by drag — "Move columns -
// Drag and drop the column header to a new location" — on every table it shows, and VirtualTable
// (ui/table.tsx) had sizing and visibility but no columnOrder at all: the columns array's own order
// was the only order a page could ever render. This drives an actual header drag through a real
// page (Scope's rule table, chosen because its columns render even with an empty rule set) and
// checks the rendered header order changed, then reloads the page and checks it survived — the
// persistence the bead's brief calls out explicitly ("an order that resets on navigation is worse
// than none").
//
// Scope is driven here for its table shape only; nothing about scope rules themselves is under
// test.

import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/** The scope table's header row, left to right, as rendered text — lowercased, because the header
 *  row is styled with `text-transform: uppercase` and Playwright's innerText follows CSS casing,
 *  not the DOM's own text content. */
async function headerOrder(page: import("@playwright/test").Page): Promise<string[]> {
  const texts = await page.locator('[aria-label="Scope rules"] thead th').allInnerTexts();
  return texts.map((text) => text.toLowerCase());
}

test.describe("Table column drag-reorder — burpsy-react-ui-mem3", () => {
  test("dragging a column header moves it, and the new order survives a reload", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("scope"));

    const before = await headerOrder(page);
    expect(before[0]).toContain("enabled");
    expect(before[2]).toContain("host");

    // Drag the Host header's handle and drop it on the Enabled header, so Host should land first.
    const hostHandle = page.locator('[aria-label="Scope rules"] thead th', { hasText: "Host" }).locator(".col-drag-handle");
    const enabledHeader = page.locator('[aria-label="Scope rules"] thead th', { hasText: "Enabled" });
    await hostHandle.dragTo(enabledHeader);

    const afterDrag = await headerOrder(page);
    expect(afterDrag[0], `header order after drag: ${afterDrag.join(", ")}`).toContain("host");
    expect(afterDrag.indexOf(afterDrag.find((h) => h.includes("host"))!)).toBeLessThan(
      afterDrag.indexOf(afterDrag.find((h) => h.includes("enabled"))!),
    );

    // Reload — a full navigation, not a client-side route change — and the order must still hold.
    // This is the one assertion that fails if the fix only reorders in memory: a page remount with
    // nothing behind it re-reads the columns prop in its original order every time.
    await page.reload();
    await page.waitForSelector('[aria-label="Scope rules"] thead th');
    const afterReload = await headerOrder(page);
    expect(afterReload).toEqual(afterDrag);

    expect(consoleErrors).toEqual([]);
  });
});
