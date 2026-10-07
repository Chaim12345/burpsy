// burpsy-react-ui-ufn: the Comparer had no hex view. Burp's own docs describe one ("Text - View
// both items in text form. Hex - View both items in hex form."), and this build's own comment on
// the padding glyph (GAP_CHAR = "·") says outright that it is indistinguishable from a real
// middot in the data — i.e. the text view cannot reliably show a whitespace-only or
// non-printable-byte difference, which is exactly the class of difference a byte-level comparer
// exists to find. This drives a real comparison through the real backend and reads the rendered
// hex bytes back, rather than asserting the toggle merely exists.

import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

test.describe("Comparer hex view — burpsy-react-ui-ufn", () => {
  test("toggling to Hex renders both panes as byte-level hex, and a whitespace-only difference is a distinct byte pair", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("comparer"));

    // Slot A gets a tab, slot B gets a space, at the same position — in text form these can look
    // identical or render as invisible whitespace, which is the whole reason this view exists.
    const editors = page.locator(".cm-content");
    await editors.nth(0).click();
    await page.keyboard.type("field:a\tvalue", { delay: 5 });
    await editors.nth(1).click();
    await page.keyboard.type("field:a value", { delay: 5 });

    await page.getByRole("button", { name: "Compare", exact: true }).click();
    await expect(page.getByText(/difference\(s\) found/)).toBeVisible();

    // Before the toggle: the text panes are on screen, no hex grid.
    await expect(page.locator(".diff-panes")).toBeVisible();
    await expect(page.locator(".diff-pane-body").first()).not.toContainText("00000000");

    await page.getByRole("button", { name: "Hex" }).click();

    // After the toggle: an 8-digit offset column opens each row, which text mode never renders.
    const panes = page.locator(".diff-pane-body");
    await expect(panes.first()).toContainText("00000000");
    await expect(panes.nth(1)).toContainText("00000000");

    // The byte that actually differs: 0x09 (tab) in A's pane, 0x20 (space) in B's pane. If this
    // reused the text pane's padded/aligned strings instead of real per-side bytes, both would
    // read back whatever the shared padding glyph encodes to, not the true byte.
    await expect(panes.first()).toContainText("09");
    await expect(panes.nth(1)).toContainText("20");

    // The differing byte is actually painted, not just present as text — same mechanism the
    // History row-highlight test (behaviour.spec.ts) uses: a real background, not a class nothing
    // paints. diff-replace is a decorative overlay across the differing hex cell.
    const hunkCell = panes.first().locator(".diff-replace").first();
    await expect(hunkCell).toBeVisible();
    const highlighted = await hunkCell.evaluate((el) => getComputedStyle(el).backgroundColor);
    const plain = await panes.first().locator("span").first().evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(highlighted, "the diff-replace class landed on the hex cell but painted nothing").not.toBe(plain);

    expect(consoleErrors).toEqual([]);
  });
});
