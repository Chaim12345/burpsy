// Behaviour, not smoke.
//
// Each of these asserts an observable consequence rather than a mechanism: the theme toggle is
// checked by reading a rendered colour, not by reading back the attribute it just set, because an
// attribute no stylesheet consumes would satisfy the second and change nothing on screen.

import { activePane, expect, gotoApp, gotoRoute, pinTheme, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

test.describe("shell behaviour", () => {
  test("the theme toggle actually re-themes", async ({ page, consoleErrors }) => {
    await pinTheme(page, "dark");
    await gotoApp(page);

    const shellBackground = () =>
      page.evaluate(() => getComputedStyle(document.body).backgroundColor);

    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    const dark = await shellBackground();

    // The toolbar button's accessible name states the destination, not the current state — so this is
    // also a check that the label is not inverted, a mistake that is invisible without a screen reader.
    await page.getByRole("button", { name: "Use light theme" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    const light = await shellBackground();

    expect(light, "data-theme flipped but nothing on screen changed colour").not.toBe(dark);
    await expect(page.getByRole("button", { name: "Use dark theme" })).toBeVisible();

    // And the keyboard binding reaches the same code path.
    await page.keyboard.press("ControlOrMeta+Shift+l");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    expect(await shellBackground()).toBe(dark);

    expect(consoleErrors).toEqual([]);
  });

  test("the theme survives a reload", async ({ page }) => {
    // zustand persists theme under burpsy.workspace and partialize keeps it. An operator who picks
    // light and gets dark back on the next page load will not pick it twice.
    await pinTheme(page, "dark");
    await gotoApp(page);
    await page.getByRole("button", { name: "Use light theme" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  });

  test("mod+K opens the command palette, and it navigates", async ({ page, consoleErrors }) => {
    await gotoApp(page);
    await page.keyboard.press("ControlOrMeta+k");

    const search = page.getByLabel("Search commands");
    await expect(search).toBeVisible();
    await expect(search).toBeFocused();

    // Filtering, then running an entry. Opening the palette proves a dialog mounts; running something
    // out of it proves the actions are wired, which is the part that can silently rot.
    await search.fill("sequencer");
    const first = page.locator("#palette-results [role=option]").first();
    await expect(first).toContainText("Sequencer");
    await first.click();

    await expect(page.locator("main h1")).toHaveText(/^Sequencer/);
    await expect(search).toHaveCount(0);
    expect(new URL(page.url()).hash).toBe("#sequencer");
    expect(consoleErrors).toEqual([]);
  });

  test("Escape closes the palette without navigating", async ({ page }) => {
    await gotoApp(page);
    const before = page.url();
    await page.keyboard.press("ControlOrMeta+k");
    await expect(page.getByLabel("Search commands")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByLabel("Search commands")).toHaveCount(0);
    expect(page.url()).toBe(before);
  });

  test("? opens the shortcut sheet", async ({ page, consoleErrors }) => {
    await gotoApp(page);
    await page.keyboard.press("?");

    const dialog = page.locator(".dialog-content", { has: page.locator(".dialog-title") });
    await expect(dialog).toBeVisible();
    await expect(page.locator(".dialog-title")).toHaveText("Keyboard shortcuts");

    // The sheet's whole justification is that it documents the bindings that differ from Burp's, so
    // the divergence is visible instead of surprising. If the notes stop rendering it is decoration.
    await expect(dialog.locator(".shortcut-note").first()).toBeVisible();
    await expect(dialog.getByText("alt+1…0")).toBeVisible();

    await page.getByRole("button", { name: "Close" }).click();
    await expect(dialog).toHaveCount(0);
    expect(consoleErrors).toEqual([]);
  });
});

test.describe("data views", () => {
  test("HTTP history shows the seeded traffic", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("history"));
    const rows = page.locator("tr.data-row");
    // The harness proxies five distinct paths before any test runs. Fewer than that means either the
    // proxy did not capture them or the table is not reading /api/history.
    await expect(rows).toHaveCount(5);
    await expect(page.locator("tr.data-row", { hasText: "/mango/deep/path" })).toHaveCount(1);
    expect(consoleErrors).toEqual([]);
  });

  test("a table header sorts, and reorders the rows", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("history"));
    const rows = page.locator("tr.data-row");
    await expect(rows).toHaveCount(5);

    const paths = async () => (await rows.locator("td").nth(3).allInnerTexts()).map((text) => text.trim());
    const pathHeader = page.locator("th", { has: page.getByRole("button", { name: "Path" }) });

    // Unsorted, history is in capture order — which is the order the harness proxied them in, and
    // deliberately not alphabetical, so an ascending sort must visibly move things.
    const captureOrder = await paths();

    await page.getByRole("button", { name: "Path", exact: true }).click();
    await expect(pathHeader).toHaveAttribute("aria-sort", "ascending");
    const ascending = await paths();
    expect(ascending).toEqual([...ascending].sort());
    expect(ascending, "aria-sort said ascending but the rows did not move").not.toEqual(captureOrder);

    await page.getByRole("button", { name: "Path", exact: true }).click();
    await expect(pathHeader).toHaveAttribute("aria-sort", "descending");
    expect(await paths()).toEqual([...ascending].reverse());

    expect(consoleErrors).toEqual([]);
  });

  test("selecting a row opens its detail without leaving the route", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("history"));
    const row = page.locator("tr.data-row", { hasText: "/mango/deep/path" });
    await row.click();
    await expect(row).toHaveAttribute("aria-selected", "true");
    // The stored request must be the origin form the upstream received, which is what makes Repeater
    // and Intruder start from the right bytes. e2e-go.sh asserts the same fact over the API; this is
    // the assertion that the operator can actually see it.
    await expect(page.getByText("GET /mango/deep/path HTTP/1.1").first()).toBeVisible();
    expect(new URL(page.url()).hash).toBe("#history");
    expect(consoleErrors).toEqual([]);
  });

  test("keyboard navigation moves the table selection", async ({ page }) => {
    await gotoRoute(page, route("history"));
    const rows = page.locator("tr.data-row");
    await rows.first().click();
    await expect(rows.first()).toHaveAttribute("aria-selected", "true");

    await page.keyboard.press("ArrowDown");
    await expect(rows.nth(1)).toHaveAttribute("aria-selected", "true");
    await page.keyboard.press("End");
    await expect(rows.last()).toHaveAttribute("aria-selected", "true");
    await page.keyboard.press("Home");
    await expect(rows.first()).toHaveAttribute("aria-selected", "true");
  });

  test("the Tool log shows the request burpsy itself sent", async ({ page, consoleErrors }) => {
    // Logger's whole subject is traffic burpsy originated, so proxy traffic must NOT appear here and
    // the harness's one repeater send must. A logger that echoed HTTP history would pass a row count.
    await gotoRoute(page, route("logger"));
    await expect(page.locator("tr.data-row", { hasText: "/repeated" })).toHaveCount(1);
    await expect(page.locator("tr.data-row", { hasText: "/mango/deep/path" })).toHaveCount(0);
    expect(consoleErrors).toEqual([]);
  });

  test("the site map lists the proxied host as a tree", async ({ page, consoleErrors }) => {
    // The site map became a real tree in commit 37cd0e8; before that it was a flat list. Asserting a
    // host row exists AND that it can be expanded is what distinguishes the two.
    await gotoRoute(page, route("sitemap"));
    const hostRow = page.locator(".tree-row-label", { hasText: "127.0.0.1" }).first();
    await expect(hostRow).toBeVisible();
    await page.getByRole("button", { name: /^Expand / }).first().click();
    await expect(page.locator(".tree-row-label")).not.toHaveCount(1);
    expect(consoleErrors).toEqual([]);
  });

  test("the status bar reports the stored bytes the API reports", async ({ page }) => {
    // Cheap, and it is the one place the shell claims a number that comes from the server rather than
    // from the store — so it is where a broken /api/stats would show up as a plausible-looking dash.
    await gotoApp(page);
    await expect(page.locator(".statusbar")).toContainText("exchanges");
    await expect(page.locator(".statusbar")).not.toContainText("— stored");
  });
});

test.describe("Intruder tabs", () => {
  test("switching tabs swaps the visible pane", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("intruder"));

    // Radix keeps inactive panes mounted and marked [hidden]. `activePane` is the only correct way to
    // read "the pane on screen" — a bare .tool-pane locator resolves to whichever the DOM lists first,
    // which is usually an inactive one, and makes a working tab group look broken.
    await expect(activePane(page)).toHaveCount(1);

    // Tab labels are uppercased by CSS. getByRole matches the accessible name, which is the DOM text,
    // so this works — but a `textContent === "payloads"` comparison would not, and did not, for the
    // agent who tried it first.
    await page.getByRole("tab", { name: /payloads/i }).click();
    await expect(activePane(page)).toHaveCount(1);
    await expect(activePane(page)).toContainText(/payload/i);

    await page.getByRole("tab", { name: /positions/i }).click();
    await expect(activePane(page)).toHaveCount(1);

    expect(consoleErrors).toEqual([]);
  });
});

test.describe("preferences reach the rendered UI", () => {
  test("the density command changes the table's row class", async ({ page, consoleErrors }) => {
    // Density is a preference set in one place (the palette, or the View menu) and consumed in
    // another (every table). That crossing is where a preference quietly stops being read — the
    // control still toggles, the toast still appears, and nothing on screen gets denser.
    await gotoRoute(page, route("history"));
    await expect(page.locator(".table-frame")).toHaveClass(/density-comfortable/);

    await page.keyboard.press("ControlOrMeta+k");
    await page.getByLabel("Search commands").fill("compact");
    await page.locator("#palette-results [role=option]").first().click();

    await expect(page.locator(".table-frame")).toHaveClass(/density-compact/);
    expect(consoleErrors).toEqual([]);
  });

  test("the menu bar opens a Repeater tab and navigates to it", async ({ page, consoleErrors }) => {
    // The menu bar is the one surface with no keyboard shortcut of its own, so nothing else covers
    // it. "New request tab" also writes to the store and navigates, which makes it the item most
    // likely to half-work.
    await gotoRoute(page, route("dashboard"));
    // Scoped to .menu-bar: "Repeater" also names a tool tab, and an unscoped getByRole would resolve
    // to whichever comes first in the DOM — which is a different control that does something else.
    await page.locator(".menu-bar").getByRole("button", { name: "Repeater", exact: true }).click();
    await page.getByRole("menuitem", { name: /New request tab/ }).click();

    await expect(page.locator("main h1")).toHaveText(/^Repeater/);
    await expect(page.getByText("Request 1")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });
});
