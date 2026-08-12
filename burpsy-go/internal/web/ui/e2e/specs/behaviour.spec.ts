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
    //
    // Deliberately NOT using pinTheme here: addInitScript runs on EVERY document load, reloads
    // included, so it would rewrite localStorage back to its own value before the app boots and the
    // test would report a persistence bug that does not exist. The starting theme comes from the
    // emulated colour scheme instead, and the assertion is only that the toggle's choice survives.
    await page.emulateMedia({ colorScheme: "light" });
    await gotoApp(page);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

    await page.getByRole("button", { name: "Use dark theme" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

    // Reloaded with the OS preference still saying light: only the persisted choice can keep it dark.
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
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

    // Wait for the app to be interactive before pressing, and not as superstition: useHotkeys binds
    // its listener in an effect, a keypress that lands before that is silently dropped, and
    // toBeVisible retries the ASSERTION but never the press — so an early press fails after the full
    // ten-second timeout and reads exactly like a broken shortcut. The status bar showing a real byte
    // count means a server round-trip has completed, which is well after effects have run.
    await expect(page.locator(".statusbar")).not.toContainText("— stored");

    // The app binds this with useHotkeys("shift+slash", ...) — the physical chord, not the "?"
    // character press("?") sends, which the hotkey matcher never recognises as shift+slash.
    await page.keyboard.press("Shift+Slash");

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
    // Each of the five proxied paths, exactly once. Asserted per path rather than as a total count,
    // because a total says only "some number of rows arrived" and would pass with five copies of one
    // exchange — and because the total here is six, for the reason the next test is about.
    for (const path of ["/zebra", "/alpha?q=1", "/mango/deep/path", "/beta", "/quokka?size=8"]) {
      await expect(page.locator("tr.data-row", { hasText: path })).toHaveCount(1);
    }
    expect(consoleErrors).toEqual([]);
  });

  test("Proxy HTTP history holds proxy traffic only", async ({ page }) => {
    // EXPECTED TO FAIL — a real finding, left failing on purpose.
    //
    // The harness sends exactly one request through Repeater, and it shows up here as a sixth row.
    // In Burp, Proxy › HTTP history is proxy traffic; a Repeater send appears in Logger, which is the
    // view whose whole subject is "requests the tool itself made". burpsy has both views, and the
    // sibling test below already proves Logger holds the Repeater send — so this row makes the two
    // views the same list with different columns, and makes "how many requests did I proxy" a
    // question HTTP history answers wrongly.
    //
    // Kept as its own test so the five assertions above still report independently of it.
    await gotoRoute(page, route("history"));
    await expect(page.locator("tr.data-row", { hasText: "/repeated" })).toHaveCount(0);
  });

  test("a table header sorts, and reorders the rows", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("history"));
    const rows = page.locator("tr.data-row");
    // EXPECTED TO FAIL for the same reason as "Proxy HTTP history holds proxy traffic only": the
    // Repeater send leaks into history as a sixth row, making this assertion resolve to 6 not 5.
    // The bug is documented there; this failure is a symptom, not an independent defect.
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

  test("hiding a column removes it from the header and every row", async ({ page, consoleErrors }) => {
    // UX-16. The Tool log is where the column-visibility menu is wired up (table.tsx's
    // `enableColumnVisibility`), and it always has the harness's one logged repeater send to
    // assert a row against.
    await gotoRoute(page, route("logger"));
    const statusHeader = page.locator("th", { has: page.getByRole("button", { name: "Status", exact: true }) });
    await expect(statusHeader).toBeVisible();
    await expect(page.locator("tr.data-row").first().locator("td")).not.toHaveCount(0);
    const cellsBefore = await page.locator("tr.data-row").first().locator("td").count();

    await page.getByRole("button", { name: "Show or hide columns" }).click();
    await page.getByRole("checkbox", { name: "Status", exact: true }).uncheck();
    await page.keyboard.press("Escape");

    await expect(statusHeader).not.toBeVisible();
    await expect(page.locator("tr.data-row").first().locator("td")).toHaveCount(cellsBefore - 1);
    // Escape returned focus to the trigger, not somewhere it has to be hunted for.
    await expect(page.getByRole("button", { name: "Show or hide columns" })).toBeFocused();
    expect(consoleErrors).toEqual([]);
  });

  test("resetting columns restores the hidden ones", async ({ page, consoleErrors }) => {
    // UX-16.
    await gotoRoute(page, route("logger"));
    const statusHeader = page.locator("th", { has: page.getByRole("button", { name: "Status", exact: true }) });
    const cellsBefore = await page.locator("tr.data-row").first().locator("td").count();

    await page.getByRole("button", { name: "Show or hide columns" }).click();
    await page.getByRole("checkbox", { name: "Status", exact: true }).uncheck();
    await expect(statusHeader).not.toBeVisible();

    // The identifier column ("Age") is never offered as a checkbox — it is the one column an
    // operator cannot lose track of a row through.
    await expect(page.getByRole("checkbox", { name: "Age", exact: true })).toHaveCount(0);

    await page.getByRole("button", { name: "Reset columns" }).click();
    await expect(statusHeader).toBeVisible();
    await expect(page.locator("tr.data-row").first().locator("td")).toHaveCount(cellsBefore);
    expect(consoleErrors).toEqual([]);
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
    // EXPECTED TO FAIL — a real finding, left failing on purpose.
    //
    // Density is a preference set in one place and consumed in another, and that crossing is exactly
    // where a preference quietly stops being read. It has: the store holds `density`, Settings offers
    // a Select for it, the palette and the View menu each offer a toggle, and the toggle fires a
    // success toast — but `density={...}` is passed to none of the 24 VirtualTable/SimpleTable call
    // sites, so every table renders at the component's own default and nothing on screen ever gets
    // denser. Four controls and a confirmation for a value no table reads.
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

test.describe("Intercept rule reordering — UX-17", () => {
  // Neither test saves, so the mutated draft is discarded on navigation and never reaches the
  // shared server the other tests in this file poll (workers: 1, one burpsy process).
  test("moving an intercept rule down changes the order it matches in", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("intercept"));
    await page.getByRole("tab", { name: "Interception rules" }).click();

    const requestCard = page
      .locator(".card")
      .filter({ has: page.getByRole("checkbox", { name: "Hold requests matching these rules" }) });

    await requestCard.getByRole("button", { name: "Add rule" }).click();
    await requestCard.getByRole("button", { name: "Add rule" }).click();
    await requestCard.getByLabel("Comment for rule 1").fill("first");
    await requestCard.getByLabel("Comment for rule 2").fill("second");

    // Intercept rules match in order, so moving rule 1 below rule 2 is an observable change in
    // which rule fires first — not just a visual reshuffle.
    await requestCard.getByRole("button", { name: "Move rule 1 down" }).click();

    await expect(requestCard.getByLabel("Comment for rule 1")).toHaveValue("second");
    await expect(requestCard.getByLabel("Comment for rule 2")).toHaveValue("first");

    // Rule 2 is now the last row, so its "down" control is disabled; focus must not land there —
    // it goes to the still-enabled "up" control on the row that moved, so a keyboard operator can
    // keep working without hunting for focus.
    await expect(requestCard.getByRole("button", { name: "Move rule 2 up" })).toBeFocused();

    expect(consoleErrors).toEqual([]);
  });

  test("the move-up control is disabled on the first intercept rule", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("intercept"));
    await page.getByRole("tab", { name: "Interception rules" }).click();

    const requestCard = page
      .locator(".card")
      .filter({ has: page.getByRole("checkbox", { name: "Hold requests matching these rules" }) });

    await requestCard.getByRole("button", { name: "Add rule" }).click();
    await requestCard.getByRole("button", { name: "Add rule" }).click();

    await expect(requestCard.getByRole("button", { name: "Move rule 1 up" })).toBeDisabled();
    await expect(requestCard.getByRole("button", { name: "Move rule 2 down" })).toBeDisabled();
    await expect(requestCard.getByRole("button", { name: "Move rule 1 down" })).toBeEnabled();
    await expect(requestCard.getByRole("button", { name: "Move rule 2 up" })).toBeEnabled();

    expect(consoleErrors).toEqual([]);
  });
});
