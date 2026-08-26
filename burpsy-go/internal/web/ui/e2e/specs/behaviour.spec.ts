// Behaviour, not smoke.
//
// Each of these asserts an observable consequence rather than a mechanism: the theme toggle is
// checked by reading a rendered colour, not by reading back the attribute it just set, because an
// attribute no stylesheet consumes would satisfy the second and change nothing on screen.

import { request as httpRequest } from "node:http";
import { activePane, expect, gotoApp, gotoRoute, pinTheme, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

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
    // Since the FlatLaf restyle (7d0c7d5) the shell ships dark (Darcula) as its first-launch
    // default regardless of the OS colour scheme, so this flow pins both facts at once: first
    // launch is dark even under an OS that says light, and an operator's explicit choice survives
    // a reload that would otherwise fall back to the dark default.
    //
    // Deliberately NOT using pinTheme here: addInitScript runs on EVERY document load, reloads
    // included, so it would rewrite localStorage back to its own value before the app boots and
    // the test would report a persistence bug that does not exist.
    await page.emulateMedia({ colorScheme: "light" });
    await gotoApp(page);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

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
    // The harness sends exactly one request through Repeater, and it must not show up here. In
    // Burp, Proxy › HTTP history is proxy traffic; a Repeater send appears in Logger, which is the
    // view whose whole subject is "requests the tool itself made". burpsy now enforces that split:
    // the repeater tags its exchange SourceRepeater, /api/history drops repeater/intruder/scanner-
    // attributed rows, and persist round-trips the attribution so a restart cannot bring the row
    // back. The sibling test below already proves Logger holds the send.
    //
    // This was a deliberate red test pinning the leak (2026-08); the fix landed and this is now
    // the regression guard. Kept as its own test so the five assertions above still report
    // independently of it.
    await gotoRoute(page, route("history"));
    await expect(page.locator("tr.data-row", { hasText: "/repeated" })).toHaveCount(0);
  });

  test("a table header sorts, and reorders the rows", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("history"));
    const rows = page.locator("tr.data-row");
    // Five rows exactly: the Repeater send no longer leaks into history (see the test above), so
    // the count is the five proxied exchanges and nothing else.
    await expect(rows).toHaveCount(5);

    // All five path cells: only the Path column renders a <code> element, so targeting it
    // avoids the column-index fragility that .nth(3) across a flattened td list caused (it
    // narrowed to one cell, not one per row — the sort assertion was comparing 1-element arrays).
    const paths = async () =>
      (await page.locator("tr.data-row code").allInnerTexts()).map((text) => text.trim());
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
    // Density is a preference set in one place and consumed in another, and that crossing is exactly
    // where a preference quietly stops being read. The store holds density, Settings offers a Select
    // for it, and the palette and the View menu each offer a toggle. The tables consume it directly:
    // VirtualTable and SimpleTable fall back to the store's value when no page passes an explicit
    // density prop (src/ui/table.tsx), so the toggle reaches every table at once instead of needing
    // 24 call sites kept in sync — the drift that made this a deliberate red test (2026-08). The fix
    // landed; this is now the regression guard.
    //
    // Since the FlatLaf restyle (7d0c7d5) the first-launch default is compact (Burp's own density),
    // so the flow starts from compact and asserts the command moves the table to comfortable.
    await gotoRoute(page, route("history"));
    await expect(page.locator(".table-frame")).toHaveClass(/density-compact/);

    await page.keyboard.press("ControlOrMeta+k");
    await page.getByLabel("Search commands").fill("comfortable");
    await page.locator("#palette-results [role=option]").first().click();

    await expect(page.locator(".table-frame")).toHaveClass(/density-comfortable/);
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

test.describe("History row annotation and scope filter — UX-15, UX-18", () => {
  test("highlighting a history row tints it and survives a reload", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("history"));
    const row = page.locator("tr.data-row", { hasText: "/mango/deep/path" });
    const otherRow = page.locator("tr.data-row", { hasText: "/beta" });
    await row.click();

    // The picker only exists once a row is selected — it lives in the detail pane, not the row
    // itself, so painting a colour never costs one of the 24px rows the density budget is spent on.
    await page.getByRole("button", { name: "Highlight row red" }).click();
    await expect(row).toHaveClass(/row-highlight-red/);

    // A real background fill, not the 2px inset shadow row-flag-bad/warn render as (the survey's
    // finding this task exists to fix) — the highlighted row's cell colour must actually differ from
    // an unhighlighted one, not just carry a class nothing paints.
    const tinted = await row.locator("td").first().evaluate((el) => getComputedStyle(el).backgroundColor);
    const plain = await otherRow.locator("td").first().evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(tinted, "the row-highlight-red class landed but the background did not change").not.toBe(plain);

    await page.reload();
    await expect(page.locator("main h1")).toHaveText(/^HTTP history/);
    await expect(page.locator("tr.data-row", { hasText: "/mango/deep/path" })).toHaveClass(/row-highlight-red/);

    expect(consoleErrors).toEqual([]);
  });

  test("a note on a history row shows the comment indicator", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("history"));
    const row = page.locator("tr.data-row", { hasText: "/quokka?size=8" });
    await row.click();
    await expect(row.locator(".comment-indicator")).toHaveCount(0);

    const note = page.getByRole("textbox", { name: "Row note" });
    await note.fill("came back to check this one");
    await note.blur();

    await expect(row.locator(".comment-indicator")).toBeVisible();
    // The glyph is decorative; the reason it is there is not, and that has to reach a screen reader.
    await expect(row.locator(".comment-indicator")).toHaveAttribute("title", "Has a note");

    expect(consoleErrors).toEqual([]);
  });

  test("the in-scope-only toggle filters the rows and shows in the query", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("history"));
    const rows = page.locator("tr.data-row");
    await expect(rows).toHaveCount(5);

    // Every seeded exchange shares one host (the harness's throwaway origin) and it is served over
    // bare 127.0.0.1, so a single exclude rule on that host takes the whole capture out of scope —
    // a plain hostname with no wildcard, which is exactly the case the DSL can express exactly.
    try {
      await page.request.post("/api/scope", { data: { action: "exclude", pattern: "127.0.0.1" } });

      const queryBox = page.getByRole("textbox", { name: "Filter history" });
      await page.getByRole("button", { name: "In scope only" }).click();

      // "Reflect it in the query text" (DESIGN.md / the task brief): the toggle's effect is visible
      // as real DSL, not a second hidden filter — the operator can read it, and could have typed it.
      await expect(queryBox).toHaveValue('NOT host = "127.0.0.1"');
      await expect(page.getByText("No exchange matches this filter")).toBeVisible();
      await expect(rows).toHaveCount(0);

      // Turning it back off restores the capture and removes exactly the clause it added.
      await page.getByRole("button", { name: "In scope only" }).click();
      await expect(queryBox).toHaveValue("");
      await expect(rows).toHaveCount(5);
    } finally {
      // Single shared server for the whole file (workers: 1) — leaving this rule in place would take
      // every later test's traffic out of scope too.
      await page.request.post("/api/scope", { data: { action: "clear" } });
    }

    expect(consoleErrors).toEqual([]);
  });
});

test.describe("the editable Inspector — Unit 14", () => {
  /**
   * A GET through the proxy that RESOLVES WITH THE BODY, unlike the harness's own
   * viaProxy which only waits for the end of the stream. The body is the assertion:
   * the throwaway origin echoes `ORIGIN-OK <method> <url>`, so reading it back is
   * how a test learns what bytes the proxy actually forwarded — as opposed to what
   * the console displayed, which is the thing under test and cannot vouch for itself.
   *
   * `agent: false` for the same reason the harness does it; see viaProxy's comment.
   */
  function proxyGet(proxyPort: number, url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const target = new URL(url);
      const request = httpRequest(
        { host: "127.0.0.1", port: proxyPort, method: "GET", path: url, headers: { Host: target.host }, agent: false },
        (response) => {
          let body = "";
          response.setEncoding("utf8");
          response.on("data", (chunk: string) => {
            body += chunk;
          });
          response.once("end", () => resolve(body));
        },
      );
      request.once("error", reject);
      request.end();
    });
  }

  test("an Inspector edit changes the request Repeater actually sends", async ({ page, consoleErrors }) => {
    const { targetPort } = readHarness();
    const origin = `http://127.0.0.1:${targetPort}`;
    await gotoRoute(page, route("repeater"));

    // A fresh browser has no persisted tabs, so the page opens on its empty state.
    await page.getByRole("button", { name: "New request" }).first().click();
    await page.getByLabel("Target", { exact: true }).fill(origin);

    const requestEditor = page.locator(".editor-grid-inspected > *").first();
    await expect(requestEditor).toContainText("GET /");

    // Edit the request target through the Inspector, not the Raw view — the whole
    // claim being tested is that the Inspector writes the message the tool sends.
    const inspector = page.locator(".inspector");
    const targetField = inspector.getByLabel("Request attributes value for Target");
    await targetField.fill("/inspector-edited");
    await inspector.getByRole("button", { name: "Apply" }).click();

    // First: the edit reached the raw bytes, spliced rather than reflowed.
    await expect(requestEditor).toContainText("GET /inspector-edited HTTP/1.1");
    // And the field is no longer dirty, so Apply has gone.
    await expect(inspector.getByRole("button", { name: "Apply" })).toHaveCount(0);

    // Then the assertion that matters: send it, and let the ORIGIN say what it received.
    // A console that displayed the edit but sent the old bytes passes the check above
    // and fails this one.
    await page.getByRole("button", { name: "Send", exact: true }).click();
    const responseEditor = page.locator(".editor-grid-inspected > *").nth(1);
    await expect(responseEditor).toContainText("ORIGIN-OK GET /inspector-edited");

    expect(consoleErrors).toEqual([]);
  });

  test("adding a header in the Inspector puts it on the wire", async ({ page, consoleErrors }) => {
    const { targetPort } = readHarness();
    await gotoRoute(page, route("repeater"));
    await page.getByRole("button", { name: "New request" }).first().click();
    await page.getByLabel("Target", { exact: true }).fill(`http://127.0.0.1:${targetPort}`);

    const inspector = page.locator(".inspector");
    // The headers section starts collapsed only when empty; a template request has a
    // Host header, so it is open and its count is honest about what is in it.
    const headers = inspector.locator(".inspector-section").filter({ hasText: "Request headers" });
    await headers.getByRole("button", { name: "Add" }).click();
    await headers.getByLabel("New Request headers name").fill("X-Inspector");
    await headers.getByLabel("New Request headers value").fill("unit-14");
    await headers.getByRole("button", { name: "Apply" }).click();

    const requestEditor = page.locator(".editor-grid-inspected > *").first();
    await expect(requestEditor).toContainText("X-Inspector: unit-14");

    // And it comes back as a row of the Inspector's own headers section, which is the
    // round trip: written into the bytes, then re-parsed out of them.
    await expect(headers.getByLabel("Request headers value for X-Inspector")).toHaveValue("unit-14");

    expect(consoleErrors).toEqual([]);
  });

  test("a Repeater response is inspectable but says why it is not editable", async ({ page, consoleErrors }) => {
    const { targetPort } = readHarness();
    await gotoRoute(page, route("repeater"));
    await page.getByRole("button", { name: "New request" }).first().click();
    await page.getByLabel("Target", { exact: true }).fill(`http://127.0.0.1:${targetPort}`);
    await page.getByRole("button", { name: "Send", exact: true }).click();

    const inspector = page.locator(".inspector");
    await expect(inspector.getByLabel("Request attributes value for Method")).toBeVisible();

    await inspector.getByRole("button", { name: "Inspect the response" }).click();

    // The response's fields are readable — the Set-Cookie the origin sets is right there —
    // and the pane states why they cannot be typed into, rather than offering a dead field.
    await expect(inspector).toContainText("Response attributes");
    await expect(inspector).toContainText("A response that has already arrived cannot be edited");
    await expect(inspector.getByLabel(/Response attributes value for/)).toHaveCount(0);
    await expect(inspector).toContainText("E2E_SESSION");

    await inspector.getByRole("button", { name: "Inspect the request" }).click();
    await expect(inspector.getByLabel("Request attributes value for Method")).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });

  test("the Inspector's decoder decodes a value and writes it back", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("repeater"));
    await page.getByRole("button", { name: "New request" }).first().click();

    const inspector = page.locator(".inspector");
    // Put a percent-encoded query parameter on the request to have something to decode.
    const query = inspector.locator(".inspector-section").filter({ hasText: "Query parameters" });
    await query.getByRole("button", { name: "Add" }).click();
    await query.getByLabel("New Query parameters name").fill("next");
    await query.getByLabel("New Query parameters value").fill("%2Fhome%3Fa%3D1");
    await query.getByRole("button", { name: "Apply" }).click();

    // Encoding the value on the way in is the writers' job, so what is stored is the
    // double-encoded form; the row reads back the once-decoded text.
    const valueField = query.getByLabel("Query parameters value for next");
    await expect(valueField).toHaveValue("%2Fhome%3Fa%3D1");

    // Send it to the Selection section and run a URL decode over it.
    await query.getByRole("button", { name: "Decode next" }).click();
    const selection = inspector.locator(".inspector-selection");
    await expect(selection.getByLabel("Selection text")).toHaveValue("%2Fhome%3Fa%3D1");

    await selection.getByRole("button", { name: "Add decoder" }).click();
    await selection.getByLabel("Decoder 1 encoding").selectOption("url-decode");
    await expect(selection.getByLabel("Selection text")).toHaveValue("/home?a=1");

    // Apply writes the DECODED text back into the parameter it came from.
    await selection.getByRole("button", { name: "Apply" }).click();
    await expect(query.getByLabel("Query parameters value for next")).toHaveValue("/home?a=1");

    expect(consoleErrors).toEqual([]);
  });

  test("the Inspector dock preference survives a reload", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("repeater"));
    await page.getByRole("button", { name: "New request" }).first().click();

    const inspector = page.locator(".inspector");
    await expect(inspector).toHaveClass(/inspector-dock-right/);

    await inspector.getByRole("button", { name: "Inspector settings" }).click();
    await page.getByRole("radio", { name: "Left" }).check();

    // Docking left has to move the pane, not just relabel a setting: the Inspector's
    // left edge must end up left of the request editor's.
    await expect(inspector).toHaveClass(/inspector-dock-left/);
    const inspectorBox = await inspector.boundingBox();
    const editorBox = await page.locator(".editor-grid-inspected > .editor").first().boundingBox();
    expect(inspectorBox!.x).toBeLessThan(editorBox!.x);

    await page.reload();
    await expect(page.locator("main h1")).toHaveText(/^Repeater/);
    await expect(page.locator(".inspector")).toHaveClass(/inspector-dock-left/);

    // Put it back: the store is persisted per browser profile, and Playwright reuses
    // the context across tests in a file.
    await page.locator(".inspector").getByRole("button", { name: "Inspector settings" }).click();
    await page.getByRole("radio", { name: "Right" }).check();
    await expect(page.locator(".inspector")).toHaveClass(/inspector-dock-right/);

    expect(consoleErrors).toEqual([]);
  });

  test("an Inspector edit in Intercept changes the bytes actually forwarded", async ({ page, consoleErrors }) => {
    const { proxyPort, targetPort } = readHarness();
    const origin = `http://127.0.0.1:${targetPort}`;

    // Interception is global to the one shared burpsy process, so it is turned back off
    // in `finally` no matter how this test ends — leaving it on would hang every later
    // test's traffic behind a held message nobody forwards.
    await page.request.post("/api/intercept/enable", { data: { enabled: true } });
    let inFlight: Promise<string> | null = null;
    try {
      await gotoRoute(page, route("intercept"));

      // Fire the request and DO NOT await it: the proxy is holding it, so it only
      // resolves once this test forwards it below.
      inFlight = proxyGet(proxyPort, `${origin}/held-original`);

      const row = page.locator("tr.data-row", { hasText: "/held-original" });
      await expect(row).toBeVisible();
      await row.click();

      const inspector = page.locator(".inspector");
      await inspector.getByLabel("Request attributes value for Target").fill("/forwarded-by-inspector");
      await inspector.getByRole("button", { name: "Apply" }).click();

      // The held-bytes editor is the buffer Forward sends, so the edit has to show there.
      await expect(page.locator(".held-grid-inspected > *").first()).toContainText("GET /forwarded-by-inspector");

      await page.getByRole("button", { name: "Forward" }).click();

      // The origin is the witness. It echoes the path it was asked for, so this fails if
      // the console showed the edit and forwarded the original bytes.
      const body = await inFlight;
      inFlight = null;
      expect(body).toContain("ORIGIN-OK GET /forwarded-by-inspector");
      expect(body).not.toContain("/held-original");
    } finally {
      await page.request.post("/api/intercept/enable", { data: { enabled: false } });
      await page.request.post("/api/intercept/drop-all", { data: {} }).catch(() => null);
      // A request still parked in the proxy would keep its socket open into teardown.
      if (inFlight) await inFlight.catch(() => null);
    }

    expect(consoleErrors).toEqual([]);
  });
});
