// Every route renders, names itself, and logs nothing.
//
// One test per route rather than one loop inside one test, so a failure names the route in its title
// and the other nineteen still report. A single "all routes" test that fails tells you the console is
// broken somewhere.

import { expect, gotoApp, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

/** nav.ts's one `hidden` leaf, as the palette labels it. */
const HIDDEN_LEAF = "Proxy › Exchange detail";

test.describe("routes", () => {
  for (const route of ROUTES) {
    test(`#${route.id} renders "${route.h1}" and logs no errors`, async ({
      page,
      consoleErrors,
      failedRequests,
    }) => {
      // KNOWN PRODUCT ISSUE, found when this suite first ran in CI (bead e2eorph, 2026-10-27): the
      // harness starts burpsy without -db, and the Settings page's LLM triage section asks
      // GET /api/settings/triage regardless, which answers 503 ("persistence is not attached") and
      // renders as an error notice. test.fail keeps the check live: it turns red when the page
      // stops making a request it knows can fail on a project-less instance, and this line goes.
      test.fail(route.id === "settings", "GET /api/settings/triage -> 503 on an instance started without -db");
      await page.goto(`/#${route.id}`);

      // The h1 assertion is the render check. Every page got one in commit 608da8e; asserting the
      // exact text also catches a route silently falling back to the default leaf, which a
      // "some h1 exists" check would pass.
      await expect(page.locator("main h1")).toHaveText(new RegExp(`^${route.h1.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));

      // The ErrorBoundary renders role="alert" with this class when a page throws during render.
      // Without this check a crashed route still has the shell's h1 above it and looks fine.
      await expect(page.locator(".crash-panel")).toHaveCount(0);

      // The hash is the routing key in both directions; a route that renders but does not own the
      // URL cannot be linked to or reloaded into.
      expect(new URL(page.url()).hash).toBe(`#${route.id}`);

      // Zero console errors, no allowlist. This one has caught real bugs in this UI.
      expect(consoleErrors).toEqual([]);

      // And nothing the page asked for came back 4xx/5xx, bar the documented CA probe. A route that
      // renders while a query it depends on is failing shows an empty state and looks fine.
      expect(failedRequests).toEqual([]);
    });
  }

  test("the command palette lists exactly the routes this suite knows about", async ({ page, consoleErrors }) => {
    // The cross-check that keeps harness/routes.ts from drifting away from src/nav.ts. The palette's
    // "Go to" group is built by flat-mapping TOOLS over their leaves, so it is the app's own opinion
    // about what is routable — a leaf added to nav.ts and not here fails this test, which is the
    // whole point of asserting against the app instead of against a second copy of the list.
    await gotoApp(page);
    await page.keyboard.press("ControlOrMeta+k");
    const search = page.getByLabel("Search commands");
    await expect(search).toBeVisible();

    // "Go to" entries are labelled either "Tool › Leaf" or just "Leaf"; matching on the group heading
    // is not possible from the flat listbox, so the count and the labels are checked instead.
    const options = page.locator("#palette-results [role=option]");
    const labels = await options.locator(".palette-item-label").allInnerTexts();

    for (const route of ROUTES) {
      const found = labels.some((label) => label.split("\n")[0]?.trim().endsWith(route.label));
      expect(found, `palette is missing a "Go to" entry for ${route.id} (${route.label})`).toBe(true);
    }

    // And nothing extra: navigation entries plus the five commands the shell defines.
    // A "Go to" entry is shaped "Tool › Leaf" for the three tools with several leaves, or is a
    // single-leaf tool's bare label. Counted by that shape, not by suffix-matching ROUTES: the palette
    // also jumps to Settings sections, and "Settings › Scanner" ends with the Scanner leaf's label.
    // Counting by shape is also what makes a leaf added to nav.ts and not to ROUTES fail here.
    const multiLeaf = /^(Target|Proxy|Extensions) › /;
    const singleLeaf = new Set(ROUTES.filter((route) => !["target", "proxy", "extender"].includes(route.tool)).map((route) => route.label));
    // "Proxy › Exchange detail" is excluded by name: it is a hidden leaf (nav.ts `hidden: true`, the
    // detached-window route) that the palette lists anyway — a known defect with its own test below.
    const navigationEntries = labels
      .map((label) => label.split("\n")[0]?.trim() ?? "")
      .filter((first) => (multiLeaf.test(first) || singleLeaf.has(first)) && first !== HIDDEN_LEAF);
    expect(navigationEntries.length, `palette "Go to" entries: ${navigationEntries.join(" | ")}`).toBe(ROUTES.length);

    expect(consoleErrors).toEqual([]);
  });

  test("a hidden nav leaf is not offered as a Go to entry", async ({ page }) => {
    // nav.ts marks the detached exchange window `hidden`; the palette used to list it anyway
    // (fixed in burpsy-react-ui-palette-hidden-leaf), so this runs as a plain assertion.
    await gotoApp(page);
    await page.keyboard.press("ControlOrMeta+k");
    await expect(page.getByLabel("Search commands")).toBeVisible();
    const labels = await page.locator("#palette-results [role=option] .palette-item-label").allInnerTexts();
    expect(labels.map((label) => label.split("\n")[0]?.trim())).not.toContain(HIDDEN_LEAF);
  });

  test("every alt+N hotkey navigates to its tool's entry leaf", async ({ page, consoleErrors }) => {
    await gotoApp(page);
    for (const route of ROUTES.filter((entry) => entry.hotkey)) {
      await page.keyboard.press(`Alt+${route.hotkey}`);
      await expect(page.locator("main h1")).toHaveText(
        new RegExp(`^${route.h1.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
        // A named message here because "expected Dashboard, got Issues" out of a loop is otherwise
        // impossible to attribute to a key.
      );
      expect(new URL(page.url()).hash, `alt+${route.hotkey} should route to #${route.id}`).toBe(`#${route.id}`);
    }
    expect(consoleErrors).toEqual([]);
  });

  test("the sub-tab row appears only for tools that own more than one view", async ({ page }) => {
    // The row is conditional, and a regression that always renders it eats a row of vertical
    // space on every route whose tool owns a single leaf.
    //
    // The expected count is DERIVED from ROUTES rather than written as a literal. It used to be a
    // hardcoded 4, which went stale the moment Proxy gained the Proxy-settings leaf: the test then
    // failed for a correct UI, which teaches the next reader to edit the number instead of looking.
    const proxyLeaves = ROUTES.filter((route) => route.tool === "proxy").length;
    expect(proxyLeaves).toBeGreaterThan(1); // otherwise this test is asserting nothing
    // Proxy owns four leaves, Repeater one. The row is conditional, and a regression that always
    // renders it eats a row of vertical space on ten of the twenty routes.
    await gotoRoute(page, ROUTES.find((route) => route.id === "history")!);
    await expect(page.locator("nav.sub-tabs")).toBeVisible();
    await expect(page.locator("nav.sub-tabs button")).toHaveCount(proxyLeaves);

    await gotoRoute(page, ROUTES.find((route) => route.id === "repeater")!);
    await expect(page.locator("nav.sub-tabs")).toHaveCount(0);
  });

  test("the skip link reaches the workspace", async ({ page }) => {
    // The first tab stop on the page must be the skip link, and it must land focus somewhere real.
    // Keyboard-only operation is the reason the shell has one at all.
    // No click first: the skip link sits at the top-left corner and is only visually hidden, so
    // clicking near the origin to "reset focus" lands ON it and the following Tab then leaves it.
    await gotoApp(page);
    await page.keyboard.press("Tab");
    await expect(page.locator("a.skip-link")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("#main-content")).toBeFocused();
  });
});
