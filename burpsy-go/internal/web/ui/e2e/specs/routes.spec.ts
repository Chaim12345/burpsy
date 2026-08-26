// Every route renders, names itself, and logs nothing.
//
// One test per route rather than one loop inside one test, so a failure names the route in its title
// and the other nineteen still report. A single "all routes" test that fails tells you the console is
// broken somewhere.

import { expect, gotoApp, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

test.describe("routes", () => {
  for (const route of ROUTES) {
    test(`#${route.id} renders "${route.h1}" and logs no errors`, async ({
      page,
      consoleErrors,
      failedRequests,
    }) => {
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
    const navigationEntries = labels.filter((label) =>
      ROUTES.some((route) => label.split("\n")[0]?.trim().endsWith(route.label)),
    );
    expect(navigationEntries.length).toBe(ROUTES.length);

    expect(consoleErrors).toEqual([]);
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
