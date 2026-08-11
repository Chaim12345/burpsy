// axe-core against every route, in both themes.
//
// The point of wiring this into the gate is that accessibility work does not stay done. This tree has
// just had ~47 unlabelled form controls fixed at the primitive level; without a check that runs on
// every verify.sh, the forty-eighth arrives unnoticed.
//
// The assertion is zero violations, and the expected first state of this file is RED. That is
// deliberate. Weakening it to a threshold ("no more than 12 violations") would make the number the
// contract instead of the behaviour, and thresholds only ever go up. If a rule genuinely cannot be
// satisfied, add it to ALLOWED_RULES below with a reason — a named exception is reviewable, a number
// is not.

import AxeBuilder from "@axe-core/playwright";
import { expect, gotoApp, gotoRoute, pinTheme, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

/**
 * Rules excluded from the assertion, each with the reason it is excluded. Empty is the goal.
 *
 * Rules listed here are still RUN and still reported in the per-route summary printed to stdout, so
 * an exception cannot hide a growing count — it only stops that one rule failing the gate.
 */
const ALLOWED_RULES: Record<string, string> = {
  // Nothing is excluded. Entries are expected to look like:
  //   "color-contrast": "the orange accent is the product's identity; tracked in <ticket>",
};

const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

function summarise(violations: { id: string; impact?: string | null; nodes: unknown[] }[]): string {
  if (violations.length === 0) return "0 violations";
  return violations
    .map((violation) => `${violation.id}(${violation.impact ?? "?"})×${violation.nodes.length}`)
    .join(" ");
}

for (const theme of ["dark", "light"] as const) {
  test.describe(`axe — ${theme} theme`, () => {
    for (const route of ROUTES) {
      test(`#${route.id}`, async ({ page }, testInfo) => {
        await pinTheme(page, theme);
        await gotoRoute(page, route);

        const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

        // Printed unconditionally, pass or fail. The count before any exclusion is the number worth
        // reading in the log, and it is the only place a rule in ALLOWED_RULES is still visible.
        const line = `axe ${theme} #${route.id}: ${summarise(results.violations)}`;
        testInfo.annotations.push({ type: "axe", description: line });
        process.stdout.write(`  ${line}\n`);

        const blocking = results.violations.filter((violation) => !(violation.id in ALLOWED_RULES));
        const detail = blocking
          .map(
            (violation) =>
              `${violation.id} (${violation.impact}): ${violation.help}\n` +
              violation.nodes
                .slice(0, 4)
                .map((node) => `      ${node.target.join(" ")}`)
                .join("\n"),
          )
          .join("\n    ");

        expect(blocking, `#${route.id} (${theme}):\n    ${detail}`).toEqual([]);
      });
    }
  });
}

test.describe("axe — transient surfaces", () => {
  // Dialogs are where accessibility bugs hide, because they are not on screen when a route is scanned.
  // Both of these are reachable by keyboard only, which is the case that matters most.
  test("the command palette", async ({ page }) => {
    await pinTheme(page, "dark");
    await gotoApp(page);
    await page.keyboard.press("ControlOrMeta+k");
    await expect(page.getByLabel("Search commands")).toBeVisible();

    const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
    process.stdout.write(`  axe dark palette: ${summarise(results.violations)}\n`);
    expect(results.violations.filter((violation) => !(violation.id in ALLOWED_RULES))).toEqual([]);
  });

  test("the shortcut sheet", async ({ page }) => {
    await pinTheme(page, "dark");
    await gotoApp(page);
    // The app binds this with useHotkeys("shift+slash", ...) — the physical chord, not the character
    // it produces. press("?") sends the "?" character, which react-hotkeys-hook's key matcher never
    // sees as shift+slash, so the sheet never opened and every route in this describe block failed on
    // a missing .dialog-title. press("Shift+Slash") sends the actual chord the binding listens for.
    await page.keyboard.press("Shift+Slash");
    await expect(page.locator(".dialog-title")).toHaveText("Keyboard shortcuts");

    const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
    process.stdout.write(`  axe dark shortcuts: ${summarise(results.violations)}\n`);
    expect(results.violations.filter((violation) => !(violation.id in ALLOWED_RULES))).toEqual([]);
  });
});
