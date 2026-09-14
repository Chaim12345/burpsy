// Screenshots of every route, at both viewports, in both themes. No count in this comment, on purpose:
// the two stale ones it used to carry (18 × 2 × 2 = 72, then 20 × 2 × 2 = 80) were both left behind as
// routes were added, and the list they counted is harness/routes.ts. A number here is a claim nobody
// re-derives; the spec's own summary line reports the real one when it runs.
//
// Why this exists rather than a note saying the design was reviewed: docs/ui-map/07-design-analysis.md
// reports measurements taken out-of-tree that cannot be reproduced from this repository, and it
// measures the LIGHT theme while saying dark "was audited separately" — an artifact nobody has been
// able to find. Dark is the shipped default, so on the evidence in the tree the default theme has
// never been measured. This spec is what makes that reproducible: `./e2e-ui.sh` and the images are
// under e2e/artifacts/screenshots/, gitignored, regenerated on demand.
//
// These are artifacts, not baselines. There is no toHaveScreenshot comparison, because a committed
// pixel baseline for a UI under active design work fails on every intended change and teaches people
// to update baselines without looking — which is worse than no check. The assertions here are the
// ones a screenshot can honestly support: it rendered, it is not blank, and the two themes genuinely
// differ at this viewport.

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { expect, gotoRoute, pinTheme, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const VIEWPORTS = [
  { name: "1440x900", width: 1440, height: 900 },
  // The narrow pass is not decoration: the shell hides its menu bar below a breakpoint and the
  // command palette is the only route to those actions, so this width exercises a different UI.
  { name: "390x844", width: 390, height: 844 },
] as const;

const OUT = join(import.meta.dirname, "..", "artifacts", "screenshots");

test.beforeAll(() => {
  mkdirSync(OUT, { recursive: true });
});

for (const viewport of VIEWPORTS) {
  for (const theme of ["dark", "light"] as const) {
    test.describe(`${viewport.name} ${theme}`, () => {
      for (const route of ROUTES) {
        test(`#${route.id}`, async ({ page }) => {
          await page.setViewportSize({ width: viewport.width, height: viewport.height });
          await pinTheme(page, theme);
          await gotoRoute(page, route);

          // NOT waitForLoadState("networkidle"): the shell opens an EventSource on /api/events and
          // holds it for the life of the page, so the network is never idle and every screenshot test
          // would burn its full timeout before firing. Wait for the thing that actually means "the
          // first render is settled" instead — the status bar showing a real byte count rather than
          // the em-dash placeholder it starts with, which only happens once /api/stats has resolved.
          await expect(page.locator(".statusbar")).not.toContainText("— stored");

          const shot = await page.screenshot({
            path: join(OUT, `${viewport.name}-${theme}-${route.id}.png`),
            fullPage: false,
          });

          // A blank or near-blank PNG compresses to almost nothing. This is the floor below which the
          // screenshot proves nothing, and it has to be checked or an all-white page would "pass".
          expect(shot.byteLength, `#${route.id} rendered a suspiciously small image`).toBeGreaterThan(9_000);
        });
      }
    });
  }

  test(`${viewport.name}: the two themes are visibly different`, async ({ page }) => {
    // The check the screenshots themselves cannot make. Capturing 68 images proves nothing about
    // theming if both halves look the same, and at 390px the theme is applied by the same variables
    // the desktop layout uses — so a media query that scoped a colour to a breakpoint would show here.
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    // pinTheme installs an init script, which only runs on a document load — so each sample needs a
    // real navigation. Both samples go to the same hash, so same-URL optimisation can skip the load
    // event on the second call. Passing through about:blank between samples ensures the app URL
    // always arrives as a fresh load with all accumulated init scripts running in order.
    const sample = async (theme: "dark" | "light") => {
      await pinTheme(page, theme);
      await page.goto("about:blank");
      await page.goto(`/#${ROUTES[0]!.id}`);
      await expect(page.locator("main h1")).toBeVisible();
      return page.evaluate(() => {
        const style = getComputedStyle(document.body);
        return `${style.backgroundColor}|${style.color}`;
      });
    };
    const dark = await sample("dark");
    const light = await sample("light");
    expect(light).not.toBe(dark);
  });
}
