// HTTP history's Clear (burpsy-react-ui-r6li), in a file of its own that sorts LAST.
//
// Clear empties the one exchange store the whole run shares — including the harness's seeded
// traffic (harness/server.ts SEEDED_PATHS, exchange 0, the Repeater send) that the history, macro
// recorder, Organizer and suite-search specs read. It lived in behaviour.spec.ts, which sorts second,
// so every one of those specs failed in a full run and passed on its own (found when the suite first
// ran in CI, bead e2eorph). The config runs one worker with fullyParallel off, and in that mode
// Playwright runs files in alphabetical order (its documented way to control order across files),
// hence the `zz-` prefix: nothing runs after this test, so nothing can depend on what it destroys.
// Rename it and the order-dependence comes back.

import { request as httpRequest } from "node:http";
import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/** A GET through the proxy, resolving when the response ends (agent: false, as the harness does). */
function proxyGet(proxyPort: number, url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const request = httpRequest(
      { host: "127.0.0.1", port: proxyPort, method: "GET", path: url, headers: { Host: target.host }, agent: false },
      (response) => {
        response.resume();
        response.once("end", () => resolve());
      },
    );
    request.once("error", reject);
    request.end();
  });
}

test.describe("History clear — r6li (runs last: it empties the shared store)", () => {
  test("Clear empties the table and Delete items is disabled with nothing ticked", async ({ page, consoleErrors }) => {
    const { proxyPort, targetPort } = readHarness();
    const origin = `http://127.0.0.1:${targetPort}`;
    const marker = `/r6li-clear-${Date.now()}`;
    await proxyGet(proxyPort, `${origin}${marker}`);

    await gotoRoute(page, route("history"));
    const markerRow = page.locator("tr.data-row", { hasText: marker });
    await expect(markerRow).toHaveCount(1);
    await expect(page.locator("tr.data-row")).not.toHaveCount(0);

    await expect(page.getByRole("button", { name: "Delete items", exact: true })).toBeDisabled();

    await page.getByRole("button", { name: "Clear", exact: true }).click();
    await page.getByRole("button", { name: /^Clear \d/ }).click();

    await expect(page.locator("tr.data-row")).toHaveCount(0);
    expect(consoleErrors).toEqual([]);
  });
});
