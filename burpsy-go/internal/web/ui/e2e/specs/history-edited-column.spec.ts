import { request as httpRequest } from "node:http";
import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/**
 * A request through the proxy that is deliberately not awaited: it resolves only when the test
 * forwards the held message below. Same helper as behaviour.spec.ts's and intercept-retarget.spec.ts's
 * — there is no API that parks a message in the queue without a real request behind it, and inventing
 * one to test what Forward does with it would be testing the fixture.
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

// Burp's HTTP history has an "Edited" column: "Flag whether the request or response were modified by
// the user" (tools/proxy/http-history/index.html). burpsy-react-ui-c05 retained the original and
// auto-modified message stages so the difference could be *shown* at all; burpsy-react-ui-n10e is the
// column that reads it.
//
// The column shipped with c05 and then had no test of its own — the Go side computes the flag and the
// table renders it, but nothing had ever driven an edit through the proxy and looked at the row. That
// is the gap this closes, and it is the reason the assertions below are phrased against a *pair* of
// rows: a column that rendered a badge on every row would satisfy "the edited row is marked", so the
// untouched seeded row is asserted to be unmarked in the same breath.
test.describe("History — the Edited column", () => {
  test("a request the operator edited in Intercept is flagged, and untouching traffic is not", async ({
    page,
    consoleErrors,
  }) => {
    // Interception is global to the one shared burpsy process, so it is put back the way it was found
    // in `finally` however this test ends: left on, every later test's traffic would hang behind a
    // held message nobody forwards.
    await page.request.post("/api/intercept/enable", { data: { enabled: true } });
    // The master switch alone holds nothing — the request list has to be active as well, and an
    // active list with no rules is Burp's "intercept everything".
    await page.request.put("/api/intercept/rules/requests", { data: { active: true, rules: [] } });

    const { proxyPort, targetPort } = readHarness();
    const origin = `http://127.0.0.1:${targetPort}`;

    let inFlight: Promise<string> | null = null;
    try {
      await gotoRoute(page, route("intercept"));
      inFlight = proxyGet(proxyPort, `${origin}/before-the-edit`);

      const held = page.locator("tr.data-row", { hasText: "/before-the-edit" });
      await expect(held).toBeVisible();
      await held.click();

      // Edit through the Inspector rather than the raw pane, because the Inspector writes into the
      // same buffer Forward sends — the claim being tested is about a *message* edit, and a raw-pane
      // keystroke would not prove the Inspector path stores a stage.
      const inspector = page.locator(".inspector");
      await inspector.getByLabel("Request attributes value for Target").fill("/intercept-edited");
      await inspector.getByRole("button", { name: "Apply" }).click();

      await page.getByRole("button", { name: "Forward", exact: true }).click();
      const body = await inFlight;
      inFlight = null;
      // The origin echoes the target it was asked for, so this is the target's answer rather than the
      // console's: an edit that only reached the page would leave this reading /before-the-edit.
      expect(body).toContain("ORIGIN-OK GET /intercept-edited");
    } finally {
      await page.request.post("/api/intercept/enable", { data: { enabled: false } });
      await page.request.put("/api/intercept/rules/requests", { data: { active: false, rules: [] } });
      await page.request.post("/api/intercept/drop-all", { data: {} }).catch(() => null);
      if (inFlight) await inFlight.catch(() => null);
    }

    await gotoRoute(page, route("history"));

    // The exchange is recorded under the path that actually went out, and it carries the badge.
    const editedRow = page.locator("tr.data-row", { hasText: "/intercept-edited" });
    await expect(editedRow).toHaveCount(1);
    await expect(editedRow.getByText("edited", { exact: true })).toBeVisible();

    // And a row nobody touched shows the empty marker instead. This is the half that fails if the
    // flag is hard-coded true, which is the shape a column like this degenerates into.
    const seeded = page.locator("tr.data-row", { hasText: "/zebra" }).first();
    await expect(seeded).toBeVisible();
    await expect(seeded.getByText("edited", { exact: true })).toHaveCount(0);

    // The column is present and readable by name, not only by badge: the header is what tells an
    // operator what the badge column means at all.
    await expect(page.getByRole("columnheader", { name: "Edited" })).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });
});
