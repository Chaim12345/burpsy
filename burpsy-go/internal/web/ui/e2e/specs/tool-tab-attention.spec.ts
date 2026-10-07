import { request as httpRequest } from "node:http";
import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/**
 * The one request this spec parks in the intercept queue, sent through the proxy and deliberately
 * not awaited: it resolves only when the test forwards it below. Same shape as behaviour.spec.ts's
 * held-request helper, which is what this is copied from — there is no API that holds a message
 * without a real request behind it, and inventing one to test an indicator about real held traffic
 * would be testing the fixture.
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

// Burp's ToolTabFlasher contract (spec 1.1, 4.1-4.12): every tool module can signal attention on its
// tab, and the shell renders it. burpsy had no such signal at all, so with interception holding a
// request the operator's browser simply hung and nothing outside Proxy ▸ Intercept said why
// (burpsy-react-ui-xvo).
//
// The assertion that matters is the one about *where* the operator is looking: the count is read
// while the Dashboard is on screen, not the intercept page. An indicator that only rendered on its
// own tool's page would satisfy every unit test of the rule and none of the operator's problem.
test.describe("tool tab attention", () => {
  test("the Proxy tab shows how many requests interception is holding, from another tool", async ({
    page,
    consoleErrors,
  }) => {
    const { proxyPort, targetPort } = readHarness();
    const origin = `http://127.0.0.1:${targetPort}`;

    // Interception is global to the one shared burpsy process, so it is turned back off in
    // `finally` however this test ends — leaving it on would hang every later test's traffic behind
    // a held message nobody forwards.
    await page.request.post("/api/intercept/enable", { data: { enabled: true } });
    // The master switch alone holds nothing: the request list has to be active as well
    // (internal/intercept/intercept.go), and an active list with no rules is the unconditional
    // "hold everything inbound" state.
    await page.request.put("/api/intercept/rules/requests", { data: { active: true, rules: [] } });

    let inFlight: Promise<string> | null = null;
    try {
      await gotoRoute(page, route("dashboard"));
      const proxyTab = page.locator(".tool-tab").filter({ hasText: "Proxy" });
      // Nothing is held yet, so the tab carries no badge — the control for the assertion below,
      // without which "the badge appeared" could be a badge that is always there.
      await expect(proxyTab.locator(".tool-tab-attention")).toHaveCount(0);

      inFlight = proxyGet(proxyPort, `${origin}/held-for-attention`);

      // Read on the Dashboard, with the Proxy page never opened — that is the whole point.
      await expect(proxyTab.locator(".tool-tab-attention")).toHaveText("1");

      // The visible count is not the accessible statement. "1" beside a tab name says nothing about
      // one of what, so the sentence the tab exposes is asserted too: this is the difference between
      // a number and an indicator.
      await expect(proxyTab).toHaveAccessibleName(/1 held request — .*Intercept/);

      // Release it, and the tab stops asking for attention. The held request is selected first:
      // the toolbar's Forward acts on the selection, so clicking it before picking a row would be
      // clicking a control that is not there yet.
      await gotoRoute(page, route("intercept"));
      const row = page.locator("tr.data-row", { hasText: "/held-for-attention" });
      await expect(row).toBeVisible();
      await row.click();
      // exact: the toolbar also offers "Forward all (n)", and role-name matching is
      // substring-by-default, so the unqualified name resolves to two buttons.
      await page.getByRole("button", { name: "Forward", exact: true }).click();
      const body = await inFlight;
      inFlight = null;
      expect(body).toContain("ORIGIN-OK GET /held-for-attention");

      await expect(proxyTab.locator(".tool-tab-attention")).toHaveCount(0);
    } finally {
      await page.request.post("/api/intercept/enable", { data: { enabled: false } });
      await page.request.put("/api/intercept/rules/requests", { data: { active: false, rules: [] } });
      await page.request.post("/api/intercept/drop-all", { data: {} }).catch(() => null);
      // A request still parked in the proxy would keep its socket open into teardown.
      if (inFlight) await inFlight.catch(() => null);
    }

    expect(consoleErrors).toEqual([]);
  });
});
