import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/**
 * A request through the proxy that is deliberately not awaited: it resolves only when the test
 * forwards the held message below. Same helper as behaviour.spec.ts's and tool-tab-attention.spec.ts's
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

interface SecondOrigin {
  port: number;
  hits: () => number;
  close: () => Promise<void>;
}

/**
 * An origin for the retarget to land on, on its own loopback ADDRESS rather than another port of the
 * harness's origin.
 *
 * The address is the point. A second port on 127.0.0.1 would prove the port reached the wire and
 * leave the host field — the first thing an operator edits, and the one an egress fence is worried
 * about — unexercised, because a scope rule without a port arm covers every port of its host. The Go
 * suite's out-of-scope test makes the same choice for the same reason.
 *
 * Resolves to null when 127.0.0.2 cannot be bound, and the test skips rather than quietly falling back
 * to the harness origin: a retarget test that only ever changed a port would pass while the host field
 * did nothing, which is the shape of a vacuous test this suite has been burned by before.
 */
function startSecondOrigin(): Promise<SecondOrigin | null> {
  return new Promise((resolve) => {
    let hits = 0;
    const server = createServer((_req, res) => {
      hits += 1;
      const body = "SECOND-ORIGIN-OK";
      res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": Buffer.byteLength(body), Connection: "close" });
      res.end(body);
    });
    server.once("error", () => resolve(null));
    server.listen(0, "127.0.0.2", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        port,
        hits: () => hits,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}

// Burp's intercept header bar carries an "Edit target" pencil beside the authority label
// (BurpClass9694.java: proxyInterceptEditTargetButton, tooltip "Click to modify"): the item being held
// can be sent somewhere other than where the client asked. burpsy rendered the authority read-only and
// the forward body carried no destination at all, so the capability was absent end to end
// (burpsy-react-ui-akv).
//
// Three claims are asserted here, and each one is invisible from the others:
//
//  1. The pencil is where Burp puts it, it opens on the message being held, and the three fields it
//     refuses to accept are refused in the dialog rather than by the server after Forward.
//  2. A destination the operator set is what the request is actually sent to — proved by the response
//     body coming from a second origin the client never named.
//  3. The page says the message is retargeted before the operator presses Forward, because a
//     destination that changes where bytes go and looks exactly like the ordinary case is the one
//     thing this control must not be.
test.describe("Intercept — a held request's target", () => {
  test("sends the request to the destination the operator typed, and says so first", async ({
    page,
    consoleErrors,
  }) => {
    // Interception is global to the one shared burpsy process, so it is put back the way it was found
    // in `finally` however this test ends: left on, every later test's traffic would hang behind a
    // held message nobody forwards.
    await page.request.post("/api/intercept/enable", { data: { enabled: true } });
    // The master switch alone holds nothing — the request list has to be active as well
    // (internal/intercept/intercept.go), and an active list with no rules is Burp's "intercept
    // everything".
    await page.request.put("/api/intercept/rules/requests", { data: { active: true, rules: [] } });

    const second = await startSecondOrigin();
    test.skip(
      second === null,
      "127.0.0.2 cannot be bound here, so the host axis of a retarget could not be exercised",
    );
    if (second === null) throw new Error("unreachable");

    const { proxyPort, targetPort } = readHarness();
    const origin = `http://127.0.0.1:${targetPort}`;

    let inFlight: Promise<string> | null = null;
    try {
      await gotoRoute(page, route("intercept"));
      inFlight = proxyGet(proxyPort, `${origin}/retarget-me`);

      const row = page.locator("tr.data-row", { hasText: "/retarget-me" });
      await expect(row).toBeVisible();
      await row.click();

      // The authority the client asked for, as the header bar names it, and the pencil that changes it.
      await expect(page.locator(".detail-head-title strong")).toContainText(`127.0.0.1:${targetPort}`);
      await page.getByRole("button", { name: "Edit target" }).click();

      // A destination the socket cannot take is refused in the dialog, with the reason, and the
      // dialog's own button is disabled while it is refused. Asserted here rather than only in the
      // unit tests because this is the boundary the engine also refuses at, and two layers disagreeing
      // about what a usable destination is is exactly the trap the wire's total-replacement contract
      // exists to avoid.
      await page.getByLabel("Port", { exact: true }).fill("0");
      await expect(page.getByText(/whole number in 1\.\.65535/)).toBeVisible();
      await expect(page.getByRole("button", { name: "Use this destination" })).toBeDisabled();

      await page.getByLabel("Host", { exact: true }).fill("127.0.0.2");
      await page.getByLabel("Port", { exact: true }).fill(String(second.port));
      await expect(page.getByRole("button", { name: "Use this destination" })).toBeEnabled();

      // Before Forward, and while the message is still held: the header bar names the edited
      // destination and the page marks it as an edit rather than leaving the two indistinguishable.
      await page.getByRole("button", { name: "Use this destination" }).click();
      await expect(page.locator(".detail-head-title strong")).toContainText(`127.0.0.2:${second.port}`);
      await expect(page.locator(".detail-head-title").getByText("retargeted")).toBeVisible();

      // exact: the toolbar also offers "Forward all (n)", and role-name matching is
      // substring-by-default, so an unqualified name resolves to two buttons.
      await page.getByRole("button", { name: "Forward", exact: true }).click();
      const body = await inFlight;
      inFlight = null;
      expect(body).toContain("SECOND-ORIGIN-OK");
      // And it did not also go where the client asked. A proxy that retargeted AND sent it on the
      // original path would satisfy the assertion above on its own.
      expect(second.hits()).toBe(1);
    } finally {
      await page.request.post("/api/intercept/enable", { data: { enabled: false } });
      await page.request.put("/api/intercept/rules/requests", { data: { active: false, rules: [] } });
      await page.request.post("/api/intercept/drop-all", { data: {} }).catch(() => null);
      if (inFlight) await inFlight.catch(() => null);
      await second?.close();
    }

    expect(consoleErrors).toEqual([]);
  });
});
