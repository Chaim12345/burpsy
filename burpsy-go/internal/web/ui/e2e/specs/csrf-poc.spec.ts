import { request as httpRequest } from "node:http";
import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/**
 * A POST with a JSON body through the proxy — the request shape the technique selector exists
 * for. The harness origin answers every method, so the exchange is real captured traffic, not a
 * fixture.
 */
function proxyPostJSON(proxyPort: number, url: string, json: string): Promise<void> {
 return new Promise((resolve, reject) => {
  const target = new URL(url);
  const request = httpRequest(
   {
    host: "127.0.0.1",
    port: proxyPort,
    method: "POST",
    path: url,
    headers: { Host: target.host, "Content-Type": "application/json", "Content-Length": String(json.length) },
    agent: false,
   },
   (response) => {
    response.resume();
    response.once("end", () => resolve());
   },
  );
  request.once("error", reject);
  request.end(json);
 });
}

/**
 * Burp's CSRF PoC generator offers a technique choice, and its docs are explicit that JSON bodies
 * "can only be generated using either a form with plain text encoding, or a cross-domain XHR"
 * (generate-csrf-poc.html). This drives the real dialog: a JSON body with no equals character
 * takes auto to the XHR, auto-submit is a toggle, and "Test in browser" opens the PoC on the PoC
 * host's own port — never the console's origin, which is the security property the whole dialog
 * exists to hold.
 */
test.describe("History — Generate CSRF PoC", () => {
 // The exchange context menu is long, and the generator sits near its end: at
 // the default 720px viewport a right-click on the first row opens it past
 // the bottom edge, where no click can reach. A taller viewport is the honest
 // fix — the menu is a real menu, not an overlay to be scrolled.
 test.use({ viewport: { width: 1280, height: 1400 } });

 test("a JSON exchange gives a cross-domain XHR PoC, auto-submit toggles, and Test in browser is off the console origin", async ({
  page,
  consoleErrors,
 }) => {
  const { proxyPort, targetPort, webPort } = readHarness();
  await proxyPostJSON(proxyPort, `http://127.0.0.1:${targetPort}/csrf-poc-json`, '{"user": "admin"}');

  await gotoRoute(page, route("history"));
  const row = page.locator("tr.data-row", { hasText: "/csrf-poc-json" }).first();
  await expect(row).toBeVisible();
  await row.click({ button: "right" });
  // "Engagement tools" is the section heading, not a submenu: the generator
  // sits in it directly, the way Burp nests it under a heading.
  await page.getByRole("menuitem", { name: "Generate CSRF PoC" }).click();

  // The dialog opens with auto's choice for a no-equals JSON body: the XHR.
  const dialog = page.locator(".dialog-content");
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("Generated HTML — xhr technique");
  await expect(dialog).toContainText("xhr.open('POST'");
  await expect(dialog).toContainText("xhr.withCredentials = true");
  await expect(dialog).toContainText("requires CORS");

  // Auto-submit off: the PoC keeps the request but fires nothing on load.
  await dialog.getByRole("checkbox", { name: /auto-submit/ }).uncheck();
  await dialog.getByRole("button", { name: "Regenerate" }).click();
  await expect(dialog).toContainText("xhr.send(");
  await expect(dialog).not.toContainText("    send();");

  // Test in browser opens the PoC host's one-shot URL: its own port, a /poc/
  // path, and the generated page inside.
  const [popup] = await Promise.all([page.waitForEvent("popup"), dialog.getByRole("button", { name: "Test in browser" }).click()]);
  const popupURL = new URL(popup.url());
  expect(popupURL.port, "the PoC must be served from a port that is not the console's").not.toBe(String(webPort));
  expect(popupURL.pathname.startsWith("/poc/"), "the PoC path is the PoC host's own").toBe(true);
  // The served page is the generated XHR PoC — asserted on its script, not on
  // the HTML comment, because the comment is invisible to a text locator.
  const served = await popup.content();
  expect(served).toContain("xhr.open('POST'");
  expect(served).toContain("Send request");

  // The PoC host token was spent by that one fetch: the operator's reload of
  // the popup reads as gone, not as a replayable attack page.
  const spent = await popup.request.get(popup.url());
  expect(spent.status()).toBe(410);

  expect(consoleErrors).toEqual([]);
 });
});
