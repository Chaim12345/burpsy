import { expect } from "@playwright/test";
import { gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

// The Scope page used to be a one-line delegate to Settings' shared section, whose notice honestly
// said the UI offered host patterns only. The Go API grew port and path arms (ScopeRequest.Path /
// .Port, identity-aware remove) without the UI following, so an operator could not express Burp's
// ordinary "this host, this port, but not /admin" rule from the console at all. These tests pin the
// standalone Burp-style rule table: full tuples in, exact-tuple removal out.

test.describe("Scope page — Burp-style rule table", () => {
  test("adding a rule with port and path arms shows the full tuple", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("scope"));

    await page.getByLabel("Rule kind").selectOption("include");
    await page.getByLabel("Host pattern").fill("api.example.com");
    await page.getByLabel("Port").fill("8443");
    await page.getByLabel("Path prefix").fill("/v2");
    await page.getByRole("button", { name: "Add rule" }).click();

    const row = page.locator("tr.data-row", { hasText: "api.example.com" });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText("Include");
    await expect(row).toContainText("8443");
    await expect(row).toContainText("/v2");
    expect(consoleErrors).toEqual([]);
  });

  test("removing a scoped rule leaves its same-host sibling alone", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("scope"));

    // Scope persists across tests (the harness server is shared), so start from a clean table.
    await page.getByRole("button", { name: "Clear scope" }).click();
    await expect(page.locator("tr.data-row")).toHaveCount(0);

    // Two rules on one host differing only in path — removing by host alone would delete both,
    // which is exactly the bug the backend's identity-aware remove exists to prevent.
    for (const path of ["/v2", "/admin"]) {
      await page.getByLabel("Rule kind").selectOption("exclude");
      await page.getByLabel("Host pattern").fill("api.example.com");
      await page.getByLabel("Path prefix").fill(path);
      await page.getByRole("button", { name: "Add rule" }).click();
    }
    await expect(page.locator("tr.data-row", { hasText: "api.example.com" })).toHaveCount(2);

    await page.locator("tr.data-row", { hasText: "/v2" }).click();
    await page.getByRole("button", { name: "Remove rule" }).click();

    await expect(page.locator("tr.data-row", { hasText: "api.example.com" })).toHaveCount(1);
    await expect(page.locator("tr.data-row", { hasText: "api.example.com" })).toContainText("/admin");
    await expect(page.locator("tr.data-row", { hasText: "api.example.com" })).not.toContainText("/v2");
    expect(consoleErrors).toEqual([]);
  });
});
