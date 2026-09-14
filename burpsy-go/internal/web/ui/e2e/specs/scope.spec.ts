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

// Burp's Paste URL, and Load from file filling the same box (dao). The claim is Burp's: a pasted URL
// is decomposed into the arms the form has, so a scope list handed to the operator stops being one
// manual entry per host.
//
// The refusals are asserted as carefully as the additions, and that is the point of the preview: a
// line that never becomes a rule is the failure nobody sees afterwards — the scan then touches
// something the operator did not authorise, or skips something they did, and the table looks fine.
// A test that only counted the added rows would pass with the bad line silently dropped.
test.describe("Scope page — Paste URL", () => {
  /**
   * Start from an empty table, whatever the previous spec left.
   *
   * Not a plain click: the button is disabled when the table is already empty, and a spec that only
   * passes when some earlier spec left rules behind is a spec that fails when run on its own — which
   * is how a suite teaches people to run it in pieces. The clear is guarded and the empty table is
   * asserted either way, so the precondition is stated rather than hoped for.
   */
  const emptyScope = async (page: import("@playwright/test").Page) => {
    const clear = page.getByRole("button", { name: "Clear scope" });
    if (await clear.isEnabled()) await clear.click();
    await expect(page.locator("tr.data-row")).toHaveCount(0);
  };

  test("pasted URLs become rules, and the unreadable line is named before anything is written", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("scope"));
    // Scope persists across tests (the harness server is shared), so start from a clean table — and
    // clear again at the end so this file's rules cannot narrow a later spec's scope.
    await emptyScope(page);

    await page.getByRole("button", { name: "Paste URL" }).click();
    await page
      .getByLabel(/Entries to add/)
      .fill("# acme engagement\nhttps://api.example.com:8443/v2\n*.example.com\nexample.com/api");

    // The preview says what will happen before it happens: two rules, one line refused by number.
    await expect(page.getByText("2 rules to add")).toBeVisible();
    await expect(page.getByText("1 unreadable")).toBeVisible();
    await expect(page.getByText(/Line 4: example.com\/api/)).toBeVisible();
    await expect(page.getByText(/no scheme/)).toBeVisible();

    await page.getByRole("button", { name: "Add 2 rules" }).click();

    // The arms are the form's arms, not a rule named after a URL: the port and the path prefix are
    // columns of their own, and the protocol arm is carried too.
    const scoped = page.locator("tr.data-row", { hasText: "api.example.com" });
    await expect(scoped).toHaveCount(1);
    await expect(scoped).toContainText("8443");
    await expect(scoped).toContainText("/v2");
    await expect(scoped).toContainText("https");
    await expect(page.locator("tr.data-row", { hasText: "*.example.com" })).toHaveCount(1);
    await expect(page.locator("tr.data-row")).toHaveCount(2);
    expect(consoleErrors).toEqual([]);

    await page.getByRole("button", { name: "Clear scope" }).click();
  });

  /**
   * Load from file is the same box, filled from disk — which is the whole reason there is no second
   * format to agree on, and the half of Burp's pair the paste-only implementation would have
   * declined without saying so. The file here carries a comment and two entries, because a real
   * scope list pasted out of an engagement brief does.
   */
  test("Load from file fills the paste box rather than adding a second format", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("scope"));
    await emptyScope(page);

    await page.getByRole("button", { name: "Paste URL" }).click();
    // Scoped to the dialog: the shell has a file input of its own (config import), and an
    // unscoped selector picks whichever one the DOM happens to put first.
    await page
      .getByRole("dialog", { name: "Paste URLs" })
      .locator('input[type="file"]')
      .setInputFiles({
        name: "scope.txt",
        mimeType: "text/plain",
        buffer: Buffer.from("# acme brief\nhttps://from-file.test:9443/api\nfrom-file.test\n"),
      });

    // The box holds the file, character for character — trailing newline included, because the file
    // is the operator's text and reformatting it would be the UI deciding what a line is twice. They
    // review and edit what will be added instead of a file being applied behind their back.
    await expect(page.getByLabel(/Entries to add/)).toHaveValue(
      "# acme brief\nhttps://from-file.test:9443/api\nfrom-file.test\n",
    );
    await expect(page.getByText("2 rules to add")).toBeVisible();

    await page.getByRole("button", { name: "Add 2 rules" }).click();
    // Two rules, because the file held two entries: the URL's arms and the bare host's. Asserted on
    // the port and path columns rather than on one row's text, since both rows name this host.
    await expect(page.locator("tr.data-row")).toHaveCount(2);
    const fromFile = page.locator("tr.data-row", { hasText: "9443" });
    await expect(fromFile).toHaveCount(1);
    await expect(fromFile).toContainText("/api");
    expect(consoleErrors).toEqual([]);

    await emptyScope(page);
  });

  test("re-pasting a list already in scope adds nothing and says so", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("scope"));
    await emptyScope(page);

    const box = () => page.getByLabel(/Entries to add/);
    await page.getByRole("button", { name: "Paste URL" }).click();
    await box().fill("https://a.test:9443/x");
    await page.getByRole("button", { name: "Add 1 rule" }).click();
    await expect(page.locator("tr.data-row")).toHaveCount(1);

    // The same entry again: an operator re-pasting a list they already added must not end up with
    // every host twice, and the duplicate is reported rather than silently skipped.
    await page.getByRole("button", { name: "Paste URL" }).click();
    await box().fill("https://a.test:9443/x");
    await expect(page.getByText("1 already in scope")).toBeVisible();
    await expect(page.getByText("0 rules to add")).toBeVisible();
    // And there is nothing to press: the Add button is off rather than adding a duplicate.
    await expect(page.getByRole("button", { name: /^Add 0 rules$/ })).toBeDisabled();
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.locator("tr.data-row")).toHaveCount(1);
    expect(consoleErrors).toEqual([]);

    await emptyScope(page);
  });
});
