// Burp's "Paste host / URL as request" (burpsy-react-ui-ce8), driven end to end.
//
// The second test is the one worth having. requestFromUrl used to pass the pasted scheme straight
// into `target`, so a ws:// or ftp:// paste produced a Repeater tab that looked fine and answered
// 400 "unknown scheme" on the first Send — targetParts knows http, https and nothing else. Refusing
// at the paste, where the operator can still see what they pasted, is the whole difference.

import type { Page } from "@playwright/test";
import { expect, gotoApp, test } from "../harness/fixtures";

// The prompt is the console's own themed dialog (lib/dialogs.ts, bea3), not window.prompt, so it is
// driven like any other dialog: the field, then Enter.
async function pasteUrl(page: Page, value: string): Promise<void> {
  await page.getByRole("button", { name: "Repeater", exact: true }).first().click();
  await page.getByRole("menuitem", { name: "Paste host / URL as request" }).click();
  const dialog = page.getByRole("dialog", { name: "Paste host or URL as request" });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Host or URL").fill(value);
  await dialog.getByLabel("Host or URL").press("Enter");
  await expect(dialog).toBeHidden();
}

test("Paste host / URL as request builds a working Repeater tab", async ({ page }) => {
  await gotoApp(page);
  await pasteUrl(page, "http://shop.test:8080/catalog?id=1");
  await expect(page.getByRole("heading", { level: 1, name: "Repeater" })).toBeVisible();
  await expect(page.locator(".cm-content").first()).toContainText("GET /catalog?id=1 HTTP/1.1");
  await expect(page.locator(".cm-content").first()).toContainText("Host: shop.test:8080");
  // The target field is what the send is dialled against; a ws:// or ftp:// value here is a 400.
  await expect(page.locator('input[value="http://shop.test:8080"]').first()).toBeVisible();
});

test("a scheme burpsy cannot send is refused instead of opening a broken tab", async ({ page }) => {
  await gotoApp(page);
  await pasteUrl(page, "ftp://files.test/pub");
  await expect(page.getByText(/Not a host or URL burpsy can send to/)).toBeVisible();
});
