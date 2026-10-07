// burpsy-react-ui-i3l: Organizer could only jump a saved item back to HTTP history to read its
// bytes — pages/organizer.tsx used to hold only a title/highlight/note editor and an
// `openInHistory` escape hatch (the removed comment read "Reveal the underlying exchange in HTTP
// history rather than copying its bytes here"). Burp's own docs describe reading the request and
// response in place as the point of Organizer ("Select a message to inspect its request and
// response in the lower pane"), so this drives a real save-then-select through the real backend
// and asserts the actual bytes appear on the Organizer page itself — proving the pane is wired to
// the traffic store, not a static placeholder that merely occupies the layout.

import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

test.describe("Organizer request/response pane — burpsy-react-ui-i3l", () => {
  test("selecting a saved item shows its real request and response bytes on the page, not just a link back to history", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("organizer"));

    // Exchange 0 is the harness's first seeded request, GET /zebra (see harness/server.ts's seed()).
    // A dense zero-based id, and organizer.tsx's own add() guard (`exchange < 0`, not `<= 0`) exists
    // specifically because exchange 0 is a real exchange, not an empty id.
    await page.getByLabel("Exchange id to save").fill("0");
    await page.getByRole("button", { name: "Save exchange" }).click();
    await expect(page.getByText(/^Saved exchange #0$/)).toBeVisible();

    // The row for the item just saved; select it to open the detail pane.
    await page.getByRole("row", { name: /#0/ }).first().click();

    // Request tab is the default. Real bytes, not "No request bytes captured." or an empty editor.
    const requestPane = page.locator(".editor-combined").getByRole("tabpanel", { name: "Request" });
    await expect(requestPane).toContainText("/zebra");
    await expect(requestPane).not.toContainText("No request bytes captured");

    // Switch to Response and check it too — proving both legs of the pane are live, not just one.
    await page.getByRole("tab", { name: "Response" }).click();
    const responsePane = page.locator(".editor-combined").getByRole("tabpanel", { name: "Response" });
    await expect(responsePane).toContainText("HTTP/1.");
    await expect(responsePane).not.toContainText("No response was captured");

    expect(consoleErrors).toEqual([]);
  });
});
