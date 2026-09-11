// burpsy-react-ui-luu3: Burp's message-editor docs — "To view the code point for a character,
// select a character ... An entry will appear in the Inspector that indicates the decimal and hex
// code points ... In editable contexts ... you can edit this value to overwrite the selected
// character." burpsy's Inspector Selection section applied codecs to a whole value but never
// showed a single character's code point at all, so there was no way to type a non-printing byte.
//
// Driven through Repeater's editable request Inspector (not touched as a source file — only
// exercised here) because it is the one Inspector instance whose edits round-trip back into real
// bytes the operator could send. The test selects one visible character, edits its decimal code
// point, and checks two things: the Selection field's text actually changed, and Applying it wrote
// the new byte back into the request the Inspector's own attributes row reads from — proving the
// control is wired to the message, not a local widget that stops at its own state.

import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

test.describe("Inspector code point — burpsy-react-ui-luu3", () => {
  test("editing a selected character's decimal code point overwrites it, and Apply writes it back into the request", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("repeater"));

    // A fresh tab whose request is the template `GET / HTTP/1.1` against example.com — a real
    // Host header to decode, not a placeholder string.
    await page.getByRole("button", { name: "New request" }).click();

    // The Host row lives in "Request attributes", open by default (rows > 0, auto-expand) — and
    // also, separately, in "Request headers" below it, so the Decode button is scoped to the
    // attributes section specifically rather than matching both.
    await page.locator("#inspector-attributes-rows").getByRole("button", { name: "Decode Host" }).click();

    const selectionField = page.getByRole("textbox", { name: "Selection text" });
    await expect(selectionField).toHaveValue("example.com");

    // Select exactly the first character ("e"): click to place the caret at the very start, then
    // extend the selection by one with the keyboard — a real user gesture, not a synthetic range.
    await selectionField.click();
    await page.keyboard.press("Home");
    await page.keyboard.press("Shift+ArrowRight");

    const decimalField = page.getByRole("textbox", { name: "Selected character's code point, decimal" });
    const hexField = page.getByRole("textbox", { name: "Selected character's code point, hex" });
    // 'e' is U+0065: decimal 101, hex 65.
    await expect(decimalField).toHaveValue("101");
    await expect(hexField).toHaveValue("65");

    // Overwrite it with 'X' (U+0058, decimal 88) by editing the decimal field.
    await decimalField.fill("88");
    await decimalField.press("Enter");

    await expect(selectionField).toHaveValue("Xxample.com");
    // The hex field mirrors the same commit, proving both fields track one underlying code point
    // rather than the hex box being decorative.
    await expect(hexField).toHaveValue("58");

    // Apply writes the edited value back into the Host header the Inspector parsed it from. The
    // attributes row for an editable message renders its value as an <input>, not text, so the
    // written-back value is read with toHaveValue rather than toContainText.
    await page.getByRole("button", { name: "Apply", exact: true }).click();
    await expect(page.locator("#inspector-attributes-rows").getByRole("button", { name: "Decode Host" })).toBeVisible();
    const hostValue = page
      .locator("#inspector-attributes-rows dl.inspector-rows > div", { hasText: "Host" })
      .locator("dd input");
    await expect(hostValue).toHaveValue("Xxample.com");

    expect(consoleErrors).toEqual([]);
  });
});
