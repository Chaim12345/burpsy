// burpsy-react-ui-p836: burpsy's settings/ui/message-editor.html analogue never existed — the
// message editor rendered whatever UTF-8 decoding the server happened to apply, with no way to
// view the body as anything else. Burp's own docs list four modes ("Recognize automatically based
// on message headers", "Use the platform default" (UTF-8), "Display as raw bytes", "Use a specific
// character set") and state the scope precisely: "The charset encoding options only apply to the
// message body."
//
// No wire change was needed for this (see ui/editor.tsx's own comment on bodyBytes): the server
// already sends either the exact octets (`body_base64`, for a non-UTF-8 body) or a body whose text
// round-trips to the exact octets on re-encode (a UTF-8-valid one, which is why body_base64 is
// absent exactly then) — both cases hand the client real bytes to reinterpret.
//
// Driven through Repeater's editable request draft, which needs no server cooperation at all: the
// test types a body containing "é" (UTF-8: 0xC3 0xA9) directly into the draft, then asks the editor
// to redisplay it under Windows-1252, where those same two bytes read as "Ã©" — classic mojibake,
// and the one unambiguous signal that the control is decoding real bytes rather than doing
// something cosmetic to the string already on screen.

import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

test.describe("Message editor character set — burpsy-react-ui-p836", () => {
  test("reinterpreting the body under Windows-1252 shows the mojibake those bytes actually are, and headers are unaffected", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("repeater"));
    await page.getByRole("button", { name: "New request" }).click();

    // Scoped to the request pane specifically: Repeater shows a request and a response editor
    // side by side, both carrying this control, and only one of them is a plain "Request".
    const requestShell = page.locator(".editor-shell", {
      has: page.locator(".editor-label-inline", { hasText: /^Request$/ }),
    });
    const editor = requestShell.locator(".cm-content");
    // A <select>, not the custom-charset <input> beside it — both end their aria-label the same
    // way ("... character set"), so this is scoped by role as well as by name.
    const charsetSelect = requestShell.getByRole("combobox", { name: "Request character set" });

    await editor.click();
    await page.keyboard.press("Control+a");
    await page.keyboard.type("GET / HTTP/1.1\nHost: example.com\n\né", { delay: 5 });

    // Platform default (the control's initial value, and today's only behaviour) shows the body
    // exactly as typed.
    await expect(editor).toContainText("é");
    await expect(editor).toContainText("Host: example.com");

    // Switch to a specific character set. The default draft value is already "windows-1252",
    // which is the point being tested, so selecting the mode is enough.
    await charsetSelect.selectOption("custom");

    // 0xC3 0xA9 (é in UTF-8) read one byte at a time under Windows-1252 is "Ã©" — the body changes,
    // the Host header (pure ASCII, unaffected by any charset choice per Burp's own scope note)
    // does not.
    await expect(editor).toContainText("Ã©");
    await expect(editor).not.toContainText("é");
    await expect(editor).toContainText("Host: example.com");
    await expect(requestShell.getByText(/showing the body decoded as windows-1252/)).toBeVisible();

    // Editing is off while the override is showing: a keystroke must not reach the document.
    // Control+End, not End: a click lands the cursor on whichever line is under the pointer, and
    // End only reaches the end of THAT line — the keystroke has to target the body's end to test it.
    await editor.click();
    await page.keyboard.press("Control+End");
    await page.keyboard.type("X");
    await expect(editor).not.toContainText("X");

    // Back to Platform default restores both the original bytes and editability.
    await charsetSelect.selectOption("utf-8");
    await expect(editor).toContainText("é");
    await expect(editor).not.toContainText("Ã©");
    await editor.click();
    await page.keyboard.press("Control+End");
    await page.keyboard.type("!");
    await expect(editor).toContainText("é!");

    expect(consoleErrors).toEqual([]);
  });
});
