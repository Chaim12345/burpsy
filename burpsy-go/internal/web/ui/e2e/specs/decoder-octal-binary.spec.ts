// burpsy-react-ui-ku62: Burp's Decoder lists Octal and Binary among its eight codecs
// ("URL. HTML. Base64. ASCII hex. Hex. Octal. Binary. GZIP.") and burpsy had neither — the
// dropdown only offered six. Adding the two names to the UI's list is not the fix by itself: the
// server has no passthrough branch, so an option that reaches an unimplemented layer is a 400, not
// a quiet no-op. This drives the real pipeline through the real backend for both directions, so a
// wire mismatch between the dropdown and `internal/tools/codec.go` fails here rather than only in
// a unit test that mocks the transport.
//
// The literal digit strings ("110 151" for "Hi") are pinned to internal/tools/codec_test.go's
// TestOctalEncodesThreeDigitsPerByteAndDecodeTakesUnpaddedTokensToo /
// TestBinaryEncodesEightDigitsPerByteAndDecodeTakesUnpaddedTokensToo — if either side's format ever
// drifts, both suites break together instead of silently disagreeing.

import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

test.describe("Decoder Octal/Binary — burpsy-react-ui-ku62", () => {
  test("encoding as Octal then decoding the result as Octal round-trips through the real backend", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("decoder"));

    await page.locator(".cm-content").first().click();
    await page.keyboard.type("Hi", { delay: 5 });

    // Step 1, already on the page: switch it from the default "Decode / auto" to "Encode / octal".
    await page.getByLabel("Step 1 operation").selectOption("encode");
    await page.getByLabel("Step 1 encoding").selectOption("octal");

    // A second step feeds step 1's output back through Decode/octal, so a correct round trip
    // proves both the encode and the decode legs are wired to the server, not just one of them.
    await page.getByRole("button", { name: "Decode", exact: true }).click();
    await page.getByLabel("Step 2 encoding").selectOption("octal");

    await page.getByRole("button", { name: "Run pipeline" }).click();

    const cards = page.locator(".tool-output");
    await expect(cards.nth(0)).toHaveText("110 151");
    await expect(cards.nth(1)).toHaveText("Hi");

    expect(consoleErrors).toEqual([]);
  });

  test("encoding as Binary then decoding the result as Binary round-trips through the real backend", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("decoder"));

    await page.locator(".cm-content").first().click();
    await page.keyboard.type("Hi", { delay: 5 });

    await page.getByLabel("Step 1 operation").selectOption("encode");
    await page.getByLabel("Step 1 encoding").selectOption("binary");

    await page.getByRole("button", { name: "Decode", exact: true }).click();
    await page.getByLabel("Step 2 encoding").selectOption("binary");

    await page.getByRole("button", { name: "Run pipeline" }).click();

    const cards = page.locator(".tool-output");
    await expect(cards.nth(0)).toHaveText("01001000 01101001");
    await expect(cards.nth(1)).toHaveText("Hi");

    expect(consoleErrors).toEqual([]);
  });
});
