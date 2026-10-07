import { expect } from "@playwright/test";
import { gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

// Burp's four further randomness tests on the Sequencer page (burpsy-react-ui-d2g):
// character transition analysis, the spectral test, the correlation test and the
// compression test.
//
// Two things are asserted here that a Go unit test cannot reach:
//
//  1. The rows are produced by the server, not by the page. The observed string is the
//     statistic the engine printed, so a page that rendered its own placeholder numbers
//     would fail on the phrasing the Go tests also assert.
//  2. The two states both render. A sample that cannot support a test must show
//     "not tested" *with its reason*, not a blank cell and not a pass — the same
//     distinction the FIPS table already makes below one 20,000-bit block, and the one
//     an operator would otherwise have to read the JSON to discover.
//
// The large sample is loaded through the page's own "Load from file" affordance rather
// than typed: 512 tokens is the compression test's floor, and typing that many lines
// through CodeMirror would make the spec about the keyboard.

/** 512 hex tokens of 32 characters — enough for the compression test's floor. */
function hexTokens(count: number, seed: number): string[] {
  const out: string[] = [];
  let state = seed >>> 0;
  const next = () => {
    // A deterministic xorshift32, so a failure here can be reproduced exactly.
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };
  for (let i = 0; i < count; i++) {
    let token = "";
    for (let j = 0; j < 32; j++) token += (next() & 15).toString(16);
    out.push(token);
  }
  return out;
}

test.describe("Sequencer — the extended randomness battery", () => {
  test("a large sample runs the battery and every row carries its own statistic", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("sequencer"));

    const tokens = hexTokens(600, 0x9e3779b9);
    // The page carries more than one hidden file input — the editor has one and the app's
    // configuration import has another — and they are all `sr-only`, so which is first is a
    // DOM-order detail. The badge below is what makes this self-verifying: it counts the
    // tokens the editor actually holds, so a file that landed anywhere else fails there.
    await page.locator('input[type="file"]').first().setInputFiles({
      name: "sequencer-tokens.txt",
      mimeType: "text/plain",
      buffer: Buffer.from(tokens.join("\n") + "\n"),
    });
    await expect(page.getByText(`${tokens.length} pasted`)).toBeVisible();

    await page.getByRole("button", { name: "Analyse" }).click();

    const card = page.locator(".card", { has: page.getByRole("heading", { name: "Extended tests" }) });
    await expect(card).toBeVisible({ timeout: 30_000 });

    // Every one of the four is named, so a battery that silently dropped a member is a
    // failure rather than a shorter table.
    for (const name of ["Character transition analysis", "Spectral test", "Correlation test", "Compression test"]) {
      await expect(card.getByRole("cell", { name })).toBeVisible();
    }

    // Server-produced statistics: these strings exist only in internal/sequencer.
    await expect(card.getByText(/worst of \d+ combination\(s\)/)).toBeVisible();
    await expect(card.getByText(/worst of \d+ pair\(s\)/)).toBeVisible();
    await expect(card.getByText(/reduction against the .*incompressible control/)).toBeVisible();
    await expect(card.getByText(/p = [\d.e-]+ uncorrected/).first()).toBeVisible();

    // The sentence that keeps a flagged row from being read as a grade change.
    await expect(card.getByText(/do not change the grade above, which is the FIPS 140-2 battery's/)).toBeVisible();

    // 600 tokens of 32 hex characters is 19,200 bits: every table in this battery is
    // 256 cells wide, so the transition test cannot fill one and must say so rather
    // than pass. That refusal is the honest half of the feature and it has to render.
    const refusals = card.getByText("not tested");
    await expect(refusals).toHaveCount(1);
    await expect(card.getByText(/needs about \d+ transitions/)).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });

  test("a sample too small for the battery says so instead of passing it", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("sequencer"));

    const editor = page.locator(".cm-content").first();
    await editor.click();
    // Two short tokens: sixteen bits. Not one of the four can be supported at that size —
    // the spectral test needs twenty bits to fill the smallest table worth five
    // observations a cell, the correlation test needs thirty tokens and the compression
    // test five hundred and twelve.
    await page.keyboard.type("ab\ncd", { delay: 2 });

    await page.getByRole("button", { name: "Analyse" }).click();

    const card = page.locator(".card", { has: page.getByRole("heading", { name: "Extended tests" }) });
    await expect(card).toBeVisible({ timeout: 30_000 });

    // All four refuse, and the refusals are not interchangeable: each names the condition
    // its own test needed, which is what turns "not tested" into something an operator can
    // act on rather than a shrug.
    await expect(card.getByText("not tested")).toHaveCount(4);
    await expect(card.getByText(/needs about \d+ transitions/)).toBeVisible();
    await expect(card.getByText(/below 30 samples/)).toBeVisible();
    await expect(card.getByText(/needs at least 512/)).toBeVisible();
    await expect(card.getByText(/cannot fill a testable tuplet table/)).toBeVisible();

    // No row may render a verdict badge it did not earn.
    await expect(card.getByText("pass", { exact: true })).toHaveCount(0);
    await expect(card.getByText("fail", { exact: true })).toHaveCount(0);

    // And the summary says outright that nothing ran, which is a different sentence from
    // "nothing found".
    await expect(card.getByText(/None of the 4 extended tests could run/)).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });
});
