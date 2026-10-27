import { expect, type Locator, type Page } from "@playwright/test";
import { gotoApp, test } from "../harness/fixtures";

// Burp's suite-wide Search crosses tools: "You can perform suite-wide searches in the search
// dialog. To access the search dialog, click Search on the tab bar" (tools/search.html). What makes
// it *suite-wide* rather than a second filter box is exactly what these tests pin: it can be
// narrowed to a tool, so a search of Proxy history and a search of Repeater return different sets;
// it looks inside response bodies, which the history rows themselves never carry; and the highlight
// in the preview comes from the server's offsets rather than from the browser re-matching the text.
//
// The seeded traffic is five proxied exchanges (/zebra, /alpha?q=1, /mango/deep/path, /beta,
// /quokka?size=8), one Repeater send (/repeated?x=9), and the scanner probes an audit produces.
// Every assertion below is phrased against that split, because "crosses tools" is a claim about
// which sets are reachable, and a search that searched only Proxy history would satisfy any
// assertion phrased purely as a match count.
//
// Changing an option does not re-run the search — the dialog asks, it does not poll — so every
// option change below is followed by pressing Search. An assertion made without that click would be
// reading the previous search's results and would pass whatever the new filter did.

async function openSearch(page: Page): Promise<Locator> {
  await gotoApp(page);
  // Burp puts Search on the tab bar; the shell carries it there for the same reason — it crosses
  // tools, so no single tool page can own it.
  await page.getByRole("button", { name: "Search across tools" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  return dialog;
}

async function search(dialog: Locator, term: string): Promise<void> {
  await dialog.getByLabel("Search for").fill(term);
  await dialog.getByRole("button", { name: "Search", exact: true }).click();
}

test.describe("Shell — suite-wide Search", () => {
  test("a tool filter narrows the search to that tool's traffic, which is what makes it suite-wide", async ({
    page,
    consoleErrors,
  }) => {
    const dialog = await openSearch(page);

    // Nothing has been searched yet, so the dialog says so rather than showing an empty table with
    // column headers stranded above it.
    await expect(dialog.getByText("No search yet")).toBeVisible();

    // Every response the target serves says ORIGIN-OK, so the term is present in the proxied
    // traffic and in the Repeater send alike. A search that only ever looked at Proxy history would
    // return the same rows for both filters below, and the first draft of this feature did exactly
    // that — which is why the two filters are asserted against each other rather than separately.
    await search(dialog, "ORIGIN-OK");

    const repeated = dialog.locator("tr", { hasText: "/repeated" });
    const zebra = dialog.locator("tr", { hasText: "/zebra" });
    await expect(repeated).toHaveCount(1);
    await expect(zebra).toHaveCount(1);

    // By role: each result row now has a "Preview ... from repeater" button, which a bare
    // getByLabel("Repeater") also matched.
    await dialog.getByRole("checkbox", { name: "Repeater", exact: true }).check();
    await dialog.getByRole("button", { name: "Search", exact: true }).click();
    await expect(repeated).toHaveCount(1);
    await expect(zebra).toHaveCount(0);
    // The Repeater set is small enough to examine whole, so the header states a count with no
    // "may be more" caveat. Not pinned to 1: in a full run, behaviour.spec's Inspector tests send
    // Repeater requests of their own before this file runs (the seeded send is the only one only
    // when this spec runs alone).
    await expect(dialog.getByText(/^\d+ items? of \d+ examined$/)).toBeVisible();

    // The other way, to prove the narrowing is a filter and not a coincidence of which rows exist.
    await dialog.getByRole("checkbox", { name: "Repeater", exact: true }).uncheck();
    await dialog.getByRole("checkbox", { name: "Proxy history", exact: true }).check();
    await dialog.getByRole("button", { name: "Search", exact: true }).click();
    await expect(repeated).toHaveCount(0);
    await expect(zebra).toHaveCount(1);

    expect(consoleErrors).toEqual([]);
  });

  test("the location and area axes reach response bytes the history rows never load, and the preview marks the server's offsets", async ({
    page,
    consoleErrors,
  }) => {
    const dialog = await openSearch(page);
    const row = dialog.locator("tr", { hasText: "/mango/deep/path" });

    // "mango" is in the request target and in the response body (the target echoes the path), so a
    // full search finds it twice.
    await search(dialog, "mango");
    await expect(row).toHaveCount(1);
    await expect(row.locator("td").nth(6)).toHaveText("2");
    await expect(dialog.getByText(/literal text, case insensitive/)).toBeVisible();

    // Response headers hold no "mango": the request half is switched off and the response half has
    // nothing, so the exchange must disappear. This is the assertion that would pass for a search
    // which ignored the axes entirely.
    await dialog.getByLabel("Location").selectOption("response");
    await dialog.getByLabel("Within").selectOption("headers");
    await dialog.getByRole("button", { name: "Search", exact: true }).click();
    await expect(row).toHaveCount(0);
    await expect(dialog.getByText("No matches")).toBeVisible();

    // The response body does, though — bytes the console never fetched for the history row.
    await dialog.getByLabel("Within").selectOption("body");
    await dialog.getByRole("button", { name: "Search", exact: true }).click();
    await expect(row).toHaveCount(1);
    await expect(row.locator("td").nth(6)).toHaveText("1");

    // Back to the full search for the preview assertion.
    await dialog.getByLabel("Location").selectOption("both");
    await dialog.getByLabel("Within").selectOption("both");
    await dialog.getByRole("button", { name: "Search", exact: true }).click();
    await expect(row).toHaveCount(1);

    await row.click();
    const marks = dialog.locator(".search-dialog-message mark");
    await expect(marks).toHaveCount(1);
    // Every highlight is the term itself. A pane that re-matched the text in the browser instead of
    // using the server's offsets is what this catches: Go's regexp and JavaScript's RegExp do not
    // accept quite the same patterns, so the two can disagree about the same response.
    for (const mark of await marks.all()) {
      await expect(mark).toHaveText("mango");
    }

    expect(consoleErrors).toEqual([]);
  });

  test("negative matches list the complement, and a pattern that cannot compile is reported rather than answered with nothing", async ({
    page,
    consoleErrors,
  }) => {
    const dialog = await openSearch(page);
    await dialog.getByRole("checkbox", { name: "Proxy history", exact: true }).check();

    // Only /quokka carries the term, so the negative search must return the other proxied rows.
    await search(dialog, "quokka");
    await expect(dialog.locator("tr", { hasText: "/quokka" })).toHaveCount(1);

    await dialog.getByLabel("Negative matches").check();
    await dialog.getByRole("button", { name: "Search", exact: true }).click();
    await expect(dialog.locator("tr", { hasText: "/quokka" })).toHaveCount(0);
    await expect(dialog.locator("tr", { hasText: "/zebra" })).toHaveCount(1);

    // A negative row has no match to point at, and the pane says which filter listed it rather than
    // rendering an empty viewer or an unexplained zero.
    await dialog.locator("tr", { hasText: "/zebra" }).click();
    await expect(dialog.getByText("no match — listed by the negative filter")).toBeVisible();

    // A regex that does not compile is the caller's mistake, and answering it with "no matches"
    // would read as "the term is absent" when nothing was ever searched for.
    await dialog.getByLabel("Negative matches").uncheck();
    await dialog.getByLabel("Regular expression").check();
    await search(dialog, "(unclosed");
    await expect(dialog.getByRole("alert")).toContainText("regular expression");

    // And a valid one works, so the refusal above is about the pattern rather than about regexes.
    await search(dialog, "quok+a");
    await expect(dialog.locator("tr", { hasText: "/quokka" })).toHaveCount(1);

    expect(consoleErrors).toEqual([]);
  });
});
