import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

// Burp's New-scan dialog offers four scan types, and "Crawl and audit" is the primary one: "Maps the
// attack surface and identifies vulnerabilities". burpsy could launch only the crawl half, so the
// audit of what a crawl found was reachable only as the always-on live sweep over traffic the
// operator's own browser had sent.
//
// What these tests pin is the whole path: the dialog sends a scan kind rather than always a crawl,
// the server runs the audit over the exchanges the crawl itself fetched, and the audit reports
// itself as its own task row with its own progress — because a scan that quietly skipped its audit
// would look exactly like a scan that found nothing.
//
// The harness origin answers every path with plain text and no links, so the crawl fetches the seed
// (and robots.txt) and stops. That is deliberate: what is being tested is whether the audit phase
// runs at all and over which exchanges, not whether the checks find anything, and a target whose
// content made the counts large would make the assertions about counts fragile for no gain.

test.describe("Dashboard — Crawl and audit (Burp's primary scan kind)", () => {
  test("the dialog offers Burp's four scan types, and a disabled one says what is missing", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("dashboard"));
    await page.getByRole("button", { name: "New scan" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();

    // Burp opens on Crawl and audit, so the card that is selected before anything is clicked is the
    // one that decides what Start does.
    const crawlAndAudit = dialog.getByRole("button", { name: /^Crawl and audit/ });
    await expect(crawlAndAudit).toBeEnabled();
    await expect(crawlAndAudit).toHaveAttribute("class", /scan-type-selected/);

    // Anchored past the title: /^Crawl\b/ matches "Crawl and audit" too, so the plain Crawl card
    // would never be the element under test.
    await expect(dialog.getByRole("button", { name: /^Crawl Maps/ })).toBeEnabled();

    // The two burpsy cannot run are present and disabled rather than absent, and each names the
    // capability it is missing. "not built yet" was the old text and it is a reason no operator can
    // act on: it does not say whether the thing is coming, blocked, or simply never planned.
    const api = dialog.getByRole("button", { name: /^API-only scan/ });
    await expect(api).toBeDisabled();
    await expect(api).toContainText("API-definition import");

    const selected = dialog.getByRole("button", { name: /^Audit selected items/ });
    await expect(selected).toBeDisabled();
    await expect(selected).toContainText("selection-driven");

    expect(consoleErrors).toEqual([]);
  });

  test("launching one registers the crawl and then its audit, and the audit's row reports its own progress", async ({
    page,
    consoleErrors,
  }) => {
    const { targetPort } = readHarness();
    await gotoRoute(page, route("dashboard"));
    await page.getByRole("button", { name: "New scan" }).click();
    const dialog = page.getByRole("dialog");

    await dialog.getByLabel("URLs to scan").fill(`http://127.0.0.1:${targetPort}/crawl-audit-1/`);
    await dialog.getByLabel("Max requests (empty = uncapped)").fill("4");
    await dialog.getByLabel("Max depth").fill("2");
    // The dialog says a crawl-and-audit is two rows before the operator commits to it, so the second
    // row appearing is the behaviour that was described rather than a surprise.
    await expect(dialog).toContainText("Two tasks appear below");
    await dialog.getByRole("button", { name: "Start", exact: true }).click();

    await expect(page.getByText(/Crawl and audit started on/)).toBeVisible();

    // The crawl's own row.
    const crawlTile = page.locator(".task-tile", { hasText: "crawl (" }).first();
    await expect(crawlTile).toBeVisible();

    // And the audit's, which is the half that did not exist. Matched on the registry's kind, not on
    // a title the UI could have invented: the row exists because the server registered it.
    const auditTile = page.locator(".task-tile", { hasText: "audit-session (" }).first();
    await expect(auditTile).toBeVisible({ timeout: 60_000 });
    await expect(auditTile).toContainText("crawl of 127.0.0.1");

    // It finishes. A row stuck on "running" is the failure mode a feature like this actually has —
    // the audit half being launched and then doing nothing is indistinguishable, on screen, from an
    // audit that is still working.
    await expect(auditTile.getByText("done", { exact: true })).toBeVisible({ timeout: 60_000 });

    // And the retained run says which kind it was. Asserted against the API rather than the screen
    // because it is the claim that the *server* took the kind: a UI that rendered two rows while
    // sending a plain crawl would satisfy every assertion above.
    const runs = await page.request.get("/api/crawl").then((r) => r.json());
    const latest = (runs.crawls ?? []).find((run: { seeds: string[] }) =>
      (run.seeds ?? []).some((seed: string) => seed.includes("/crawl-audit-1/")),
    );
    expect(latest?.kind, "the retained run must record the kind the server ran").toBe("crawl-audit");

    expect(consoleErrors).toEqual([]);
  });

  test("a plain Crawl registers no audit, so the default is not quietly the expensive option", async ({
    page,
    consoleErrors,
  }) => {
    const { targetPort } = readHarness();
    await gotoRoute(page, route("dashboard"));
    await page.getByRole("button", { name: "New scan" }).click();
    const dialog = page.getByRole("dialog");

    await dialog.getByRole("button", { name: /^Crawl Maps/ }).click();
    // The two-row explanation belongs to crawl-and-audit only; leaving it up for a plain crawl would
    // promise a task that never appears.
    await expect(dialog).not.toContainText("Two tasks appear below");
    await dialog.getByLabel("URLs to scan").fill(`http://127.0.0.1:${targetPort}/crawl-audit-2/`);
    await dialog.getByLabel("Max requests (empty = uncapped)").fill("4");
    await dialog.getByRole("button", { name: "Start", exact: true }).click();

    const crawlTile = page.locator(".task-tile", { hasText: "/crawl-audit-2/" }).first();
    await expect(crawlTile).toBeVisible();
    await expect(crawlTile.getByText("done", { exact: true })).toBeVisible({ timeout: 60_000 });

    // Read from the API, so the assertion is about what ran and not about what was rendered.
    const runs = await page.request.get("/api/crawl").then((r) => r.json());
    const latest = (runs.crawls ?? []).find((run: { seeds: string[] }) =>
      (run.seeds ?? []).some((seed: string) => seed.includes("/crawl-audit-2/")),
    );
    expect(latest?.kind, "an omitted kind is a plain crawl").toBe("crawl");

    // No audit row anywhere for this launch. The tile list is read whole and filtered in the test:
    // hasText on the tile would match through the target URL, which every row shares.
    const tiles = await page.locator(".task-tile").allInnerTexts();
    expect(tiles.some((text) => text.includes("/crawl-audit-2/") && text.includes("audit-session"))).toBe(
      false,
    );

    expect(consoleErrors).toEqual([]);
  });
});
