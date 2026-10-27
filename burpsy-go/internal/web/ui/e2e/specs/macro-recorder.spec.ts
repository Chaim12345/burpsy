import { expect, type Page } from "@playwright/test";
import { gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

// The macro's step cards only. The rule editor's action cards (session.tsx ActionCard) share the
// .step-card class, and a new rule now carries default actions, so a bare .step-card count also
// counted those (5 for 3 recorded steps). A macro step is the card with a "Step N URL" field.
const macroSteps = (page: Page) => page.locator(".step-card").filter({ has: page.getByLabel(/^Step \d+ URL$/) });

// Burp's Macro Recorder is a selection over Proxy history, not a form: "Macros are made up of
// requests taken from the Proxy history … Select the items you need from the Proxy history list"
// (settings/sessions/macros.html). These tests pin the two things that make it that rather than a
// typed form — the rows come from traffic the proxy actually captured, and the order the operator
// clicked is the order the macro replays in — plus the one behaviour a partial result depends on:
// a row that cannot become a step is reported rather than dropped.
//
// The harness seeds five proxied exchanges, all on one host with different paths, so a selection
// whose click order happened to match the list's own order would pass a sort-free assertion by
// accident. Three rows are therefore picked in an order that matches neither reading of the list:
// middle, oldest, newest. Sorting the selection by its position in history — whichever end the page
// lists from — moves at least one of them, so "step 1 is the first row clicked" can only hold if
// selection order survived.

test.describe("Session page — Macro Recorder from Proxy history", () => {
  test("records the selected rows as steps, in the order they were clicked", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("session"));

    // The recorder lives in the rule editor, so the editor has to be open first. This is also the
    // gate Burp has: there is no macro without a rule to attach it to.
    await page.getByRole("button", { name: "New rule" }).first().click();
    await page.getByRole("button", { name: "Record from history" }).click();

    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();

    // Seeded order is zebra, alpha, mango/deep/path, beta, quokka; the clicks are mango, zebra,
    // quokka. Whatever order the table is listed in, that is not it.
    const mango = dialog.locator("tr", { hasText: "/mango/deep/path" });
    const zebra = dialog.locator("tr", { hasText: "/zebra" });
    const quokka = dialog.locator("tr", { hasText: "/quokka" });
    await expect(mango).toHaveCount(1);
    await mango.getByRole("checkbox").check();
    await zebra.getByRole("checkbox").check();
    await quokka.getByRole("checkbox").check();

    // The Order column is the visible statement of the promise. Read 1 for /zebra and the steps that
    // come back would still look plausible — while replaying the login flow in the wrong order.
    await expect(mango.locator("td").nth(1)).toHaveText("1");
    await expect(zebra.locator("td").nth(1)).toHaveText("2");
    await expect(quokka.locator("td").nth(1)).toHaveText("3");

    await dialog.getByRole("button", { name: "Record 3 steps" }).click();
    await expect(dialog).toBeHidden();

    // The steps land in the editor as editable drafts of the captured requests — the URL is the
    // exchange's addressing joined with the stored origin-form target, which is why it is asserted
    // here rather than only on the server side.
    await expect(page.getByLabel("Step 1 URL")).toHaveValue(/\/mango\/deep\/path$/);
    await expect(page.getByLabel("Step 2 URL")).toHaveValue(/\/zebra$/);
    await expect(page.getByLabel("Step 3 URL")).toHaveValue(/\/quokka\?size=8$/);
    await expect(page.getByLabel("Step 1 method")).toHaveValue("GET");

    // Three steps, not four: the rule's untouched placeholder step is replaced, not left above the
    // recorded flow. A blank step has no URL and would fail validation at save time, which is how a
    // recorder that "worked" still cannot produce a usable rule.
    await expect(macroSteps(page)).toHaveCount(3);

    expect(consoleErrors).toEqual([]);
  });

  test("closing without recording adds nothing, and reopening starts from an empty selection", async ({
    page,
    consoleErrors,
  }) => {
    await gotoRoute(page, route("session"));
    await page.getByRole("button", { name: "New rule" }).first().click();

    // A new rule starts as one untouched placeholder step, so that is the baseline the cancel has
    // to leave alone. Counting rather than reading a value, because "nothing was added" is a
    // statement about how many steps exist.
    const steps = macroSteps(page);
    await expect(steps).toHaveCount(1);

    await page.getByRole("button", { name: "Record from history" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.locator("tr", { hasText: "/zebra" }).getByRole("checkbox").check();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();

    await expect(steps).toHaveCount(1);
    await expect(page.getByLabel("Step 1 URL")).toHaveValue("");

    // A stale tick is how a request ends up in a macro twice: reopening must not resurrect it.
    await page.getByRole("button", { name: "Record from history" }).click();
    const reopened = page.getByRole("dialog");
    await expect(reopened.locator("tr", { hasText: "/zebra" }).getByRole("checkbox")).not.toBeChecked();
    // And with nothing picked, there is nothing to record — the confirm button cannot be reached
    // by someone who cancelled, thought better of it, and clicked through out of habit.
    await expect(reopened.getByRole("button", { name: "Record steps" })).toBeDisabled();
    expect(consoleErrors).toEqual([]);
  });
});
