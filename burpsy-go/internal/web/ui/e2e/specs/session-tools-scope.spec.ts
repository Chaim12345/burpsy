import { expect } from "@playwright/test";
import { gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

// Burp's tools scope on a session-handling rule (settings/sessions/session-handling-rules.html,
// burpsy-react-ui-so3): the Scope tab's first axis, and the one with no substitute — a rule that
// re-logs-in on a 302 must be keepable away from an Intruder attack that is deliberately fuzzing
// the session cookie, and no other axis can say that.
//
// Two things are asserted end to end here, and the second is the one a unit test cannot reach:
//
//  1. The checklist's entries are the tools the server actually enforces. The list is served by
//     /api/session/rules rather than hard-coded in the page precisely so the editor cannot offer a
//     tool the API would refuse; if the page stopped reading it, this would be the only place that
//     noticed.
//  2. Checking one and saving survives a reopen. That path runs through the request, the SQLite-free
//     in-memory coordinator, ruleToDto and ruleIn — the round trip where a scope that reached the
//     matcher but not the wire would silently widen the rule the next time the operator saved it.
test.describe("Session page — a rule's tools scope", () => {
  test("offers the server's tool list and keeps the checked tools across a reopen", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("session"));
    await page.getByRole("button", { name: "New rule" }).first().click();

    // The checklist is built from the server's list, so the tools the Logger's capture filter also
    // knows are all present. Asserting two of them rather than the whole set keeps this spec about
    // the wiring; the server-side test pins the list itself against toollog.
    await expect(page.getByLabel("Apply this rule to crawler")).toBeVisible();
    await expect(page.getByLabel("Apply this rule to intruder")).toBeVisible();

    // Nothing checked reads as "every tool", and the page says so out loud rather than leaving an
    // operator to guess whether an empty checkbox row means "all" or "none".
    await expect(page.getByText("No tools checked, so the rule applies to every tool.")).toBeVisible();

    await page.getByLabel("Apply this rule to crawler").check();
    await expect(page.getByText(/fires only for requests made by the checked tools/)).toBeVisible();

    // A rule the server will accept: a name and one macro step. The step is the placeholder the
    // editor seeded, filled in so validation passes — the point of this spec is the scope, not the
    // macro.
    await page.getByLabel("Name", { exact: true }).fill("crawler-only re-login");
    await page.getByLabel("Step 1 method").fill("POST");
    await page.getByLabel("Step 1 URL").fill("https://target.test/login");
    await page.getByRole("button", { name: "Save rule" }).click();

    // Reopen from the list. If the DTO dropped scope_tools the checkbox comes back clear, and the
    // next save would write "every tool" over the restriction the operator stated.
    await page.getByRole("button", { name: "Edit crawler-only re-login" }).click();
    await expect(page.getByLabel("Apply this rule to crawler")).toBeChecked();
    await expect(page.getByLabel("Apply this rule to intruder")).not.toBeChecked();

    // And the rule's row in the list says which tools it applies to, so an operator scanning the
    // list is not told "every host" by a rule that only ever fires for one tool.
    await expect(page.getByText(/from crawler/)).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });
});
