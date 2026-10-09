import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";
import { readHarness } from "../harness/server";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/**
 * Content discovery as a session (burpsy-react-ui-dgbi): Burp's "Discover content" builds its
 * guesses from the built-in lists and recurses into what it finds. The harness boots burpsy with a
 * deterministic ffuf stand-in on the allowlist (see harness/server.ts), so this drives the real
 * page, the real route and the real session driver end to end — a sweep with the built-in short
 * directory list and two levels of recursion, whose results show the second level.
 */
test.describe("Content discovery — built-in lists and recursion", () => {
 test("a sweep with the built-in short list and 2 levels recurses and shows both levels", async ({
  page,
  consoleErrors,
 }) => {
  const { targetPort } = readHarness();
  const origin = `http://127.0.0.1:${targetPort}/`;

  // Scope first: the sweep is refused without it, and the refusal is the wrong
  // thing to screenshot. /api/scope is an unattended-caller-gated route, so the
  // include goes through the one-time confirmation the gate exists for — the
  // same flow a scripted caller uses in production.
  // The token is bound to the exact call (burpsy-react-ui-e0yq), so the mint describes it.
  const include = JSON.stringify({ action: "include", pattern: "127.0.0.1" });
  const confirm = await page.request.post("/api/scope/confirm", { data: { method: "POST", url: "/api/scope", body: include } });
  expect(confirm.ok(), "minting the scope confirmation").toBe(true);
  const { token } = (await confirm.json()) as { token: string };
  const scoped = await page.request.post("/api/scope", {
   data: include,
   headers: { "X-Burpsy-Confirm": token, "content-type": "application/json" },
  });
  expect(scoped.ok(), "the scope include must be accepted").toBe(true);

  await gotoRoute(page, route("contentdiscovery"));

  // The tool card reports the allowlisted stand-in available, so the launch
  // form — not the refusal — is on the page.
  const target = page.getByLabel("Target URL");
  await expect(target).toBeVisible();
  await target.fill(origin);

  // The built-in short directory list, ticked by its inventory label.
  const shortList = page.getByRole("checkbox", { name: /builtin-short-directories/ });
  await shortList.check();

  // Two levels of recursion — Burp's "how many levels of subdirectory".
  await page.getByLabel("Subdirectory levels").selectOption("2");

  await page.getByRole("button", { name: /Start sweep/ }).click();

  // The run finishes on its own; poll the API rather than the UI so the wait
  // cannot be satisfied by a spinner.
  let run: { state?: string; task_id?: number } = {};
  for (let i = 0; i < 40; i += 1) {
   const list = await page.request.get("/api/discovery").then((r) => r.json());
   run = (list.runs ?? [])[0] ?? {};
   if (run.state && run.state !== "running") break;
   await page.waitForTimeout(500);
  }
  expect(run.state, "the sweep should have finished").toBe("done");

  // The results show the recursion: the levels metric names both levels, and
  // the level-2 discovery (/admin/deep/notes.txt) is in the table — the row
  // that cannot exist without the second level having run.
  const detail = page.locator("main");
  await expect(detail).toContainText("Recursion levels");
  await expect(detail).toContainText("level 1:");
  await expect(detail).toContainText("level 2:");
  await expect(detail).toContainText("level 2: 1 found");
  // The discovery rows render the path in a code cell; exact text so the
  // redirect column (a different path) cannot satisfy the match.
  await expect(page.getByText("/admin/deep/notes.txt", { exact: true })).toBeVisible();
  await expect(page.getByText("/admin/report.txt", { exact: true })).toBeVisible();

  expect(consoleErrors).toEqual([]);
 });
});
