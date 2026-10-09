import { readFile } from "node:fs/promises";
import { expect, gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

/**
 * The report-settings dialog (burpsy-react-ui-a9qy) is Burp's reporting wizard as a surface on the
 * Issues page: title, organisation, contents depth, issue-detail sections, and the HTTP-messages
 * mode and bound. The harness seeds one audit against exchange 0, so the page has real findings to
 * export, and the assertions land on the downloaded artefact rather than on the dialog's own state —
 * a wizard whose buttons work but whose file ignores the choices is the bug this bead was filed on.
 */
test.describe("Issues — report settings (Burp's reporting wizard)", () => {
 test("choosing by-URL organisation and a message bound lands in the downloaded report", async ({
  page,
  consoleErrors,
 }) => {
  await gotoRoute(page, route("scanner"));

  // Open the wizard.
  await page.getByRole("button", { name: /Report settings/ }).click();
  const dialog = page.locator(".dialog-content");
  await expect(dialog).toBeVisible();

  // The organisation and the message choices from Burp's own wizard wording
  // (report-settings.html: "By URL", "Include in full", "limit each message
  // to a maximum length").
  await page.getByLabel("Organise issues by").selectOption("url");
  await page.getByRole("checkbox", { name: "Include in full" }).check();
  await page.getByLabel("Maximum message length (bytes)").fill("20");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(dialog).not.toBeVisible();

  // The HTML export link carries what was chosen; the JSON link does not
  // carry the HTML-only choices, because a parameter that quietly does
  // nothing is worse than an absent one.
  const htmlLink = page.getByRole("link", { name: "HTML" });
  await expect(htmlLink).toHaveAttribute("href", /organise_by=url/);
  await expect(htmlLink).toHaveAttribute("href", /message_mode=full/);
  await expect(htmlLink).toHaveAttribute("href", /max_message_len=20/);
  await expect(page.getByRole("link", { name: "JSON" })).not.toHaveAttribute("href", /organise_by/);

  // Download the report and read it back: the organisation shows as a
  // by-URL group heading, and the bound shows as the truncation marker —
  // the two things that cannot be faked by a dialog that only changes its
  // own state.
  const [download] = await Promise.all([page.waitForEvent("download"), htmlLink.click()]);
  const content = await readFile((await download.path())!, "utf8");
  expect(content, "the by-URL organisation must reach the document").toContain(`class="group"`);
  expect(content, "the 20-byte bound must bite and be marked").toContain("[truncated at 20 bytes]");
  expect(content, "full mode must attach the evidence messages").toContain(`class="msg"`);

  expect(consoleErrors).toEqual([]);
 });

 test("the settings button shows the dialog is carrying non-default choices", async ({ page, consoleErrors }) => {
  await gotoRoute(page, route("scanner"));

  const button = page.getByRole("button", { name: /Report settings/ });
  await expect(button).toHaveText(/Report settings$/);

  await button.click();
  await page.getByLabel("Report title").fill("Acme re-test");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(button).toHaveText(/Report settings \*$/);
  // And the title really is the document's heading, not just the button's.
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: "HTML" }).click()]);
  const content = await readFile((await download.path())!, "utf8");
  expect(content).toContain("<h1>Acme re-test</h1>");

  expect(consoleErrors).toEqual([]);
 });
});
