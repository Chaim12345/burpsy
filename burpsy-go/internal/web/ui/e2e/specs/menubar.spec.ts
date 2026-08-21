import { expect } from "@playwright/test";
import { gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

// The menu bar lagged Burp in three ways: the second menu was called "Project" where Burp has
// "File", there was no Tools menu at all (the only way between tools was the tab strip), and View
// had no way back from a dragged-out split layout. These tests pin all three.

test.describe("Menu bar — File, Tools, reset layout", () => {
  test("Tools menu lists every tool and navigates to it", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("dashboard"));

    const triggers = page.locator(".menu-trigger");
    await expect(triggers).toHaveCount(6);
    await expect(triggers).toContainText(["burpsy", "File", "Repeater", "Tools", "View", "Help"]);

    await page.locator('.menu-trigger:has-text("Tools")').click();
    for (const label of ["Dashboard", "Target", "Proxy", "Intruder", "Repeater", "Sequencer", "Decoder", "Comparer", "Logger", "Organizer", "Session", "Settings"]) {
      await expect(page.getByRole("menuitem", { name: new RegExp(`^${label}`) })).toBeVisible();
    }

    await page.getByRole("menuitem", { name: /^Logger/ }).click();
    await expect(page).toHaveURL(/#logger/);
    expect(consoleErrors).toEqual([]);
  });

  test("Reset panel layout clears persisted splits and reloads", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("dashboard"));
    await page.evaluate(() => localStorage.setItem("burpsy.split.probe", "37%"));

    await page.locator('.menu-trigger:has-text("View")').click();
    await page.getByRole("menuitem", { name: "Reset panel layout" }).click();

    // The action reloads the page; wait for the app to come back before asserting.
    await expect(page.locator(".menu-trigger")).toHaveCount(6);
    const probe = await page.evaluate(() => localStorage.getItem("burpsy.split.probe"));
    expect(probe).toBeNull();
    expect(consoleErrors).toEqual([]);
  });
});
