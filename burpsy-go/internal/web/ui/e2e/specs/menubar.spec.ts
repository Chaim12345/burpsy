import { expect } from "@playwright/test";
import { gotoRoute, test } from "../harness/fixtures";
import { ROUTES } from "../harness/routes";

const route = (id: string) => ROUTES.find((entry) => entry.id === id)!;

// The menu bar lagged Burp in three ways: the menus did not match Burp's, the tab list sat in a
// burpsy-only Tools menu as navigate actions, and View had no way back from a dragged-out split
// layout. These tests pin the fixes. Bead lje3 moved the tab list into View, as Burp has it: one
// checkable entry per top-level tab (show/hide, not navigate) plus "Restore default tab layout".

// Every top-level tab, in nav.ts's TOOLS order.
const TABS = ["Dashboard", "Target", "Proxy", "Intruder", "Repeater", "Collaborator", "Sequencer", "Decoder", "Comparer", "Logger", "Organizer", "Session", "Extensions", "Discover", "Settings"];

test.describe("Menu bar — Burp's menus, the View tab list, reset layout", () => {
  test("the menus are Burp's, and View lists every top-level tab as a show/hide toggle", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("dashboard"));

    const triggers = page.locator(".menu-trigger");
    await expect(triggers).toHaveText(["burpsy", "File", "Project", "Intruder", "Repeater", "View", "Help"]);

    await page.locator('.menu-trigger:has-text("View")').click();
    for (const label of TABS) {
      await expect(page.getByRole("menuitemcheckbox", { name: new RegExp(`^${label}`) })).toBeChecked();
    }
    await expect(page.getByRole("menuitem", { name: "Restore default tab layout" })).toBeVisible();

    // Unchecking a tab hides it from the strip; Restore brings it back.
    await page.getByRole("menuitemcheckbox", { name: /^Logger/ }).click();
    const strip = page.getByRole("navigation", { name: "Tools" });
    await expect(strip.locator(".tool-tab").filter({ hasText: "Logger" })).toHaveCount(0);
    await page.locator('.menu-trigger:has-text("View")').click();
    await page.getByRole("menuitem", { name: "Restore default tab layout" }).click();
    await expect(strip.locator(".tool-tab").filter({ hasText: "Logger" })).toHaveCount(1);
    expect(consoleErrors).toEqual([]);
  });

  test("Reset panel layout clears persisted splits and reloads", async ({ page, consoleErrors }) => {
    await gotoRoute(page, route("dashboard"));
    await page.evaluate(() => localStorage.setItem("burpsy.split.probe", "37%"));

    await page.locator('.menu-trigger:has-text("View")').click();
    await page.getByRole("menuitem", { name: "Reset panel layout" }).click();

    // The action reloads the page; wait for the app to come back before asserting.
    await expect(page.locator(".menu-trigger")).toHaveCount(7);
    const probe = await page.evaluate(() => localStorage.getItem("burpsy.split.probe"));
    expect(probe).toBeNull();
    expect(consoleErrors).toEqual([]);
  });
});
