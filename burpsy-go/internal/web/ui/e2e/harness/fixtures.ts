// The `test` every spec imports, extended with the two things this suite needs everywhere: a
// console-error recorder, and a route opener that waits for the app rather than for a timeout.

import { test as base, expect, type Page } from "@playwright/test";
import { ROUTES, type Route } from "./routes";

/**
 * Why console errors are collected for every test rather than in one dedicated spec: an error thrown
 * during a render that still produces plausible-looking output is invisible to a screenshot and to
 * most assertions, and this UI has shipped exactly that before. Making the recorder a fixture means
 * a new spec gets the check by default instead of by remembering.
 *
 * Nothing is filtered. If a route legitimately logs an error the right fix is the route, and if that
 * is not possible the filter belongs in the one test that needs it, named and explained — not here,
 * where it would silently cover every future spec too.
 */
export const test = base.extend<{ consoleErrors: string[]; failedRequests: string[] }>({
  consoleErrors: async ({ page }, use) => {
    const errors: string[] = [];
    page.on("console", (message) => {
      // Chromium logs its own "Failed to load resource: ..." line at error level for every non-2xx
      // response. That is a NETWORK fact, not a JavaScript fact, and it says nothing about which
      // request it came from — so it is counted by the failedRequests fixture below, which knows the
      // method, the URL and the status, instead of here where it would be an unattributable string.
      // Nothing else is filtered: everything the application itself logs at error level lands here.
      if (message.type() !== "error") return;
      if (message.text().startsWith("Failed to load resource:")) return;
      errors.push(`console.error: ${message.text()}`);
    });
    page.on("pageerror", (error) => errors.push(`uncaught: ${error.message}`));
    await use(errors);
  },

  failedRequests: async ({ page }, use) => {
    const failures: string[] = [];
    page.on("response", (response) => {
      if (response.status() < 400) return;
      const method = response.request().method();
      const path = new URL(response.url()).pathname;
      // The one expected failure in a default run. `useCaCert` probes with HEAD /ca.crt and reads a
      // 404 as "TLS interception is off, so there is no CA to hand out" — a deliberate feature: the
      // status bar and the palette both gate the download on it rather than offering a link to an
      // error page. burpsy is started here without -intercept-tls, so this 404 is correct behaviour.
      if (method === "HEAD" && path === "/ca.crt" && response.status() === 404) return;
      failures.push(`${method} ${path} -> ${response.status()}`);
    });
    await use(failures);
  },
});

export { expect };

/** Serialised zustand-persist state, so a run starts from a known theme instead of the OS's. */
function persistedState(theme: "light" | "dark"): string {
  return JSON.stringify({
    state: { theme, density: "comfortable", repeaterTabs: [], activeRepeaterTab: null },
    version: 0,
  });
}

/**
 * Pin the theme before the app boots. The store's default is "system", which resolves against the
 * browser's prefers-color-scheme — fine in the app, useless in a test, where "dark" must mean dark
 * regardless of what the machine running CI prefers.
 */
export async function pinTheme(page: Page, theme: "light" | "dark"): Promise<void> {
  await page.addInitScript(
    ([key, value]) => window.localStorage.setItem(key as string, value as string),
    ["burpsy.workspace", persistedState(theme)] as const,
  );
  await page.emulateMedia({ colorScheme: theme });
}

/**
 * Open a route and wait for its page to be on screen.
 *
 * The wait is on the h1 having the route's own title, not merely on an h1 existing: navigation is a
 * hash change against a mounted app, so the previous route's h1 is present for a frame or two and a
 * bare `waitFor("h1")` resolves against the page we just left.
 */
export async function gotoRoute(page: Page, route: Route): Promise<void> {
  if (page.url().startsWith("http")) {
    await page.evaluate((id) => {
      window.location.hash = `#${id}`;
    }, route.id);
  } else {
    await page.goto(`/#${route.id}`);
  }
  await expect(page.locator("main h1")).toHaveText(new RegExp(`^${escapeRegExp(route.h1)}`));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * POST /api/scope from a test, through the unattended-caller gate (internal/web/confirm_gate.go,
 * burpsy-react-ui-ejp5): a token minted for exactly this call at /api/scope/confirm, spent in the
 * X-Burpsy-Confirm header — the flow a scripted caller uses in production.
 *
 * Every test-side scope write goes through here, and the result is asserted. Before the gate existed
 * a bare `page.request.post("/api/scope", ...)` worked; after it, the same call was refused and
 * nothing looked at the status, so a "clear" in a finally block quietly cleared nothing and one
 * spec's include rule leaked into every later spec (found when the suite first ran in CI, bead
 * e2eorph: the Scope specs saw 2 rules where they expected 0).
 */
export async function scopeCall(page: Page, action: Record<string, unknown>): Promise<void> {
  const response = await confirmedPost(page, "/api/scope", action);
  expect(response.ok(), `POST /api/scope ${JSON.stringify(action)}: ${response.status()} ${await response.text()}`).toBe(true);
}

/**
 * POST to any gated route (/api/scope, /api/crawl, ...: needsConfirmation in internal/web) with a
 * token minted at `${url}/confirm` for exactly this body. Returns the response for the caller to
 * assert on; a refused mint fails here.
 */
export async function confirmedPost(page: Page, url: string, data: Record<string, unknown>) {
  const body = JSON.stringify(data);
  const confirm = await page.request.post(`${url}/confirm`, { data: { method: "POST", url, body } });
  expect(confirm.ok(), `minting a confirmation for ${url} ${body}: ${confirm.status()}`).toBe(true);
  const { token } = (await confirm.json()) as { token: string };
  return page.request.post(url, { data: body, headers: { "X-Burpsy-Confirm": token, "content-type": "application/json" } });
}

/** Wait for the shell itself — used by tests that do not care which route they land on. */
export async function gotoApp(page: Page, route = ROUTES[0]!): Promise<void> {
  await page.goto(`/#${route.id}`);
  await expect(page.locator("header.toolbar-row")).toBeVisible();
  await expect(page.locator("main h1")).toBeVisible();
}

/**
 * The active pane of a Radix Tabs group.
 *
 * Radix keeps inactive panes mounted and marks them `hidden`, so `.tool-pane` matches several
 * elements and `.first()` is whichever the DOM happens to list first — usually an inactive one. That
 * makes a working tab group read as broken. Always go through this.
 */
export function activePane(page: Page) {
  return page.locator(".tool-pane:not([hidden])");
}
