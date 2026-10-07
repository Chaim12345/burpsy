// Playwright configuration for the burpsy console suite.
//
// Run it through ../../../../../e2e-ui.sh (repo root), not directly: that wrapper is where "no browser
// installed" turns into a SKIP with a reason rather than a wall of Playwright output. Running
// `npx playwright test` here works fine for iterating.
//
// This suite is no longer the UI gate — the live browser pass is (`ui-live.sh` plus
// burpsy-go/docs/UI-VERIFICATION.md). What it still is, and why it is kept: the screenshot artifacts,
// and a second, differently-shaped opinion on the console. verify.sh skips it deliberately; run it
// when you want either of those.
//
// The suite drives a real burpsy-go — built, started and seeded with real proxy traffic by
// harness/global-setup.ts. There is no mock server and no fixture JSON: a console asserted against
// invented data proves the console can render invented data.

import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./specs",
  // Kept out of the tree's committed content; .gitignore has the matching entries.
  outputDir: "./artifacts/test-results",
  snapshotDir: "./artifacts/snapshots",

  globalSetup: "./harness/global-setup.ts",
  globalTeardown: "./harness/global-teardown.ts",

  // One worker, on purpose. Every test shares one burpsy process holding one exchange store, so a
  // parallel run has tests seeing each other's traffic — and "did sorting reorder the rows" turns
  // into a race against another worker adding a row. Serial is slower and honest.
  workers: 1,
  fullyParallel: false,

  // No retries. A retry that goes green hides a flake, and this suite exists to produce trustworthy
  // signal about the UI rather than a green tick.
  retries: 0,

  reporter: [["list"], ["html", { outputFolder: "./artifacts/report", open: "never" }]],

  timeout: 40_000,
  expect: { timeout: 10_000 },

  use: {
    // globalSetup picks the port, so it cannot be a literal here.
    baseURL: process.env.BURPSY_E2E_BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
    ...devices["Desktop Chrome"],
    // The desktop default. screenshots.spec.ts overrides per test for the 390x844 pass.
    viewport: { width: 1440, height: 900 },
  },

  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
});
