// The UAT smoke (burpsy-react-ui-uat2): one short operator flow, run by the pipeline on every change.
//
//   cd burpsy-go/internal/web/ui/e2e && npm ci && npx playwright install chromium && npm run uat
//
// Same harness as the full suite (harness/global-setup.ts builds and seeds a real burpsy-go; no mocks).
//
// Browser choice, given the CI Chrome start-up flakiness history (burpsy-react-ui-2o0c): set
// BURPSY_UAT_CHROME=/path/to/chrome to drive an installed Chrome/Chromium instead of Playwright's
// download; otherwise Playwright's own Chromium is used. In CI containers set BURPSY_UAT_NO_SANDBOX=1.
// `launch.timeout` is generous because "websocket url timeout" on a cold runner is the known failure,
// and a retry is NOT used: a retry that goes green hides a flake. A failure prints the trace.

import { defineConfig, devices } from "@playwright/test";

const executablePath = process.env.BURPSY_UAT_CHROME || undefined;
const args = process.env.BURPSY_UAT_NO_SANDBOX ? ["--no-sandbox", "--disable-dev-shm-usage"] : [];

export default defineConfig({
  testDir: "./specs-uat",
  outputDir: "./artifacts/uat-results",
  globalSetup: "./harness/global-setup.ts",
  globalTeardown: "./harness/global-teardown.ts",
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"], ["junit", { outputFile: "./artifacts/uat-junit.xml" }]],
  timeout: 90_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: process.env.BURPSY_E2E_BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ...devices["Desktop Chrome"],
    viewport: { width: 1440, height: 900 },
    launchOptions: { executablePath, args, timeout: 60_000 },
  },
  projects: [{ name: "chromium" }],
});
