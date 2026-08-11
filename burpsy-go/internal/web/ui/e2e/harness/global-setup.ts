import { start } from "./server";

/**
 * Runs once, before any worker starts. Mutating process.env here is the documented way to hand a
 * dynamically chosen baseURL to the workers: they are forked from this process after globalSetup
 * returns, so they inherit it.
 */
export default async function globalSetup(): Promise<void> {
  const harness = await start();
  process.env.BURPSY_E2E_BASE_URL = `http://127.0.0.1:${harness.webPort}`;
  process.env.BURPSY_E2E_WEB_PORT = String(harness.webPort);
  process.env.BURPSY_E2E_ORIGIN_PORT = String(harness.targetPort);
}
