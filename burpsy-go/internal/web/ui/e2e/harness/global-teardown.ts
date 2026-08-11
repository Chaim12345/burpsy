import { readHarness, stop } from "./server";

/**
 * Runs once, after every worker has finished — including after a failing run, which is when leaving
 * a burpsy holding 182xx would be most annoying. The state file is the handoff: teardown is a
 * separate invocation from setup and shares nothing else with it.
 */
export default async function globalTeardown(): Promise<void> {
  try {
    stop(readHarness());
  } catch {
    // No state file means setup never got far enough to start anything. Nothing to clean up, and
    // throwing here would replace setup's real error with a misleading one.
  }
}
