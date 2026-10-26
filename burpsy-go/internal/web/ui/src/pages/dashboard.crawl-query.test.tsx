// The Dashboard's task detail asked GET /api/crawl?task=<id> for every task, so a task with no retained
// crawl run (the seeded scan in the UAT harness) answered 404 on every Dashboard load. The shell already
// keeps the retained-run list (GET /api/crawl), and the server answers ?task= from the same registry, so
// the detail is requested only for a task that list names. Run with `bun run test:components`.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, screen } from "@testing-library/react";
import { renderWithProviders } from "../../test/render";
import { DashboardPage } from "./dashboard";

const originalFetch = globalThis.fetch;
let urls: string[] = [];
let retained: { task_id: number; state: string; kind: string }[] = [];
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

const TASK = {
 id: 1,
 kind: "scan",
 target: "http://t.test",
 state: "done",
 done: 1,
 total: 1,
 fraction: 1,
 fraction_known: true,
 cancellable: false,
};
const DASHBOARD = {
 summaries: [],
 tasks: [TASK],
 tasks_running: 0,
 activity: [],
 events: [],
 events_shown: 0,
 events_total: 0,
 events_dropped: 0,
 exchanges: 0,
 messages: 0,
 sources: {},
 paused: false,
};

beforeEach(() => {
 urls = [];
 retained = [];
 window.localStorage.clear();
 globalThis.fetch = (async (input: RequestInfo | URL) => {
  const url = new URL(String(input), "http://localhost");
  urls.push(url.pathname + url.search);
  if (url.pathname === "/api/dashboard") return json(DASHBOARD);
  if (url.pathname === "/api/crawl") {
   if (url.searchParams.get("task")) return new Response("No crawl is retained", { status: 404 });
   return json({ crawls: retained });
  }
  return json({});
 }) as typeof fetch;
});
afterEach(() => {
 cleanup();
 globalThis.fetch = originalFetch;
});

describe("Dashboard task detail and /api/crawl?task=", () => {
 test("a task the retained-run list does not name is never asked for (no 404)", async () => {
  renderWithProviders(<DashboardPage />);
  await screen.findAllByText(/scan/i);
  await new Promise((r) => setTimeout(r, 200));
  expect(urls).toContain("/api/crawl");
  expect(urls.filter((u) => u.startsWith("/api/crawl?task="))).toEqual([]);
 });

 test("a task the list names is still fetched, so its report and definition reach the detail", async () => {
  retained = [{ task_id: 1, state: "done", kind: "api-scan" }];
  renderWithProviders(<DashboardPage />);
  await screen.findAllByText(/scan/i);
  await new Promise((r) => setTimeout(r, 300));
  expect(urls.filter((u) => u.startsWith("/api/crawl?task=1"))).not.toEqual([]);
 });
});
