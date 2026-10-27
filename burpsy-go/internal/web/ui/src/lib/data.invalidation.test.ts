// Which caches a server event refreshes. The Dashboard asks for a task's crawl run only when the
// retained-run list (["crawls"]) names it. The server emits no "task" frame: a task starting or finishing
// is a "dashboard" frame (dash.Registry.Start records an event, whose OnChange fires changeDashboard, and a
// crawl notifies it again on finish), so that is the kind that has to refresh the list.
import { describe, expect, test } from "bun:test";
import { INVALIDATION } from "./data";

describe("dashboard events and the retained-run list", () => {
 test("a dashboard frame refreshes the dashboard and the retained-run list", () => {
  expect(INVALIDATION.dashboard).toContainEqual(["dashboard"]);
  expect(INVALIDATION.dashboard).toContainEqual(["crawls"]);
 });
});
