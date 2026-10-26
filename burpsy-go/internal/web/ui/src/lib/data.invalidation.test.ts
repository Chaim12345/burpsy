// Which caches a server event refreshes. The Dashboard asks for a task's crawl run only when the
// retained-run list (["crawls"]) names it, so a task event has to refresh that list too, or a run
// registered after the first load would stay hidden until something else refetched it.
import { describe, expect, test } from "bun:test";
import { INVALIDATION } from "./data";

describe("task events and the retained-run list", () => {
 for (const kind of ["task", "tasks"]) {
  test(`${kind} refreshes the dashboard and the retained-run list`, () => {
   expect(INVALIDATION[kind]).toContainEqual(["dashboard"]);
   expect(INVALIDATION[kind]).toContainEqual(["crawls"]);
  });
 }
});
