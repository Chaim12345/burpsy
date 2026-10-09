import { describe, expect, test } from "bun:test";
import { EVENT_LOG_FILTER_DEFAULTS, EVENT_SEVERITY_OPTIONS, eventSource, filterEvents, isFiltered, severityCounts } from "./event-log-filter";
import type { ToolEvent } from "./types";

const tasks = [
 { id: 3, kind: "crawl", target: "https://demo.local/" },
 { id: 4, kind: "scan", target: "https://shop.local/" },
];

const events: ToolEvent[] = [
 { id: 1, kind: "task.started", severity: "info", detail: "crawl started", task_id: 3, at_ms: 1 },
 { id: 2, kind: "scope.changed", severity: "info", detail: "include https://demo.local/", at_ms: 2 },
 { id: 3, kind: "crawl.bounded", severity: "warn", detail: "stopped at max depth", task_id: 3, at_ms: 3 },
 { id: 4, kind: "task.finished", severity: "error", detail: "connection refused", task_id: 4, at_ms: 4 },
 { id: 5, kind: "task.finished", severity: "info", detail: "done", task_id: 9, at_ms: 5 },
];

const ids = (list: ToolEvent[]) => list.map((event) => event.id);

describe("the event log's filters", () => {
 test("the defaults keep every event", () => {
  expect(ids(filterEvents(events, EVENT_LOG_FILTER_DEFAULTS, tasks))).toEqual([1, 2, 3, 4, 5]);
  expect(isFiltered(EVENT_LOG_FILTER_DEFAULTS)).toBe(false);
 });

 test("offers exactly the three severities the Go log emits, plus all", () => {
  expect(EVENT_SEVERITY_OPTIONS.map((option) => option.value)).toEqual(["all", "error", "warn", "info"]);
 });

 test("a severity keeps only that level", () => {
  expect(ids(filterEvents(events, { ...EVENT_LOG_FILTER_DEFAULTS, severity: "warn" }, tasks))).toEqual([3]);
  expect(ids(filterEvents(events, { ...EVENT_LOG_FILTER_DEFAULTS, severity: "error" }, tasks))).toEqual([4]);
  expect(ids(filterEvents(events, { ...EVENT_LOG_FILTER_DEFAULTS, severity: "info" }, tasks))).toEqual([1, 2, 5]);
 });

 test("search is case-insensitive over kind, detail and source", () => {
  expect(ids(filterEvents(events, { ...EVENT_LOG_FILTER_DEFAULTS, search: "BOUNDED" }, tasks))).toEqual([3]);
  expect(ids(filterEvents(events, { ...EVENT_LOG_FILTER_DEFAULTS, search: "refused" }, tasks))).toEqual([4]);
  // The source label: the task's target is searchable though it is in no event's own text.
  expect(ids(filterEvents(events, { ...EVENT_LOG_FILTER_DEFAULTS, search: "shop.local" }, tasks))).toEqual([4]);
  expect(ids(filterEvents(events, { ...EVENT_LOG_FILTER_DEFAULTS, search: "  " }, tasks))).toEqual([1, 2, 3, 4, 5]);
  expect(isFiltered({ ...EVENT_LOG_FILTER_DEFAULTS, search: "  " })).toBe(false);
 });

 test("a source keeps only that task's events, and filters combine", () => {
  expect(ids(filterEvents(events, { ...EVENT_LOG_FILTER_DEFAULTS, source: 3 }, tasks))).toEqual([1, 3]);
  expect(ids(filterEvents(events, { severity: "warn", search: "", source: 3 }, tasks))).toEqual([3]);
  expect(ids(filterEvents(events, { severity: "error", search: "", source: 3 }, tasks))).toEqual([]);
  expect(isFiltered({ ...EVENT_LOG_FILTER_DEFAULTS, source: 3 })).toBe(true);
 });

 test("the Source column names the task, a task no longer listed by id, and no task as such", () => {
  expect(eventSource(events[0]!, tasks)).toBe("Task 3 · crawl (https://demo.local/)");
  expect(eventSource(events[4]!, tasks)).toBe("Task 9");
  expect(eventSource(events[1]!, tasks)).toBe("not a task");
 });

 test("counts each severity for the filter's labels", () => {
  expect(severityCounts(events)).toEqual({ error: 1, warn: 1, info: 3 });
 });
});
