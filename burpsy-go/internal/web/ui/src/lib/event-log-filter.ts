// The dashboard event log's filters and Source column (burpsy-react-ui-lxqq).
//
// Burp's event log filters by type and searches; burpsy's dash.EventLog has three severities —
// info, warn, error (internal/dash/events.go) — so those are the levels offered. Burp's Critical
// and Debug have no counterpart on the wire, and a filter for a level nothing emits would always
// answer "no events", which reads as "nothing went wrong" rather than "this level does not exist".

import type { TaskRow, ToolEvent } from "./types";

export type EventSeverityFilter = "all" | "error" | "warn" | "info";

export const EVENT_SEVERITY_OPTIONS: { value: EventSeverityFilter; label: string }[] = [
 { value: "all", label: "All severities" },
 { value: "error", label: "Error" },
 { value: "warn", label: "Warning" },
 { value: "info", label: "Info" },
];

/** "all" for every source, or a task id to keep only that task's events. */
export type EventSourceFilter = "all" | number;

export interface EventLogFilter {
 severity: EventSeverityFilter;
 /** Case-insensitive substring over the kind, the detail and the Source label. */
 search: string;
 source: EventSourceFilter;
}

export const EVENT_LOG_FILTER_DEFAULTS: EventLogFilter = { severity: "all", search: "", source: "all" };

/**
 * What the Source column says for an event: the task it is about, by the name the task list
 * shows, or that it is about no task. A task id the list no longer holds (the task was deleted)
 * still names the id rather than pretending the event had no source.
 */
export function eventSource(event: Pick<ToolEvent, "task_id">, tasks: Pick<TaskRow, "id" | "kind" | "target">[]): string {
 const id = event.task_id ?? 0;
 if (id <= 0) return "not a task";
 const task = tasks.find((candidate) => candidate.id === id);
 return task ? `Task ${id} · ${task.kind} (${task.target})` : `Task ${id}`;
}

export function filterEvents<E extends ToolEvent>(
 events: E[],
 filter: EventLogFilter,
 tasks: Pick<TaskRow, "id" | "kind" | "target">[],
): E[] {
 const needle = filter.search.trim().toLowerCase();
 return events.filter((event) => {
  if (filter.severity !== "all" && event.severity !== filter.severity) return false;
  if (filter.source !== "all" && (event.task_id ?? 0) !== filter.source) return false;
  if (needle === "") return true;
  return (
   event.kind.toLowerCase().includes(needle) ||
   event.detail.toLowerCase().includes(needle) ||
   eventSource(event, tasks).toLowerCase().includes(needle)
  );
 });
}

/** How many events each severity has, for the filter's option labels. */
export function severityCounts(events: Pick<ToolEvent, "severity">[]): Record<Exclude<EventSeverityFilter, "all">, number> {
 const counts = { error: 0, warn: 0, info: 0 };
 for (const event of events) {
  if (event.severity === "error" || event.severity === "warn" || event.severity === "info") counts[event.severity]++;
 }
 return counts;
}

/** Whether any filter narrows the list, so an empty result can say "filtered" instead of "empty". */
export function isFiltered(filter: EventLogFilter): boolean {
 return filter.severity !== "all" || filter.search.trim() !== "" || filter.source !== "all";
}
