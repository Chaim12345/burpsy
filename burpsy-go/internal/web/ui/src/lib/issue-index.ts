/**
 * Pure reads over an issues document. The worker and the main thread share this so a fallback
 * (no worker, or the worker script failed to load) cannot sort or slice differently from the
 * worker. JSON.parse of the whole list used to run on the main thread, inside the click that
 * opened Issues; the worker does that parse and posts the rows back in small chunks.
 */
import { taskActivityFindings } from "./task-activity";
import { SEVERITY_KEYS, severityKey } from "./severity";
import type { FindingDetail, IssuesDetail } from "./types.attack";

/** How many findings one worker message carries. Small enough that receiving it is not a long task. */
export const ISSUE_CHUNK = 200;

/** Worst-first rank. Unknown severities sort after every known one, matching the dock. */
export function issueSeverityRank(severity: string): number {
 const key = severityKey(severity);
 return key ? SEVERITY_KEYS.indexOf(key) : SEVERITY_KEYS.length;
}

export function readIssueDocument(text: string): IssuesDetail {
 const data = JSON.parse(text) as Partial<IssuesDetail>;
 return {
  enabled: data.enabled === true,
  hint: data.hint,
  loaded: data.loaded,
  counts: data.counts,
  findings: Array.isArray(data.findings) ? data.findings : [],
 };
}

/** The dock's short list: worst first, original order kept for equal severity, then cut. */
export function topFindings(findings: readonly FindingDetail[], limit: number): FindingDetail[] {
 const indexed = findings.map((finding, index) => ({ finding, index }));
 indexed.sort((a, b) => issueSeverityRank(a.finding.severity) - issueSeverityRank(b.finding.severity) || a.index - b.index);
 const cap = Math.max(0, limit);
 return indexed.slice(0, cap).map((row) => row.finding);
}

export function taskFindings(findings: readonly FindingDetail[], taskId: number, limit: number) {
 return taskActivityFindings(findings, taskId, limit);
}
