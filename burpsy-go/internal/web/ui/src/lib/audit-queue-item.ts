/**
 * How one audit item's progress and timing read (burpsy-react-ui-xdtx).
 *
 * Extracted from the page so the two distinctions the engine's own comments insist on are testable
 * rather than buried in JSX: a plan of zero is not a plan that ran nothing, and a finished item is
 * not necessarily 100% audited.
 */

/** The two fields these read, as a narrow structural type — the row carries far more. */
export interface AuditItemProgressFields {
 steps_planned?: number;
 steps_done?: number;
 queued_unix_ms?: number;
 updated_unix_ms?: number;
}

/**
 * "done/planned steps (n%)", or "not planned".
 *
 * A zero denominator reads "not planned" because StepsPlanned is zero for an item refused BEFORE
 * planning — a different fact from a plan of length zero that ran to completion, and one the
 * engine's AuditItem comment spells out. Reporting it as 0% would say the item did nothing, when it
 * may never have been given work.
 *
 * No clamping. An item that did more steps than it planned is reported as it is, because a plan can
 * grow when a breaker opens and a clamped 100% would hide the denominator moving — which is the
 * number an operator needs when an item's accounting does not add up.
 */
export function itemProgress(item: AuditItemProgressFields): string {
 const planned = item.steps_planned ?? 0;
 const done = item.steps_done ?? 0;
 if (planned === 0) return "not planned";
 return `${done}/${planned} steps (${Math.round((done / planned) * 100)}%)`;
}

/**
 * "queued → updated" in local time, the queue time alone when the row has not moved, and "" when
 * there is no timestamp at all — which the page renders as an em dash rather than as a wrong time.
 *
 * The range is the point: it is the only way to tell a slow item from a stalled one, which is the
 * question a partial audit actually raises.
 */
export function itemTiming(item: AuditItemProgressFields): string {
 const queued = item.queued_unix_ms;
 if (!queued) return "";
 const at = (ms: number) => new Date(ms).toLocaleTimeString();
 const updated = item.updated_unix_ms;
 return updated && updated !== queued ? `${at(queued)} → ${at(updated)}` : at(queued);
}
