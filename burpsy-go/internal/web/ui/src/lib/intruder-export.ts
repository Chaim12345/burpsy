/**
 * Exporting an Intruder attack out of burpsy (burpsy-react-ui-pf4).
 *
 * Two documents leave the Results tab. The JSON one is the RunView the server
 * already answered /run with — report, examples and payload sets, self-describing
 * and bounded exactly as the page renders it. The CSV one is the flat per-attempt
 * sheet a Burp user will ask for by name, and because a flat sheet has nowhere to
 * hide the attack's bounds, the caveat block rides at the top of the file: a
 * truncated or unbucketed attack cannot download as a complete result set.
 *
 * Both build from data the page already holds — no server round trip — so an
 * export always matches what the operator is looking at.
 */
import { csvCell } from "./api";
import { describeCaptureFilter } from "./intruder-capture";
import {
  assignmentAt,
  planSetLengths,
  resolvePayloads,
  type Attempt,
  type AttackMode,
  type AttackReport,
  type PayloadSetReport,
  type ResolvedPayload,
} from "./types.tools";

/** What the page knows about the payload sets at launch, structurally — the store's snapshot shape without importing it. */
export interface ResolverSnapshot {
  mode: AttackMode;
  points: number;
  sets: (string[] | null)[];
}

/**
 * The text a payload cell shows: resolved parts joined, position-only references
 * for parts whose text never crossed the wire, and "(empty)" for a part that was
 * the empty string. Shared by the table and the CSV so the two cannot disagree.
 */
export function payloadLabelText(parts: ResolvedPayload[]): string {
  if (!parts.length) return "";
  return parts
    .map((part) => (part.text === null ? `set ${part.set + 1} payload #${part.index + 1}` : part.text === "" ? "(empty)" : part.text))
    .join(" | ");
}

/** payloadLabel as the page renders it: the text plus whether every part is real payload text. */
export function payloadLabel(parts: ResolvedPayload[]): { text: string; complete: boolean } {
  if (!parts.length) return { text: "", complete: false };
  return { text: payloadLabelText(parts), complete: parts.every((part) => part.text !== null) };
}

/**
 * Decode an attempt ordinal into its payload combination.
 *
 * The server sends an `examples` entry for every ordinal it kept a row for — every
 * bucket's first ordinal, and every attempt in the (detail-limited) attempts table —
 * resolved server-side from the post-processing-rule payload sets (api_tools.go's
 * payloadsAt), so a rule that transforms bytes without dropping any (add_prefix,
 * hash, …) still names the payload that was actually sent. That covers every row
 * the page renders; the fallback recomputes the ordinal from the plan — pure
 * arithmetic on the index, which is what internal/intruder/plan.go's Fill is — for
 * an ordinal outside what Examples carries. A set whose server-reported count
 * disagrees with the browser's list is a set whose indices moved — a processing
 * rule skipped a payload — so its text is treated as unknown.
 */
export function intruderPayloadResolver(args: {
  report: AttackReport;
  sets: PayloadSetReport[];
  examples: Map<number, string[]>;
  snapshot: ResolverSnapshot | null;
}): (ordinal: number) => ResolvedPayload[] | null {
  const { report, sets, examples, snapshot } = args;
  const setCounts = sets.map((set) => set.count);
  const mode = snapshot?.mode ?? report.kind;
  const points = snapshot?.points ?? 0;
  const lengths = planSetLengths(mode, points, setCounts);
  const known = setCounts.map((count, index) => {
    const items = snapshot?.sets[index] ?? null;
    return items && items.length === count ? items : null;
  });
  return (ordinal: number): ResolvedPayload[] | null => {
    const fromServer = examples.get(ordinal);
    // An empty example list is the server saying it could not place that ordinal either, so it
    // must fall through to "unknown" rather than render as a blank payload.
    if (fromServer?.length) return fromServer.map((text, index) => ({ set: index, index: -1, text }));
    const slots = assignmentAt(mode, points, lengths, report.planned, ordinal);
    if (!slots || !slots.length) return null;
    return resolvePayloads(slots, known);
  };
}

/**
 * The flat per-attempt sheet.
 *
 * The caveat block comes before the header row, as `#` comment lines: truncated,
 * buckets_truncated, unbucketed and detail_limit are exactly the bounds that make a
 * capped attack look complete when they are missing, so they are always written —
 * `false` included — and the detail_limit line says outright that rows beyond it
 * were not kept once the attempts table reached that bound.
 *
 * `comments` is the Results tab's browser-only annotations (burpsy-react-ui-c7w6), keyed by
 * ordinal exactly like `payloadAt` — it rides in last, and defaults to empty, so every existing
 * caller (and every fixture in this file's own tests) that never heard of comments keeps
 * producing the same sheet it always did.
 */
export function intruderReportToCSV(
  report: AttackReport,
  attempts: Attempt[],
  payloadAt: (ordinal: number) => ResolvedPayload[] | null,
  now = new Date(),
  comments: Map<number, string> = new Map(),
): string {
  const stopped = report.status === "stopped" && report.stop_reason ? ` — ${report.stop_reason}` : "";
  const capped = attempts.length >= report.detail_limit;
  const caveats = [
    `# burpsy intruder attack — ${report.kind}`,
    `# exported: ${now.toISOString()}`,
    `# status: ${report.status ?? "completed"}${stopped}`,
    `# planned: ${report.planned} of ${report.combinations_exact ? "" : ">= "}${report.combinations} combinations; enumerated: ${report.enumerated ?? report.planned}; sent: ${report.sent}; failed: ${report.failed}`,
    `# truncated: ${report.truncated} (max_requests: ${report.max_requests})`,
    `# buckets_truncated: ${report.buckets_truncated}; unbucketed: ${report.unbucketed}`,
    capped
      ? `# detail_limit: ${report.detail_limit} — per-attempt rows beyond this were not kept`
      : `# detail_limit: ${report.detail_limit}`,
    // Store requests / responses (nqww): an empty Response ID column is the attack's own setting.
    ...(report.requests_stored === false || report.responses_stored === false
      ? [
          `# stored: requests ${report.requests_stored === false ? "no" : "yes"}, responses ${
            report.responses_stored === false ? "no" : "yes"
          } — empty ids below are the attack's storage setting, not missing responses`,
        ]
      : []),
    // The capture filter (ip2b): the rows below are the captured items only, and this says so.
    ...(report.capture_filter
      ? [
          `# capture_filter: ${describeCaptureFilter(report.capture_filter)}; discarded: ${report.discarded ?? 0} — counted in sent/failed, not written below`,
        ]
      : []),
  ];
  const headers = [
    "Ordinal",
    "Payload",
    "Status",
    "Time of day",
    "Length",
    "Duration (ms)",
    "Reflected",
    "Grep matched",
    "Grep extract",
    "Error",
    "Timeout",
    "Cookies",
    "Response ID",
    "Comment",
  ];
  const rows = attempts.map((attempt) => {
    const parts = payloadAt(attempt.ordinal);
    return [
      attempt.ordinal,
      parts ? payloadLabelText(parts) : "",
      attempt.status ?? "",
      attempt.time_of_day,
      attempt.response_len,
      attempt.duration_ms,
      attempt.reflected ? "yes" : "no",
      attempt.grep_matched === null || attempt.grep_matched === undefined ? "" : attempt.grep_matched ? "yes" : "no",
      attempt.grep_extract ?? "",
      attempt.error ?? "",
      attempt.timeout ? "yes" : "no",
      attempt.cookies.join("; "),
      attempt.response_id ?? "",
      comments.get(attempt.ordinal) ?? "",
    ];
  });
  return [...caveats, headers.map(csvCell).join(","), ...rows.map((row) => row.map(csvCell).join(","))].join("\n");
}

/**
 * Download filenames for the two exports. The stem names the attack (kind and
 * planned count) and the minute it was taken; colons are replaced because they
 * are illegal in Windows filenames and ISO timestamps are full of them.
 */
export function intruderExportFilenames(report: AttackReport, now = new Date()): { csv: string; json: string } {
  const stamp = now.toISOString().replace(/:/g, "-").replace(/\.\d+Z$/, "");
  const stem = `intruder-${report.kind}-${report.planned}-${stamp}`;
  return { csv: `${stem}.csv`, json: `${stem}.json` };
}
