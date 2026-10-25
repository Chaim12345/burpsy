import { describe, expect, it } from "bun:test";
import {
  intruderExportFilenames,
  intruderPayloadResolver,
  intruderReportToCSV,
  payloadLabel,
  payloadLabelText,
} from "./intruder-export";
import type { AttackReport, PayloadSetReport, ResolvedPayload } from "./types.tools";

function report(overrides: Partial<AttackReport> = {}): AttackReport {
  return {
    kind: "sniper",
    combinations: 3,
    combinations_exact: true,
    max_requests: 0,
    truncated: false,
    planned: 3,
    status: "completed",
    enumerated: 3,
    sent: 3,
    failed: 0,
    elapsed_ms: 120,
    buckets: [],
    buckets_truncated: false,
    unbucketed: 0,
    errors: [],
    attempts: [
      {
        ordinal: 0, status: 200, response_len: 10, duration_ms: 5, reflected: false, request_id: null,
        response_id: 7, error: null, grep_matched: null, grep_extract: null,
        grep_match_counts: [],
        time_of_day: "2026-09-07T12:00:00.000Z", cookies: [], timeout: false,
      },
      {
        ordinal: 1, status: 403, response_len: 20, duration_ms: 6, reflected: true, request_id: null,
        response_id: null, error: null, grep_matched: true, grep_extract: "tok",
        grep_match_counts: [],
        time_of_day: "2026-09-07T12:00:01.000Z", cookies: ["sessid", "csrf"], timeout: false,
      },
    ],
    detail_limit: 500,
    grep_matched: 0,
    pool: null,
    auto_throttle_engaged: 0,
    retries_used: 0,
    baseline: false,
    ...overrides,
  };
}

const resolveNothing = (): ResolvedPayload[] | null => null;
const fixedParts: ResolvedPayload[] = [
  { set: 0, index: 0, text: "admin" },
  { set: 1, index: 3, text: null },
];
const resolveFixed = (): ResolvedPayload[] | null => fixedParts;

describe("payloadLabelText", () => {
  it("joins resolved parts and names the ones the wire never carried", () => {
    expect(payloadLabelText(fixedParts)).toBe("admin | set 2 payload #4");
  });

  it("shows (empty) for a part that is the empty string, never a blank", () => {
    expect(payloadLabelText([{ set: 0, index: 0, text: "" }])).toBe("(empty)");
  });

  it("is empty for no parts, and payloadLabel marks it incomplete", () => {
    expect(payloadLabelText([])).toBe("");
    expect(payloadLabel([])).toEqual({ text: "", complete: false });
  });
});

describe("intruderReportToCSV", () => {
  it("writes the caveat block, the header row and one quoted row per attempt", () => {
    const csv = intruderReportToCSV(report(), report().attempts, resolveFixed, new Date("2026-09-07T12:00:00Z"));
    const lines = csv.split("\n");
    expect(lines[0]).toBe("# burpsy intruder attack — sniper");
    expect(lines[1]).toBe("# exported: 2026-09-07T12:00:00.000Z");
    expect(lines[2]).toBe("# status: completed");
    expect(lines[3]).toBe("# planned: 3 of 3 combinations; enumerated: 3; sent: 3; failed: 0");
    expect(lines[4]).toBe("# truncated: false (max_requests: 0)");
    expect(lines[5]).toBe("# buckets_truncated: false; unbucketed: 0");
    expect(lines[6]).toBe("# detail_limit: 500");
    expect(lines[7]).toContain(
      '"Ordinal","Payload","Status","Time of day","Length","Duration (ms)","Reflected","Grep matched","Grep extract","Error","Timeout","Cookies","Response ID","Comment"',
    );
    expect(lines[8]).toBe('"0","admin | set 2 payload #4","200","2026-09-07T12:00:00.000Z","10","5","no","","","","no","","7",""');
    expect(lines[9]).toBe('"1","admin | set 2 payload #4","403","2026-09-07T12:00:01.000Z","20","6","yes","yes","tok","","no","sessid; csrf","",""');
    expect(lines).toHaveLength(10);
  });

  it("records a stopped attack and its reason so a prefix cannot read as the whole plan", () => {
    const csv = intruderReportToCSV(report({ status: "stopped", stop_reason: "stopped by operator", enumerated: 2, planned: 200000, sent: 2 }), report().attempts, resolveNothing);
    expect(csv.split("\n")[2]).toBe("# status: stopped — stopped by operator");
    expect(csv.split("\n")[3]).toContain("enumerated: 2");
  });

  it("carries the truncation caveats a capped attack needs, including the detail-limit line", () => {
    const capped = report({
      truncated: true,
      max_requests: 2,
      combinations: 4096,
      combinations_exact: false,
      buckets_truncated: true,
      unbucketed: 7,
      detail_limit: 2,
    });
    const csv = intruderReportToCSV(capped, capped.attempts, resolveNothing);
    expect(csv.split("\n")[3]).toBe("# planned: 3 of >= 4096 combinations; enumerated: 3; sent: 3; failed: 0");
    expect(csv.split("\n")[4]).toBe("# truncated: true (max_requests: 2)");
    expect(csv.split("\n")[5]).toBe("# buckets_truncated: true; unbucketed: 7");
    expect(csv.split("\n")[6]).toBe("# detail_limit: 2 — per-attempt rows beyond this were not kept");
  });

  it("escapes quotes, commas and newlines in payload text so spreadsheets round-trip it", () => {
    const row: ResolvedPayload[] = [{ set: 0, index: 0, text: 'a,b"c\nd' }];
    const csv = intruderReportToCSV(report(), report().attempts, () => row);
    // The payload's newline stays inside the quoted cell — a real CSV parser reads this
    // as one row, so assert on the row text rather than on a split line.
    expect(csv).toContain('"0","a,b""c\nd","200","2026-09-07T12:00:00.000Z","10","5","no","","","","no","","7",""');
  });

  it("leaves the payload cell empty when the ordinal cannot be placed at all", () => {
    const csv = intruderReportToCSV(report(), report().attempts, resolveNothing);
    expect(csv.split("\n")[8]).toBe('"0","","200","2026-09-07T12:00:00.000Z","10","5","no","","","","no","","7",""');
  });

  it("carries a browser-only comment keyed by ordinal, and leaves an uncommented row blank", () => {
    // The control this proves is wired: intruder.tsx's per-row comment input writes into exactly
    // this map, and this is the only place that map's contents ever reach a durable artifact — an
    // export nobody can prove reads the operator's typing is a control wired to nothing.
    const csv = intruderReportToCSV(report(), report().attempts, resolveNothing, new Date("2026-09-07T12:00:00Z"), new Map([[1, "looks like an IDOR"]]));
    const lines = csv.split("\n");
    expect(lines[8]).toBe('"0","","200","2026-09-07T12:00:00.000Z","10","5","no","","","","no","","7",""');
    expect(lines[9]).toBe('"1","","403","2026-09-07T12:00:01.000Z","20","6","yes","yes","tok","","no","sessid; csrf","","looks like an IDOR"');
  });

  it("names the capture filter and what it discarded, so the captured rows cannot read as the whole attack (ip2b)", () => {
    const filtered = report({
      sent: 5,
      discarded: 3,
      capture_filter: { discard_no_response: false, term: "", regex: false, case_sensitive: false, negate: false, statuses: ["2xx"] },
    });
    const lines = intruderReportToCSV(filtered, filtered.attempts, resolveNothing).split("\n");
    expect(lines[7]).toBe("# capture_filter: Discarding 3xx, 4xx, 5xx; discarded: 3 — counted in sent/failed, not written below");
    expect(lines[8]).toStartWith('"Ordinal"');
    // No filter, no line: the sheet every existing export produced is unchanged.
    expect(intruderReportToCSV(report(), report().attempts, resolveNothing).split("\n")[7]).toStartWith('"Ordinal"');
  });

  it("says when empty ids are the attack's storage setting (nqww)", () => {
    const unstored = report({ requests_stored: true, responses_stored: false });
    const lines = intruderReportToCSV(unstored, unstored.attempts, resolveNothing).split("\n");
    expect(lines[7]).toBe("# stored: requests yes, responses no — empty ids below are the attack's storage setting, not missing responses");
    expect(intruderReportToCSV(report({ requests_stored: true, responses_stored: true }), report().attempts, resolveNothing).split("\n")[7]).toStartWith('"Ordinal"');
  });

  it("guards a comment beginning with = so Excel reads text, not a formula", () => {
    const csv = intruderReportToCSV(report(), report().attempts, resolveNothing, new Date(), new Map([[0, "=cmd|'/c calc'!A0"]]));
    expect(csv).toContain("\"'=cmd|'/c calc'!A0\"");
  });
});

describe("intruderPayloadResolver", () => {
  const sets = [{ kind: "simple", count: 3, total: 3, total_exact: true, truncated: false, max_count: 0, skipped: 0, dropped: [] } satisfies PayloadSetReport];

  it("prefers a server example when one names the ordinal", () => {
    const at = intruderPayloadResolver({
      report: report(),
      sets,
      examples: new Map([[1, ["root"]]]),
      snapshot: { mode: "sniper", points: 1, sets: [null] },
    });
    expect(at(1)).toEqual([{ set: 0, index: -1, text: "root" }]);
  });

  it("falls back to plan arithmetic from the launch snapshot", () => {
    const at = intruderPayloadResolver({
      report: report({ planned: 3 }),
      sets,
      examples: new Map(),
      snapshot: { mode: "sniper", points: 1, sets: [["a", "b", "c"]] },
    });
    expect(at(2)).toEqual([{ set: 0, index: 2, text: "c" }]);
  });

  it("treats a set whose length disagrees with the server count as unknown, and an out-of-plan ordinal as unplaceable", () => {
    const at = intruderPayloadResolver({
      report: report({ planned: 3 }),
      sets,
      examples: new Map(),
      snapshot: { mode: "sniper", points: 1, sets: [["a", "b", "c", "extra"]] },
    });
    const [part] = at(0)!;
    expect(part?.text).toBeNull();
    expect(at(9)).toBeNull();
  });
});

describe("intruderExportFilenames", () => {
  it("names the attack and stamps the time without characters Windows filenames forbid", () => {
    const { csv, json } = intruderExportFilenames(report({ kind: "cluster_bomb", planned: 4096 }), new Date("2026-09-07T12:34:56Z"));
    expect(csv).toBe("intruder-cluster_bomb-4096-2026-09-07T12-34-56.csv");
    expect(json).toBe("intruder-cluster_bomb-4096-2026-09-07T12-34-56.json");
  });
});
