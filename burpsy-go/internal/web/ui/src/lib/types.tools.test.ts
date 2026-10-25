import { describe, expect, test } from "bun:test";
import {
 assignmentAt,
 attackProgress,
 customIteratorSize,
 customIteratorSlots,
 dateSetSize,
 estimateRequests,
 parseCharSubstitutions,
 planSetLengths,
 quoteRegex,
 resolvePayloads,
 type AttackReport,
 type SetSize,
} from "./types.tools";

// ---- decoding an attempt's ordinal into its payloads ------------------------------------------
//
// The Intruder results table showed an ordinal and no payload (burpsy-react-ui-fvx): attempt #4173
// returned an interesting length and there was no way to learn what caused it. The server can
// recover the combination — payloadsAt in internal/web/api_tools.go — but only calls it for each
// bucket's first ordinal, so attempt rows arrived with nothing to join against.
//
// assignmentAt is the browser-side port of (*AttackPlan).Fill (internal/intruder/plan.go:240). The
// expectations below are derived from that function, not from assignmentAt's own output, because a
// port that is self-consistently wrong would label every row confidently and falsely.

describe("assignmentAt mirrors (*AttackPlan).Fill", () => {
 test("sniper walks one set across the positions in turn", () => {
  // plan.go:246-248 — Point: i/n, Set: 0, Payload: i%n, with n = set 0's length.
  const lengths = planSetLengths("sniper", 3, [2]);
  expect(lengths).toEqual([2]);
  const seen = [0, 1, 2, 3, 4, 5].map((ordinal) => assignmentAt("sniper", 3, lengths, 6, ordinal));
  expect(seen).toEqual([
   [{ point: 0, set: 0, payload: 0 }],
   [{ point: 0, set: 0, payload: 1 }],
   [{ point: 1, set: 0, payload: 0 }],
   [{ point: 1, set: 0, payload: 1 }],
   [{ point: 2, set: 0, payload: 0 }],
   [{ point: 2, set: 0, payload: 1 }],
  ]);
 });

 test("battering ram puts the same payload in every position", () => {
  // plan.go:249-252 — one slot per point, all carrying payload i.
  expect(assignmentAt("battering_ram", 3, [4], 4, 2)).toEqual([
   { point: 0, set: 0, payload: 2 },
   { point: 1, set: 0, payload: 2 },
   { point: 2, set: 0, payload: 2 },
  ]);
 });

 test("pitchfork advances every set in lockstep", () => {
  // plan.go:253-256 — slot j reads set j at the same index.
  const lengths = planSetLengths("pitchfork", 2, [5, 5]);
  expect(assignmentAt("pitchfork", 2, lengths, 5, 3)).toEqual([
   { point: 0, set: 0, payload: 3 },
   { point: 1, set: 1, payload: 3 },
  ]);
 });

 test("cluster bomb varies set 0 fastest — the lockout-safe spray order", () => {
  // plan.go:257-269 documents this direction and why it matters: with usernames in set 0 and
  // passwords in set 1, every username is tried against password 1 before password 2. Decoding
  // it the other way round would name the wrong payload on every single row.
  const lengths = planSetLengths("cluster_bomb", 2, [2, 3]);
  const decoded = [0, 1, 2, 3, 4, 5].map((ordinal) => assignmentAt("cluster_bomb", 2, lengths, 6, ordinal)!.map((slot) => slot.payload));
  expect(decoded).toEqual([
   [0, 0],
   [1, 0],
   [0, 1],
   [1, 1],
   [0, 2],
   [1, 2],
  ]);
 });

 test("an ordinal outside the plan has no answer", () => {
  expect(assignmentAt("sniper", 1, [3], 3, 3)).toBeNull();
  expect(assignmentAt("sniper", 1, [3], 3, -1)).toBeNull();
  expect(assignmentAt("sniper", 1, [3], 3, 1.5)).toBeNull();
 });

 test("a mode that reads no set has no answer rather than a wrong one", () => {
  expect(assignmentAt("sniper", 1, [], 0, 0)).toBeNull();
  expect(assignmentAt("cluster_bomb", 2, [2, 0], 0, 0)).toBeNull();
 });
});

describe("planSetLengths mirrors NewAttackPlan's setsUsed", () => {
 test("the single-set modes read set 0 only", () => {
  // plan.go:136-140 — extra sets are the caller's business, not the plan's.
  expect(planSetLengths("sniper", 3, [4, 9, 9])).toEqual([4]);
  expect(planSetLengths("battering_ram", 3, [4, 9])).toEqual([4]);
  expect(planSetLengths("sniper", 3, [])).toEqual([]);
 });

 test("the multi-set modes read one set per position, truncated to the sets that exist", () => {
  // plan.go:141-146.
  expect(planSetLengths("cluster_bomb", 2, [4, 5, 6])).toEqual([4, 5]);
  expect(planSetLengths("pitchfork", 5, [4, 5])).toEqual([4, 5]);
 });
});

describe("resolvePayloads separates known payload text from an unknowable set", () => {
 const slots = [
  { point: 0, set: 0, payload: 1 },
  { point: 1, set: 1, payload: 0 },
 ];

 test("a set the browser holds resolves to its text", () => {
  expect(resolvePayloads(slots, [["a", "b"], ["x"]])).toEqual([
   { set: 0, index: 1, text: "b" },
   { set: 1, index: 0, text: "x" },
  ]);
 });

 test("an unknown set keeps its index and reports no text", () => {
  // internal/intruder tags PayloadSet.Items `json:"-"`, so a file-backed set's payloads never
  // cross the wire. null is "not knowable here" — never an empty payload, never a failure.
  expect(resolvePayloads(slots, [["a", "b"], null])).toEqual([
   { set: 0, index: 1, text: "b" },
   { set: 1, index: 0, text: null },
  ]);
 });

 test("an index past the end of a known set reports no text rather than undefined", () => {
  expect(resolvePayloads([{ point: 0, set: 0, payload: 7 }], [["a", "b"]])).toEqual([{ set: 0, index: 7, text: null }]);
 });

 test("an empty payload is text, not an absence", () => {
  expect(resolvePayloads([{ point: 0, set: 0, payload: 0 }], [[""]])).toEqual([{ set: 0, index: 0, text: "" }]);
 });
});

// ---- sizing an attack before launching it -----------------------------------------------------
//
// The header badge and the over-budget warning used the constants 1, 10 and 4 for the file, dates
// and custom-iterator payload types (burpsy-react-ui-1ww). A 50,000-line wordlist read "1 request";
// an 8,000-combination iterator read "4" and could not trip the warning that exists to stop an
// accidental outage.

describe("dateSetSize", () => {
 test("counts both ends of the range", () => {
  // 2024 is a leap year: 2024-01-01 to 2024-12-31 inclusive is 366 days.
  expect(dateSetSize("2024-01-01", "2024-12-31", 1)).toBe(366);
  expect(dateSetSize("2024-01-01", "2024-01-01", 1)).toBe(1);
 });

 test("steps in whole days", () => {
  expect(dateSetSize("2024-01-01", "2024-01-08", 7)).toBe(2);
  expect(dateSetSize("2024-01-01", "2024-01-07", 7)).toBe(1);
 });

 test("a reversed range produces nothing", () => {
  expect(dateSetSize("2024-12-31", "2024-01-01", 1)).toBe(0);
 });

 test("an unparseable bound or a non-positive step is unknown, not a guess", () => {
  expect(dateSetSize("not-a-date", "2024-12-31", 1)).toBeNull();
  expect(dateSetSize("2024-01-01", "", 1)).toBeNull();
  expect(dateSetSize("2024-01-01", "2024-12-31", 0)).toBeNull();
  expect(dateSetSize("2024-01-01", "2024-12-31", -3)).toBeNull();
 });
});

describe("customIteratorSize", () => {
 test("is the product of the per-line item counts", () => {
  expect(customIteratorSize("a,b\nc,d")).toBe(4);
  expect(customIteratorSize("a,b,c\n1,2,3,4")).toBe(12);
  // The worked case from the issue: three lines of 20 is 8,000, not 4.
  const twenty = Array.from({ length: 20 }, (_, i) => `i${i}`).join(",");
  expect(customIteratorSize([twenty, twenty, twenty].join("\n"))).toBe(8000);
 });

 test("an empty iterator produces nothing", () => {
  expect(customIteratorSize("")).toBe(0);
  expect(customIteratorSize("\n\n")).toBe(0);
 });

 test("slots drop blank items and blank lines, so the estimate matches what is sent", () => {
  expect(customIteratorSlots("a, ,b\n\nc,")).toEqual([["a", "b"], ["c"]]);
  expect(customIteratorSize("a, ,b\n\nc,")).toBe(2);
 });
});

describe("estimateRequests", () => {
 const sizes = (values: SetSize[]) => values;

 test("a known configuration is exact", () => {
  expect(estimateRequests("sniper", 3, sizes([5]))).toEqual({ count: 15, exact: true });
  expect(estimateRequests("battering_ram", 3, sizes([5]))).toEqual({ count: 5, exact: true });
  expect(estimateRequests("pitchfork", 2, sizes([5, 3]))).toEqual({ count: 3, exact: true });
  expect(estimateRequests("cluster_bomb", 2, sizes([5, 3]))).toEqual({ count: 15, exact: true });
 });

 test("an unknown set makes the count a floor, counting it as one payload", () => {
  expect(estimateRequests("cluster_bomb", 2, sizes([100, null]))).toEqual({ count: 100, exact: false });
  expect(estimateRequests("sniper", 2, sizes([null]))).toEqual({ count: 2, exact: false });
 });

 test("an unknown set the mode never reads does not make the count a floor", () => {
  // Sniper and battering ram read set 0 only, so a file in set 2 cannot affect their count.
  expect(estimateRequests("sniper", 2, sizes([10, null]))).toEqual({ count: 20, exact: true });
  expect(estimateRequests("battering_ram", 2, sizes([10, null]))).toEqual({ count: 10, exact: true });
 });

 test("no sets at all is zero, and known to be zero", () => {
  expect(estimateRequests("cluster_bomb", 0, sizes([]))).toEqual({ count: 0, exact: true });
 });
});

// ---- the grep fields take regular expressions -------------------------------------------------
//
// Both grep fields are compiled with regexp.Compile on the server (buildGrep, api_tools.go:736) but
// were labelled and placeheld as literal strings (burpsy-react-ui-tpy). Simple-string mode quotes
// the literal here, so the operator's `root:` is sent as a pattern that matches `root:`.

// ---- a stopped attack must not report a complete answer ---------------------------------------
//
// An intruder task is cancellable from the Dashboard (api_tools.go:711 registers the cancel), so a
// stopped report is reachable today with no Intruder UI involved. The report panel used `planned` as
// its denominator and read "Sent 12 of 400 planned" — asserting the target was asked 400 times and
// answered 12, when it was asked 12. Filed against burpsy-react-ui-wub.

describe("attackProgress", () => {
 const report = (over: Partial<AttackReport>): AttackReport => ({ planned: 400, sent: 12, ...over }) as AttackReport;

 test("a completed attack is described by its plan", () => {
  expect(attackProgress(report({ status: "completed", enumerated: 400 }))).toEqual({
   stopped: false,
   paused: false,
   reached: 400,
  });
 });

 test("a stopped attack is described by what it reached, not what it planned", () => {
  expect(attackProgress(report({ status: "stopped", enumerated: 12 }))).toEqual({
   stopped: true,
   paused: false,
   reached: 12,
  });
 });

 test("a paused attack counts as stopped for reporting, and says which it is", () => {
  // Its counts describe a prefix exactly as a stopped one's do; the wording differs, the maths
  // does not.
  expect(attackProgress(report({ status: "paused", enumerated: 12 }))).toEqual({
   stopped: true,
   paused: true,
   reached: 12,
  });
 });

 test("an older server that sends neither field reads as completed over its plan", () => {
  // Sound only because no server that omits these fields could stop an attack. A future field
  // that changes that must not reuse the absence.
  expect(attackProgress(report({}))).toEqual({ stopped: false, paused: false, reached: 400 });
 });

 test("enumerated is used even when status is absent", () => {
  expect(attackProgress(report({ enumerated: 12 })).reached).toBe(12);
 });

 test("enumerated of zero is a real count, not a missing one", () => {
  // `?? planned` rather than `|| planned` for exactly this: an attack stopped before it reached
  // any plan position reached none, and 400 would be a fabrication.
  expect(attackProgress(report({ status: "stopped", enumerated: 0 })).reached).toBe(0);
 });
});

describe("quoteRegex", () => {
 test("escapes exactly the bytes regexp.QuoteMeta escapes", () => {
  // Go's specialBytes: \.+*?()|[]{}^$
  expect(quoteRegex("\\.+*?()|[]{}^$")).toBe("\\\\\\.\\+\\*\\?\\(\\)\\|\\[\\]\\{\\}\\^\\$");
 });

 test("leaves ordinary text alone", () => {
  expect(quoteRegex("root:")).toBe("root:");
  expect(quoteRegex("welcome back")).toBe("welcome back");
 });

 test("quotes the comma-separated string the old placeholder invited", () => {
  // Typing the old placeholder compiled to a regex matching that exact 20-character sequence.
  // Quoted, it at least means what it says — a literal — and the label now says which it is.
  expect(quoteRegex("error, root:, welcome")).toBe("error, root:, welcome");
 });

 test("a quoted literal with regex metacharacters matches itself under RE2", () => {
  // Checked with JS's own engine, which agrees with RE2 on this subset.
  const literal = "a+b(c)";
  expect(new RegExp(quoteRegex(literal)).test(literal)).toBe(true);
  expect(new RegExp(quoteRegex(literal)).test("aab c")).toBe(false);
 });
});

describe("parseCharSubstitutions", () => {
 test("parses one char=replacement pair per line", () => {
  expect(parseCharSubstitutions("e=3\na=4\no=0")).toEqual({ e: "3", a: "4", o: "0" });
 });

 test("skips a blank line and a line with no '='", () => {
  expect(parseCharSubstitutions("e=3\n\nnotasubstitution\na=4")).toEqual({ e: "3", a: "4" });
 });

 test("allows an empty replacement (substitute to nothing)", () => {
  expect(parseCharSubstitutions("e=")).toEqual({ e: "" });
 });

 test("splits on the first '=' only, so a replacement can itself contain one", () => {
  expect(parseCharSubstitutions("e=1=1")).toEqual({ e: "1=1" });
 });

 test("trims whitespace around both sides", () => {
  expect(parseCharSubstitutions(" e = 3 ")).toEqual({ e: "3" });
 });

 test("an empty textarea produces an empty table, not an error", () => {
  expect(parseCharSubstitutions("")).toEqual({});
 });
});
