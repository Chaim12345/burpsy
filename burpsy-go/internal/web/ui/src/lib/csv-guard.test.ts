import { describe, expect, test } from "bun:test";
import { historyToCSV, organizerToCSV, toolLogToCSV } from "./api";
import { intruderReportToCSV } from "./intruder-export";
import type { AttackReport, Attempt } from "./types.tools";

/**
 * The Excel formula guard is the acceptance criterion burpsy-react-ui-656 names: a value
 * starting with -, +, = or @ must not execute as a formula when the export is opened in
 * Excel. A captured host or path can carry any bytes the target sent, so the guard is a
 * real injection boundary, not polish. csvCell prefixes the leading character with an
 * apostrophe *inside* the double quotes, so '=cmd exports as the cell "'=cmd".
 */
describe("historyToCSV guards formula-leading cells", () => {
 test("a path beginning with = is prefixed so Excel reads text", () => {
  const csv = historyToCSV([
   {
    id: 1,
    started_ms: 0,
    method: "GET",
    host: "evil.test",
    port: 80,
    path: "/=cmd|'/c calc'!A0",
    status: 200,
    response_len: 5,
    duration_ms: 1,
    notes: "",
   },
  ]);
  // The path cell: apostrophe before the leading =, whole cell quoted, inner ' untouched.
  expect(csv).toContain("\"/=cmd|'/c calc'!A0\"");
 });

 test("a host beginning with @ is guarded the same way", () => {
  const csv = historyToCSV([
   { id: 2, started_ms: 0, method: "GET", host: "@evil.test", port: 80, path: "/", status: 200, response_len: 0, duration_ms: 1 },
  ]);
  expect(csv).toContain("\"'@evil.test\"");
 });

 test("a note beginning with - is guarded retroactively (656's History clause)", () => {
  const csv = historyToCSV([
   { id: 3, started_ms: 0, method: "GET", host: "a.test", port: 80, path: "/", status: 200, response_len: 0, duration_ms: 1, notes: "-1+1" },
  ]);
  expect(csv).toContain("\"'-1+1\"");
 });

 test("ordinary values are still plain quoted text", () => {
  const csv = historyToCSV([
   { id: 4, started_ms: 0, method: "GET", host: "a.test", port: 80, path: "/x", status: 200, response_len: 3, duration_ms: 9, notes: "plain note" },
  ]);
  expect(csv).toContain('"plain note"');
 });
});

describe("toolLogToCSV", () => {
 test("covers the logger columns and guards the comment", () => {
  const csv = toolLogToCSV([
   { id: 7, started_ms: 0, tool: "repeater", host: "h.test", port: 8080, method: "GET", path: "/=x", status: 200, response_len: null, duration_ms: 3, comment: "=boom" },
  ]);
  const lines = csv.split("\n");
  expect(lines[0]).toBe('"ID","Timestamp","Tool","Host","Port","Method","Path","Status","Length","Duration","Comment"');
  expect(lines[1]).toContain('"repeater"');
  expect(lines[1]).toContain("\"'=boom\"");
  // no response is an empty cell, not a zero
  expect(lines[1]).toContain(',"",');
 });
});

describe("organizerToCSV", () => {
 test("covers the item fields with the exchange id, never a body", () => {
  const csv = organizerToCSV([
   { id: 9, title: "Token endpoint", note: "+retry", highlight: "red", workflow_status: "in_progress", exchange: 42 },
  ]);
  const lines = csv.split("\n");
  expect(lines[0]).toBe('"ID","Title","Note","Highlight","Status","Exchange"');
  expect(lines[1]).toContain('"Token endpoint"');
  expect(lines[1]).toContain("\"'+retry\"");
  expect(lines[1]).toContain('"42"');
 });
});

describe("intruderReportToCSV", () => {
 // A payload list is more attacker-influenced than a captured host or path: it is routinely
 // sourced from external fuzzing corpora, so a formula-leading entry like =1+1 or
 // =cmd|'/c calc'!A0 reaches the exported sheet without an operator ever typing it. This must
 // route through the same csvCell as the other three exporters, not a local copy that can drift.
 const report: AttackReport = {
  kind: "sniper",
  combinations: 1,
  combinations_exact: true,
  max_requests: 0,
  truncated: false,
  planned: 1,
  sent: 1,
  failed: 0,
  elapsed_ms: 1,
  buckets: [],
  buckets_truncated: false,
  unbucketed: 0,
  errors: [],
  attempts: [],
  detail_limit: 500,
  grep_matched: 0,
  pool: null,
  auto_throttle_engaged: 0,
 };
 const attempts: Attempt[] = [
  { ordinal: 0, status: 200, response_len: 5, duration_ms: 1, reflected: false, request_id: null, response_id: null, error: null, grep_matched: null, grep_extract: null },
 ];

 test("a payload beginning with = is guarded so Excel reads text, not a formula", () => {
  const csv = intruderReportToCSV(report, attempts, () => [{ set: 0, index: 0, text: "=cmd|'/c calc'!A0" }]);
  expect(csv).toContain("\"'=cmd|'/c calc'!A0\"");
 });

 test("a payload beginning with @ is guarded the same way", () => {
  const csv = intruderReportToCSV(report, attempts, () => [{ set: 0, index: 0, text: "@sum(1,1)" }]);
  expect(csv).toContain("\"'@sum(1,1)\"");
 });
});
