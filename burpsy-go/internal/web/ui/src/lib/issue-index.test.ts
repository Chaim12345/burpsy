import { describe, expect, test } from "bun:test";
import { readIssueDocument, topFindings } from "./issue-index";
import type { FindingDetail } from "./types.attack";

function finding(id: number, severity: string): FindingDetail {
 return {
  id,
  severity,
  confidence: "firm",
  host: "a.test",
  detail: null,
  remediation: null,
  times_seen: 1,
  occurrences: [],
  false_positive: false,
  comment: "",
 };
}

describe("issue index", () => {
 test("a summary document with no findings array is an empty list, not a throw", () => {
  const doc = readIssueDocument(JSON.stringify({ enabled: true, hint: "none" }));
  expect(doc.enabled).toBe(true);
  expect(doc.findings).toEqual([]);
 });

 test("the dock window is the worst findings, and it does not reorder equals", () => {
  const rows = topFindings(
   [finding(1, "Low"), finding(2, "High"), finding(3, "High"), finding(4, "Informational")],
   2,
  );
  expect(rows.map((row) => row.id)).toEqual([2, 3]);
 });
});
