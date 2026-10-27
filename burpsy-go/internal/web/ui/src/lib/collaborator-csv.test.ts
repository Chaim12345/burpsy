import { describe, expect, test } from "bun:test";
import { burpDateTime, collaboratorToCSV, COLLABORATOR_CSV_HEADERS, type CollaboratorExportRow } from "./collaborator-csv";

const row = (over: Partial<CollaboratorExportRow>): CollaboratorExportRow => ({
 id: 0,
 interaction_id: "AbC",
 type: "http",
 client_ip: "203.0.113.9",
 at_ms: new Date(2026, 9, 8, 13, 4, 5, 7).getTime(),
 collapsed: false,
 ...over,
});

describe("Collaborator CSV export (aw2y)", () => {
 test("Burp's date-time format", () => {
  expect(burpDateTime(new Date(2026, 9, 8, 13, 4, 5, 7).getTime())).toBe("2026-Oct-08 13:04:05.007");
 });

 test("one row per interaction with the bytes as Base64 and the operator's comment", () => {
  const csv = collaboratorToCSV(
   [row({ id: 3, payload: "bsy1.x.oast.me", raw_request_b64: btoa("GET / HTTP/1.1\r\n"), raw_response_b64: "" })],
   { 3: "the login form" },
  );
  const lines = csv.trimEnd().split("\r\n");
  expect(lines).toHaveLength(2);
  expect(lines[0]).toBe(COLLABORATOR_CSV_HEADERS.map((h) => `"${h}"`).join(","));
  expect(lines[1]).toContain(`"2026-Oct-08 13:04:05.007","HTTP","bsy1.x.oast.me","203.0.113.9"`);
  expect(lines[1]).toContain(`"the login form","${btoa("GET / HTTP/1.1\r\n")}"`);
 });

 test("attacker-influenced cells cannot become Excel formulas", () => {
  const csv = collaboratorToCSV([row({ payload: "=cmd|' /C calc'!A0", raw_request_b64: "+AAA" })], {});
  expect(csv).toContain(`"'=cmd|' /C calc'!A0"`);
  expect(csv).toContain(`"'+AAA"`);
 });
});
