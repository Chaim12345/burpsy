import { describe, expect, test } from "bun:test";
import { ORGANIZER_COLUMNS, ORGANIZER_HEADERS, organizerRowCells } from "./organizer-columns";

const width = (resolved: boolean): number => organizerRowCells(resolved).reduce((sum, cell) => sum + cell.span, 0);

describe("the Organizer table's row cells", () => {
 test("the header reads Workflow before Type", () => {
  expect(ORGANIZER_HEADERS.indexOf("Workflow")).toBe(ORGANIZER_HEADERS.indexOf("Type") - 1);
 });

 test("a resolved row renders exactly the header's columns, in header order", () => {
  expect(organizerRowCells(true).map((cell) => cell.key)).toEqual(ORGANIZER_COLUMNS.map((column) => column.key));
  expect(width(true)).toBe(ORGANIZER_HEADERS.length);
 });

 test("an unresolved row spans Request and Status, and still fills exactly the header's width", () => {
  // The old row was colSpan={4} plus the Workflow cell: five columns under four headers.
  expect(width(false)).toBe(ORGANIZER_HEADERS.length);
  const cells = organizerRowCells(false);
  const notice = cells.findIndex((cell) => cell.key === "unresolved");
  expect(cells[notice]).toEqual({ key: "unresolved", span: 2 });
  expect(cells.slice(notice + 1, notice + 3).map((cell) => cell.key)).toEqual(["workflow", "type"]);
 });

 test("an unresolved row keeps the workflow badge under the Workflow header", () => {
  // Column index of each cell = sum of the spans before it.
  let column = 0;
  const at: Record<string, number> = {};
  for (const cell of organizerRowCells(false)) {
   at[cell.key] = column;
   column += cell.span;
  }
  expect(at.workflow).toBe(ORGANIZER_HEADERS.indexOf("Workflow"));
  expect(at.type).toBe(ORGANIZER_HEADERS.indexOf("Type"));
  expect(at.title).toBe(ORGANIZER_HEADERS.indexOf("Title"));
  expect(at.actions).toBe(ORGANIZER_HEADERS.length - 1);
 });
});
