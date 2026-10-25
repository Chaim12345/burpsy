// The history table's derived columns, tested as functions rather than through the table.
//
// Extension and Query are computed from the row's own path because /api/history returns index
// rows and never touches a body (internal/web/AGENTS.md). That makes them pure, and a pure
// derivation that decides what an operator sees in a column should be pinned here, not inferred
// from a screenshot.
import { expect, test, describe } from "bun:test";
import { pathParts } from "../pages/history";

describe("pathParts", () => {
 test("reads the extension from the last segment", () => {
  expect(pathParts("/app.js").extension).toBe("js");
  expect(pathParts("/a/b/logo.PNG").extension).toBe("png"); // lower-cased
  expect(pathParts("/report.pdf?v=2").extension).toBe("pdf"); // query stripped first
 });

 test("reports no extension where there is none", () => {
  expect(pathParts("/plain").extension).toBe("");
  expect(pathParts("/").extension).toBe("");
  expect(pathParts("/api/users?id=1").extension).toBe("");
 });

 test("a dot in a directory name is not an extension", () => {
  // The bug this guards: taking the last dot in the whole path would call this "com/index".
  expect(pathParts("/cdn.example.com/index").extension).toBe("");
 });

 test("a dotfile and a trailing dot have no extension", () => {
  expect(pathParts("/.gitignore").extension).toBe("");
  expect(pathParts("/weird.").extension).toBe("");
 });

 test("counts query parameters", () => {
  expect(pathParts("/search?q=a&page=2&sort=x").queryCount).toBe(3);
  expect(pathParts("/api/users?id=1").queryCount).toBe(1);
 });

 test("a bare or empty query is zero parameters, not one", () => {
  // "?" alone must not read as a parameterised request -- the Parameterized filter keys on this.
  expect(pathParts("/x?").queryCount).toBe(0);
  expect(pathParts("/x").queryCount).toBe(0);
  expect(pathParts("/x?&&").queryCount).toBe(0);
 });

 test("a valueless parameter still counts", () => {
  expect(pathParts("/x?debug").queryCount).toBe(1);
  expect(pathParts("/x?a&b=2").queryCount).toBe(2);
 });
});
