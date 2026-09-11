import { describe, expect, test } from "bun:test";
import { cookieOptions, formFieldOptions, headerOptions } from "./sequencer-token-options";

// The picker's data source (6t8): names parsed out of the response the operator actually has.
// The assertions are what make "pick from the response" true — a name absent from these lists
// is a name the capture cannot read, and a name that IS here must extract cleanly server-side.

const RESPONSE = [
 "HTTP/1.1 200 OK",
 "Content-Type: text/html",
 "Set-Cookie: SESSIONID=abc123; Path=/; HttpOnly",
 "Set-Cookie: prefs=theme%3Ddark; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
 "X-Request-Id: req-77",
 "",
 "<html><body>",
 '<form method="post">',
 '<input type="hidden" NAME="csrf_token" value="a1b2c3d4">',
 '<input type=\'text\' name=\'user\' value=\'ignored\'>',
 "<select name=\"locale\"><option value=\"en\">en</option></select>",
 "</form>",
 "</body></html>",
].join("\r\n");

describe("sequencer token options", () => {
 test("cookies carry their names and a value excerpt", () => {
  const options = cookieOptions(RESPONSE);
  expect(options.map((o) => o.name).sort()).toEqual(["SESSIONID", "prefs"].sort());
  expect(options.find((o) => o.name === "SESSIONID")?.excerpt).toBe("abc123");
 });

 test("headers list everything except Set-Cookie", () => {
  const options = headerOptions(RESPONSE);
  const names = options.map((o) => o.name);
  expect(names).toContain("Content-Type");
  expect(names).toContain("X-Request-Id");
  expect(names.some((n) => /^set-cookie$/i.test(n))).toBe(false);
 });

 test("form fields cover input and select, with their values as excerpts", () => {
  const options = formFieldOptions(RESPONSE);
  const names = options.map((o) => o.name);
  expect(names).toContain("csrf_token");
  expect(names).toContain("user");
  expect(names).toContain("locale");
  expect(options.find((o) => o.name === "csrf_token")?.excerpt).toBe("a1b2c3d4");
 });

 test("a response with no body yields empty form-field options and keeps the headers", () => {
  const headOnly = "HTTP/1.1 204 No Content\r\nX-Token: t\r\n\r\n";
  expect(formFieldOptions(headOnly)).toEqual([]);
  expect(headerOptions(headOnly).map((o) => o.name)).toEqual(["X-Token"]);
 });
});
