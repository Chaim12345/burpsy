import { describe, expect, test } from "bun:test";
import { actionPath, refusedActionPath } from "./session-script";

describe("refusedActionPath", () => {
 test("reads a top-level action's position from a compile refusal", () => {
  expect(refusedActionPath("action 2 (Run a pre-request script): script does not compile: SyntaxError: Unexpected token")).toBe("action 2");
 });
 test("reads a nested branch path", () => {
  expect(refusedActionPath("action 1 → else 2 (Run a pre-request script): does not compile: x")).toBe("action 1 → else 2");
 });
 test("a message naming no action is no path", () => {
  expect(refusedActionPath("A rule needs a name")).toBe("");
 });
});

describe("actionPath", () => {
 test("matches the server's numbering", () => {
  expect(actionPath("", 0)).toBe("action 1");
  expect(actionPath("action 1", 1, "else")).toBe("action 1 → else 2");
  expect(actionPath(actionPath("", 2), 0, "then")).toBe("action 3 → then 1");
 });
});
