import { describe, expect, test } from "bun:test";
import { followUpAfterScopeAdd } from "./history-logging";

describe("followUpAfterScopeAdd", () => {
 test("follows the choice while out-of-scope items are still logged", () => {
  expect(followUpAfterScopeAdd("stop", false)).toBe("stop");
  expect(followUpAfterScopeAdd("ask", false)).toBe("ask");
  expect(followUpAfterScopeAdd("nothing", false)).toBe("none");
 });
 test("does nothing when out-of-scope items are already not logged", () => {
  for (const mode of ["stop", "ask", "nothing"]) expect(followUpAfterScopeAdd(mode, true)).toBe("none");
 });
 test("an unknown choice asks, the default", () => {
  expect(followUpAfterScopeAdd("", false)).toBe("ask");
 });
});
