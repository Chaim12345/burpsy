/** burpsy-react-ui-n2un: the Help menu reaches Documentation and Diagnostics, not only two hotkeys. */
import { describe, expect, test } from "bun:test";
import { helpMenuGroups } from "./help-menu";

function setup() {
 const calls: string[] = [];
 const groups = helpMenuGroups({
  openShortcuts: () => calls.push("shortcuts"),
  openPalette: () => calls.push("palette"),
  openDocumentation: () => calls.push("documentation"),
  openDiagnostics: () => calls.push("diagnostics"),
 });
 const actions = groups.flatMap((group) => group.actions);
 return { calls, groups, actions, byId: (id: string) => actions.find((action) => action.id === id) };
}

describe("helpMenuGroups", () => {
 test("keeps the keyboard shortcuts and palette entries", () => {
  const { byId, calls } = setup();
  byId("keys")?.onSelect?.();
  byId("palette")?.onSelect?.();
  expect(calls).toEqual(["shortcuts", "palette"]);
 });

 test("Documentation and Diagnostics are reachable from Help", () => {
  const { byId, calls } = setup();
  expect(byId("documentation")?.label).toBe("Documentation");
  expect(byId("diagnostics")?.label).toBe("Diagnostics");
  byId("documentation")?.onSelect?.();
  byId("diagnostics")?.onSelect?.();
  expect(calls).toEqual(["documentation", "diagnostics"]);
 });

 test("every action has a unique id", () => {
  const { actions } = setup();
  expect(new Set(actions.map((action) => action.id)).size).toBe(actions.length);
 });

 test("offers no outbound links: nothing here opens a vendor site", () => {
  const { actions } = setup();
  expect(
   actions
    .map((action) => action.label.toLowerCase())
    .filter((label) => /support center|release notes|report bug|check for updates|license/.test(label)),
  ).toEqual([]);
 });
});
