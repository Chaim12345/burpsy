// Multi-row selection rules (burpsy-react-ui-fe16). The reducer is the whole behaviour; VirtualTable
// only translates clicks and keys into these actions.
import { describe, expect, test } from "bun:test";
import {
 clickAction,
 contextKeepsSelection,
 EMPTY_SELECTION,
 reduceSelection,
 type SelectionAction,
 type SelectionState,
} from "./table-selection";

const ORDER = ["1", "2", "3", "4", "5", "6"];

function run(actions: SelectionAction[], order: readonly string[] = ORDER, from: SelectionState = EMPTY_SELECTION): SelectionState {
 return actions.reduce((state, action) => reduceSelection(state, action, order), from);
}

describe("click", () => {
 test("a plain click selects exactly that row and anchors there", () => {
  expect(run([{ type: "only", id: "3" }])).toEqual({ ids: ["3"], anchor: "3", focus: "3" });
  expect(
   run([
    { type: "only", id: "3" },
    { type: "only", id: "5" },
   ]).ids,
  ).toEqual(["5"]);
 });

 test("Ctrl-click toggles one row in and out, keeping the rest in displayed order", () => {
  const state = run([
   { type: "only", id: "4" },
   { type: "toggle", id: "2" },
   { type: "toggle", id: "6" },
  ]);
  expect(state.ids).toEqual(["2", "4", "6"]);
  expect(run([{ type: "toggle", id: "4" }], ORDER, state).ids).toEqual(["2", "6"]);
 });

 test("Shift-click selects the range from the anchor, in either direction", () => {
  expect(
   run([
    { type: "only", id: "2" },
    { type: "range", id: "5" },
   ]).ids,
  ).toEqual(["2", "3", "4", "5"]);
  expect(
   run([
    { type: "only", id: "5" },
    { type: "range", id: "2" },
   ]).ids,
  ).toEqual(["2", "3", "4", "5"]);
 });

 test("a second Shift-click re-ranges from the same anchor rather than growing the first range", () => {
  const state = run([
   { type: "only", id: "3" },
   { type: "range", id: "6" },
   { type: "range", id: "1" },
  ]);
  expect(state.ids).toEqual(["1", "2", "3"]);
  expect(state.anchor).toBe("3");
 });

 test("the range is over the DISPLAYED order, not the data order", () => {
  // Sorted descending on screen: a range from 5 to 2 is 5,4,3,2 as shown — and with a filter
  // hiding 4, the hidden row is not selected behind the operator's back.
  const shown = ["6", "5", "3", "2", "1"];
  expect(
   run(
    [
     { type: "only", id: "5" },
     { type: "range", id: "2" },
    ],
    shown,
   ).ids,
  ).toEqual(["5", "3", "2"]);
 });

 test("clickAction maps modifiers: shift wins over mod, plain is only", () => {
  expect(clickAction("1", { shift: true, mod: true }).type).toBe("range");
  expect(clickAction("1", { shift: false, mod: true }).type).toBe("toggle");
  expect(clickAction("1", { shift: false, mod: false }).type).toBe("only");
 });
});

describe("keyboard", () => {
 test("Shift+Down extends from the anchor; plain Down collapses to one row", () => {
  const extended = run([
   { type: "only", id: "2" },
   { type: "extend", delta: 1 },
   { type: "extend", delta: 1 },
  ]);
  expect(extended.ids).toEqual(["2", "3", "4"]);
  expect(extended.focus).toBe("4");
  expect(run([{ type: "move", delta: 1 }], ORDER, extended)).toEqual({ ids: ["5"], anchor: "5", focus: "5" });
 });

 test("Shift+Up past the anchor flips the range to the other side", () => {
  expect(
   run([
    { type: "only", id: "3" },
    { type: "extend", delta: 1 },
    { type: "extend", delta: -3 },
   ]).ids,
  ).toEqual(["1", "2", "3"]);
 });

 test("Shift+End selects to the last row, and movement clamps at the ends", () => {
  expect(
   run([
    { type: "only", id: "4" },
    { type: "extend", delta: "end" },
   ]).ids,
  ).toEqual(["4", "5", "6"]);
  expect(
   run([
    { type: "only", id: "6" },
    { type: "move", delta: 5 },
   ]).focus,
  ).toBe("6");
 });

 test("with nothing focused, Down starts at the first row", () => {
  expect(run([{ type: "move", delta: 1 }]).ids).toEqual(["1"]);
 });

 test("Ctrl+A selects every displayed row", () => {
  expect(run([{ type: "only", id: "3" }, { type: "all" }]).ids).toEqual(ORDER);
 });
});

describe("pruning when the displayed rows change", () => {
 test("a filter that hides selected rows drops them, and a hidden focus/anchor is cleared", () => {
  const state = run([
   { type: "only", id: "2" },
   { type: "range", id: "5" },
  ]);
  const pruned = reduceSelection(state, { type: "prune" }, ["1", "3", "4", "6"]);
  expect(pruned.ids).toEqual(["3", "4"]);
  expect(pruned.anchor).toBeNull();
  expect(pruned.focus).toBeNull();
 });

 test("a range whose anchor was filtered away degrades to one row instead of reaching back", () => {
  const state = run([{ type: "only", id: "2" }]);
  expect(reduceSelection(state, { type: "range", id: "5" }, ["1", "3", "4", "5"]).ids).toEqual(["5"]);
 });

 test("an id that is not displayed is not selectable", () => {
  expect(run([{ type: "only", id: "99" }])).toEqual(EMPTY_SELECTION);
  expect(run([{ type: "set", ids: ["2", "99"], focus: "2" }]).ids).toEqual(["2"]);
 });
});

describe("right-click", () => {
 test("inside a multi-selection keeps it; on any other row, or a single selection, it does not", () => {
  const state = run([
   { type: "only", id: "2" },
   { type: "range", id: "4" },
  ]);
  expect(contextKeepsSelection(state, "3")).toBe(true);
  expect(contextKeepsSelection(state, "6")).toBe(false);
  expect(contextKeepsSelection(run([{ type: "only", id: "2" }]), "2")).toBe(false);
 });
});
