// The Comparer's item tables (burpsy-react-ui-yy2): what the store model does.
//
// The DOM half (the two tables, selection, Remove, Clear) needs a mounted console; the model
// rules are worth pinning without one because they decide whether send-to destroys — the
// defect this bead was filed on:
//
//   - add appends and never replaces: three sends to one side leave three items;
//   - remove takes exactly the named item, and removing the selected one is the caller's to
//     also deselect (the store cannot know the page's selection);
//   - clear empties the side without touching the other;
//   - ids are monotonic per session, so a remove-then-add can never alias a stale React key.
import { describe, expect, test } from "bun:test";
import { useApp, newComparerItem } from "./store";

// A fresh-ish store state for each test: mutate through the setters on the live store, as the
// page does. The store is module-level; each test clears both sides first so its count is its
// own.
function reset() {
 useApp.getState().clearComparerItems("a");
 useApp.getState().clearComparerItems("b");
}

describe("the Comparer item tables' store model", () => {
 test("send-to appends, so a third send no longer destroys what was there", () => {
  reset();
  const { addComparerItem } = useApp.getState();
  addComparerItem("a", newComparerItem("GET /one", "one"));
  addComparerItem("a", newComparerItem("GET /two", "two"));
  addComparerItem("a", newComparerItem("GET /three", "three"));
  const a = useApp.getState().comparerItems.a;
  expect(
   a.map((item) => item.label),
   "the whole point of the bead: the item tables hold every message sent, not the newest",
  ).toEqual(["GET /one", "GET /two", "GET /three"]);
 });

 test("remove takes exactly the named item and leaves the side's order alone", () => {
  reset();
  const { addComparerItem, removeComparerItem } = useApp.getState();
  addComparerItem("a", newComparerItem("one", "1"));
  const doomed = newComparerItem("two", "2");
  addComparerItem("a", doomed);
  addComparerItem("a", newComparerItem("three", "3"));
  removeComparerItem("a", doomed.id);
  expect(
   useApp.getState().comparerItems.a.map((item) => item.label),
   "removing the middle item must not reorder or take the neighbours",
  ).toEqual(["one", "three"]);
 });

 test("clearing one side leaves the other untouched — the sides are independent lists", () => {
  reset();
  const state = useApp.getState();
  state.addComparerItem("a", newComparerItem("a-item", "a"));
  state.addComparerItem("b", newComparerItem("b-item", "b"));
  state.clearComparerItems("a");
  expect(useApp.getState().comparerItems.a).toEqual([]);
  expect(
   useApp.getState().comparerItems.b.map((item) => item.label),
   "clearing side A destroyed side B's list — the two tables are independent",
  ).toEqual(["b-item"]);
 });

 test("item ids are monotonic per session, so a stale React key can never alias a new item", () => {
  reset();
  const first = newComparerItem("x", "1");
  const second = newComparerItem("y", "2");
  expect(second.id).toBeGreaterThan(first.id);
  const { removeComparerItem, addComparerItem } = useApp.getState();
  addComparerItem("a", first);
  removeComparerItem("a", first.id);
  const replacement = newComparerItem("x again", "1");
  expect(replacement.id, "a re-added item must never reuse the removed one's id — the row would inherit a stale selection").toBeGreaterThan(
   first.id,
  );
 });
});
