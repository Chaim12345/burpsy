// The Repeater tab strip's three view affordances (burpsy-react-ui-fkj): the scrolling/wrapped
// choice, drag-to-reorder, and a per-tab colour. All pure over a tab list, so a test pins the
// decision without a browser — which is the only reason an off-by-one in a reorder is catchable
// before it reaches an operator's drag.
import { describe, expect, test } from "bun:test";
import { reorderTabWithinGroup, reorderTabs, tabColour, tabDropdownGroups, type TabLike } from "./repeater-tabs";

const tab = (id: string, over: Partial<TabLike> = {}): TabLike => ({ id, name: id, ...over });

/** The strip in order, with names matching ids so an assertion reads as a sequence. */
const strip = (...ids: string[]): TabLike[] => ids.map((id) => tab(id));

describe("the scrolling / wrapped tab view", () => {
  test("the dropdown lists every open tab, grouped as the strip is", () => {
    const groups = tabDropdownGroups(
      [tab("a"), tab("b", { groupId: "g1" }), tab("c", { groupId: "g1" }), tab("d")],
      [{ id: "g1", name: "checkout" }],
    );
    expect(groups.map((group) => group.title)).toEqual(["Ungrouped", "checkout"]);
    expect(groups[0]?.tabs.map((entry) => entry.id)).toEqual(["a", "d"]);
    expect(groups[1]?.tabs.map((entry) => entry.id)).toEqual(["b", "c"]);
  });

  test("a tab whose group was deleted still lists, under its id rather than vanishing", () => {
    // The strip renders an ungrouped tab whose groupId names nothing (pages/repeater.tsx's own
    // filter), so a dropdown that resolved titles from the group list would show an empty heading
    // for it. The id is the honest fallback.
    const groups = tabDropdownGroups([tab("a", { groupId: "gone" })], []);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.title).toBe("gone");
  });

  test("an empty strip is an empty dropdown, not a crash", () => {
    expect(tabDropdownGroups([])).toEqual([]);
  });
});

describe("drag to reorder", () => {
  test("moves a tab forward to exactly where it was dropped", () => {
    expect(reorderTabs(strip("a", "b", "c", "d"), 0, 3).map((entry) => entry.id)).toEqual(["b", "c", "d", "a"]);
  });

  test("moves a tab backward, and the target index is not off by one after the removal", () => {
    // The defect this shape exists to prevent: remove first, then insert at the *drop* index, and a
    // backward move lands one place short of where the operator let go.
    expect(reorderTabs(strip("a", "b", "c", "d"), 3, 1).map((entry) => entry.id)).toEqual(["a", "d", "b", "c"]);
  });

  test("a drop past either end lands at the end, not off the list", () => {
    expect(reorderTabs(strip("a", "b", "c"), 0, 99).map((entry) => entry.id)).toEqual(["b", "c", "a"]);
    // A tab dragged to the far left goes first: the clamp is at the START of the list, not the end.
    expect(reorderTabs(strip("a", "b", "c"), 2, -5).map((entry) => entry.id)).toEqual(["c", "a", "b"]);
  });

  test("a drop on a tab's own position changes nothing and returns the same array", () => {
    const tabs = strip("a", "b", "c");
    expect(reorderTabs(tabs, 1, 1)).toBe(tabs);
  });

  test("an index that names no tab is ignored rather than corrupting the list", () => {
    const tabs = strip("a", "b");
    expect(reorderTabs(tabs, 7, 0).map((entry) => entry.id)).toEqual(["a", "b"]);
    expect(reorderTabs(tabs, -1, 0).map((entry) => entry.id)).toEqual(["a", "b"]);
  });
});

describe("reordering inside a group", () => {
  const grouped: TabLike[] = [
    tab("a"),
    tab("b", { groupId: "g1" }),
    tab("c", { groupId: "g1" }),
    tab("d"),
    tab("e", { groupId: "g2" }),
  ];

  test("a tab moves among its own group's members and leaves every other row where it was", () => {
    // b is dropped onto c's own row: within the group, c comes first and b follows.
    const next = reorderTabWithinGroup(grouped, "b", 2);
    expect(next.map((entry) => entry.id)).toEqual(["a", "c", "b", "d", "e"]);
  });

  test("a drop outside the tab's group is a no-op, not a silent join", () => {
    // The alternative would make an accidental drag change which group a request belongs to, which
    // is a data change made by a gesture aimed at ordering.
    const next = reorderTabWithinGroup(grouped, "b", 4);
    expect(next.map((entry) => entry.id)).toEqual(["a", "b", "c", "d", "e"]);
  });

  test("an id that names no tab changes nothing", () => {
    expect(reorderTabWithinGroup(grouped, "missing", 0)).toBe(grouped);
  });
});

describe("a tab's colour", () => {
  const groups = [{ id: "g1", color: "#4488cc" }];

  test("a tab's own colour wins over its group's, because that is what an operator is marking", () => {
    const marked = tabColour({ groupId: "g1", color: "#cc4444" }, groups);
    expect(marked).toEqual({ color: "#cc4444", from: "tab" });
  });

  test("an ungrouped tab can be coloured — the gap this bead names", () => {
    expect(tabColour({ color: "#22aa55" }, groups)).toEqual({ color: "#22aa55", from: "tab" });
  });

  test("with no colour of its own, a grouped tab inherits the group's", () => {
    expect(tabColour({ groupId: "g1" }, groups)).toEqual({ color: "#4488cc", from: "group" });
  });

  test("an ungrouped, uncoloured tab has no colour, and the UI says so rather than drawing one", () => {
    expect(tabColour({}, groups)).toEqual({ color: "", from: undefined });
  });

  test("a group id that names no group leaves the tab uncoloured", () => {
    expect(tabColour({ groupId: "gone" }, groups)).toEqual({ color: "", from: undefined });
  });
});
