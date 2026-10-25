import { describe, expect, test, beforeEach } from "bun:test";
import { useApp, type RepeaterTab } from "./store";

// ---- the Repeater tab ceiling must not destroy work -------------------------------------
//
// `openRepeaterTab` and `duplicateRepeaterTab` used to end in a bare `.slice(-12)`. Opening a
// thirteenth tab dropped the oldest with no toast, no confirmation, and no entry on the reopen
// stack that exists to protect request drafts.
//
// The report (BURP_PARITY_GAP_ANALYSIS.md §6.7b) proved it by driving the committed store:
// "oldest tab A still present? false. Recoverable from reopen stack? false." These tests pin
// the second half — the cap may evict, but never without leaving the work recoverable.

const CAP = 12;

function reset() {
  useApp.setState({ repeaterTabs: [], closedRepeaterTabs: [], activeRepeaterTab: null });
}

function open(name: string): string {
  return useApp.getState().openRepeaterTab({
    name,
    target: "example.test",
    request: `GET /${name} HTTP/1.1\r\nHost: example.test\r\n\r\n`,
  });
}

function names(list: { name: string }[]): string[] {
  return list.map((t) => t.name);
}

describe("the Repeater tab cap", () => {
  beforeEach(reset);

  test("holds at the cap and does not grow", () => {
    for (let i = 1; i <= CAP + 3; i++) open(`tab${i}`);
    expect(useApp.getState().repeaterTabs).toHaveLength(CAP);
  });

  // The defect itself. Before the fix the oldest tab was simply gone.
  test("a tab pushed out by the cap lands on the reopen stack, not the floor", () => {
    for (let i = 1; i <= CAP; i++) open(`tab${i}`);
    expect(names(useApp.getState().repeaterTabs)).toContain("tab1");
    expect(useApp.getState().closedRepeaterTabs).toHaveLength(0);

    open("tab13");

    const state = useApp.getState();
    expect(names(state.repeaterTabs)).not.toContain("tab1");
    expect(names(state.closedRepeaterTabs)).toEqual(["tab1"]);
  });

  // Recoverability is the whole point: the draft has to come back, not just the tab's name.
  test("the evicted tab is recoverable with its request draft intact", () => {
    for (let i = 1; i <= CAP; i++) open(`tab${i}`);
    const draft = useApp.getState().repeaterTabs[0]!.request;
    open("tab13");

    useApp.getState().reopenClosedRepeaterTab();

    const back = useApp.getState().repeaterTabs.find((t: RepeaterTab) => t.name === "tab1");
    expect(back).toBeDefined();
    expect(back!.request).toBe(draft);
  });

  test("duplicating at the cap also evicts rather than discards", () => {
    for (let i = 1; i <= CAP; i++) open(`tab${i}`);
    const target = useApp.getState().repeaterTabs.at(-1)!.id;

    useApp.getState().duplicateRepeaterTab(target);

    const state = useApp.getState();
    expect(state.repeaterTabs).toHaveLength(CAP);
    expect(names(state.repeaterTabs)).toContain("tab12 copy");
    expect(names(state.closedRepeaterTabs)).toEqual(["tab1"]);
  });

  // Below the cap nothing is touched. Without this the fix could be "always evict", which
  // would put a tab on the reopen stack on every single open and make reopen useless.

  // The defect this file was written for, pinned where it can be re-broken: the cap tests exercise
  // openRepeaterTab, so a version of openRepeaterTab that hands capRepeaterTabs only the new tab
  // fails all of them — but the failure reads as "the cap is broken", not "the call site forgot
  // the existing tabs". This one says it directly (uaq0).
  test("opening a tab appends to the strip, and never replaces it", () => {
    open("first");
    open("second");
    open("third");
    expect(names(useApp.getState().repeaterTabs), "each open must keep what was already there").toEqual([
      "first",
      "second",
      "third",
    ]);
  });

  test("below the cap nothing is evicted", () => {
    for (let i = 1; i <= CAP - 1; i++) open(`tab${i}`);
    const state = useApp.getState();
    expect(state.repeaterTabs).toHaveLength(CAP - 1);
    expect(state.closedRepeaterTabs).toHaveLength(0);
  });

  // Eviction order matches the bulk-close paths (left→right), so reopen walks tabs back in the
  // same direction however they left the strip.
  test("multiple evictions preserve oldest-first order on the reopen stack", () => {
    useApp.setState({
      repeaterTabs: Array.from({ length: CAP + 2 }, (_, i) => ({
        id: `pre${i}`,
        name: `pre${i}`,
        target: "example.test",
        protocol: "https",
        request: "",
      })),
      closedRepeaterTabs: [],
      activeRepeaterTab: null,
    });

    open("fresh");

    const state = useApp.getState();
    expect(state.repeaterTabs).toHaveLength(CAP);
    // Three had to go: the two over the cap plus one to make room for `fresh`.
    expect(names(state.closedRepeaterTabs)).toEqual(["pre0", "pre1", "pre2"]);
  });

  // A close and a cap-eviction are the same event — "a tab left the strip" — so they must not
  // use two different rules. This is the guard against the two paths drifting apart again.
  test("a cap-eviction is indistinguishable from a close on the reopen stack", () => {
    for (let i = 1; i <= CAP; i++) open(`tab${i}`);
    const closedById = useApp.getState().repeaterTabs[0]!.id;
    useApp.getState().closeRepeaterTab(closedById);
    const viaClose = useApp.getState().closedRepeaterTabs.at(-1)!;

    reset();
    for (let i = 1; i <= CAP; i++) open(`tab${i}`);
    open("overflow");
    const viaCap = useApp.getState().closedRepeaterTabs.at(-1)!;

    // Same tab identity and same payload shape, whichever way it left.
    expect(viaCap.name).toBe(viaClose.name);
    expect(viaCap.request).toBe(viaClose.request);
    expect(Object.keys(viaCap).sort()).toEqual(Object.keys(viaClose).sort());
  });
});
