import { describe, expect, test } from "bun:test";
import {
  INTRUDER_TAB_CAP,
  closeAllIntruderTabs,
  closeIntruderTab,
  freshLive,
  initialIntruderTabs,
  openIntruderTab,
  renameIntruderTab,
  reopenIntruderTab,
  repairIntruderTabs,
  runOf,
  switchIntruderTab,
  withRunFor,
  type IntruderTabsState,
} from "./intruder-tabs";
import type { IntruderRun } from "./store";

const start = (): IntruderTabsState => ({ ...freshLive(), ...initialIntruderTabs() });
const apply = (s: IntruderTabsState, patch: Partial<IntruderTabsState>): IntruderTabsState => ({ ...s, ...patch });
const withMsg = (s: IntruderTabsState, msgId: string): IntruderTabsState => ({ ...s, intruder: { ...s.intruder, msgId } });
const run = (label: string): IntruderRun => ({ view: null, legacy: label, snapshot: null });

describe("intruder attack tabs", () => {
  test("each tab keeps its own attack across switches", () => {
    let s = withMsg(start(), "11");
    s = apply(s, openIntruderTab(s));
    expect(s.intruder.msgId).toBe("");
    expect(s.intruderTabs.map((t) => t.name)).toEqual(["1", "2"]);
    s = withMsg(s, "22");
    s = apply(s, switchIntruderTab(s, "i1"));
    expect(s.intruder.msgId).toBe("11");
    s = apply(s, switchIntruderTab(s, "i2"));
    expect(s.intruder.msgId).toBe("22");
    // Exactly one copy of each tab's state: the active slot is never also parked.
    expect(s.intruderTabs.find((t) => t.id === s.activeIntruderTabId)?.parked).toBeNull();
  });

  test("a report lands in the tab that launched it, even after a switch", () => {
    let s = withMsg(start(), "11");
    s = apply(s, openIntruderTab(s)); // the operator moves on while tab 1's attack runs
    s = apply(s, withRunFor(s, "i1", run("tab one's report")));
    expect(s.intruderRun).toBeNull();
    expect(runOf(s, "i1")?.legacy).toBe("tab one's report");
    s = apply(s, switchIntruderTab(s, "i1"));
    expect(s.intruderRun?.legacy).toBe("tab one's report");
  });

  test("closing the active tab moves to its neighbour, and reopen brings it back with its work", () => {
    let s = withMsg(start(), "11");
    s = apply(s, openIntruderTab(s));
    s = withMsg(s, "22");
    s = apply(s, closeIntruderTab(s, "i2"));
    expect(s.activeIntruderTabId).toBe("i1");
    expect(s.intruder.msgId).toBe("11");
    s = apply(s, reopenIntruderTab(s));
    expect(s.activeIntruderTabId).toBe("i2");
    expect(s.intruder.msgId).toBe("22");
    expect(s.closedIntruderTabs).toEqual([]);
  });

  test("closing an inactive tab leaves the live attack alone", () => {
    let s = withMsg(start(), "11");
    s = apply(s, openIntruderTab(s));
    s = withMsg(s, "22");
    s = apply(s, closeIntruderTab(s, "i1"));
    expect(s.intruder.msgId).toBe("22");
    expect(s.intruderTabs.map((t) => t.id)).toEqual(["i2"]);
    expect(s.closedIntruderTabs[0]?.parked?.intruder.msgId).toBe("11");
  });

  test("close all leaves one fresh tab, and reopen replaces that placeholder", () => {
    let s = withMsg(start(), "11");
    s = apply(s, openIntruderTab(s));
    s = withMsg(s, "22");
    s = apply(s, closeAllIntruderTabs(s));
    expect(s.intruderTabs.length).toBe(1);
    expect(s.intruder.msgId).toBe("");
    s = apply(s, reopenIntruderTab(s));
    expect(s.intruderTabs.map((t) => t.id)).toEqual(["i2"]);
    expect(s.intruder.msgId).toBe("22");
  });

  test("names are never reused, renames stick, and the strip is capped", () => {
    let s = start();
    for (let i = 0; i < INTRUDER_TAB_CAP + 3; i++) s = apply(s, openIntruderTab(withMsg(s, String(i))));
    expect(s.intruderTabs.length).toBe(INTRUDER_TAB_CAP);
    expect(new Set(s.intruderTabs.map((t) => t.name)).size).toBe(INTRUDER_TAB_CAP);
    expect(s.closedIntruderTabs.length).toBe(4); // the starting tab plus CAP + 3 opened, CAP kept
    s = apply(s, renameIntruderTab(s, s.activeIntruderTabId, "  login brute  "));
    expect(s.intruderTabs.find((t) => t.id === s.activeIntruderTabId)?.name).toBe("login brute");
    expect(renameIntruderTab(s, s.activeIntruderTabId, "   ")).toEqual({});
  });

  test("a workspace saved before tabs existed gets one tab holding its attack", () => {
    const repaired = repairIntruderTabs({});
    expect(repaired.intruderTabs).toEqual([{ id: "i1", name: "1", parked: null }]);
    expect(repaired.activeIntruderTabId).toBe("i1");
  });

  test("a lost active id never hands the live attack to a parked tab", () => {
    const parkedLive = { ...freshLive(), intruder: { ...freshLive().intruder, msgId: "7" } };
    const repaired = repairIntruderTabs({
      intruderTabs: [{ id: "i3", name: "3", parked: parkedLive }],
      activeIntruderTabId: "gone",
      intruderTabCounter: 3,
    });
    expect(repaired.intruderTabs.find((t) => t.id === "i3")?.parked?.intruder.msgId).toBe("7");
    expect(repaired.intruderTabs.find((t) => t.id === repaired.activeIntruderTabId)?.parked).toBeNull();
    expect(repaired.activeIntruderTabId).not.toBe("i3");
  });
});
