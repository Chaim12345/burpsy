// Intruder attack tabs (burpsy-react-ui-9bv2): Burp's "When you send a request to Burp Intruder, this
// creates a new attack tab", with Close all tabs and Reopen closed tab
// (desktop/tools/intruder/configure-attack/managing-tabs.html).
//
// The page edits ONE attack — the store's `intruder`, `intruderRun` and `intruderTab` — and that stays
// true: those three fields are the active tab's live state. Every other tab keeps its state parked in
// its slot. Switching parks the live state in the slot being left and unparks the one being entered,
// so each tab's state exists in exactly one place at a time and the page never learns tabs exist.
//
// The one place that must know: an attack outlives the tab switch that happens while it runs, and its
// report belongs to the tab that launched it. `withRunFor` writes it there, live or parked.

import { emptyIntruderConfig, type IntruderConfig, type IntruderRun } from "./store";

export interface IntruderLive {
 intruder: IntruderConfig;
 intruderRun: IntruderRun | null;
 intruderTab: string;
}

export interface IntruderTabSlot {
 id: string;
 name: string;
 /** This tab's state while another tab is active; null for the active tab, whose state is live. */
 parked: IntruderLive | null;
}

export interface IntruderTabsState extends IntruderLive {
 intruderTabs: IntruderTabSlot[];
 activeIntruderTabId: string;
 /** Monotonic, so a new tab's default name never repeats one already used (Burp numbers them). */
 intruderTabCounter: number;
 /** Reopen stack, most recent last; each entry carries its state. Session-only. */
 closedIntruderTabs: IntruderTabSlot[];
}

/**
 * Open tabs are persisted with their reports, so the strip is bounded. Measured: one finished
 * 500-row attack (the server's detail limit) adds about 200K characters to burpsy.workspace, and the
 * browser's localStorage quota is about 5M characters per origin, shared with Repeater drafts. Eight
 * full tabs is about 1.6M; sixteen would be 3.2M, close enough to the quota that a save could fail.
 */
export const INTRUDER_TAB_CAP = 8;
export const INTRUDER_REOPEN_CAP = 8;

export function freshLive(): IntruderLive {
 return { intruder: emptyIntruderConfig(), intruderRun: null, intruderTab: "positions" };
}

export function initialIntruderTabs(): Pick<
 IntruderTabsState,
 "intruderTabs" | "activeIntruderTabId" | "intruderTabCounter" | "closedIntruderTabs"
> {
 return { intruderTabs: [{ id: "i1", name: "1", parked: null }], activeIntruderTabId: "i1", intruderTabCounter: 1, closedIntruderTabs: [] };
}

/** A tab with no request and no report: a send-to fills it rather than opening another. */
export function isPristine(live: IntruderLive): boolean {
 return live.intruder.msgId === "" && live.intruderRun === null;
}

function liveOf(s: IntruderTabsState): IntruderLive {
 return { intruder: s.intruder, intruderRun: s.intruderRun, intruderTab: s.intruderTab };
}

function parked(s: IntruderTabsState): IntruderTabSlot[] {
 return s.intruderTabs.map((tab) => (tab.id === s.activeIntruderTabId ? { ...tab, parked: liveOf(s) } : tab));
}

function enter(tabs: IntruderTabSlot[], id: string): Partial<IntruderTabsState> {
 const target = tabs.find((tab) => tab.id === id);
 const live = target?.parked ?? freshLive();
 return { ...live, intruderTabs: tabs.map((tab) => (tab.id === id ? { ...tab, parked: null } : tab)), activeIntruderTabId: id };
}

export function switchIntruderTab(s: IntruderTabsState, id: string): Partial<IntruderTabsState> {
 if (id === s.activeIntruderTabId || !s.intruderTabs.some((tab) => tab.id === id)) return {};
 return enter(parked(s), id);
}

/** A new, empty attack tab, made active. At the cap, the oldest inactive tab moves to the reopen stack. */
export function openIntruderTab(s: IntruderTabsState): Partial<IntruderTabsState> {
 const counter = s.intruderTabCounter + 1;
 const id = `i${counter}`;
 let tabs = [...parked(s), { id, name: String(counter), parked: null }];
 let closed = s.closedIntruderTabs;
 while (tabs.length > INTRUDER_TAB_CAP) {
  const evict = tabs.find((tab) => tab.id !== id)!;
  tabs = tabs.filter((tab) => tab !== evict);
  closed = [...closed, evict].slice(-INTRUDER_REOPEN_CAP);
 }
 return { ...enter(tabs, id), intruderTabCounter: counter, closedIntruderTabs: closed };
}

export function closeIntruderTab(s: IntruderTabsState, id: string): Partial<IntruderTabsState> {
 const index = s.intruderTabs.findIndex((tab) => tab.id === id);
 if (index < 0) return {};
 const all = parked(s);
 const closing = all[index]!;
 const closed = [...s.closedIntruderTabs, closing].slice(-INTRUDER_REOPEN_CAP);
 const rest = all.filter((tab) => tab.id !== id);
 if (!rest.length) {
  // Closing the last tab leaves one fresh tab: the page always edits some attack.
  const counter = s.intruderTabCounter + 1;
  const fresh = { id: `i${counter}`, name: String(counter), parked: null };
  return { ...freshLive(), intruderTabs: [fresh], activeIntruderTabId: fresh.id, intruderTabCounter: counter, closedIntruderTabs: closed };
 }
 if (id !== s.activeIntruderTabId) {
  return {
   intruderTabs: rest.map((tab) => (tab.id === s.activeIntruderTabId ? { ...tab, parked: null } : tab)),
   closedIntruderTabs: closed,
  };
 }
 const next = rest[Math.min(index, rest.length - 1)]!;
 return { ...enter(rest, next.id), closedIntruderTabs: closed };
}

export function closeAllIntruderTabs(s: IntruderTabsState): Partial<IntruderTabsState> {
 const closed = [...s.closedIntruderTabs, ...parked(s)].slice(-INTRUDER_REOPEN_CAP);
 const counter = s.intruderTabCounter + 1;
 const fresh = { id: `i${counter}`, name: String(counter), parked: null };
 return { ...freshLive(), intruderTabs: [fresh], activeIntruderTabId: fresh.id, intruderTabCounter: counter, closedIntruderTabs: closed };
}

export function reopenIntruderTab(s: IntruderTabsState): Partial<IntruderTabsState> {
 const last = s.closedIntruderTabs.at(-1);
 if (!last) return {};
 let tabs = parked(s);
 // A lone pristine tab is a placeholder, not work: the reopened attack takes its place.
 if (tabs.length === 1 && isPristine(liveOf(s))) tabs = [];
 tabs = [...tabs, last];
 let closed = s.closedIntruderTabs.slice(0, -1);
 // At the cap the oldest tab moves to the reopen stack, as in openIntruderTab: never dropped.
 while (tabs.length > INTRUDER_TAB_CAP) {
  const evict = tabs[0]!;
  tabs = tabs.slice(1);
  closed = [evict, ...closed].slice(-INTRUDER_REOPEN_CAP);
 }
 return { ...enter(tabs, last.id), closedIntruderTabs: closed };
}

export function renameIntruderTab(s: IntruderTabsState, id: string, name: string): Partial<IntruderTabsState> {
 const trimmed = name.trim();
 if (!trimmed) return {};
 return { intruderTabs: s.intruderTabs.map((tab) => (tab.id === id ? { ...tab, name: trimmed.slice(0, 40) } : tab)) };
}

/** Store a finished (or re-requested) attack's report in the tab that launched it. */
export function withRunFor(s: IntruderTabsState, id: string, run: IntruderRun | null): Partial<IntruderTabsState> {
 if (id === s.activeIntruderTabId) return { intruderRun: run };
 const tab = s.intruderTabs.find((t) => t.id === id);
 if (!tab?.parked) return {};
 return { intruderTabs: s.intruderTabs.map((t) => (t.id === id ? { ...t, parked: { ...t.parked!, intruderRun: run } } : t)) };
}

/** The report a tab holds, live or parked. */
export function runOf(s: IntruderTabsState, id: string): IntruderRun | null {
 if (id === s.activeIntruderTabId) return s.intruderRun;
 return s.intruderTabs.find((t) => t.id === id)?.parked?.intruderRun ?? null;
}

/**
 * Repair a persisted strip: missing (a workspace saved before tabs existed), or one whose active id
 * names no tab. Parked configurations are filled from the defaults for the same reason the live one
 * is (mergePersistedWorkspace): a field the page grew later must arrive with its default.
 */
export function repairIntruderTabs(
 saved: Partial<IntruderTabsState>,
): Pick<IntruderTabsState, "intruderTabs" | "activeIntruderTabId" | "intruderTabCounter"> {
 const init = initialIntruderTabs();
 const tabs = Array.isArray(saved.intruderTabs) ? saved.intruderTabs.filter((t) => t && typeof t.id === "string") : [];
 if (!tabs.length)
  return {
   intruderTabs: init.intruderTabs,
   activeIntruderTabId: init.activeIntruderTabId,
   intruderTabCounter: Math.max(1, saved.intruderTabCounter ?? 1),
  };
 const repaired = tabs.map((t) => ({
  id: t.id,
  name: typeof t.name === "string" && t.name ? t.name : t.id,
  parked: t.parked ? { ...t.parked, intruder: { ...emptyIntruderConfig(), ...t.parked.intruder } } : null,
 }));
 let active = typeof saved.activeIntruderTabId === "string" ? saved.activeIntruderTabId : "";
 if (!repaired.some((t) => t.id === active)) {
  // The live state belongs to some tab; with the active id lost, the first unparked tab takes it,
  // or a new slot does — never a parked tab, whose own state would then be overwritten.
  const unparked = repaired.find((t) => !t.parked);
  active = unparked?.id ?? `i${(saved.intruderTabCounter ?? repaired.length) + 1}`;
  if (!unparked) repaired.push({ id: active, name: String((saved.intruderTabCounter ?? repaired.length) + 1), parked: null });
 }
 const counter = Math.max(saved.intruderTabCounter ?? 0, ...repaired.map((t) => Number(t.id.slice(1)) || 0));
 return {
  intruderTabs: repaired.map((t) => (t.id === active ? { ...t, parked: null } : t)),
  activeIntruderTabId: active,
  intruderTabCounter: counter,
 };
}
