// Live updates: the page is told what changed instead of asking.
//
// Every tab used to be a poll or a button — four seconds on the header and the dashboard, 1.5 on the
// intercept queue, a Refresh button on the rest. So proxying a request meant waiting, or clicking, to
// see it. This module holds the one EventSource for the whole page (`GET /api/events`) and hands each
// pane the moment its data went stale.
//
// A frame carries a kind and a count, never a row: `{"kind":"history","changes":412}` means "whatever
// reads /api/history is out of date, and 412 changes went into that". The pane then re-fetches through
// the endpoint it already used, so exactly one place in the tree serialises an exchange. Pushing rows
// down the stream would mean a second one, and two producers of the same shape drift.
//
// Three things keep push from costing more than the poll it replaced:
//
//   * The server coalesces. At most one frame per kind per 150ms window, however fast a crawl runs —
//     see internal/web/events.go.
//   * A hidden pane does not fetch. It records that it is stale and re-renders when its tab is next
//     shown, so a crawl that fires frames for six panes causes one fetch, not six. This is why a tab
//     switch is watched (a class change on `main > section`) rather than ignored.
//   * `minGapMs` bounds how often one pane can re-fetch even while frames keep arriving, for the panes
//     whose endpoint is expensive enough to notice.
//
// The polling fallback is a fallback and not a belt-and-braces second channel: it starts only while the
// stream is not delivering, and stops the moment a frame arrives. An environment whose proxy eats
// event-streams therefore degrades to roughly today's behaviour instead of showing a frozen tab, and an
// environment where the stream works pays for one connection and no polls. Which of the two is in
// effect is on screen next to the header counts, because a live-looking pane that is silently stale is
// worse than one that is honestly four seconds behind.

import { $ } from "./common";

/** Kinds mirror Go's changeKind wire names in internal/web/events.go. */
export type LiveKind = "history" | "issues" | "toollog" | "dashboard" | "ws" | "intercept" | "organizer";

export interface LivePane {
  /** Which kinds make this pane stale. */
  kinds: readonly LiveKind[];
  /** Id of the `<section>` the pane lives in, or "" for page chrome that is always visible. */
  section: string;
  /**
   * Re-reads the pane's endpoint(s) and re-renders. Must be safe to call at any time.
   *
   * `changes` is how many underlying changes accumulated since this pane last ran — the sum of the
   * server's own counts, so a pane that wants to report what it is behind by can do so honestly. It is
   * 0 when the refresh was not caused by a frame (a poll while the stream is down, or a resync after a
   * reconnect), which is the case a pane must not render as "nothing changed". Most panes ignore it.
   */
  refresh: (changes: number) => void;
  /** How often to poll this pane *while the stream is not delivering*. Never used otherwise. */
  fallbackMs?: number;
  /** Floor on the gap between two re-fetches while the stream is delivering. */
  minGapMs?: number;
}

/** Matches the 4s poll the header and the dashboard used before this existed. */
const DEFAULT_FALLBACK_MS = 4000;
/** Caps a pane at ~3 re-fetches a second even under a saturated crawl. */
const DEFAULT_MIN_GAP_MS = 300;
/** How often the fallback loop checks whether any pane is due. Only runs while the stream is down. */
const FALLBACK_TICK_MS = 500;
/** The server pings every 20s, so three missed pings means the stream died without saying so. */
const SILENCE_LIMIT_MS = 60_000;
const WATCHDOG_TICK_MS = 15_000;

interface Pane {
  kinds: readonly LiveKind[];
  section: string;
  refresh: (changes: number) => void;
  fallbackMs: number;
  minGapMs: number;
  /** Something changed and this pane has not re-read yet — set while hidden, cleared by a refresh. */
  stale: boolean;
  /** Changes accumulated since the last refresh, summed over however many frames were coalesced. */
  owed: number;
  lastRun: number;
  timer?: ReturnType<typeof setTimeout>;
}

const panes: Pane[] = [];
let stream: EventSource | null = null;
/** True once a frame has actually arrived: headers alone do not prove a stream flows. */
let delivering = false;
let connects = 0;
let lastFrameAt = 0;
let fallbackTimer: ReturnType<typeof setInterval> | undefined;
let indicator: HTMLElement | null = null;

/** Registers a pane for live updates. Call from the pane's init(), before initLive(). */
export function live(spec: LivePane): void {
  panes.push({
    kinds: spec.kinds,
    section: spec.section,
    refresh: spec.refresh,
    fallbackMs: spec.fallbackMs ?? DEFAULT_FALLBACK_MS,
    minGapMs: spec.minGapMs ?? DEFAULT_MIN_GAP_MS,
    stale: false,
    owed: 0,
    lastRun: Date.now(),
  });
}

/** Opens the stream and starts the fallback that covers the time before the first frame. */
export function initLive(): void {
  ensureIndicator();
  watchTabSwitches();
  connect();
  // Down until proven otherwise: if /api/events never delivers, the panes must still update.
  startFallback();
  setInterval(() => {
    if (delivering && Date.now() - lastFrameAt > SILENCE_LIMIT_MS) {
      // Headers came through, frames stopped. Something between here and the server is holding the
      // response open without passing anything along, and EventSource will not notice on its own.
      reconnect();
    }
  }, WATCHDOG_TICK_MS);
}

function connect(): void {
  if (typeof EventSource === "undefined") {
    markDown();
    return;
  }
  try {
    stream = new EventSource("/api/events");
  } catch {
    markDown();
    return;
  }
  stream.onmessage = (e: MessageEvent<string>) => onFrame(e.data);
  stream.onerror = () => {
    // EventSource reconnects by itself, on the server's `retry:` hint. All that is needed here is to
    // start polling in the meantime and say so on screen.
    markDown();
  };
}

function reconnect(): void {
  stream?.close();
  stream = null;
  markDown();
  connect();
}

function onFrame(data: string): void {
  lastFrameAt = Date.now();
  let frame: { kind?: string; changes?: number };
  try {
    frame = JSON.parse(data) as { kind?: string; changes?: number };
  } catch {
    return;
  }
  if (!frame.kind) return;
  if (frame.kind === "hello") {
    markUp();
    // A stream that has just (re)connected may have missed changes while it was down — a server that
    // restarted has no memory of what this client was told. The first connection is the exception: the
    // panes have just loaded themselves, so re-reading everything would be a duplicate fetch.
    if (connects++ > 0) panes.forEach((pane) => markStale(pane, 0));
    return;
  }
  if (frame.kind === "ping") {
    // Keepalive. Its only job is the timestamp taken above.
    markUp();
    return;
  }
  markUp();
  for (const pane of panes) {
    if (pane.kinds.includes(frame.kind as LiveKind)) markStale(pane, frame.changes ?? 0);
  }
}

function markStale(pane: Pane, changes: number): void {
  pane.stale = true;
  pane.owed += changes;
  schedule(pane);
}

/** Runs a stale pane, respecting its minimum gap. A hidden pane is left stale until its tab is shown. */
function schedule(pane: Pane): void {
  if (!pane.stale || pane.timer !== undefined || !visible(pane)) return;
  const wait = Math.max(0, pane.minGapMs - (Date.now() - pane.lastRun));
  pane.timer = setTimeout(() => {
    pane.timer = undefined;
    if (!pane.stale || !visible(pane)) return;
    pane.stale = false;
    pane.lastRun = Date.now();
    const owed = pane.owed;
    pane.owed = 0;
    pane.refresh(owed);
  }, wait);
}

function visible(pane: Pane): boolean {
  if (pane.section === "") return true;
  return document.getElementById(pane.section)?.classList.contains("on") === true;
}

/** Re-renders a pane that went stale while its tab was in the background, as the tab comes forward. */
function watchTabSwitches(): void {
  const sections = Array.from(document.querySelectorAll("main > section"));
  if (sections.length === 0) return;
  // A class observer rather than a click handler on the tab bar: it holds however the class got
  // toggled, including switchTab() called from a cross-tab hand-off.
  const observer = new MutationObserver(() => {
    for (const pane of panes) {
      if (pane.stale) schedule(pane);
    }
  });
  sections.forEach((s) => observer.observe(s, { attributes: true, attributeFilter: ["class"] }));
}

// ---- fallback ---------------------------------------------------------------------------------

function startFallback(): void {
  if (fallbackTimer !== undefined) return;
  fallbackTimer = setInterval(() => {
    if (delivering) return;
    const now = Date.now();
    for (const pane of panes) {
      if (!visible(pane) || now - pane.lastRun < pane.fallbackMs) continue;
      pane.stale = false;
      pane.owed = 0;
      pane.lastRun = now;
      // 0 changes: a poll cannot know what changed, only that it is time to look again.
      pane.refresh(0);
    }
  }, FALLBACK_TICK_MS);
}

function stopFallback(): void {
  if (fallbackTimer === undefined) return;
  clearInterval(fallbackTimer);
  fallbackTimer = undefined;
}

function markUp(): void {
  lastFrameAt = Date.now();
  if (delivering) return;
  delivering = true;
  stopFallback();
  renderIndicator();
}

function markDown(): void {
  if (!delivering && fallbackTimer !== undefined) return;
  delivering = false;
  startFallback();
  renderIndicator();
}

// ---- the honest indicator ---------------------------------------------------------------------

function ensureIndicator(): void {
  const stats = $("#stats");
  if (!stats || indicator) return;
  // A sibling of #stats rather than part of it: refreshStats() assigns textContent, which would
  // otherwise wipe this out four times a minute. Built here rather than in index.html so the mode is
  // reported by the code that knows it.
  indicator = document.createElement("span");
  indicator.id = "live-state";
  indicator.className = "hint";
  stats.insertAdjacentElement("afterend", indicator);
  renderIndicator();
}

function renderIndicator(): void {
  if (!indicator) return;
  indicator.textContent = delivering ? "live" : "polling";
  indicator.title = delivering
    ? "changes are pushed from the server as they happen (/api/events)"
    : "the event stream is not delivering, so panes are polled on an interval instead — this is the fallback, not a live view";
}
