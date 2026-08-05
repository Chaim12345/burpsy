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

/** Opens the EventSource and starts the fallback watchdog. Call once, after every pane has
 * registered. */
export function initLive(): void {
  if (stream) return; // already open

  // One indicator for the whole page: a pill in the header that says "live" or "polling".
  indicator = document.createElement("span");
  indicator.id = "live-indicator";
  indicator.className = "status-pill off";
  indicator.textContent = "polling";
  indicator.title = "Event stream not connected — falling back to polling";

  const statsEl = $("#stats");
  if (statsEl) {
    statsEl.before(indicator);
  } else {
    // Fallback if stats element doesn't exist
    const header = $("header");
    if (header) {
      header.appendChild(indicator);
    }
  }

  openStream();
  startWatchdog();
  startFallback();
}

function openStream(): void {
  connects++;
  const url = new URL("/api/events", window.location.href);
  url.searchParams.set("v", String(connects));

  stream = new EventSource(url);

  stream.onopen = () => {
    delivering = false; // will be set to true by the first frame
    if (indicator) {
      indicator.className = "status-pill off";
      indicator.textContent = "connecting...";
      indicator.title = "Event stream connecting...";
    }
  };

  stream.onmessage = (e) => {
    delivering = true;
    lastFrameAt = Date.now();
    if (indicator) {
      indicator.className = "status-pill good";
      indicator.textContent = "live";
      indicator.title = "Event stream connected — updates are pushed in real-time";
    }

    let frame: { kind: string; changes: number };
    try {
      frame = JSON.parse(e.data);
    } catch {
      return; // ignore malformed frames
    }

    const kind = frame.kind as LiveKind;
    const changes = frame.changes;

    // Deliver to every pane that cares about this kind
    for (const p of panes) {
      if (p.kinds.includes(kind)) {
        // If the pane is hidden, mark it stale and accumulate the count
        const section = $(`#${p.section}`);
        if (!section || !section.classList.contains("on")) {
          p.stale = true;
          p.owed += changes;
          continue;
        }

        // If the pane is visible, refresh it if enough time has passed
        const now = Date.now();
        if (now - p.lastRun >= p.minGapMs) {
          p.refresh(p.owed + changes);
          p.owed = 0;
          p.lastRun = now;
          p.stale = false;
        } else {
          // Not enough time has passed, accumulate the count
          p.owed += changes;
        }
      }
    }
  };

  stream.onerror = () => {
    if (indicator) {
      indicator.className = "status-pill bad";
      indicator.textContent = "reconnecting...";
      indicator.title = "Event stream disconnected — will retry automatically";
    }
    // Let the watchdog reopen
  };
}

function startWatchdog(): void {
  setInterval(() => {
    // Three missed pings means the stream died without saying so
    if (Date.now() - lastFrameAt > SILENCE_LIMIT_MS) {
      if (stream) {
        stream.close();
        stream = null;
      }
      openStream();
    }
  }, WATCHDOG_TICK_MS);
}

function startFallback(): void {
  fallbackTimer = setInterval(() => {
    if (delivering) return; // stream is working, no fallback needed

    if (indicator) {
      indicator.className = "status-pill bad";
      indicator.textContent = "polling";
      indicator.title = "Event stream not connected — using fallback polling";
    }

    for (const p of panes) {
      // Only poll panes that are visible and due
      const section = $(`#${p.section}`);
      if (!section || !section.classList.contains("on")) continue;

      const now = Date.now();
      if (now - p.lastRun >= p.fallbackMs) {
        p.refresh(0); // 0 because this is a poll, not a frame
        p.lastRun = now;
      }
    }
  }, FALLBACK_TICK_MS);
}

// Tab switch observer: when a tab becomes visible, refresh it if it's stale
export function observeTabSwitches(): void {
  const main = $("main");
  if (!main) return;

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.attributeName !== "class") continue;
      for (const p of panes) {
        const section = $(`#${p.section}`);
        if (section && section.classList.contains("on") && p.stale) {
          p.refresh(p.owed);
          p.owed = 0;
          p.lastRun = Date.now();
          p.stale = false;
        }
      }
    }
  });

  observer.observe(main, { subtree: true, attributes: true, attributeFilter: ["class"] });
}
