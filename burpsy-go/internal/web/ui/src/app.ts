// Entry point: wires up tab switching and every tab's init(), then keeps the header (stats, scope,
// CA cert link) refreshed. Bundled by Bun into one app.js — see crates/web/build.rs.

import { initTabs, getJSON, $ } from "./common";
import type { Stats, ScopeInfo } from "./types";
import { initDashboard } from "./dashboard";
import { initHistory } from "./history";
import { initWshistory } from "./wshistory";
import { initSitemap } from "./sitemap";
import { initRepeater } from "./repeater";
import { initIntruder } from "./intruder";
import { initIntercept } from "./intercept";
import { initScanner } from "./scanner";
import { initDecoder } from "./decoder";
import { initComparer } from "./comparer";
import { initToolLog } from "./toollog";
import { initOrganizer } from "./organizer";
import { initMatchReplace } from "./matchreplace";
import { initSession } from "./session";
import { initSequencer } from "./sequencer";
import { initShortcuts } from "./shortcuts";
import { initLive, live } from "./live";
import { refreshLiveAudit } from "./liveaudit";

initTabs();
initDashboard();
initHistory();
initWshistory();
initSitemap();
initRepeater();
initIntruder();
initIntercept();
initScanner();
initDecoder();
initComparer();
initToolLog();
initOrganizer();
initMatchReplace();
initSession();
initSequencer();
// Last: the bindings act on the selection each pane registered above, so every pane must have had its
// chance to register before a key can be pressed.
initShortcuts();

async function refreshStats(): Promise<void> {
  try {
    const s = await getJSON<Stats>("/api/stats");
    const el = $("#stats");
    if (el) {
      el.textContent = `${s.exchanges} exchanges · ${s.messages} msgs · ${(s.stored_bytes / 1048576).toFixed(2)} MB stored`;
    }
  } catch {
    // best-effort; a transient failure here should not spam the console every 4s
  }
}

async function refreshScope(): Promise<void> {
  try {
    const s = await getJSON<ScopeInfo>("/api/scope");
    const el = $("#scope-badge");
    if (!el) return;
    el.textContent = s.allow_all ? "scope: everything" : `scope: ${s.rules.length} rule(s)`;
    el.title = s.allow_all ? "everything is in scope" : JSON.stringify(s.rules);
  } catch {
    // scope is always present in practice; a transient failure just leaves the badge blank
  }
}

async function refreshCaLink(): Promise<void> {
  const a = $<HTMLAnchorElement>("#ca-link");
  if (!a) return;
  try {
    const r = await fetch("/ca.crt", { method: "HEAD" });
    a.style.display = r.ok ? "" : "none";
  } catch {
    a.style.display = "none";
  }
}

void refreshStats();
void refreshScope();
void refreshCaLink();

// The header counts follow captured traffic, so they are pushed like everything else rather than polled
// on a timer. `section: ""` because the header is always on screen — unlike a pane, it has no tab to be
// hidden behind. The 4s fallback is what this used to do unconditionally, and now only happens when the
// event stream is not delivering.
live({ kinds: ["history"], section: "", refresh: () => void refreshStats(), fallbackMs: 4000 });

// The live-audit card is drawn on two panes (Dashboard and Scanner) and its counts follow captured
// traffic and new findings, so it is registered once per pane rather than once per module: each copy
// only needs re-reading while its own tab is on screen, and liveaudit.ts collapses two fetches in the
// same tick into one. Wired here rather than in mountLiveAudit because the module knows its own id
// prefixes, not which section each of them was mounted into.
for (const section of ["dashboard", "scanner"]) {
  live({
    kinds: ["history", "issues", "dashboard"],
    section,
    refresh: () => void refreshLiveAudit(),
    minGapMs: 1000,
    fallbackMs: 4000,
  });
}

// Last of all: every pane has registered by now, and initLive must not open the stream before the panes
// that would answer its frames exist.
initLive();
