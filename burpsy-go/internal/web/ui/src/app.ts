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
setInterval(() => void refreshStats(), 4000);
