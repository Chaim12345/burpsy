/**
 * The bottom dock (burpsy-react-ui-08wx): Burp keeps "All issues" and "Event log" one click away
 * under every tool. This is a collapsed bar above the status strip; opening a tab slides a short
 * list up. It reads the same two resources the Dashboard does, so nothing new is fetched.
 *
 * Not offered: "Detach". The console has no pop-out window mechanism to hang it on, and a second
 * browser window would need its own copy of the query cache and auth state.
 */
import { useState } from "react";
import { useDashboard, useIssues } from "../lib/data";
import { SEVERITY_KEYS, severityKey, severityTone } from "../lib/severity";
import type { Finding, ToolEvent } from "../lib/types";
import { Badge } from "./primitives";

export const DOCK_STORAGE_KEY = "burpsy.dock.tab";
export type DockTab = "issues" | "events";

function readTab(): DockTab | null {
 try {
  const raw = window.localStorage.getItem(DOCK_STORAGE_KEY);
  return raw === "issues" || raw === "events" ? raw : null;
 } catch {
  return null;
 }
}

function writeTab(tab: DockTab | null): void {
 try {
  if (tab) window.localStorage.setItem(DOCK_STORAGE_KEY, tab);
  else window.localStorage.removeItem(DOCK_STORAGE_KEY);
 } catch {
  /* storage blocked: the dock still works, it just forgets */
 }
}

function rank(finding: Finding): number {
 const key = severityKey(finding.severity);
 return key ? SEVERITY_KEYS.indexOf(key) : SEVERITY_KEYS.length;
}

/** Findings worst first; the sort is stable so equal severities keep the server's order. */
export function sortIssues(findings: Finding[]): Finding[] {
 return [...findings].sort((a, b) => rank(a) - rank(b));
}

export function sortEvents(events: ToolEvent[]): ToolEvent[] {
 return [...events].sort((a, b) => (b.at_ms ?? 0) - (a.at_ms ?? 0));
}

const EVENT_TONE: Record<string, "bad" | "warn" | "neutral"> = { error: "bad", warn: "warn", info: "neutral" };

export function BottomDock(): JSX.Element {
 const [tab, setTab] = useState<DockTab | null>(readTab);
 const issues = useIssues();
 const dashboard = useDashboard();
 const findings = issues.data?.findings ?? [];
 const events = dashboard.data?.events ?? [];

 const choose = (next: DockTab) => {
  const value = tab === next ? null : next;
  setTab(value);
  writeTab(value);
 };
 const collapse = () => {
  setTab(null);
  writeTab(null);
 };

 return (
  <section className="bottom-dock" aria-label="Issues and event log" data-open={tab ? "true" : "false"}>
   <div className="bottom-dock-bar">
    <button type="button" className="bottom-dock-tab" aria-pressed={tab === "issues"} onClick={() => choose("issues")}>
     All issues ({findings.length})
    </button>
    <button type="button" className="bottom-dock-tab" aria-pressed={tab === "events"} onClick={() => choose("events")}>
     Event log ({events.length})
    </button>
    {tab ? (
     <button type="button" className="bottom-dock-close" onClick={collapse}>
      Collapse dock
     </button>
    ) : null}
   </div>
   {tab === "issues" ? (
    <ul className="bottom-dock-list">
     {findings.length === 0 ? <li className="bottom-dock-empty">{issues.data?.hint ?? "No issues yet."}</li> : null}
     {sortIssues(findings).map((finding, index) => (
      <li key={`${finding.issue_name ?? finding.check_name}-${finding.host}-${index}`} data-testid="dock-issue">
       <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge> {finding.issue_name ?? finding.check_name}
       <span className="bottom-dock-host"> {finding.host}</span>
      </li>
     ))}
    </ul>
   ) : null}
   {tab === "events" ? (
    <ul className="bottom-dock-list">
     {events.length === 0 ? <li className="bottom-dock-empty">No events yet.</li> : null}
     {sortEvents(events).map((event, index) => (
      <li key={event.id ?? index} data-testid="dock-event">
       <Badge tone={EVENT_TONE[event.severity] ?? "neutral"}>{event.severity}</Badge> {event.kind}
       <span className="bottom-dock-host"> {event.detail}</span>
      </li>
     ))}
    </ul>
   ) : null}
  </section>
 );
}
