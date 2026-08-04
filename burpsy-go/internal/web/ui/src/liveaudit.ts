// The live active audit switch, owned in one place and drawn in as many panes as want it.
//
// Why this module exists: the switch lived in the Dashboard, which is where Burp puts it, and an
// operator who went looking for "scan on/off" in the Scanner tab found nothing there and concluded it
// did not exist. The fix is to put the control in both places — but two panes each with their own
// fetch, their own `enabled` flag and their own POST is how a UI ends up showing "on" on one screen
// and "off" on another. So there is exactly one fetch, one POST, one cached state and one renderer
// here; a pane contributes markup and a mount, nothing else. Flipping the switch anywhere re-renders
// everywhere, which is what makes the two panes unable to disagree.
//
// The counting fields are all rendered, not just `swept` and `findings`. `behind`, `skipped` and
// `stalled_at` exist precisely so a swept count is never mistaken for complete coverage — a sweep
// 9,000 exchanges behind is not caught up — and `collapsed` / `ledger_resets` exist so the ledger's
// saving, and the times that ledger was dropped, are visible rather than inferred from a request rate.
// A pane that shows the number and omits the caveats re-creates the problem they were added to solve,
// so the renderer draws them together or not at all.

import { $, esc, getJSON, postJSON, toast } from "./common";

interface LiveAuditResp {
  wired: boolean;
  enabled: boolean;
  hint?: string;
  swept?: number;
  findings?: number;
  /** Exchanges the sweep gave up waiting on. Carried beside `swept`, never added to it: an exchange
   * the sweep abandoned is not one that came back clean. */
  skipped?: number;
  /** The exchange id the cursor is currently waiting on, absent when it is moving. */
  stalled_at?: number;
  /** Recorded-but-not-yet-reached exchanges: the backlog. Not optional — a zero backlog is the most
   * useful thing this field says, and omitting it would make caught-up indistinguishable from a build
   * that never reported it. */
  behind: number;
  /** Checks the shared ledger refused as already covered. This work ran; it is reported rather than
   * counted as a caveat. */
  collapsed: number;
  /** How many times that ledger was dropped at its unit cap. Each reset re-dispatches checks it had
   * already collapsed, so a nonzero count belongs on screen. */
  ledger_resets: number;
  query?: string;
}

/** Every mounted control's id prefix. Dashboard is "dash" (which keeps its original element ids),
 * Scanner is "scan". */
const mounts: string[] = [];
/** The last state fetched, so a pane mounting later renders immediately instead of after one fetch. */
let last: LiveAuditResp | null = null;
/** The in-flight GET, so two panes mounting in the same tick share one request instead of racing two.
 * "One fetch" is the claim this module makes; it should be literally true. */
let inFlight: Promise<void> | null = null;

/** The control's markup. `prefix` namespaces every id, so two copies can coexist on one page. */
export function liveAuditCardHtml(prefix: string): string {
  return `
    <div class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:4px">
        <div class="card-title" style="margin:0">Live active audit</div>
        <label class="switch" title="audit new in-scope traffic as it is captured"><input type="checkbox" id="${prefix}-audit-toggle" /><span class="slider"></span></label>
      </div>
      <p class="hint">Auditing new in-scope traffic. Active checks are never sent automatically
        while this is off.</p>
      <div id="${prefix}-audit-hint" class="hint"></div>
      <div class="row">
        <div class="stat-tile grow"><div class="label">Exchanges swept</div><div class="value" id="${prefix}-audit-swept">0</div></div>
        <div class="stat-tile grow"><div class="label">Findings</div><div class="value" id="${prefix}-audit-findings">0</div></div>
      </div>
      <div class="row" id="${prefix}-audit-chips"></div>
      <div id="${prefix}-audit-verdict"></div>
    </div>`;
}

/** Wires one copy of the control. Call after the pane has inserted `liveAuditCardHtml(prefix)`. */
export function mountLiveAudit(prefix: string): void {
  const toggle = $<HTMLInputElement>(`#${prefix}-audit-toggle`);
  if (!toggle) return;
  if (!mounts.includes(prefix)) mounts.push(prefix);
  toggle.addEventListener("change", (e) => void setLiveAudit((e.target as HTMLInputElement).checked));
  if (last) applyTo(prefix, last);
  // No poll of its own: the swept/behind counts move when traffic is captured and findings are added,
  // and app.ts subscribes this card to exactly those kinds through live.ts — once per visible mount,
  // deduped by `inFlight` if both ever fire in the same tick.
  void refreshLiveAudit();
}

/** Fetches the state once and renders every mount from it. */
export function refreshLiveAudit(): Promise<void> {
  if (mounts.length === 0) return Promise.resolve();
  if (inFlight) return inFlight;
  inFlight = (async () => {
    try {
      const r = await getJSON<LiveAuditResp>("/api/scanner/live");
      last = r;
      for (const prefix of mounts) applyTo(prefix, r);
    } catch {
      // best-effort: a transient failure leaves the last known state on screen rather than blanking
      // the switch, which would read as "the feature vanished".
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}

/** Flips the switch. Every mount is re-rendered from the server's answer, so the two panes cannot
 * drift apart and a refused POST cannot leave a switch showing a state the sweep is not in. */
async function setLiveAudit(enabled: boolean): Promise<void> {
  try {
    last = await postJSON<LiveAuditResp>("/api/scanner/live", { enabled });
    for (const prefix of mounts) applyTo(prefix, last);
  } catch (e) {
    toast((e as Error).message, "error");
    await refreshLiveAudit();
  }
}

function applyTo(prefix: string, r: LiveAuditResp): void {
  const toggle = $<HTMLInputElement>(`#${prefix}-audit-toggle`);
  const hint = $(`#${prefix}-audit-hint`);
  const chips = $(`#${prefix}-audit-chips`);
  const verdict = $(`#${prefix}-audit-verdict`);
  if (!toggle || !hint) return;

  toggle.disabled = !r.wired;
  if (!r.wired) {
    toggle.checked = false;
    hint.textContent = r.hint ?? "not available";
    if (chips) chips.innerHTML = "";
    if (verdict) verdict.innerHTML = "";
    return;
  }
  toggle.checked = r.enabled;
  const state = r.enabled ? "sweeping new in-scope traffic" : "off — no active checks are being sent";
  hint.textContent = r.query ? `${state} · filtered to ${r.query}` : state;
  $(`#${prefix}-audit-swept`)!.textContent = (r.swept ?? 0).toLocaleString();
  $(`#${prefix}-audit-findings`)!.textContent = (r.findings ?? 0).toLocaleString();
  if (chips) chips.innerHTML = chipsHtml(r);
  if (verdict) verdict.innerHTML = verdictHtml(r);
}

/** Every count the endpoint reports beside `swept`, as chips. The two that mean "this work ran"
 * (collapsed, ledger_resets) are drawn without a severity colour so they do not read as caveats. */
function chipsHtml(r: LiveAuditResp): string {
  const chips: string[] = [];
  if (r.behind > 0) {
    chips.push(
      chip(`${r.behind.toLocaleString()} not swept yet`, "sev-medium", "captured but not yet reached by the sweep cursor"),
    );
  }
  if (r.skipped) {
    chips.push(
      chip(
        `${r.skipped.toLocaleString()} given up on`,
        "sev-low",
        "the sweep stopped waiting for a response; these were not audited and are not counted as clean",
      ),
    );
  }
  if (r.stalled_at !== undefined) {
    chips.push(chip(`waiting on #${r.stalled_at}`, "sev-medium", "the cursor is blocked on this exchange"));
  }
  if (r.collapsed) {
    chips.push(
      chip(
        `${r.collapsed.toLocaleString()} already covered`,
        "",
        "checks the shared ledger refused because an identical one had already run — this work ran, it is not a gap",
      ),
    );
  }
  if (r.ledger_resets) {
    chips.push(
      chip(
        `${r.ledger_resets.toLocaleString()} ledger reset(s)`,
        "sev-low",
        "the dedup ledger was dropped at its cap; checks it had collapsed will re-dispatch once more",
      ),
    );
  }
  return chips.join(" ");
}

function chip(text: string, cls: string, title: string): string {
  return `<span class="pill pill-outline ${cls}" title="${esc(title)}">${esc(text)}</span>`;
}

/** States whether the swept count is a total or a floor. Drawn from the same fields as the chips, so
 * a caveat can never be present without the verdict admitting it. */
function verdictHtml(r: LiveAuditResp): string {
  const gaps: string[] = [];
  if (r.behind > 0) gaps.push(`${r.behind.toLocaleString()} exchange(s) not reached yet`);
  if (r.skipped) gaps.push(`${r.skipped.toLocaleString()} given up on with no response`);
  if (r.stalled_at !== undefined) gaps.push(`the cursor is waiting on exchange ${r.stalled_at}`);
  if (gaps.length === 0) {
    return `<div class="hint ok">complete — the sweep is caught up, nothing skipped and nothing waiting</div>`;
  }
  return `<div class="hint err">a floor, not a total: ${esc(gaps.join("; "))}</div>`;
}
