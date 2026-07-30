// Intruder tab: find insertion points on a stored request and run an attack over one or more of
// them in any of the four Burp attack shapes (sniper, battering ram, pitchfork, cluster bomb).
// Listens for History's "send to Intruder" hand-off so the request msg id doesn't have to be
// typed by hand.

import { $, $all, esc, statusBadge, postJSON, on } from "./common";
import { EVT_SEND_TO_INTRUDER } from "./types";
import type { SendToIntruderDetail } from "./types";

type Mode = "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";

interface PointView {
  index: number;
  kind: string;
  label: string;
  offset: number;
  len: number;
  current: string;
}

/** Legacy per-attempt row, still returned when a request names neither `mode` nor `payload_sets`. */
interface AttemptView {
  payload: string;
  status: number | null;
  len: number;
  duration_ms: number;
  error: string | null;
}

/** Mirrors `ResultBucket` in crates/intruder/src/engine.rs. */
interface ResultBucket {
  status: number | null;
  response_len: number;
  reflected: boolean;
  count: number;
  first_ordinal: number;
}

/** Mirrors `ErrorBucket` in crates/intruder/src/engine.rs. */
interface ErrorBucket {
  error: string;
  count: number;
}

/** Mirrors `AttackReport` in crates/intruder/src/engine.rs (fields the UI doesn't render are omitted). */
interface AttackReport {
  kind: string;
  combinations: number;
  combinations_exact: boolean;
  max_requests: number;
  truncated: boolean;
  sent: number;
  failed: number;
  elapsed_ms: number;
  buckets: ResultBucket[];
  buckets_truncated: boolean;
  unbucketed: number;
  errors: ErrorBucket[];
}

/** Mirrors `BucketExample` / `RunView` in crates/web/src/lib.rs. */
interface BucketExample {
  first_ordinal: number;
  payloads: string[];
}

interface RunReport {
  report: AttackReport;
  examples: BucketExample[];
}

/** A representative XSS/traversal/SSTI probe set, matching Burp's own default Intruder payloads. */
const DEFAULT_PAYLOADS = ["'\n", '"', "../../etc/passwd", "{{7*7}}", "<script>"].join(",");

/** Points found by the last "Find points" call. */
let points: PointView[] = [];
/** Indices into `points` currently checked. */
const selected = new Set<number>();
let mode: Mode = "sniper";
/** Payload text entered for sniper/battering ram, kept across re-renders of that one field. */
let sniperPayloads = DEFAULT_PAYLOADS;
/** Per-position payload text entered for pitchfork/cluster bomb, kept across selection changes. */
const positionPayloads = new Map<number, string>();

export function initIntruder(): void {
  const section = $("#intruder");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <input id="int-msg" placeholder="request msg id" style="width:130px" />
      <input id="int-target" placeholder="http://host:port" style="width:280px" />
      <label><input type="checkbox" id="int-all" /> all point types</label>
      <button class="go" id="int-find">Find points</button>
    </div>
    <table>
      <thead><tr><th></th><th>#</th><th>Kind</th><th>Label</th><th>Offset</th><th>Len</th><th>Current value</th></tr></thead>
      <tbody id="int-points"></tbody>
    </table>
    <div class="row" style="margin-top:10px">
      <label>mode
        <select id="int-mode">
          <option value="sniper">sniper</option>
          <option value="battering_ram">battering ram</option>
          <option value="pitchfork">pitchfork</option>
          <option value="cluster_bomb">cluster bomb</option>
        </select>
      </label>
      <button class="go" id="int-run">Attack</button>
      <span id="int-meta" class="hint"></span>
    </div>
    <div id="int-payloads" class="stack"></div>
    <div id="int-report" class="hint"></div>
    <div id="int-results"></div>
  `;
  $("#int-find")!.addEventListener("click", () => void findPoints());
  $("#int-run")!.addEventListener("click", () => void runAttack());
  $<HTMLSelectElement>("#int-mode")!.addEventListener("change", (e) => {
    capturePayloadValues();
    mode = (e.target as HTMLSelectElement).value as Mode;
    renderPayloadArea();
  });
  on<SendToIntruderDetail>(EVT_SEND_TO_INTRUDER, (d) => {
    $<HTMLInputElement>("#int-msg")!.value = String(d.msgId);
    $<HTMLInputElement>("#int-target")!.value = d.target;
  });
  renderPayloadArea();
}

async function findPoints(): Promise<void> {
  const body = $("#int-points")!;
  const msgId = Number($<HTMLInputElement>("#int-msg")!.value);
  const all = $<HTMLInputElement>("#int-all")!.checked;
  selected.clear();
  positionPayloads.clear();
  try {
    points = await postJSON<PointView[]>("/api/intruder/points", { msg_id: msgId, all });
  } catch (e) {
    points = [];
    body.innerHTML = `<tr><td colspan="7" class="err">${esc((e as Error).message)}</td></tr>`;
    renderPayloadArea();
    return;
  }
  renderPointsTable();
  renderPayloadArea();
}

function renderPointsTable(): void {
  const body = $("#int-points")!;
  body.innerHTML =
    points
      .map(
        (p) =>
          `<tr><td><input type="checkbox" class="int-pt" data-idx="${p.index}" ${selected.has(p.index) ? "checked" : ""} /></td>
           <td>${p.index}</td><td>${esc(p.kind)}</td><td>${esc(p.label)}</td><td>${p.offset}</td><td>${p.len}</td><td>${esc(p.current)}</td></tr>`,
      )
      .join("") || `<tr><td colspan="7" class="hint">no insertion points found</td></tr>`;
  $all<HTMLInputElement>("#int-points .int-pt").forEach((cb) => {
    cb.addEventListener("change", () => {
      capturePayloadValues();
      const idx = Number(cb.dataset["idx"]);
      if (cb.checked) selected.add(idx);
      else selected.delete(idx);
      renderPayloadArea();
    });
  });
}

function pointLabel(p: PointView): string {
  return `#${p.index} ${p.kind}${p.label ? ` (${p.label})` : ""}`;
}

/** Saves whatever is currently typed before the payload area gets rebuilt out from under it. */
function capturePayloadValues(): void {
  if (mode === "sniper" || mode === "battering_ram") {
    const el = $<HTMLTextAreaElement>("#int-payloads-single");
    if (el) sniperPayloads = el.value;
  } else {
    $all<HTMLTextAreaElement>(".int-payload-set").forEach((el) => {
      positionPayloads.set(Number(el.dataset["idx"]), el.value);
    });
  }
}

/** Rebuilds the payload-entry area to match the current mode and selected positions. */
function renderPayloadArea(): void {
  const area = $("#int-payloads")!;
  const sel = [...selected].sort((a, b) => a - b);
  if (mode === "sniper" || mode === "battering_ram") {
    area.innerHTML = `
      <div class="row">
        <textarea id="int-payloads-single" placeholder="payloads, comma separated"
                  style="width:460px;min-height:60px">${esc(sniperPayloads)}</textarea>
      </div>
    `;
    return;
  }
  if (sel.length === 0) {
    area.innerHTML = `<div class="hint">select 2-20 insertion points above for ${esc(mode)}</div>`;
    return;
  }
  area.innerHTML = sel
    .map((idx) => {
      const p = points[idx];
      const label = p ? pointLabel(p) : `#${idx}`;
      const value = positionPayloads.get(idx) ?? DEFAULT_PAYLOADS;
      return `<div class="row">
        <label style="width:220px">${esc(label)}</label>
        <textarea class="int-payload-set" data-idx="${idx}" placeholder="payloads, comma separated"
                  style="width:400px;min-height:60px">${esc(value)}</textarea>
      </div>`;
    })
    .join("");
}

async function runAttack(): Promise<void> {
  const meta = $("#int-meta")!;
  const report = $("#int-report")!;
  const results = $("#int-results")!;
  const sel = [...selected].sort((a, b) => a - b);
  if (sel.length === 0) {
    meta.innerHTML = `<span class="err">select at least one insertion point</span>`;
    return;
  }
  if ((mode === "pitchfork" || mode === "cluster_bomb") && (sel.length < 2 || sel.length > 20)) {
    meta.innerHTML = `<span class="err">${esc(mode)} needs between 2 and 20 selected points</span>`;
    return;
  }

  capturePayloadValues();
  const payloadSets: string[][] =
    mode === "sniper" || mode === "battering_ram"
      ? [sniperPayloads.split(",")]
      : sel.map((idx) => (positionPayloads.get(idx) ?? "").split(","));

  meta.textContent = "running…";
  report.innerHTML = "";
  results.innerHTML = "";
  const body = {
    msg_id: Number($<HTMLInputElement>("#int-msg")!.value),
    target: $<HTMLInputElement>("#int-target")!.value,
    all: $<HTMLInputElement>("#int-all")!.checked,
    mode,
    points: sel,
    payload_sets: payloadSets,
  };
  let out: RunReport | AttemptView[];
  try {
    out = await postJSON<RunReport | AttemptView[]>("/api/intruder/run", body);
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  if (Array.isArray(out)) {
    renderLegacyResults(out);
    return;
  }
  renderReport(out);
}

/** Fallback for the flat-array shape — reachable only if a caller still posts the legacy form. */
function renderLegacyResults(rows: AttemptView[]): void {
  const meta = $("#int-meta")!;
  const results = $("#int-results")!;
  meta.textContent = `${rows.length} attempts`;
  results.innerHTML = `
    <table>
      <thead><tr><th>Payload</th><th>Status</th><th>Len</th><th>ms</th><th>Error</th></tr></thead>
      <tbody>
        ${rows
          .map(
            (a) =>
              `<tr><td>${esc(a.payload)}</td><td>${statusBadge(a.status)}</td><td>${a.len}</td>
               <td>${a.duration_ms}</td><td class="err">${esc(a.error ?? "")}</td></tr>`,
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function renderReport(out: RunReport): void {
  const meta = $("#int-meta")!;
  const report = $("#int-report")!;
  const results = $("#int-results")!;
  const r = out.report;
  meta.textContent = `${r.sent} sent`;
  report.innerHTML = `
    <div class="row">
      <span>${esc(r.kind)}</span>
      <span>combinations: ${r.combinations}${r.combinations_exact ? "" : "+"}</span>
      <span>sent: ${r.sent}</span>
      <span>failed: ${r.failed}</span>
      <span>${r.elapsed_ms} ms</span>
      ${r.truncated ? `<span class="err">truncated at ${r.max_requests}</span>` : ""}
    </div>
  `;
  const examplesByOrdinal = new Map(out.examples.map((e) => [e.first_ordinal, e.payloads]));
  results.innerHTML = `
    <table>
      <thead><tr><th>First #</th><th>Status</th><th>Len</th><th>Reflected</th><th>Count</th><th>Payloads</th></tr></thead>
      <tbody>
        ${
          r.buckets
            .map((b) => {
              const payloads = examplesByOrdinal.get(b.first_ordinal) ?? [];
              return `<tr><td>${b.first_ordinal}</td><td>${statusBadge(b.status)}</td><td>${b.response_len}</td>
                <td>${b.reflected ? "yes" : ""}</td><td>${b.count}</td><td>${esc(payloads.join(" + "))}</td></tr>`;
            })
            .join("") || `<tr><td colspan="6" class="hint">no buckets</td></tr>`
        }
      </tbody>
    </table>
    ${r.buckets_truncated ? `<div class="hint">bucket list truncated; ${r.unbucketed} unbucketed responses</div>` : ""}
    ${r.errors.length ? `<div class="hint err">${esc(r.errors.map((e) => `${e.error} ×${e.count}`).join(", "))}</div>` : ""}
  `;
}
