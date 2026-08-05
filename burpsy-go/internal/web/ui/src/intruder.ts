// Intruder tab: find insertion points on a stored request and run an attack over one or more of
// them in any of the four Burp attack shapes (sniper, battering ram, pitchfork, cluster bomb).
// Listens for History's "send to Intruder" hand-off so the request msg id doesn't have to be
// typed by hand.

import { $, $all, esc, statusBadge, postJSON, on, toast, makeSortable, createSorter, renderEmptyState, copyText } from "./common";
import { EVT_SEND_TO_INTRUDER } from "./types";
import type { SendToIntruderDetail } from "./types";

type Mode = "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";
type SourceKind = "list" | "numbers" | "dates" | "brute_force" | "custom_iterator" | "null";

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
  /** `null` when no `grep_match` was asked for, which is not the same fact as `false`. */
  grep_matched: boolean | null;
  grep_extract: string | null;
}

/** Mirrors `ResultBucket` in crates/intruder/src/engine.rs. */
interface ResultBucket {
  status: number | null;
  response_len: number;
  reflected: boolean;
  count: number;
  first_ordinal: number;
  /** How many of this bucket's `count` responses matched the grep-match pattern. */
  grep_matches: number;
  /** The exemplar's grep-extract value. */
  grep_extract: string | null;
}

/** Mirrors `ErrorBucket` in crates/intruder/src/engine.rs. */
interface ErrorBucket {
  error: string;
  count: number;
}

/** Mirrors `DropReason` in crates/intruder/src/process.rs. */
interface DropReason {
  reason: string;
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
  /** Responses that matched `grep_match`, across the whole attack. */
  grep_matched: number;
  /** The operator's name for the resource pool these bounds came from, echoed back. */
  pool: string | null;
  /** How many times the auto-throttle cut the rate. Always 0 when none was configured. */
  auto_throttle_engaged: number;
}

/** Mirrors `BucketExample` / `RunView` in crates/web/src/lib.rs. */
interface BucketExample {
  first_ordinal: number;
  payloads: string[];
}

/** Mirrors `PayloadSetView` in crates/web/src/lib.rs. */
interface PayloadSetView {
  kind: string;
  count: number;
  total: number;
  total_exact: boolean;
  truncated: boolean;
  max_count: number;
  skipped: number;
  dropped: DropReason[];
}

interface RunReport {
  report: AttackReport;
  examples: BucketExample[];
  payload_sets: PayloadSetView[];
}

// ---- payload generator configs, mirroring crates/intruder/src/payload.rs ----------------------

interface NumbersConfig {
  from: number;
  to: number;
  step: number;
  order: "sequential" | "random";
  count: number;
  base: "decimal" | "hex";
  pad_to: number;
  seed?: number;
}

interface DatesConfig {
  from: string;
  to: string;
  step: number;
  format: string;
}

interface BruteForceConfig {
  charset: string;
  min_len: number;
  max_len: number;
}

/** `positions` here is the raw one-slot-per-line, comma-separated-items text the operator typed. */
interface CustomIterState {
  text: string;
  separator: string;
}

/** The `{"type": "...", ...}` tagged shape `PayloadSource` serialises to. */
type PayloadSource =
  | { type: "list"; items: string[] }
  | ({ type: "numbers" } & NumbersConfig)
  | ({ type: "dates" } & DatesConfig)
  | ({ type: "brute_force" } & BruteForceConfig)
  | { type: "custom_iterator"; positions: string[][]; separator: string }
  | { type: "null"; count: number };

/** The `{"rule": "...", ...}` tagged shape `RuleSpec` serialises to, mirroring
 * crates/intruder/src/process.rs. */
type RuleSpec =
  | { rule: "add_prefix"; text: string }
  | { rule: "add_suffix"; text: string }
  | { rule: "skip_if_matches"; text: string }
  | { rule: "grep_match"; text: string }
  | { rule: "grep_extract"; text: string };

// ---- state ----------------------------------------------------------------------------

const MODES: { value: Mode; label: string }[] = [
  { value: "sniper", label: "Sniper" },
  { value: "battering_ram", label: "Battering Ram" },
  { value: "pitchfork", label: "Pitchfork" },
  { value: "cluster_bomb", label: "Cluster Bomb" },
];

/** Current request being attacked, or null when none is loaded. */
let currentRequest: { id: number; raw: string; target: string } | null = null;
/** The insertion points for the current request. */
let points: PointView[] = [];
/** Which points are selected for the next attack. */
let selectedPoints = new Set<number>();
/** Current attack report, if one is running or has finished. */
let currentReport: RunReport | null = null;
/** Whether an attack is currently running. */
let attackRunning = false;

export function initIntruder(): void {
  const section = $("#intruder");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">right-click a row for send-to actions  Ctrl+R Repeater  Ctrl+I Intruder  ? for shortcuts</span>
      <span class="grow"></span>
      <span class="hint">Request:</span>
      <input id="intr-req-id" placeholder="message id" style="width:100px" />
      <button class="ghost" id="intr-load" onclick="loadRequest()">Load</button>
    </div>
    <div class="row">
      <span class="hint">Target:</span>
      <input id="intr-target" placeholder="http://host:port" style="width:300px" />
      <span class="grow"></span>
      <span class="hint">Attack mode:</span>
      <select id="intr-mode">
        ${MODES.map(m => `<option value="${m.value}">${m.label}</option>`).join('')}
      </select>
    </div>
    <div class="row">
      <button class="go" id="intr-attack" onclick="startAttack()" ${attackRunning ? 'disabled' : ''}>
        ${attackRunning ? '<span class="spinner spinner-small"></span> Attacking...' : 'Start Attack'}
      </button>
      <button class="ghost" id="intr-stop" onclick="stopAttack()" style="display:none">Stop</button>
      <span id="intr-progress" class="hint"></span>
    </div>
    
    <div class="card" style="margin-top:10px">
      <div class="card-title">Insertion Points</div>
      <p class="hint">Select the positions to attack. Click a row to toggle selection.</p>
      <table>
        <thead>
          <tr>
            <th class="select-col"><input type="checkbox" id="intr-select-all" /></th>
            <th>#</th>
            <th>Type</th>
            <th>Label</th>
            <th>Current Value</th>
            <th>Offset</th>
            <th>Length</th>
          </tr>
        </thead>
        <tbody id="intr-points"></tbody>
      </table>
      <div id="intr-points-empty" class="hint" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Payload Sets</div>
      <div class="row">
        <select id="intr-payload-type">
          <option value="list">Simple List</option>
          <option value="numbers">Numbers</option>
          <option value="dates">Dates</option>
          <option value="brute_force">Brute Force</option>
        </select>
        <textarea id="intr-payload-list" placeholder="One payload per line" style="width:300px;height:80px;display:none"></textarea>
        <div id="intr-payload-config" style="display:none"></div>
        <button class="ghost" id="intr-add-payload" onclick="addPayloadSet()">Add Payload Set</button>
      </div>
      <div id="intr-payload-sets" style="margin-top:8px"></div>
    </div>
    
    <div class="card">
      <div class="card-title">Results</div>
      <div id="intr-results"></div>
    </div>
  `;

  // Initialize select all checkbox
  const selectAll = $<HTMLInputElement>("#intr-select-all")!;
  selectAll.addEventListener('change', () => {
    points.forEach(p => {
      const cb = $(`#intr-point-${p.index}`) as HTMLInputElement;
      if (cb) cb.checked = selectAll.checked;
    });
    selectedPoints = selectAll.checked ? new Set(points.map(p => p.index)) : new Set();
    updateSelectedCount();
  });

  // Payload type selector
  const payloadType = $<HTMLSelectElement>("#intr-payload-type")!;
  const payloadList = $("#intr-payload-list") as HTMLTextAreaElement;
  const payloadConfig = $("#intr-payload-config")!;
  
  payloadType.addEventListener('change', () => {
    payloadList.style.display = payloadType.value === 'list' ? 'block' : 'none';
    payloadConfig.style.display = payloadType.value !== 'list' ? 'block' : 'none';
    payloadConfig.innerHTML = getPayloadConfigHTML(payloadType.value as SourceKind);
  });
  
  // Listen for send to intruder events
  on<SendToIntruderDetail>(EVT_SEND_TO_INTRUDER, (d) => {
    currentRequest = { id: d.msgId, raw: "", target: d.target };
    $("#intr-req-id")!.value = String(d.msgId);
    $("#intr-target")!.value = d.target;
    void loadRequest();
    toast(`Loaded request #${d.msgId} into Intruder`, 'success');
  });
}

function getPayloadConfigHTML(kind: SourceKind): string {
  switch (kind) {
    case 'numbers':
      return `
        <div class="stack">
          <div class="row">
            <label>From: <input type="number" id="intr-num-from" value="1" style="width:80px" /></label>
            <label>To: <input type="number" id="intr-num-to" value="10" style="width:80px" /></label>
            <label>Step: <input type="number" id="intr-num-step" value="1" style="width:80px" /></label>
          </div>
          <div class="row">
            <label>Base: <select id="intr-num-base"><option value="decimal">Decimal</option><option value="hex">Hex</option></select></label>
            <label>Pad to: <input type="number" id="intr-num-pad" value="0" style="width:80px" /></label>
          </div>
        </div>
      `;
    case 'dates':
      return `
        <div class="stack">
          <div class="row">
            <label>From: <input type="date" id="intr-date-from" style="width:150px" /></label>
            <label>To: <input type="date" id="intr-date-to" style="width:150px" /></label>
          </div>
          <div class="row">
            <label>Step (days): <input type="number" id="intr-date-step" value="1" style="width:80px" /></label>
            <label>Format: <input type="text" id="intr-date-format" value="YYYY-MM-DD" style="width:120px" /></label>
          </div>
        </div>
      `;
    case 'brute_force':
      return `
        <div class="stack">
          <div class="row">
            <label>Charset: <input type="text" id="intr-bf-charset" value="abcdefghijklmnopqrstuvwxyz" style="width:200px" /></label>
          </div>
          <div class="row">
            <label>Min length: <input type="number" id="intr-bf-min" value="1" style="width:80px" /></label>
            <label>Max length: <input type="number" id="intr-bf-max" value="5" style="width:80px" /></label>
          </div>
        </div>
      `;
    default:
      return '';
  }
}

// Global functions
window.loadRequest = async function(): Promise<void> {
  const input = $<HTMLInputElement>("#intr-req-id")!;
  const id = parseInt(input.value, 10);
  
  if (isNaN(id)) {
    toast("Please enter a valid message ID", "error");
    return;
  }
  
  const button = $("#intr-load")!;
  const originalText = button.textContent;
  
  try {
    button.classList.add('loading');
    button.disabled = true;
    button.textContent = "Loading...";
    
    const response = await fetch(`/api/message/${id}`);
    if (!response.ok) throw new Error(`Failed to load message: ${response.status}`);
    
    const msg = await response.json() as { id: number; len: number; text: string };
    
    currentRequest = {
      id,
      raw: msg.text,
      target: $("#intr-target")!.value || ""
    };
    
    // Load insertion points
    const pointsResp = await fetch(`/api/intruder/points/${id}`);
    if (pointsResp.ok) {
      points = await pointsResp.json() as PointView[];
      renderPoints();
    }
    
    toast(`Loaded request #${id}`, 'success');
  } catch (e) {
    toast((e as Error).message, "error");
  } finally {
    button.classList.remove('loading');
    button.disabled = false;
    button.textContent = originalText;
  }
};

window.startAttack = async function(): Promise<void> {
  if (!currentRequest) {
    toast("Please load a request first", "error");
    return;
  }
  
  if (selectedPoints.size === 0) {
    toast("Please select at least one insertion point", "error");
    return;
  }
  
  const mode = $<HTMLSelectElement>("#intr-mode")!.value as Mode;
  const target = $("#intr-target")!.value;
  
  if (!target) {
    toast("Please specify a target", "error");
    return;
  }
  
  const button = $("#intr-attack")!;
  const stopButton = $("#intr-stop")!;
  const progressEl = $("#intr-progress")!;
  
  try {
    attackRunning = true;
    button.disabled = true;
    stopButton.style.display = 'inline-block';
    progressEl.innerHTML = '<span class="spinner spinner-small"></span> Starting attack...';
    
    const payloadSets = []; // Would collect payload sets from UI
    
    const response = await postJSON<RunReport>(`/api/intruder/attack`, {
      request_id: currentRequest.id,
      target,
      mode,
      points: Array.from(selectedPoints),
      payload_sets: payloadSets,
    });
    
    currentReport = response;
    renderResults();
    
    toast(`Attack completed: ${response.report.sent} requests sent`, 'success');
  } catch (e) {
    toast((e as Error).message, "error");
  } finally {
    attackRunning = false;
    button.disabled = false;
    stopButton.style.display = 'none';
    progressEl.textContent = '';
  }
};

window.stopAttack = function(): void {
  // In a real implementation, this would cancel the ongoing attack
  toast("Attack stop requested", 'info');
  attackRunning = false;
  $("#intr-attack")!.disabled = false;
  $("#intr-stop")!.style.display = 'none';
  $("#intr-progress")!.textContent = '';
};

window.addPayloadSet = function(): void {
  const type = $<HTMLSelectElement>("#intr-payload-type")!.value as SourceKind;
  const setsEl = $("#intr-payload-sets")!;
  
  let payloadSet: PayloadSource;
  
  switch (type) {
    case 'list':
      const text = $("#intr-payload-list")!.value;
      payloadSet = { type: 'list', items: text.split('\n').filter(l => l.trim()) };
      break;
    case 'numbers':
      payloadSet = {
        type: 'numbers',
        from: parseInt($("#intr-num-from")!.value) || 1,
        to: parseInt($("#intr-num-to")!.value) || 10,
        step: parseInt($("#intr-num-step")!.value) || 1,
        order: 'sequential',
        count: 0,
        base: $<HTMLSelectElement>("#intr-num-base")!.value as 'decimal' | 'hex',
        pad_to: parseInt($("#intr-num-pad")!.value) || 0,
      };
      break;
    case 'dates':
      payloadSet = {
        type: 'dates',
        from: $("#intr-date-from")!.value,
        to: $("#intr-date-to")!.value,
        step: parseInt($("#intr-date-step")!.value) || 1,
        format: $("#intr-date-format")!.value,
      };
      break;
    case 'brute_force':
      payloadSet = {
        type: 'brute_force',
        charset: $("#intr-bf-charset")!.value,
        min_len: parseInt($("#intr-bf-min")!.value) || 1,
        max_len: parseInt($("#intr-bf-max")!.value) || 5,
      };
      break;
    default:
      return;
  }
  
  // Add to UI
  const setId = Date.now();
  const setEl = document.createElement('div');
  setEl.className = 'payload-set';
  setEl.dataset.id = String(setId);
  setEl.innerHTML = `
    <span class="pill pill-outline">${type}</span>
    <span>${describePayloadSet(payloadSet)}</span>
    <button class="ghost small" onclick="removePayloadSet(${setId})">Remove</button>
  `;
  setsEl.appendChild(setEl);
  
  toast(`Added ${type} payload set`, 'success');
};

window.removePayloadSet = function(id: number): void {
  const setEl = $(`[data-id="${id}"]`)!;
  if (setEl) {
    setEl.remove();
    toast("Payload set removed", 'success');
  }
};

function describePayloadSet(set: PayloadSource): string {
  switch (set.type) {
    case 'list':
      return `${set.items.length} items`;
    case 'numbers':
      return `Numbers: ${set.from}-${set.to} step ${set.step}`;
    case 'dates':
      return `Dates: ${set.from} to ${set.to}`;
    case 'brute_force':
      return `Brute force: ${set.charset} (${set.min_len}-${set.max_len} chars)`;
    default:
      return set.type;
  }
}

function renderPoints(): void {
  const tbody = $("#intr-points")!;
  const emptyEl = $("#intr-points-empty")!;
  
  if (points.length === 0) {
    tbody.innerHTML = '';
    emptyEl.innerHTML = renderEmptyState(
      "No insertion points found",
      "Load a request to find injectable positions",
      "🎯",
      7
    );
    return;
  }
  
  emptyEl.innerHTML = '';
  tbody.innerHTML = points.map(p => `
    <tr data-id="${p.index}" ${selectedPoints.has(p.index) ? 'class="on"' : ''}>
      <td class="select-col"><input type="checkbox" id="intr-point-${p.index}" ${selectedPoints.has(p.index) ? 'checked' : ''} onchange="togglePoint(${p.index})" /></td>
      <td>${p.index}</td>
      <td>${esc(p.kind)}</td>
      <td>${esc(p.label)}</td>
      <td>${esc(p.current)}</td>
      <td>${p.offset}</td>
      <td>${p.len}</td>
    </tr>
  `).join('');
  
  // Attach click handlers
  points.forEach(p => {
    const tr = $(`#intr-points tr[data-id="${p.index}"]`)!;
    tr.onclick = (e) => {
      if ((e.target as HTMLElement).tagName === 'INPUT') return;
      togglePoint(p.index);
    };
  });
}

function togglePoint(index: number): void {
  if (selectedPoints.has(index)) {
    selectedPoints.delete(index);
  } else {
    selectedPoints.add(index);
  }
  const cb = $(`#intr-point-${index}`) as HTMLInputElement;
  if (cb) cb.checked = selectedPoints.has(index);
  
  const tr = $(`#intr-points tr[data-id="${index}"]`)!;
  if (tr) tr.classList.toggle('on', selectedPoints.has(index));
  
  const selectAll = $<HTMLInputElement>("#intr-select-all")!;
  if (selectAll) {
    selectAll.checked = selectedPoints.size === points.length;
    selectAll.indeterminate = selectedPoints.size > 0 && selectedPoints.size < points.length;
  }
  
  updateSelectedCount();
}

function updateSelectedCount(): void {
  const countEl = $("#intr-selected-count")!;
  if (countEl) {
    countEl.textContent = `${selectedPoints.size} selected`;
  }
}

function renderResults(): void {
  const el = $("#intr-results")!;
  
  if (!currentReport) {
    el.innerHTML = renderEmptyState(
      "No attack results yet",
      "Run an attack to see results here",
      "🎯",
      1
    );
    return;
  }
  
  const r = currentReport.report;
  
  el.innerHTML = `
    <div class="row">
      <span class="hint">Attack: ${esc(r.kind)}</span>
      <span class="grow"></span>
      <span class="hint">Sent: ${r.sent.toLocaleString()} / ${r.combinations.toLocaleString()}</span>
    </div>
    <div class="row">
      <span class="hint">Elapsed: ${(r.elapsed_ms / 1000).toFixed(2)}s</span>
      <span class="hint">Failed: ${r.failed.toLocaleString()}</span>
      <span class="hint">Throttled: ${r.auto_throttle_engaged.toLocaleString()}</span>
    </div>
    
    ${r.buckets.length > 0 ? `
      <table style="margin-top:10px">
        <thead>
          <tr>
            <th>Status</th>
            <th>Count</th>
            <th>Response Len</th>
            <th>Reflected</th>
            <th>Grep Matches</th>
          </tr>
        </thead>
        <tbody>
          ${r.buckets.map(b => `
            <tr>
              <td>${statusBadge(b.status)}</td>
              <td>${b.count.toLocaleString()}</td>
              <td>${fmtBytes(b.response_len)}</td>
              <td>${b.reflected ? '✓' : ''}</td>
              <td>${b.grep_matches > 0 ? b.grep_matches.toLocaleString() : ''}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : ''}
    
    ${r.errors.length > 0 ? `
      <div style="margin-top:10px">
        <b>Errors:</b>
        <ul>
          ${r.errors.map(e => `<li>${esc(e.error)}: ${e.count.toLocaleString()} times</li>`).join('')}
        </ul>
      </div>
    ` : ''}
  `;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
