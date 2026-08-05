// Intercept tab: the two condition lists that decide what gets held, then the queue itself — hold,
// view/edit, forward or drop live proxy requests *and* responses. The queue is pushed from the server
// (see live.ts): a held message blocks its connection with somebody watching this tab, so it is the one
// surface where the difference between "as it happens" and "within 1.5 seconds" is the whole feature.
//
// Why the rule tables are edited locally and saved explicitly, unlike Match & Replace's per-row PUT:
// the queue below them re-renders whenever the server says it changed, and a PUT-per-keystroke against
// a list that re-render touched would fight the operator's cursor. So `load()` only ever touches `#ic-body`, the rule tables live in
// their own containers, and every keystroke writes into local state rather than to the server. The
// server sees a list only when "Save" is pressed — which is also the one place a bad regex can be
// reported, since that is where the server compiles it.

import { $, $all, esc, getJSON, postJSON, putJSON, toast, makeSortable, createSorter, renderEmptyState } from "./common";
import { live } from "./live";

type MatchField = "host" | "path" | "extension" | "method" | "url" | "status_code" | "content_type";
type Category = "regex" | "literal";
type Direction = "request" | "response";

interface RuleSpec {
  field: MatchField;
  enabled: boolean;
  string_match: string;
  category: Category;
  comment: string;
}

interface RulesResp {
  /** Absent when interception is not wired up at all; every other field goes with it. */
  wired?: boolean;
  active?: boolean;
  unconditional?: boolean;
  count?: number;
  rules?: RuleSpec[];
}

interface HeldView {
  id: number;
  direction: Direction;
  host: string;
  port: number;
  tls: boolean;
  method: string;
  path: string;
  status: number | null;
  held_ms: number;
  len: number;
  raw: string;
}

interface StatusResp {
  enabled: boolean;
  wired: boolean;
  hint?: string;
  pending: number;
  held: HeldView[];
  holds_every_request?: boolean;
  holds_every_response?: boolean;
}

const FIELDS: { value: MatchField; label: string }[] = [
  { value: "host", label: "Host" },
  { value: "path", label: "Path" },
  { value: "extension", label: "File extension" },
  { value: "method", label: "Method" },
  { value: "url", label: "URL" },
  { value: "status_code", label: "Status code" },
  { value: "content_type", label: "Content type" },
];
const CATEGORIES: { value: Category; label: string }[] = [
  { value: "regex", label: "Regex" },
  { value: "literal", label: "Literal" },
];

/** One list's editable state, held locally so a poll never overwrites a half-typed condition. */
interface ListState {
  active: boolean;
  rules: RuleSpec[];
}

const lists: Record<Direction, ListState> = {
  request: { active: true, rules: [] },
  response: { active: false, rules: [] },
};

let selectedId: number | null = null;
/** Ticks the "Held" column while something is held — see startHeldClock. */
let heldClock: ReturnType<typeof setInterval> | undefined;

export function initIntercept(): void {
  const section = $("#intercept");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <label class="switch"><input type="checkbox" id="ic-enabled" /><span class="slider"></span></label>
      <span>Intercept is on</span>
      <span id="ic-status" class="hint"></span>
      <span class="grow"></span>
    </div>
    ${rulesSectionHtml("request")}
    ${rulesSectionHtml("response")}
    <div class="row"><b>Held queue</b><span id="ic-queue-hint" class="hint"></span></div>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th data-sort="direction">Dir</th>
          <th data-sort="method">Method</th>
          <th data-sort="host">Host</th>
          <th data-sort="path">Path</th>
          <th data-sort="status">Status</th>
          <th>Held</th>
          <th data-sort="len">Len</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="ic-body"></tbody>
    </table>
    <div id="ic-editor"></div>
  `;
  
  // Initialize table sorting
  makeSortable('ic-body', 'id');
  
  // Handle sort events
  $('#ic-body')?.addEventListener('sort', (e: CustomEvent) => {
    // Sort would be handled by re-fetching from server
    void load();
  });
  
  $<HTMLInputElement>("#ic-enabled")!.addEventListener("change", (e) =>
    void setEnabled((e.target as HTMLInputElement).checked),
  );
  (["request", "response"] as const).forEach(wireRulesSection);
  void load();
  void loadRules("request");
  void loadRules("response");
  // The latency that matters most in the whole UI: a held request blocks its connection, and an operator
  // is sitting here waiting for the row to appear. So this pane takes every frame as it arrives —
  // minGapMs 0, because /api/intercept returns the queue and nothing else — instead of the 1.5s poll
  // that used to be the wait. The rule lists are not re-read: they only change when this pane changes
  // them, and re-reading would fight the operator's typing.
  live({ kinds: ["intercept"], section: "intercept", refresh: () => void load(), minGapMs: 0, fallbackMs: 1500 });
}

function rulesSectionHtml(dir: Direction): string {
  return `
    <details ${lists[dir].active ? 'open' : ''}>
      <summary>
        <label class="switch"><input type="checkbox" class="ic-list-active" data-dir="${dir}" ${lists[dir].active ? 'checked' : ''} /><span class="slider"></span></label>
        <span>${dir} rules</span>
        <span class="hint">match on ${dir}</span>
      </summary>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Match</th>
            <th>Type</th>
            <th>Comment</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody class="ic-rules ic-rules-${dir}"></tbody>
      </table>
      <div class="row" style="margin-top:4px">
        <select class="ic-field" data-dir="${dir}">
          ${FIELDS.map(f => `<option value="${f.value}">${f.label}</option>`).join('')}
        </select>
        <select class="ic-category" data-dir="${dir}">
          ${CATEGORIES.map(c => `<option value="${c.value}">${c.label}</option>`).join('')}
        </select>
        <input type="text" class="ic-pattern" data-dir="${dir}" placeholder="pattern" style="width:200px" />
        <input type="text" class="ic-comment" data-dir="${dir}" placeholder="comment" style="width:150px" />
        <button class="ghost small" data-dir="${dir}" onclick="addRule('${dir}')">Add</button>
      </div>
    </details>
  `;
}

function wireRulesSection(dir: Direction): void {
  const activeCb = $<HTMLInputElement>(`.ic-list-active[data-dir="${dir}"]`)!;
  activeCb.addEventListener('change', () => {
    lists[dir].active = activeCb.checked;
    void saveRules(dir);
  });

  const addBtn = $(`button[data-dir="${dir}"]`)!;
  addBtn.addEventListener('click', () => addRule(dir));

  // Load existing rules
  void loadRules(dir);
}

// Global function for adding rules
window.addRule = function(dir: Direction): void {
  const field = $(`.ic-field[data-dir="${dir}"]`) as HTMLSelectElement;
  const category = $(`.ic-category[data-dir="${dir}"]`) as HTMLSelectElement;
  const pattern = $(`.ic-pattern[data-dir="${dir}"]`) as HTMLInputElement;
  const comment = $(`.ic-comment[data-dir="${dir}"]`) as HTMLInputElement;

  if (!field || !category || !pattern) return;

  const rule: RuleSpec = {
    field: field.value as MatchField,
    enabled: true,
    string_match: pattern.value,
    category: category.value as Category,
    comment: comment.value,
  };

  lists[dir].rules.push(rule);
  pattern.value = '';
  comment.value = '';
  renderRules(dir);
  void saveRules(dir);
};

function renderRules(dir: Direction): void {
  const tbody = $(`.ic-rules-${dir}`)!;
  if (!tbody) return;

  if (lists[dir].rules.length === 0) {
    tbody.innerHTML = renderEmptyState(
      "No rules defined",
      `Add rules to intercept ${dir}s matching specific criteria`,
      "📝",
      5
    );
    return;
  }

  tbody.innerHTML = lists[dir].rules.map((r, i) => `
    <tr>
      <td>${FIELDS.find(f => f.value === r.field)?.label || r.field}</td>
      <td>${esc(r.string_match)}</td>
      <td>${CATEGORIES.find(c => c.value === r.category)?.label || r.category}</td>
      <td>${esc(r.comment)}</td>
      <td>
        <button class="ghost small" onclick="toggleRule('${dir}', ${i})">${r.enabled ? 'Disable' : 'Enable'}</button>
        <button class="ghost small" onclick="removeRule('${dir}', ${i})">Remove</button>
      </td>
    </tr>
  `).join('');
}

// Global functions for rule management
window.toggleRule = function(dir: Direction, index: number): void {
  const rule = lists[dir].rules[index];
  if (rule) {
    rule.enabled = !rule.enabled;
    renderRules(dir);
    void saveRules(dir);
  }
};

window.removeRule = function(dir: Direction, index: number): void {
  lists[dir].rules.splice(index, 1);
  renderRules(dir);
  void saveRules(dir);
};

async function saveRules(dir: Direction): Promise<void> {
  try {
    await putJSON(`/api/intercept/rules/${dir}`, { rules: lists[dir].rules });
    toast(`Saved ${dir} rules`, 'success');
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

async function loadRules(dir: Direction): Promise<void> {
  try {
    const resp = await getJSON<RulesResp>(`/api/intercept/rules/${dir}`);
    if (resp.rules) {
      lists[dir].rules = resp.rules;
      lists[dir].active = resp.active ?? false;
      renderRules(dir);
      const activeCb = $<HTMLInputElement>(`.ic-list-active[data-dir="${dir}"]`)!;
      activeCb.checked = lists[dir].active;
    }
  } catch (e) {
    // Not wired up yet, ignore
  }
}

async function setEnabled(enabled: boolean): Promise<void> {
  try {
    await postJSON("/api/intercept/enable", { enabled });
  } catch (e) {
    $("#ic-status")!.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
  void load();
}

async function load(): Promise<void> {
  const body = $("#ic-body")!;
  const status = $("#ic-status")!;
  const checkbox = $<HTMLInputElement>("#ic-enabled")!;
  const queueHint = $("#ic-queue-hint")!;
  
  // Show loading state
  body.innerHTML = `<tr><td colspan="9" class="loading-state"><span class="spinner spinner-medium"></span> Loading queue...</td></tr>`;
  
  let resp: StatusResp;
  try {
    resp = await getJSON<StatusResp>("/api/intercept");
  } catch (e) {
    status.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    body.innerHTML = renderEmptyState(
      "Error loading intercept queue",
      (e as Error).message,
      "⚠️",
      9
    );
    return;
  }

  checkbox.checked = resp.enabled;
  status.innerHTML = !resp.wired
    ? esc(resp.hint ?? "interception is not wired up")
    : `<span class="status-pill ${resp.pending ? "bad" : "off"}">${resp.pending} pending</span>`;
  queueHint.textContent = queueHint(resp);

  if (resp.held.length === 0) {
    body.innerHTML = renderEmptyState(
      "No requests held",
      resp.enabled ? "Requests matching your rules will appear here" : "Enable interception to start holding requests",
      "🚦",
      9
    );
    stopHeldClock();
    return;
  }

  body.innerHTML = resp.held.map(renderHeld).join("");
  startHeldClock();
}

function queueHint(resp: StatusResp): string {
  if (!resp.wired) return "";
  if (!resp.enabled) return "interception is off";
  if (resp.holds_every_request) return "holding every request";
  if (resp.holds_every_response) return "holding every response";
  return "";
}

function renderHeld(h: HeldView): string {
  const heldSecs = Math.floor(h.held_ms / 1000);
  const held = heldSecs > 60 ? `${Math.floor(heldSecs / 60)}m ${heldSecs % 60}s` : `${heldSecs}s`;

  return `
    <tr data-id="${h.id}" ${selectedId === h.id ? 'class="on"' : ''}>
      <td>${h.id}</td>
      <td>${h.direction === 'request' ? '→' : '←'}</td>
      <td>${esc(h.method)}</td>
      <td>${esc(h.host)}</td>
      <td>${esc(h.path)}</td>
      <td>${h.status ? h.status : '-'}</td>
      <td class="held-time" data-start="${h.held_ms}">${held}</td>
      <td>${fmtBytes(h.len)}</td>
      <td>
        <button class="ghost small" onclick="forwardHeld(${h.id})">Forward</button>
        <button class="ghost small" onclick="dropHeld(${h.id})">Drop</button>
      </td>
    </tr>
  `;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function startHeldClock(): void {
  if (heldClock) return;
  heldClock = setInterval(() => {
    $all(".held-time").forEach(el => {
      const start = parseInt(el.getAttribute('data-start') || '0');
      const heldSecs = Math.floor((Date.now() - start) / 1000);
      const held = heldSecs > 60 ? `${Math.floor(heldSecs / 60)}m ${heldSecs % 60}s` : `${heldSecs}s`;
      el.textContent = held;
    });
  }, 1000);
}

function stopHeldClock(): void {
  if (heldClock) {
    clearInterval(heldClock);
    heldClock = undefined;
  }
}

function markSelected(id: number | null): void {
  selectedId = id;
  $all("#ic-body tr").forEach((tr) => tr.classList.toggle("on", Number(tr.dataset["id"]) === id));
}

// Global functions for held message actions
window.forwardHeld = async function(id: number): Promise<void> {
  try {
    await postJSON(`/api/intercept/forward/${id}`, {});
    toast(`Forwarded message #${id}`, 'success');
    markSelected(null);
    void load();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};

window.dropHeld = async function(id: number): Promise<void> {
  try {
    await postJSON(`/api/intercept/drop/${id}`, {});
    toast(`Dropped message #${id}`, 'success');
    markSelected(null);
    void load();
  } catch (e) {
    toast((e as Error).message, "error");
  }
};
