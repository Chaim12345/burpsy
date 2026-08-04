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

import { $, $all, esc, getJSON, postJSON, putJSON } from "./common";
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
      <thead><tr><th>#</th><th>Dir</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Held</th><th>Len</th></tr></thead>
      <tbody id="ic-body"></tbody>
    </table>
    <div id="ic-editor"></div>
  `;
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
  let resp: StatusResp;
  try {
    resp = await getJSON<StatusResp>("/api/intercept");
  } catch (e) {
    status.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  checkbox.checked = resp.enabled;
  status.innerHTML = !resp.wired
    ? esc(resp.hint ?? "interception is not wired up")
    : `<span class="status-pill ${resp.pending ? "bad" : "off"}">${resp.pending} pending</span>`;
  $("#ic-queue-hint")!.textContent = queueHint(resp);

  body.innerHTML =
    resp.held
      .map(
        (h) => `<tr class="clickable" data-id="${h.id}">
      <td>${h.id}</td><td>${esc(h.direction)}</td><td>${esc(h.method)}</td>
      <td>${esc(h.host)}:${h.port}${h.tls ? " (tls)" : ""}</td>
      <td>${esc(h.path)}</td><td>${h.status === null ? "-" : h.status}</td>
      <td class="ic-held" data-base="${h.held_ms}">${h.held_ms} ms</td><td>${h.len}</td>
    </tr>`,
      )
      .join("") || `<tr><td colspan="8" class="hint">nothing held</td></tr>`;

  startHeldClock(Date.now());

  $all("#ic-body tr[data-id]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const id = Number(tr.dataset["id"]);
      const h = resp.held.find((x) => x.id === id);
      if (h) openEditor(h);
    });
  });

  // Keep the editor in sync with the queue: close it if the selected message already resolved
  // (forwarded/dropped elsewhere, or its client disconnected).
  if (selectedId !== null && !resp.held.some((h) => h.id === selectedId)) {
    selectedId = null;
    $("#ic-editor")!.innerHTML = "";
  }
}

/** Ages the "Held" column between fetches.
 *
 * The queue itself is pushed, so it is only re-read when it actually changes — which would leave a
 * message that has been held for a minute still reporting the 3ms it had been held for when its row
 * arrived. That number is the one thing on the row that changes without anything happening, so it is
 * counted here instead: the server's own held_ms is the baseline, and the local clock adds the time
 * since the fetch. No request, and it stops itself as soon as the queue is empty.
 */
function startHeldClock(fetchedAt: number): void {
  if (heldClock !== undefined) {
    clearInterval(heldClock);
    heldClock = undefined;
  }
  if ($all(".ic-held").length === 0) return;
  heldClock = setInterval(() => {
    const cells = $all<HTMLElement>(".ic-held");
    if (cells.length === 0) {
      if (heldClock !== undefined) clearInterval(heldClock);
      heldClock = undefined;
      return;
    }
    const since = Date.now() - fetchedAt;
    cells.forEach((cell) => {
      cell.textContent = `${Number(cell.dataset["base"] ?? 0) + since} ms`;
    });
  }, 1000);
}

/// "Interception is on" and "nothing is being held" are both true whenever a list is switched off or
/// every condition in it is unchecked, and that pairing is otherwise indistinguishable from a proxy
/// that has stopped working. Say which it is.
function queueHint(resp: StatusResp): string {
  if (!resp.wired) return "";
  if (!resp.enabled) return "the master switch is off, so nothing is held";
  const holding = [
    resp.holds_every_request ? "every request" : lists.request.active ? "matching requests" : null,
    resp.holds_every_response
      ? "every response"
      : lists.response.active
        ? "matching responses"
        : null,
  ].filter((s): s is string => s !== null);
  return holding.length
    ? `holding ${holding.join(" and ")}`
    : "interception is on, but both rule lists are switched off — nothing will be held";
}

// ---- condition lists ---------------------------------------------------------------------------

function rulesSectionHtml(dir: Direction): string {
  const noun = dir === "request" ? "requests" : "responses";
  return `<div class="card">
    <div class="row">
      <b>${dir === "request" ? "Request" : "Response"} interception rules</b>
      <label><input type="checkbox" id="ic-${dir}-active" /> hold ${noun} matching these rules</label>
      <span class="grow"></span>
      <button class="go small" id="ic-${dir}-save">Save</button>
      <span id="ic-${dir}-meta" class="hint"></span>
    </div>
    <table>
      <thead><tr>
        <th style="width:40px">On</th><th style="width:150px">Field</th><th>Match</th>
        <th style="width:110px">Kind</th><th style="width:140px">Comment</th><th style="width:80px"></th>
      </tr></thead>
      <tbody id="ic-${dir}-body"></tbody>
    </table>
    <button class="dashed" id="ic-${dir}-add">+ add rule</button>
  </div>`;
}

function wireRulesSection(dir: Direction): void {
  $<HTMLInputElement>(`#ic-${dir}-active`)!.addEventListener("change", (e) => {
    lists[dir].active = (e.target as HTMLInputElement).checked;
    note(dir, "unsaved");
  });
  $(`#ic-${dir}-save`)!.addEventListener("click", () => void saveRules(dir));
  $(`#ic-${dir}-add`)!.addEventListener("click", () => {
    lists[dir].rules.push(defaultRule(dir));
    renderRules(dir);
    note(dir, "unsaved");
  });
}

/// A new row's field defaults to what that direction is usually written against: a host for a
/// request, a status code for a response.
function defaultRule(dir: Direction): RuleSpec {
  return {
    field: dir === "request" ? "host" : "status_code",
    enabled: true,
    string_match: "",
    category: "regex",
    comment: "",
  };
}

function note(dir: Direction, text: string, isError = false): void {
  const el = $(`#ic-${dir}-meta`)!;
  if (isError) el.innerHTML = `<span class="err">${esc(text)}</span>`;
  else el.textContent = text;
}

function optionsHtml<T extends string>(opts: { value: T; label: string }[], selected: T): string {
  return opts
    .map(
      (o) => `<option value="${o.value}"${o.value === selected ? " selected" : ""}>${o.label}</option>`,
    )
    .join("");
}

function renderRules(dir: Direction): void {
  const body = $(`#ic-${dir}-body`)!;
  const { rules } = lists[dir];
  $<HTMLInputElement>(`#ic-${dir}-active`)!.checked = lists[dir].active;
  body.innerHTML = rules.length
    ? rules
        .map(
          (r, i) => `<tr data-idx="${i}">
      <td><input type="checkbox" class="ic-r-on"${r.enabled ? " checked" : ""} /></td>
      <td><select class="ic-r-field">${optionsHtml(FIELDS, r.field)}</select></td>
      <td><input class="ic-r-match" style="width:100%" value="${esc(r.string_match)}" placeholder="pattern to match" /></td>
      <td><select class="ic-r-cat">${optionsHtml(CATEGORIES, r.category)}</select></td>
      <td><input class="ic-r-comment" style="width:100%" value="${esc(r.comment)}" placeholder="label" /></td>
      <td><button class="ghost small ic-r-del">Remove</button></td>
    </tr>`,
        )
        .join("")
    : `<tr><td colspan="6" class="hint">no rules — every ${dir} is held while this list is on</td></tr>`;

  $all<HTMLTableRowElement>(`#ic-${dir}-body tr[data-idx]`).forEach((tr) => {
    const idx = Number(tr.dataset["idx"]);
    const rule = lists[dir].rules[idx];
    if (!rule) return;
    const bind = <T extends HTMLElement>(
      sel: string,
      event: string,
      apply: (el: T) => void,
    ): void => {
      tr.querySelector<T>(sel)!.addEventListener(event, (e) => {
        apply(e.target as T);
        note(dir, "unsaved");
      });
    };
    bind<HTMLInputElement>(".ic-r-on", "change", (el) => {
      rule.enabled = el.checked;
    });
    bind<HTMLSelectElement>(".ic-r-field", "change", (el) => {
      rule.field = el.value as MatchField;
    });
    bind<HTMLInputElement>(".ic-r-match", "input", (el) => {
      rule.string_match = el.value;
    });
    bind<HTMLSelectElement>(".ic-r-cat", "change", (el) => {
      rule.category = el.value as Category;
    });
    bind<HTMLInputElement>(".ic-r-comment", "input", (el) => {
      rule.comment = el.value;
    });
    tr.querySelector(".ic-r-del")!.addEventListener("click", () => {
      lists[dir].rules = lists[dir].rules.filter((_, i) => i !== idx);
      renderRules(dir);
      note(dir, "unsaved");
    });
  });
}

function endpoint(dir: Direction): string {
  return `/api/intercept/rules/${dir === "request" ? "requests" : "responses"}`;
}

async function loadRules(dir: Direction): Promise<void> {
  let resp: RulesResp;
  try {
    resp = await getJSON<RulesResp>(endpoint(dir));
  } catch (e) {
    note(dir, (e as Error).message, true);
    return;
  }
  if (resp.wired === false) {
    note(dir, "interception is not wired up");
    return;
  }
  lists[dir] = { active: resp.active ?? false, rules: resp.rules ?? [] };
  renderRules(dir);
  note(dir, describe(dir, resp));
}

async function saveRules(dir: Direction): Promise<void> {
  note(dir, "saving…");
  let resp: RulesResp;
  try {
    resp = await putJSON<RulesResp>(endpoint(dir), lists[dir]);
  } catch (e) {
    // The server compiled and refused, so the list on the proxy is unchanged. The local edit stays on
    // screen: a bad pattern is something to fix, not something to retype.
    note(dir, (e as Error).message, true);
    return;
  }
  renderRules(dir);
  note(dir, describe(dir, resp));
  void load();
}

function describe(dir: Direction, resp: RulesResp): string {
  if (resp.active === false) return `off — no ${dir} is held`;
  if (resp.unconditional) return `on with no conditions — every ${dir} is held`;
  // Named explicitly because it is the one state that looks selective and holds nothing: rows are
  // present, so the list is never blanket, but no enabled condition can match either. Leaving the
  // operator to infer it from "on with 3 condition(s)" is how a working proxy reads as a broken one.
  if (!(resp.rules ?? []).some((r) => r.enabled)) {
    return `on, but every condition is unchecked — no ${dir} is held`;
  }
  return `on with ${resp.count ?? 0} condition(s)`;
}

// ---- the queue editor --------------------------------------------------------------------------

function openEditor(h: HeldView): void {
  selectedId = h.id;
  const editor = $("#ic-editor")!;
  const title =
    h.direction === "response"
      ? `#${h.id} response ${h.status ?? "?"} to ${esc(h.method)} ${esc(h.host)}:${h.port}${esc(h.path)}`
      : `#${h.id} ${esc(h.method)} ${esc(h.host)}:${h.port}${esc(h.path)}`;
  editor.innerHTML = `
    <div class="card">
      <div class="row"><b>${title}</b></div>
      <textarea id="ic-raw" spellcheck="false">${esc(h.raw)}</textarea>
      <div class="row">
        <label><input type="checkbox" id="ic-fixlen" checked /> fix Content-Length</label>
        <button class="go" id="ic-forward">Forward</button>
        <input id="ic-reason" placeholder="drop reason (optional)" style="width:220px" />
        <button class="ghost" id="ic-drop">Drop</button>
        <span id="ic-editor-meta" class="hint"></span>
      </div>
    </div>
  `;
  $("#ic-forward")!.addEventListener("click", () => void forward(h.id));
  $("#ic-drop")!.addEventListener("click", () => void dropHeld(h.id));
}

async function forward(id: number): Promise<void> {
  const raw = $<HTMLTextAreaElement>("#ic-raw")!.value;
  const fix = $<HTMLInputElement>("#ic-fixlen")!.checked;
  try {
    await postJSON(`/api/intercept/${id}/forward`, { raw, fix_content_length: fix });
  } catch (e) {
    $("#ic-editor-meta")!.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  selectedId = null;
  $("#ic-editor")!.innerHTML = "";
  void load();
}

async function dropHeld(id: number): Promise<void> {
  const reason = $<HTMLInputElement>("#ic-reason")!.value;
  try {
    await postJSON(`/api/intercept/${id}/drop`, reason ? { reason } : {});
  } catch (e) {
    $("#ic-editor-meta")!.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  selectedId = null;
  $("#ic-editor")!.innerHTML = "";
  void load();
}
