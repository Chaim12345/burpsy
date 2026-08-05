// Match & Replace tab: a Burp-style rule table (enable checkbox / target-type / match / replace /
// comment per row) with add/edit/delete, plus the existing dry-run tester.
//
// Live preview: while the add/edit form is open, every edit (debounced 300ms) calls
// `POST /api/tools/rules/test` with `draft_rules` set to the saved rules with the in-progress row
// spliced in, and renders "original vs auto-modified" from the response. `draft_rules` is compiled
// and tested inline by the server — it never touches the persisted rule set, so an in-progress
// (possibly half-typed, possibly invalid) edit never affects live traffic. The persisted config
// only ever changes on an explicit action: "Save rule" here, or the table's enable-toggle/delete/
// fix-Content-Length controls, all of which PUT immediately the same way the old UI did.

import { $, $all, esc, getJSON, putJSON, postJSON } from "./common";
import { renderSyntax, wireSyntaxEditor } from "./syntax";

type Target =
  | "request_first_line"
  | "request_header"
  | "request_body"
  | "response_header"
  | "response_body";
type Category = "regex" | "literal";

interface RuleSpec {
  rule_type: Target;
  enabled: boolean;
  string_match: string;
  string_replace: string;
  category: Category;
  comment: string;
  /** Not editable from this UI; preserved verbatim when a rule that has one is edited. */
  scope?: unknown;
  /** DSL-02: burpsy-query grammar (host/status/method/mime/body) gating whether this rule applies,
   * alongside (not instead of) `scope`. Absent means "every message `scope`, if any, already lets
   * through." */
  query?: string;
}

interface RuleSetSpec {
  rules: RuleSpec[];
  update_content_length: boolean;
}

interface RulesGetResp {
  affects_requests: boolean;
  affects_responses: boolean;
  config: RuleSetSpec;
}

interface BytesView {
  text: string;
  len: number;
  utf8: boolean;
  truncated: boolean;
}

type PutResult = { ok: true; compiled: number } | { ok: false; error: string };

const TARGETS: { value: Target; label: string }[] = [
  { value: "request_first_line", label: "Request line" },
  { value: "request_header", label: "Request header" },
  { value: "request_body", label: "Request body" },
  { value: "response_header", label: "Response header" },
  { value: "response_body", label: "Response body" },
];
const CATEGORIES: { value: Category; label: string }[] = [
  { value: "regex", label: "Regex" },
  { value: "literal", label: "Literal" },
];
const TYPE_LABEL: Record<Target, string> = TARGETS.reduce(
  (acc, t) => ({ ...acc, [t.value]: t.label }),
  {} as Record<Target, string>,
);

let spec: RuleSetSpec = { rules: [], update_content_length: false };
/** `null` while adding a new rule; the row index while editing an existing one. */
let editingIndex: number | null = null;
let formOpen = false;
let previewTimer: ReturnType<typeof setTimeout> | undefined;

export function initMatchReplace(): void {
  const el = $("#matchreplace");
  if (!el) return;
  el.innerHTML = `
    <div class="command-bar">
      <label><input type="checkbox" id="mr-ucl" /> fix Content-Length after a body rewrite</label>
      <button class="ghost" id="mr-reload">Reload rules</button>
      <span id="mr-meta" class="hint"></span>
    </div>
    <div class="table-panel"><div class="panel-head"><div><div class="eyebrow">Automatic transforms</div><div class="panel-title">Rules</div></div><span id="mr-affects" class="hint"></span></div><div class="table-scroll"><table>
      <thead><tr><th style="width:40px">On</th><th>Type</th><th>Match</th><th>Replace</th><th>Comment</th><th></th></tr></thead>
      <tbody id="mr-body"></tbody>
    </table></div><button class="dashed panel-add" id="mr-add-rule">+ add rule</button></div>
    <div id="mr-form"></div>

    <div class="panel test-lab"><div class="panel-head"><div><div class="eyebrow">Preview</div><div class="panel-title">Dry-run test</div></div></div><div class="row">
      <select id="mr-direction"><option value="request">request</option><option value="response">response</option></select>
      <input id="mr-host" placeholder="host" value="localhost" style="width:140px" />
      <input id="mr-port" placeholder="port" value="80" style="width:80px" />
      <input id="mr-path" placeholder="path" value="/" style="width:140px" />
      <input id="mr-method" placeholder="method" value="GET" style="width:90px" />
      <label><input type="checkbox" id="mr-tls" /> tls</label>
    </div>
    <textarea id="mr-test-text" placeholder="raw request/response text to test against" style="min-height:120px"></textarea>
    <div class="row">
      <button class="go" id="mr-test">Test</button>
      <span id="mr-test-meta" class="hint"></span>
    </div>
    <pre id="mr-test-out"></pre>
    </div>
  `;
  $("#mr-reload")!.addEventListener("click", () => void loadRules());
  $("#mr-add-rule")!.addEventListener("click", () => openForm(null));
  $<HTMLInputElement>("#mr-ucl")!.addEventListener("change", (e) =>
    void toggleUpdateContentLength((e.target as HTMLInputElement).checked),
  );
  $("#mr-test")!.addEventListener("click", () => void testRules());
  wireSyntaxEditor($<HTMLTextAreaElement>("#mr-test-text")!);
  ["mr-direction", "mr-host", "mr-port", "mr-path", "mr-method", "mr-tls", "mr-test-text"].forEach((id) => {
    const field = $(`#${id}`)!;
    field.addEventListener(changeEventFor(field), () => schedulePreview());
  });
  renderTable();
  void loadRules();
}

function changeEventFor(el: Element): string {
  if (el.tagName === "SELECT") return "change";
  if (el instanceof HTMLInputElement && el.type === "checkbox") return "change";
  return "input";
}

function directionOf(rt: Target): "request" | "response" {
  return rt === "response_header" || rt === "response_body" ? "response" : "request";
}

function computeAffects(s: RuleSetSpec): { req: boolean; res: boolean } {
  let req = false;
  let res = false;
  for (const r of s.rules) {
    if (!r.enabled) continue;
    if (directionOf(r.rule_type) === "request") req = true;
    else res = true;
  }
  return { req, res };
}

function updateAffectsHint(): void {
  const { req, res } = computeAffects(spec);
  $("#mr-affects")!.textContent = `affects requests: ${req} · affects responses: ${res}`;
}

function defaultRule(): RuleSpec {
  return {
    rule_type: "request_header",
    enabled: true,
    string_match: "",
    string_replace: "",
    category: "regex",
    comment: "",
  };
}

async function putSpec(next: RuleSetSpec): Promise<PutResult> {
  try {
    const resp = await putJSON<{ compiled: number }>("/api/tools/rules", next);
    return { ok: true, compiled: resp.compiled };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

/** Persist `next` as the saved rule set, updating local state on success. */
async function persistSpec(next: RuleSetSpec): Promise<boolean> {
  const result = await putSpec(next);
  const meta = $("#mr-meta")!;
  if (result.ok) {
    spec = next;
    meta.textContent = `compiled ${result.compiled} rule(s)`;
    return true;
  }
  meta.innerHTML = `<span class="err">${esc(result.error)}</span>`;
  return false;
}

async function loadRules(): Promise<void> {
  closeForm();
  const affects = $("#mr-affects")!;
  try {
    const resp = await getJSON<RulesGetResp>("/api/tools/rules");
    spec = resp.config;
    affects.textContent = `affects requests: ${resp.affects_requests} · affects responses: ${resp.affects_responses}`;
    renderTable();
  } catch (e) {
    affects.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}

async function toggleEnabled(i: number, checked: boolean): Promise<void> {
  const rules = spec.rules.map((r, idx) => (idx === i ? { ...r, enabled: checked } : r));
  await persistSpec({ ...spec, rules });
  renderTable();
  updateAffectsHint();
}

async function deleteRule(i: number): Promise<void> {
  const rules = spec.rules.filter((_, idx) => idx !== i);
  await persistSpec({ ...spec, rules });
  renderTable();
  updateAffectsHint();
}

async function toggleUpdateContentLength(checked: boolean): Promise<void> {
  const ok = await persistSpec({ ...spec, update_content_length: checked });
  if (!ok) $<HTMLInputElement>("#mr-ucl")!.checked = spec.update_content_length;
}

// ---- table -----------------------------------------------------------------------------------

function ruleRowHtml(r: RuleSpec, i: number): string {
  const scopedNote =
    r.scope !== undefined
      ? ` <span class="hint" title="has a scope condition; not editable from this UI">scoped</span>`
      : "";
  const queriedNote =
    r.query !== undefined
      ? ` <span class="hint" title="${esc(r.query)}">query: ${esc(r.query)}</span>`
      : "";
  return `<tr data-idx="${i}">
    <td><input type="checkbox" class="mr-row-enabled" ${r.enabled ? "checked" : ""} /></td>
    <td>${esc(TYPE_LABEL[r.rule_type])}</td>
    <td>${r.string_match ? esc(r.string_match) : '<span class="hint">(empty)</span>'}</td>
    <td>${r.string_replace ? esc(r.string_replace) : '<span class="hint">(empty)</span>'}</td>
    <td>${esc(r.comment)}${scopedNote}${queriedNote}</td>
    <td><div class="actions">
      <button class="ghost small mr-row-edit">Edit</button>
      <button class="ghost small mr-row-delete">Delete</button>
    </div></td>
  </tr>`;
}

function renderTable(): void {
  const body = $("#mr-body")!;
  body.innerHTML = spec.rules.length
    ? spec.rules.map((r, i) => ruleRowHtml(r, i)).join("")
    : `<tr><td colspan="6" class="hint">no rules yet — click "+ add rule" below</td></tr>`;
  $<HTMLInputElement>("#mr-ucl")!.checked = spec.update_content_length;
  $all<HTMLTableRowElement>("#mr-body tr[data-idx]").forEach((tr) => {
    const i = Number(tr.dataset["idx"]);
    tr.querySelector<HTMLInputElement>(".mr-row-enabled")!.addEventListener("change", (e) =>
      void toggleEnabled(i, (e.target as HTMLInputElement).checked),
    );
    tr.querySelector(".mr-row-edit")!.addEventListener("click", () => openForm(i));
    tr.querySelector(".mr-row-delete")!.addEventListener("click", () => void deleteRule(i));
  });
}

// ---- add/edit form + live preview -------------------------------------------------------------

function optionsHtml<T extends string>(opts: { value: T; label: string }[], selected: T): string {
  return opts
    .map((o) => `<option value="${o.value}" ${o.value === selected ? "selected" : ""}>${o.label}</option>`)
    .join("");
}

function ruleFormHtml(rule: RuleSpec, isNew: boolean): string {
  return `<div class="card">
    <div class="row"><b>${isNew ? "Add rule" : "Edit rule"}</b></div>
    <div class="row">
      <label><input type="checkbox" id="mrf-enabled" ${rule.enabled ? "checked" : ""} /> enabled</label>
      <label>Type <select id="mrf-type">${optionsHtml(TARGETS, rule.rule_type)}</select></label>
      <label>Category <select id="mrf-category">${optionsHtml(CATEGORIES, rule.category)}</select></label>
    </div>
    <div class="row">
      <input id="mrf-match" placeholder="match (empty = add header, header rules only)" style="width:100%" value="${esc(rule.string_match)}" />
    </div>
    <div class="row">
      <input id="mrf-replace" placeholder="replace (empty = delete the matched text)" style="width:100%" value="${esc(rule.string_replace)}" />
    </div>
    <div class="row">
      <input id="mrf-comment" placeholder="comment" style="width:100%" value="${esc(rule.comment)}" />
    </div>
    <div class="row">
      <input id="mrf-query" placeholder='query (DSL-02): status == 200 and method == "POST"' style="width:100%" value="${esc(rule.query ?? "")}" />
    </div>
    <div class="row">
      <button class="go" id="mrf-save">Save rule</button>
      <button class="ghost" id="mrf-cancel">Cancel</button>
      <span id="mrf-meta" class="hint"></span>
    </div>
    <div class="row"><b>Live preview</b><span id="mrf-preview-meta" class="hint"></span></div>
    <div class="two">
      <div class="stack"><div class="hint">Original</div><pre id="mrf-preview-original"></pre></div>
      <div class="stack"><div class="hint">Auto-modified</div><pre id="mrf-preview-modified"></pre></div>
    </div>
  </div>`;
}

function openForm(idx: number | null): void {
  if (previewTimer) clearTimeout(previewTimer);
  editingIndex = idx;
  formOpen = true;
  const rule = idx === null ? defaultRule() : (spec.rules[idx] ?? defaultRule());
  $("#mr-form")!.innerHTML = ruleFormHtml(rule, idx === null);
  syncDirectionForType(rule.rule_type);
  wireForm();
  schedulePreview();
}

function closeForm(): void {
  editingIndex = null;
  formOpen = false;
  const host = $("#mr-form");
  if (host) host.innerHTML = "";
}

function syncDirectionForType(rt: Target): void {
  const dirSel = $<HTMLSelectElement>("#mr-direction");
  if (dirSel) dirSel.value = directionOf(rt);
}

function wireForm(): void {
  $("#mrf-type")!.addEventListener("change", () => {
    syncDirectionForType($<HTMLSelectElement>("#mrf-type")!.value as Target);
    schedulePreview();
  });
  $("#mrf-category")!.addEventListener("change", () => schedulePreview());
  $("#mrf-match")!.addEventListener("input", () => schedulePreview());
  $("#mrf-replace")!.addEventListener("input", () => schedulePreview());
  $("#mrf-query")!.addEventListener("input", () => schedulePreview());
  $("#mrf-enabled")!.addEventListener("change", () => schedulePreview());
  $("#mrf-save")!.addEventListener("click", () => void saveForm());
  $("#mrf-cancel")!.addEventListener("click", () => cancelForm());
}

function readFormRule(): RuleSpec {
  const base = editingIndex === null ? undefined : spec.rules[editingIndex];
  const rule: RuleSpec = {
    rule_type: $<HTMLSelectElement>("#mrf-type")!.value as Target,
    enabled: $<HTMLInputElement>("#mrf-enabled")!.checked,
    string_match: $<HTMLInputElement>("#mrf-match")!.value,
    string_replace: $<HTMLInputElement>("#mrf-replace")!.value,
    category: $<HTMLSelectElement>("#mrf-category")!.value as Category,
    comment: $<HTMLInputElement>("#mrf-comment")!.value,
  };
  if (base?.scope !== undefined) rule.scope = base.scope;
  const query = $<HTMLInputElement>("#mrf-query")!.value.trim();
  if (query) rule.query = query;
  return rule;
}

function buildDraftSpec(draft: RuleSpec): RuleSetSpec {
  const rules =
    editingIndex === null
      ? [...spec.rules, draft]
      : spec.rules.map((r, i) => (i === editingIndex ? draft : r));
  return { rules, update_content_length: spec.update_content_length };
}

function schedulePreview(): void {
  if (!formOpen) return;
  if (previewTimer) clearTimeout(previewTimer);
  previewTimer = setTimeout(() => void runPreview(), 300);
}

async function runPreview(): Promise<void> {
  const metaEl = $("#mrf-preview-meta");
  const origEl = $("#mrf-preview-original");
  const modEl = $("#mrf-preview-modified");
  if (!metaEl || !origEl || !modEl) return; // form was closed before the debounce fired
  const sampleText = $<HTMLTextAreaElement>("#mr-test-text")!.value;
  if (!sampleText) {
    metaEl.textContent = "enter sample text in the dry-run section below to preview";
    origEl.textContent = "";
    modEl.textContent = "";
    return;
  }
  const draftRules = buildDraftSpec(readFormRule());
  metaEl.textContent = "testing…";
  try {
    const resp = await postJSON<{ changed: boolean; output: BytesView }>("/api/tools/rules/test", {
      text: sampleText,
      direction: $<HTMLSelectElement>("#mr-direction")!.value,
      host: $<HTMLInputElement>("#mr-host")!.value,
      port: Number($<HTMLInputElement>("#mr-port")!.value) || 80,
      path: $<HTMLInputElement>("#mr-path")!.value,
      method: $<HTMLInputElement>("#mr-method")!.value || "GET",
      tls: $<HTMLInputElement>("#mr-tls")!.checked,
      draft_rules: draftRules,
    });
    metaEl.textContent = resp.changed ? "changed" : "no change";
    renderSyntax(origEl, sampleText, "http");
    renderSyntax(modEl, resp.output.text, "http");
  } catch (e) {
    metaEl.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}

async function saveForm(): Promise<void> {
  if (previewTimer) clearTimeout(previewTimer);
  const next = buildDraftSpec(readFormRule());
  const result = await putSpec(next);
  if (!result.ok) {
    $("#mrf-meta")!.innerHTML = `<span class="err">${esc(result.error)}</span>`;
    return;
  }
  spec = next;
  $("#mr-meta")!.textContent = `compiled ${result.compiled} rule(s)`;
  closeForm();
  renderTable();
  updateAffectsHint();
}

function cancelForm(): void {
  if (previewTimer) clearTimeout(previewTimer);
  closeForm();
}

// ---- dry-run tester (independent of the live-editing preview above) ---------------------------

async function testRules(): Promise<void> {
  const meta = $("#mr-test-meta")!;
  const out = $("#mr-test-out")!;
  meta.textContent = "testing…";
  try {
    const resp = await postJSON<{ changed: boolean; output: BytesView }>("/api/tools/rules/test", {
      text: $<HTMLTextAreaElement>("#mr-test-text")!.value,
      direction: $<HTMLSelectElement>("#mr-direction")!.value,
      host: $<HTMLInputElement>("#mr-host")!.value,
      port: Number($<HTMLInputElement>("#mr-port")!.value) || 80,
      path: $<HTMLInputElement>("#mr-path")!.value,
      method: $<HTMLInputElement>("#mr-method")!.value || "GET",
      tls: $<HTMLInputElement>("#mr-tls")!.checked,
    });
    meta.textContent = resp.changed ? "changed" : "no change";
    renderSyntax(out, resp.output.text, "http");
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}
