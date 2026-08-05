// Session tab: the list of session-handling rules, a manual "log in again", and the shared cookie
// jar.
//
// Session handling is a *list* of independently-scoped rules (crates/web/src/routes/session.rs), so
// this panel is a list plus an editor for the selected rule: name, enabled, scope, the macro's steps
// with their parameter extractions, the validity rule, and the retry bound.
//
// Two things stay raw JSON textareas rather than becoming bespoke forms: the scope (a `Scope`
// document, exactly what /api/scope serves) and the validity rule (a tagged-enum tree —
// `{"status_is":200}`, `{"all":[...]}`). Both are recursive or open-ended shapes, and Match & Replace
// takes the same fallback for the same reason. The extraction fields *are* real inputs, because they
// are flat and are the part an operator edits while staring at a response body.
//
// "Update macro" appears only after a login run that actually ran a macro (`recovered`): the server
// promotes what the last successful run sent, and answers 409 when there is nothing observed — so an
// enabled-looking button that could only fail is not offered.

import { $, esc, getJSON, postJSON, putJSON, delJSON } from "./common";
import { refreshSyntaxEditor, wireSyntaxEditor } from "./syntax";

// ---- wire shapes ------------------------------------------------------------------------------

type ExtractFrom = "body" | { header: string };
type ExtractHow = { regex: { pattern: string; group?: number } } | { json_path: string } | "whole";

interface ExtractionDto {
  name: string;
  from?: ExtractFrom;
  how: ExtractHow;
}

interface StepDto {
  method: string;
  url: string;
  headers: [string, string][];
  body: string;
  extract?: ExtractionDto[];
}

interface RuleDto {
  id?: number;
  name: string;
  enabled: boolean;
  scope?: unknown;
  steps: StepDto[];
  validity: unknown;
  max_attempts?: number;
}

interface RulesResp {
  wired: boolean;
  rules: RuleDto[];
  hint?: string;
}

interface CookiesResp {
  wired: boolean;
  cookies?: { host: string; cookies: { name: string; value: string }[] }[];
  hint?: string;
}

/**
 * One field per thing a recovery outcome can say. The server tags every outcome distinctly rather
 * than collapsing them into ok/error — "the login was attempted and did not work" (`gave_up`) is a
 * different thing from "the macro could not be sent" (`macro_failed`), and an operator has to be able
 * to tell them apart. The whole body is also dumped as JSON below, so a field added server-side stays
 * visible even before this type names it.
 */
interface LoginResp {
  /**
   * "no_rule_applies" | "already_valid" | "recovered" | "still_invalid_after_relogin" | "gave_up"
   * | "macro_failed" | "retry_failed" | "probe_failed"
   */
  outcome?: string;
  rule?: string;
  rule_id?: number;
  /** no_rule_applies: the probe url, how many rules exist, and what to do about it. */
  url?: string;
  rules?: number;
  hint?: string;
  /** How many times the macro ran: recovered / still_invalid_after_relogin / gave_up / retry_failed. */
  login_attempts?: number;
  /** macro_failed: the 1-based attempt, and the step within it that could not be sent. */
  attempt?: number;
  step_index?: number;
  /** still_invalid_after_relogin: "valid" | "invalid" | "indeterminate". */
  validity?: string;
  /** recovered / still_invalid_after_relogin: what the retried probe came back with. */
  response?: { status: number; headers?: Record<string, string>; body: string };
  /** macro_failed / retry_failed / probe_failed. */
  error?: string;
}

const DEFAULT_VALIDITY = JSON.stringify({ status_is: 200 }, null, 2);

/** The list as the server last reported it. */
let rules: RuleDto[] = [];
/** The rule open in the editor — a copy, so an unsaved edit never mutates the list. */
let editing: RuleDto | null = null;
/** The rule whose macro the last login run observed, i.e. the one "update macro" can promote. */
let promotable: number | null = null;

export function initSession(): void {
  const section = $("#session");
  if (!section) return;
  section.innerHTML = `
    <div class="session-layout"><div class="session-rail"><div class="card">
      <div class="row"><b>Session handling rules</b><span id="sess-hint" class="hint"></span></div>
      <div id="sess-rule-list"></div>
      <button class="dashed" id="sess-add-rule">+ add rule</button>
    </div>
    <div class="card">
      <div class="row"><b>Cookie jar</b><button class="ghost small" id="sess-cookies-refresh">Refresh</button></div>
      <div id="sess-cookies"></div>
    </div></div><div class="session-workspace">
    <div class="card" id="sess-editor" style="display:none">
      <div class="row"><b id="sess-editor-title">Rule</b><span id="sess-save-meta" class="hint"></span></div>
      <div class="row">
        <label>name <input id="sess-name" style="width:220px" placeholder="admin login" /></label>
        <label><input type="checkbox" id="sess-enabled" /> enabled</label>
        <label>max attempts <input id="sess-max" style="width:80px" placeholder="default" /></label>
      </div>
      <div class="two">
        <label class="stack">scope (JSON — empty applies everywhere)
          <textarea id="sess-scope" style="min-height:110px" placeholder='{"rules":[{"kind":"Include","host":"target.test"}]}'></textarea>
        </label>
        <label class="stack">validity rule (JSON)
          <textarea id="sess-validity" style="min-height:110px">${esc(DEFAULT_VALIDITY)}</textarea>
        </label>
      </div>
      <div class="row"><b>Macro steps</b><span class="hint">a later step can send an earlier step's extracted value as <code>{{name}}</code></span></div>
      <div id="sess-steps" class="stack"></div>
      <button class="dashed" id="sess-add-step">+ add step</button>
      <div class="row">
        <button class="go" id="sess-save">Save rule</button>
        <button class="ghost" id="sess-cancel">Close</button>
      </div>
    </div>
    <div class="card">
      <div class="row"><b>Log in again</b><span id="sess-login-meta" class="hint"></span></div>
      <div class="row">
        <input id="sess-probe-method" placeholder="GET" style="width:80px" />
        <input id="sess-probe-url" placeholder="http://target/whoami" style="width:320px" />
      </div>
      <textarea id="sess-probe-headers" placeholder="Header: value (one per line)" style="min-height:60px"></textarea>
      <textarea id="sess-probe-body" placeholder="body (optional)" style="min-height:60px"></textarea>
      <div class="row">
        <button class="go" id="sess-login">Log in again</button>
        <button class="ghost" id="sess-update-macro" style="display:none">Update macro from this run</button>
        <span id="sess-update-meta" class="hint"></span>
      </div>
      <div id="sess-login-out"></div>
    </div>
    </div></div>
  `;
  $("#sess-add-rule")!.addEventListener("click", () => startDraft());
  $("#sess-add-step")!.addEventListener("click", () => addStepRow());
  $("#sess-save")!.addEventListener("click", () => void saveRule());
  $("#sess-cancel")!.addEventListener("click", () => closeEditor());
  $("#sess-login")!.addEventListener("click", () => void logInAgain());
  $("#sess-update-macro")!.addEventListener("click", () => void updateMacro());
  $("#sess-cookies-refresh")!.addEventListener("click", () => void loadCookies());
  wireSyntaxEditor($<HTMLTextAreaElement>("#sess-scope")!, "auto");
  wireSyntaxEditor($<HTMLTextAreaElement>("#sess-validity")!, "auto");
  void loadRules();
  void loadCookies();
}

// ---- the rule list ----------------------------------------------------------------------------

async function loadRules(): Promise<void> {
  const hint = $("#sess-hint")!;
  let resp: RulesResp;
  try {
    resp = await getJSON<RulesResp>("/api/session/rules");
  } catch (e) {
    hint.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  rules = resp.rules ?? [];
  if (!resp.wired) {
    hint.textContent = resp.hint ?? "session re-login is not attached to this process";
  } else {
    hint.textContent = rules.length ? `${rules.length} rule(s)` : "no rules yet — add one";
  }
  renderList();
}

function scopeSummary(scope: unknown): string {
  if (scope === undefined || scope === null) return "applies everywhere";
  const s = scope as { allow_all?: boolean; rules?: { kind?: string; host?: string | null }[] };
  if (s.allow_all) return "every host";
  const hosts = (s.rules ?? []).map((r) => `${r.kind === "Exclude" ? "-" : ""}${r.host ?? "*"}`);
  return hosts.length ? hosts.join(", ") : "empty scope";
}

function renderList(): void {
  const list = $("#sess-rule-list")!;
  if (rules.length === 0) {
    list.innerHTML = `<span class="hint">A rule names a login: which targets it covers, the steps to
      replay, and what a valid session looks like.</span>`;
    return;
  }
  list.innerHTML = rules
    .map(
      (r) => `<div class="row" data-id="${r.id ?? ""}">
        <button class="ghost small rule-pick">${esc(r.name)}</button>
        <span class="pill pill-outline">${r.enabled ? "enabled" : "off"}</span>
        <span class="hint">${esc(scopeSummary(r.scope))}</span>
        <span class="hint">${r.steps.length} step(s)${
          r.steps.some((s) => (s.extract ?? []).length > 0) ? " · extracts" : ""
        }</span>
        <span class="hint">max ${esc(r.max_attempts)}</span>
        <button class="ghost small rule-del">delete</button>
      </div>`,
    )
    .join("");
  list.querySelectorAll<HTMLElement>(".row").forEach((row) => {
    const id = Number(row.dataset["id"]);
    row.querySelector(".rule-pick")!.addEventListener("click", () => openRule(id));
    row.querySelector(".rule-del")!.addEventListener("click", () => void deleteRule(id));
  });
}

function openRule(id: number): void {
  const found = rules.find((r) => r.id === id);
  if (!found) return;
  // Edited through a copy: an abandoned edit must not leave the list showing something the server
  // does not have.
  editing = JSON.parse(JSON.stringify(found)) as RuleDto;
  renderEditor();
}

function startDraft(): void {
  editing = {
    name: "",
    enabled: true,
    steps: [{ method: "POST", url: "", headers: [], body: "" }],
    validity: { status_is: 200 },
  };
  renderEditor();
}

function closeEditor(): void {
  editing = null;
  $("#sess-editor")!.style.display = "none";
}

async function deleteRule(id: number): Promise<void> {
  const hint = $("#sess-hint")!;
  try {
    await delJSON(`/api/session/rules/${id}`);
  } catch (e) {
    hint.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  if (editing?.id === id) closeEditor();
  if (promotable === id) hideUpdateMacro();
  await loadRules();
}

// ---- the editor -------------------------------------------------------------------------------

function renderEditor(): void {
  const rule = editing;
  if (!rule) return;
  $("#sess-editor")!.style.display = "";
  $("#sess-editor-title")!.textContent =
    rule.id === undefined ? "New rule" : `Rule ${rule.id}: ${rule.name}`;
  $("#sess-save-meta")!.textContent = "";
  $<HTMLInputElement>("#sess-name")!.value = rule.name;
  $<HTMLInputElement>("#sess-enabled")!.checked = rule.enabled;
  $<HTMLInputElement>("#sess-max")!.value =
    rule.max_attempts === undefined ? "" : String(rule.max_attempts);
  $<HTMLTextAreaElement>("#sess-scope")!.value =
    rule.scope === undefined || rule.scope === null ? "" : JSON.stringify(rule.scope, null, 2);
  $<HTMLTextAreaElement>("#sess-validity")!.value = JSON.stringify(rule.validity, null, 2);
  refreshSyntaxEditor($<HTMLTextAreaElement>("#sess-scope")!, "auto");
  refreshSyntaxEditor($<HTMLTextAreaElement>("#sess-validity")!, "auto");
  $("#sess-steps")!.innerHTML = "";
  rule.steps.forEach((s) => addStepRow(s));
}

function stepRowHtml(step: StepDto | undefined, index: number): string {
  const headers = (step?.headers ?? []).map(([k, v]) => `${k}: ${v}`).join("\n");
  return `<div class="subsection on step">
    <div class="row">
      <span class="pill pill-outline">step ${index}</span>
      <input class="step-method" placeholder="POST" style="width:80px" value="${esc(step?.method ?? "POST")}" />
      <input class="step-url grow" placeholder="http://target/login" value="${esc(step?.url ?? "")}" />
      <button class="ghost small step-remove">remove step</button>
    </div>
    <div class="two">
      <textarea class="step-headers" placeholder="Header: value (one per line)" style="min-height:52px">${esc(headers)}</textarea>
      <textarea class="step-body" placeholder="body" style="min-height:52px">${esc(step?.body ?? "")}</textarea>
    </div>
    <div class="row"><span class="hint">extract from this step's response:</span>
      <button class="ghost small step-add-extract">+ add extraction</button>
    </div>
    <div class="extractions stack"></div>
  </div>`;
}

function addStepRow(step?: StepDto): void {
  const container = $("#sess-steps")!;
  const div = document.createElement("div");
  div.innerHTML = stepRowHtml(step, container.children.length);
  const row = div.firstElementChild as HTMLElement;
  container.appendChild(row);
  const extractions = row.querySelector<HTMLElement>(".extractions")!;
  row.querySelector(".step-remove")!.addEventListener("click", () => {
    row.remove();
    renumberSteps();
  });
  row
    .querySelector(".step-add-extract")!
    .addEventListener("click", () => addExtractionRow(extractions));
  (step?.extract ?? []).forEach((e) => addExtractionRow(extractions, e));
}

/** Step numbers are load-bearing: an extraction is only usable by a *later* step. */
function renumberSteps(): void {
  Array.from(document.querySelectorAll("#sess-steps .step")).forEach((row, i) => {
    const label = row.querySelector(".pill");
    if (label) label.textContent = `step ${i}`;
  });
}

function extractionRowHtml(e?: ExtractionDto): string {
  const from = e?.from;
  const isHeader = typeof from === "object" && from !== null;
  const header = isHeader ? from.header : "";
  const how = e?.how;
  const kind = how === "whole" ? "whole" : how && "json_path" in how ? "json_path" : "regex";
  const pattern =
    how && typeof how === "object" && "regex" in how
      ? how.regex.pattern
      : how && typeof how === "object" && "json_path" in how
        ? how.json_path
        : "";
  const group = how && typeof how === "object" && "regex" in how ? (how.regex.group ?? 1) : 1;
  const sel = (v: string, want: string) => (v === want ? " selected" : "");
  return `<div class="row extraction">
    <input class="ex-name" placeholder="csrf" style="width:110px" value="${esc(e?.name ?? "")}" title="referred to as {{name}} by a later step" />
    <select class="ex-from">
      <option value="body"${sel("body", isHeader ? "header" : "body")}>from body</option>
      <option value="header"${sel("header", isHeader ? "header" : "body")}>from header</option>
    </select>
    <input class="ex-header" placeholder="X-Token" style="width:120px" value="${esc(header)}" />
    <select class="ex-how">
      <option value="regex"${sel("regex", kind)}>regex</option>
      <option value="json_path"${sel("json_path", kind)}>json path</option>
      <option value="whole"${sel("whole", kind)}>whole value</option>
    </select>
    <input class="ex-pattern grow" placeholder='name="csrf" value="([^"]+)"  or  data.token' value="${esc(pattern)}" />
    <input class="ex-group" style="width:56px" title="capture group" value="${esc(group)}" />
    <button class="ghost small ex-remove">remove</button>
  </div>`;
}

function addExtractionRow(container: HTMLElement, e?: ExtractionDto): void {
  const div = document.createElement("div");
  div.innerHTML = extractionRowHtml(e);
  const row = div.firstElementChild as HTMLElement;
  container.appendChild(row);
  row.querySelector(".ex-remove")!.addEventListener("click", () => row.remove());
  const how = row.querySelector<HTMLSelectElement>(".ex-how")!;
  const from = row.querySelector<HTMLSelectElement>(".ex-from")!;
  const sync = (): void => {
    row.querySelector<HTMLInputElement>(".ex-header")!.style.display =
      from.value === "header" ? "" : "none";
    row.querySelector<HTMLInputElement>(".ex-group")!.style.display =
      how.value === "regex" ? "" : "none";
    row.querySelector<HTMLInputElement>(".ex-pattern")!.style.display =
      how.value === "whole" ? "none" : "";
  };
  how.addEventListener("change", sync);
  from.addEventListener("change", sync);
  sync();
}

function parseHeaders(text: string): [string, string][] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf(":");
      return i === -1 ? [l, ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
    }) as [string, string][];
}

function collectExtractions(step: Element): ExtractionDto[] {
  return Array.from(step.querySelectorAll(".extraction")).map((row) => {
    const value = (sel: string): string =>
      (row.querySelector(sel) as HTMLInputElement | HTMLSelectElement).value;
    const from: ExtractFrom =
      value(".ex-from") === "header" ? { header: value(".ex-header") } : "body";
    const pattern = value(".ex-pattern");
    let how: ExtractHow;
    if (value(".ex-how") === "whole") {
      how = "whole";
    } else if (value(".ex-how") === "json_path") {
      how = { json_path: pattern };
    } else {
      // A blank group field means the server's default of 1, not group 0 (the whole match) — which
      // is what `Number("")` would silently produce.
      const raw = value(".ex-group").trim();
      const group = raw === "" ? 1 : Number(raw);
      how = { regex: { pattern, group: Number.isInteger(group) && group >= 0 ? group : 1 } };
    }
    return { name: value(".ex-name"), from, how };
  });
}

function collectSteps(): StepDto[] {
  return Array.from(document.querySelectorAll("#sess-steps .step")).map((row) => {
    const extract = collectExtractions(row);
    const step: StepDto = {
      method: (row.querySelector(".step-method") as HTMLInputElement).value || "GET",
      url: (row.querySelector(".step-url") as HTMLInputElement).value,
      headers: parseHeaders((row.querySelector(".step-headers") as HTMLTextAreaElement).value),
      body: (row.querySelector(".step-body") as HTMLTextAreaElement).value,
    };
    if (extract.length) step.extract = extract;
    return step;
  });
}

async function saveRule(): Promise<void> {
  const meta = $("#sess-save-meta")!;
  const fail = (msg: string): void => {
    meta.innerHTML = `<span class="err">${esc(msg)}</span>`;
  };
  const rule = editing;
  if (!rule) return;

  const steps = collectSteps();
  if (steps.length === 0) return fail("a rule needs at least one step");
  let validity: unknown;
  try {
    validity = JSON.parse($<HTMLTextAreaElement>("#sess-validity")!.value);
  } catch {
    return fail("the validity rule is not valid JSON");
  }
  const scopeRaw = $<HTMLTextAreaElement>("#sess-scope")!.value.trim();
  let scope: unknown;
  if (scopeRaw) {
    try {
      scope = JSON.parse(scopeRaw);
    } catch {
      return fail("the scope is not valid JSON");
    }
  }
  const body: RuleDto = {
    name: $<HTMLInputElement>("#sess-name")!.value.trim(),
    enabled: $<HTMLInputElement>("#sess-enabled")!.checked,
    steps,
    validity,
  };
  // Omitted rather than sent as null: absent means "applies everywhere", and an *empty* scope is
  // refused by the server because it would match nothing.
  if (scope !== undefined) body.scope = scope;
  const maxRaw = $<HTMLInputElement>("#sess-max")!.value.trim();
  if (maxRaw) body.max_attempts = Number(maxRaw);

  try {
    const saved =
      rule.id === undefined
        ? await postJSON<{ rule: RuleDto }>("/api/session/rules", body)
        : await putJSON<{ rule: RuleDto }>(`/api/session/rules/${rule.id}`, body);
    meta.textContent = "saved";
    editing = saved.rule;
    await loadRules();
    renderEditor();
  } catch (e) {
    fail((e as Error).message);
  }
}

// ---- log in again, and promoting what it did --------------------------------------------------

function hideUpdateMacro(): void {
  promotable = null;
  $("#sess-update-macro")!.style.display = "none";
  $("#sess-update-meta")!.textContent = "";
}

async function logInAgain(): Promise<void> {
  const meta = $("#sess-login-meta")!;
  const out = $("#sess-login-out")!;
  const probe: StepDto = {
    method: $<HTMLInputElement>("#sess-probe-method")!.value || "GET",
    url: $<HTMLInputElement>("#sess-probe-url")!.value,
    headers: parseHeaders($<HTMLTextAreaElement>("#sess-probe-headers")!.value),
    body: $<HTMLTextAreaElement>("#sess-probe-body")!.value,
  };
  meta.textContent = "running…";
  out.innerHTML = "";
  hideUpdateMacro();
  try {
    const resp = await postJSON<LoginResp>("/api/session/login", { probe });
    meta.textContent = resp.rule ? `rule: ${resp.rule}` : "";
    const good = resp.outcome === "already_valid" || resp.outcome === "recovered";
    const pill = resp.outcome
      ? `<span class="status-pill ${good ? "good" : "bad"}">${esc(resp.outcome)}</span>`
      : "";
    out.innerHTML = `${pill}<pre>${esc(JSON.stringify(resp, null, 2))}</pre>`;
    // Only a run that actually replayed the macro left anything to promote; `already_valid` means
    // nothing ran, and the server would answer 409.
    if (resp.outcome === "recovered" && typeof resp.rule_id === "number") {
      promotable = resp.rule_id;
      const button = $("#sess-update-macro")!;
      button.style.display = "";
      button.textContent = `Update macro of "${resp.rule ?? resp.rule_id}" from this run`;
      $("#sess-update-meta")!.textContent = "overwrites the stored steps with what just worked";
    }
    void loadCookies();
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}

async function updateMacro(): Promise<void> {
  const meta = $("#sess-update-meta")!;
  if (promotable === null) return;
  try {
    const promoted = promotable;
    const resp = await postJSON<{ steps: StepDto[] }>(
      `/api/session/rules/${promoted}/update-macro`,
      {},
    );
    await loadRules();
    // Reopen it so the operator sees what was written, rather than trusting the message.
    if (editing?.id === promoted) openRule(promoted);
    hideUpdateMacro();
    meta.textContent = `macro updated: ${resp.steps.length} step(s) replaced with what the run sent`;
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}

// ---- cookie jar -------------------------------------------------------------------------------

async function loadCookies(): Promise<void> {
  const el = $("#sess-cookies")!;
  let resp: CookiesResp;
  try {
    resp = await getJSON<CookiesResp>("/api/session/cookies");
  } catch (e) {
    el.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  if (!resp.wired) {
    el.innerHTML = `<span class="hint">${esc(resp.hint ?? "session re-login is not attached to this process")}</span>`;
    return;
  }
  const hosts = resp.cookies ?? [];
  el.innerHTML = hosts.length
    ? hosts
        .map(
          (h) => `<div><b>${esc(h.host)}</b><table><tbody>${h.cookies
            .map((c) => `<tr><td>${esc(c.name)}</td><td>${esc(c.value)}</td></tr>`)
            .join("")}</tbody></table></div>`,
        )
        .join("")
    : `<span class="hint">jar is empty</span>`;
}
