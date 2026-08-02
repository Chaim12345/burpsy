// Intruder tab: find insertion points on a stored request and run an attack over one or more of
// them in any of the four Burp attack shapes (sniper, battering ram, pitchfork, cluster bomb).
// Listens for History's "send to Intruder" hand-off so the request msg id doesn't have to be
// typed by hand.

import { $, $all, esc, statusBadge, postJSON, on } from "./common";
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
  | { rule: "replace"; pattern: string; replace: string; all: boolean }
  | { rule: "uppercase" }
  | { rule: "lowercase" }
  | { rule: "encode"; layer: string }
  | { rule: "decode"; layer: string }
  | { rule: "hash"; algorithm: string }
  | { rule: "skip_if_matches"; pattern: string };

type RuleKind = RuleSpec["rule"];

/** One row in the processing-rule-chain builder — a superset of every rule's fields, so switching
 * a row's kind doesn't need a different object shape. */
interface RuleRow {
  rule: RuleKind;
  text: string;
  pattern: string;
  replace: string;
  all: boolean;
  layer: string;
  algorithm: string;
}

/** A representative XSS/traversal/SSTI probe set, matching Burp's own default Intruder payloads. */
const DEFAULT_PAYLOADS = ["'\n", '"', "../../etc/passwd", "{{7*7}}", "<script>"].join(",");

/** Pseudo-index for the single shared payload set sniper/battering ram use, so it can live in the
 * same per-position state map as pitchfork/cluster bomb's real position indices. */
const SINGLE = -1;

/** Points found by the last "Find points" call. */
let points: PointView[] = [];
/** Indices into `points` currently checked. */
const selected = new Set<number>();
let mode: Mode = "sniper";

/** Per-position (or `SINGLE`) generator state, kept across re-renders the same way the old
 * `sniperPayloads`/`positionPayloads` did for the plain list case. */
interface SourceState {
  kind: SourceKind;
  list: string;
  numbers: NumbersConfig;
  dates: DatesConfig;
  bruteForce: BruteForceConfig;
  customIter: CustomIterState;
  nullCount: string;
}
const sources = new Map<number, SourceState>();

function sourceFor(idx: number): SourceState {
  let s = sources.get(idx);
  if (!s) {
    s = {
      kind: "list",
      list: DEFAULT_PAYLOADS,
      numbers: { from: 1, to: 100, step: 1, order: "sequential", count: 0, base: "decimal", pad_to: 0 },
      dates: { from: "2024-01-01", to: "2024-01-31", step: 1, format: "yyyy-MM-dd" },
      bruteForce: { charset: "abc123", min_len: 1, max_len: 3 },
      customIter: { text: "adm,usr\n1,2,3", separator: "-" },
      nullCount: "10",
    };
    sources.set(idx, s);
  }
  return s;
}

/** One shared processing-rule chain, applied to every payload set. */
let ruleChain: RuleRow[] = [];

function defaultRuleRow(rule: RuleKind = "add_prefix"): RuleRow {
  return { rule, text: "", pattern: "", replace: "", all: false, layer: "url", algorithm: "md5" };
}

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
    <div id="int-rules" class="stack" style="margin-top:10px"></div>
    <div class="row" style="margin-top:10px">
      <label>max payloads <input id="int-maxpayloads" placeholder="default" style="width:90px" /></label>
      <label>grep match <input id="int-grep-match" placeholder="regex" style="width:160px" /></label>
      <label>grep extract <input id="int-grep-extract" placeholder="regex" style="width:160px" /></label>
    </div>
    <div class="row" style="margin-top:6px">
      <label>pool name <input id="int-pool" placeholder="optional" style="width:140px" /></label>
      <label><input type="checkbox" id="int-throttle-enable" /> auto-throttle</label>
      <label>statuses <input id="int-throttle-statuses" value="429,503" style="width:90px" /></label>
      <label>after <input id="int-throttle-after" value="3" style="width:50px" /></label>
      <label>factor <input id="int-throttle-factor" value="2" style="width:50px" /></label>
      <label>recover after <input id="int-throttle-recover" value="50" style="width:60px" /></label>
    </div>
    <div id="int-report" class="hint"></div>
    <div id="int-results"></div>
  `;
  $("#int-find")!.addEventListener("click", () => void findPoints());
  $("#int-run")!.addEventListener("click", () => void runAttack());
  $<HTMLSelectElement>("#int-mode")!.addEventListener("change", (e) => {
    captureSourceValues();
    mode = (e.target as HTMLSelectElement).value as Mode;
    renderPayloadArea();
  });
  on<SendToIntruderDetail>(EVT_SEND_TO_INTRUDER, (d) => {
    $<HTMLInputElement>("#int-msg")!.value = String(d.msgId);
    $<HTMLInputElement>("#int-target")!.value = d.target;
  });
  renderPayloadArea();
  renderRulesArea();
}

async function findPoints(): Promise<void> {
  const body = $("#int-points")!;
  const msgId = Number($<HTMLInputElement>("#int-msg")!.value);
  const all = $<HTMLInputElement>("#int-all")!.checked;
  selected.clear();
  // The single shared payload set (sniper/battering ram) survives a re-find as a convenience; a
  // per-position one does not, because the positions it was keyed to may no longer exist.
  for (const idx of [...sources.keys()]) {
    if (idx !== SINGLE) sources.delete(idx);
  }
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
      captureSourceValues();
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

// ---- payload area: one source picker + generator form per position ----------------------------

/** Saves whatever is currently typed before the payload area gets rebuilt out from under it. */
function captureSourceValues(): void {
  $all<HTMLTextAreaElement>(".int-src-list").forEach((el) => {
    sourceFor(Number(el.dataset["idx"])).list = el.value;
  });
  $all<HTMLElement>(".int-source-body").forEach((el) => {
    const bodyEl = el;
    const idx = Number(bodyEl.dataset["idx"]);
    const s = sourceFor(idx);
    const str = (f: string) => (bodyEl.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[data-f="${f}"]`)?.value ?? "");
    const num = (f: string) => Number(str(f)) || 0;
    switch (s.kind) {
      case "numbers": {
        const seedRaw = str("seed").trim();
        s.numbers = {
          from: num("from"),
          to: num("to"),
          step: num("step"),
          order: (bodyEl.querySelector<HTMLSelectElement>(`[data-f="order"]`)?.value as "sequential" | "random") || "sequential",
          count: num("count"),
          base: (bodyEl.querySelector<HTMLSelectElement>(`[data-f="base"]`)?.value as "decimal" | "hex") || "decimal",
          pad_to: num("pad_to"),
          seed: seedRaw === "" ? undefined : Number(seedRaw),
        };
        break;
      }
      case "dates":
        s.dates = { from: str("from"), to: str("to"), step: num("step"), format: str("format") };
        break;
      case "brute_force":
        s.bruteForce = { charset: str("charset"), min_len: num("min_len"), max_len: num("max_len") };
        break;
      case "custom_iterator":
        s.customIter = { text: str("positions"), separator: str("separator") };
        break;
      case "null":
        s.nullCount = str("count");
        break;
      case "list":
        break; // captured above via .int-src-list
    }
  });
}

/** Rebuilds the payload-entry area to match the current mode and selected positions. */
function renderPayloadArea(): void {
  const area = $("#int-payloads")!;
  const sel = [...selected].sort((a, b) => a - b);
  if (mode === "sniper" || mode === "battering_ram") {
    area.innerHTML = renderSourceBlock(SINGLE, "");
    wireSourceControls();
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
      return renderSourceBlock(idx, `<label style="width:220px">${esc(label)}</label>`);
    })
    .join("");
  wireSourceControls();
}

function renderSourceBlock(idx: number, labelHtml: string): string {
  const s = sourceFor(idx);
  const options: [SourceKind, string][] = [
    ["list", "list"],
    ["numbers", "numbers"],
    ["dates", "dates"],
    ["brute_force", "brute forcer"],
    ["custom_iterator", "custom iterator"],
    ["null", "null payloads"],
  ];
  return `<div class="row int-source-row">
      ${labelHtml}
      <select class="int-src-kind" data-idx="${idx}">
        ${options.map(([v, label]) => `<option value="${v}" ${s.kind === v ? "selected" : ""}>${label}</option>`).join("")}
      </select>
    </div>
    <div class="int-source-body" data-idx="${idx}">${sourceBodyHtml(idx, s)}</div>`;
}

function sourceBodyHtml(idx: number, s: SourceState): string {
  switch (s.kind) {
    case "list":
      return `<div class="row">
        <textarea class="int-src-list" data-idx="${idx}" placeholder="payloads, comma separated"
                  style="width:400px;min-height:60px">${esc(s.list)}</textarea>
        <label class="hint">load from file <input type="file" class="int-src-file" data-idx="${idx}" /></label>
      </div>`;
    case "numbers":
      return `<div class="row">
        <label>from <input class="int-src-f" data-f="from" data-idx="${idx}" style="width:80px" value="${s.numbers.from}" /></label>
        <label>to <input class="int-src-f" data-f="to" data-idx="${idx}" style="width:80px" value="${s.numbers.to}" /></label>
        <label>step <input class="int-src-f" data-f="step" data-idx="${idx}" style="width:60px" value="${s.numbers.step}" /></label>
        <label>order
          <select class="int-src-f" data-f="order" data-idx="${idx}">
            <option value="sequential" ${s.numbers.order === "sequential" ? "selected" : ""}>sequential</option>
            <option value="random" ${s.numbers.order === "random" ? "selected" : ""}>random</option>
          </select>
        </label>
        <label>count (random) <input class="int-src-f" data-f="count" data-idx="${idx}" style="width:70px" value="${s.numbers.count}" /></label>
        <label>base
          <select class="int-src-f" data-f="base" data-idx="${idx}">
            <option value="decimal" ${s.numbers.base === "decimal" ? "selected" : ""}>decimal</option>
            <option value="hex" ${s.numbers.base === "hex" ? "selected" : ""}>hex</option>
          </select>
        </label>
        <label>pad to <input class="int-src-f" data-f="pad_to" data-idx="${idx}" style="width:50px" value="${s.numbers.pad_to}" /></label>
        <label>seed <input class="int-src-f" data-f="seed" data-idx="${idx}" style="width:80px" value="${s.numbers.seed ?? ""}" /></label>
      </div>`;
    case "dates":
      return `<div class="row">
        <label>from <input class="int-src-f" data-f="from" data-idx="${idx}" style="width:110px" placeholder="YYYY-MM-DD" value="${esc(s.dates.from)}" /></label>
        <label>to <input class="int-src-f" data-f="to" data-idx="${idx}" style="width:110px" placeholder="YYYY-MM-DD" value="${esc(s.dates.to)}" /></label>
        <label>step (days) <input class="int-src-f" data-f="step" data-idx="${idx}" style="width:60px" value="${s.dates.step}" /></label>
        <label>format <input class="int-src-f" data-f="format" data-idx="${idx}" style="width:120px" value="${esc(s.dates.format)}" /></label>
      </div>`;
    case "brute_force":
      return `<div class="row">
        <label>charset <input class="int-src-f" data-f="charset" data-idx="${idx}" style="width:180px" value="${esc(s.bruteForce.charset)}" /></label>
        <label>min len <input class="int-src-f" data-f="min_len" data-idx="${idx}" style="width:60px" value="${s.bruteForce.min_len}" /></label>
        <label>max len <input class="int-src-f" data-f="max_len" data-idx="${idx}" style="width:60px" value="${s.bruteForce.max_len}" /></label>
      </div>`;
    case "custom_iterator":
      return `<div class="row">
        <textarea class="int-src-f" data-f="positions" data-idx="${idx}" placeholder="one slot per line, comma-separated items"
                  style="width:300px;min-height:60px">${esc(s.customIter.text)}</textarea>
        <label>separator <input class="int-src-f" data-f="separator" data-idx="${idx}" style="width:60px" value="${esc(s.customIter.separator)}" /></label>
      </div>`;
    case "null":
      return `<div class="row">
        <label>count <input class="int-src-f" data-f="count" data-idx="${idx}" style="width:70px" value="${esc(s.nullCount)}" /></label>
      </div>`;
  }
}

function wireSourceControls(): void {
  $all<HTMLSelectElement>(".int-src-kind").forEach((sel) => {
    sel.addEventListener("change", () => {
      captureSourceValues();
      const idx = Number(sel.dataset["idx"]);
      sourceFor(idx).kind = sel.value as SourceKind;
      renderPayloadArea();
    });
  });
  $all<HTMLInputElement>(".int-src-file").forEach((input) => {
    input.addEventListener("change", () => {
      const idx = Number(input.dataset["idx"]);
      const file = input.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        const text = typeof reader.result === "string" ? reader.result : "";
        // TOOLS-02: Burp's own `.pay` list format is just newline-delimited strings, no binary
        // format to parse. Comma-joined to match this textarea's existing convention — a payload
        // containing a literal comma already has this same limitation typed in by hand (since
        // task #14); loading a file just surfaces it rather than introducing it new.
        const lines = text.split("\n").map((l) => l.replace(/\r$/, ""));
        if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
        sourceFor(idx).list = lines.join(",");
        renderPayloadArea();
      };
      reader.readAsText(file);
    });
  });
}

function buildPayloadSource(idx: number): PayloadSource {
  const s = sourceFor(idx);
  switch (s.kind) {
    case "list":
      return { type: "list", items: s.list.split(",") };
    case "numbers":
      return { type: "numbers", ...s.numbers };
    case "dates":
      return { type: "dates", ...s.dates };
    case "brute_force":
      return { type: "brute_force", ...s.bruteForce };
    case "custom_iterator":
      return {
        type: "custom_iterator",
        positions: s.customIter.text
          .split("\n")
          .map((line) => line.split(","))
          .filter((slot) => slot.some((v) => v !== "")),
        separator: s.customIter.separator,
      };
    case "null":
      return { type: "null", count: Number(s.nullCount) || 0 };
  }
}

// ---- processing-rule chain ----------------------------------------------------------------------

function renderRulesArea(): void {
  const el = $("#int-rules")!;
  el.innerHTML = `
    <div class="row"><b>Processing rules</b><button class="ghost small" id="int-rule-add">+ add rule</button></div>
    ${ruleChain.map((r, i) => ruleRowHtml(r, i)).join("") || `<div class="hint">no processing rules</div>`}
  `;
  $("#int-rule-add")!.addEventListener("click", () => {
    captureRuleChain();
    ruleChain.push(defaultRuleRow());
    renderRulesArea();
  });
  wireRuleRows();
}

const RULE_OPTIONS: [RuleKind, string][] = [
  ["add_prefix", "add prefix"],
  ["add_suffix", "add suffix"],
  ["replace", "regex replace"],
  ["uppercase", "uppercase"],
  ["lowercase", "lowercase"],
  ["encode", "encode"],
  ["decode", "decode"],
  ["hash", "hash"],
  ["skip_if_matches", "skip if matches"],
];

const ENCODE_LAYERS = ["url", "html", "base64", "base64url", "hex", "gzip", "deflate"];

function ruleRowHtml(r: RuleRow, i: number): string {
  return `<div class="row int-rule-row" data-i="${i}">
    <select class="int-rule-kind" data-i="${i}">
      ${RULE_OPTIONS.map(([v, label]) => `<option value="${v}" ${r.rule === v ? "selected" : ""}>${label}</option>`).join("")}
    </select>
    ${ruleFieldsHtml(r, i)}
    <button class="ghost small" data-act="up" data-i="${i}">up</button>
    <button class="ghost small" data-act="down" data-i="${i}">down</button>
    <button class="ghost small" data-act="del" data-i="${i}">remove</button>
  </div>`;
}

function ruleFieldsHtml(r: RuleRow, i: number): string {
  switch (r.rule) {
    case "add_prefix":
    case "add_suffix":
      return `<input class="int-rule-f" data-f="text" data-i="${i}" placeholder="text" style="width:160px" value="${esc(r.text)}" />`;
    case "replace":
      return `<input class="int-rule-f" data-f="pattern" data-i="${i}" placeholder="pattern" style="width:140px" value="${esc(r.pattern)}" />
        <input class="int-rule-f" data-f="replace" data-i="${i}" placeholder="replace" style="width:140px" value="${esc(r.replace)}" />
        <label><input type="checkbox" class="int-rule-f" data-f="all" data-i="${i}" ${r.all ? "checked" : ""} /> all</label>`;
    case "uppercase":
    case "lowercase":
      return "";
    case "encode":
    case "decode":
      return `<select class="int-rule-f" data-f="layer" data-i="${i}">
        ${ENCODE_LAYERS.map((l) => `<option value="${l}" ${r.layer === l ? "selected" : ""}>${l}</option>`).join("")}
      </select>`;
    case "hash":
      return `<select class="int-rule-f" data-f="algorithm" data-i="${i}">
        <option value="md5" ${r.algorithm === "md5" ? "selected" : ""}>md5</option>
        <option value="sha256" ${r.algorithm === "sha256" ? "selected" : ""}>sha256</option>
      </select>`;
    case "skip_if_matches":
      return `<input class="int-rule-f" data-f="pattern" data-i="${i}" placeholder="pattern" style="width:200px" value="${esc(r.pattern)}" />`;
  }
}

function captureRuleChain(): void {
  $all<HTMLElement>(".int-rule-row").forEach((row) => {
    const i = Number(row.dataset["i"]);
    const r = ruleChain[i];
    if (!r) return;
    const text = row.querySelector<HTMLInputElement>(`[data-f="text"]`);
    if (text) r.text = text.value;
    const pattern = row.querySelector<HTMLInputElement>(`[data-f="pattern"]`);
    if (pattern) r.pattern = pattern.value;
    const replace = row.querySelector<HTMLInputElement>(`[data-f="replace"]`);
    if (replace) r.replace = replace.value;
    const all = row.querySelector<HTMLInputElement>(`[data-f="all"]`);
    if (all) r.all = all.checked;
    const layer = row.querySelector<HTMLSelectElement>(`[data-f="layer"]`);
    if (layer) r.layer = layer.value;
    const algorithm = row.querySelector<HTMLSelectElement>(`[data-f="algorithm"]`);
    if (algorithm) r.algorithm = algorithm.value;
  });
}

function wireRuleRows(): void {
  $all<HTMLSelectElement>(".int-rule-kind").forEach((sel) => {
    sel.addEventListener("change", () => {
      captureRuleChain();
      const i = Number(sel.dataset["i"]);
      ruleChain[i] = defaultRuleRow(sel.value as RuleKind);
      renderRulesArea();
    });
  });
  $all<HTMLButtonElement>(".int-rule-row button").forEach((btn) => {
    btn.addEventListener("click", () => {
      captureRuleChain();
      const i = Number(btn.dataset["i"]);
      const act = btn.dataset["act"];
      if (act === "del") {
        ruleChain.splice(i, 1);
      } else if (act === "up" && i > 0) {
        [ruleChain[i - 1], ruleChain[i]] = [ruleChain[i]!, ruleChain[i - 1]!];
      } else if (act === "down" && i < ruleChain.length - 1) {
        [ruleChain[i], ruleChain[i + 1]] = [ruleChain[i + 1]!, ruleChain[i]!];
      }
      renderRulesArea();
    });
  });
}

function buildRuleSpecs(): RuleSpec[] {
  return ruleChain.map((r): RuleSpec => {
    switch (r.rule) {
      case "add_prefix":
        return { rule: "add_prefix", text: r.text };
      case "add_suffix":
        return { rule: "add_suffix", text: r.text };
      case "replace":
        return { rule: "replace", pattern: r.pattern, replace: r.replace, all: r.all };
      case "uppercase":
        return { rule: "uppercase" };
      case "lowercase":
        return { rule: "lowercase" };
      case "encode":
        return { rule: "encode", layer: r.layer };
      case "decode":
        return { rule: "decode", layer: r.layer };
      case "hash":
        return { rule: "hash", algorithm: r.algorithm };
      case "skip_if_matches":
        return { rule: "skip_if_matches", pattern: r.pattern };
    }
  });
}

// ---- run + render --------------------------------------------------------------------------------

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

  captureSourceValues();
  captureRuleChain();
  const idxs = mode === "sniper" || mode === "battering_ram" ? [SINGLE] : sel;
  const anyGenerator = idxs.some((i) => sourceFor(i).kind !== "list");

  meta.textContent = "running…";
  report.innerHTML = "";
  results.innerHTML = "";
  const body: Record<string, unknown> = {
    msg_id: Number($<HTMLInputElement>("#int-msg")!.value),
    target: $<HTMLInputElement>("#int-target")!.value,
    all: $<HTMLInputElement>("#int-all")!.checked,
    mode,
    points: sel,
  };
  // Additive: with every position left on "list" and none of the new controls touched, this posts
  // exactly what task #14's frontend always has — payload_sets and nothing else new.
  if (anyGenerator) {
    body["payload_sources"] = idxs.map((i) => buildPayloadSource(i));
  } else {
    body["payload_sets"] = idxs.map((i) => sourceFor(i).list.split(","));
  }
  const rules = buildRuleSpecs();
  if (rules.length > 0) body["payload_rules"] = rules;
  const maxPayloadsRaw = $<HTMLInputElement>("#int-maxpayloads")!.value.trim();
  if (maxPayloadsRaw) body["max_payloads"] = Number(maxPayloadsRaw);
  const grepMatchRaw = $<HTMLInputElement>("#int-grep-match")!.value.trim();
  if (grepMatchRaw) body["grep_match"] = grepMatchRaw;
  const grepExtractRaw = $<HTMLInputElement>("#int-grep-extract")!.value.trim();
  if (grepExtractRaw) body["grep_extract"] = grepExtractRaw;
  const poolRaw = $<HTMLInputElement>("#int-pool")!.value.trim();
  if (poolRaw) body["pool"] = poolRaw;
  if ($<HTMLInputElement>("#int-throttle-enable")!.checked) {
    body["auto_throttle"] = {
      statuses: $<HTMLInputElement>("#int-throttle-statuses")!
        .value.split(",")
        .map((v) => Number(v.trim()))
        .filter((n) => Number.isFinite(n)),
      after: Number($<HTMLInputElement>("#int-throttle-after")!.value) || 0,
      factor: Number($<HTMLInputElement>("#int-throttle-factor")!.value) || 1,
      recover_after: Number($<HTMLInputElement>("#int-throttle-recover")!.value) || 0,
    };
  }

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
      ${r.grep_matched > 0 ? `<span>grep matched: ${r.grep_matched}</span>` : ""}
      ${r.pool ? `<span>pool: ${esc(r.pool)}</span>` : ""}
      ${r.auto_throttle_engaged > 0 ? `<span class="err">throttled ${r.auto_throttle_engaged}×</span>` : ""}
    </div>
    ${payloadSetsHtml(out.payload_sets)}
  `;
  const examplesByOrdinal = new Map(out.examples.map((e) => [e.first_ordinal, e.payloads]));
  results.innerHTML = `
    <table>
      <thead><tr><th>First #</th><th>Status</th><th>Len</th><th>Reflected</th><th>Count</th><th>Grep</th><th>Extract</th><th>Payloads</th></tr></thead>
      <tbody>
        ${
          r.buckets
            .map((b) => {
              const payloads = examplesByOrdinal.get(b.first_ordinal) ?? [];
              return `<tr><td>${b.first_ordinal}</td><td>${statusBadge(b.status)}</td><td>${b.response_len}</td>
                <td>${b.reflected ? "yes" : ""}</td><td>${b.count}</td>
                <td>${b.grep_matches > 0 ? `${b.grep_matches}/${b.count}` : ""}</td>
                <td>${esc(b.grep_extract ?? "")}</td>
                <td>${esc(payloads.join(" + "))}</td></tr>`;
            })
            .join("") || `<tr><td colspan="8" class="hint">no buckets</td></tr>`
        }
      </tbody>
    </table>
    ${r.buckets_truncated ? `<div class="hint">bucket list truncated; ${r.unbucketed} unbucketed responses</div>` : ""}
    ${r.errors.length ? `<div class="hint err">${esc(r.errors.map((e) => `${e.error} ×${e.count}`).join(", "))}</div>` : ""}
  `;
}

/** Renders what each payload set actually cost: the cap, the truncation, and every reason a
 * processing rule dropped a payload — never buried, per the intruder crate's own bounding
 * philosophy. */
function payloadSetsHtml(sets: PayloadSetView[]): string {
  if (sets.length === 0) return "";
  return `<div class="stack">
    ${sets
      .map((s, i) => {
        const total = `${s.count}/${s.total}${s.total_exact ? "" : "+"}`;
        const dropped = s.dropped.map((d) => `${esc(d.reason)} ×${d.count}`).join(", ");
        return `<div class="row">
          <span>set ${i} (${esc(s.kind)}): ${total}</span>
          ${s.truncated ? `<span class="err">truncated at ${s.max_count}</span>` : ""}
          ${s.skipped > 0 ? `<span class="err">${s.skipped} skipped${dropped ? `: ${dropped}` : ""}</span>` : ""}
        </div>`;
      })
      .join("")}
  </div>`;
}
