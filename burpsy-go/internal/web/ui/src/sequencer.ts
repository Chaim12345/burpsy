// Sequencer tab: check whether an application's session ids or CSRF tokens are actually
// unpredictable. Two token sources, picked with a radio: paste a list, or capture from a live
// request. Paste is one call and returns immediately; live capture starts a background job and this
// polls it, because it is minutes of real traffic and needs a progress figure and a stop button.
//
// The character-distribution display is plain divs with a percentage width — no charting library,
// because this project has no frontend dependencies beyond bun and typescript and is staying that
// way. Only positions worth looking at are drawn by default; a fixed position is the interesting
// finding, so those are flagged rather than hidden.

import { $, $all, esc, postJSON, getJSON, toast } from "./common";
import { wireSyntaxEditor } from "./syntax";

// ---- wire shapes, mirrored from crates/web/src/routes/sequencer.rs and burpsy-sequencer ----

interface CharCount {
  label: string;
  byte: number;
  count: number;
  fraction: number;
}

interface PositionStats {
  index: number;
  samples: number;
  distinct: number;
  entropy_bits: number;
  counts: CharCount[];
}

interface CharacterAnalysis {
  tokens: number;
  min_len: number;
  max_len: number;
  alphabet_size: number;
  alphabet: string[];
  positions: PositionStats[];
  positions_truncated: boolean;
  entropy_bits_per_char: number;
  total_entropy_bits: number;
  assumes_positional_independence: boolean;
  entropy_ceiling_bits: number;
  max_possible_bits: number;
}

interface BitStats {
  bits: number;
  ones: number;
  zeros: number;
  bit_entropy: number;
  longest_run: number;
  runs_zeros: number[];
  runs_ones: number[];
}

interface FipsTest {
  id: string;
  name: string;
  spec: string;
  requirement: string;
  passed: boolean;
  blocks_passed: number;
  blocks_failed: number;
  observed: string;
}

interface FipsReport {
  bits_supplied: number;
  bits_tested: number;
  bits_untested: number;
  blocks_tested: number;
  block_bits: number;
  /** null when not one whole block was supplied — no verdict, rather than a wrong one. */
  tests: FipsTest[] | null;
}

interface SequencerReport {
  tokens: number;
  encoding: "raw" | "hex" | "base64";
  encoding_detected: boolean;
  characters: CharacterAnalysis;
  bits: BitStats;
  fips: FipsReport;
  grade: "insufficient" | "pass" | "fail";
  verdict: string;
  warnings: string[];
}

interface FailureView {
  message: string;
  count: number;
}

interface CaptureView {
  id: number;
  target: string;
  wanted: number;
  captured: number;
  attempted: number;
  state: "running" | "finished";
  clamped: boolean;
  ended: "complete" | "stopped" | "gave_up" | "refused" | null;
  sent: number | null;
  refused: number | null;
  failures: FailureView[];
  report: SequencerReport | null;
}

// ---- panel ------------------------------------------------------------------------------------

/** Positions drawn expanded before the operator asks for more. Enough to see a fixed prefix. */
const POSITIONS_SHOWN = 24;

/** How often a running capture is re-polled. Matches Intercept's cadence. */
const POLL_MS = 1000;

let pollTimer: ReturnType<typeof setInterval> | undefined;
let activeCapture: number | undefined;
let showAllPositions = false;
let lastReport: SequencerReport | null = null;

export function initSequencer(): void {
  const section = $("#sequencer");
  if (!section) return;
  section.innerHTML = `
    <div class="sequencer-layout"><div class="panel seq-config">
      <div class="row">
        <b>Token source</b>
        <label><input type="radio" name="seq-src" value="paste" checked /> paste a list</label>
        <label><input type="radio" name="seq-src" value="live" /> capture from a request</label>
        <label>bits read as
          <select id="seq-encoding">
            <option value="">detect</option>
            <option value="hex">hex</option>
            <option value="base64">base64</option>
            <option value="raw">raw bytes</option>
          </select>
        </label>
      </div>

      <div id="seq-paste-pane">
        <textarea id="seq-tokens" spellcheck="false" style="min-height:150px"
          placeholder="one token per line&#10;a1b2c3d4&#10;e5f60718&#10;..."></textarea>
        <div class="row">
          <button class="go" id="seq-analyse">Analyse</button>
          <span id="seq-paste-meta" class="hint"></span>
        </div>
      </div>

      <div id="seq-live-pane" style="display:none">
        <div class="row">
          <input id="seq-target" placeholder="http://host:port or https://host" style="width:320px" />
          <label>tokens <input id="seq-count" style="width:80px" placeholder="100" /></label>
          <label>req/s <input id="seq-rps" style="width:70px" placeholder="5" /></label>
        </div>
        <textarea id="seq-raw" spellcheck="false" style="min-height:120px">GET /login HTTP/1.1
Host: example.com
Connection: close

</textarea>
        <div class="row">
          <b>Token is</b>
          <select id="seq-part">
            <option value="body">in the body</option>
            <option value="headers">in the headers</option>
            <option value="whole">anywhere in the response</option>
          </select>
          <label><input type="radio" name="seq-how" value="pattern" checked /> matching</label>
          <input id="seq-pattern" placeholder="sid=([0-9a-f]+)" style="width:240px" />
          <label><input type="radio" name="seq-how" value="span" /> at offset</label>
          <input id="seq-offset" placeholder="offset" style="width:80px" />
          <input id="seq-len" placeholder="length" style="width:80px" />
        </div>
        <div class="row">
          <button class="go" id="seq-start">Start capture</button>
          <button class="ghost" id="seq-stop" disabled>Stop</button>
          <span id="seq-live-meta" class="hint"></span>
        </div>
      </div>
    </div>

    <div id="seq-results" class="seq-results"><div class="empty-state"><b>No analysis yet</b><span>Paste tokens or capture them from a request to begin.</span></div></div></div>
  `;

  wireSyntaxEditor($<HTMLTextAreaElement>("#seq-raw")!);

  $all<HTMLInputElement>("input[name=seq-src]").forEach((r) => {
    r.onchange = () => {
      const live = r.value === "live" && r.checked;
      const paste = $("#seq-paste-pane");
      const livePane = $("#seq-live-pane");
      if (paste) paste.style.display = live ? "none" : "";
      if (livePane) livePane.style.display = live ? "" : "none";
    };
  });
  $("#seq-analyse")!.addEventListener("click", () => void analysePaste());
  $("#seq-start")!.addEventListener("click", () => void startCapture());
  $("#seq-stop")!.addEventListener("click", () => void stopCapture());
}

// ---- paste mode -------------------------------------------------------------------------------

function chosenEncoding(): string | undefined {
  const v = $<HTMLSelectElement>("#seq-encoding")?.value ?? "";
  return v === "" ? undefined : v;
}

async function analysePaste(): Promise<void> {
  const meta = $("#seq-paste-meta")!;
  const text = $<HTMLTextAreaElement>("#seq-tokens")!.value;
  if (!text.trim()) {
    meta.innerHTML = `<span class="err">paste at least one token</span>`;
    return;
  }
  meta.textContent = "analysing…";
  const body: { text: string; encoding?: string } = { text };
  const encoding = chosenEncoding();
  if (encoding) body.encoding = encoding;
  try {
    const report = await postJSON<SequencerReport>("/api/sequencer/analyse", body);
    meta.textContent = `${report.tokens} token(s)`;
    renderReport(report);
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}

// ---- live capture -----------------------------------------------------------------------------

interface ExtractBody {
  part: string;
  pattern?: string;
  offset?: number;
  len?: number;
}

/** Build the extractor the backend expects, or explain what is missing. */
function buildExtract(): ExtractBody | string {
  const part = $<HTMLSelectElement>("#seq-part")!.value;
  const how = $all<HTMLInputElement>("input[name=seq-how]").find((r) => r.checked)?.value;
  if (how === "span") {
    const offset = Number($<HTMLInputElement>("#seq-offset")!.value);
    const len = Number($<HTMLInputElement>("#seq-len")!.value);
    if (!Number.isInteger(offset) || offset < 0) return "offset must be a whole number";
    if (!Number.isInteger(len) || len < 1) return "length must be at least 1";
    return { part, offset, len };
  }
  const pattern = $<HTMLInputElement>("#seq-pattern")!.value.trim();
  if (!pattern) return "give a pattern that matches the token";
  return { part, pattern };
}

async function startCapture(): Promise<void> {
  const meta = $("#seq-live-meta")!;
  const target = $<HTMLInputElement>("#seq-target")!.value.trim();
  const raw = $<HTMLTextAreaElement>("#seq-raw")!.value;
  if (!target) {
    meta.innerHTML = `<span class="err">give a target</span>`;
    return;
  }
  const extract = buildExtract();
  if (typeof extract === "string") {
    meta.innerHTML = `<span class="err">${esc(extract)}</span>`;
    return;
  }
  const body: Record<string, unknown> = { target, raw, extract };
  const count = Number($<HTMLInputElement>("#seq-count")!.value);
  if (Number.isInteger(count) && count > 0) body.count = count;
  const rps = Number($<HTMLInputElement>("#seq-rps")!.value);
  if (Number.isFinite(rps) && rps > 0) body.rps = rps;
  const encoding = chosenEncoding();
  if (encoding) body.encoding = encoding;

  meta.textContent = "starting…";
  try {
    const view = await postJSON<CaptureView>("/api/sequencer/capture", body);
    activeCapture = view.id;
    if (view.clamped) {
      toast(`count reduced to the ${view.wanted}-token ceiling`, "info");
    }
    $<HTMLButtonElement>("#seq-stop")!.disabled = false;
    renderProgress(view);
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => void poll(), POLL_MS);
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}

async function stopCapture(): Promise<void> {
  if (activeCapture === undefined) return;
  try {
    renderProgress(await postJSON<CaptureView>(`/api/sequencer/capture/${activeCapture}/stop`));
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

async function poll(): Promise<void> {
  if (activeCapture === undefined) return;
  let view: CaptureView;
  try {
    view = await getJSON<CaptureView>(`/api/sequencer/capture/${activeCapture}`);
  } catch (e) {
    stopPolling();
    $("#seq-live-meta")!.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    return;
  }
  if (view.state === "finished") {
    stopPolling();
    renderProgress(view);
    if (view.report) {
      renderReport(view.report);
    } else {
      // No tokens at all. The failures are the whole story, so they are the whole output.
      $("#seq-results")!.innerHTML = `<div class="card">
        <div class="card-title">Captured nothing</div>
        ${failuresHtml(view.failures)}
      </div>`;
    }
    return;
  }
  renderProgress(view);
}

function stopPolling(): void {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = undefined;
  $<HTMLButtonElement>("#seq-stop")!.disabled = true;
}

const ENDED_LABEL: Record<string, string> = {
  complete: "complete",
  stopped: "stopped by you",
  gave_up: "gave up — too many failures in a row",
  refused: "refused: out of scope",
};

function renderProgress(view: CaptureView): void {
  const meta = $("#seq-live-meta")!;
  const pct = view.wanted > 0 ? Math.round((view.captured / view.wanted) * 100) : 0;
  if (view.state === "running") {
    meta.textContent = `${view.captured} / ${view.wanted} tokens (${pct}%), ${view.attempted} request(s) sent`;
    return;
  }
  const ended = ENDED_LABEL[view.ended ?? ""] ?? (view.ended ?? "finished");
  const good = view.ended === "complete" || view.ended === "stopped";
  meta.innerHTML =
    `<span class="status-pill ${good ? "good" : "bad"}">${esc(ended)}</span> ` +
    `${view.captured} token(s) from ${view.attempted} request(s) · ` +
    `sender: ${view.sent ?? 0} sent, ${view.refused ?? 0} refused`;
}

function failuresHtml(failures: FailureView[]): string {
  if (failures.length === 0) return "";
  return `<table><thead><tr><th>Problem</th><th>Times</th></tr></thead><tbody>${failures
    .map((f) => `<tr><td>${esc(f.message)}</td><td>${f.count}</td></tr>`)
    .join("")}</tbody></table>`;
}

// ---- results ----------------------------------------------------------------------------------

const GRADE_LABEL: Record<string, string> = {
  pass: "PASS",
  fail: "FAIL",
  insufficient: "NOT TESTED",
};

function renderReport(report: SequencerReport): void {
  lastReport = report;
  const grade = report.grade;
  const pill = grade === "pass" ? "good" : grade === "fail" ? "bad" : "";
  const encoding = report.encoding_detected
    ? `${report.encoding} (detected)`
    : `${report.encoding} (you chose this)`;

  $("#seq-results")!.innerHTML = `
    <div class="card">
      <div class="row">
        <span class="status-pill ${pill}">${GRADE_LABEL[grade] ?? esc(grade)}</span>
        <b>Verdict</b>
      </div>
      <div class="detail-text">${esc(report.verdict)}</div>
      ${warningsHtml(report.warnings)}
    </div>

    <div class="card">
      <div class="card-title">Sample</div>
      <div class="row">
        ${tile("Tokens", String(report.tokens))}
        ${tile("Alphabet", String(report.characters.alphabet_size))}
        ${tile("Length", lengthLabel(report.characters))}
        ${tile("Entropy / token", `${report.characters.total_entropy_bits.toFixed(1)} b`)}
        ${tile("Bits read as", encoding)}
      </div>
      <div class="hint">
        Entropy per token is the sum of the per-position figures, which assumes the positions are
        independent — it is an upper estimate, not a measurement. This alphabet and length could carry
        at most ${report.characters.max_possible_bits.toFixed(1)} bits, and
        ${report.tokens} sample(s) cap any single position at
        ${report.characters.entropy_ceiling_bits.toFixed(1)} bits however good the generator is.
      </div>
    </div>

    ${fipsHtml(report)}
    ${positionsHtml(report.characters)}
  `;

  const toggle = $("#seq-toggle-positions");
  if (toggle) {
    toggle.addEventListener("click", () => {
      showAllPositions = !showAllPositions;
      if (lastReport) renderReport(lastReport);
    });
  }
}

function tile(label: string, value: string): string {
  return `<div class="stat-tile"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div></div>`;
}

function lengthLabel(c: CharacterAnalysis): string {
  return c.min_len === c.max_len ? String(c.max_len) : `${c.min_len}–${c.max_len}`;
}

function warningsHtml(warnings: string[]): string {
  if (warnings.length === 0) return "";
  return `<ul class="hint">${warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>`;
}

function fipsHtml(report: SequencerReport): string {
  const f = report.fips;
  const coverage =
    `${f.bits_supplied} bit(s) supplied · ${f.blocks_tested} whole ${f.block_bits}-bit block(s) tested` +
    (f.bits_untested > 0 ? ` · ${f.bits_untested} bit(s) not tested` : "");

  if (f.tests === null) {
    return `<div class="card">
      <div class="card-title">FIPS 140-2 bit-level tests</div>
      <div class="hint">${esc(coverage)}</div>
      <div class="detail-text">Not run. Every FIPS 140-2 threshold is defined on a
        ${f.block_bits}-bit sample, so running them against a shorter one would produce a confident
        answer that means nothing. Capture more tokens.</div>
    </div>`;
  }
  return `<div class="card">
    <div class="card-title">FIPS 140-2 bit-level tests</div>
    <div class="hint">${esc(coverage)}</div>
    <table>
      <thead><tr><th>Test</th><th>Result</th><th>Observed</th><th>Requirement</th><th>Blocks</th></tr></thead>
      <tbody>${f.tests
        .map(
          (t) => `<tr>
            <td title="${esc(t.spec)}">${esc(t.name)}</td>
            <td><span class="status-pill ${t.passed ? "good" : "bad"}">${t.passed ? "pass" : "fail"}</span></td>
            <td>${esc(t.observed)}</td>
            <td class="muted">${esc(t.requirement)}</td>
            <td>${t.blocks_passed} / ${t.blocks_passed + t.blocks_failed}</td>
          </tr>`,
        )
        .join("")}</tbody>
    </table>
    <div class="hint">Ones: ${report.bits.ones} of ${report.bits.bits}
      (${(report.bits.bit_entropy * 100).toFixed(2)}% of a perfect split) · longest run
      ${report.bits.longest_run} bit(s).</div>
  </div>`;
}

/**
 * Per-position character distribution: one bar row per observed character, width proportional to
 * its share. Plain divs and a percentage width — no library, and none needed.
 */
function positionsHtml(c: CharacterAnalysis): string {
  if (c.positions.length === 0) {
    return `<div class="card"><div class="card-title">Character positions</div>
      <div class="hint">no tokens to analyse</div></div>`;
  }
  const shown = showAllPositions ? c.positions : c.positions.slice(0, POSITIONS_SHOWN);
  const hidden = c.positions.length - shown.length;
  const toggle =
    c.positions.length > POSITIONS_SHOWN
      ? `<button class="ghost small" id="seq-toggle-positions">${
          showAllPositions ? `show first ${POSITIONS_SHOWN}` : `show all ${c.positions.length}`
        }</button>`
      : "";

  return `<div class="card">
    <div class="row"><b>Character positions</b>${toggle}
      <span class="hint">alphabet: ${esc(c.alphabet.join(""))}</span></div>
    ${
      c.positions_truncated
        ? `<div class="hint">Only the first ${c.positions.length} of ${c.max_len} positions are reported.</div>`
        : ""
    }
    <div class="seq-positions">${shown.map(positionHtml).join("")}</div>
    ${hidden > 0 ? `<div class="hint">${hidden} more position(s) not shown.</div>` : ""}
  </div>`;
}

function positionHtml(p: PositionStats): string {
  // A position that never varies is the finding, so it is called out rather than drawn as one long
  // bar the eye slides over.
  const dead = p.distinct <= 1;
  return `<div class="seq-position${dead ? " dead" : ""}">
    <div class="seq-position-head">
      <b>#${p.index}</b>
      <span class="${dead ? "err" : "muted"}">${p.entropy_bits.toFixed(2)} bits</span>
      <span class="muted">${p.distinct} distinct · ${p.samples} sample(s)</span>
      ${dead ? `<span class="err">never varies</span>` : ""}
    </div>
    <div class="seq-bars">${p.counts
      .map(
        (ch) => `<div class="seq-bar-row" title="${esc(ch.label)}: ${ch.count} (${(ch.fraction * 100).toFixed(1)}%)">
          <span class="seq-bar-label">${esc(ch.label)}</span>
          <span class="seq-bar-track"><span class="seq-bar-fill" style="width:${(ch.fraction * 100).toFixed(2)}%"></span></span>
          <span class="seq-bar-count">${ch.count}</span>
        </div>`,
      )
      .join("")}</div>
  </div>`;
}
