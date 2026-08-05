// Decoder tab: smart multi-layer decode, explicit "decode as", encode, and hash.

import { $, $all, esc, postJSON } from "./common";

interface BytesView {
  text: string;
  len: number;
  utf8: boolean;
  truncated: boolean;
}
interface RunView {
  layer: string | null;
  confidence: string | null;
  why: string;
}
interface PassView {
  output: BytesView;
  runs: RunView[];
}
interface SmartResp {
  mode: "smart";
  layers: string[];
  output: BytesView;
  passes: PassView[];
}
interface ExplicitResp {
  mode: "explicit";
  layers: string[];
  output: BytesView;
}
interface EncodeResp {
  encoding: string;
  output: BytesView;
}
interface HashResp {
  algorithm: string;
  /** Hex, so this is always ASCII and `len` is twice the digest's size in bytes. */
  output: BytesView;
}

const LAYERS = ["url", "html", "base64", "base64url", "hex", "gzip", "deflate", "jwt"];
const ENCODABLE_LAYERS = LAYERS.filter((l) => l !== "jwt");
// Weakest first, matching both Burp's menu and `HashAlgorithm::ALL`. MD5 and SHA-1 are offered
// because targets still use them, not because they are worth choosing.
const HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"];

type ViewMode = "text" | "hex";

/** The last decode response, kept so flipping Text/Hex re-renders instead of re-requesting. */
let lastDecode: SmartResp | ExplicitResp | null = null;

/**
 * Whether the output pane is currently showing that decode. Encode and hash write to the same pane,
 * and silently swapping their result back to a stale decode when the radio moves would be worse than
 * the toggle appearing to do nothing until the next Decode.
 */
let paneShowsDecode = false;

export function initDecoder(): void {
  const el = $("#decoder");
  if (!el) return;
  el.innerHTML = `
    <div class="split-workspace tall">
      <article class="editor-pane">
        <div class="pane-label">Input</div>
        <textarea id="dec-input" placeholder="paste text to decode / encode / hash"></textarea>
        <div class="editor-actions">
          <select id="dec-encoding">
            <option value="smart">smart</option>
            ${LAYERS.map((l) => `<option value="${l}">${l}</option>`).join("")}
          </select>
          <label><input type="checkbox" id="dec-guess" /> guess base64/hex</label>
          <button class="go" id="dec-run">Decode</button>
        </div>
        <div class="editor-actions secondary-actions">
          <span class="hint">view decoded output as</span>
          <label><input type="radio" name="dec-view" value="text" checked /> Text</label>
          <label><input type="radio" name="dec-view" value="hex" /> Hex</label>
        </div>
        <div class="editor-actions secondary-actions">
          <select id="enc-encoding">
            ${ENCODABLE_LAYERS.map((l) => `<option value="${l}">${l}</option>`).join("")}
          </select>
          <button class="go" id="enc-run">Encode</button>
        </div>
        <div class="editor-actions secondary-actions">
          <select id="hash-algorithm">
            ${HASH_ALGORITHMS.map((a) => `<option value="${a}">${a}</option>`).join("")}
          </select>
          <button class="go" id="hash-run">Hash</button>
          <span class="hint">one-way — there is no decode back</span>
        </div>
      </article>
      <article class="editor-pane"><div class="pane-label">Output</div><pre id="dec-output">Decoded, encoded, or hashed output will appear here.</pre></article>
    </div>
  `;
  $("#dec-run")!.addEventListener("click", () => void runDecode());
  $("#enc-run")!.addEventListener("click", () => void runEncode());
  $("#hash-run")!.addEventListener("click", () => void runHash());
  $all<HTMLInputElement>('input[name="dec-view"]').forEach((r) => {
    r.addEventListener("change", () => {
      if (paneShowsDecode && lastDecode) $("#dec-output")!.innerHTML = renderDecodeResp(lastDecode);
    });
  });
}

function viewMode(): ViewMode {
  return $<HTMLInputElement>('input[name="dec-view"]:checked')?.value === "hex" ? "hex" : "text";
}

function flagNote(flags: string[]): string {
  const s = flags.filter(Boolean).join(", ");
  return s ? `\n<span class="hint">(${esc(s)})</span>` : "";
}

function bytesLine(b: BytesView): string {
  return `${esc(b.text)}${flagNote([b.utf8 ? "" : "not-utf8", b.truncated ? "truncated" : ""])}`;
}

/** Bytes per hex-dump row — the classic width, and it fits beside the ASCII gutter. */
const HEX_COLS = 16;

/**
 * Cap on how much gets dumped. A hex row costs roughly five times its bytes in markup, so an
 * inflated response that renders fine as text will hang the tab as hex.
 */
const MAX_HEX_BYTES = 8192;

function hexDump(bytes: Uint8Array): string {
  const shown = bytes.subarray(0, MAX_HEX_BYTES);
  const lines: string[] = [];
  for (let off = 0; off < shown.length; off += HEX_COLS) {
    const chunk = shown.subarray(off, off + HEX_COLS);
    const cells = Array.from(chunk, (b) => b.toString(16).padStart(2, "0"));
    const ascii = Array.from(chunk, (b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".")).join("");
    const pad = "   ".repeat(HEX_COLS - cells.length);
    lines.push(`${off.toString(16).padStart(8, "0")}  ${cells.join(" ")}${pad}  |${esc(ascii)}|`);
  }
  if (!lines.length) return `<span class="hint">(0 bytes)</span>`;
  if (bytes.length > shown.length) {
    const rest = bytes.length - shown.length;
    lines.push(`<span class="hint">… ${rest} more bytes not dumped; switch to Text for the whole output</span>`);
  }
  return lines.join("\n");
}

/**
 * The decoded bytes as a hex dump.
 *
 * The API hands back `text` — a *lossy* UTF-8 rendering — plus the true byte length, not the raw
 * bytes. So when `utf8` is true this dump is exact, and when it is false the replacement characters
 * are all that reached the browser, making this a dump of those rather than of what the decoder
 * produced. That case is called out instead of papered over: a hex view exists precisely so an
 * operator can trust the bytes, and quietly dumping U+FFFD as `ef bf bd` would break that. The real
 * fix belongs on the server — a base64 field beside `text` — and until then, saying so is the honest
 * option.
 */
function bytesHexBlock(b: BytesView): string {
  const bytes = new TextEncoder().encode(b.text);
  return `${hexDump(bytes)}${flagNote([
    b.utf8 ? "" : `not-utf8: dumped from lossy text, ${bytes.length} B here vs ${b.len} B decoded`,
    b.truncated ? "truncated" : "",
  ])}`;
}

function renderDecodeResp(resp: SmartResp | ExplicitResp): string {
  const view = viewMode();
  const lines = [
    `<b>layers:</b> ${resp.layers.length ? esc(resp.layers.join(" → ")) : "(none)"}`,
    `<b>output (${view}):</b>\n${view === "hex" ? bytesHexBlock(resp.output) : bytesLine(resp.output)}`,
  ];
  if (resp.mode === "smart") {
    resp.passes.forEach((p, i) => {
      lines.push(`<b>pass ${i + 1}:</b>`);
      p.runs.forEach((r) => {
        lines.push(`  ${r.layer ? esc(r.layer) : "plain"}${r.confidence ? ` (${esc(r.confidence)})` : ""} — ${esc(r.why)}`);
      });
    });
  }
  return lines.join("\n");
}

async function runDecode(): Promise<void> {
  const input = $<HTMLTextAreaElement>("#dec-input")!.value;
  const encoding = $<HTMLSelectElement>("#dec-encoding")!.value;
  const guess = $<HTMLInputElement>("#dec-guess")!.checked;
  const out = $("#dec-output")!;
  out.textContent = "decoding…";
  try {
    const resp = await postJSON<SmartResp | ExplicitResp>("/api/tools/decode", {
      input,
      encoding,
      guess_alphabets: guess,
    });
    lastDecode = resp;
    paneShowsDecode = true;
    out.innerHTML = renderDecodeResp(resp);
  } catch (e) {
    paneShowsDecode = false;
    out.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}

async function runEncode(): Promise<void> {
  const input = $<HTMLTextAreaElement>("#dec-input")!.value;
  const encoding = $<HTMLSelectElement>("#enc-encoding")!.value;
  const out = $("#dec-output")!;
  paneShowsDecode = false;
  out.textContent = "encoding…";
  try {
    const resp = await postJSON<EncodeResp>("/api/tools/encode", { input, encoding });
    out.innerHTML = `<b>${esc(resp.encoding)}:</b>\n${bytesLine(resp.output)}`;
  } catch (e) {
    out.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}

async function runHash(): Promise<void> {
  const input = $<HTMLTextAreaElement>("#dec-input")!.value;
  const algorithm = $<HTMLSelectElement>("#hash-algorithm")!.value;
  const out = $("#dec-output")!;
  // A digest has no layers to unwind and no Text/Hex choice worth making — hex is the only form
  // worth printing — so the view radio deliberately does not apply here.
  paneShowsDecode = false;
  out.textContent = "hashing…";
  try {
    const resp = await postJSON<HashResp>("/api/tools/hash", { input, algorithm });
    const bytes = resp.output.len / 2;
    out.innerHTML = `<b>${esc(resp.algorithm)}:</b>\n${esc(resp.output.text)}\n<span class="hint">(${bytes} bytes, hex)</span>`;
  } catch (e) {
    out.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
  }
}
