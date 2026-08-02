// Comparer tab: byte/word diff between two messages or pasted texts. Listens for History's
// "send to Comparer" hand-off so a request/response can be loaded by clicking, not by id.

import { $, $all, esc, getJSON, postJSON, on } from "./common";
import { EVT_SEND_TO_COMPARER } from "./types";
import type { SendToComparerDetail } from "./types";

interface OpView {
  kind: string;
  a_offset: number;
  a_len: number;
  b_offset: number;
  b_len: number;
  text?: string;
}
interface CompareResp {
  identical: boolean;
  deleted_tokens: number;
  inserted_tokens: number;
  truncated: boolean;
  ops_omitted: number;
  ops: OpView[];
}

// Hunk navigation state for the currently rendered diff. Reset each time runCompare() re-renders
// #cmp-output. currentHunk is -1 until the operator jumps to a hunk for the first time.
let hunkCount = 0;
let currentHunk = -1;

export function initComparer(): void {
  const el = $("#comparer");
  if (!el) return;
  el.innerHTML = `
    <div class="two">
      <div class="stack">
        <div class="hint" id="cmp-a-label">Side A</div>
        <input id="cmp-a-msg" placeholder="msg id (optional)" style="width:140px" />
        <textarea id="cmp-a-text" placeholder="text for side A"></textarea>
      </div>
      <div class="stack">
        <div class="hint" id="cmp-b-label">Side B</div>
        <input id="cmp-b-msg" placeholder="msg id (optional)" style="width:140px" />
        <textarea id="cmp-b-text" placeholder="text for side B"></textarea>
      </div>
    </div>
    <div class="row">
      <select id="cmp-granularity"><option value="word">word</option><option value="byte">byte</option></select>
      <button class="go" id="cmp-run">Compare</button>
      <span id="cmp-meta" class="hint"></span>
    </div>
    <div class="row">
      <button class="ghost" id="cmp-hunk-prev">◀ Prev</button>
      <span id="cmp-hunk-counter" class="hint">no hunks</span>
      <button class="ghost" id="cmp-hunk-next">Next ▶</button>
    </div>
    <pre id="cmp-output"></pre>
  `;
  $("#cmp-run")!.addEventListener("click", () => void runCompare());
  $("#cmp-hunk-prev")!.addEventListener("click", () => jumpHunk(-1));
  $("#cmp-hunk-next")!.addEventListener("click", () => jumpHunk(1));
  updateHunkNav();
  on<SendToComparerDetail>(EVT_SEND_TO_COMPARER, (d) => {
    $<HTMLInputElement>(`#cmp-${d.side}-msg`)!.value = String(d.msgId);
    $(`#cmp-${d.side}-label`)!.textContent = `Side ${d.side.toUpperCase()}: ${d.label} (msg ${d.msgId})`;
  });
}

/** Move to the next (delta=1) or previous (delta=-1) hunk, wrapping past either end. */
function jumpHunk(delta: number): void {
  if (hunkCount === 0) return;
  currentHunk =
    currentHunk === -1 ? (delta > 0 ? 0 : hunkCount - 1) : (currentHunk + delta + hunkCount) % hunkCount;
  focusHunk(currentHunk);
}

function focusHunk(n: number): void {
  const out = $("#cmp-output")!;
  $all(".diff-hunk-current", out).forEach((e) => e.classList.remove("diff-hunk-current"));
  const target = document.getElementById(`cmp-hunk-${n}`);
  target?.classList.add("diff-hunk-current");
  target?.scrollIntoView({ block: "center", behavior: "smooth" });
  updateHunkNav();
}

function updateHunkNav(): void {
  const counter = $("#cmp-hunk-counter")!;
  const prevBtn = $<HTMLButtonElement>("#cmp-hunk-prev")!;
  const nextBtn = $<HTMLButtonElement>("#cmp-hunk-next")!;
  if (hunkCount === 0) {
    counter.textContent = "no hunks";
    prevBtn.disabled = true;
    nextBtn.disabled = true;
    return;
  }
  prevBtn.disabled = false;
  nextBtn.disabled = false;
  counter.textContent = currentHunk === -1 ? `${hunkCount} hunk${hunkCount === 1 ? "" : "s"}` : `hunk ${currentHunk + 1} / ${hunkCount}`;
}

async function resolveSideText(prefix: "a" | "b"): Promise<string> {
  const msgRaw = $<HTMLInputElement>(`#cmp-${prefix}-msg`)!.value.trim();
  if (msgRaw) {
    const m = await getJSON<{ text: string }>(`/api/message/${msgRaw}`);
    return m.text;
  }
  return $<HTMLTextAreaElement>(`#cmp-${prefix}-text`)!.value;
}

/** Slice by the same byte offsets the server computed, not JS string (UTF-16) offsets. */
function byteSlice(s: string, offset: number, len: number): string {
  const bytes = new TextEncoder().encode(s);
  return new TextDecoder().decode(bytes.slice(offset, offset + len));
}

async function runCompare(): Promise<void> {
  const meta = $("#cmp-meta")!;
  const out = $("#cmp-output")!;
  meta.textContent = "comparing…";
  try {
    const [a, b] = await Promise.all([resolveSideText("a"), resolveSideText("b")]);
    const resp = await postJSON<CompareResp>("/api/tools/compare", {
      a: { text: a },
      b: { text: b },
      granularity: $<HTMLSelectElement>("#cmp-granularity")!.value,
    });
    meta.textContent =
      (resp.identical ? "identical" : `${resp.deleted_tokens} deleted, ${resp.inserted_tokens} inserted`) +
      (resp.truncated ? " (truncated)" : "") +
      (resp.ops_omitted ? ` · ${resp.ops_omitted} ops omitted` : "");
    let nextHunk = 0;
    out.innerHTML = resp.ops
      .map((op) => {
        if (op.kind === "equal") return esc(byteSlice(a, op.a_offset, op.a_len));
        const cls = op.kind === "delete" ? "diff-delete" : "diff-insert";
        const n = nextHunk++;
        return `<span class="${cls}" data-hunk="${n}" id="cmp-hunk-${n}">${esc(op.text ?? "")}</span>`;
      })
      .join("");
    hunkCount = nextHunk;
    currentHunk = -1;
    updateHunkNav();
  } catch (e) {
    meta.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    hunkCount = 0;
    currentHunk = -1;
    updateHunkNav();
  }
}
