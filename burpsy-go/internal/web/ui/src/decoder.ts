// Decoder tab: encode/decode, hash, and compress/uncompress text. One pane for the input and
// one for the output, with a select for the operation to apply. The input is always treated as raw
// bytes — the operator pastes text or hex, and the decoder treats it as a byte sequence regardless
// of what it looks like.

import { $, esc, toast, copyText } from "./common";

// All the operations the backend supports, grouped by category.
const OPERATIONS: { category: string; ops: { value: string; label: string }[] }[] = [
  {
    category: "Decode",
    ops: [
      { value: "url_decode", label: "URL decode" },
      { value: "html_decode", label: "HTML decode" },
      { value: "base64_decode", label: "Base64 decode" },
      { value: "hex_decode", label: "Hex decode" },
      { value: "gzip_decompress", label: "Gzip decompress" },
      { value: "deflate_decompress", label: "Deflate decompress" },
    ],
  },
  {
    category: "Encode",
    ops: [
      { value: "url_encode", label: "URL encode" },
      { value: "html_encode", label: "HTML encode" },
      { value: "base64_encode", label: "Base64 encode" },
      { value: "hex_encode", label: "Hex encode" },
      { value: "gzip_compress", label: "Gzip compress" },
      { value: "deflate_compress", label: "Deflate compress" },
    ],
  },
  {
    category: "Hash",
    ops: [
      { value: "md5", label: "MD5" },
      { value: "sha1", label: "SHA-1" },
      { value: "sha256", label: "SHA-256" },
    ],
  },
];

export function initDecoder(): void {
  const section = $("#decoder");
  if (!section) return;
  section.innerHTML = `
    <div class="row">
      <span class="hint">Apply an operation to the input text below.</span>
      <span class="grow"></span>
      <button class="ghost small" onclick="swapDecoder()">Swap</button>
      <button class="ghost small" onclick="clearDecoder()">Clear</button>
    </div>
    <div class="two">
      <div>
        <div class="viewer-header">
          <b class="muted">Input</b>
          <button class="ghost small" onclick="copyInput()">Copy</button>
        </div>
        <textarea id="dec-input" placeholder="Paste text or hex to decode/encode..." spellcheck="false" style="min-height:150px"></textarea>
      </div>
      <div>
        <div class="viewer-header">
          <b class="muted">Output</b>
          <button class="ghost small" onclick="copyOutput()">Copy</button>
        </div>
        <textarea id="dec-output" readonly spellcheck="false" style="min-height:150px"></textarea>
      </div>
    </div>
    <div class="row" style="margin-top:10px">
      <div class="stack">
        ${OPERATIONS.map(
          (g) => `
            <div>
              <b class="muted" style="font-size:11px">${esc(g.category)}:</b>
              <select style="width:200px" onchange="applyOp(this)">
                <option value="">— select —</option>
                ${g.ops.map((o) => `<option value="${o.value}">${esc(o.label)}</option>`).join("")}
              </select>
            </div>
          `,
        ).join("")}
      </div>
    </div>
  `;
}

// Global functions
window.copyInput = function(): void {
  const el = $("#dec-input") as HTMLTextAreaElement;
  if (el) copyText(el.value, 'input');
};

window.copyOutput = function(): void {
  const el = $("#dec-output") as HTMLTextAreaElement;
  if (el) copyText(el.value, 'output');
};

window.swapDecoder = function(): void {
  const input = $("#dec-input") as HTMLTextAreaElement;
  const output = $("#dec-output") as HTMLTextAreaElement;
  if (input && output) {
    const temp = input.value;
    input.value = output.value;
    output.value = temp;
    toast("Swapped input and output", 'success');
  }
};

window.clearDecoder = function(): void {
  const input = $("#dec-input") as HTMLTextAreaElement;
  const output = $("#dec-output") as HTMLTextAreaElement;
  if (input) input.value = '';
  if (output) output.value = '';
  toast("Cleared", 'success');
};

async function applyOp(select: HTMLSelectElement): Promise<void> {
  const op = select.value;
  if (!op) return;

  const input = $("#dec-input") as HTMLTextAreaElement;
  const output = $("#dec-output") as HTMLTextAreaElement;

  if (!input || !output) return;

  if (!input.value) {
    toast("Please enter input text", "warning");
    return;
  }

  const button = select;
  const originalValue = select.value;

  try {
    select.disabled = true;
    
    const response = await fetch("/api/tools/decode", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ op, input: input.value }),
    });

    if (!response.ok) throw new Error(`Operation failed: ${response.status}`);

    const result = await response.json() as { output: string; error?: string };

    if (result.error) {
      toast(result.error, "error");
      return;
    }

    output.value = result.output;
    toast(`Applied: ${select.options[select.selectedIndex].text}`, 'success');
  } catch (e) {
    toast((e as Error).message, "error");
  } finally {
    select.disabled = false;
    select.value = originalValue;
  }
}
