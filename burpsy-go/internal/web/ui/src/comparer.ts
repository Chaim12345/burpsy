// Comparer tab: diff two requests or responses side by side. The two sides are independent:
// each can be loaded from History, or pasted directly. The diff is computed on demand, not stored.

import { $, esc, toast, copyText, renderEmptyState } from "./common";
import { EVT_SEND_TO_COMPARER } from "./types";
import { on } from "./common";
import type { SendToComparerDetail } from "./types";

interface DiffResult {
  a: string;
  b: string;
  diff: { type: "equal" | "delete" | "insert"; text: string }[];
}

// State for both sides
let left: { msgId: number | null; text: string } = { msgId: null, text: "" };
let right: { msgId: number | null; text: string } = { msgId: null, text: "" };

export function initComparer(): void {
  const section = $("#comparer");
  if (!section) return;
  section.innerHTML = `
    <div class="two">
      <div>
        <div class="viewer-header">
          <b class="muted">Side A</b>
          <button class="ghost small" onclick="copySide('a')">Copy</button>
          <button class="ghost small" onclick="clearSide('a')">Clear</button>
          <span id="comp-a-meta" class="viewer-meta"></span>
        </div>
        <div class="code-viewer" id="comp-a-container">
          <div class="code-lines" id="comp-a-lines"></div>
          <textarea id="comp-a" placeholder="Paste or send from History..." spellcheck="false"></textarea>
        </div>
      </div>
      <div>
        <div class="viewer-header">
          <b class="muted">Side B</b>
          <button class="ghost small" onclick="copySide('b')">Copy</button>
          <button class="ghost small" onclick="clearSide('b')">Clear</button>
          <span id="comp-b-meta" class="viewer-meta"></span>
        </div>
        <div class="code-viewer" id="comp-b-container">
          <div class="code-lines" id="comp-b-lines"></div>
          <textarea id="comp-b" placeholder="Paste or send from History..." spellcheck="false"></textarea>
        </div>
      </div>
    </div>
    <div class="row" style="margin-top:10px">
      <button class="go" onclick="computeDiff()">Diff</button>
      <button class="ghost" onclick="swapSides()">Swap Sides</button>
      <button class="ghost" onclick="clearBoth()">Clear Both</button>
      <span class="grow"></span>
      <span class="hint" id="comp-status"></span>
    </div>
    <div id="comp-diff" style="margin-top:10px"></div>
  `;

  // Style textareas to match code viewer
  [$("#comp-a"), $("#comp-b")].forEach((el) => {
    if (el) {
      (el as HTMLTextAreaElement).style.background = 'transparent';
      (el as HTMLTextAreaElement).style.border = 'none';
      (el as HTMLTextAreaElement).style.padding = '8px 8px 8px 40px';
      (el as HTMLTextAreaElement).style.minHeight = '200px';
      (el as HTMLTextAreaElement).style.resize = 'none';
      (el as HTMLTextAreaElement).style.fontFamily = 'var(--font-mono)';
      (el as HTMLTextAreaElement).style.fontSize = '13px';
      (el as HTMLTextAreaElement).style.lineHeight = '1.5';
      (el as HTMLTextAreaElement).style.width = '100%';
    }
  });

  // Listen for send to comparer events
  on<SendToComparerDetail>(EVT_SEND_TO_COMPARER, (d) => {
    if (d.side === "a") {
      left.msgId = d.msgId;
      left.text = ""; // Will be loaded
      $("#comp-a-meta")!.textContent = d.label;
      void loadMessage(d.msgId, "a");
      toast(`Loaded ${d.label} into Comparer A`, 'success');
    } else {
      right.msgId = d.msgId;
      right.text = ""; // Will be loaded
      $("#comp-b-meta")!.textContent = d.label;
      void loadMessage(d.msgId, "b");
      toast(`Loaded ${d.label} into Comparer B`, 'success');
    }
  });
}

// Global functions
window.copySide = function(side: 'a' | 'b'): void {
  const el = $(`#comp-${side}`) as HTMLTextAreaElement;
  if (el) copyText(el.value, `side ${side.toUpperCase()}`);
};

window.clearSide = function(side: 'a' | 'b'): void {
  const el = $(`#comp-${side}`) as HTMLTextAreaElement;
  if (el) {
    el.value = '';
    if (side === 'a') {
      left.text = '';
      left.msgId = null;
      $("#comp-a-meta")!.textContent = '';
    } else {
      right.text = '';
      right.msgId = null;
      $("#comp-b-meta")!.textContent = '';
    }
    updateLineNumbers(side);
    toast(`Cleared side ${side.toUpperCase()}`, 'success');
  }
};

window.clearBoth = function(): void {
  clearSide('a');
  clearSide('b');
  $("#comp-diff")!.innerHTML = '';
  $("#comp-status")!.textContent = '';
  toast("Cleared both sides", 'success');
};

window.swapSides = function(): void {
  const aEl = $("#comp-a") as HTMLTextAreaElement;
  const bEl = $("#comp-b") as HTMLTextAreaElement;
  const aMeta = $("#comp-a-meta")!;
  const bMeta = $("#comp-b-meta")!;

  if (aEl && bEl) {
    const tempText = aEl.value;
    const tempMeta = aMeta.textContent;
    const tempMsgId = left.msgId;

    aEl.value = bEl.value;
    left.text = bEl.value;
    left.msgId = right.msgId;
    aMeta.textContent = bMeta.textContent;

    bEl.value = tempText;
    right.text = tempText;
    right.msgId = tempMsgId;
    bMeta.textContent = tempMeta;

    updateLineNumbers('a');
    updateLineNumbers('b');
    
    // Recompute diff if both sides have content
    if (left.text && right.text) {
      void computeDiff();
    }
    
    toast("Swapped sides", 'success');
  }
};

window.computeDiff = async function(): Promise<void> {
  const aEl = $("#comp-a") as HTMLTextAreaElement;
  const bEl = $("#comp-b") as HTMLTextAreaElement;
  const statusEl = $("#comp-status")!;
  const diffEl = $("#comp-diff")!;

  if (!aEl || !bEl) return;

  if (!aEl.value || !bEl.value) {
    toast("Please enter text in both sides", "warning");
    return;
  }

  try {
    statusEl.innerHTML = '<span class="spinner spinner-small"></span> Computing diff...';
    diffEl.innerHTML = '';

    const response = await fetch("/api/tools/diff", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ a: aEl.value, b: bEl.value }),
    });

    if (!response.ok) throw new Error(`Diff failed: ${response.status}`);

    const result = await response.json() as DiffResult;

    statusEl.textContent = `${result.diff.filter(d => d.type === 'delete').length} deletions, ${result.diff.filter(d => d.type === 'insert').length} insertions`;
    
    // Render diff
    diffEl.innerHTML = `
      <div class="card">
        <div class="card-title">Diff Result</div>
        <pre class="diff-viewer">${renderDiff(result.diff)}</pre>
      </div>
    `;
    
    toast("Diff computed", 'success');
  } catch (e) {
    toast((e as Error).message, "error");
    statusEl.textContent = '';
  }
};

function renderDiff(diff: { type: string; text: string }[]): string {
  return diff.map((d) => {
    switch (d.type) {
      case 'delete':
        return `<span class="diff-delete">${esc(d.text)}</span>`;
      case 'insert':
        return `<span class="diff-insert">${esc(d.text)}</span>`;
      default:
        return esc(d.text);
    }
  }).join('');
}

async function loadMessage(msgId: number, side: 'a' | 'b'): Promise<void> {
  try {
    const response = await fetch(`/api/message/${msgId}`);
    if (!response.ok) throw new Error(`Failed to load message: ${response.status}`);
    
    const msg = await response.json() as { id: number; len: number; text: string };
    
    const el = $(`#comp-${side}`) as HTMLTextAreaElement;
    if (el) {
      el.value = msg.text;
      if (side === 'a') {
        left.text = msg.text;
      } else {
        right.text = msg.text;
      }
      updateLineNumbers(side);
      $("#comp-status")!.textContent = '';
      $("#comp-diff")!.innerHTML = '';
    }
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

function updateLineNumbers(side: 'a' | 'b'): void {
  const el = $(`#comp-${side}`) as HTMLTextAreaElement;
  const linesEl = $(`#comp-${side}-lines`) as HTMLElement;
  
  if (el && linesEl) {
    const lines = el.value.split('\n').length;
    linesEl.innerHTML = Array.from({length: lines}, (_, i) => i + 1).join('\n');
  }
}
