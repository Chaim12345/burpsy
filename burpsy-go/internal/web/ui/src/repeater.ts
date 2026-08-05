// Repeater tab: hand-edit and resend requests. Real Burp keeps one numbered tab per sent
// request, each with its own history; this mirrors that with an in-memory tab strip (state is
// lost on reload — no backend persistence). Listens for History's "send to Repeater" hand-off,
// which opens a fresh tab so it never clobbers whatever the operator is already editing.

import { $, esc, statusBadge, postJSON, on, toast, copyText, createSpinner } from "./common";
import { EVT_SEND_TO_REPEATER } from "./types";
import type { SendToRepeaterDetail } from "./types";

type Protocol = "Http1" | "Http2";

interface SendResp {
  status: number | null;
  duration_ms: number;
  response: string;
  request_msg_id: number;
  response_msg_id: number;
  exchange_id: number;
}

interface RepeaterTab {
  id: number;
  target: string;
  raw: string;
  protocol: Protocol;
  status: number | null;
  duration_ms: number | null;
  request_msg_id: number | null;
  response: string;
}

const DEFAULT_RAW = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: burpsy\r\nConnection: close\r\n\r\n";

const tabs: RepeaterTab[] = [];
let activeId = 0;
let nextId = 1;

export function initRepeater(): void {
  const section = $("#repeater");
  if (!section) return;
  section.innerHTML = `
    <div class="tabstrip" id="rep-tabs"></div>
    <div class="row">
      <input id="rep-target" placeholder="http://host:port or https://host" style="width:340px" />
      <select id="rep-protocol" title="protocol to send this request over (H2-01)">
        <option value="Http1">HTTP/1.1</option>
        <option value="Http2">HTTP/2</option>
      </select>
      <button class="go" id="rep-send">Send</button>
      <span id="rep-meta" class="hint"></span>
    </div>
    <div class="two">
      <div>
        <div class="viewer-header">
          <b class="muted">Request</b>
          <button class="ghost small" onclick="copyRequest()">Copy</button>
          <span class="viewer-meta" id="rep-req-meta"></span>
        </div>
        <div class="code-viewer" id="rep-req-container">
          <div class="code-lines" id="rep-req-lines"></div>
          <textarea id="rep-raw" spellcheck="false"></textarea>
        </div>
      </div>
      <div>
        <div class="viewer-header">
          <b class="muted">Response</b>
          <button class="ghost small" onclick="copyResponse()">Copy</button>
          <span class="viewer-meta" id="rep-res-meta"></span>
        </div>
        <div class="code-viewer" id="rep-res-container">
          <div class="code-lines" id="rep-res-lines"></div>
          <pre id="rep-res" spellcheck="false"></pre>
        </div>
      </div>
    </div>
  `;
  
  // Update textarea styling to match code viewer
  const textarea = $("#rep-raw") as HTMLTextAreaElement;
  if (textarea) {
    textarea.style.background = 'transparent';
    textarea.style.border = 'none';
    textarea.style.padding = '8px 8px 8px 40px';
    textarea.style.minHeight = '220px';
    textarea.style.resize = 'none';
    textarea.style.fontFamily = 'var(--font-mono)';
    textarea.style.fontSize = '13px';
    textarea.style.lineHeight = '1.5';
    textarea.style.width = '100%';
  }
  
  $("#rep-send")!.addEventListener("click", () => void send());
  $("#rep-tabs")!.addEventListener("click", (e) => onTabStripClick(e));
  addTab();
  on<SendToRepeaterDetail>(EVT_SEND_TO_REPEATER, (d) => {
    addTab({ target: d.target, raw: d.raw, protocol: d.protocol });
    toast(`loaded into Repeater (tab ${activeId})`, 'success');
  });
}

// Global functions for copy buttons
window.copyRequest = function(): void {
  const textarea = $("#rep-raw") as HTMLTextAreaElement;
  if (textarea) copyText(textarea.value, 'request');
};

window.copyResponse = function(): void {
  const pre = $("#rep-res") as HTMLElement;
  if (pre) copyText(pre.textContent || '', 'response');
};

function onTabStripClick(e: Event): void {
  const target = e.target as HTMLElement;
  if (target.id === "rep-tab-add") {
    addTab();
    return;
  }
  const closeId = target.dataset["close"];
  if (closeId) {
    closeTab(Number(closeId));
    return;
  }
  const item = target.closest<HTMLElement>(".tab-item");
  if (item?.dataset["id"]) selectTab(Number(item.dataset["id"]));
}

function renderTabs(): void {
  const el = $("#rep-tabs");
  if (!el) return;
  el.innerHTML =
    tabs
      .map(
        (t) =>
          `<div class="tab-item${t.id === activeId ? " on" : ""}" data-id="${t.id}">${t.id}` +
          `<span class="tab-close" data-close="${t.id}" title="close tab">&times;</span></div>`,
      )
      .join("") + `<button class="tab-add" id="rep-tab-add" title="new tab">+</button>`;
}

function saveEditorIntoActiveTab(): void {
  const tab = tabs.find((t) => t.id === activeId);
  if (!tab) return;
  tab.target = $<HTMLInputElement>("#rep-target")!.value;
  tab.raw = $<HTMLTextAreaElement>("#rep-raw")!.value;
  tab.protocol = $<HTMLSelectElement>("#rep-protocol")!.value as Protocol;
}

function loadActiveIntoEditor(): void {
  const tab = tabs.find((t) => t.id === activeId);
  if (!tab) return;
  $<HTMLInputElement>("#rep-target")!.value = tab.target;
  $<HTMLTextAreaElement>("#rep-raw")!.value = tab.raw;
  $<HTMLSelectElement>("#rep-protocol")!.value = tab.protocol;
  
  const metaEl = $("#rep-meta")!;
  if (tab.request_msg_id) {
    metaEl.innerHTML = `${statusBadge(tab.status)}  ${tab.duration_ms} ms  req msg ${tab.request_msg_id}`;
  } else {
    metaEl.innerHTML = "";
  }
  
  const resEl = $("#rep-res") as HTMLElement;
  if (resEl) {
    resEl.textContent = tab.response;
    updateViewerLines('rep-res-container', tab.response);
  }
  
  updateViewerLines('rep-req-container', tab.raw);
  
  const reqMeta = $("#rep-req-meta")!;
  const resMeta = $("#rep-res-meta")!;
  
  reqMeta.textContent = tab.raw.length > 0 ? `${fmtBytes(tab.raw.length)}` : 'Empty';
  resMeta.textContent = tab.response.length > 0 ? `${fmtBytes(tab.response.length)}` : 'No response';
}

function updateViewerLines(containerId: string, content: string): void {
  const container = $(`#${containerId}`) as HTMLElement;
  const linesEl = $(`#${containerId}-lines`) as HTMLElement;
  if (!container || !linesEl) return;

  const lines = content.split('\n').length;
  linesEl.innerHTML = Array.from({length: lines}, (_, i) => i + 1).join('\n');
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function addTab(opts?: { target?: string; raw?: string; protocol?: Protocol }): void {
  if (tabs.length > 0) saveEditorIntoActiveTab();
  const tab: RepeaterTab = {
    id: nextId++,
    target: opts?.target ?? "",
    raw: opts?.raw ?? DEFAULT_RAW,
    // Defaults to whatever protocol carried the originating exchange (H2-01: an h2-captured
    // request resends over h2 unless the operator changes it), or HTTP/1.1 for a blank tab.
    protocol: opts?.protocol ?? "Http1",
    status: null,
    duration_ms: null,
    request_msg_id: null,
    response: "",
  };
  tabs.push(tab);
  activeId = tab.id;
  renderTabs();
  loadActiveIntoEditor();
}

function selectTab(id: number): void {
  if (id === activeId) return;
  saveEditorIntoActiveTab();
  activeId = id;
  renderTabs();
  loadActiveIntoEditor();
}

function closeTab(id: number): void {
  const idx = tabs.findIndex((t) => t.id === id);
  if (idx === -1) return;
  if (tabs.length === 1) {
    // Always keep at least one tab open — reset it in place rather than removing it.
    tabs[0] = { id: tabs[0]!.id, target: "", raw: DEFAULT_RAW, protocol: "Http1", status: null, duration_ms: null, request_msg_id: null, response: "" };
    activeId = tabs[0]!.id;
  } else {
    tabs.splice(idx, 1);
    if (activeId === id) {
      activeId = tabs[Math.min(idx, tabs.length - 1)]!.id;
    }
  }
  renderTabs();
  loadActiveIntoEditor();
}

async function send(): Promise<void> {
  saveEditorIntoActiveTab();
  const tab = tabs.find((t) => t.id === activeId);
  if (!tab) return;

  const button = $("#rep-send")!;
  const originalText = button.textContent;
  
  try {
    // Show loading state
    button.classList.add('loading');
    button.disabled = true;
    
    const res = await postJSON<SendResp>(`/api/repeater/send`, {
      target: tab.target,
      raw: tab.raw,
      protocol: tab.protocol,
    });

    // Update tab state
    tab.status = res.status;
    tab.duration_ms = res.duration_ms;
    tab.request_msg_id = res.request_msg_id;
    tab.response = res.response;
    
    // Update UI
    loadActiveIntoEditor();
    
    const resMeta = $("#rep-res-meta")!;
    resMeta.textContent = res.response.length > 0 
      ? `Status: ${res.status} - ${fmtBytes(res.response.length)}` 
      : 'No response';
    
    toast(`Request sent: ${res.status || 'No response'} in ${res.duration_ms}ms`, 'success');
  } catch (e) {
    toast((e as Error).message, "error");
  } finally {
    button.classList.remove('loading');
    button.disabled = false;
    button.textContent = originalText;
  }
}
