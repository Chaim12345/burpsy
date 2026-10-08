// Repeater tab: hand-edit and resend requests. Real Burp keeps one numbered tab per sent
// request, each with its own history; this mirrors that with an in-memory tab strip (state is
// lost on reload — no backend persistence). Listens for History's "send to Repeater" hand-off,
// which opens a fresh tab so it never clobbers whatever the operator is already editing.

import { $, esc, statusBadge, postJSON, on, toast } from "./common";
import { EVT_SEND_TO_REPEATER } from "./types";
import type { SendToRepeaterDetail } from "./types";
import { renderSyntax, refreshSyntaxEditor, wireSyntaxEditor } from "./syntax";
import { decodeMessageB64, decodeNote } from "./decode";

type Protocol = "Http1" | "Http2";

interface SendResp {
  status: number | null;
  duration_ms: number;
  response: string;
  response_b64: string;
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
  response_b64: string;
}

const DEFAULT_RAW = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: burpsy\r\nConnection: close\r\n\r\n";

// Browsers normalise a <textarea> value to LF (CRLF -> LF) when .value is read, which silently
// rewrites a captured CRLF request into bytes a peer reads as malformed: the sender's h2 detection
// keys on "\r\n", so an LF-only copy is misread as HTTP/1.1 and the raw LF line endings go on the
// wire where the peer expects CRLF. The operator's intent is the captured bytes, so send restores
// CRLF before posting. Idempotent: CRLF stays CRLF, lone CR becomes CRLF, lone LF becomes CRLF.
function crlf(raw: string): string {
  return raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n/g, "\r\n");
}

const tabs: RepeaterTab[] = [];
let activeId = 0;
let nextId = 1;

export function initRepeater(): void {
  const section = $("#repeater");
  if (!section) return;
  section.innerHTML = `
    <div class="tabstrip" id="rep-tabs"></div>
    <div class="command-bar">
      <input id="rep-target" placeholder="http://host:port or https://host" class="control-target" />
      <select id="rep-protocol" title="protocol to send this request over (H2-01)">
        <option value="Http1">HTTP/1.1</option>
        <option value="Http2">HTTP/2</option>
      </select>
      <button class="go" id="rep-send">Send</button>
      <span id="rep-meta" class="hint"></span>
      <span id="rep-decode" class="hint"></span>
    </div>
    <div class="split-workspace tall">
      <article class="editor-pane"><div class="pane-label">Request editor</div><textarea id="rep-raw" spellcheck="false"></textarea></article>
      <article class="editor-pane"><div class="pane-label">Response</div><pre id="rep-res">Send the request to inspect the response.</pre></article>
    </div>
  `;
  $("#rep-send")!.addEventListener("click", () => void send());
  $("#rep-tabs")!.addEventListener("click", (e) => onTabStripClick(e));
  wireSyntaxEditor($<HTMLTextAreaElement>("#rep-raw")!);
  addTab();
  on<SendToRepeaterDetail>(EVT_SEND_TO_REPEATER, (d) => {
    addTab({ target: d.target, raw: d.raw, protocol: d.protocol });
    toast(`loaded into Repeater (tab ${activeId})`);
  });
}

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
  refreshSyntaxEditor($<HTMLTextAreaElement>("#rep-raw")!);
  $<HTMLSelectElement>("#rep-protocol")!.value = tab.protocol;
  $("#rep-meta")!.innerHTML = tab.request_msg_id
    ? `${statusBadge(tab.status)} · ${tab.duration_ms} ms · req msg ${tab.request_msg_id}`
    : "";
  void renderResponse(tab);
}

/** Render the response pane from the lossless bytes when we have them, so a Windows-1252 or
 * gzip body shows what the peer actually sent rather than the U+FFFD wall of the JSON text
 * transport (see decode.ts). Falls back to the lossy rendering if anything fails — showing
 * *something* beats showing nothing, and the note always says which one the operator got. */
async function renderResponse(tab: RepeaterTab): Promise<void> {
  const el = $("#rep-res")!;
  const note = $("#rep-decode")!;
  if (tab.response_b64) {
    try {
      const d = await decodeMessageB64(tab.response_b64);
      renderSyntax(el, d.text, "http");
      note.textContent = decodeNote(d);
      return;
    } catch {
      // fall through to the lossy copy
    }
  }
  note.textContent = "";
  renderSyntax(el, tab.response, "http");
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
    response_b64: "",
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
    tabs[0] = { id: tabs[0]!.id, target: "", raw: DEFAULT_RAW, protocol: "Http1", status: null, duration_ms: null, request_msg_id: null, response: "", response_b64: "" };
    activeId = tabs[0]!.id;
  } else {
    tabs.splice(idx, 1);
    if (activeId === id) activeId = tabs[Math.min(idx, tabs.length - 1)]!.id;
  }
  renderTabs();
  loadActiveIntoEditor();
}

async function send(): Promise<void> {
  saveEditorIntoActiveTab();
  const tab = tabs.find((t) => t.id === activeId);
  if (!tab) return;
  const sendingId = tab.id;
  $("#rep-res")!.textContent = "sending…";
  try {
    const d = await postJSON<SendResp>("/api/repeater/send", {
      target: tab.target,
      raw: crlf(tab.raw),
      protocol: tab.protocol,
    });
    tab.status = d.status;
    tab.duration_ms = d.duration_ms;
    tab.request_msg_id = d.request_msg_id;
    tab.response = d.response;
    tab.response_b64 = d.response_b64;
    if (activeId === sendingId) {
      $("#rep-meta")!.innerHTML = `${statusBadge(d.status)} · ${d.duration_ms} ms · req msg ${d.request_msg_id}`;
      void renderResponse(tab);
    }
  } catch (e) {
    if (activeId === sendingId) {
      $("#rep-res")!.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    }
  }
}
