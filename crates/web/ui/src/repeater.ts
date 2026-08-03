// Repeater tab: hand-edit and resend requests. Real Burp keeps one numbered tab per sent
// request, each with its own history; this mirrors that with an in-memory tab strip (state is
// lost on reload — no backend persistence). Listens for History's "send to Repeater" hand-off,
// which opens a fresh tab so it never clobbers whatever the operator is already editing.

import { $, esc, statusBadge, postJSON, on, toast } from "./common";
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
      <input id="rep-target" placeholder="http://host:port or https://host" style="width:340px" aria-label="Target URL" />
      <select id="rep-protocol" title="protocol to send this request over (H2-01)" aria-label="Protocol">
        <option value="Http1">HTTP/1.1</option>
        <option value="Http2">HTTP/2</option>
      </select>
      <button class="go" id="rep-send" title="Send request (Ctrl+Enter)">Send</button>
      <span id="rep-meta" class="hint"></span>
    </div>
    <div class="two">
      <textarea id="rep-raw" spellcheck="false" aria-label="Raw HTTP Request"></textarea>
      <pre id="rep-res" tabindex="0" aria-label="Response Output" title="Response container (scrollable with keyboard)"></pre>
    </div>
  `;
  $("#rep-send")!.addEventListener("click", () => void send());
  $("#rep-tabs")!.addEventListener("click", (e) => onTabStripClick(e));

  const handleShortcut = (e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      void send();
    }
  };

  const rawEl = $<HTMLTextAreaElement>("#rep-raw");
  if (rawEl) {
    rawEl.addEventListener("keydown", handleShortcut);
  }

  const targetEl = $<HTMLInputElement>("#rep-target");
  if (targetEl) {
    targetEl.addEventListener("keydown", (e: KeyboardEvent) => {
      if (e.key === "Enter" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        void send();
      } else {
        handleShortcut(e);
      }
    });
  }
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
  $<HTMLSelectElement>("#rep-protocol")!.value = tab.protocol;
  $("#rep-meta")!.innerHTML = tab.request_msg_id
    ? `${statusBadge(tab.status)} · ${tab.duration_ms} ms · req msg ${tab.request_msg_id}`
    : "";
  $("#rep-res")!.textContent = tab.response;
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
      raw: tab.raw,
      protocol: tab.protocol,
    });
    tab.status = d.status;
    tab.duration_ms = d.duration_ms;
    tab.request_msg_id = d.request_msg_id;
    tab.response = d.response;
    if (activeId === sendingId) {
      $("#rep-meta")!.innerHTML = `${statusBadge(d.status)} · ${d.duration_ms} ms · req msg ${d.request_msg_id}`;
      $("#rep-res")!.textContent = d.response;
    }
  } catch (e) {
    if (activeId === sendingId) {
      $("#rep-res")!.innerHTML = `<span class="err">${esc((e as Error).message)}</span>`;
    }
  }
}
