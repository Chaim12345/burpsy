// Organizer tab: the operator's shortlist of saved exchanges with a note and a Burp-style
// highlight colour. Items are normally added via History's "Save" action; adding by exchange id
// here too, for completeness.

import { $, $all, esc, getJSON, postJSON, delJSON, toast } from "./common";
import { live } from "./live";

interface OrgItem {
  id: number;
  exchange: number;
  title: string;
  note: string;
  highlight: string;
}

const HIGHLIGHTS = ["none", "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"];

export function initOrganizer(): void {
  const el = $("#organizer");
  if (!el) return;
  el.innerHTML = `
    <div class="command-bar">
      <input id="org-add-exchange" placeholder="Exchange ID" class="control-short" />
      <button class="go" id="org-add">Add to organizer</button>
    </div>
    <div id="org-list" class="organizer-grid"></div>
  `;
  $("#org-add")!.addEventListener("click", () => void add());
  // The case this exists for is cross-tab: History's Save writes an item here, and before the stream
  // this pane found out by being clicked.
  live({ kinds: ["organizer"], section: "organizer", refresh: () => void load() });
  void load();
}

async function add(): Promise<void> {
  const input = $<HTMLInputElement>("#org-add-exchange")!;
  const exchange = Number(input.value);
  if (!Number.isFinite(exchange) || input.value.trim() === "") {
    toast("enter a numeric exchange id", "error");
    return;
  }
  try {
    await postJSON("/api/tools/organizer", { exchange });
    input.value = "";
    void load();
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

async function load(): Promise<void> {
  const list = $("#org-list")!;
  try {
    const resp = await getJSON<{ items: OrgItem[] }>("/api/tools/organizer");
    list.innerHTML = resp.items.length
      ? resp.items.map(itemHtml).join("")
      : `<div class="empty-state"><b>No saved items</b><span>Save an exchange from History or add one by ID above.</span></div>`;
    wireItems();
  } catch (e) {
    list.innerHTML = `<p class="err">${esc((e as Error).message)}</p>`;
  }
}

function itemHtml(item: OrgItem): string {
  return `<div class="card hl-${esc(item.highlight)}" data-id="${item.id}">
    <div class="row">
      <input class="org-title" value="${esc(item.title)}" style="width:260px" />
      <select class="org-highlight">
        ${HIGHLIGHTS.map((h) => `<option value="${h}" ${h === item.highlight ? "selected" : ""}>${h}</option>`).join("")}
      </select>
      <span class="hint">exchange #${item.exchange}</span>
      <span class="grow"></span>
      <button class="ghost small org-save">Save</button>
      <button class="ghost small org-remove">Remove</button>
    </div>
    <textarea class="org-note" placeholder="note" style="min-height:50px">${esc(item.note)}</textarea>
  </div>`;
}

function wireItems(): void {
  $all("#org-list .card").forEach((card) => {
    const id = Number(card.dataset["id"]);
    card.querySelector(".org-save")!.addEventListener("click", () => void save(id, card));
    card.querySelector(".org-remove")!.addEventListener("click", () => void remove(id));
  });
}

async function save(id: number, card: HTMLElement): Promise<void> {
  const title = card.querySelector<HTMLInputElement>(".org-title")!.value;
  const note = card.querySelector<HTMLTextAreaElement>(".org-note")!.value;
  const highlight = card.querySelector<HTMLSelectElement>(".org-highlight")!.value;
  try {
    await postJSON(`/api/tools/organizer/${id}`, { title, note, highlight });
    toast("saved");
    void load();
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

async function remove(id: number): Promise<void> {
  try {
    await delJSON(`/api/tools/organizer/${id}`);
    void load();
  } catch (e) {
    toast((e as Error).message, "error");
  }
}
