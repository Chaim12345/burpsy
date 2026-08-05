// Global keyboard shortcuts, plus the cheat sheet that makes them findable. An undiscoverable
// shortcut is the same complaint as a missing button, so the bindings and the overlay are rendered
// from one table below: the sheet cannot list a key that is not wired, and a wired key cannot be
// missing from the sheet.
//
// Ctrl+R and Ctrl+I are Burp's own send-to-Repeater / send-to-Intruder, kept identical because they
// are muscle memory for anyone arriving from Burp. Cmd is accepted alongside Ctrl for macOS.
//
// Tab switching is Ctrl+Shift+Left / Ctrl+Shift+Right rather than Ctrl+1..9. Ctrl+1..9 and Alt+1..9
// are reserved by Chrome and Firefox for their own tab strips and cannot be preventDefault()ed by a
// page, so binding them would produce keys that visibly do the wrong thing.
//
// Two rules keep these from getting in the way:
//
//  * Nothing fires while focus is in an <input>, <textarea>, <select> or a contenteditable, unless
//    the binding opts in (Ctrl+Enter in the Repeater editor does). Ctrl+R inside the Repeater request
//    editor must not send the request being edited somewhere else.
//
//  * preventDefault() happens only once a binding has *claimed* the event. Ctrl+R is the browser's
//    reload; on a tab with no selectable rows it stays the browser's reload. On a tab that does have
//    rows we claim it, and if nothing is selected we say so through the toast instead of eating the
//    key and doing nothing.

import { $, $all, esc, switchTab, toast } from "./common";
import type { Exchange } from "./types";
import { fetchExchange, sendToRepeater, sendToIntruder } from "./sendto";
import { isContextMenuOpen } from "./contextmenu";

/** What the active tab's selected row stands for. A pane registers a getter, not a value, so the
 * shortcut always reads the selection as it is at the moment the key is pressed. */
export interface RowTarget {
  /** Names the row in a message, e.g. "exchange #42". */
  label: string;
  /** The exchange, when the pane already holds it (History). */
  exchange?: Exchange;
  /** The exchange id, when the pane holds only that (Site map, WS History, Scanner). */
  exchangeId?: number;
  /** Why this row has no exchange to act on. Reported instead of acting. */
  note?: string;
}

const rowSources = new Map<string, () => RowTarget | null>();

/** Registers the active-row getter for one tab. Only panes that can actually produce a captured
 * exchange register: on a tab with no source, Ctrl+R and Ctrl+I are left to the browser rather than
 * being swallowed to show an apology. */
export function registerRowTarget(tabId: string, get: () => RowTarget | null): void {
  rowSources.set(tabId, get);
}

function activeTabId(): string | null {
  return $("main > section.on")?.id ?? null;
}

function tabLabel(tabId: string): string {
  const btn = $all<HTMLButtonElement>("nav button[data-t]").find((b) => b.dataset["t"] === tabId);
  return btn?.textContent?.trim() ?? tabId;
}

function activeRowSource(): (() => RowTarget | null) | undefined {
  const id = activeTabId();
  return id === null ? undefined : rowSources.get(id);
}

/** True when the active tab has rows these shortcuts can act on — the test for whether Ctrl+R and
 * Ctrl+I are ours or the browser's on this screen. */
function hasRowSource(): boolean {
  return activeRowSource() !== undefined;
}

async function resolveTarget(t: RowTarget): Promise<Exchange | null> {
  if (t.exchange) return t.exchange;
  if (t.exchangeId !== undefined) return await fetchExchange(t.exchangeId);
  toast(t.note ?? `${t.label} has no captured request to send`, "error");
  return null;
}

function sendSelected(where: "repeater" | "intruder", keys: string): void {
  const get = activeRowSource();
  if (!get) return;
  const target = get();
  if (!target) {
    const id = activeTabId();
    toast(`nothing selected — click a row in ${id ? tabLabel(id) : "this tab"} first, then press ${keys}`);
    return;
  }
  void resolveTarget(target).then((ex) => {
    if (!ex) return;
    if (where === "repeater") void sendToRepeater(ex);
    else sendToIntruder(ex);
  });
}

function moveTab(delta: number): void {
  const buttons = $all<HTMLButtonElement>("nav button[data-t]");
  if (buttons.length === 0) return;
  const current = buttons.findIndex((b) => b.classList.contains("on"));
  const from = current === -1 ? 0 : current;
  const next = buttons[(((from + delta) % buttons.length) + buttons.length) % buttons.length];
  const id = next?.dataset["t"];
  if (id) switchTab(id);
}

// ---- the binding table ------------------------------------------------------------------------

interface Binding {
  /** As shown in the cheat sheet. */
  keys: string;
  what: string;
  /** Which screens it applies to, for the cheat sheet. */
  where: string;
  when: (e: KeyboardEvent) => boolean;
  /** Whether this binding owns the key right now. Absent means always. Must be synchronous:
   * preventDefault() cannot wait on a fetch. */
  claim?: () => boolean;
  run: () => void;
  /** Fires even with focus in an input/textarea/select/contenteditable. Default false. */
  inEditable?: boolean;
}

/** Ctrl or, on macOS, Cmd — and nothing else held. */
function mod(e: KeyboardEvent): boolean {
  return (e.ctrlKey || e.metaKey) && !e.altKey;
}

const ROW_PANES = "History, Site map, WS History, Scanner";

const BINDINGS: Binding[] = [
  {
    keys: "Ctrl+R",
    what: "Send the selected row to Repeater",
    where: ROW_PANES,
    when: (e) => mod(e) && !e.shiftKey && e.key.toLowerCase() === "r",
    claim: hasRowSource,
    run: () => sendSelected("repeater", "Ctrl+R"),
  },
  {
    keys: "Ctrl+I",
    what: "Send the selected row to Intruder",
    where: ROW_PANES,
    when: (e) => mod(e) && !e.shiftKey && e.key.toLowerCase() === "i",
    claim: hasRowSource,
    run: () => sendSelected("intruder", "Ctrl+I"),
  },
  {
    keys: "Ctrl+Enter",
    what: "Send the request being edited",
    where: "Repeater — works inside the editor",
    when: (e) => mod(e) && !e.shiftKey && e.key === "Enter",
    claim: () => activeTabId() === "repeater" && $("#rep-send") !== null,
    // Clicks the pane's own Send button rather than re-implementing the send: one entry point means
    // the shortcut cannot drift from what the button does.
    run: () => $<HTMLButtonElement>("#rep-send")?.click(),
    inEditable: true,
  },
  {
    keys: "Ctrl+Shift+→",
    what: "Next tab",
    where: "anywhere",
    when: (e) => mod(e) && e.shiftKey && e.key === "ArrowRight",
    run: () => moveTab(1),
  },
  {
    keys: "Ctrl+Shift+←",
    what: "Previous tab",
    where: "anywhere",
    when: (e) => mod(e) && e.shiftKey && e.key === "ArrowLeft",
    run: () => moveTab(-1),
  },
  {
    keys: "?",
    what: "Show or hide this list",
    where: "anywhere",
    when: (e) => !e.ctrlKey && !e.metaKey && !e.altKey && e.key === "?",
    run: () => toggleSheet(),
  },
];

// ---- the cheat sheet --------------------------------------------------------------------------

const SHEET_ID = "shortcut-sheet";

/** Panes with a right-click menu, listed in the sheet. Right-click is as undiscoverable as a
 * shortcut, so it is documented in the same place rather than left to be stumbled on. */
const MENU_PANES: [string, string][] = [
  ["History", "send to Repeater / Intruder / Comparer, save to Organizer, copy URL or curl"],
  ["Site map", "the node's most recent exchange: send to any tool, copy its URL, open it in History"],
  ["WS History", "the upgrade exchange, and copy the message payload"],
  ["Scanner", "the finding's first occurrence: open it in History or send it to any tool"],
  ["Logger", "copy the host or path, or filter History by that host"],
];

function sheetHtml(): string {
  const rows = BINDINGS.map(
    (b) =>
      `<tr><td><kbd>${esc(b.keys)}</kbd></td><td>${esc(b.what)}</td><td class="hint">${esc(b.where)}</td></tr>`,
  ).join("");
  const menus = MENU_PANES.map(
    ([pane, what]) => `<tr><td><b>${esc(pane)}</b></td><td colspan="2" class="hint">${esc(what)}</td></tr>`,
  ).join("");
  return `
    <div class="sheet">
      <div class="row">
        <b class="card-title" style="margin:0">Keyboard shortcuts</b>
        <span class="grow"></span>
        <button class="ghost small" id="sheet-close">Close</button>
      </div>
      <table>
        <thead><tr><th>Key</th><th>Does</th><th>Where</th></tr></thead>
        <tbody>
          ${rows}
          <tr><td><kbd>Esc</kbd></td><td>Close this list, or an open right-click menu</td><td class="hint">anywhere</td></tr>
        </tbody>
      </table>
      <p class="hint">On macOS press <kbd>⌘</kbd> wherever this says <kbd>Ctrl</kbd>. Tab switching
        avoids <kbd>Ctrl</kbd>+<kbd>1</kbd>..<kbd>9</kbd> because the browser reserves those for its own
        tabs and a page cannot override them. <kbd>Ctrl</kbd>+<kbd>R</kbd> stays the browser's reload on
        any tab without selectable rows.</p>
      <div class="card-title" style="margin-top:12px">Right-click a row</div>
      <table><tbody>${menus}</tbody></table>
      <p class="hint">Right-click also selects the row, so <kbd>Ctrl</kbd>+<kbd>R</kbd> afterwards acts
        on the same one.</p>
    </div>`;
}

function sheetEl(): HTMLElement | null {
  return document.getElementById(SHEET_ID);
}

function closeSheet(): void {
  const el = sheetEl();
  if (!el) return;
  el.remove();
  document.removeEventListener("keydown", onSheetKey, true);
}

function openSheet(): void {
  if (sheetEl()) return;
  const el = document.createElement("div");
  el.id = SHEET_ID;
  el.className = "sheet-backdrop";
  el.innerHTML = sheetHtml();
  document.body.appendChild(el);
  el.addEventListener("click", (e) => {
    // Backdrop click and the Close button both dismiss; a click inside the sheet does not.
    if (e.target === el || (e.target as HTMLElement).id === "sheet-close") closeSheet();
  });
  document.addEventListener("keydown", onSheetKey, true);
}

export function toggleSheet(): void {
  if (sheetEl()) closeSheet();
  else openSheet();
}

function onSheetKey(e: KeyboardEvent): void {
  if (e.key === "Escape" || e.key === "?") {
    e.preventDefault();
    e.stopPropagation();
    closeSheet();
  }
}

// ---- dispatch ---------------------------------------------------------------------------------

/** True when the key belongs to whatever the operator is typing into. */
function inEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

function onKey(e: KeyboardEvent): void {
  // An open menu owns the keyboard; it handles its own keys in the capture phase and stops them, so
  // this is a second line of defence rather than the only one.
  if (isContextMenuOpen()) return;
  if (e.isComposing) return;
  const editable = inEditable(e.target);
  for (const b of BINDINGS) {
    if (!b.when(e)) continue;
    if (editable && b.inEditable !== true) return;
    if (b.claim && !b.claim()) return;
    e.preventDefault();
    b.run();
    return;
  }
}

/** Adds the header help affordance. Done from here rather than in index.html so the button and the
 * sheet it opens are never out of step, and so this module is the only thing that needs to know the
 * sheet exists.
 *
 * Inserted into the workspace header (identified by class, not tag, so the menu bar and the
 * workspace header cannot be confused) and appended rather than positioned relative to the CA link:
 * the CA link used to live beside it in the header, but the sidebar redesign moved it into the
 * sidebar foot, and `insertBefore` on a node that is no longer a child threw `NotFoundError` and
 * halted the whole module. Appending to the header's own children does not care where the CA link
 * went. */
function addHelpButton(): void {
  const header = $<HTMLElement>(".workspace > header") ?? $("header");
  if (!header || document.getElementById("shortcut-help")) return;
  const btn = document.createElement("button");
  btn.id = "shortcut-help";
  btn.className = "ghost small";
  btn.type = "button";
  btn.textContent = "? shortcuts";
  btn.title = "keyboard shortcuts and right-click actions (press ?)";
  btn.addEventListener("click", () => toggleSheet());
  header.appendChild(btn);
}

export function initShortcuts(): void {
  addHelpButton();
  document.addEventListener("keydown", onKey);
}
