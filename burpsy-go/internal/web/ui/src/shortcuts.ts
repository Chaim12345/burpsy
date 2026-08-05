// Keyboard shortcuts: one place to bind the global keys, and one place to document them.
//
// Two deliberate choices:
//
//   * The bindings are attached to the document, not to the pane that is currently on screen.
//     That means a shortcut works even when its pane is not the one the operator is looking at,
//     which is the whole point of a global shortcut.
//
//   * A pane that wants to be the target of a shortcut registers a function with
//     `registerRowTarget`. The shortcut handler calls that function to get the thing to act on,
//     so the shortcut code never has to know which pane is on screen or how that pane stores its
//     selection. The pane can change its selection model without the shortcuts breaking.

import { $, toast } from "./common";
import { EVT_SEND_TO_REPEATER, EVT_SEND_TO_INTRUDER, EVT_SEND_TO_COMPARER } from "./types";
import { emit } from "./common";
import { isContextMenuOpen } from "./contextmenu";
import type { Exchange } from "./types";

/** One pane's notion of "the currently selected row". A pane registers this so the shortcuts can
 * ask it for the row to act on. */
interface RowTarget {
  label: string;
  exchange?: Exchange;
  exchangeId?: number;
  note?: string;
}

const targets: Map<string, () => RowTarget | null> = new Map();

/** Registers a pane as a possible shortcut target. `id` is the pane's own identifier (the same
 * one it uses for its `<section id>`). */
export function registerRowTarget(id: string, fn: () => RowTarget | null): void {
  targets.set(id, fn);
}

/** Returns the currently active pane's selected row, or null if the active pane has no selection
 * or does not register one. */
function activeTarget(): RowTarget | null {
  const active = $all("section.on").find(s => s.id);
  if (!active) return null;
  const fn = targets.get(active.id);
  return fn ? fn() : null;
}

/** The one place every shortcut is bound. A pane that wants to be reachable registers its
 * selection with `registerRowTarget`; the handler here resolves which pane is on screen and
 * asks it for the row. */
function bindShortcuts(): void {
  document.addEventListener("keydown", (e) => {
    // Ignore if typing in an input
    if ((e.target as HTMLElement).tagName === "INPUT" ||
        (e.target as HTMLElement).tagName === "TEXTAREA" ||
        (e.target as HTMLElement).isContentEditable) {
      return;
    }

    // Ignore if context menu is open
    if (isContextMenuOpen()) {
      return;
    }

    // Ctrl+R: Send to Repeater
    if (e.ctrlKey && e.key === "r") {
      e.preventDefault();
      const t = activeTarget();
      if (t?.exchange) {
        emit(EVT_SEND_TO_REPEATER, {
          target: `${t.exchange.tls ? "https" : "http"}://${t.exchange.host}:${t.exchange.port}`,
          raw: "", // Will be fetched by repeater
          protocol: t.exchange.protocol,
        });
        toast(`Sent to Repeater: ${t.label}`);
      } else if (t?.exchangeId) {
        // Fetch exchange and send
        void fetchExchangeAndSend(t.exchangeId);
      } else {
        toast("No row selected", "warning");
      }
    }

    // Ctrl+I: Send to Intruder
    if (e.ctrlKey && e.key === "i") {
      e.preventDefault();
      const t = activeTarget();
      if (t?.exchange) {
        emit(EVT_SEND_TO_INTRUDER, {
          msgId: t.exchange.request,
          target: `${t.exchange.tls ? "https" : "http"}://${t.exchange.host}:${t.exchange.port}`,
        });
        toast(`Sent to Intruder: ${t.label}`);
      } else if (t?.exchangeId) {
        // For exchangeId, we need to fetch the exchange first
        void fetchExchangeAndSendToIntruder(t.exchangeId);
      } else {
        toast("No row selected", "warning");
      }
    }

    // Ctrl+A: Send to Comparer (A)
    if (e.ctrlKey && e.key === "a") {
      e.preventDefault();
      const t = activeTarget();
      if (t?.exchange) {
        emit(EVT_SEND_TO_COMPARER, {
          side: "a",
          msgId: t.exchange.request,
          label: t.label,
        });
        toast(`Sent to Comparer A: ${t.label}`);
      } else {
        toast("No row selected", "warning");
      }
    }

    // Ctrl+B: Send to Comparer (B)
    if (e.ctrlKey && e.key === "b") {
      e.preventDefault();
      const t = activeTarget();
      if (t?.exchange) {
        emit(EVT_SEND_TO_COMPARER, {
          side: "b",
          msgId: t.exchange.request,
          label: t.label,
        });
        toast(`Sent to Comparer B: ${t.label}`);
      } else {
        toast("No row selected", "warning");
      }
    }

    // Escape: Close modals, clear selections
    if (e.key === "Escape") {
      // Close any open modals
      const backdrop = $(".sheet-backdrop");
      if (backdrop) {
        e.preventDefault();
        backdrop.remove();
      }
    }
  });
}

async function fetchExchangeAndSend(exchangeId: number): Promise<void> {
  try {
    const response = await fetch(`/api/exchange/${exchangeId}`);
    if (!response.ok) throw new Error(`Failed to fetch exchange: ${response.status}`);
    const exchange = await response.json() as Exchange;
    emit(EVT_SEND_TO_REPEATER, {
      target: `${exchange.tls ? "https" : "http"}://${exchange.host}:${exchange.port}`,
      raw: "", // Will be fetched by repeater
      protocol: exchange.protocol,
    });
    toast(`Sent to Repeater: exchange #${exchangeId}`);
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

async function fetchExchangeAndSendToIntruder(exchangeId: number): Promise<void> {
  try {
    const response = await fetch(`/api/exchange/${exchangeId}`);
    if (!response.ok) throw new Error(`Failed to fetch exchange: ${response.status}`);
    const exchange = await response.json() as Exchange;
    emit(EVT_SEND_TO_INTRUDER, {
      msgId: exchange.request,
      target: `${exchange.tls ? "https" : "http"}://${exchange.host}:${exchange.port}`,
    });
    toast(`Sent to Intruder: exchange #${exchangeId}`);
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

// Shortcut help sheet
let sheetBackdrop: HTMLElement | null = null;

export function showShortcutSheet(): void {
  if (sheetBackdrop) {
    sheetBackdrop.remove();
    sheetBackdrop = null;
    return;
  }

  sheetBackdrop = document.createElement("div");
  sheetBackdrop.className = "sheet-backdrop";
  sheetBackdrop.innerHTML = `
    <div class="sheet">
      <h2>Keyboard Shortcuts</h2>
      <p class="hint">Available globally when not typing in an input field</p>
      <table>
        <thead>
          <tr><th>Key</th><th>Action</th><th>Context</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><kbd>Ctrl+R</kbd></td>
            <td>Send to Repeater</td>
            <td>History, Scanner, Site map, WS History</td>
          </tr>
          <tr>
            <td><kbd>Ctrl+I</kbd></td>
            <td>Send to Intruder</td>
            <td>History, Scanner, Site map, WS History</td>
          </tr>
          <tr>
            <td><kbd>Ctrl+A</kbd></td>
            <td>Send to Comparer (A)</td>
            <td>History, Scanner, Site map, WS History</td>
          </tr>
          <tr>
            <td><kbd>Ctrl+B</kbd></td>
            <td>Send to Comparer (B)</td>
            <td>History, Scanner, Site map, WS History</td>
          </tr>
          <tr>
            <td><kbd>↑</kbd>/<kbd>↓</kbd></td>
            <td>Navigate rows</td>
            <td>All tables</td>
          </tr>
          <tr>
            <td><kbd>Enter</kbd></td>
            <td>Open/Select row</td>
            <td>All tables</td>
          </tr>
          <tr>
            <td><kbd>Esc</kbd></td>
            <td>Close modal/deselect</td>
            <td>All</td>
          </tr>
          <tr>
            <td><kbd>?</kbd></td>
            <td>Show this help</td>
            <td>All</td>
          </tr>
        </tbody>
      </table>
      <div style="margin-top:12px;text-align:right">
        <button class="go" onclick="this.closest('.sheet-backdrop').remove()">Close</button>
      </div>
    </div>
  `;
  document.body.appendChild(sheetBackdrop);

  // Close on escape
  sheetBackdrop.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      sheetBackdrop?.remove();
      sheetBackdrop = null;
    }
  });
}

export function initShortcuts(): void {
  bindShortcuts();
  
  // Also bind ? key to show help
  document.addEventListener('keydown', (e) => {
    if (e.key === '?' && !isContextMenuOpen() && 
        (e.target as HTMLElement).tagName !== "INPUT" &&
        (e.target as HTMLElement).tagName !== "TEXTAREA") {
      e.preventDefault();
      showShortcutSheet();
    }
  });
}
