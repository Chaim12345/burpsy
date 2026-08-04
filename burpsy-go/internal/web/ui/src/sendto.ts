// The hand-off actions themselves, in one place, so that History's row buttons, every pane's
// right-click menu and the keyboard shortcuts all run the same code. They used to exist only as the
// body of History's `handleAction` switch, which is why no other pane could offer them.
//
// Everything here is derived from a captured exchange. Nothing invents a request: "copy as curl"
// reads the stored request bytes and re-renders them, rather than reconstructing a plausible request
// from the method and path a row happens to display — a curl command that is not the request that
// was captured is worse than no button.

import { getJSON, postJSON, emit, switchTab, toast } from "./common";
import type { Exchange, MessageView } from "./types";
import { EVT_SEND_TO_REPEATER, EVT_SEND_TO_INTRUDER, EVT_SEND_TO_COMPARER, EVT_SHOW_EXCHANGE } from "./types";
import type { MenuItem } from "./contextmenu";

/** `scheme://host:port` — the Repeater target field's format, which always carries the port. */
function targetOf(ex: Exchange): string {
  return `${ex.tls ? "https" : "http"}://${ex.host}:${ex.port}`;
}

/** The row's absolute URL. The port is dropped when it is the scheme's default, because this string
 * is meant to be pasted somewhere else and `https://host:443/x` is noise there. */
function urlOf(ex: Exchange): string {
  const scheme = ex.tls ? "https" : "http";
  const defaultPort = ex.tls ? 443 : 80;
  const authority = ex.port === defaultPort ? ex.host : `${ex.host}:${ex.port}`;
  return `${scheme}://${authority}${ex.path}`;
}

export async function sendToRepeater(ex: Exchange): Promise<void> {
  try {
    const req = await getJSON<MessageView>(`/api/message/${ex.request}`);
    emit(EVT_SEND_TO_REPEATER, { target: targetOf(ex), raw: req.text, protocol: ex.protocol });
    switchTab("repeater");
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

export function sendToIntruder(ex: Exchange): void {
  emit(EVT_SEND_TO_INTRUDER, { msgId: ex.request, target: targetOf(ex) });
  switchTab("intruder");
}

export function sendToComparer(ex: Exchange, side: "a" | "b"): void {
  emit(EVT_SEND_TO_COMPARER, { side, msgId: ex.request, label: `${ex.method} ${ex.path}` });
  switchTab("comparer");
  toast(`sent request #${ex.request} to Comparer ${side.toUpperCase()}`);
}

function showInHistory(ex: Exchange): void {
  emit(EVT_SHOW_EXCHANGE, { exchangeId: ex.id });
  switchTab("history");
}

export async function saveToOrganizer(ex: Exchange): Promise<void> {
  try {
    await postJSON("/api/tools/organizer", { exchange: ex.id });
    toast(`saved ${ex.method} ${ex.path} to Organizer`);
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

/** Opens the row's URL in a new browser tab. Named for what it does rather than "request in
 * browser": this navigates the operator's browser, which only reaches burpsy at all if that browser
 * is pointed at the proxy — the request is not replayed through burpsy by this button. */
function openUrl(ex: Exchange): void {
  window.open(urlOf(ex), "_blank", "noopener,noreferrer");
}

// ---- clipboard --------------------------------------------------------------------------------

/** Copies text, reporting either way. The execCommand path is the fallback for a context where the
 * async clipboard is unavailable or denied; without it a blocked clipboard looks like a dead button. */
export async function copyText(text: string, what: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast(`copied ${what}`);
    return;
  } catch {
    // fall through to the legacy path
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("aria-hidden", "true");
  ta.style.position = "fixed";
  ta.style.top = "-1000px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  toast(ok ? `copied ${what}` : `could not copy ${what} — the clipboard is blocked`, ok ? "info" : "error");
}

/** Single-quotes a value for a POSIX shell. */
function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Renders the captured request as a curl command.
 *
 * Content-Length is the one header dropped: curl computes it from the body it is actually sending,
 * and a copied-through value that disagrees produces a request the server reads as truncated. Every
 * other header — Host included, so a virtual-host request still reaches the same vhost — is passed
 * as captured. */
function asCurl(ex: Exchange, raw: string): string {
  const split = raw.search(/\r?\n\r?\n/);
  const head = split === -1 ? raw : raw.slice(0, split);
  const body = split === -1 ? "" : raw.slice(split).replace(/^\r?\n\r?\n/, "");
  const lines = head.split(/\r?\n/);
  const method = (lines[0] ?? "").split(" ")[0] || ex.method || "GET";
  const parts = [`curl -i -sS -X ${method} ${shellQuote(urlOf(ex))}`];
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    if (/^content-length$/i.test(line.slice(0, colon).trim())) continue;
    parts.push(`-H ${shellQuote(line.trim())}`);
  }
  if (body.length > 0) parts.push(`--data-raw ${shellQuote(body)}`);
  return parts.join(" \\\n  ");
}

async function copyAsCurl(ex: Exchange): Promise<void> {
  try {
    const req = await getJSON<MessageView>(`/api/message/${ex.request}`);
    await copyText(asCurl(ex, req.text), `#${ex.id} as curl`);
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

// ---- the shared menu block --------------------------------------------------------------------

interface ExchangeAction {
  label: string;
  hint?: string;
  /** A separator is drawn before this action. */
  before?: boolean;
  act: (ex: Exchange) => void | Promise<void>;
}

/** The action list every pane offers for an exchange, in one order so the menu reads the same
 * everywhere. `hint` mirrors shortcuts.ts's table; the binding itself lives there, not here. */
function exchangeActions(showHistory: boolean): ExchangeAction[] {
  const actions: ExchangeAction[] = [
    { label: "Send to Repeater", hint: "Ctrl+R", act: (ex) => sendToRepeater(ex) },
    { label: "Send to Intruder", hint: "Ctrl+I", act: (ex) => sendToIntruder(ex) },
    { label: "Send to Comparer (A)", act: (ex) => sendToComparer(ex, "a") },
    { label: "Send to Comparer (B)", act: (ex) => sendToComparer(ex, "b") },
    { label: "Save to Organizer", before: true, act: (ex) => saveToOrganizer(ex) },
    { label: "Copy URL", before: true, act: (ex) => copyText(urlOf(ex), `#${ex.id} URL`) },
    { label: "Copy as curl", act: (ex) => copyAsCurl(ex) },
    { label: "Open URL in a new tab", act: (ex) => openUrl(ex) },
  ];
  if (showHistory) {
    actions.push({ label: "Show in History", before: true, act: (ex) => showInHistory(ex) });
  }
  return actions;
}

function toMenuItems(actions: ExchangeAction[], run: (a: ExchangeAction) => () => void): MenuItem[] {
  const items: MenuItem[] = [];
  for (const a of actions) {
    if (a.before) items.push({ separator: true });
    const item: MenuItem = { label: a.label, run: run(a) };
    if (a.hint !== undefined) item.hint = a.hint;
    items.push(item);
  }
  return items;
}

/** The standard block for an exchange the caller already holds. */
export function exchangeMenuItems(ex: Exchange, opts?: { showInHistory?: boolean }): MenuItem[] {
  return toMenuItems(exchangeActions(opts?.showInHistory === true), (a) => () => void a.act(ex));
}

/** The standard block for a pane that carries only an exchange id — Site map, WS History, Scanner.
 * The exchange is fetched when an item is chosen rather than when the menu opens, so right-clicking
 * a row costs no request. `absent` is the reason shown, dimmed, when the row has no exchange at all. */
export function exchangeIdMenuItems(
  id: number | null | undefined,
  absent = "no captured request here — nothing to send",
  opts?: { showInHistory?: boolean },
): MenuItem[] {
  if (id === null || id === undefined) return [{ label: absent, disabled: true }];
  return toMenuItems(
    exchangeActions(opts?.showInHistory === true),
    (a) => () => void withExchange(id, (ex) => a.act(ex)),
  );
}

/** Fetches one exchange and hands it to `fn`, reporting a failure through the toast rather than the
 * console — the operator clicked something and is owed an answer either way. */
async function withExchange(id: number, fn: (ex: Exchange) => void | Promise<void>): Promise<void> {
  try {
    const ex = await getJSON<Exchange>(`/api/exchange/${id}`);
    await fn(ex);
  } catch (e) {
    toast((e as Error).message, "error");
  }
}

/** Resolves an exchange id for the keyboard shortcuts, which need the object itself. Returns null
 * (and says why) rather than throwing, because a shortcut that silently does nothing is the problem
 * this whole change exists to fix. */
export async function fetchExchange(id: number): Promise<Exchange | null> {
  try {
    return await getJSON<Exchange>(`/api/exchange/${id}`);
  } catch (e) {
    toast((e as Error).message, "error");
    return null;
  }
}
