// Shared helpers for every tab: DOM shortcuts, HTML escaping, the fetch wrappers every panel
// calls the JSON API through, tab switching, a toast, and a tiny event bus so one tab can hand
// off to another (e.g. History's "send to Repeater").

export function $<T extends Element = HTMLElement>(sel: string, root: ParentNode = document): T | null {
  return root.querySelector<T>(sel);
}

export function $all<T extends Element = HTMLElement>(sel: string, root: ParentNode = document): T[] {
  return Array.from(root.querySelectorAll<T>(sel));
}

const ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** HTML-escape untrusted text before interpolating it into innerHTML. */
export function esc(s: string | number | null | undefined): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ESCAPE_MAP[c] ?? c);
}

/** A status code, colour-coded by its leading digit, or a dash when absent. */
export function statusBadge(status: number | null | undefined): string {
  if (status === null || status === undefined) return "-";
  return `<span class="s${String(status)[0]}">${status}</span>`;
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public body: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface ErrorBody {
  error?: string;
}

function isErrorBody(v: unknown): v is ErrorBody {
  return typeof v === "object" && v !== null && "error" in v;
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const r = await fetch(url, init);
  const text = await r.text();
  let json: unknown = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  if (!r.ok) {
    const message = isErrorBody(json) && json.error ? json.error : text || `${r.status} ${r.statusText}`;
    throw new ApiError(message, r.status, json ?? text);
  }
  return json as T;
}

export const getJSON = <T>(url: string): Promise<T> => request<T>("GET", url);
export const postJSON = <T>(url: string, body: unknown = {}): Promise<T> => request<T>("POST", url, body);
export const putJSON = <T>(url: string, body: unknown = {}): Promise<T> => request<T>("PUT", url, body);
export const delJSON = <T>(url: string): Promise<T> => request<T>("DELETE", url);

// ---- tabs ---------------------------------------------------------------------------------

export function switchTab(id: string): void {
  $all("nav button[data-t]").forEach((b) => {
    const active = (b as HTMLElement).dataset["t"] === id;
    b.classList.toggle("on", active);
    b.setAttribute("aria-selected", active ? "true" : "false");
  });
  $all("main > section").forEach((s) => s.classList.toggle("on", s.id === id));
}

export function initTabs(): void {
  $all<HTMLButtonElement>("nav button[data-t]").forEach((b) => {
    b.onclick = () => switchTab(b.dataset["t"]!);
  });
}

// ---- toast ----------------------------------------------------------------------------------

let toastTimer: ReturnType<typeof setTimeout> | undefined;

export function toast(message: string, kind: "info" | "error" = "info"): void {
  let el = document.getElementById("toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    document.body.appendChild(el);
  }
  el.textContent = message;
  el.className = kind;
  // Force a reflow so re-triggering the class while already visible restarts the CSS transition.
  void el.offsetWidth;
  el.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el?.classList.remove("show"), 3000);
}

// ---- cross-tab event bus ---------------------------------------------------------------------

const bus = new EventTarget();

export function on<T = unknown>(event: string, handler: (detail: T) => void): void {
  bus.addEventListener(event, (e) => handler((e as CustomEvent<T>).detail));
}

export function emit<T = unknown>(event: string, detail: T): void {
  bus.dispatchEvent(new CustomEvent(event, { detail }));
}
