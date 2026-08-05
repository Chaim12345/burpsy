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

const TAB_SUBTITLES: Record<string, string> = {
  dashboard: "Operations, coverage, and recent activity",
  history: "Captured HTTP traffic and message inspection",
  wshistory: "Captured WebSocket conversations",
  sitemap: "Discovered hosts, paths, and observed behavior",
  intercept: "Review and modify traffic before it continues",
  repeater: "Edit and resend individual requests",
  intruder: "Automated payload-driven request attacks",
  scanner: "Passive findings and targeted active audits",
  sequencer: "Measure token quality and randomness",
  decoder: "Decode, encode, and hash technical data",
  comparer: "Inspect byte- or word-level differences",
  logger: "Requests originated by burpsy tools",
  organizer: "Curated exchanges and investigation notes",
  matchreplace: "Automatic request and response transformations",
  session: "Login macros, validation, and recovery policy",
};

export function switchTab(id: string): void {
  let title = "burpsy";
  $all<HTMLButtonElement>("nav button[data-t]").forEach((b) => {
    const active = b.dataset["t"] === id;
    b.classList.toggle("on", active);
    b.setAttribute("aria-current", active ? "page" : "false");
    if (active) title = b.textContent?.trim() || title;
  });
  $all("main > section").forEach((s) => s.classList.toggle("on", s.id === id));
  $all("main > section").forEach((s) => s.setAttribute("aria-hidden", String(s.id !== id)));
  const heading = $("#page-title");
  if (heading) heading.textContent = title;
  const subtitle = $("#page-subtitle");
  if (subtitle) subtitle.textContent = TAB_SUBTITLES[id] ?? "Security testing workspace";
  document.title = `${title} · burpsy`;
  history.replaceState(null, "", `#${id}`);
  closeNavigation();
}

export function initTabs(): void {
  const tabs = $all<HTMLButtonElement>("nav button[data-t]");
  const visible = tabs.filter((b) => (b.offsetParent !== null));
  visible.forEach((b, index) => {
    b.onclick = () => switchTab(b.dataset["t"]!);
    b.onkeydown = (event) => {
      if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
      event.preventDefault();
      const next = (index + (event.key === "ArrowDown" ? 1 : -1) + visible.length) % visible.length;
      visible[next]!.focus();
    };
  });
  const requested = location.hash.slice(1);
  if (requested && tabs.some((tab) => tab.dataset["t"] === requested)) switchTab(requested);

  $("#nav-toggle")?.addEventListener("click", () => {
    document.body.classList.toggle("nav-open");
    updateNavigationState();
  });
  $("#nav-scrim")?.addEventListener("click", closeNavigation);
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeNavigation();
  });
}

/** Adds durable accessible names to the many compact technical editors without duplicating their
 * visible placeholders. Tool panes are mounted after initTabs(), so app.ts calls this once they all
 * exist. Native labels remain authoritative; this only fills otherwise unnamed controls. */
export function enhanceAccessibility(): void {
  $all<HTMLInputElement | HTMLTextAreaElement>("input[placeholder], textarea[placeholder]").forEach((control) => {
    if (!control.getAttribute("aria-label") && !control.labels?.length) {
      control.setAttribute("aria-label", control.placeholder);
    }
  });
  $all<HTMLSelectElement>("select").forEach((control) => {
    if (!control.getAttribute("aria-label") && !control.labels?.length && !control.title) {
      const first = control.options[0]?.textContent?.trim();
      if (first) control.setAttribute("aria-label", first);
    }
  });
  $all<HTMLElement>("main > section").forEach((section) => section.setAttribute("aria-hidden", String(!section.classList.contains("on"))));
}

function closeNavigation(): void {
  document.body.classList.remove("nav-open");
  updateNavigationState();
}

function updateNavigationState(): void {
  const open = document.body.classList.contains("nav-open");
  $("#nav-toggle")?.setAttribute("aria-expanded", String(open));
  const scrim = $<HTMLElement>("#nav-scrim");
  if (scrim) scrim.hidden = !open;
}

// ---- toast ----------------------------------------------------------------------------------

let toastTimer: ReturnType<typeof setTimeout> | undefined;

export function toast(message: string, kind: "info" | "error" = "info"): void {
  let el = document.getElementById("toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
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
