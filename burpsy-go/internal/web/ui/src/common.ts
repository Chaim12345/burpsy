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
    public isRetryable: boolean = false,
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

// ---- Loading State Management ------------------------------------------------------------

/** Show loading state on an element */
export function showLoading(el: HTMLElement): void {
  el.classList.add('loading');
  el.disabled = true;
  const originalText = el.getAttribute('data-original-text') || el.textContent;
  el.setAttribute('data-original-text', originalText);
  el.textContent = originalText + '...';
}

/** Hide loading state on an element */
export function hideLoading(el: HTMLElement): void {
  el.classList.remove('loading');
  el.disabled = false;
  const originalText = el.getAttribute('data-original-text');
  if (originalText) {
    el.textContent = originalText;
  }
}

/** Create a loading spinner element */
export function createSpinner(size: 'small' | 'medium' | 'large' = 'medium'): HTMLElement {
  const spinner = document.createElement('span');
  spinner.className = `spinner spinner-${size}`;
  spinner.setAttribute('aria-label', 'Loading...');
  return spinner;
}

// ---- Enhanced Toast System ----------------------------------------------------------------

interface ToastOptions {
  duration?: number; // default 4000ms
  dismissible?: boolean; // default true
  persistent?: boolean; // stays until dismissed
  type?: 'info' | 'error' | 'success' | 'warning';
}

let toastContainer: HTMLElement | null = null;
let toasts: HTMLElement[] = [];

export function toast(msg: string, kind: 'info' | 'error' | 'success' | 'warning' = 'info', opts: ToastOptions = {}): void {
  if (!toastContainer) {
    toastContainer = createToastContainer();
  }

  const el = document.createElement('div');
  el.className = `toast ${kind} ${opts.persistent ? 'persistent' : ''}`;
  el.setAttribute('role', 'alert');
  
  const icon = getToastIcon(kind);
  const dismissible = opts.dismissible !== false;
  
  el.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <span class="toast-message">${esc(msg)}</span>
    ${dismissible ? '<button class="toast-dismiss" aria-label="Dismiss">&times;</button>' : ''}
  `;

  toastContainer.appendChild(el);
  toasts.push(el);

  // Auto-dismiss if not persistent
  if (!opts.persistent) {
    const duration = opts.duration ?? (kind === 'error' ? 6000 : 4000);
    setTimeout(() => removeToast(el), duration);
  }

  // Dismiss button handler
  if (dismissible) {
    const dismissBtn = el.querySelector('.toast-dismiss') as HTMLButtonElement;
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => removeToast(el));
    }
  }

  // Limit to 5 toasts at once
  while (toasts.length > 5) {
    removeToast(toasts[0]);
  }
}

function getToastIcon(kind: string): string {
  switch (kind) {
    case 'error': return '❌';
    case 'success': return '✅';
    case 'warning': return '⚠️';
    default: return 'ℹ️';
  }
}

function createToastContainer(): HTMLElement {
  const el = document.createElement('div');
  el.id = 'toast-container';
  document.body.appendChild(el);
  return el;
}

function removeToast(el: HTMLElement): void {
  el.classList.add('hiding');
  setTimeout(() => {
    el.remove();
    toasts = toasts.filter(t => t !== el);
    // Remove container if empty
    if (toasts.length === 0 && toastContainer) {
      toastContainer.remove();
      toastContainer = null;
    }
  }, 200);
}

// ---- Request wrappers ----------------------------------------------------------------------

async function request<T>(method: string, url: string, body?: unknown, retries: number = 0): Promise<T> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
  
  let lastError: Error;
  
  for (let i = 0; i <= retries; i++) {
    try {
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
        const isRetryable = r.status >= 500 || r.status === 429;
        throw new ApiError(message, r.status, json ?? text, isRetryable);
      }
      return json as T;
    } catch (e) {
      lastError = e as Error;
      if (i < retries && (e as ApiError).isRetryable) {
        await new Promise(resolve => setTimeout(resolve, 100 * (i + 1)));
        continue;
      }
      throw e;
    }
  }
  throw lastError;
}

export const getJSON = <T>(url: string): Promise<T> => request<T>("GET", url);
export const postJSON = <T>(url: string, body: unknown = {}): Promise<T> => request<T>("POST", url, body);
export const putJSON = <T>(url: string, body: unknown = {}): Promise<T> => request<T>("PUT", url, body);
export const delJSON = <T>(url: string): Promise<T> => request<T>("DELETE", url);

// ---- tabs ---------------------------------------------------------------------------------

export function switchTab(id: string): void {
  $all("nav button[data-t]").forEach((b) => b.classList.toggle("on", (b as HTMLElement).dataset["t"] === id));
  $all("main > section").forEach((s) => s.classList.toggle("on", s.id === id));
}

export function initTabs(): void {
  $all<HTMLButtonElement>("nav button[data-t]").forEach((b) => {
    b.onclick = () => switchTab(b.dataset["t"]!);
  });
}

// ---- Event Bus ----------------------------------------------------------------------------

type EventHandler<T> = (detail: T) => void;
const listeners = new Map<string, Set<EventHandler<unknown>>>();

export function on<T>(event: string, handler: EventHandler<T>): () => void {
  if (!listeners.has(event)) {
    listeners.set(event, new Set());
  }
  const set = listeners.get(event)!;
  set.add(handler as EventHandler<unknown>);
  
  return () => {
    set.delete(handler as EventHandler<unknown>);
    if (set.size === 0) {
      listeners.delete(event);
    }
  };
}

export function emit<T>(event: string, detail: T): void {
  const set = listeners.get(event);
  if (set) {
    set.forEach(handler => (handler as EventHandler<T>)(detail));
  }
}

// ---- Local Storage Helpers ----------------------------------------------------------------

export function persistFilter(key: string, input: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): void {
  const save = () => {
    if (input.type === 'checkbox') {
      localStorage.setItem(`filter:${key}`, String((input as HTMLInputElement).checked));
    } else {
      localStorage.setItem(`filter:${key}`, input.value);
    }
  };
  
  input.addEventListener('input', save);
  input.addEventListener('change', save);
  
  // Restore on load
  const saved = localStorage.getItem(`filter:${key}`);
  if (saved !== null) {
    if (input.type === 'checkbox') {
      (input as HTMLInputElement).checked = saved === 'true';
    } else {
      input.value = saved;
    }
    // Trigger change event for components that need it
    if (input.type === 'checkbox') {
      (input as HTMLInputElement).dispatchEvent(new Event('change'));
    }
  }
}

// ---- Search Highlighting ------------------------------------------------------------------

export function highlightSearch(text: string, query: string): string {
  if (!query) return esc(text);
  
  try {
    // Escape regex special characters
    const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escapedQuery, 'gi');
    return esc(text).replace(regex, match => 
      `<span class="search-highlight">${match}</span>`
    );
  } catch {
    // Invalid regex, return unhighlighted
    return esc(text);
  }
}

// ---- Table Sorting ------------------------------------------------------------------------

export function makeSortable(tableId: string, defaultSort: string = ''): void {
  const table = $(`#${tableId}`);
  if (!table) return;

  const headers = table.querySelectorAll('th[data-sort]');
  let currentSort: string | null = defaultSort;
  let ascending = true;

  headers.forEach(th => {
    th.addEventListener('click', () => {
      const field = th.dataset.sort!;

      // Remove sort indicators
      headers.forEach(h => {
        h.classList.remove('sorted', 'sorted-asc', 'sorted-desc');
      });

      // Set new sort
      if (currentSort === field) {
        ascending = !ascending;
      } else {
        currentSort = field;
        ascending = true;
      }

      th.classList.add('sorted', ascending ? 'sorted-asc' : 'sorted-desc');

      // Trigger re-sort
      const event = new CustomEvent('sort', {
        detail: { field, ascending }
      });
      table.dispatchEvent(event);
    });
  });
}

export function createSorter<T>(field: keyof T, ascending: boolean): (a: T, b: T) => number {
  return (a, b) => {
    let aVal: any = a[field];
    let bVal: any = b[field];

    // Handle nulls
    if (aVal === null || aVal === undefined) return ascending ? 1 : -1;
    if (bVal === null || bVal === undefined) return ascending ? -1 : 1;

    // Numeric comparison
    if (typeof aVal === 'number') {
      return ascending ? aVal - bVal : bVal - aVal;
    }

    // String comparison
    aVal = String(aVal);
    bVal = String(bVal);
    return ascending 
      ? aVal.localeCompare(bVal)
      : bVal.localeCompare(aVal);
  };
}

// ---- Theme Management --------------------------------------------------------------------

export function initTheme(): void {
  const saved = localStorage.getItem('theme') as 'dark' | 'light' | null;
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = saved || (prefersDark ? 'dark' : 'light');
  document.documentElement.classList.toggle('light', theme === 'light');

  // Add toggle button to header
  const toggle = document.createElement('button');
  toggle.className = 'ghost theme-toggle';
  toggle.innerHTML = theme === 'dark' ? '☀️' : '🌙';
  toggle.title = 'Toggle theme';
  toggle.onclick = () => {
    const isLight = document.documentElement.classList.toggle('light');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    toggle.innerHTML = isLight ? '🌙' : '☀️';
    // Re-apply theme to all elements
    document.documentElement.style.setProperty('--theme', isLight ? 'light' : 'dark');
  };

  const header = $('header');
  if (header) {
    // Insert after h1
    const h1 = header.querySelector('h1');
    if (h1) {
      h1.after(toggle);
    } else {
      header.prepend(toggle);
    }
  }
}

// ---- Bulk Selection ----------------------------------------------------------------------

export function addBulkSelect(
  tableId: string, 
  onSelectionChange: (selected: Set<number>) => void
): Set<number> {
  const selected = new Set<number>();
  const table = $(`#${tableId}`);
  if (!table) return selected;

  // Add checkbox to header
  const headerRow = table.querySelector('thead tr');
  if (headerRow) {
    const th = document.createElement('th');
    th.style.width = '24px';
    th.style.minWidth = '24px';
    th.innerHTML = '<input type="checkbox" class="select-all" />';
    headerRow.insertBefore(th, headerRow.firstChild);
  }

  // Add checkboxes to rows
  const rows = table.querySelectorAll('tbody tr[data-id]');
  rows.forEach(row => {
    const td = document.createElement('td');
    td.style.width = '24px';
    td.style.minWidth = '24px';
    td.innerHTML = '<input type="checkbox" class="row-checkbox" />';
    row.insertBefore(td, row.firstChild);

    const checkbox = td.querySelector('input') as HTMLInputElement;
    checkbox.addEventListener('change', () => {
      const id = Number(row.dataset.id);
      if (checkbox.checked) {
        selected.add(id);
      } else {
        selected.delete(id);
      }
      onSelectionChange(selected);
      updateSelectAll();
    });
  });

  // Select all handler
  const selectAll = table.querySelector('.select-all') as HTMLInputElement;
  if (selectAll) {
    selectAll.addEventListener('change', () => {
      rows.forEach(row => {
        const checkbox = row.querySelector('.row-checkbox') as HTMLInputElement;
        if (checkbox) {
          checkbox.checked = selectAll.checked;
          const id = Number(row.dataset.id);
          if (selectAll.checked) {
            selected.add(id);
          } else {
            selected.delete(id);
          }
        }
      });
      onSelectionChange(selected);
    });
  }

  function updateSelectAll(): void {
    if (selectAll) {
      const allChecked = rows.length > 0 && selected.size === rows.length;
      const someChecked = selected.size > 0;
      selectAll.checked = allChecked;
      selectAll.indeterminate = someChecked && !allChecked;
    }
  }

  return selected;
}

// ---- Empty State Helper ----------------------------------------------------------------

export function renderEmptyState(
  message: string, 
  hint: string, 
  icon: string = '📭',
  cols: number = 1
): string {
  return `
    <tr>
      <td colspan="${cols}" class="empty-state">
        <div class="empty-icon">${icon}</div>
        <div class="empty-title">${esc(message)}</div>
        <div class="empty-hint">${esc(hint)}</div>
      </td>
    </tr>
  `;
}

// ---- Copy to Clipboard with Fallback ----------------------------------------------------

export async function copyText(text: string, what: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast(`Copied ${what}`, 'success');
    return;
  } catch {
    // fall through to the legacy path
  }
  
  // Legacy fallback
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("aria-hidden", "true");
  ta.style.position = "fixed";
  ta.style.top = "-1000px";
  ta.style.left = "-1000px";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  
  if (ok) {
    toast(`Copied ${what}`, 'success');
  } else {
    toast(`Could not copy ${what} - clipboard blocked`, 'error');
  }
}
