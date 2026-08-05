export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Go handlers answer with either a bare string or {"error": "..."}; show whichever we get. */
function readFailure(text: string, fallback: string): string {
  const trimmed = text.trim();
  if (!trimmed) return fallback;
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as { error?: unknown; message?: unknown };
      const detail = parsed.error ?? parsed.message;
      if (typeof detail === "string" && detail) return detail;
    } catch {
      return trimmed;
    }
  }
  return trimmed;
}

export async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body !== undefined && !headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await fetch(url, { ...init, headers });
  const text = await response.text();
  if (!response.ok) throw new ApiError(readFailure(text, response.statusText), response.status, text);
  if (!text) return null as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError("response was not JSON", response.status, text);
  }
}

export function json(method: string, body?: unknown): RequestInit {
  return { method, body: body === undefined ? undefined : JSON.stringify(body) };
}

export function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value)) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1073741824) return `${(value / 1048576).toFixed(2)} MB`;
  return `${(value / 1073741824).toFixed(2)} GB`;
}

export function formatCount(value: number | undefined | null): string {
  return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString() : "—";
}

export function formatDuration(ms: number | undefined | null): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  const minutes = Math.floor(ms / 60000);
  return `${minutes}m ${Math.round((ms % 60000) / 1000)}s`;
}

export function relativeTime(atMs: number, now = Date.now()): string {
  if (!Number.isFinite(atMs) || atMs <= 0) return "—";
  const seconds = Math.max(0, Math.round((now - atMs) / 1000));
  if (seconds < 1) return "now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

export function absoluteTime(atMs: number): string {
  if (!Number.isFinite(atMs) || atMs <= 0) return "unknown";
  return new Date(atMs).toLocaleString();
}

/** Coarse family of an HTTP status, used for colour and filter buckets. */
export function statusTone(status: number | null | undefined): "neutral" | "good" | "info" | "warn" | "bad" {
  if (status === null || status === undefined) return "neutral";
  if (status >= 500) return "bad";
  if (status >= 400) return "warn";
  if (status >= 300) return "info";
  if (status >= 200) return "good";
  return "neutral";
}

export async function copyToClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Clipboard API needs a secure context; fall back to a detached textarea.
    const scratch = document.createElement("textarea");
    scratch.value = text;
    scratch.setAttribute("readonly", "");
    scratch.style.position = "fixed";
    scratch.style.opacity = "0";
    document.body.appendChild(scratch);
    scratch.select();
    document.execCommand("copy");
    document.body.removeChild(scratch);
  }
}

export function downloadText(filename: string, text: string, type = "text/plain"): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

/** Build a minimal raw HTTP/1.1 request for a target, used when seeding Repeater by hand. */
export function templateRequest(host: string, path = "/"): string {
  return [`GET ${path} HTTP/1.1`, `Host: ${host}`, "Accept: */*", "", ""].join("\r\n");
}

/** Pull the authority out of a raw request's Host header so Repeater can prefill a target. */
export function authorityFromRaw(raw: string, fallbackProtocol = "https"): string {
  const match = /^host:[ \t]*(.+)$/im.exec(raw);
  const host = match?.[1]?.trim();
  if (!host) return "";
  return host.includes("://") ? host : `${fallbackProtocol}://${host}`;
}
