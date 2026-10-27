// API client. The confirm gate (X-Burpsy-Confirm) is a human-intent signal:
// when the backend answers a gated call with a confirm challenge, we surface a
// dialog describing the exact call and only a human click mints the token.

export class ApiError extends Error {
  constructor(message, status, body) { super(message); this.status = status; this.body = body; }
}

export class ConfirmRequired {
  constructor(challenge, retry) {
    this.challenge = challenge; // {route, risk, expires_in, ...}
    this.retry = retry;         // (token) => Promise<result>
  }
}

async function rawCall(method, url, body, extraHeaders = {}) {
  const init = { method, headers: { ...extraHeaders } };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const res = await fetch(url, init);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (data && data.confirm_with === 'X-Burpsy-Confirm') {
    throw new ConfirmRequired(data, async (token) => {
      const res2 = await fetch(url, { ...init, headers: { ...init.headers, 'X-Burpsy-Confirm': token } });
      const text2 = await res2.text();
      let data2 = null;
      try { data2 = text2 ? JSON.parse(text2) : null; } catch { data2 = { raw: text2 }; }
      if (!res2.ok) throw new ApiError(data2?.error || res2.statusText, res2.status, data2);
      return data2;
    });
  }
  if (!res.ok) throw new ApiError(data?.error || (typeof data?.raw === 'string' && data.raw.trim()) || res.statusText || 'request failed', res.status, data);
  return data;
}

// Mint a one-time confirm token for an exact call. Called only from the
// confirmation dialog's human click handler.
export async function mintConfirm(route, method, url, body) {
  const res = await fetch(`${route.replace(/\/+$/, '')}/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method, url, body: body === undefined ? '' : (typeof body === 'string' ? body : JSON.stringify(body)) }),
  });
  const data = await res.json();
  if (!res.ok || !data.token) throw new ApiError(data?.error || 'confirm failed', res.status, data);
  return data;
}

export const api = {
  get: (url) => rawCall('GET', url),
  post: (url, body) => rawCall('POST', url, body ?? {}),
  patch: (url, body) => rawCall('PATCH', url, body ?? {}),
  del: (url) => rawCall('DELETE', url),
};

export function fmtTime(ms) {
  if (!ms) return '';
  const d = new Date(ms);
  return d.toLocaleTimeString(undefined, { hour12: false });
}
export function fmtBytes(n) {
  if (n == null) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
