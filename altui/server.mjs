#!/usr/bin/env node
// altui dev server: static files + same-origin /api proxy to a burpsy backend.
//
// Security contract (deliberate, do not relax without an operator decision):
//  - Binds 127.0.0.1 only. This console is a local operator tool; exposing it on
//    a LAN would expose the backend's full API, including gated routes, to anyone
//    who can reach the port. The confirm gate is not an auth system.
//  - Adds NO CORS headers. The SPA is same-origin, so none are needed; adding
//    Access-Control-Allow-Origin would invite cross-site callers.
//  - Never mints confirm tokens. The X-Burpsy-Confirm flow is a human-intent
//    signal; the proxy forwards calls and 428s verbatim and the SPA asks the
//    human. Auto-minting here would silently bypass the gate.
//  - Does not strip or rewrite Origin / Sec-Fetch-* / Cookie headers; it passes
//    the browser's call through and removes only hop-by-hop framing headers.
//
// Env: ALTUI_PORT (default 3817), BURPSY_BACKEND (default http://127.0.0.1:28081).

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = Number(process.env.ALTUI_PORT || 3817);
const BACKEND = new URL(process.env.BURPSY_BACKEND || 'http://127.0.0.1:28081');
const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
]);

function serveStatic(req, res) {
  let p;
  try {
    p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'malformed URL' }));
    return;
  }
  if (p === '/') p = '/index.html';
  const file = normalize(join(ROOT, p));
  if (!file.startsWith(ROOT)) { res.writeHead(403); res.end(); return; }
  readFile(file).then((data) => {
    res.writeHead(200, {
      'Content-Type': MIME[extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    res.end(data);
  }).catch(() => { res.writeHead(404); res.end('not found'); });
}

function proxy(req, res) {
  const url = new URL(req.url, BACKEND);
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) headers[k] = v;
  }
  // Same-origin semantics, preserved not bypassed: the backend (api_sameorigin.go)
  // demands Origin == Host on mutations so a foreign web page cannot drive the API.
  // This proxy is the console's origin, so a call is legitimate only when it came
  // from this console - Origin present and equal to OUR authority. We then rewrite
  // Origin to the backend authority so the pair matches there. A foreign Origin is
  // refused here rather than laundered; an absent Origin (curl, non-browser) passes
  // through untouched exactly as it would hitting the backend directly.
  // Fixed allowlist of loopback origins for THIS console's configured port -
  // never derived from the request's Host header, which an attacker controls.
  const myOrigins = new Set([
    `http://127.0.0.1:${PORT}`,
    `http://localhost:${PORT}`,
    `http://[::1]:${PORT}`,
  ]);
  if (headers.origin !== undefined) {
    if (!myOrigins.has(headers.origin)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'cross-origin call refused by altui proxy' }));
      return;
    }
    headers.origin = BACKEND.origin;
  }
  headers.host = BACKEND.host;
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    const upstream = http.request(url, { method: req.method, headers }, (up) => {
      const out = {};
      for (const [k, v] of Object.entries(up.headers)) {
        if (!HOP_BY_HOP.has(k.toLowerCase())) out[k] = v;
      }
      res.writeHead(up.statusCode, out);
      up.pipe(res);
    });
    upstream.on('error', (e) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `backend unreachable: ${e.message}`, backend: BACKEND.origin }));
    });
    if (body) upstream.write(body);
    upstream.end();
  });
}

// Inbound Host gate, mirroring the backend's api_sameorigin.go rule (loopback
// authority, any port). Without it the proxy answers a browser that reached it
// via DNS rebinding (Host: attacker.example -> 127.0.0.1) and launders that
// call's provenance when rewriting Host for the backend. Reads are gated here
// too, not just mutations: a rebound page must not read API responses either.
const LOOPBACK_HOST = /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/i;
function hostAllowed(req) {
  const h = req.headers.host;
  return typeof h === 'string' && LOOPBACK_HOST.test(h.trim());
}

http.createServer((req, res) => {
  if (!hostAllowed(req)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'refused: non-loopback Host (DNS rebinding guard)' }));
    return;
  }
  if (req.url.startsWith('/api/') || req.url === '/api' || req.url.startsWith('/reissue/')) proxy(req, res);
  else serveStatic(req, res);
}).listen(PORT, '127.0.0.1', () => {
  console.log(`altui on http://127.0.0.1:${PORT}  (backend ${BACKEND.origin}, loopback only)`);
});
