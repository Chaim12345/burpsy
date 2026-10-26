#!/usr/bin/env node
// Explicit proxy security-boundary tests. Run: node altui/test-proxy.mjs
// Spawns the proxy on a scratch port against a stub backend and asserts the
// authority/provenance rules a caller can actually observe.
import { spawn } from 'node:child_process';
import http from 'node:http';

const PROXY_PORT = 38917;
const BACKEND_PORT = 38918;
const MY_ORIGIN = `http://127.0.0.1:${PROXY_PORT}`;

let failed = 0;
function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  (' + extra + ')' : ''}`);
  if (!cond) failed++;
}

// stub backend records what it received
let lastSeen = null;
const backend = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    lastSeen = { host: req.headers.host, origin: req.headers.origin, method: req.method, url: req.url };
    if (req.url.startsWith('/api/events')) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'X-Accel-Buffering': 'no' });
      res.write('data: {"kind":"hello"}\n\n');
      setTimeout(() => res.end('data: {"kind":"ping"}\n\n'), 150);
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  });
});
await new Promise((r) => backend.listen(BACKEND_PORT, '127.0.0.1', r));

const child = spawn('node', [new URL('./server.mjs', import.meta.url).pathname], {
  env: { ...process.env, ALTUI_PORT: String(PROXY_PORT), BURPSY_BACKEND: `http://127.0.0.1:${BACKEND_PORT}` },
  stdio: 'ignore',
});
await new Promise((r) => setTimeout(r, 700));

function call({ host, origin, method = 'GET', path = '/api/stats' }) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (host) headers.host = host;
    if (origin) headers.origin = origin;
    const req = http.request({ host: '127.0.0.1', port: PROXY_PORT, path, method, headers }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

// 1. loopback Host: allowed
let r = await call({ host: `127.0.0.1:${PROXY_PORT}` });
check('loopback Host allowed', r.status === 200);
// 2. localhost Host: allowed
r = await call({ host: `localhost:${PROXY_PORT}` });
check('localhost Host allowed', r.status === 200);
// 3. foreign Host (rebinding): refused, backend NOT hit
lastSeen = null;
r = await call({ host: 'evil.example.com' });
check('foreign Host refused (rebinding guard)', r.status === 403 && lastSeen === null);
// 4. foreign Host on static path: refused too (reads gated)
r = await call({ host: 'evil.example.com', path: '/' });
check('foreign Host refused on static', r.status === 403);
// 5. own Origin on mutation: rewritten to backend authority
lastSeen = null;
r = await call({ host: `127.0.0.1:${PROXY_PORT}`, origin: MY_ORIGIN, method: 'POST', path: '/api/repeater/send' });
check('own Origin rewritten to backend authority', r.status === 200 && lastSeen?.origin === `http://127.0.0.1:${BACKEND_PORT}`, `backend saw origin=${lastSeen?.origin}`);
// 6. foreign Origin: refused by proxy, backend NOT hit
lastSeen = null;
r = await call({ host: `127.0.0.1:${PROXY_PORT}`, origin: 'http://evil.example.com', method: 'POST', path: '/api/repeater/send' });
check('foreign Origin refused', r.status === 403 && lastSeen === null);
// 7. absent Origin (curl-style): passed through untouched
lastSeen = null;
r = await call({ host: `127.0.0.1:${PROXY_PORT}`, method: 'POST', path: '/api/repeater/send' });
check('absent Origin passed through (no provenance invented)', r.status === 200 && lastSeen?.origin === undefined);
// 8. no CORS headers ever
check('no CORS headers added', r.headers['access-control-allow-origin'] === undefined);
// 9. SSE streams (first frame arrives before response end)
const sse = await new Promise((resolve) => {
  const t0 = Date.now();
  const req = http.get({ host: '127.0.0.1', port: PROXY_PORT, path: '/api/events', headers: { host: `127.0.0.1:${PROXY_PORT}` } }, (res) => {
    res.once('data', (chunk) => { resolve({ firstAt: Date.now() - t0, chunk: String(chunk) }); req.destroy(); });
  });
});
check('SSE first frame streams unbuffered', sse.firstAt < 400 && sse.chunk.includes('hello'), `${sse.firstAt}ms`);

child.kill();
backend.close();
console.log(failed ? `\n${failed} FAILURES` : '\nall pass');
process.exit(failed ? 1 : 0);
