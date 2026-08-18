// Serves the committed UI bundle + a stub JSON API so the bundle can be smoke-tested
// without the Go binary. Run: node ui-stub.mjs
import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const uiDir = join(here, "burpsy-go", "internal", "web", "ui");

const json = (res, body, status = 200) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};

const routes = {
  "/api/stats": { stored_bytes: 12345, exchanges: 5, messages: 9, passive_checks: 0, active_checks: 0, findings: 0 },
  "/api/scope": { allow_all: true, rules: [] },
  "/api/dashboard": {
    exchanges: 5, messages: 9, stored_bytes: 12345, tasks_running: 0, tasks: [],
    summaries: [{ label: "passive checks", unit: "checks", work_unit: "checks",
      breakdown: { found: 0, skipped: 0, errored: 0, gated: 0, unaccounted: 0, complete: true } }],
    sources: { proxy: 5 }, activity: [], events: [],
  },
  "/api/issues": { issues: [], count: 0 },
  "/api/sitemap": { hosts: {} },
  "/api/intercept": { enabled: false, queue: [] },
  "/api/tools/organizer": { items: [] },
  "/api/tools/rules": { rules: [] },
  "/api/session/rules": { rules: [] },
  "/api/tools/log": { rows: [], count: 0 },
  "/api/ws/connections": [],
  "/api/crawl": { id: "c1", status: "done", progress: 100, result: { pages: 3 } },
  "/api/events/stats": { pending: 0, last_at_ms: 0 },
  "/api/http2/program": { ok: true },
  "/api/intruder/points": { points: [] },
  "/api/intruder/run": { ok: true },
  "/api/protocols": { http1: true, http2: true },
  "/api/repeater/send": { status: 200, duration_ms: 12, exchange_id: 0, response: "HTTP/1.1 200 OK\r\n\r\nOK" },
  "/api/scanner/configs": { configs: [] },
  "/api/scanner/coverage": { summary: {} },
  "/api/scanner/live": { active: false },
  "/api/sequencer/analyse": { result: "ok" },
  "/api/sequencer/capture": { started: true },
  "/api/sequencer/capture/stop": { stopped: true },
  "/api/session/cookies": { cookies: [] },
  "/api/session/login": { ok: true },
  "/api/tools/compare": { ok: true },
  "/api/tools/decode": { output: "decoded" },
  "/api/tools/encode": { output: "encoded" },
  "/api/tools/hash": { hash: "abc" },
  "/api/tools/rules/test": { ok: true },
  "/api/exchange/0": { id: 0, request: 0, response: 1, host: "127.0.0.1", port: 18299, tls: false, method: "GET", path: "/alpha", status: 200, duration_us: 1200, source: "proxy" },
  "/api/message/0": { id: 0, exchange: 0, direction: "request", host: "127.0.0.1", port: 18299, tls: false, method: "GET", path: "/alpha", headers: [["Host", "127.0.0.1:18299"]], body: "GET /alpha HTTP/1.1\r\nHost: 127.0.0.1:18299\r\n\r\n" },
  "/api/message/1": { id: 1, exchange: 0, direction: "response", host: "127.0.0.1", port: 18299, tls: false, method: "GET", path: "/alpha", headers: [], body: "HTTP/1.1 200 OK\r\n\r\nORIGIN-OK GET /alpha" },
  "/api/history": { rows: [], count: 0 },
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname in routes) return json(res, routes[url.pathname]);
  if (url.pathname === "/api/events") {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write("event: hello\ndata: {}\n\n");
    return;
  }
  if (url.pathname === "/ca.crt") return res.writeHead(404) && res.end("not found");
  if (url.pathname === "/" || url.pathname === "") {
    const index = readFileSync(join(uiDir, "index.html"), "utf8");
    res.writeHead(200, { "content-type": "text/html" });
    res.end(index);
    return;
  }
  const file = join(uiDir, url.pathname);
  if (existsSync(file)) {
    const ext = url.pathname.endsWith(".js") ? "text/javascript" : url.pathname.endsWith(".css") ? "text/css" : "application/octet-stream";
    res.writeHead(200, { "content-type": ext });
    res.end(readFileSync(file));
    return;
  }
  res.writeHead(404);
  res.end("not found: " + url.pathname);
});

server.listen(18282, "127.0.0.1", () => console.log("stub UI server on 127.0.0.1:18282"));