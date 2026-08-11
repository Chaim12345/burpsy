# burpsy-go — JSON API reference

The JSON API is the surface both the web UI and any script or agent uses to
drive burpsy. It is served on the `-web` address (default `127.0.0.1:8081`,
loopback-only). This reference is derived from the route registrations in
`internal/web/server.go` (`setupRoutes`) and the canonical route manifest in
`internal/web/route_manifest_test.go` — not guessed. If a route here disagrees
with the code, the code wins and the doc is a defect; please file it back.

> **Authorized use only.** Several routes send traffic to the engagement target
> or change what the engagement is allowed to touch. Only drive them against
> targets you are authorized to test.

## Conventions

- Base URL: `http://<web-addr>` (default `http://127.0.0.1:8081`).
- Trailing-slash routes (e.g. `/api/audit/`) are subtree patterns: you call a
  concrete path under them, e.g. `POST /api/audit/0`.
- Sending a verb a route does not implement returns **405**; a well-formed route
  with a bad path segment returns **404**.
- `GET /api/findings` and `GET /api/exchanges/` are **legacy aliases** kept so
  the original Rust-era UI keeps working; prefer `/api/issues` and
  `/api/exchange/`.

## Risk classes

Every route carries a risk class (declared in the manifest). These matter when a
**model or script** drives the API unattended rather than a human clicking:
higher classes are the ones a future confirmation gate (MCP-02, see
[MCP.md](./MCP.md)) will require a human to approve.

| Class | Meaning |
|---|---|
| `read` | Reads state, sends nothing outbound. |
| `local-write` | Mutates burpsy's own state (annotations, rules, settings); sends no traffic. |
| `egress` | Sends **bounded** traffic to the target — one request or a handful. |
| `attack` | Sends **unbounded** traffic — an attack, audit, crawl or capture. Miscounting here can be a DoS against a client system. |
| `scope` | Changes what the engagement may touch. |
| `credential` | Reads or replays credentials (cookie jar, session macros). Output is secret. |
| `destructive` | Irreversibly discards evidence. |
| `asset` | Serves a static asset (UI, CA certificate). |

---

## Capture, history & stats

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/history` | read | Proxy history, filtered by the typed query DSL. |
| GET | `/api/message/{id}` | read | Raw bytes of one stored message, with pretty and hex views. |
| GET | `/api/exchange/{id}` | read | One exchange row by id. |
| GET | `/api/exchanges/{id}` | read | Legacy alias for `/api/exchange/`. |
| GET | `/api/stats` | read | Exchange, message and stored-byte counts. |
| GET | `/api/sitemap` | read | The site map as a tree, with per-subtree exchange counts. |
| GET | `/api/dashboard` | read | Running tasks, the activity log, and every coverage summary with its found/skipped/errored/gated breakdown. |

## Findings & reporting

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/issues` | read | Findings, with the catalogue advisory each resolved to. |
| GET | `/api/findings` | read | Legacy alias for `/api/issues`. |
| GET | `/api/report/{json\|sarif\|html}` | read | Export findings as JSON, SARIF or HTML. |

## Scope

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET, POST | `/api/scope` | scope | The engagement scope: what every sender is allowed to reach. GET reads it, POST replaces it. |

## Scanner (passive coverage, audits, configs)

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/scanner/coverage` | read | What the check set covers, and what it declines to look at. |
| GET | `/api/scanner/configs` | read | The built-in scan configurations. |
| GET, POST | `/api/scanner/live` | attack | The live sweep over newly-completed proxied traffic; POST opts in. |
| POST | `/api/audit/{id}` | attack | Run an active audit over one captured exchange, by id (`0` is a valid id). |
| POST | `/api/scanner/audit` | attack | Legacy alias for `/api/audit/{id}`, taking the id in the body. |

## Repeater & raw send

| Method | Path | Risk | Summary |
|---|---|---|---|
| POST | `/api/repeater/send` | egress | Send one operator-authored request and record the exchange. |
| GET | `/api/protocols` | read | Per-surface HTTP/1.1 vs HTTP/2 counts, and why a send was downgraded. |
| POST | `/api/http2/program` | egress | Send a raw HTTP/2 frame program: the pseudo-header and frame-level surface. |

## Intruder

| Method | Path | Risk | Summary |
|---|---|---|---|
| POST | `/api/intruder/points` | read | Enumerate insertion points in a stored request; sends nothing. |
| POST | `/api/intruder/run` | attack | Run an intruder attack: payloads spliced into one insertion-point set. |

## Interception

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/intercept` | read | Interception state: enabled, wired, and what is currently held. |
| POST | `/api/intercept/enable` | local-write | Turn interception on or off. |
| GET, PUT | `/api/intercept/rules/{requests\|responses}` | local-write | The match rules deciding which messages are held, per direction. |
| POST | `/api/intercept/{id}` | local-write | Resolve one held message: forward, drop, or forward edited bytes. |

## Site map & crawl

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/sitemap` | read | The site map tree (also listed above). |
| GET, POST | `/api/crawl` | attack | GET: the last crawl's coverage report. POST: crawl from a seed URL under stated bounds. |

## Change events (SSE)

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/events` | read | SSE change stream; the UI refetches on a frame rather than polling. |
| GET | `/api/events/stats` | read | The stream's own counters: frames sent, subscribers, coalesced signals. |

## Sequencer

| Method | Path | Risk | Summary |
|---|---|---|---|
| POST | `/api/sequencer/analyse` | read | Statistical analysis of a token sample; sends nothing. |
| POST | `/api/sequencer/capture` | attack | Start a capture: N sends of one request, one token extracted per response. |
| GET, POST | `/api/sequencer/capture/{id}` | read | GET `{id}`: one capture's accumulated tokens. POST `stop`: cancel a running capture. |

## Session handling (credentials)

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/session/cookies` | credential | The coordinator's cookie jar, per authority. |
| POST | `/api/session/login` | credential | Run a login macro, or probe whether the current session is still valid. |
| GET, POST | `/api/session/rules` | credential | Session handling rules: which hosts get re-authenticated, and how. |
| PUT, DELETE | `/api/session/rules/{id}` | credential | One session rule by id: PUT replaces it (incl. macro promotion), DELETE removes it. |

## Supporting tools

| Method | Path | Risk | Summary |
|---|---|---|---|
| POST | `/api/tools/decode` | read | Run one decode layer over a buffer, reporting whether it was partial. |
| POST | `/api/tools/encode` | read | Run one encode layer over a buffer. |
| POST | `/api/tools/hash` | read | Hash a buffer under a named algorithm. |
| POST | `/api/tools/compare` | read | Diff two messages or two pasted buffers. |
| GET, POST | `/api/tools/organizer` | local-write | The organizer's saved items. |
| POST, DELETE | `/api/tools/organizer/{id}` | local-write | One organizer item: POST updates title/note/highlight, DELETE removes it. |
| GET, PUT | `/api/tools/rules` | local-write | Match & Replace rule set (PUT replaces the whole ordered set). |
| POST | `/api/tools/rules/test` | read | Test a Match & Replace rule against a sample. |
| GET, DELETE | `/api/tools/log` | **destructive** | GET: every request this process sent, per tool, with what it dropped at the bound. DELETE: **clears it**, discarding the record of what was sent to the target. |

## WebSocket capture

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/ws/connections` | read | WebSocket connections observed. |
| GET | `/api/ws/history` | read | WebSocket frame history (filterable by exchange). |
| GET | `/api/ws/message/{id}` | read | One captured WebSocket frame. |

> WebSocket **frames are captured and relayed** in both directions. Interception
> and edit-and-resend of WS frames (WS-02) is not yet shipped — an empty WS
> history means "no WebSocket traffic yet", not "unimplemented".

## Static assets

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/` | asset | The operator console (SPA): `index.html`, `app.js`, `style.css`, catch-all. |
| GET | `/ca.crt` | asset | The interception CA public certificate (see the [Quickstart](./QUICKSTART.md#6-intercept-https-tls-mitm); 404 until a CA exists). |

---

## Quick examples

```bash
WEB=http://127.0.0.1:8081

# Read state
curl -s "$WEB/api/stats"
curl -s "$WEB/api/history"
curl -s "$WEB/api/scanner/coverage"

# Set an authorized scope
curl -s -X POST "$WEB/api/scope" -H 'content-type: application/json' \
  -d '{"include":["example.com"],"exclude":["logout.example.com"]}'

# Export findings
curl -s "$WEB/api/report/json"  -o findings.json
curl -s "$WEB/api/report/sarif" -o findings.sarif
curl -s "$WEB/api/report/html"  -o findings.html
```

> The exact request/response body shape for each route is defined by its handler
> in `internal/web/api_*.go`. This reference pins the route surface (path,
> methods, risk); when you script a specific `POST` body, confirm the fields
> against the handler or its `*_test.go` before relying on them.
