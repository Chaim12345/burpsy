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

## Who may call this API (burpsy-react-ui-s19k)

**There is no authentication and no token.** The console binds to `127.0.0.1` by
default, and that is the *whole* of the access control. What the server does
instead is refuse any **mutating** request — `POST`, `PUT`, `PATCH`, `DELETE` —
that did not come from the console's own page:

| Check | Refuses | Forgeable by page script? |
|---|---|---|
| `Host` must be loopback | DNS rebinding to `127.0.0.1` | no — the browser sends the real name |
| `Sec-Fetch-Site` must be `same-origin`/`same-site`/`none` | ordinary CSRF | no — set by the browser |
| `Origin`, when present, must match `Host` | CSRF in older browsers | no |

`GET` is not gated: a cross-origin `GET` cannot change server state, and gating
it would break the CA certificate download and every page reload.

Three consequences worth stating plainly:

- **A non-loopback bind (`-web 0.0.0.0:8081`) needs the host named**, or the
  console refuses the operator's own browser along with everything else. Name it
  with `WithAllowedHosts` (the `-web` flag's caller). With no name configured only
  loopback is accepted, which is the safe default and the one that stops rebinding.
- **Anyone who can reach a non-loopback bind can still READ the console** — history,
  cookies, session material, findings. The gate stops browser-driven attacks; it is
  not authentication, and it is not a substitute for it. If you bind off this
  machine, put it behind something that authenticates.
- **A non-browser client is unaffected.** Anything that can open a TCP connection
  can drive the API; `Sec-Fetch-Site` and `Origin` are browser-supplied. That is
  the intended shape — your scripts are the operator.

Implementation: `internal/web/api_sameorigin.go`. It is installed over the
finished mux in `setupRoutes`, not in `ListenAndServe`, so a route added later
cannot be registered outside it and no new handler's author has to remember
anything.

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
| GET | `/api/message/{id}` | read | Raw bytes of one stored message, with pretty and hex views. With any of `byte_offset`, `max_bytes` (1–65536, default 2048), `pattern` (RE2; anchors the window at the first match, `byte_offset` then relative to it), `case_insensitive`, `decoded`: a **window** of the body instead — `head` in full, `window_base64` (exact) and `window_text` (+ `window_utf8`), `next_offset` (null at the end), `anchor`, `matches` (≤100, always an array). Reads a body of any size to its last byte. |
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
| GET, POST | `/api/scope/check` | read | Is a URL in scope? `GET ?url=` or `POST {"urls":[…]}` (≤1000) answers per URL `in_scope` (retained, and sendable by the tools), `proxy_forwards`, the `reason`, and the `matched_rule` that decided (null when none did). Decided by `core.Scope.Decide`, which a test holds to `Contains`' answer. |

## Scanner (passive coverage, audits, configs)

| Method | Path | Risk | Summary |
|---|---|---|---|
| GET | `/api/scanner/coverage` | read | What the check set covers, and what it declines to look at. |
| GET | `/api/scanner/configs` | read | The built-in scan configurations. |
| GET, POST | `/api/scanner/live` | attack | The live sweep over newly-completed proxied traffic; POST opts in. |
| POST | `/api/audit/{id}` | attack | Run an active audit over one captured exchange, by id (`0` is a valid id). |
| POST | `/api/audit/selected` | attack | Run one active audit over a selection: `{"exchange_ids":[1,2,3]}` (plus optional `config`, `pool`). Answers **202** with `{task_id, kind, count, exchange_ids, duplicates_dropped, target, config_name, unapplied, pool}` rather than with the outcome — a selection has no bound on its size, so the work is followed through the task row. Refuses an empty selection (400) and an unknown configuration or pool. |
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
| POST | `/api/sitemap/record` | local-write | Record a captured exchange into the map by id (`{"exchange_id":N}`) — Burp's add_to_sitemap. The map follows the store, so the answer is either `already_on_map` or `was_suppressed` (a Delete host/branch/item hid it; the exchange is now pinned onto the map until a later suppression covers it). |
| GET, POST | `/api/crawl` | attack | GET: the last crawl's coverage report, or one run by `?task=N`. POST: crawl from a seed URL under stated bounds. |
| POST | `/api/apiscan` | attack | Start an API-only scan — Burp's fourth scan kind. Body `{definition, base_url?, audit?, max_requests?, pool?, requests_per_second?, user_agent?, headers?}`, where `definition` is an OpenAPI 3.x or Swagger 2.0 document as text (JSON or YAML). Answers **202** with `{task_id, state, kind:"api-scan", audit, definition:{...}}`; the endpoints are sent by the crawl engine in seeds-only mode and `report.seeds_only` is `true` on the retained run. `dry_run: true` instead answers **200** with `{dry_run:true, definition}` and starts nothing — the New scan dialog's preview. Refusals are 400 and name what the document actually is (AsyncAPI, Postman, Swagger 1.x, RAML); a document naming no host is a 400 asking for `base_url`; a host no scope rule can reach is a 400 quoting the scope's own explanation. |

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
| GET, PUT | `/api/tools/rules` | local-write | Match & Replace rule set (PUT replaces the whole ordered set). Carries the two set-wide switches, `update_content_length` and Burp's `in_scope_only` ("Only apply to in-scope items"); GET also reports `scope_skipped`, how many messages the restriction turned away. A rule carrying a per-rule `scope` or `query` is refused with a 400 — Burp's rule model has neither, and dropping the condition on save would silently widen what the rule touches. |
| POST | `/api/tools/rules/test` | read | Test a Match & Replace rule against a sample. Refuses the same unrepresentable rule fields the live path refuses. |
| POST | `/api/collaborator/poll` | read | Re-read the out-of-band interaction log. An empty body answers the channel status, as always. `{"payload_ids":[…],"wait_seconds":N,"min_interactions":M}` filters to those payloads (address or marker, any case; an id this process never minted is a 400) and long-polls up to 60 s until `min_interactions` (default 1) attributable interactions are in the log. The reply adds a `poll` block: `status` complete / timeout / empty / unavailable, `received`, `distinct`, `waited_ms` and the index rows (always an array). |
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
