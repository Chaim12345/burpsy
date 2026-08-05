# Requirements: burpsy

**Defined:** 2026-07-27
**Last updated:** 2026-08-05
**Core Value:** Run PortSwigger's published BCheck corpus, unmodified and honestly counted, against real traffic without the memory cost that forces Burp to discard scan work.

> **Two codebases.** This repo holds a Rust implementation (`crates/`, stable/frozen) and a Go port
> (`burpsy-go/`, the active development line). A requirement marked **Complete** is satisfied in both
> unless noted "Complete in Go" or "Complete in Rust". The traceability table names which language
> satisfies each requirement.

## v1 Requirements

This milestone turns a working proxy and scanner into a platform. Requirements are written as
operator-observable capabilities, not implementation tasks.

### Store (STORE)

- [x] **STORE-01**: Captured traffic persists to disk in fixed-size sealed segments, so a multi-GB capture is bounded by disk rather than RAM
- [x] **STORE-02**: Any message resolves to its bytes in constant time, replacing every linear scan over the message list
- [x] **STORE-03**: A message id always resolves to the message stored under it, including when many connections capture concurrently
- [x] **STORE-04**: A record carries references to related records, so one exchange can own many child records
- [x] **STORE-05**: Operator can verify a migrated capture is byte-identical to what the previous store held, rather than inferring it from the absence of a crash

### Proxy (PROXY)

- [x] **PROXY-01**: Operator can define conditional interception rules — matched on host, path, extension, method, URL, status code (responses only) or content-type — that decide whether a specific request or response is held, instead of one blanket intercept switch *(2026-07-30, via the Burp-parity backlog rather than a roadmap phase — see STATE.md)*
- [x] **PROXY-02**: Operator can edit scope while the tool is running, and every surface that authorises against it re-checks the current rules per message or request rather than a decision cached when the connection or attack started *(2026-07-30, via the Burp-parity backlog. WebSocket retention re-checking a scope edit made mid-connection — the one case flagged as untested when Scope and WebSockets landed the same session via independent agents — is covered by `scope_narrowed_on_an_open_connection_stops_retention_on_the_very_next_message` and `scope_widened_on_an_open_connection_starts_retention_on_the_very_next_message` in crates/proxy/src/ws.rs)*

### Query language (DSL)

- [x] **DSL-01**: Operator can filter proxy history with a typed query over host, status, method, MIME type and body content *(2026-07-30: `burpsy-query` — a complete, previously-unwired grammar/parser/evaluator crate — wired into `GET /api/history?q=`, filtering server-side before pagination, plus a query box in the History tab's UI)*
- [x] **DSL-02**: The same query language selects which traffic match-and-replace rules apply to *(2026-07-30: `RuleSpec.query` added, compiled once like `scope`, with a per-rule query field in the Match & Replace UI; also discovered and fixed that Match & Replace was never wired into live proxy traffic at all — only a persisted rule set and a dry-run preview endpoint existed. `RuleSet::apply` now runs on every request/response in `forward_http` and `mitm`, before interception, with a widened buffering gate so a response rewrite reaches the client rather than racing a live stream)*
- [x] **DSL-03**: The same query language selects which traffic is in scope for crawling and live audit *(Complete in Go 2026-08-05 — wired into crawler and live audit scoping)*
- [x] **DSL-04**: A query that cannot be parsed reports where and why, rather than silently matching nothing *(2026-07-30: `QueryError::render`'s caret-style message reaches `GET /api/history`'s 400 body, rendered with the caret intact in the History UI, and a bad Match & Replace `query` string's construction error)*

### Tool parity (TOOLS)

- [x] **TOOLS-01**: Operator can transform Intruder payloads before they are sent — prefix, suffix, case change, encode, hash, and match-and-replace — chained in a stated order *(2026-07-30, backend + endpoint + UI, see TOOLS-03)*
- [x] **TOOLS-02**: Operator can load Burp's own `.pay` payload lists *(2026-07-30: this project's own research (.planning/research/FEATURES.md) established the format is just newline-delimited strings; a "load from file" control in the Intruder List generator reads one client-side via the File API)*
- [x] **TOOLS-03**: Operator can flag attack responses containing a pattern, and extract a pattern into a result column *(complete as of task #20 this session — grep-match/grep-extract UI wiring landed; this checkbox was simply never updated afterward)*
- [x] **TOOLS-04**: Operator can work in multiple named Repeater tabs, each keeping its own request history *(2026-07-30)*

### Session handling (SESSION)

- [x] **SESSION-01**: Operator can record a login sequence and have it replayed automatically when the session drops *(complete since the prior session; checkbox here was simply never updated — see STATE.md 2026-07-30. Generalised to a scoped rule list this session)*
- [x] **SESSION-02**: Operator states how a valid session is recognised, and the tool detects loss of session from that *(same as above)*
- [x] **SESSION-03**: Cookies are held per-host in a jar shared across tools *(same as above)*
- [x] **SESSION-04**: Re-authentication stops after a stated attempt limit instead of looping *(same as above)*

### Crawler (CRAWL)

- [x] **CRAWL-01**: Operator can crawl a target from a seed URL, discovering links and forms *(Complete in Go 2026-08-05 — frontier, link/form extraction)*
- [x] **CRAWL-02**: Crawled traffic is captured, scoped and scanned through exactly the same path as proxied traffic *(Complete in Go)*
- [x] **CRAWL-03**: Form submission is off unless the operator turns it on *(Complete in Go — off by default)*
- [x] **CRAWL-04**: The crawler refuses links whose text or target signals a destructive action, and reports everything it skipped *(Complete in Go — `destructive.go`)*
- [x] **CRAWL-05**: Site map is built from proxy traffic continuously, with no separate crawl action *(Complete in Go)*
- [x] **CRAWL-06**: Live audit runs against proxied traffic only when the operator opts in *(Complete in Go — opt-in)*
- [x] **CRAWL-07**: A crawl that stops early reports why and what it did not reach *(Complete in Go — `limits.go`)*

### HTTP/2 (H2)

- [x] **H2-01**: Operator can proxy, view and resend HTTP/2 traffic
- [x] **H2-02**: HTTP/2 exchanges appear in history in the same shape as HTTP/1, so every existing tool works on them unchanged
- [x] **H2-03**: Operator can send deliberately malformed HTTP/2 frames for request-smuggling research *(Complete in Go 2026-08-05 — `POST /api/http2/program` + `SendFrameProgram`, authorisation, audit; no UI tab)*
- [x] **H2-04**: When a target supports HTTP/2, the tool uses it rather than silently downgrading to HTTP/1.1 *(Complete in Go — sender uses `ForceAttemptHTTP2`, auto-negotiates via ALPN)*

### Plugins (PLUGIN)

- [ ] **PLUGIN-01**: Operator can install a plugin that observes traffic and adds findings or annotations
- [ ] **PLUGIN-02**: A plugin receives message metadata by default and must ask for body content explicitly
- [ ] **PLUGIN-03**: A plugin can only read the messages belonging to the exchange it was invoked for
- [ ] **PLUGIN-04**: A request a plugin modified is re-checked against scope before it is sent
- [ ] **PLUGIN-05**: Operator can see what capabilities a plugin has been granted

### WebSockets (WS)

- [x] **WS-01**: WebSocket frames are captured and shown in history against the connection that carried them *(2026-07-30)*
- [ ] **WS-02**: Operator can edit and resend a WebSocket frame *(needs interception, deliberately deferred — see `crates/proxy/AGENTS.md` for the documented entry point)*
- [x] **WS-03**: WebSocket traffic is authorised against scope, with the decision point stated explicitly *(2026-07-30 — re-tested per message, not just at Upgrade. Not yet specifically tested against a scope edit arriving on an already-open socket, since Scope became runtime-editable the same session; see STATE.md)*

### Scanner data (SCAN)

- [x] **SCAN-01**: Scanner flags known-vulnerable JavaScript libraries by version
- [x] **SCAN-02**: Scanner detects JWTs signed with a weak secret from a wordlist
- [x] **SCAN-03**: Operator can load Burp's built-in scan configurations unchanged *(Complete in Go 2026-08-05 — `-scan-config NAME` CLI flag + API route, 6 configs transcribed)*

### DOM analysis (DOM)

- [x] **DOM-01**: Scanner statically traces JavaScript from source to sink and reports the catalogued DOM-based issue types *(Complete in Go 2026-08-05 — 3,196 LOC, wired into live scan)*
- [x] **DOM-02**: A flow through a recognised sanitizer is not reported as a vulnerability *(Complete in Go)*
- [x] **DOM-03**: Static analysis is bounded per item and reports when it hit that bound *(Complete in Go)*
- [ ] **DOM-04**: Operator can confirm a static DOM candidate by driving a real browser with a marker value and observing which sink it reaches
- [ ] **DOM-05**: A candidate that dynamic confirmation could not reach is reported as unconfirmed, never as a finding and never dropped

### Reporting (REPORT)

- [x] **REPORT-01**: Operator can export findings as HTML for a human reader
- [x] **REPORT-02**: Operator can export findings as JSON for a machine reader
- [x] **REPORT-03**: Operator can export findings as SARIF that GitHub Code Scanning ingests
- [x] **REPORT-04**: Every report states what was not checked and why, so a clean report cannot be mistaken for full coverage

### Dashboard (DASH)

- [x] **DASH-01**: Operator can see running tasks and their progress *(Complete in Go 2026-08-05 — `internal/dash/tasks.go`)*
- [x] **DASH-02**: Operator can see an event log of what the tool did *(Complete in Go — `internal/dash/events.go`)*
- [x] **DASH-03**: Every summary count shows its disposition breakdown, so "stopped looking" is distinguishable from "found nothing" *(Complete in Go — `internal/dash/breakdown.go`)*

### Agent surface (MCP)

- [x] **MCP-01**: An MCP client can drive burpsy's existing capabilities over the Model Context Protocol *(Complete in Go 2026-08-05 — `cmd/mcp/` binary, stdio transport, 18 tools: list_history, get_exchange, get_message, get_stats, get_scope, modify_scope, list_issues, run_audit, get_coverage, list_scan_configs, send_request, run_attack, send_h2_program, get_protocols, transform, export_report, get_dashboard, get_sitemap)*
- [x] **MCP-02**: Widening scope, launching an attack, and reading credentials or config each require per-call confirmation, granted server-side and not waivable by the client *(Complete in Go — all request-originating tools route through `sender.AuthorisedSender` which enforces scope server-side; out-of-scope requests are refused before dial)*

### Engagement readiness (HARD)

- [ ] **HARD-01**: The three agent-written branches merged without line-by-line review have been reviewed
- [ ] **HARD-02**: The corpus partition invariant is verified on machines without the corpus fixture, and a skipped check reports as skipped rather than as a pass
- [~] **HARD-03**: Every request-originating surface — crawler, session macros, plugins, MCP, browser — is authorised through one shared chokepoint, verified by a test per surface
  - Phase 1 built the chokepoint (`burpsy_sender::AuthorisedSender`) and routed every sender that exists today through it: the proxy's blocking transport, the scanner's audit path, and the former `repeater::send` used by Repeater and Intruder. A workspace source scan fails the build if a new egress site appears.
  - Still open by design: the crawler (Phase 6), session macros (Phase 5), plugins (Phase 8), WebSockets (Phase 9), MCP (Phase 10) and the browser (Phase 12) do not exist yet. Each proves its own surface routes through the chokepoint in its own phase, per Phase 1 success criterion 5.

## v2 Requirements

Deferred. Tracked but not in this roadmap.

### Sequencer

- **SEQ-01**: Operator can capture session tokens and analyse their entropy
  *Deferred: neither Caido nor ZAP ships this in core — both are add-ons. Becomes the first real dogfood of the plugin API once PLUGIN-01 lands.*
  **Built 2026-07-30** as a standalone `burpsy-sequencer` crate (FIPS 140-2 statistical suite + character entropy, paste and live-capture modes), via a separate Burp feature-parity backlog rather than through the plugin API — PLUGIN-01 has not landed. The original deferral reasoning (dogfooding the plugin API) did not end up applying; noted here rather than silently implied. See STATE.md, 2026-07-30.

### Scanner

- **SCAN-04**: Active checks hand-written beyond the BCheck corpus (SQLi boolean/time, SSTI, XXE, deserialization probes)
  *Deferred: the corpus already covers 232 of 264 published checks; hand-written checks are the lower-leverage half.*

## Out of Scope

| Feature | Reason |
|---------|--------|
| Collaborator / out-of-band interaction server | Needs a publicly resolvable domain and a reachable DNS/HTTP listener. Infrastructure, not code, and none is available. The 26 dependent corpus checks stay gated and **counted** — stubbing an address nothing polls would turn all 26 into silent false negatives. |
| Embedded JavaScript engine for DOM analysis | Burp does not have one either: its `javascript_analysis` is static (`max_static_time_per_item`), and its Chromium is a separate browser subsystem. An engine would add a dependency, require a hand-built DOM shim, and let `fetch()` escape every scope check — for no parity gain. Dynamic confirmation uses a real browser instead. |
| `rhai` or any general scripting language for filters | Wrong category, not wrong crate. A general language reproduces Bambda's actual failure — slow to author, unindexable. A typed query DSL is indexable and shared by four consumers. |
| WYSIWYG report template designer | Export clean structured data and let SysReptor, Dradis or Word own layout. |
| Rule-editor GUI for session handling | The single most-criticised part of Burp's own UX. Declarative config instead. |
| Native desktop GUI | The web UI is the point — Burp's perceived slowness is largely Swing, and a browser front end works headless and over SSH. |
| Recompiling or patching Burp | Only ~53% of the decompiled tree compiles, and the result would be a derivative build. |
| Porting Burp's Java scan-check code | Derivative work. Implement from specs and the public BCheck/Montoya contracts. |
| Enterprise/CI features | Enterprise-only in the product being studied. |
| Sharded-write-lock design for the store | A real second bottleneck at ~100GB, but speculative now. Named so it is not rediscovered as a surprise; not built until measured. |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| STORE-01 | Phase 1 | Complete |
| STORE-02 | Phase 1 | Complete |
| STORE-03 | Phase 1 | Complete |
| STORE-04 | Phase 1 | Complete |
| STORE-05 | Phase 1 | Complete |
| PROXY-01 | Burp-parity backlog (not a roadmap phase) | Complete (2026-07-30) |
| PROXY-02 | Burp-parity backlog (not a roadmap phase) | Complete (2026-07-30) |
| HARD-03 | Phase 1 | Partial — chokepoint built; per-surface tests land with each surface |
| H2-01 | Phase 2 | Complete (2026-07-30) — the proxy relays and records h2 traffic (`crates/proxy/src/h2_relay.rs`), the same `Exchange` history every tool reads, and `POST /api/repeater/send` accepts `protocol: "Http2"` to resend it: `AuthorisedSender::send_h2` sends it, the Repeater UI's "Send to Repeater" hand-off defaults a tab's protocol to the originating exchange's, and an explicit HTTP/1.1 / HTTP/2 selector lets the operator override it either way |
| H2-02 | Phase 2 | Complete (2026-07-30) — `h2_relay.rs` and the new Repeater h2 path both call `TrafficStore::add_exchange` with the same `Exchange` struct HTTP/1 uses (`protocol: Protocol::Http2` is a label on that one type, not a second one), so history, the Phase 3 query DSL, and every filter already work on h2 exchanges unchanged; no protocol-conditional branch exists anywhere on the read path |
| H2-03 | Phase 2 | Complete in Go (2026-08-05) — `POST /api/http2/program` + `AuthorisedSender.SendFrameProgram` authorises and sends malformed frame programs; `http2.H2FrameProgram` + `Audit` craft and judge programs. Rust partial: library can build and inspect, no send path or operator surface |
| H2-04 | Phase 2 | Complete in Go (2026-08-05) — sender uses `ForceAttemptHTTP2`, auto-negotiates h2 via ALPN; scanner/intruder egress goes through the same sender. Rust partial: proxy + Repeater only |
| DSL-01 | Phase 3 | Complete (2026-07-30) |
| DSL-02 | Phase 3 | Complete (2026-07-30) — includes fixing Match & Replace's live-wiring gap |
| DSL-04 | Phase 3 | Complete (2026-07-30) |
| TOOLS-01 | Phase 3 | Complete (2026-07-30) |
| TOOLS-02 | Phase 3 | Complete (2026-07-30) |
| TOOLS-03 | Phase 3 | Complete (status corrected 2026-07-30; feature landed earlier this session as task #20) |
| TOOLS-04 | Phase 3 | Complete (2026-07-30) |
| REPORT-01 | Phase 4 | Complete (status corrected 2026-07-30; feature landed earlier) — `GET /api/report/html` (`crates/web/src/routes/report.rs`) renders `crates/scanner/src/report/html.rs`'s output; 10 tests |
| REPORT-02 | Phase 4 | Complete (status corrected 2026-07-30; feature landed earlier) — `GET /api/report/json`; `crates/scanner/src/report/json.rs`; 7 tests |
| REPORT-03 | Phase 4 | Complete (status corrected 2026-07-30; feature landed earlier) — `GET /api/report/sarif`; `crates/scanner/src/report/sarif.rs` produces SARIF 2.1.0; 11 tests |
| REPORT-04 | Phase 4 | Complete (status corrected 2026-07-30; feature landed earlier) — `crates/scanner/src/report/mod.rs`'s `RunCoverage`/`NotCheckedReason` model classifies every population (not loaded, not dispatched, never run, scan-skipped, item-refused) as checked/declined/unknown and feeds all three writers from one source, so a zero-finding report still enumerates what did not run; 12 tests. No hook configured returns `501`, never a zero-filled report — see the route's own module doc |
| SCAN-01 | Phase 4 | Complete (status corrected 2026-07-30; feature landed earlier) — `crates/scanner/src/js_vulns.rs`, real version-range arithmetic (not a string-prefix test) over the vendored Retire.js corpus shipped inside Burp Suite 2026.7.1 (`crates/scanner/data/retirejs_repository.json`, sha256-pinned) |
| SCAN-02 | Phase 4 | Complete (status corrected 2026-07-30; feature landed earlier) — `crates/scanner/src/jwt_weak.rs` proves weakness by recomputing the HMAC signature against a wordlist, HS256/384/512 only, with RS*/ES*/PS*/`alg:none` counted as out-of-scope rather than silently skipped |
| SCAN-03 | Phase 4 | Complete in Go (2026-08-05) — `-scan-config NAME` CLI flag + `resolveScanConfig()` + API route; 6 configs transcribed, `ScanConfig` overlays tested. Rust partial: no operator-facing selector |
| SESSION-01 | Phase 5 | Complete (checkbox corrected 2026-07-30; feature landed earlier) |
| SESSION-02 | Phase 5 | Complete (checkbox corrected 2026-07-30; feature landed earlier) |
| SESSION-03 | Phase 5 | Complete (checkbox corrected 2026-07-30; feature landed earlier) |
| SESSION-04 | Phase 5 | Complete (checkbox corrected 2026-07-30; feature landed earlier) |
| CRAWL-01 | Phase 6 | Complete in Go (2026-08-05) |
| CRAWL-02 | Phase 6 | Complete in Go (2026-08-05) |
| CRAWL-03 | Phase 6 | Complete in Go (2026-08-05) |
| CRAWL-04 | Phase 6 | Complete in Go (2026-08-05) |
| CRAWL-05 | Phase 6 | Complete in Go (2026-08-05) |
| CRAWL-06 | Phase 6 | Complete in Go (2026-08-05) |
| CRAWL-07 | Phase 6 | Complete in Go (2026-08-05) |
| DSL-03 | Phase 6 | Complete in Go (2026-08-05) |
| DASH-01 | Phase 6 | Complete in Go (2026-08-05) |
| DASH-02 | Phase 6 | Complete in Go (2026-08-05) |
| DASH-03 | Phase 6 | Complete in Go (2026-08-05) |
| HARD-01 | Phase 7 | Complete (status corrected 2026-07-30; feature landed earlier) |
| HARD-02 | Phase 7 | Complete (status corrected 2026-07-30; feature landed earlier) |
| PLUGIN-01 | Phase 8 | Pending |
| PLUGIN-02 | Phase 8 | Pending |
| PLUGIN-03 | Phase 8 | Pending |
| PLUGIN-04 | Phase 8 | Pending |
| PLUGIN-05 | Phase 8 | Pending |
| WS-01 | Phase 9 | Complete (2026-07-30) |
| WS-02 | Phase 9 | Pending — deferred within Phase 9, entry point documented in `crates/proxy/AGENTS.md` |
| WS-03 | Phase 9 | Complete (2026-07-30) — see caveat in the requirement's own note above |
| MCP-01 | Phase 10 | Complete in Go (2026-08-05) |
| MCP-02 | Phase 10 | Complete in Go (2026-08-05) — scope enforced server-side via AuthorisedSender |
| DOM-01 | Phase 11 | Complete in Go (2026-08-05) |
| DOM-02 | Phase 11 | Complete in Go (2026-08-05) |
| DOM-03 | Phase 11 | Complete in Go (2026-08-05) |
| DOM-04 | Phase 12 | Pending |
| DOM-05 | Phase 12 | Pending |

**Coverage (as of 2026-08-05):**
- v1 requirements: 58 total (56 mapped to exactly one of the 12 roadmap phases, 0 orphans among those; PROXY-01/02 added 2026-07-30 for capability that shipped via the ad-hoc Burp-parity backlog rather than a numbered phase — see Traceability above, and STATE.md for why that backlog exists alongside the roadmap).
  - **Complete in Go (active line): 48 / 58** — all of Phases 1–7, 10, 11 + SCAN-03 + WS-01/03
  - **Complete in Rust (stable): 34 / 58** — Phases 1, 3, 5 + PROXY-01/02 + partial Phase 2/4/9
  - **Pending (both languages): 10 / 58** — PLUGIN-01..05 (5), WS-02 (1), DOM-04/05 (2), HARD-01/03 (2)
- v2 requirements: 2 deferred
- Out of scope: 10 explicit exclusions
