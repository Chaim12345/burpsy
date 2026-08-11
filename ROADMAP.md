# burpsy roadmap — from here to Burp parity

Feature inventory taken from the Burp 2026.7.1 teardown, not from marketing pages: the 21
`MontoyaApi` subsystems, the tool-tab modules keyed on `burp.Zgdx`, the scanner's 7 check-dispatch
scopes / 8 insertion-point types / 5 scan phases / 183 `burp.Zcot` issue types, and the shipped data
resources (`KnowledgeBase/Issues`, `BuiltInConfigs`, `PayloadStrings`, `RetireJS`).

## What "Montoya coverage" means here, and what it does not

`MontoyaApi` is used throughout this document as the **feature inventory** — it is the most complete
public enumeration of what Burp can do, and counting its methods per subsystem is how the size of each
area is estimated. It is not an interface being implemented.

Stated once, plainly, because leaving it implied invites the wrong expectation:

- **No Montoya jar will ever load into burpsy.** There is no JVM, and nothing here is binary- or
  source-compatible with `MontoyaApi`. A Burp extension cannot be pointed at this tool.
- What is being built is a **functional analogue over HTTP + JSON-RPC**: the same capabilities,
  reachable over the JSON API the operator console already uses, plus a JSON-RPC child-process
  protocol for plugins. Where a Montoya method has an honest web analogue, it gets one. Where it does
  not, it is listed under WONT with the reason.
- The method counts in the tables below (`montoya/http` (52), `montoya/utilities` (36), …) are the
  size of the *problem*, not a checklist of signatures to match. "36 of 36" is not a goal and would
  not be a meaningful claim.

The clearest case is `userInterface()`: 10 of its 13 registration points contribute **Swing objects**
(`registerSuiteTab`, `applyThemeToComponent`, `swingUtils`, `currentDisplayFont`, menu-bar component
insertion). There is no honest web analogue for a Swing component, and a "component" JSON schema whose
only consumer is the thing that defined it is a fiction. So three of the thirteen get built — context
menu items, message-editor tabs, menu actions — and the other ten are declared WONT rather than
counted as coverage.

Status legend: **DONE** · **PART** partial · **TODO** · **WONT** deliberately out of scope.

---

## Phase 0 — shipped

| Feature | Status | Notes |
|---|---|---|
| Append-only traffic store, offset-based | **DONE** | `MessageShape` holds only spans; zero-copy asserted by test |
| Tolerant HTTP parser (CRLF + bare LF) | **DONE** | malformed traffic is the point, not an error |
| HTTP proxy, full capture | **DONE** | target rewritten, all other bytes preserved (asserted) |
| HTTPS `CONNECT` tunnel, recorded | **PART** | spliced + logged with `tls:true`; **not decrypted** |
| Repeater, byte-exact send | **DONE** | raw TCP not hyper; verbatim casing/order test |
| Insertion-point engine, 8 types | **DONE** | mirrors `burp.Zuq` taxonomy |
| Intruder sniper + battering ram plan | **PART** | sniper runs; plan() supports both; sequential only |
| Web UI: History / Repeater / Intruder | **DONE** | single page, no build step |
| JSON API | **DONE** | 7 endpoints |

---

## Phase 1 — TLS interception (the unblocker)

Nothing else matters as much: without this the proxy is blind to ~all real traffic.

| Task | Notes |
|---|---|
| **1.1 CA generation** | `rcgen` — self-signed CA, persisted to `~/.burpsy/ca.{pem,key}`, 2048-bit RSA or P-256 |
| **1.2 CA export endpoint** | `GET /ca.crt` so the browser can install it, mirroring Burp's `http://burpsuite/cert` |
| **1.3 Per-host leaf signing** | sign on demand from the `CONNECT` host; cache by SNI in a `DashMap`, bounded LRU |
| **1.4 SNI-driven handshake** | `rustls` server config with a `ResolvesServerCert` that mints leaves lazily |
| **1.5 MITM the tunnel** | after `200 Connection Established`, TLS-accept client, TLS-connect upstream, then run the plain-HTTP path over both |
| **1.6 ALPN + HTTP/2** | negotiate `h2`; needs an h2 framing layer to stay byte-honest. **Defer h2 to 2.x** — `http/1.1` only ALPN at first, which is what most testing wants anyway |
| **1.7 Passthrough list** | host patterns that bypass MITM (cert-pinned apps, TLS-client-auth). Burp has this; essential in practice |
| **1.8 Invalid-cert upstream handling** | already permissive in `repeater`; reuse that verifier |

**Acceptance:** proxy an HTTPS site in a browser with the CA installed, see plaintext request/response
in History, and resend it through Repeater.

---

## Phase 2 — core tool parity

| Feature | Burp reference | Task |
|---|---|---|
| **Scope** | `montoya/scope` (3), `Zcur` | include/exclude rules, regex + host/port/path, applied to capture *and* attack |
| **Site map / Target tree** | `montoya/sitemap` (3) | tree of host → path → params, built from history; per-node issue rollup (`Ze3h` model) |
| **Interception (hold & edit)** | `montoya/proxy` (26) | queue a request, edit raw, forward/drop. Needs a UI socket (SSE or WS) |
| **Match & replace** | proxy options | ordered rules on request/response, header/body, regex |
| **Proxy history filters** | `Zfp2` `logger.display_filter.by_tool.*` | by host, status, method, MIME, search string |
| **Repeater tabs** | `Zfw8` `newHttpRepeaterTabOption` | multiple named tabs, history per tab, `Zcso`-style tab state |
| **Repeater connection control** | `Zcu0` `EnableH1ConnectionReuse`, `UpdateContentLength` | per-tab + global toggles; we already default to "don't touch bytes" |
| **Intruder: pitchfork + cluster bomb** | `AttackKind` | extend `plan()`; multi-position payload sets |
| **Intruder payload processing** | `PayloadStrings/*.pay` | prefix/suffix, case mod, encode/hash, match-replace; load Burp's own `.pay` lists |
| **Intruder concurrency + throttle** | `resourcePoolSelectionConfig` | worker pool, rate limit, backoff. **Gate concurrency behind a limiter** — unbounded parallelism DoSes the target |
| **Intruder grep-match / grep-extract** | `free.intruder.matchgrep.*` prefs | flag responses containing patterns; extract into a result column |
| **Decoder** | `montoya/decoder` (1) | url/html/base64/hex/gzip/jwt, chained, both ways |
| **Comparer** | `montoya/comparer` (1) | word + byte diff of two messages; `compare_http_messages` semantics |
| **Logger** | `montoya/logger` (2) | all-traffic view across tools, with the `Zfp2` capture filters |
| **Organizer** | `montoya/organizer` (4) | starred/annotated requests, notes, colours (`HighlightColor`) |
| **Sequencer** | `Zrdc` `sequencer.live_capture` | token capture + entropy analysis (FIPS-ish bit tests) |

---

## Phase 3 — scanner

The teardown makes this tractable because **the checks are data, not code**.

| Task | Notes |
|---|---|
| **3.1 Issue catalog** | ingest the 183 `KnowledgeBase/Issues/*.json` — `typeIndex`, name, severity, description, remediation, CWE. Already extracted to `out/scanner_spec/issue_catalog.tsv` |
| **3.2 Passive checks** | run on every proxied response: security headers, cookie flags, TLS cookie w/o Secure, autocomplete, cleartext password, info disclosure, CORS, cacheability. ~68 of the catalog are INFO/LOW and mostly passive |
| **3.3 Check dispatch scopes** | implement `burp.Zcud`'s 7 scopes: perUrl / perPath / perHost / perRequest / inSessionPerRequest / perInsertionPoint / storedPerInsertionPoint. **Copy the filter-then-instantiate order** — config filter, then applicability filter, then construct |
| **3.4 Audit-item state machine** | `burp.Zq5`'s 15 states; `NON_TERMINAL` / `COMPLETED` sets drive progress + resumability |
| **3.5 Circuit breakers** | `consecutive_audit_check_failures_to_skip_insertion_point`, `consecutive_insertion_point_failures_to_fail_audit_item`, pause thresholds |
| **3.6 Active checks** | reflected XSS, SQLi (error + boolean + time), path traversal, command injection, SSTI, XXE, open redirect, header injection, deserialization probes |
| **3.7 BCheck interpreter** | `burp.Zht9` gave us the v2-beta grammar: `metadata:` / `define:` / `given insertion point then` / `send payload: appending:` / `report issue:`. **Highest leverage item in the whole roadmap** — inherit the public corpus instead of porting checks |
| **3.8 Issue dedup / consolidation** | `burp.Zbvp` chain-of-responsibility: `findIssuesOfSameType` → `shouldMergeIssues`, keyed on issue type, with per-type overrides (e.g. JWT secret equality). `Zby4` CRC-over-type-set for cheap shape matching |
| **3.9 Crawler** | frontier, link + form extraction, `crawl_limits` (time/request/unique-location), `crawl_strategy`. Headless-browser crawl is a later, separate lift |
| **3.10 Live passive crawl** | `crawler.live_passive_crawl.*` — derive sitemap from proxy traffic without active requests |
| **3.11 Live audit** | same audit pipeline fed from proxy traffic (`Zrb9.buildLiveAuditTaskView`) rather than a crawl frontier |
| **3.12 Scan configs** | ingest the 29 `BuiltInConfigs/*.json` verbatim — config compatibility is nearly free and immediately useful |
| **3.13 RetireJS** | `retirejs_repository.json` — vulnerable JS library detection |
| **3.14 JWT checks** | `Scanner/jwt_secrets.txt` (1.1MB wordlist) → weak HMAC secret |

---

## BCheck interpreter — status

Measured against PortSwigger's 264 published checks, every number recomputed by
`crates/scanner` at load time rather than quoted from an earlier estimate:

| Bucket | Checks | State |
|---|---|---|
| passive (`given response`, no send) | 105 | **runs** (M1) |
| active (sends requests) | 127 | **runs** (M2) |
| needs an insertion point (`send payload`) | 6 | M3 |
| needs Collaborator | 26 | needs an interaction server |
| **runnable** | **232 / 264 = 87.9%** | |

The four buckets sum to 264, asserted in a test, so a coverage claim cannot drift from what the
evaluator actually executes.

**What M2 required beyond a parser.** The parser accepted 264/264 before this work, but
`skip_modifiers()` discarded every `send request` modifier clause — acceptance was real, the AST was
lossy. The conformance runner now tallies captured clauses and agrees with an independent grep of the
corpus at **381/381** across all six targets and both operations.

Two false-positive sources were found and closed while building it:

* `str::contains("")` is `true`, so coercing an unresolvable path to `""` made
  `{missing} in {latest.response}` report on *every* response. 15 corpus checks put a variable on the
  left of `in`, and `{check.response.body}` (156 uses) is reachable from any failed send. Absent
  operands now make a comparison false, never true, and are recorded as diagnostics.
* A failed send abandons the check rather than continuing with absent bindings.

Both are covered by tests that fail if the guard is removed, and `e2e-audit.sh` proves them against a
live origin: a probe of a 404 path produces nothing, and killing the origin mid-run yields three
counted send failures and zero new findings.

**Verified inference, not guesswork.** Replacing `path:` leaves the query string intact, because
PortSwigger's grammar exposes `path` and `query_string` as separate targets. That is an inference from
the grammar, not an observation of Burp's runtime, and it is marked as such in the code.

**Deliberately absent.** `generate_collaborator_address()` is not stubbed. Inventing an address that
nothing polls would convert all 26 OOB checks into silent false negatives, so they are gated out and
counted instead.

## Phase 4 — platform

| Feature | Burp reference | Task |
|---|---|---|
| **Persistence / project files** | `montoya/persistence` (4), `montoya/project` (1) | **mmap-backed store** — the offset design already permits it with no API change. This is what makes multi-GB captures viable where Burp needs a 7.65GB project file |
| **Collaborator (OOB)** | `montoya/collaborator` (16) | DNS + HTTP interaction server, payload minting, polling. Needs a hosted domain — big lift |
| **Extensions / plugin API** | `montoya/extension` (2), `Zcps` | plugin surface. **Prefer WASM or a JSON-RPC child process over embedding a JVM.** Caido's lesson: JS/TS plugins lower the barrier vs Java |
| **Bambda-style filters** | `montoya/bambda` (3) | expression language for filtering/highlighting. Consider `rhai` rather than inventing one |
| **WebSockets** | `montoya/websocket` (15) | capture, history, WS repeater (`Zfw1 newWSRepeaterTabOption`) |
| **HTTP/2** | `montoya/http` (52) | first-class h2, incl. deliberately malformed frames for smuggling work |
| **Utilities** | `montoya/utilities` (36) | crypto/hash, random, JSON/XML tools, shell helpers |
| **Session handling** | `applicationLoginConfig`, `maintain_session` | macros, recorded logins, cookie jar, re-auth on session loss |
| **Reporting** | — | HTML/JSON/SARIF export with catalog-backed descriptions and remediation |
| **Dashboard** | `Zsq4 buildDashboardPanel`, `Zbcc` | task list + progress (`adaptCrawlToRelativeProgress`), event log, activity log |

---

## Phase 5 — the things Burp added recently

| Feature | Notes |
|---|---|
| **MCP server** | Burp ships `mcp-proxy-all.jar` on `127.0.0.1:18765`. Exposing burpsy's API as MCP is *cheap* — the JSON API already exists — and makes it agent-drivable. High value/effort ratio |
| **AI / agentic (Burp AT)** | `montoya/ai` (6) + the 54-tool `McpBurpTool` registry. If the MCP server exists, an agent can drive burpsy with any model — no vendor backend, no AI credits |
| **DOM/JS analysis** | `scan_type_javascript_analysis` — needs a JS engine; large |

---

## Deliberately out of scope

| Item | Why |
|---|---|
| Native Swing-style desktop GUI | web UI is the point; Burp's perceived slowness is largely Swing |
| Recompiling/patching Burp itself | only ~53% of the decompiled tree compiles, and it would be a derivative build |
| Porting Burp's Java scan-check code | derivative work. Implement from the **specs and public BCheck/Montoya contracts** instead |
| Enterprise/CI features | `Names are not supported in the desktop product - this is an Enterprise-only feature` |
| Loading Burp extensions | no JVM, and no binary or source compatibility with `MontoyaApi`. See the note at the top |
| `userInterface()`'s 10 Swing registration points | `registerSuiteTab`, `applyThemeToComponent`, `swingUtils`, `currentDisplayFont`, menu-bar component insertion. No honest web analogue; a component schema with one consumer is a fiction. The three declarative points — context-menu items, message-editor tabs, menu actions — are in scope |
| `registerHttpRequestEditorProvider` | looks portable and is not fully: Burp exposes caret position and live selection to the plugin, which a stateless HTTP call cannot |
| `burpSuite().exportProjectFileAndExit()` / `loadProjectFile()` / `restart()` | all three presuppose Burp project files. burpsy's durable state is an mmap-backed capture directory plus a SQLite mirror, which is a different object |
| `project().name()` | no analogue, and the tempting fallback is the harmful one. A name derived from the `-db` filename would end up in report headers as if the operator had chosen it. The route returns `name: null` |
| `importBambda(String)` | takes **Java source**. The filter substrate here is a closed typed grammar (`internal/query`), deliberately not a scripting engine, so this cannot be honoured. The route answers 400 with a grammar reference — never `{"imported": true}` for something that was never executed |
| Hosting a Collaborator server | the client is in scope (Interactsh-compatible); running the DNS/HTTP interaction infrastructure is not. Unconfigured, OOB checks are **gated and counted**, never silently skipped — 26 corpus checks depend on it, and a returning stub would convert all 26 into false negatives |

---

## Ordering rationale

1. **TLS interception first** — everything downstream is blind without it.
2. **Scope + sitemap next** — every other tool needs "is this in scope" and "what have we seen".
3. **Passive checks before active** — free on traffic you already have, no extra requests, immediate value.
4. **BCheck interpreter before hand-written active checks** — one interpreter inherits a corpus.
5. **mmap store before the scanner scales** — the whole memory thesis pays off only once findings and audit items accumulate.
6. **MCP server early** — it is nearly free given the existing API, and makes the tool scriptable/agent-drivable long before the UI is complete.
