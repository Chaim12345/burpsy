# Requirements: burpsy

**Defined:** 2026-07-27
**Core Value:** Run PortSwigger's published BCheck corpus, unmodified and honestly counted, against real traffic without the memory cost that forces Burp to discard scan work.

## v1 Requirements

This milestone turns a working proxy and scanner into a platform. Requirements are written as
operator-observable capabilities, not implementation tasks.

### Store (STORE)

- [x] **STORE-01**: Captured traffic persists to disk in fixed-size sealed segments, so a multi-GB capture is bounded by disk rather than RAM
- [x] **STORE-02**: Any message resolves to its bytes in constant time, replacing every linear scan over the message list
- [x] **STORE-03**: A message id always resolves to the message stored under it, including when many connections capture concurrently
- [x] **STORE-04**: A record carries references to related records, so one exchange can own many child records
- [x] **STORE-05**: Operator can verify a migrated capture is byte-identical to what the previous store held, rather than inferring it from the absence of a crash

### Query language (DSL)

- [ ] **DSL-01**: Operator can filter proxy history with a typed query over host, status, method, MIME type and body content
- [ ] **DSL-02**: The same query language selects which traffic match-and-replace rules apply to
- [ ] **DSL-03**: The same query language selects which traffic is in scope for crawling and live audit
- [ ] **DSL-04**: A query that cannot be parsed reports where and why, rather than silently matching nothing

### Tool parity (TOOLS)

- [ ] **TOOLS-01**: Operator can transform Intruder payloads before they are sent — prefix, suffix, case change, encode, hash, and match-and-replace — chained in a stated order
- [ ] **TOOLS-02**: Operator can load Burp's own `.pay` payload lists
- [ ] **TOOLS-03**: Operator can flag attack responses containing a pattern, and extract a pattern into a result column
- [ ] **TOOLS-04**: Operator can work in multiple named Repeater tabs, each keeping its own request history

### Session handling (SESSION)

- [ ] **SESSION-01**: Operator can record a login sequence and have it replayed automatically when the session drops
- [ ] **SESSION-02**: Operator states how a valid session is recognised, and the tool detects loss of session from that
- [ ] **SESSION-03**: Cookies are held per-host in a jar shared across tools
- [ ] **SESSION-04**: Re-authentication stops after a stated attempt limit instead of looping

### Crawler (CRAWL)

- [ ] **CRAWL-01**: Operator can crawl a target from a seed URL, discovering links and forms
- [ ] **CRAWL-02**: Crawled traffic is captured, scoped and scanned through exactly the same path as proxied traffic
- [ ] **CRAWL-03**: Form submission is off unless the operator turns it on
- [ ] **CRAWL-04**: The crawler refuses links whose text or target signals a destructive action, and reports everything it skipped
- [ ] **CRAWL-05**: Site map is built from proxy traffic continuously, with no separate crawl action
- [ ] **CRAWL-06**: Live audit runs against proxied traffic only when the operator opts in
- [ ] **CRAWL-07**: A crawl that stops early reports why and what it did not reach

### HTTP/2 (H2)

- [ ] **H2-01**: Operator can proxy, view and resend HTTP/2 traffic
- [ ] **H2-02**: HTTP/2 exchanges appear in history in the same shape as HTTP/1, so every existing tool works on them unchanged
- [ ] **H2-03**: Operator can send deliberately malformed HTTP/2 frames for request-smuggling research
- [ ] **H2-04**: When a target supports HTTP/2, the tool uses it rather than silently downgrading to HTTP/1.1

### Plugins (PLUGIN)

- [ ] **PLUGIN-01**: Operator can install a plugin that observes traffic and adds findings or annotations
- [ ] **PLUGIN-02**: A plugin receives message metadata by default and must ask for body content explicitly
- [ ] **PLUGIN-03**: A plugin can only read the messages belonging to the exchange it was invoked for
- [ ] **PLUGIN-04**: A request a plugin modified is re-checked against scope before it is sent
- [ ] **PLUGIN-05**: Operator can see what capabilities a plugin has been granted

### WebSockets (WS)

- [ ] **WS-01**: WebSocket frames are captured and shown in history against the connection that carried them
- [ ] **WS-02**: Operator can edit and resend a WebSocket frame
- [ ] **WS-03**: WebSocket traffic is authorised against scope, with the decision point stated explicitly

### Scanner data (SCAN)

- [ ] **SCAN-01**: Scanner flags known-vulnerable JavaScript libraries by version
- [ ] **SCAN-02**: Scanner detects JWTs signed with a weak secret from a wordlist
- [ ] **SCAN-03**: Operator can load Burp's built-in scan configurations unchanged

### DOM analysis (DOM)

- [ ] **DOM-01**: Scanner statically traces JavaScript from source to sink and reports the catalogued DOM-based issue types
- [ ] **DOM-02**: A flow through a recognised sanitizer is not reported as a vulnerability
- [ ] **DOM-03**: Static analysis is bounded per item and reports when it hit that bound
- [ ] **DOM-04**: Operator can confirm a static DOM candidate by driving a real browser with a marker value and observing which sink it reaches
- [ ] **DOM-05**: A candidate that dynamic confirmation could not reach is reported as unconfirmed, never as a finding and never dropped

### Reporting (REPORT)

- [ ] **REPORT-01**: Operator can export findings as HTML for a human reader
- [ ] **REPORT-02**: Operator can export findings as JSON for a machine reader
- [ ] **REPORT-03**: Operator can export findings as SARIF that GitHub Code Scanning ingests
- [ ] **REPORT-04**: Every report states what was not checked and why, so a clean report cannot be mistaken for full coverage

### Dashboard (DASH)

- [ ] **DASH-01**: Operator can see running tasks and their progress
- [ ] **DASH-02**: Operator can see an event log of what the tool did
- [ ] **DASH-03**: Every summary count shows its disposition breakdown, so "stopped looking" is distinguishable from "found nothing"

### Agent surface (MCP)

- [ ] **MCP-01**: An MCP client can drive burpsy's existing capabilities over the Model Context Protocol
- [ ] **MCP-02**: Widening scope, launching an attack, and reading credentials or config each require per-call confirmation, granted server-side and not waivable by the client

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
| HARD-03 | Phase 1 | Partial — chokepoint built; per-surface tests land with each surface |
| H2-01 | Phase 2 | Pending |
| H2-02 | Phase 2 | Pending |
| H2-03 | Phase 2 | Pending |
| H2-04 | Phase 2 | Pending |
| DSL-01 | Phase 3 | Pending |
| DSL-02 | Phase 3 | Pending |
| DSL-04 | Phase 3 | Pending |
| TOOLS-01 | Phase 3 | Pending |
| TOOLS-02 | Phase 3 | Pending |
| TOOLS-03 | Phase 3 | Pending |
| TOOLS-04 | Phase 3 | Pending |
| REPORT-01 | Phase 4 | Pending |
| REPORT-02 | Phase 4 | Pending |
| REPORT-03 | Phase 4 | Pending |
| REPORT-04 | Phase 4 | Pending |
| SCAN-01 | Phase 4 | Pending |
| SCAN-02 | Phase 4 | Pending |
| SCAN-03 | Phase 4 | Pending |
| SESSION-01 | Phase 5 | Pending |
| SESSION-02 | Phase 5 | Pending |
| SESSION-03 | Phase 5 | Pending |
| SESSION-04 | Phase 5 | Pending |
| CRAWL-01 | Phase 6 | Pending |
| CRAWL-02 | Phase 6 | Pending |
| CRAWL-03 | Phase 6 | Pending |
| CRAWL-04 | Phase 6 | Pending |
| CRAWL-05 | Phase 6 | Pending |
| CRAWL-06 | Phase 6 | Pending |
| CRAWL-07 | Phase 6 | Pending |
| DSL-03 | Phase 6 | Pending |
| DASH-01 | Phase 6 | Pending |
| DASH-02 | Phase 6 | Pending |
| DASH-03 | Phase 6 | Pending |
| HARD-01 | Phase 7 | Pending |
| HARD-02 | Phase 7 | Pending |
| PLUGIN-01 | Phase 8 | Pending |
| PLUGIN-02 | Phase 8 | Pending |
| PLUGIN-03 | Phase 8 | Pending |
| PLUGIN-04 | Phase 8 | Pending |
| PLUGIN-05 | Phase 8 | Pending |
| WS-01 | Phase 9 | Pending |
| WS-02 | Phase 9 | Pending |
| WS-03 | Phase 9 | Pending |
| MCP-01 | Phase 10 | Pending |
| MCP-02 | Phase 10 | Pending |
| DOM-01 | Phase 11 | Pending |
| DOM-02 | Phase 11 | Pending |
| DOM-03 | Phase 11 | Pending |
| DOM-04 | Phase 12 | Pending |
| DOM-05 | Phase 12 | Pending |

**Coverage:**
- v1 requirements: 56 total (corrected from the 52 stated above — the itemized list was always 56; the summary count was stale). All 56 mapped to exactly one of 12 phases, 0 orphans.
- v2 requirements: 2 deferred
- Out of scope: 10 explicit exclusions
