# Roadmap: burpsy

> **Dated banner — 2026-08-18.** This twelve-phase roadmap was authored against the
> **Rust** tree. The Go port in `burpsy-go/` is now the active implementation and is
> tracked per-gap rather than per-phase: see `.planning/GO-PORT.md`,
> `burpsy-go/PORT_STATUS.md` and `burpsy-go/gaps.md` (all 13 Rust↔Go parity gaps
> COMPLETE as of 2026-08-04). Phase 6's Go work (crawler + dashboard) has landed
> including the session gate; Phases 8 and 10 (plugin API, MCP) are documented in Go
> as deliberately not shipped (`burpsy-go/docs/MCP.md`). This file is retained as the
> historical Rust-era roadmap.

## Overview

This milestone turns burpsy's working proxy and scanner into a platform: a race-free segmented
store, first-class HTTP/2, a shared typed query language, full tool parity, session survival, an
authenticated crawler with an honest dashboard, a hardening pass before real engagement use, a
capability-scoped plugin API, WebSockets, an MCP server, and DOM analysis split into a static pass
and a dynamic confirmation pass.

Twelve phases against this milestone's nominal 4-6 granularity target is a deliberate overshoot,
not drift. Four operator scope decisions each force a real phase boundary that folding away would
blur into an incoherent phase: moving HTTP/2 earlier (ahead of WebSockets and the plugin API),
splitting DOM analysis into a static phase and a separately-gated dynamic-confirmation phase,
carving the scope chokepoint decision (HARD-03) out of the Hardening group and into the store
phase it must precede the crawler alongside, and treating the filter DSL as one shared grammar
built early with a consumer (crawl/audit scoping) that only becomes observable once the crawler
exists. The store and its scope-chokepoint decision ship first because every later
request-originating surface depends on one or both of them. The Hardening Pass sits at phase 7 —
once proxy, scanner, HTTP/2, tool parity, session handling, and an authenticated crawler are all
real — so the engagement-readiness constraint PROJECT.md states as a hard precondition is
satisfiable without waiting for the last five feature phases.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

- [x] **Phase 1: Store & Scope Chokepoint** - Race-free segmented store with an O(1) index, plus the one authorising sender every later surface must route through
- [ ] **Phase 2: HTTP/2** - h2 traffic captured, viewed, resent and honestly negotiated, moved ahead of WebSockets and the plugin API *(Partial as of 2026-07-30: H2-01/H2-02 complete — relay, history parity, and an authorised Repeater resend path all land; H2-03/H2-04 partial — malformed-frame authoring and h2 egress exist, but frame-program sending has no UI, and Scanner/Intruder egress is still HTTP/1.1-only — see REQUIREMENTS.md)*
- [x] **Phase 3: Query DSL & Tool Parity** - One typed query grammar plus Intruder/Repeater's remaining parity gaps *(Complete 2026-07-30: all of DSL-01/02/04, TOOLS-01/02/03/04 — see REQUIREMENTS.md)*
- [ ] **Phase 4: Reporting & Scanner Data** - HTML/JSON/SARIF export and the scanner's remaining data-driven checks, both decoupled from platform work *(Substantially complete as of 2026-07-30: REPORT-01/02/03/04 and SCAN-01/02 all complete; SCAN-03's built-in scan-config data and overlay logic are built and tested but have no operator-facing selector yet — see REQUIREMENTS.md)*
- [x] **Phase 5: Session Handling** - Recorded login survives session loss on the operator's own terms, without looping
- [ ] **Phase 6: Crawler & Dashboard** - Authenticated crawling fed by and feeding proxy traffic, with an honest view of what was and wasn't reached
- [x] **Phase 7: Hardening Pass** - Engagement-readiness gate: the three unreviewed branches and the fixture-independent corpus invariant
- [ ] **Phase 8: Plugin API** - Capability-scoped plugin hooks, metadata by default, scope re-checked before send
- [ ] **Phase 9: WebSockets** - Captured, editable, scope-authorised WS frames, reusing the connection state machine HTTP/2 generalised *(Partial as of 2026-07-30: WS-01/03 landed — capture, history, per-message scope authorisation; WS-02 edit-and-resend needs interception, deliberately deferred, see `crates/proxy/AGENTS.md`)*
- [ ] **Phase 10: MCP Server** - Agent-drivable JSON API over MCP, with server-side per-call confirmation on the risky calls
- [ ] **Phase 11: DOM Static Analysis** - Source-to-sink taint over the catalogued DOM issue types, bounded and honest about its limits
- [ ] **Phase 12: DOM Dynamic Confirmation** - Real-browser confirmation of static candidates — confirmed or honestly UNCONFIRMED, never dropped

## Phase Details

### Phase 1: Store & Scope Chokepoint
**Goal**: Captured traffic is stored durably and addressed in constant time under concurrent capture, and every future request-originating surface has exactly one place to be authorised.
**Depends on**: Nothing (first phase)
**Requirements**: STORE-01, STORE-02, STORE-03, STORE-04, STORE-05, HARD-03
**Status**: Complete
**Success Criteria** (what must be TRUE):
  1. A multi-GB capture stays bounded by disk rather than RAM, because traffic seals into fixed-size segments as it is captured
  2. Any message's bytes resolve via one direct lookup instead of a scan, and message ids resolve correctly under concurrent capture from many connections at once — the id-assignment race is closed, not narrowed
  3. A record can carry references to multiple related child records through one `related` slot — unused by anything yet, but ready for a WebSocket frame or an HTTP/2 raw frame to attach to its parent exchange
  4. Operator can run a migration check that emits a per-record byte-equality verdict naming any mismatching id, rather than inferring success from the absence of a crash
  5. One authorising sender type is the only path from a constructed request to a socket; the existing proxy and scanner senders both route through it, and a test proves no alternate egress path exists — per-surface verification (crawler, session macros, plugins, WebSockets, MCP, browser) lands in each surface's own later phase
**Plans**: TBD

### Phase 2: HTTP/2
**Goal**: HTTP/2 traffic is a first-class citizen of the existing pipeline — captured, resendable, and negotiated honestly — sequenced ahead of WebSockets and the plugin API rather than after them.
**Depends on**: Phase 1 (the `related` slot the store's design reserved for this)
**Requirements**: H2-01, H2-02, H2-03, H2-04
**Status**: Partial (2026-07-30) — H2-01/H2-02 complete; H2-03/H2-04 partial, see REQUIREMENTS.md
**Success Criteria** (what must be TRUE):
  1. Operator can proxy an HTTP/2 exchange end to end and resend it through Repeater
  2. An HTTP/2 exchange sits in history in the same shape as HTTP/1, so filters, Repeater, and the scanner already built keep working on it unchanged
  3. Operator can send deliberately malformed HTTP/2 frames at a target for request-smuggling research
  4. When a target advertises HTTP/2 support, the proxy negotiates it instead of silently falling back to HTTP/1.1 — the ALPN-downgrade coverage gap this milestone would otherwise carry until its last feature phase is closed here instead
**Plans**: TBD

### Phase 3: Query DSL & Tool Parity
**Goal**: A single typed query grammar reaches its first two consumers, and Intruder/Repeater close out their remaining parity gaps.
**Depends on**: Phase 1 (the O(1) index makes filtering large history practical)
**Requirements**: DSL-01, DSL-02, DSL-04, TOOLS-01, TOOLS-02, TOOLS-03, TOOLS-04
**Status**: Complete (2026-07-30)
**Success Criteria** (what must be TRUE):
  1. Operator can filter proxy history with a typed query over host, status, method, MIME type, and body content
  2. The same query language selects which history entries a match-and-replace rule applies to
  3. A query that fails to parse reports where and why, instead of silently matching nothing
  4. Operator can chain prefix/suffix/case/encode/hash/match-replace transforms on Intruder payloads in a stated order, including payloads loaded from Burp's own `.pay` lists
  5. Operator can flag and extract patterns from attack responses via grep-match/grep-extract, and can switch between multiple named Repeater tabs, each its own interface component with independent history
**Plans**: TBD
**UI hint**: yes

### Phase 4: Reporting & Scanner Data
**Goal**: Findings leave the tool in formats other software and humans can consume, honestly scoped to what was actually checked; the scanner's remaining data-driven checks are complete.
**Depends on**: Nothing new — parallelizable with Phases 1-3 (built on the existing issue catalog and audit engine)
**Requirements**: REPORT-01, REPORT-02, REPORT-03, REPORT-04, SCAN-01, SCAN-02, SCAN-03
**Status**: Substantially complete (2026-07-30) — REPORT-01..04 and SCAN-01/02 done; SCAN-03 partial, see REQUIREMENTS.md
**Success Criteria** (what must be TRUE):
  1. Operator can export findings as a single HTML page for a human reader
  2. Operator can export the same findings as JSON, and as SARIF that GitHub Code Scanning ingests without modification
  3. A zero-finding report still enumerates what did not run and why — including the 26 Collaborator-gated checks — so a clean report cannot be mistaken for full coverage
  4. Scanner flags known-vulnerable JavaScript libraries by version and JWTs signed with a weak wordlist secret, using Burp's own built-in scan configurations unchanged
**Plans**: TBD

### Phase 5: Session Handling
**Goal**: A recorded login survives session loss automatically, on the operator's own terms for what "valid" means, without looping forever.
**Depends on**: Nothing new — parallelizable with Phases 1-4 (built on the existing proxy and cookie handling)
**Requirements**: SESSION-01, SESSION-02, SESSION-03, SESSION-04
**Success Criteria** (what must be TRUE):
  1. Operator can record a login sequence and have it replay automatically when the session drops
  2. Operator states how a valid session is recognised, and the tool detects loss of session from that statement alone
  3. Cookies are held per-host in one jar shared across Proxy, Repeater, and Intruder
  4. Re-authentication stops after a stated attempt limit instead of looping indefinitely
**Plans**: TBD

### Phase 6: Crawler & Dashboard
**Goal**: Operator can crawl an authenticated target continuously from proxy traffic, with everything the crawl reached — and everything it didn't — visible in one place.
**Depends on**: Phase 1 (store, volume), Phase 3 (the query language's third consumer), Phase 5 (session survival to reach authenticated pages)
**Requirements**: CRAWL-01, CRAWL-02, CRAWL-03, CRAWL-04, CRAWL-05, CRAWL-06, CRAWL-07, DSL-03, DASH-01, DASH-02, DASH-03
**Success Criteria** (what must be TRUE):
  1. Operator can crawl a target from a seed URL, discovering links and forms, with form submission off unless explicitly turned on
  2. Crawled traffic is captured, scoped, and scanned through exactly the same path as proxied traffic, and the crawler refuses links that signal a destructive action while reporting everything it skipped
  3. Site map builds continuously from proxy traffic with no separate crawl action, and live audit runs against it only when the operator opts in — both scoped using the query language from Phase 3
  4. A crawl stopped by its limit shows what stopped it and how many frontier URLs went unfetched, rather than ending silently
  5. Operator can see running tasks and their progress, an event log of what the tool did, and every summary count broken into found/skipped/errored/gated — so "12 issues" never reads as "that's all there is"
**Plans**: TBD
**UI hint**: yes

### Phase 7: Hardening Pass
**Goal**: The tool is safe to point at a real authorised engagement — the constraint PROJECT.md states as a hard precondition is now satisfiable, not deferred past five more feature phases.
**Depends on**: Phases 1-6 (everything reviewed here was built across them)
**Requirements**: HARD-01, HARD-02
**Success Criteria** (what must be TRUE):
  1. Each of the three previously-unreviewed merged branches has a documented line-by-line review, and any defect found in it is fixed and tested
  2. On a machine without the `/tmp/BChecks` fixture, the corpus partition invariant test reports SKIPPED, and the overall suite does not report that check as passed
**Plans**: TBD

### Phase 8: Plugin API
**Goal**: Operator can extend the tool with a plugin whose access is capability-scoped by default, not by convention.
**Depends on**: Phase 1 (segment-backed span resolution for `read_span`; the chokepoint architecture the plugin's re-check must route through)
**Requirements**: PLUGIN-01, PLUGIN-02, PLUGIN-03, PLUGIN-04, PLUGIN-05
**Success Criteria** (what must be TRUE):
  1. Operator can install a plugin that observes traffic and adds findings or annotations
  2. A plugin receives message metadata by default and must explicitly ask for body content, and can only read messages belonging to the exchange it was invoked for
  3. A request a plugin modified is re-checked against scope before it is sent — through the same chokepoint from Phase 1, not a plugin-specific bypass
  4. Operator can see what capabilities a plugin has been granted
**Plans**: TBD

### Phase 9: WebSockets
**Goal**: WebSocket traffic is a captured, editable, scope-authorised citizen of history — the connection-lifetime scope question resolved explicitly, not left implicit.
**Depends on**: Phase 1 (the `related` slot's first real consumer), Phase 2 (reuses the per-connection state machine HTTP/2 generalised)
**Requirements**: WS-01, WS-02, WS-03
**Success Criteria** (what must be TRUE):
  1. WebSocket frames are captured and shown in history against the connection that carried them
  2. Operator can edit and resend a WebSocket frame
  3. WebSocket traffic is authorised against scope with the decision point stated explicitly — not authorised once at Upgrade and then left unchecked for the connection's lifetime
**Plans**: TBD

### Phase 10: MCP Server
**Goal**: An MCP client can drive burpsy over the Model Context Protocol, with the riskiest actions gated server-side rather than left to client trust.
**Depends on**: Phases 1-9 (re-exposes the JSON API only once that surface has stopped changing)
**Requirements**: MCP-01, MCP-02
**Success Criteria** (what must be TRUE):
  1. An MCP client can drive burpsy's existing capabilities — proxy, crawler, scanner, repeater — over the Model Context Protocol
  2. Widening scope, launching an attack, and reading credentials or config each require a per-call confirmation granted server-side, which the client cannot waive on its own behalf
**Plans**: TBD

### Phase 11: DOM Static Analysis
**Goal**: The scanner traces JavaScript from source to sink statically and reports the catalogued DOM-based issue types, bounded and honest about its own limits.
**Depends on**: Phase 1 (store), Phase 4 (the issue catalog data the DOM issue types slot into)
**Requirements**: DOM-01, DOM-02, DOM-03
**Success Criteria** (what must be TRUE):
  1. Scanner statically traces JavaScript from source to sink and reports the catalogued DOM-based issue types
  2. A flow through a recognised sanitizer is not reported as a vulnerability
  3. Static analysis is bounded per item and reports when it hit that bound, rather than silently truncating
**Plans**: TBD

### Phase 12: DOM Dynamic Confirmation
**Goal**: A static DOM candidate is confirmed or honestly left unconfirmed by driving a real browser — never silently dropped, never asserted without evidence.
**Depends on**: Phase 11 (confirms its candidates), Phase 1 (the browser is a new request-originating surface and must route through the same chokepoint)
**Requirements**: DOM-04, DOM-05
**Success Criteria** (what must be TRUE):
  1. Operator can confirm a static DOM candidate by driving a real browser with a marker value and observing which sink it reaches
  2. A candidate that dynamic confirmation could not reach is reported as UNCONFIRMED — present in the report, never dropped and never asserted as a finding
  3. All browser network egress routes through the same authorising chokepoint as every other surface, verified by its own test — HARD-03's last per-surface check
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12

This table was stale for the whole milestone — every row said "Not started" regardless of actual
status, including Phase 1, which the checklist above and STATE.md both already called Complete. Rows
below are corrected against STATE.md and this session's own verified work; Phases 2, 4, 6, 8, 10–12
are carried forward unchanged since nothing this session touched or re-verified them.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Store & Scope Chokepoint | 0/TBD | Complete | prior to 2026-07-28 |
| 2. HTTP/2 | 0/TBD | Partial (H2-01/02 complete) | - |
| 3. Query DSL & Tool Parity | 0/TBD | Complete | 2026-07-30 |
| 4. Reporting & Scanner Data | 0/TBD | Substantially delivered (SCAN-03 partial) | - |
| 5. Session Handling | 0/TBD | Complete | prior to 2026-07-28 |
| 6. Crawler & Dashboard | 0/TBD | Not started | - |
| 7. Hardening Pass | 0/TBD | Complete | prior to 2026-07-28 |
| 8. Plugin API | 0/TBD | Not started | - |
| 9. WebSockets | 0/TBD | Partial (WS-01/03) | - |
| 10. MCP Server | 0/TBD | Not started | - |
| 11. DOM Static Analysis | 0/TBD | Not started | - |
| 12. DOM Dynamic Confirmation | 0/TBD | Not started | - |
