# Project Research Summary

**Project:** burpsy
**Domain:** Rust web-application-security testing platform (Burp Suite reimplementation) — platform/plugin-era milestone on an existing 9-crate workspace
**Researched:** 2026-07-27
**Confidence:** MEDIUM overall

## Executive Summary

This milestone turns a working proxy+scanner into a platform: crawler, live passive crawl, live audit, WebSockets, session handling, a plugin API, Bambda-style filters, MCP server, HTTP/2, and DOM/JS analysis. The single most important conclusion across all four research passes is that the mmap-backed segmented store is not one platform item among several — it is the prerequisite everything else sits on. It is also, conveniently, the same piece of work that fixes the already-documented O(n^2) set_response scan (and a subtler id-assignment race the architecture research found by reading the current code, which a naive "just index by id" fix would not actually resolve). Crawler, live audit, live crawl, and WebSockets history are all volume generators against the store; shipping any of them before the store fix inherits and amplifies an existing defect rather than paying it down.

The recommended approach: build the segment/location store first (Build Order step 1), with one deliberate forward-looking addition — a 1:N parent-child relation slot (related: Vec<ChildRef>) designed into the schema now, even though only WebSocket frames use it this milestone. This is the one thing cheap now and expensive to retrofit; it is also the condition that makes deferring HTTP/2 to the end of the milestone genuinely cost-free rather than merely convenient. Everything else — tool-parity leftovers (Intruder processing, Repeater tabs, history filters, Sequencer, reporting), session handling, the crawler, the plugin API, WebSockets, HTTP/2, dashboard, and MCP — follows in a dependency-driven order detailed below, not the "kind of work" grouping PROJECT.md currently uses.

The dominant risk theme, independently confirmed by the pitfalls research, is not any single feature's complexity but scope-enforcement discipline: every new request-originating surface (crawler, session macros, plugin API, MCP server, and eventually an embedded JS engine) is a candidate to reintroduce the exact fail-open class this project already fixed once (scope checked against the named target rather than the bytes actually sent). Two structural gaps were found in code that doesn't exist yet: WebSocket frames have no request line for authorise_request to parse, and a JS engine's fetch() calls never touch any Rust-side check at all. Both need an explicit design decision, not an assumption that the existing chokepoint just applies. A second reversal worth flagging to the roadmap: FEATURES research argues rhai is the wrong category of tool for Bambda-style filters — a small typed query DSL (Caido's HTTPQL shape) should be built once and shared by history filters, match-and-replace, and live-audit/crawl scoping, rather than reproducing Bambda's own authoring problem in Rust-flavored syntax. STACK independently found extism has no Python PDK, meaning "WASM plugins" and "Python plugins" are two separate decisions, not one plugin phase.

## Key Findings

### Recommended Stack

New dependencies for this milestone: memmap2 0.9 (sealed-segment mmap only, never a growing mutable mapping), bytes (Bytes::from_owner — the single fact the mmap migration hinges on, confirmed no Arc wrapper needed), extism 1.30 wrapping wasmtime (in-process WASM plugin tier), a JSON-RPC child-process tier for Python/unrestricted-interpreter plugins, h2 0.4 with the unstable feature scoped to one small crate (for well-formed h2 plus the malformed-frame research capability), rhai 1.25 (confirmed as the incumbent choice for Bambda expression evaluation — see the Features disagreement below), boa_engine 0.21 (pure-Rust JS engine for DOM/JS analysis, consistent with the project's existing no-cc-dependency stance), and rmcp 2.2 (official MCP SDK, verified axum-0.8-compatible, mounted onto the existing router).

**Core technologies:**
- memmap2 + bytes::from_owner: zero-copy read path for sealed segments — dependency, not hand-rolled, because wrapping raw OS mmap safely is a memory-safety-adjacent job
- extism: in-process WASM plugin host for Rust/Go/AssemblyScript/JS-PDK plugins — ship first; it covers the higher-frequency Bambda-adjacent filter/highlight hook use case
- JSON-RPC child process (hand-rolled framing): separate tier for Python and "run my existing Node project" plugins, since extism has no Python PDK at all
- h2 (unstable feature, scoped crate): well-formed h2 plus frame-level access for the deliberately-malformed-frame research feature; stable h2 structurally cannot construct invalid frames
- boa_engine: DOM/JS analysis — no crate ships a DOM shim, so that is scoped as built-here work regardless of engine choice

### Expected Features

**Must have (table stakes):**
- Intruder payload processing (prefix/suffix/case/encode/hash/match-replace, .pay lists) + grep-match/extract
- Proxy history filters (host/status/method/MIME/search)
- Repeater tabs (multiple named, per-tab history)
- A minimal session-handling mechanism (login macro + regex verification + auto re-run) — copy ZAP's declarative shape, not Burp's rule-editor/macro-maze shape
- mmap-backed store, landed before crawler/live-crawl/live-audit/WebSockets history

**Should have (differentiators):**
- A small typed filter/query DSL (Caido HTTPQL shape) reused across history filters, match-and-replace, and live-crawl/audit inclusion — one grammar, four consumers, built once
- Full-spec SARIF (webRequest/webResponse core object-model fields) plus a synthetic physicalLocation for GitHub Code Scanning ingestion
- MCP server (real distance from Caido/ZAP, though parity with Burp's own MCP offering)
- Live passive crawl + live audit fed continuously from proxy traffic with no separate crawl action — a genuine differentiator over both Caido's and ZAP's user-triggered-action model, because it composes with the zero-copy store
- mmap store itself enabling multi-GB captures as a structural advantage over Caido/Burp's storage models — frame this as the payoff of Phase 1's design work, not a new feature

**Defer (v2+):**
- Sequencer — real but modest demand (both Caido and ZAP ship it only as an add-on/plugin, not core); P3, good first dogfood case once the plugin API exists
- Full DOM/JS static analysis engine — thin precedent even among competitors; reconsider scope (narrow heuristic vs. general engine) before committing real effort
- WYSIWYG report template designer — anti-feature; export clean structured data and let SysReptor/Dradis/Word own layout
- A rule-editor GUI for session handling — anti-feature; this is the single most-criticized piece of Burp's own UX

### Architecture Approach

The store grows a segment/location layer underneath the existing MsgId/Span/Bytes API without changing any caller's interface. New capability crates (burpsy-http2, burpsy-crawler, burpsy-plugins, burpsy-reporting) sit alongside the existing crate-boundary discipline, each depending only on burpsy-core plus what it strictly needs, never creating a reverse dependency onto burpsy-proxy or burpsy-scanner. One shared on_exchange hook (same shape as the existing AuditHook) is called by both the proxy and the crawler, so "live passive crawl" and "live audit" are this hook existing and being called from a second call site — nothing structurally new is invented for them.

**Major components:**
1. Segment + Location index (crates/core) — fixed-size, append-only segment files, either Active (buffered writes, in-memory Bytes mirror) or Sealed (mmap'd once, read-only, wrapped in one Bytes::from_owner); Vec<Location> indexed directly by MsgId replaces every linear scan, with id assignment and location write inside the same lock critical section (the race the naive fix would miss)
2. related: Vec<ChildRef> sidecar (crates/core) — the 1:N parent-child slot populated by WS frames now, h2 raw-frame references later; the single design decision that must be made during the store migration, not retrofitted
3. burpsy-http2 (new crate) — ingest-time normalization of h2 into the canonical HTTP/1-shaped MessageShape, plus a raw per-connection frame sidecar for malformed-frame research; keeps h2 unstable usage scoped to one crate
4. burpsy-plugins (new crate) — capability-scoped hook API: metadata-only by default, a bounded read_span(msg_id, offset, len) call restricted to the invoking exchange's own message ids, modify hooks always produce a new MsgId via TrafficStore::put rather than mutating in place, with scope re-checked against returned bytes before anything reaches the wire
5. burpsy-crawler (new crate) — writes through the exact same put/add_exchange/set_response calls the proxy uses, calls the same on_exchange hook, never talks to the scanner directly

### Critical Pitfalls

1. Every new request-originating surface (crawler, session macros, plugin API, MCP server) can re-derive its own scope check instead of sharing one chokepoint — structurally require these to hold the same metered/authorising sender type the scanner already uses, so bypassing scope means bypassing the type system, not forgetting a function call. Authorise at the last point before bytes hit the socket, strictly after any processing chain, plugin rewrite, or macro substitution.
2. WebSocket frames have no request line for authorise_request to parse — a genuine gap in the current scope function, not yet decided: an explicit choice is needed (authorise once at Upgrade, treat the connection's lifetime as scoped to that decision) with its own regression test, not a silent skip.
3. Crawler follows destructive links/forms (logout, delete, unsubscribe) with no operator-visible gate — GET-only heuristics are insufficient (documented GET-based logout/delete pattern); require an explicit off-by-default form-submission toggle, a semantic-signal denylist, and an operator-visible report of everything skipped for safety.
4. mmap migration risks silent data loss, treated as "didn't crash" verification — torn writes, stale mappings on growth, and uncatchable SIGBUS on shrink/truncate are distinct failure modes; require a checksum per record/segment and a read-back equivalence test against the prior store over real captured data, not just CI passing.
5. Bambda/rhai filters become either a self-DoS or an unaudited request originator — set max_operations/max_string_size/max_array_size/max_map_size explicitly and restrictively from day one; never register a network-capable function on the Bambda engine.
6. MCP server turns scanned/crawled content into an indirect prompt-injection vector — a single-source but corroborated-class finding: scope-widening, attack-launch, and credential/config-read tools need server-side, per-call confirmation (not a one-time client "always allow" grant), since the threat model is a compromised/confused agent, not an honest client.

## Implications for Roadmap

Based on combined research, the dependency-driven build order (from ARCHITECTURE, cross-checked against FEATURES and PITFALLS) should override PROJECT.md's current "kind of work" grouping:

### Phase 1: Segmented mmap store + race-free O(1) location index
**Rationale:** Foundational and self-contained inside burpsy-core. Crawler, WebSockets, and HTTP/2 all either depend on this or inherit/amplify the existing O(n^2) set_response defect — a real concurrency bug (id-assignment race), not just an inefficiency. This must ship before any volume-generating feature, not alongside it.
**Delivers:** Segment/Location types, id-to-(segment,span) index, the fix for set_response's scan, and the related: Vec<ChildRef> 1:N sidecar slot (used later, designed now).
**Addresses:** "mmap-backed store" (FEATURES table stakes — enabling item), multi-GB capture differentiator.
**Avoids:** Pitfall 10 (mmap corruption/unverifiable migration — requires checksum + read-back equivalence test) and Anti-Pattern 1 (indexing without fixing the id-assignment race).

### Phase 2: Tool-parity leftovers (parallelizable with Phase 1)
**Rationale:** None of these touch TrafficStore internals or generate exchange volume; Reporting in particular has zero coupling to platform work despite being grouped under "Platform" in PROJECT.md.
**Delivers:** Intruder payload processing + grep-match/extract, Repeater tabs, Sequencer, RetireJS/JWT wordlist data files, JSON/HTML reporting.
**Addresses:** FEATURES P1 table-stakes items.
**Avoids:** Pitfall 3 (payload-chain scope bypass — authorisation must run on final processed bytes, not a template).
**Note:** Proxy history filters (and the typed filter DSL) belong here for correctness but want the Phase 1 O(1) index before evaluation against large history — sequence just after Phase 1.

### Phase 3: Session handling (macros, recorded login, cookie jar, re-auth)
**Rationale:** Moved earlier than PROJECT.md's position — a crawler without session survival can only reach the unauthenticated surface, defeating most of the point of crawling a real app. Build before or alongside Phase 4.
**Delivers:** ZAP-shaped declarative session config (auth method + verification indicator + auto re-auth), not a Burp-style rule-editor.
**Avoids:** Pitfall 2 (unbounded re-auth retry loop — requires a hard attempt cap and a causal session-generation counter).

### Phase 4: Crawler + shared on_exchange hook + live-passive/live-audit wiring
**Rationale:** Depends on Phase 1 (crawler is a volume generator; the mmap migration must precede it, unambiguously). Also the right place to stress-test the O(1) index and the hook under realistic load before WebSockets and HTTP/2 both become callers of it too.
**Delivers:** Frontier + extraction, on_exchange hook shared with proxy, live passive crawl (automatic) and live audit (explicit operator opt-in only).
**Addresses:** FEATURES differentiator "live passive crawl + live audit fed from proxy traffic."
**Avoids:** Pitfall 1 (destructive-action crawling — semantic-signal denylist, operator-visible skip report) and Anti-Pattern 4 (silent frontier truncation — needs a CrawlOutcome disposition-counter set).

### Phase 5: Plugin API — extism tier first, JSON-RPC child-process tier as follow-on (parallelizable with Phase 4)
**Rationale:** Depends on Phase 1 only so read_span is built against the final segment-backed Span resolution. Low coupling to the crawler, so can run on a separate track.
**Delivers:** Capability-scoped hook API (extism/WASM), narrow declared-fields marshaling, bounded read_span, JSON-RPC child-process tier for Python plugins added once a concrete need is in front of the team.
**Uses:** extism 1.30 (wraps wasmtime), hand-rolled JSON-RPC framing for the IPC tier.
**Implements:** Pattern 3 (capability-scoped plugin boundary — headers by default, spans on request).
**Avoids:** Pitfall 4/7 (plugin as a fifth unaudited sender; no capability model to copy from Caido/ZAP/Burp — must be designed from scratch) and Anti-Pattern 3 (unbounded read_span as a store-enumeration sandbox escape).

### Phase 6: WebSockets
**Rationale:** Depends on Phase 1 for the same volume reason as the crawler; sequenced after Phases 4-5 so the on_exchange/plugin hook shapes accommodate one new record kind at a time.
**Delivers:** WsFrame lightweight record (not StoredMessage/MessageShape), WS capture + repeater, the related sidecar's first real consumer.
**Avoids:** Pitfall 5 (scope authorised once at Upgrade then unchecked for connection lifetime — requires an explicit design decision plus a new regression-test class) and Anti-Pattern 2 (reusing MessageShape for WS frames, which blows up per-record metadata overhead at scale).

### Phase 7: HTTP/2
**Rationale:** Sequenced after WebSockets specifically because both change the proxy's per-connection state machine; building WS first means that machine is generalized once, not twice. Per ARCHITECTURE's verdict, late h2 is not more expensive at the parse/span layer provided Pattern 2 (ingest-time normalization into canonical MessageShape) is the design and the related slot was built in Phase 1 — retrofitting a 1:N relation into an already-shipped 1:1-only index is the one thing that would make late h2 genuinely expensive, and this roadmap avoids it by construction.

**Flag the open disagreement explicitly (do not silently resolve it):** FEATURES research raises a real coverage cost to deferring h2 that ARCHITECTURE's "late is fine" verdict does not erase — an h1-only ALPN offer silently downgrades every h2-capable target, and downgrade-based testing changes the actual protocol behavior under test, which matters specifically for the smuggling/desync work this feature exists to support. Both conclusions are correct at their own layer (build-cost vs. coverage-cost) and the roadmap should name the interim coverage gap rather than treat "sequenced late" as free.
**Uses:** h2 0.4 with unstable scoped to one crate; open verification flagged in STACK (whether h2 unstable's frame constructors still block the specific malformations smuggling research needs) should be spiked before committing this phase's plan.

### Phase 8: Dashboard
**Rationale:** Depends on Phase 4 (crawl disposition counters) and Phase 5 (plugin events) for something real to surface.
**Avoids:** Pitfall 11 (dashboard/reporting collapsing "we stopped looking" into "we found nothing" — every summary tile needs a disposition breakdown, not just a positive-finding count).

### Phase 9: MCP server
**Rationale:** Last by design — it re-exposes the JSON API, so it should be built once that surface has stopped changing.
**Uses:** rmcp 2.2 mounted via StreamableHttpService onto the existing axum router.
**Avoids:** Pitfall 8 (indirect prompt injection via scanned/crawled content returned to an agent — always-escalate treatment for scope-widening/attack-launch/credential-read tools must be enforced server-side, drafted as part of this phase's design, not discovered after an incident).

### Phase 10: DOM/JS analysis
**Rationale:** Last per PROJECT.md, unchanged by this research — lowest priority, most slip-tolerant, thinnest competitive precedent.
**Uses:** boa_engine 0.21 (pure Rust, no DOM shim available off-the-shelf — budget for building one).
**Avoids:** Pitfall 9 (a JS engine's fetch() bypassing all Rust-side scope checks — must force all engine network egress through this project's own proxy with no alternate network path, decided as an architectural precondition before this phase starts).

### Phase Ordering Rationale

- The mmap store gates everything volume-related because it fixes a correctness bug (id-assignment race), not merely a performance one — shipping crawler/WS/h2 before it compounds a real bug, not just slow code.
- The related 1:N slot is designed into Phase 1 specifically so Phase 7 (HTTP/2) can stay deferred without becoming a retrofit — this is the concrete mechanism behind "late h2 is fine."
- Scope-enforcement discipline (Pitfall 4) is cross-cutting and should be settled architecturally before Phase 4 begins, since the crawler is the first new sender the milestone introduces; re-verify at Phase 5 (plugins) and Phase 9 (MCP).
- Session handling is pulled forward (Phase 3, ahead of its PROJECT.md position) because it is a dependency of Phase 4's live audit and crawler, not a peer feature.
- Reporting (part of Phase 2) is pulled forward because it has zero technical coupling to platform work, despite being grouped under "Platform" in PROJECT.md.

### Research Flags

Needs deeper research during planning:
- **Phase 1 (mmap store):** segment size/rotation policy for burpsy's actual traffic profile is unresolved (pattern is settled, the number is not).
- **Phase 5 (plugin API):** no peer tool (Caido/ZAP/Burp) documents an enforced capability/sandbox boundary at the plugin runtime — this must be designed from scratch, not copied; treat as needing its own focused design pass.
- **Phase 6/7 (WebSockets/HTTP/2):** the WS scope-semantics decision (what "authorised" means for a persistent connection) has no existing test to extend and needs explicit design before implementation.
- **Phase 7 (HTTP/2):** whether h2 unstable's frame constructors block the specific malformations the smuggling-research feature needs is an open, unverified question — needs a spike before the phase plan commits to a specific malformed-frame surface.
- **Phase 9 (MCP server):** exact rmcp feature names for the streamable-HTTP transport were not enumerated from primary source; confirm against docs.rs before writing into a plan. Also needs its own always-escalate tool classification drafted as part of the phase, informed by the single-source (LOW confidence) Burp MCP prompt-injection finding — verify that finding's specifics before relying on them.

Phases with standard, well-documented patterns (skip research-phase):
- **Phase 2 (tool-parity leftovers):** Intruder processing, Repeater tabs, Sequencer — established patterns, direct source in existing scanner/intruder crates.
- **Phase 8 (dashboard):** straightforward event-feed aggregation over already-existing disposition-counter patterns (AuditOutcome).

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | Crate versions verified directly against crates.io/GitHub source; architectural comparisons corroborated across multiple sources but not primary-source-exhaustive. No Context7-tier provenance was available in this environment. |
| Features | MEDIUM | HIGH where cross-checked against primary specs (SARIF OASIS spec, ZAP docs); several competitor claims (Caido HTTPQL field list, Caido plugin architecture) are single-source LOW and flagged as such. |
| Architecture | MEDIUM-HIGH on the store/segment design and the H2 build-order verdict (grounded directly in this codebase's own source, HIGH-confidence self-citations); MEDIUM on plugin-boundary specifics and WS/crawler integration (extrapolated, not yet built); LOW-MEDIUM on specific segment-size/lock-sharding numbers. |
| Pitfalls | MEDIUM overall; several individual claims are explicitly single-source LOW (Burp MCP prompt-injection specifics, absence of a documented BApp Store incident, absence of a ZAP sandbox model, Caido plugin SDK description) and must not be treated as established fact without independent verification. |

**Overall confidence:** MEDIUM

### Gaps to Address

- h2 unstable frame-constructor validation depth — not confirmed whether exposed constructors still block the specific malformations needed; needs a phase-7 spike (STACK Gap).
- Rhai per-message throughput at multi-GB capture scale — no benchmark found for this workload shape; needs measurement before sizing the Bambda phase, not just a sandboxing check (STACK Gap).
- mmap segment size/rotation policy — the pattern (fixed-size, sealed, never-remapped) is settled; the specific size number for burpsy's traffic profile is not (STACK Gap).
- Single-writer lock contention at ~100GB scale — flagged by ARCHITECTURE as a real second bottleneck once proxy+crawler+WS+plugin writes all append concurrently, explicitly out of scope for this milestone; name it now so it isn't rediscovered as a surprise later, do not build a sharded-lock design speculatively.
- Burp MCP indirect-prompt-injection specifics (credential leak PoC, missing config-read filtering) — single blog-post source; verify against Burp's actual MCP server changelog/code before a phase plan relies on the specific mechanism described.
- Absence of a documented plugin-sandbox model at any peer tool (Caido/ZAP/Burp) — this is a negative finding (search didn't surface one), not confirmation none exists; the Phase 5 capability model must be designed from first principles regardless, per PITFALLS' explicit conclusion.
- HTTP/2 sequencing coverage-cost disagreement — FEATURES and ARCHITECTURE reach different verdicts on whether "late h2" is cost-free (build-layer: yes, given the related slot; coverage-layer: no, given h1-only ALPN downgrades). Both are preserved above rather than resolved; the roadmapper should decide whether to name this gap in the Phase 7 description or accept it as a known, documented tradeoff.

## Sources

### Primary (HIGH confidence)
- crates/core/src/lib.rs, crates/proxy/src/lib.rs (direct reads) — confirmed O(n^2) scan, the id-assignment race, and absence of h2/WS handling
- .planning/codebase/ARCHITECTURE.md, .planning/codebase/CONCERNS.md (this repo) — current system baseline
- crates.io registry API, docs.rs (bytes::Bytes::from_owner, memmap2::Mmap trait list), GitHub source (hyperium/h2 Cargo.toml/lib.rs, modelcontextprotocol/rust-sdk Cargo.toml) — direct fetches for version/API claims
- SARIF 2.1.0 OASIS specification (docs.oasis-open.org)

### Secondary (MEDIUM confidence)
- extism.org PDK documentation (no Python PDK), ZAP Automation Framework docs (session handling shape), OWASP CSRF/MCP Tool Poisoning pages, Nuclei timeout/false-negative docs, rhai README/crates.io sandboxing primitives, Kafka segment-log design (multiple corroborating engineering blogs)
- Caido HTTPQL reference and plugin architecture docs (official but single-source per claim)

### Tertiary (LOW confidence — verify before phase planning relies on them)
- Burp MCP indirect-prompt-injection blog post (darkdrag0nite) — single source, specific claims need verification against Burp's own MCP changelog
- Absence-of-incident findings for BApp Store supply chain and ZAP's extension sandbox model — negative findings, not proof of absence
- Caido plugin SDK capability description, mitmproxy addon trust-model docs — single-ecosystem sources, not independently corroborated against third-party security analysis

---
*Research completed: 2026-07-27*
*Ready for roadmap: yes*
