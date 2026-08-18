# burpsy

> **Reading note (added 2026-08-17).** This is the GSD planning record, authored against the
> original **Rust** implementation (`crates/`) and its 12-phase roadmap. Since then the project's
> active implementation has moved to the **Go** port in `burpsy-go/`; the Rust tree is now a
> frozen parity reference. Treat the phase/requirement tracking below as the Rust-era plan of
> record — accurate as history — and read the Go port's live status from `burpsy-go/gaps.md`,
> `burpsy-go/PORT_STATUS.md`, and the dated `burpsy-go/docs/HANDOFF-*.md`. Where a count below
> (crate totals, BCheck coverage) disagrees with those, they win.

## What This Is

A reimplementation of Burp Suite's core — intercepting proxy, scanner, Repeater and
Intruder — specified from a teardown of the shipped Burp 2026.7.1 jar rather than from its
documentation. It is for security testers who want Burp's capabilities without Burp's memory
footprint and Swing latency, usable headless or over SSH. Originally written in Rust
(`crates/`); now being ported to Go (`burpsy-go/`), which is where active work lands.

## Core Value

Run PortSwigger's published BCheck corpus, unmodified and honestly counted, against real traffic
without the memory cost that forces Burp to discard scan work.

## Requirements

### Validated

<!-- Shipped and confirmed working. Inferred from the codebase map and the test suite. -->

- ✓ Append-only traffic store, offset-based — a parsed message costs ~100 bytes regardless of body size — Phase 0
- ✓ Tolerant HTTP parser (CRLF and bare LF) — malformed traffic is the subject, not an error — Phase 0
- ✓ Intercepting HTTP proxy with full capture, target rewritten and all other bytes preserved — Phase 0
- ✓ TLS interception: CA generation, SNI-driven per-host leaf signing, MITM tunnel, passthrough list — Phase 1
- ✓ Failed CONNECT attempts recorded, so "unreachable" is distinguishable from "never visited" — Phase 1
- ✓ Scope engine, include/exclude, authorised against the request actually sent — Phase 2
- ✓ Site map as a derived, incrementally-folded view over history (~1000:1 vs full rebuild) — Phase 2
- ✓ Request interception: hold, edit, forward, drop, without blocking other connections — Phase 2
- ✓ Repeater, byte-exact send over raw TCP — Phase 0
- ✓ Insertion-point engine, 8 types, mirroring Burp's taxonomy — Phase 0
- ✓ Intruder: sniper, battering ram, pitchfork and cluster bomb, lazily generated, behind a rate limiter — Phase 2
- ✓ Supporting tools: Decoder, Comparer, Logger, Organizer, match-and-replace — Phase 2
- ✓ Passive scanning over proxied responses, off the proxy hot path — Phase 3
- ✓ BCheck interpreter M1–M3 (the "232 of 264" once cited here conflated parse rate with runtime coverage; the Go port reports the two separately — see burpsy-go/docs/BCHECK-COVERAGE.md) — Phase 3
- ✓ Audit engine: 7 dispatch scopes, item state machine, two-level circuit breakers — Phase 3
- ✓ Burp's 183-issue catalog, mechanically transcribed and byte-reproducible — Phase 3
- ✓ Issue dedup keyed on (check, issue name, host), occurrences capped with an uncapped true count — Phase 3
- ✓ JSON API and a single-page web UI with no build step — Phase 0

### Active

<!-- This milestone: everything remaining except Collaborator. -->

**Tool parity leftovers (Phases 2–3)**
- [ ] Intruder payload processing — prefix/suffix, case, encode/hash, match-replace; load Burp's own `.pay` lists
- [ ] Intruder grep-match and grep-extract — flag and extract patterns into a result column
- [ ] Proxy history filters — host, status, method, MIME, search
- [ ] Repeater tabs — multiple named tabs with per-tab history and connection control
- [ ] Crawler — frontier, link and form extraction, crawl limits
- [ ] Live passive crawl and live audit fed from proxy traffic
- [ ] Scanner data: RetireJS, the JWT secret wordlist, and the 29 built-in scan configs

**Platform (Phase 4)**
- [ ] mmap-backed store — the payoff of the offset design; makes multi-GB captures viable
- [ ] WebSockets — capture, history, WS repeater
- [ ] Plugin API — WASM or a JSON-RPC child process, deliberately not an embedded JVM
- [ ] A typed query DSL (Caido HTTPQL shape) shared by history filters, match-and-replace, and crawl/audit scoping — not `rhai`; a general scripting language reproduces Bambda's own authoring problem (slow to author, unindexable) rather than fixing it
- [ ] Session handling — macros, recorded logins, cookie jar, re-auth on session loss
- [ ] Reporting — HTML/JSON/SARIF backed by the issue catalog
- [ ] Dashboard — task list, progress, event and activity logs

**Agent surface (Phase 5)**
- [ ] MCP server exposing the existing JSON API — near-free, makes the tool agent-drivable

**Engagement readiness**
- [ ] Hardening pass — must precede any use on a real engagement (see Constraints)

- [ ] HTTP/2 — first-class h2 including deliberately malformed frames for smuggling research; sequenced early (Phase 2, ahead of WebSockets and the plugin API) — an h1-only ALPN offer silently downgrades every h2-capable target, which costs real coverage for the smuggling/desync work this feature exists to support
- [ ] DOM analysis, static — source-to-sink taint over the 48 catalogued DOM-based issue types; Burp's own scanner does this statically too (`max_static_time_per_item`), no embedded JS engine
- [ ] DOM analysis, dynamic confirmation — a real headless browser drives a canary marker through each static candidate and confirms or reports it UNCONFIRMED, mirroring Burp's DOM Invader; sequenced last

### Out of Scope

- **Collaborator / out-of-band interaction server** — needs a publicly resolvable domain and a
  reachable DNS/HTTP listener. That is infrastructure, not code, and none is available. The 26
  corpus checks that depend on it stay gated and *counted*; stubbing an address nothing polls
  would convert all 26 into silent false negatives, which is worse than not running them.
- **Native desktop GUI** — the web UI is the point; Burp's perceived slowness is largely Swing,
  and a browser front end also works headless and over SSH.
- **Recompiling or patching Burp itself** — only ~53% of the decompiled tree compiles, and the
  result would be a derivative build.
- **Porting Burp's Java scan-check code** — derivative work. Implement from the specs and the
  public BCheck/Montoya contracts instead.
- **Enterprise/CI features** — Enterprise-only in the product being studied.
- **Sequencer (token entropy analysis)** — deferred to v2. Neither Caido nor ZAP ships it in
  core, both as an add-on; becomes the natural first dogfood of the plugin API once it exists.
- **`rhai` (or any general scripting language) for Bambda-style filters** — reproduces Bambda's
  actual failure (slow to author, unindexable) in different syntax. A small typed query DSL,
  shared across filters, match-and-replace, and crawl/audit scoping, replaces it.
- **An embedded JavaScript engine for DOM analysis** — Burp does not have one either: its
  `javascript_analysis` scan type is static (`max_static_time_per_item`), and its Chromium is a
  separate embedded-browser subsystem (`burp browser`), not part of the scanner. An engine would
  add a dependency, need a hand-built DOM shim, and let `fetch()` escape every scope check, for
  no parity gain. Dynamic confirmation drives a real browser instead.

## Context

**Where the specification comes from.** The design is derived from a teardown of the shipped Burp
2026.7.1 jar at `/root/burp-re/` — 19,309 readable decompiled files plus `FINDINGS.md`,
`SCAN_ENGINE.md`, `SCANNER_MAP.md` and `UI_BACKEND_MAP.md`. The tree is ZKM-obfuscated, so classes
are located by their recovered string constants rather than by name; `Zpa0`/`Zpao` (the BCheck
execution context) were identified from surviving lambda synthetics. Behaviour is taken from it;
implementation is not.

**The corpus is an oracle, not a fixture.** `/tmp/BChecks` holds PortSwigger's 264 published
checks. The test suite uses them to verify the parser accepts all 264 and captures 381 modifier
clauses, cross-checked against an independent grep. That is what stops a coverage claim drifting
from what the evaluator actually executes.

**Codebase map.** `.planning/codebase/` — seven documents written 2026-07-27.

**Research and roadmap.** `.planning/research/` — STACK, FEATURES, ARCHITECTURE and PITFALLS,
synthesized into SUMMARY.md, all 2026-07-27. `.planning/REQUIREMENTS.md` (56 v1 requirements) and
`.planning/ROADMAP.md` (12 phases) were derived from it, with four operator decisions overriding
the research's default build order — see Key Decisions.

**Known debt carried in.** `TrafficStore::set_response` is a linear scan, so bulk-filling responses
is O(n²) — this is the concrete driver behind the mmap store (Phase 1). Architecture research
found a second, subtler defect while reading the current code: `put()`/`add_exchange()` assign a
message's id from an atomic counter, then do variable-duration parse work with no lock held, then
push — so two concurrent captures can push out of id order. Currently latent (every lookup scans
by id, so nothing returns the wrong message *today*), but the mmap migration replaces those scans
with an id→location index, and the obvious `position == id` implementation would silently break
under this race — returning the wrong message rather than an error, which in a security tool means
a finding attributed to the wrong request. STORE-03 exists because of this. The corpus coverage
test returns early when `/tmp/BChecks` is absent, so on a machine without the fixture the partition
invariant is silently unchecked while the test still reports success — HARD-02 exists because of
this.

**How the code was written.** Most of it by parallel agents merged on a `verify.sh` pass rather
than a line-by-line human read. A review of two of six merged branches found three defects that
385 passing tests did not catch, including a scope fail-open. Three branches remain unreviewed.

## Constraints

- **Tech stack**: originally Rust (edition 2024, a Cargo workspace of 13 crates — not 9, as an
  earlier draft of this line said); now the active implementation is the Go port under
  `burpsy-go/` (module `github.com/burpsy-go/burpsy`, `go 1.26`), with the Rust tree kept as a
  frozen parity reference. Both were chosen for the memory control the whole project depends on.
- **Performance**: a message is stored once as bytes plus span offsets; never clone a body. Every
  subsystem is judged against this, because it is the reason the project exists.
- **Security**: scope is authorised against the bytes actually going on the wire, never against the
  target that was named. A payload in a path position, or a BCheck `replacing path:`, can move a
  request onto an excluded path.
- **Security**: bounds must be observable. Work may be limited, but a limit that is applied without
  being reported turns "we stopped looking" into "we found nothing".
- **Compatibility**: run PortSwigger's published BCheck corpus unmodified.
- **Tooling**: the Rust toolchain here is split — `/usr/bin/cargo` (1.92) shadows rustup (1.95) in
  PATH, and `clippy-driver` exists only under rustup. `verify.sh` pins both `cargo` and `RUSTC` and
  gives clippy its own target directory; a naive `cargo clippy` fails with E0514.
- **Legal**: no porting of Burp's Java implementation. Semantics and taxonomies only, cited in
  comments where they informed a decision.
- **Process**: a hardening pass must precede any use on a real authorised engagement — line-by-line
  review of the three unreviewed branches, and making the corpus invariant fixture-independent.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Checks are data, not code — run the published BCheck corpus rather than porting Java | One interpreter inherits 264 checks; porting would be derivative work | ✓ Good — corpus parses; runtime coverage counted separately (burpsy-go/docs/BCHECK-COVERAGE.md) |
| Store each message once as bytes plus span offsets | Burp's memory model is the problem being solved; copying anywhere undoes it | ✓ Good |
| Web UI rather than a native GUI | Burp's perceived slowness is largely Swing; also enables headless and SSH use | — Pending |
| Collaborator gated and counted, never stubbed | A fake address nothing polls turns 26 OOB checks into silent false negatives | ✓ Good |
| Scope authorised on outgoing bytes, not the named target | Closed a confirmed fail-open where a payload rewrote the path onto an excluded prefix | ✓ Good |
| Active scanning is only ever operator-triggered | It generates traffic; making it automatic would send unrequested probes | ✓ Good |
| Root `ROADMAP.md` frozen as the historical and teardown reference | `.planning/ROADMAP.md` drives forward work; different spans, so the two cannot diverge | — Pending |
| HTTP/2 moved to Phase 2, ahead of WebSockets and the plugin API | Research argued late-h2 is cost-free at the build layer given a `related` slot designed in early; but h1-only ALPN silently downgrades every h2-capable target, costing real coverage for the smuggling/desync work h2 exists for. Coverage won over build-cost | — Pending |
| DOM/JS analysis split into a static phase (11) and a separate dynamic-confirmation phase (12) | Static and dynamic have opposite failure modes (false positives vs. false negatives); the literature and Burp's own design (static scanner + DOM Invader) both run both. Static proposes, dynamic confirms; an unconfirmed candidate is reported as such, never dropped, never asserted | — Pending |
| Scope chokepoint (`authorise_request`) is a Phase 1 deliverable, settled before the crawler | Every new request-originating surface (crawler, session macros, plugins, MCP, browser) can reintroduce the fail-open already fixed once; the crawler is the first new one this milestone adds | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-07-27 after roadmap creation (reconciled against 4 operator scope decisions made during research and roadmapping)*
