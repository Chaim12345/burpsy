# burpsy

## What This Is

A Rust reimplementation of Burp Suite's core — intercepting proxy, scanner, Repeater and
Intruder — specified from a teardown of the shipped Burp 2026.7.1 jar rather than from its
documentation. It is for security testers who want Burp's capabilities without Burp's memory
footprint and Swing latency, usable headless or over SSH.

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
- ✓ BCheck interpreter M1–M3 — 232 of 264 published checks run (87.9%) — Phase 3
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
- [ ] Sequencer — token capture and entropy analysis
- [ ] Crawler — frontier, link and form extraction, crawl limits
- [ ] Live passive crawl and live audit fed from proxy traffic
- [ ] Scanner data: RetireJS, the JWT secret wordlist, and the 29 built-in scan configs

**Platform (Phase 4)**
- [ ] mmap-backed store — the payoff of the offset design; makes multi-GB captures viable
- [ ] WebSockets — capture, history, WS repeater
- [ ] Plugin API — WASM or a JSON-RPC child process, deliberately not an embedded JVM
- [ ] Bambda-style filter expressions — evaluate `rhai` rather than inventing a language
- [ ] Session handling — macros, recorded logins, cookie jar, re-auth on session loss
- [ ] Reporting — HTML/JSON/SARIF backed by the issue catalog
- [ ] Dashboard — task list, progress, event and activity logs

**Agent surface (Phase 5)**
- [ ] MCP server exposing the existing JSON API — near-free, makes the tool agent-drivable

**Engagement readiness**
- [ ] Hardening pass — must precede any use on a real engagement (see Constraints)

**Deferred within this milestone, by sequence**
- [ ] HTTP/2 — first-class h2 including deliberately malformed frames; sequenced late
- [ ] DOM/JS analysis — needs an embedded JS engine; sequenced last

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

**Known debt carried in.** `TrafficStore::set_response` is a linear scan, so bulk-filling responses
is O(n²) — this is the concrete driver behind the mmap store. The corpus coverage test returns
early when `/tmp/BChecks` is absent, so on a machine without the fixture the partition invariant is
silently unchecked while the test still reports success.

**How the code was written.** Most of it by parallel agents merged on a `verify.sh` pass rather
than a line-by-line human read. A review of two of six merged branches found three defects that
385 passing tests did not catch, including a scope fail-open. Three branches remain unreviewed.

## Constraints

- **Tech stack**: Rust, edition 2024, Cargo workspace of 9 crates — chosen for the memory control
  the whole project depends on.
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
| Checks are data, not code — run the published BCheck corpus rather than porting Java | One interpreter inherits 264 checks; porting would be derivative work | ✓ Good — 232/264 run |
| Store each message once as bytes plus span offsets | Burp's memory model is the problem being solved; copying anywhere undoes it | ✓ Good |
| Web UI rather than a native GUI | Burp's perceived slowness is largely Swing; also enables headless and SSH use | — Pending |
| Collaborator gated and counted, never stubbed | A fake address nothing polls turns 26 OOB checks into silent false negatives | ✓ Good |
| Scope authorised on outgoing bytes, not the named target | Closed a confirmed fail-open where a payload rewrote the path onto an excluded prefix | ✓ Good |
| Active scanning is only ever operator-triggered | It generates traffic; making it automatic would send unrequested probes | ✓ Good |
| Root `ROADMAP.md` frozen as the historical and teardown reference | `.planning/ROADMAP.md` drives forward work; different spans, so the two cannot diverge | — Pending |
| HTTP/2 sequenced late, DOM/JS analysis last | h2 reaches into core, proxy and capture; DOM/JS adds a JS engine. Both destabilise in-flight work | — Pending |

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
*Last updated: 2026-07-27 after initialization*
