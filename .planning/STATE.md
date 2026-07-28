---
gsd_state_version: '1.0'
status: planning
progress:
  total_phases: 12
  completed_phases: 1
  total_plans: 1
  completed_plans: 1
  percent: 8
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-27)

**Core value:** Run PortSwigger's published BCheck corpus, unmodified and honestly counted, against real traffic without the memory cost that forces Burp to discard scan work.
**Current focus:** Phase 2 — HTTP/2

## Current Position

Phase: 2 of 12 (HTTP/2) — Phase 1 complete
Plan: 0 of TBD in current phase
Status: Ready to plan
Last activity: 2026-07-28 — Phase 1 delivered: segmented mmap-backed store (STORE-01), two-mechanism verification plus `burpsy store verify` (STORE-05), and the `AuthorisedSender` chokepoint with a source-scan backstop (HARD-03). STORE-02/03/04 had landed earlier in the session. 438 workspace tests passing, 0 warnings.

Progress: [█░░░░░░░░░] 8%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: - min
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: -
- Trend: -

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work (made during roadmap creation, overriding research/SUMMARY.md's default build order):

- HTTP/2 moved to Phase 2 (before WebSockets and the plugin API), not after WebSockets as SUMMARY.md proposed — an h1-only ALPN offer silently downgrades every h2-capable target, which matters for the smuggling/desync research H2 exists to support. Trade-off accepted: the per-connection state machine generalises via H2 first, WebSockets (Phase 9) reuses it, rather than the reverse.
- Filter DSL (DSL-01..04) built as a typed query language (Phase 3), not `rhai`. `rhai`/scripting is explicitly Out of Scope. DSL-03 (crawl/audit scoping) is deferred in mapping to Phase 6, since it isn't observable until the crawler exists — the grammar itself ships in Phase 3.
- Sequencer (SEQ-01) deferred to v2 — no phase created for it this milestone.
- DOM analysis split into two phases: Phase 11 (static, DOM-01..03) and Phase 12 (dynamic confirmation, DOM-04..05). No embedded JS engine — dynamic confirmation drives a real browser instead.
- HARD-03 (shared scope chokepoint) carved out of the Hardening group and placed in Phase 1, settled architecturally before the crawler (Phase 6), the first new request-originating surface. HARD-01/02 remain a distinct Phase 7 gate, positioned once the tool is worth using (after proxy, scanner, H2, tool parity, session, crawler) rather than after all ten feature phases.

### Pending Todos

[From .planning/todos/pending/ — ideas captured during sessions]

None yet.

### Blockers/Concerns

None currently open.

**Corrected during Phase 1 execution (2026-07-28):**
- Phase 1's CONTEXT.md and RESEARCH.md both claimed that narrowing a crate's `tokio` features closes the async egress path *structurally*, leaving only `std::net` to be covered by a backstop test. Measured and false in this workspace: narrowing does fail an isolated `cargo build -p burpsy-intruder`, but cargo unifies features across the dependency graph, and `web`/`sender`/`cli` all enable tokio's `full` — so one tokio rlib is built with `net` present and any crate linking it can name `tokio::net` again. Verified by planting a `tokio::net::TcpStream::connect` in `intruder` and watching the workspace build succeed. Consequence: exactly one egress route is closed by the type system (the sender crate's `pub(crate)` transports), and `crates/sender/tests/no_alternate_egress.rs` is the *primary* mechanism for both `std::net` and `tokio::net`. Corrected in CONTEXT.md, the crate docs, and the test's own header.
- `01-RESEARCH.md` was written before commit `d8fe387` and describes the id-assignment race and the `related` slot as unbuilt. CONTEXT.md's "Already landed" note is authoritative where they disagree; Phase 1 treated STORE-02/03/04 as carry-forward verification rather than rebuilding them.

**Resolved during roadmap creation (2026-07-27):**
- REQUIREMENTS.md's summary line said "52 total v1 requirements" against an itemized list of 56 (the miscount traced to a regex that silently drops alphanumeric category prefixes like `H2-01` — reproduced independently before trusting the correction). Fixed; coverage re-verified at 56/56, 0 orphans, 0 duplicates.
- PROJECT.md was stale against this roadmap's operator decisions in four places (`rhai`, Sequencer, embedded JS engine, "HTTP/2 sequenced late"). Reconciled in commit `a3c9db8`, including logging the three roadmap-time decisions (HTTP/2 to Phase 2, DOM split into static/dynamic, scope chokepoint as a Phase 1 deliverable) to Key Decisions.

## Deferred Items

Items acknowledged and carried forward from previous milestone close:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Sequencer | SEQ-01 — token capture and entropy analysis | Deferred to v2 | Roadmap creation, 2026-07-27 |
| Scanner | SCAN-04 — hand-written active checks beyond the BCheck corpus | Deferred to v2 | Roadmap creation, 2026-07-27 |

## Session Continuity

Last session: 2026-07-27
Stopped at: ROADMAP.md and STATE.md written; REQUIREMENTS.md traceability update pending in same session
Resume file: None
