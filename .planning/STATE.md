---
gsd_state_version: '1.0'
status: executing
progress:
  total_phases: 12
  completed_phases: 6
  total_plans: 1
  completed_plans: 1
  percent: 50
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-27)

**Core value:** Run PortSwigger's published BCheck corpus, unmodified and honestly counted, against real traffic without the memory cost that forces Burp to discard scan work.
**Current focus:** Go port is the active development line. Rust is stable/frozen at 1,032 tests, 13 crates. Phases 6 (crawler + dashboard) and 11 (DOM static analysis) delivered in Go; MCP and plugins next.

## Two codebases — read this first

This repo holds **two implementations** of the same system:

| | Rust (`crates/`) | Go (`burpsy-go/`) |
|---|---|---|
| Role | Reference implementation, stable | **Active development line** |
| Crates/packages | 13 | 24 |
| Tests | 1,032 | 1,029 |
| Last change | 2026-07-28 | 2026-08-05 (today) |
| Status | Feature-complete; no active work | All 13 Rust-parity gaps closed; Phases 6, 11 delivered |

The Rust tree proved the architecture. The Go port is where new features land. Planning docs
(REQUIREMENTS.md, ROADMAP.md) describe capabilities that are now split across both; the traceability
table names which requirement is satisfied in which language. When a requirement says "Complete" without
qualification, it is complete in **both** unless the table says otherwise.

## Gate

Last full verification run:

| Check | Rust | Go |
|---|---|---|
| Build (warnings count as failure) | **PASS** — zero warnings | **PASS** — `go build ./...` clean |
| Linter | **PASS** — clippy clean | **PASS** — `go vet ./...` clean |
| Unit tests | **PASS** — 1,032 passing | **PASS** — 1,029 passing |
| BCheck corpus conformance | **SKIP** — `/tmp/BChecks` absent | **SKIP** — same |
| e2e-audit.sh | **PASS** | — |
| e2e-intercept.sh | **PASS** | — |
| e2e.sh | **PASS** | — |
| e2e-tls.sh | **PASS** | — |
| e2e-scan.sh | **SKIP** — needs corpus | — |

Verdict: **VERIFIED WITH GAPS (2 skipped)** — both skips are the missing corpus, reported honestly.

## Where each phase stands

- **Phase 1 — Store & Scope: COMPLETE** (Rust + Go). Runtime-editable scope, single egress chokepoint.
- **Phase 2 — HTTP/2: COMPLETE** (Go; Rust partial). Relay, egress, raw-frame crafting, ALPN all landed in Go.
- **Phase 3 — Query DSL & Tool Parity: COMPLETE** (Rust + Go).
- **Phase 4 — Reporting & Scanner Data: COMPLETE** (Go; Rust partial — SCAN-03 selector missing). Catalog, Retire.js, JWT, HTML/JSON/SARIF reports all in Go.
- **Phase 5 — Session: COMPLETE** (Rust + Go).
- **Phase 6 — Crawler & Dashboard: COMPLETE** (Go only — not in Rust). Crawler (5,834 LOC) with frontier, link/form extraction, destructive-action refusal, crawl limits; Dashboard (1,750 LOC) with task progress, event log, disposition breakdown.
- **Phase 7 — Hardening: COMPLETE** (Go; Rust partial). HARD-01 review closed, four criticals fixed, sender egress path closed (HARD-03).
- **Phase 8 — Plugin API: NOT STARTED** (neither language).
- **Phase 9 — WebSockets: PARTIAL** (Rust + Go). Capture + scope done; interception/resend deferred.
- **Phase 10 — MCP: COMPLETE** (Go only — not in Rust). `cmd/mcp/` binary, stdio transport, 18 tools. Tested end-to-end with mcporter.
- **Phase 11 — DOM Static Analysis: COMPLETE** (Go only — not in Rust). Source-to-sink taint, 3,196 LOC, wired into live scan.
- **Phase 12 — DOM Dynamic (browser confirmation): NOT STARTED** (neither language).

## What changed since the last state file

| Area | What changed | Commit |
|---|---|---|
| Go port (all 13 gaps) | Full Rust-parity port: HTTP/2, scanner catalog + coverage + audit engine, Retire.js, JWT, intruder engine + web handlers, sequencer report, RequestEdit, segment CRC32, BCheck builtins, comparer budget, session coordinator, query DSL | `017b81e`..`4c087b2` |
| Go: Crawler + Dashboard | Frontier, link/form extraction, destructive-action refusal, limits; task progress, event log, breakdown | `d492ad6` |
| Go: DOM static analysis | Source-to-sink taint, wired into live scan | `4dccc5d`, `76169db` |
| Go: Hardening | HARD-01 review — four criticals fixed; sender unauthorized egress closed (HARD-03) | `c39c4a9`, `9a2c84a`, `bc6e68f` |
| Go: UI | Live updates, row actions, `/ca.crt` route; capture attribution on handle | `3f1c0f4`, `a77a356` |
| Go: Tests | JWT weak-signature tests, retire.js content prefilter, empty audit batch pin | `775d074`, `79db733`, `fc34beb` |
| Go: MCP Server | 18-tool MCP server (`cmd/mcp/`), mark3labs/mcp-go, stdio transport, scope-enforced | this session |

## Next steps, in recommended order

1. **Commit the 30+ dirty Go files** in the working tree — they are Phase 6/11 polish and new tests, currently uncommitted.
2. **Plugin API (Phase 8)** — largest remaining architectural decision (WASM vs JSON-RPC). Required before SEQ-01's originally-envisioned plugin dogfooding.
3. **SCAN-03 selector** — backend and data exist in both languages; needs an operator-facing pick (CLI flag or API route).
4. **H2-03/H2-04 exposure** — `send_h2_program` exists in Go but nothing calls it; add a UI surface for malformed-frame research.
5. **DOM dynamic confirmation (Phase 12)** — real-browser verification of static candidates.
7. **Tag a release** — `v0.1.0` is in Cargo.toml but no git tag exists; the CI workflow builds on `v*`.

## Blockers/Concerns

**Open, and deliberately not hidden:**
- **`/tmp/BChecks` absent.** BCheck conformance + `e2e-scan.sh` skip. Both report as skips, not passes.
- **Uncommitted Go work.** 30+ files modified, 5 untracked (new tests, syntax highlighter, theme). Ready to commit.
- **`.codebase-memory/` (~3 MB binary) committed to git.** Rewritten on every re-index.
- **`target/` is ~38 GB.** Build artifact bloat, not a correctness issue.

**Resolved since the last state file:**
- All 13 Rust-parity gaps in Go: **closed**.
- Phases 6 and 11: **delivered** in Go.
- HARD-01 review: **closed** (four criticals fixed).

## Running instance

No instance is running as of this revision.

- **Rust:** `cargo run -p burpsy-cli -- --web 127.0.0.1:8081 --proxy 127.0.0.1:8090 --bchecks /tmp/BChecks`
- **Go:** `cd burpsy-go && go run ./cmd/burpsy --web 127.0.0.1:8081 --proxy 127.0.0.1:8090 --bchecks /tmp/BChecks`

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Scanner | SCAN-04 — hand-written active checks beyond BCheck | Deferred to v2 | Roadmap creation, 2026-07-27 |
| DSL | DSL-03 — crawl/audit scoping | Deferred to Phase 6 | Roadmap creation, 2026-07-27 |
| WebSockets | WS-02 (interception/resend), WS match-and-replace | Deferred within Phase 9 | 2026-07-30 |
| Sequencer | Live-capture loop (background start/poll/stop) | Stub in Go | Gap 7 closed 2026-08-04 |

## Session Continuity

Last session: 2026-08-05 (Go port gap closures, Phase 6, Phase 11, hardening)
This session: 2026-08-05 (documentation refresh)
Resume file: None — start from "Next steps" above.
