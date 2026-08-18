---
gsd_state_version: '1.0'
status: executing
progress:
  total_phases: 12
  completed_phases: 4
  total_plans: 1
  completed_plans: 1
  percent: 33
---

> **Dated banner — 2026-08-18.** Everything below was authored against the **Rust**
> tree and describes the Rust-era phase plan. The Go port in `burpsy-go/` is now the
> active implementation and has moved far past this file: all thirteen Rust↔Go parity
> gaps in `burpsy-go/gaps.md` are COMPLETE, and the per-phase status this file records
> ("Phases 6, 8, 10–12 not started") is not the Go tree's state — the crawler and
> dashboard (Phase 6) are built in Go, while the plugin API and MCP server (Phases 8,
> 10) are deliberately not shipped there. The authoritative Go-port status lives in
> `.planning/GO-PORT.md`, `burpsy-go/PORT_STATUS.md`, `burpsy-go/gaps.md`, and the
> dated `burpsy-go/docs/HANDOFF-*.md` (latest: `burpsy-go/docs/HANDOFF-2026-08-18.md`).
> This file is retained as the historical planning record.

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-27)

**Core value:** Run PortSwigger's published BCheck corpus, unmodified and honestly counted, against real traffic without the memory cost that forces Burp to discard scan work.
**Current focus:** Phases 1, 3, 5, 7 complete. Phases 2, 4, 9 partial. Phases 6, 8, 10–12 not started.
Phase 4 is "substantially delivered" (SCAN-03 lacks only an operator-facing selector). The Burp
feature-parity backlog described in the previous state file is fully merged, committed, and pushed;
what remains open is listed in "Next steps".

## Read this first

**The previous "Read this first" — "Nothing from this session is committed. HEAD is still `ac1ce4a`"
— is obsolete.** Every item it described as uncommitted working-tree state has since been committed
(29 commits, `be69143`..`b647a34`), pushed, and is in sync with `origin/master`. The planning docs
that drifted (REQUIREMENTS.md checkboxes, ROADMAP.md's progress table) were reconciled against the
code in `90933a7`, `18a1fdb`, and `64046a5`; this file's own claims are refreshed in this revision.

The one gate gap that matters is external, not code: **`/tmp/BChecks` (the 264-check PortSwigger
corpus) is absent from this machine**, so the BCheck conformance suite and `e2e-scan.sh` report
SKIP rather than PASS (correctly, per HARD-02). Everything that can run on this machine does pass —
see "Gate" below.

## Gate

Full `./verify.sh` run fresh on 2026-08-02:

| Check | Result |
|---|---|
| Build (warnings count as failure) | **PASS** — clean, zero warnings |
| Clippy | **PASS** — clean |
| Unit tests | **PASS** — 1032 passing (up from 438 when the root AGENTS.md was written) |
| BCheck corpus conformance | **SKIP** — `/tmp/BChecks` absent (partition invariant UNVERIFIED here) |
| e2e-audit.sh | **PASS** — 15 passed, 0 failed |
| e2e-intercept.sh | **PASS** — 24 passed, 0 failed |
| e2e.sh | **PASS** — 12 passed, 0 failed |
| e2e-tls.sh | **PASS** — 15 passed, 0 failed |
| e2e-scan.sh | **SKIP** — needs the same corpus |

Verdict: **VERIFIED WITH GAPS (2 skipped)** — the two skips are both the missing corpus, and both
report as skips, not passes. Placing the corpus at `/tmp/BChecks` closes the only open gate items.

## What the previous session actually was (2026-07-30, now committed)

Not roadmap-phase execution. An audit comparing burpsy against real Burp Suite produced a 19-item
gap-fix backlog (tasks #5–#21), fanned out to parallel agents (some in isolated git worktrees), then
merged back into the main tree one at a time with full-suite verification between each merge. Several
items map onto v1 requirements; several — runtime-editable Scope, conditional proxy intercept rules,
the Sequencer's FIPS 140-2 analysis — map onto nothing in REQUIREMENTS.md and were built as direct
Burp-parity items. Operator decision still open: fold them into REQUIREMENTS.md as first-class
entries, or keep the Burp-parity backlog alongside the roadmap.

SEQ-01 (Sequencer) shipped ahead of its stated dependency (PLUGIN-01) because the audit scoped it
directly; that is noted in REQUIREMENTS.md rather than silently treated as satisfying the original
deferral reasoning.

## What committed since the last state file (be69143..b647a34)

| Area | What changed | Commit |
|---|---|---|
| Web UI foundation | Bun+TypeScript UI serving (was an inline HTML/JS string) | `491dae5` |
| Repeater (TOOLS-04) | Numbered tab strip, independent state per tab | `be69143` |
| Scanner | Per-finding advisory detail panel, cross-tab jump to History | `b9b68ae` |
| History / Logger | Client-side filter bar; backend `q` free-text filter | `0b662f8`, `32cd295` |
| Site map | Filter bar, capped per-node exchange list (cap 200), per-node findings | `e6434ef` |
| Match & Replace | Rule table + live preview; later **wired into live proxy traffic** (was dry-run only) | `fc0b2db`, `220daa9` |
| Decoder | Hash actions (MD5/SHA1/SHA256/SHA512) + hex view toggle | `ce771c5` |
| Comparer | Next/prev hunk navigation | `0ab9a49` |
| Intruder (TOOLS-01/02/03) | All 4 attack modes in the UI; payload generators, processing rule chain, grep-match/grep-extract, resource-pool auto-throttle; `.pay` load | `4c25e2b`, `d31c70f`, `d9dd16b` |
| Session (SESSION-01..04) | Macro → scoped rule list, `{{name}}` extraction, update-macro retest, production coordinator | `4822fad`, `141262a`, `6e7ab42` |
| WebSockets (WS-01, WS-03) | RFC 6455 capture/history, per-message scope re-check; UI History tab | `4e4a6ca`, `d9dd16b` |
| Sequencer (SEQ-01) | New crate: FIPS 140-2 suite + character entropy | `6777f95` |
| Scope (not in REQUIREMENTS.md) | `Arc<Scope>` → runtime-editable `SharedScope` across the workspace | `32053ea` |
| Proxy intercept rules (not in REQUIREMENTS.md) | Conditional request/response holding; response-hold is a new capability | `921ee8f` |
| Query DSL (DSL-01/02/04) | Typed grammar crate wired into history filters + match-and-replace | earlier, reconciled in `90933a7` |
| HTTP/2 (H2-01/02, H2-03/04 partial) | Relay h2 instead of record-and-close; Repeater h2 resend; honest ALPN; literal HPACK encoder; shared renderer; authorised h2 egress | `c5d00eb`, `5f5b2ab`, `c57a052`, `5f136e3`, `9f10e13`, `18a1fdb` |
| E2E | Fix scripts killing their own process group; verify a live scope edit on an open WS connection | `a5fd498` |
| CI | Release workflow: 3-OS matrix, builds + attaches binaries to GitHub Releases on `v*` tags | `b647a34` |
| Planning | Reconcile STATE/REQUIREMENTS/ROADMAP with the merges | `90933a7`, `18a1fdb`, `64046a5` |

Two merges needed manual reconciliation rather than a clean patch apply: `crates/web/src/lib.rs`
(three tasks touched `AppState`/the router ladder) and `crates/proxy/src/lib.rs` (the WebSocket
relay and the response-hold logic both modify `forward_http`/`mitm`). Both were verified by a full
green test run afterward.

## Where each phase actually stands

- **Phase 1 — Store & Scope: COMPLETE.** `Scope` itself gained runtime mutation; the chokepoint
  property (one path to a socket) is untouched.
- **Phase 2 — HTTP/2: PARTIAL.** H2-01/H2-02 complete (relay, history parity, authorised Repeater
  resend). H2-03/H2-04 partial: the malformed-frame program path exists and can be sent via the
  library, but nothing in `web`/`intruder` calls `send_h2_program` yet; and Scanner/Intruder egress
  is still HTTP/1.1-only — the proxy negotiates h2 and Repeater sends h2, but "the tool uses it"
  is not yet true for active scanning or Intruder attacks.
- **Phase 3 — Query DSL & Tool Parity: COMPLETE.** DSL-01/02/04, TOOLS-01/02/03/04 all done.
- **Phase 4 — Reporting & Scanner Data: SUBSTANTIALLY DELIVERED.** REPORT-01..04, SCAN-01/02 done.
  SCAN-03 partial: `BuiltInConfig` transcribes the 6 of Burp's 29 shipped scan configs that set a
  key this engine implements, but nothing operator-facing selects one (`cli` only ever constructs
  `AuditConfig::default()`).
- **Phase 5 — Session: COMPLETE**, with the rule-list rewrite under an already-satisfied
  requirement.
- **Phase 6 — Crawler & Dashboard:** not started. Two salvageable skeleton crates
  (`crates/crawler/` 230 LOC, `crates/browser/` 233 LOC) exist stranded in the abandoned
  `.swarm/worktrees/browser-crawler` worktree — not merged, not on master.
- **Phase 7 — Hardening: COMPLETE.**
- **Phase 8 — Plugin API:** not started.
- **Phase 9 — WebSockets: PARTIAL.** WS-01/03 done; WS-02 (edit and resend a frame) needs
  interception, deliberately deferred with the entry point and a documented trap
  (`Reassembler` truncates — build a `FrameSplitter` first) in `crates/proxy/AGENTS.md`.
- **Phases 10–12 (MCP, DOM static, DOM dynamic):** not started.

## Next steps, in the order I would take them

1. **Place the BCheck corpus at `/tmp/BChecks`.** It is the only thing between this tree and a
   fully green `verify.sh`; without it the conformance suite and `e2e-scan.sh` stay SKIPped.
2. **SCAN-03 selector** — a CLI flag or API route that names one of the transcribed `BuiltInConfig`s.
   Backend and data are done and tested; only the operator-facing pick is missing.
3. **H2-03 exposure** — a UI/API surface that calls `AuthorisedSender::send_h2_program`. The library
   can send malformed programs; nothing lets an operator.
4. **H2-04's remaining leg** — make Scanner and Intruder egress call `send_h2` so active scanning
   and attacks honour an h2-capable target.
5. **Recover or prune the crawler skeletons** in `.swarm/worktrees/browser-crawler` — they are
   Phase 6's seed and are currently stranded off-master.
6. **Phase 6** (crawler + dashboard) is the largest not-started phase and the next one the roadmap
   ordering wants; it also closes CRAWL-01..07, DASH-01..03, and DSL-03.
7. **Clean up merged worktrees and branches** — see Blockers/Concerns.
8. **Decide** whether Scope-runtime-editing and conditional intercept rules get REQUIREMENTS.md
   entries (real, tested capabilities with no requirement ID today).

## Blockers/Concerns

**Open, and deliberately not hidden:**
- **`/tmp/BChecks` absent.** BCheck conformance + `e2e-scan.sh` skip on this machine. The two skips
  are the only non-green gate items.
- **Leftover worktree/branch clutter.** Merged worktrees still registered: `.worktrees/h2-egress`,
  `.worktrees/h2-mitm`, and 6 `.claude/worktrees/agent-*`. `worktree-agent-a18e24e6…` is unmerged but
  contains only a baseline snapshot (safe to delete). `.worktrees/` is untracked (gitignored).
- **Stranded crawler work.** `.swarm/worktrees/browser-crawler` (detached at `ac1ce4a`) holds the
  only copies of `crates/crawler/` and `crates/browser/` plus their `Cargo.toml` member entries.
- **`.codebase-memory/` (~3 MB binary) committed to git.** Rewritten on every re-index; the working
  tree shows it modified right after each index. Carried forward, unresolved.
- **`target/` is ~38 GB.** Build artifact bloat, not a correctness issue.
- **Three newer crates (`http2`, `query`, `session`) shipped without AGENTS.md files.** Fixed in the
  same revision as this file — each crate now has its own doc, restoring the documented
  one-per-meaningful-unit invariant.
- **CodeGraph is not initialized** in this project (codebase-memory index exists; `.codegraph/`
  does not). `codegraph init -i` would give structural querying alongside it.

**Resolved since the last state file:**
- Nothing — the previous session's list is now committed, so its "nothing committed" blocker is gone
  by definition.
- The full `./verify.sh` (clippy + e2e) gap from the last session is closed: it ran, with the
  corpus-dependent skips above.

**Carried forward from Phase 1 (still true, unchanged):**
- Narrowing a crate's `tokio` features does NOT structurally close async egress — unaffected by
  later changes, which touched *who holds* Scope, not the egress-closure mechanism.

## Running instance (for manual testing)

No instance is running as of this revision. The previous session's instance
(`--web 127.0.0.1:8081 --proxy 127.0.0.1:8090`) was backgrounded, not supervised, and is gone.

To start one: `cargo run -p burpsy-cli -- --web 127.0.0.1:8081 --proxy 127.0.0.1:8090 --bchecks /tmp/BChecks`.
Note: `socat` pid may own port 8080 on this machine (same conflict the previous session's note
warned about); use 8081. Passive scanning is off unless `--bchecks` is given.

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Sequencer | SEQ-01 — token capture and entropy analysis | **Built** — no longer deferred, but built outside its originally-stated dependency (PLUGIN-01) | Roadmap creation, 2026-07-27; delivered 2026-07-30 |
| Scanner | SCAN-04 — hand-written active checks beyond the BCheck corpus | Deferred to v2 | Roadmap creation, 2026-07-27 |
| DSL | DSL-03 — crawl/audit scoping | Deferred to Phase 6 | Roadmap creation, 2026-07-27 |
| WebSockets | WS-02 (interception/resend), WS match-and-replace | Deferred within Phase 9 — see `crates/proxy/AGENTS.md` for the documented entry point and trap | 2026-07-30 |
| H2-03 / H2-04 remainder | Frame-program UI/API surface; Scanner + Intruder h2 egress | Open within Phase 2 | 2026-07-30 |

## Session Continuity

Last session: 2026-07-30 (committed 2026-07-30, HEAD was `b647a34` after the release-workflow merge)
This session: 2026-08-02. Documentation refresh: corrected this file's stale "nothing committed"
claim, refreshed the AGENTS.md hierarchy (13 crates, 1032 tests, updated dependency graph, restored
the missing per-crate docs), ran the full gate. No code changed.
Resume file: None — start from "Next steps" above.
