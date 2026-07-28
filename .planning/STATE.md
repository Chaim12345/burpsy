---
gsd_state_version: '1.0'
status: executing
progress:
  total_phases: 12
  completed_phases: 3
  total_plans: 1
  completed_plans: 1
  percent: 25
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-27)

**Core value:** Run PortSwigger's published BCheck corpus, unmodified and honestly counted, against real traffic without the memory cost that forces Burp to discard scan work.
**Current focus:** Phase 7 gate cleared; Phases 2/3/4 carry named remainders.

## Read this first

This file was stale for most of the milestone. It claimed "Phase 2 of 12, 8%, ready to plan"
while Phases 4, 5 and 7 were being delivered, because work moved to parallel worktree agents
and nobody updated the tracker. **Git is the source of truth. The ROADMAP progress table and
the REQUIREMENTS.md checkboxes are still stale and were NOT corrected in this session** — the
operator deprioritised doc reconciliation in favour of implementation. Treat them as
unreliable until someone reconciles them against `git log`.

## Current Position

Phase: Phases 1, 5 and 7 complete. Phases 2, 3, 4 partially delivered with the remainder named
below. Phases 6, 8–12 not started.
Status: Executing
Last activity: 2026-07-28

Progress: [██▌░░░░░░░] 25% by whole phases; more by requirement, since three partial phases
carry substantial delivered work.

**Gate:** `QUICK=1 ./verify.sh` → VERIFIED WITH GAPS (1 skipped). Build clean/0 warnings,
clippy clean, **715 unit tests**, BCheck corpus conformance **264 checks parsed / 0 failed /
381 modifier clauses**. The only skip is e2e, which `QUICK=1` skips by design. **Full
`./verify.sh` including e2e has NOT been run this session** — that is the one unexercised gate.

## What landed this session

Six commits, oldest first:

| Commit | Content |
|---|---|
| `21a69cf` | The eight defects HARD-01 found (A-1..A-4, B-1, B-2, C-1, C-2) |
| `6e7ab42` | `crates/session` added to `workspace.members` — 2 925 lines that had never compiled |
| `a1e1dc7` | Two QA findings against `21a69cf`, plus the session HARD-03 proof |
| `2b20bc2` | Salvage + repair after eight agents died on a rate limit mid-flight |
| `3a6f003` | The last three MAJOR QA findings |
| `141262a` | `/api/session` routes (SESSION-01..04 reachable) + intruder flake fix |

**Thirteen defects closed**: HARD-01's eight, plus five MAJOR found by an independent QA pass
*over those eight fixes*. Read `21a69cf` and `3a6f003` together — the QA's own conclusion was
that three of its five findings were the same mistake, *"a fix applied to the path the review
named, while an equivalent sibling path was left behind"* (`forward_http` but not `mitm`, gzip
but not zlib, the empty case but not the mixed one). That pattern is the single most useful
thing to carry forward from this session.

Two of those were regressions introduced *by* the HARD-01 fixes, both in `a1e1dc7`:
- 1xx was swept in with 204/304 as "bodiless". It is **interim** (RFC 9110 §15.2), so the reader
  returned the placeholder and silently discarded the real response — a false negative on every
  check behind a CDN sending `103 Early Hints`. A test had pinned the wrong behaviour.
- A 304 can never satisfy `buf.len() == head_end + len`, so every bodiless response looked
  unframed and A-1's demotion killed connection reuse for the target permanently.

## Where each phase actually stands

- **Phase 1 — Store & Scope: COMPLETE.** STORE-01..05, HARD-03 chokepoint with a source-scan
  backstop that enumerates `crates/*/src` by directory, so it picked up two new crates this
  session with no edit.
- **Phase 2 — HTTP/2: PARTIAL.** Frame layer, HPACK, and H2-03 (deliberate-malformation API)
  landed. **H2-04 is proxy-side only** — the proxy mirrors the target's ALPN, but scanner and
  Intruder egress remain HTTP/1.1. Stated in the module docs, not implied.
- **Phase 3 — Query DSL & Tool Parity: PARTIAL.** DSL-01/02/04 and TOOLS-01..04 landed.
  DSL-03 deferred to Phase 6 by design (not observable until the crawler exists).
- **Phase 4 — Reporting & Scanner Data: SUBSTANTIALLY DELIVERED.** REPORT-01/02/03 (HTML, JSON,
  SARIF 2.1.0) plus REPORT-04 coverage honesty; SCAN-01 (RetireJS by version range), SCAN-02
  (JWT weak secret, only when a candidate actually verifies), SCAN-03. Verified live: a run with
  zero findings reports *"Partial coverage: 102 … reached a conclusion, 162 did not. This is not
  a clean bill of health"*, naming each gap including three checks whose evaluator errored —
  *"this check's silence is not evidence"*.
- **Phase 5 — Session: COMPLETE.** SESSION-01..04, `AuthorisedMacroSender`, and four
  `/api/session` routes wired in the binary. `RecoveryOutcome`'s six variants are preserved
  across HTTP rather than flattened: `GaveUp` is a **200** carrying its attempt count, because
  bounded giving-up is an honest conclusion and a 500 would file it beside a crash.
- **Phase 7 — Hardening: COMPLETE.** HARD-01 (all thirteen defects), HARD-02, HARD-03.
- **Phases 6, 8–12:** not started (crawler, plugins, WebSockets, MCP, DOM static, DOM dynamic).

## Next steps, in the order I would take them

1. **Run the full `./verify.sh`** including e2e. It has not run this session and is the only
   unexercised gate.
2. **Reconcile ROADMAP.md's progress table and REQUIREMENTS.md's checkboxes** against `git log`.
   Both still describe a project several phases behind reality.
3. **Finish H2-04**: protocol-aware egress for scanner and Intruder.
4. **Phase 6 — crawler**, which also unblocks DSL-03.

## Blockers/Concerns

**Open, and deliberately not hidden:**
- Full `./verify.sh` (with e2e) unrun this session.
- ROADMAP/REQUIREMENTS trackers stale; this file is the only reconciled one.
- H2-04 partial (above).
- `.codebase-memory/` (~3 MB binary, rewritten on every re-index) is committed. Intentional per
  the tool's own `.gitattributes` (`merge=ours binary`), but a questionable trade for a project
  whose thesis is memory frugality. Left in place pending an operator decision.

**Resolved this session:**
- The BCheck corpus was absent, so corpus conformance had been reporting UNVERIFIED. Cloned
  PortSwigger/BChecks to `/tmp/BChecks`; conformance now passes (264 checks, 381 clauses). Note
  this lives in `/tmp` and will not survive a reboot.
- `the_target_never_receives_more_than_the_configured_rate` failed under full-suite load
  ("27 arrived within 500ms; allows 26"). Both the bucket's clock and the arrival timestamps are
  wall-clock, so contention timestamps a legitimately-admitted request just inside the window.
  Given a measurement-jitter allowance; the bound itself is still the floor assertion, which
  jitter cannot satisfy if the limiter is absent. A gate that fails under its own parallelism
  teaches people to re-run until green.

**Carried forward from Phase 1 (still true):**
- Narrowing a crate's `tokio` features does NOT structurally close async egress: cargo unifies
  features across the graph, and `web`/`sender`/`cli` enable `full`, so any crate linking that
  rlib can name `tokio::net` again. Verified by planting a `TcpStream::connect` in `intruder`
  and watching the workspace build succeed. Exactly one egress route is closed by the type
  system; the rest rests on `crates/sender/tests/no_alternate_egress.rs`.

## Running instance (for manual testing)

Started under `hub` supervision, so it persists between sessions:

```
Web UI    http://localhost:8081   (or http://172.22.87.18:8081 from Windows)
Proxy     127.0.0.1:8090          NOT 8080 — socat pid 409 owns that port,
                                  which is why serve.sh's hardcoded 8080 fails
Demo app  http://127.0.0.1:8099
Corpus    --bchecks /tmp/BChecks  (264 checks; /tmp, so not reboot-safe)
```

Worth exercising: `GET /api/report/{html,json,sarif}` (the coverage section is the interesting
part), `GET /api/session/macro` (reports `wired: true, configured: false` — a distinction that
matters), and Intruder against the `/login` POST, where the demo app 500s on a quote.

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Sequencer | SEQ-01 — token capture and entropy analysis | Deferred to v2 | Roadmap creation, 2026-07-27 |
| Scanner | SCAN-04 — hand-written active checks beyond the BCheck corpus | Deferred to v2 | Roadmap creation, 2026-07-27 |
| DSL | DSL-03 — crawl/audit scoping | Deferred to Phase 6 | Roadmap creation, 2026-07-27 |

## Session Continuity

Last session: 2026-07-28
Stopped at: `141262a`. Gate green at VERIFIED WITH GAPS (e2e only). Nothing in flight, no agents
running, working tree clean.
Resume file: None — start from "Next steps" above.
