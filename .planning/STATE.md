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
**Current focus:** Phases 1, 5, 7 complete. Phases 3 and 9 gained substantial partial coverage this
session via a Burp feature-parity pass that ran outside the phase-by-phase roadmap (see "What this
session actually was" below) — **nothing from it is committed yet.**

## Read this first

**Nothing from this session is committed.** HEAD is still `ac1ce4a`, the same commit the previous
session ended on. 61 files are modified/untracked in the working tree, all verified by a full
`cargo test --workspace` (green, 0 failures, every crate) and `bunx tsc --noEmit` (clean) run just
before this update — but not reviewed line-by-line by a human and not committed. Treat this session's
work as "built and passing its own tests," not as "merged."

The ROADMAP progress table and REQUIREMENTS.md checkboxes were stale coming into this session (flagged
by the previous session, never fixed). This update corrects the specific rows this session has direct
evidence for — Phase 1/5/7 completion the previous session already claimed but never reflected in
ROADMAP.md's table, plus Phase 3 and 9's new partial coverage. It does **not** attempt a full audit of
Phases 2, 4, 6, 8, 10–12 — no work touched them this session and re-verifying old claims from scratch
was out of scope.

## What this session actually was

Not roadmap-phase execution. A separate initiative: an audit comparing burpsy against real Burp Suite
produced a 19-item gap-fix backlog (tracked as tasks #5–#21 in this session's task list, not as GSD
plans), fanned out to parallel agents (7 direct small UI tasks, 8 larger tasks in isolated git
worktrees), then merged back into the main tree one at a time with full-suite verification between
each merge. Several items map onto existing v1 requirements (below); several others — runtime-editable
Scope, conditional proxy intercept rules, the Sequencer's full FIPS-140-2 analysis — don't correspond
to any single REQUIREMENTS.md line and were built as direct Burp-parity items, not derived from a
phase's success criteria. Worth an operator decision at some point: fold these into REQUIREMENTS.md as
first-class entries, or keep tracking Burp-parity work as a separate backlog alongside the roadmap.

One of these ships ahead of its stated dependency: SEQ-01 (Sequencer) was deferred in REQUIREMENTS.md
v2 pending PLUGIN-01 ("becomes the first dogfood of the plugin API"). It landed this session as a
standalone crate with no plugin API involved, because the Burp-parity audit scoped it directly. Noted
in REQUIREMENTS.md rather than silently treated as satisfying the original deferral reasoning.

## Current Position

Phase: Phases 1, 5, 7 complete. Phase 3 and Phase 9 now Partial (were "Not started"). Phases 2, 4, 6
unchanged (Partial/Partial/Not started per last session — not re-verified this session). Phases 8,
10–12 not started.
Status: Executing
Last activity: 2026-07-30

Progress: [██▌░░░░░░░] 25% by whole phases; more by requirement — see REQUIREMENTS.md's traceability
table for the per-requirement picture, which now has real movement in Phase 3 and Phase 9.

**Gate:** `cargo test --workspace` → **green, 0 failures**, every crate, run fresh after every merge
step this session (not just at the end). `bunx tsc --noEmit` → clean. Full `./verify.sh` (the
project's own gate script, which also runs clippy and e2e) was **not run this session** — only its
cargo-test and tsc components were, run directly rather than through the script. This is the one gate
carried forward unexercised, same as last session's e2e gap.

## What landed this session

Nothing is committed, so there is no commit log to show — this is a description of working-tree state,
verified by test runs, not a set of reviewed commits. In roughly the order it was merged:

| Area | What changed | Verification |
|---|---|---|
| Repeater (TOOLS-04) | Numbered tab strip, independent state per tab | tsc clean |
| Scanner | Per-finding advisory detail panel, cross-tab jump to History | tsc clean |
| Site map | Filter bar (`q`/`in_scope_only`), capped per-node recent-exchange list (`SiteNode::recent_exchanges`, cap 200), per-node viewer + findings join | `cargo test -p burpsy-core -p burpsy-web` green |
| Match & Replace | Rule table + live preview; live preview initially mutated the **persisted, live-proxy-active** rule set on every keystroke — caught in review, fixed to a non-mutating `draft_rules` param on the test endpoint before merge | `cargo test -p burpsy-web` green, dedicated regression test added |
| History / Logger | Client-side filter bar; backend `q` free-text filter | green |
| Decoder | MD5/SHA1/SHA256/SHA512 hashing + hex/text view toggle | green, digest vectors checked against `python3 hashlib` before hardcoding |
| Comparer | Prev/next hunk navigation (sync-scroll skipped — the current layout is one flat diff, no second pane to sync) | green |
| Intruder (TOOLS-01, TOOLS-03 partial) | All 4 attack modes wired to the UI; backend payload generators (Numbers/Dates/BruteForce/CustomIterator), a processing rule chain (prefix/suffix/case/encode/hash/skip-if-matches), grep-match/grep-extract, resource-pool auto-throttle | `cargo test -p burpsy-intruder -p burpsy-web` green (86+ new tests). **UI wiring for the new generator/rule/grep/pool fields is task #20, not done** — the backend is reachable only by hand-built JSON today |
| Session handling (SESSION-01..04) | Single always-on macro → a rule list: independently scoped, custom parameter extraction (`{{name}}` substitution across steps), update-macro retest. `GET/PUT /api/session/macro` replaced by `/api/session/rules` CRUD | `cargo test -p burpsy-session -p burpsy-web` green (78 session tests, up from 28) |
| WebSockets (WS-01, WS-03) | RFC 6455 capture/history end-to-end: frame reassembly, `TrafficStore`'s third position-is-the-id index, per-message scope re-check on retention. **Interception (WS-02) and match-and-replace deliberately not started** — entry point and a specific trap (`Reassembler` truncates; don't build interception on top of it) documented in `crates/proxy/AGENTS.md` for whoever picks it up next. UI for what did land is task #21 | `cargo test --workspace` green (32 new tests at merge time) |
| Sequencer (SEQ-01, v2/deferred — see above) | New crate: FIPS 140-2 statistical suite (monobit/poker/runs/long-runs) plus character-distribution entropy, paste and live-capture modes | Reference vectors computed independently in Python before being asserted in Rust; 45 sequencer tests |
| Scope (not in REQUIREMENTS.md) | `Arc<Scope>` → `SharedScope` (`Arc<RwLock<Scope>>`-shaped) across the whole workspace — six independently-cloned scopes in `cli/src/main.rs` collapsed to one shared handle. `POST/DELETE /api/scope/rules` lets an operator add/remove rules while the process runs, no restart | Live end-to-end check against the running binary (not just unit tests): added a host to scope, watched the *same running proxy* start capturing it and the repeater accept it, without a restart |
| Proxy intercept rules (not in REQUIREMENTS.md, extends HARD-03's hold queue) | Conditional request/response holding by field (host/path/extension/method/url/status_code/content_type), regex or literal match. Response holding is a **new** capability: buffer-or-stream is decided before the response exists (streaming stays byte-identical when no rule applies) | `cargo test --workspace` green; **3 real pre-existing bugs found and fixed along the way**: a bodiless-response (204/304) framing hang that would have wedged a hold behind a warm browser cache, a `103`/interim-response status misparse that would show `103` instead of the real status, an unbounded response buffer with no cap |

Two merges required manual reconciliation rather than a clean patch apply: `crates/web/src/lib.rs`
(three tasks independently touched `AppState`/the router ladder) and `crates/proxy/src/lib.rs` (the
WebSocket relay and the response-hold logic both modify `forward_http`/`mitm`, and had to be combined
by hand — verified by a full green test run afterward, including the ALPN/interception/websocket
integration suites together in one binary for the first time).

## Where each phase actually stands

- **Phase 1 — Store & Scope: COMPLETE.** Unchanged this session, except `Scope` itself gained runtime
  mutation (see above) — the chokepoint property HARD-03 cares about (one path to a socket) is
  untouched; what changed is that the *scope value* behind that chokepoint can now be edited live.
- **Phase 2 — HTTP/2: PARTIAL.** Unchanged, not re-verified this session.
- **Phase 3 — Query DSL & Tool Parity: PARTIAL** (was "Not started" in ROADMAP.md's table, which was
  simply wrong even before this session — TOOLS-04 was reachable, if clunky, and is now properly
  multi-tab). TOOLS-01, TOOLS-03 (partial — see UI note above), TOOLS-04 landed this session. DSL-01/
  02/03/04 and TOOLS-02 (`.pay` lists) still not started.
- **Phase 4 — Reporting & Scanner Data: SUBSTANTIALLY DELIVERED.** Unchanged, not re-verified.
- **Phase 5 — Session: COMPLETE**, and ROADMAP.md's top-level checkbox and progress-table row are
  fixed to say so — they still said "Not started" despite the previous session's STATE.md claiming
  completion. This session's rule-list rewrite is a large implementation change under an
  already-satisfied requirement, not a new requirement landing.
- **Phase 6 — Crawler & Dashboard:** not started, unchanged.
- **Phase 7 — Hardening: COMPLETE**, same fix as Phase 5 — ROADMAP.md said "Not started," STATE.md
  said complete since last session. ROADMAP.md now matches.
- **Phase 8 — Plugin API:** not started.
- **Phase 9 — WebSockets: PARTIAL** (was "Not started"). WS-01 and WS-03 landed; WS-02 (edit and
  resend a frame) needs Phase 2 of the WS work (interception), not started. WS-03's "authorised
  against scope, decision point stated explicitly" is satisfied per-message, but the interaction with
  *live* scope edits on an *already-open* socket has not been specifically tested end-to-end — Scope
  becoming runtime-mutable this session is new since WS-03 was implemented, and the two were built by
  agents that didn't know about each other's work mid-flight. Worth a dedicated test before calling
  this fully closed.
- **Phases 10–12:** not started, unchanged.

## Next steps, in the order I would take them

1. **Review and commit.** 61 files, verified by tests, never reviewed line-by-line by a human or
   committed. This is the single biggest gap this session leaves — everything else is downstream of
   getting this into a real commit history.
2. **Run the full `./verify.sh`**, including clippy and e2e. Only cargo test + tsc ran this session.
3. **Task #20**: wire the new Intruder payload-generator/rule/grep/pool fields into `intruder.ts`. Pure
   frontend, backend already tested.
4. **Task #21**: WS History tab in the TypeScript UI. Same shape — backend already tested and exposed.
5. **Verify WS-03 against a live scope edit** on an open WebSocket connection specifically (see the
   Phase 9 note above) before treating that requirement as unconditionally closed.
6. **Decide** whether Scope-runtime-editing and the proxy's conditional intercept rules get their own
   REQUIREMENTS.md entries, given they're real, tested capabilities with no requirement ID today.
7. Longer-term, unchanged from last session: finish H2-04, start Phase 6 (crawler), reconcile the
   remaining phases' ROADMAP/REQUIREMENTS staleness if anyone finds evidence for or against them.

## Blockers/Concerns

**Open, and deliberately not hidden:**
- **Nothing this session is committed.** Repeated here because it is the most consequential fact in
  this file, not because the rest of the file forgot to say it once.
- Full `./verify.sh` (clippy + e2e) unrun this session — only cargo test + tsc ran.
- Phases 2, 4, 6, 8, 10–12 not re-verified; their status lines are carried forward from last session
  unchanged, not re-checked against current code.
- WS-03 vs. live scope mutation on an open socket: plausible but not specifically tested (see Phase 9
  above).
- Task #20 (Intruder UI) and #21 (WS History UI) are scoped but not started.
- `crates/proxy` WebSocket interception (WS-02) and match-and-replace: deliberately not started, with
  a documented trap for whoever picks it up (`crates/proxy/AGENTS.md`: build a `FrameSplitter` first,
  do not try to hold messages with `Reassembler` — it truncates).
- `.codebase-memory/` (~3 MB binary, rewritten on every re-index) is committed. Carried forward,
  unresolved, from last session.

**Resolved this session** (beyond the backlog items in the table above):
- This machine (12 cores / 11GB RAM) was running 6+ concurrent worktree `cargo` builds at once mid-
  session and thrashed — swap filled completely, load average hit 40+. Fixed with two durable,
  machine-level changes, not just a one-time wait-it-out: `sccache` installed as the global
  `rustc-wrapper` (`~/.cargo/config.toml`), and a `/usr/local/bin/cargo` wrapper that caps concurrent
  heavy `cargo build`/`test`/`check` invocations at 3 via `flock`, queuing the rest instead of piling
  on. Both persist for future sessions on this machine.

**Carried forward from Phase 1 (still true, unchanged):**
- Narrowing a crate's `tokio` features does NOT structurally close async egress — see previous
  session's note; unaffected by this session's `SharedScope` change, which touched *who holds* Scope,
  not the egress-closure mechanism itself.

## Running instance (for manual testing)

Restarted this session on different ports than last session's note describes (that instance is gone):

```
Web UI    http://127.0.0.1:8081
Proxy     127.0.0.1:8090          NOT 8080 — socat pid 376 (unrelated to burpsy) owns 8080 on
                                  this machine, same conflict the previous session's note warned about
Corpus    not loaded this session (--bchecks not passed) — passive scanning is off on this instance
```

Started via `cargo run -p burpsy-cli -- --web 127.0.0.1:8081 --proxy 127.0.0.1:8090`, backgrounded,
not under any supervisor — it will not survive this session ending unless something else takes it over.

Worth exercising given what changed: the Scope tab's add/remove-rule flow (watch a proxied request
change from 403 to captured without restarting), the Match & Replace live preview (confirm it no
longer PUTs to the persisted rule set while typing), and `GET /api/ws/history` after proxying an actual
WebSocket connection through 127.0.0.1:8090.

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Sequencer | SEQ-01 — token capture and entropy analysis | **Built this session** (see "What this session actually was" above) — no longer deferred, but built outside its originally-stated dependency (PLUGIN-01) | Roadmap creation, 2026-07-27; delivered 2026-07-30 |
| Scanner | SCAN-04 — hand-written active checks beyond the BCheck corpus | Deferred to v2 | Roadmap creation, 2026-07-27 |
| DSL | DSL-03 — crawl/audit scoping | Deferred to Phase 6 | Roadmap creation, 2026-07-27 |
| WebSockets | WS-02 (interception/resend), WS match-and-replace | Deferred within Phase 9 — see `crates/proxy/AGENTS.md` for the documented entry point and trap | This session, 2026-07-30 |

## Session Continuity

Last session: 2026-07-28 (commit `ac1ce4a`)
This session: 2026-07-30. Large amount of work built and test-verified, **nothing committed**. Stopped
mid-flow at the user's request to update this file — no agents running, working tree has 61
modified/untracked paths, `cargo test --workspace` and `bunx tsc --noEmit` both green as of the last
full run.
Resume file: None — start from "Next steps" above, and read "Read this first" before touching ROADMAP
or REQUIREMENTS further.
