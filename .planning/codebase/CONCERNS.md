# Codebase Concerns

**Analysis Date:** 2026-07-27

All items below were checked directly against the code at the paths cited. Where a claim from the
brief could not be independently confirmed from source (rather than from prose comments alone),
that is noted explicitly. "Inferred" means judgement formed from reading the surrounding code, not
a hard-coded fact.

## Tech Debt

**`TrafficStore::set_response` is O(n) per call, O(n²) for a bulk fill:**
- Issue: `crates/core/src/lib.rs:331-339` scans the entire `exchanges` vec linearly
  (`g.exchanges.iter_mut().find(|e| e.id == exchange_id)`) to attach a response to an existing
  exchange record. Every response arrival pays for the full history scanned so far.
- Files: `crates/core/src/lib.rs`
- Impact: fine at proxy-traffic scale (thousands of exchanges) but pathological for bulk
  ingestion/replay — confirmed by the brief's own measurement of ~49s for 100k fills. This is the
  concrete reason `ROADMAP.md` Phase 4 lists "mmap-backed store" as the fix — the current offset
  design already permits an index restructure without an API change, per the roadmap note.
- Fix approach: replace the linear scan with an id→index map (e.g. `HashMap<u64, usize>` kept in
  step with `exchanges`), or move to the mmap-backed store already planned.

**264-check BCheck corpus coverage numbers are asserted only if `/tmp/BChecks` exists locally:**
- Issue: the test that proves "232/264 runnable, four buckets sum to 264" — `loads_the_real_corpus_if_present`
  in `crates/scanner/src/lib.rs:1495-1519` — early-returns with no assertion at all
  (`if !dir.is_dir() { return; }`, line 1498) when the corpus directory is absent. In CI or any
  environment without `/tmp/BChecks` checked out, this test passes trivially without checking
  anything.
- Files: `crates/scanner/src/lib.rs:1495-1519`
- Impact: the coverage claim in `ROADMAP.md` ("recomputed by the code, not quoted") is genuinely
  self-checking *only* on a machine that has the corpus present. A CI run that lacks the fixture
  gives a false sense that the invariant was re-verified this run.
- Fix approach: fail loudly (not skip silently) when the corpus is expected but missing, or fetch
  the fixture as part of CI setup so the assertion is never silently skipped.

**Large, low-modularity files:**
- `crates/scanner/src/catalog_data.rs` (3,705 lines) is transcribed data (Burp's 183 issue
  definitions), not logic — low risk despite size.
- `crates/bcheck/src/eval.rs` (1,884 lines) and `crates/scanner/src/lib.rs` (1,584 lines) mix
  core evaluation/dispatch logic with substantial inline test suites; still, both are among the
  most load-bearing files in the codebase and the biggest single-file review burden if line-by-line
  human review is undertaken (see Process Risk below).

## Known Bugs / Deliberate Non-Fixes (documented, not accidental)

**`differs from` is refused, not approximated:**
- Symptom: any BCheck using `differs from` returns `Unsupported::ResponseVariations` and is not
  evaluated.
- Files: `crates/bcheck/src/eval.rs:460-473` (doc comment), `crates/bcheck/src/eval.rs:806-810`
  (`CmpOp::DiffersFrom` match arm).
- Trigger: 2 corpus checks use `differs from` to compare two full responses from different URLs
  (a candidate and a random-garbage control).
- Why not fixed: verified in the code comment — Burp's real semantics require
  `ResponseVariationsAnalyzer`-style baselining across ~33 response attributes to learn which
  attributes are naturally volatile before comparing; a naive byte comparison would report
  "differs" on nearly every response (e.g. any error page that echoes the requested path), making
  the two affected checks fire everywhere — a worse outcome than refusing. This is a considered
  trade-off, not an oversight.

**`report issue` (without `and continue`) has an open semantic question:**
- Symptom: plain `report issue` is implemented to end only the current `run for each` iteration
  (and, for `given insertion point`, the current insertion point), not the whole check.
- Files: `crates/bcheck/src/eval.rs:615-637`, comment at lines 626-633.
- Trigger: ~77 corpus files depend on this distinction (per the in-code comment), and PortSwigger's
  own docs are ambiguous — the docs say plain `report issue` "terminates the BCheck", while the v2
  wiki's justification for `and continue` only makes sense if plain reporting suppresses later
  loop iterations, not the whole check.
- Current behaviour: per-iteration termination, chosen because Burp's iterable-expansion model
  (independent copied contexts per iteration) favors that reading. Marked in the code as an "OPEN
  QUESTION, deliberately left as-is" pending an A/B test against real Burp.

**`funcs::base64_decode` mangles genuinely binary payloads:**
- Symptom: base64-decoded bytes that are not valid UTF-8 are lossily converted, replacing invalid
  sequences with U+FFFD.
- Files: `crates/bcheck/src/funcs.rs:178-192` (doc comment cites `PathSuffix_WAF_Proxy.bcheck:32-34`,
  which decodes `"DA=="`, `"oA=="`, `"hQ=="` to `\x0C`, `\xA0`, `\x85`).
- Trigger: any BCheck that base64-decodes a value used as raw bytes rather than text (5 corpus uses
  of `base64_decode` total; at least this one is affected).
- Fix approach: per the comment, fixing requires a byte-typed value throughout the evaluator, not a
  local patch to this function — a real refactor, not a one-line fix.

## Rate/Concurrency Behavior (documented trade-off, not a bug)

**`RateLimiter::acquire` holds the in-flight permit while waiting on the rate token:**
- Verified: `crates/intruder/src/limit.rs:138-150`. `acquire()` takes the semaphore permit first
  (line 139-145), then calls `self.reserve(...)` and sleeps for the rate-token wait *while still
  holding the permit* (lines 146-149).
- Effect: `max_in_flight` does not bound only in-flight requests — it bounds
  (in-flight + rate-limited-waiters), since a worker occupies a slot for the whole duration it
  waits for its rate token. This is conservative (never over-sends) but means throughput can sit
  below the nominal configured rate under contention, because slots get consumed by waiting
  workers rather than in-flight requests.
- The doc comment at lines 133-137 explains this ordering is deliberate (spend the token "as close
  as possible to the actual send" to avoid budget accruing while blocked on a socket), so this is a
  known and accepted conservatism, not an oversight — but it is worth flagging to anyone tuning
  attack throughput who is surprised requests/sec falls short of `per_second`.

## Fragile Areas

**Scanner partition invariant is not checked in release builds:**
- Verified: `crates/scanner/src/lib.rs:497` — `debug_assert_eq!(o.considered(), self.active.len(), "every check must be accounted for");`
- Why fragile: this is the core correctness invariant behind the whole "coverage cannot silently
  drift" claim in `ROADMAP.md` (every check lands in exactly one `Disposition`, and
  `AuditOutcome::considered()` must equal the active check-set size). `debug_assert_eq!` compiles
  to a no-op in `--release`, so a regression that breaks this partition (e.g. a check silently
  double-counted or dropped) would only be caught in debug test runs, not in a release build or in
  production use of a release binary.
- Safe modification: any change to `audit()`'s dispatch/disposition logic in
  `crates/scanner/src/lib.rs` and `crates/scanner/src/audit.rs` should be paired with running the
  existing test suite (which does exercise this path in debug mode); consider promoting this
  specific invariant to a real `assert_eq!` given how central it is to the project's coverage-honesty
  guarantee, or add a release-mode integration test that specifically checks `considered()` against
  the active set size.
- Test coverage: exercised in debug-mode unit tests (e.g. `crates/scanner/src/lib.rs:999`,
  `:1018`, `:1310` assert on related `AuditOutcome` fields), but none of those assertions are the
  `debug_assert_eq!` itself, so a release build gets no equivalent check.

## Security Considerations

**Scope enforcement: two-layer model verified sound at the call sites checked.**
- Risk: sending attack traffic to a host/path outside the authorised engagement scope.
- Files: `crates/core/src/scope.rs` (`may_contain_host` pre-filter at lines 208-227,
  `authorise_request` real decision at lines 238-256), `crates/web/src/lib.rs` (repeater at
  lines 313-318, intruder pre-filter at line 491 and per-request closure at line 659),
  `crates/scanner/src/lib.rs` (`Metered` sender wrapper, lines 587-631, which calls
  `authorise_request` on every BCheck-issued send at lines 613-621).
- Current mitigation: verified all three outbound paths (repeater, intruder, scanner/BCheck) call
  `Scope::authorise_request` against the *actual bytes about to be sent*, not just the
  operator-named target — this specifically covers requests mutated after the initial target check
  (Intruder payload splicing, BCheck `replacing path:`). The design explicitly separates a
  permissive pre-filter (`may_contain_host`, used only to decide whether a host is worth
  considering at all) from the real per-send authorization (`authorise_request`), and the
  regression tests in `crates/core/src/scope.rs:303-478` pin the exact fail-open/fail-closed defects
  a naive single-layer check previously had (path-scoped excludes wrongly blocking a whole host,
  and whole-host allows wrongly permitting excluded sub-paths).
- Residual risk: this analysis confirms the three call sites named in the brief are wired
  correctly; it does not constitute an exhaustive audit of every future/planned outbound path
  (e.g. the planned crawler, WebSockets, and Collaborator features in `ROADMAP.md` Phase 2-4 do
  not exist yet and were not checked, since they aren't implemented). Any new outbound sender
  added later must be independently verified to call `authorise_request` on its actual wire bytes,
  not merely on the operator-named target — this codebase has already had one fail-open regression
  of exactly that shape (per the `scope.rs` module comment and commit `ced8e22`).
- Recommendation: when Collaborator, WebSockets, or crawler sending land, add the same
  `Metered`-style wrapper pattern used in the scanner rather than re-deriving scope checks per
  module.

**Unparsable/unreadable request bytes are refused, not waved through:**
- Verified: `Scope::authorise_request` (`crates/core/src/scope.rs:238-256`) returns an `Err` when
  `request_path` cannot find a parseable request line, and this is pinned by test
  `a_request_with_no_readable_start_line_is_refused_not_waved_through` (`scope.rs:374-381`). This
  is a correct fail-closed default and worth calling out as a good pattern, not a concern — noted
  here for completeness since it's adjacent to the scope work above.

## Bounding and Observability (assessed, not merely asserted)

The project's stated position — "bounding work is fine, silently truncating is not" — holds up
under direct inspection of every mechanism named in the brief:

- **`AuditOutcome`** (`crates/scanner/src/lib.rs`, around line 641): a struct of named disposition
  counters (not a single pass/fail number), so a caller can distinguish "ran everything, found
  nothing" from "refused/skipped N checks". The core invariant (`considered() == active.len()`) is
  checked (in debug builds — see Fragile Areas above).
- **`AttackPlan::truncated`** (`crates/intruder/src/plan.rs:187`, doc comment at line 19): sits
  behind an explicit `max_requests` construction parameter, and `truncated()` is a first-class,
  tested query (`crates/intruder/src/plan.rs:382,401,406-409` test both the truncated and
  untruncated cases explicitly, including a test asserting untruncated plans *report no bound
  applied*).
- **`MAX_OCCURRENCES` / `times_seen`** (`crates/core/src/findings.rs:81-93,163-164,198,304,320-325`):
  occurrence records are capped at 50 (`MAX_OCCURRENCES`), but `times_seen` keeps the true
  uncapped count separately — verified by test asserting `occurrences.len() == MAX_OCCURRENCES`
  while `times_seen == MAX_OCCURRENCES + 25` for a finding that actually fired 75 times. The cap
  loses per-occurrence detail, never the fact that it happened repeatedly.
- **`unbucketed`** (`crates/intruder/src/engine.rs:170-179,283,299,334,396-403`): when
  `max_buckets` is hit, additional responses are counted in `unbucketed` and the outcome sets
  `buckets_truncated: true` rather than silently discarding them or merging them into an existing
  bucket incorrectly.
- **Response truncation on the wire** (`crates/proxy/src/sender.rs:437,461,477`): an oversized
  response sets a `truncated` flag rather than fabricating a `Content-Length`-consistent body; test
  `an_oversized_response_is_truncated_not_unbounded` (`sender.rs:574`) pins this.

No case was found, among the mechanisms the brief pointed at, where a limit is silently applied
without a corresponding observable flag/counter. This is a genuine strength of the codebase as
written; the main residual risk is process, not code — see below.

## Process Risk

**Most implementation was written by parallel agents and merged on `verify.sh`, not full human
line-by-line review.**
- Evidence: `git log --oneline` shows a sequence of `Merge branch 'worktree-agent-...'` commits
  (e.g. `c199a9b`, `74b7b65`, `d835f3f`, `066ae5f`, `9c25ed8`, `79549d3`), each corresponding to a
  worktree directory still present under `.claude/worktrees/agent-*`. Each merge is preceded by
  commits like `f3a7778 verify.sh: pin RUSTC explicitly...`, `9951025 scanner: fix type_complexity
  lint...`, `5431d2f proxy: fix two while_let_loop lints the merge introduced` — consistent with an
  automated/scripted integration pass (lint fixes post-merge) rather than a manual review pass per
  branch.
- A file `.git/sg-reviewed-shas` exists, recording a small number of reviewed commits (6 entries
  seen, all early in the history, all with a `0` flag in the last column) — suggestive of a
  lightweight review tracker, but not proof of exhaustive line-by-line coverage, and the brief
  states three of the six merged branches still have no line-by-line review.
- Impact: per the brief, a review of two of the six merged branches already found three defects
  that ~385 passing tests did not catch (the fail-open scope defect fixed in `ced8e22` is one
  concretely visible example of this pattern in the repo — the scope module's own comments describe
  exactly this kind of test-passing-but-wrong bug). This means: passing tests in this codebase are
  necessary but not sufficient evidence of correctness, and three of six branches carry unknown,
  unreviewed risk.
- Recommendation: prioritize line-by-line review of the three still-unreviewed branches, with
  particular attention to any code touching scope/authorization, rate limiting, and the
  audit-outcome accounting invariants — these are exactly the areas where "tests pass but the
  invariant is subtly wrong" has already occurred once.

## Missing / Deliberately Deferred Features (from `ROADMAP.md`, not concerns per se, but relevant scope gaps)

- **HTTPS `CONNECT` is spliced/logged but not decrypted** — proxy is currently blind to plaintext
  content of HTTPS traffic; TLS interception (CA generation, per-host leaf signing, MITM) is
  planned as Phase 1 and is described in the roadmap as "nothing else matters as much... without
  this the proxy is blind to ~all real traffic." Not yet built as of this analysis.
- **Collaborator (out-of-band interaction server) does not exist** — 26 of 264 BCheck checks are
  gated out for this reason (see Bounding section above); blocked on hosting infrastructure, not
  code, per `ROADMAP.md` Phase 4 and the BCheck-interpreter status section.
- **mmap-backed persistent store** is planned (Phase 4) specifically to resolve the
  `TrafficStore::set_response` O(n²) issue documented above.
- **Extensions/plugin API, WebSockets, HTTP/2, session handling, reporting export** are all listed
  as not-yet-built in `ROADMAP.md` Phase 4 — not defects, but real capability gaps relative to
  Burp parity claims elsewhere in project docs.

---

*Concerns audit: 2026-07-27*
