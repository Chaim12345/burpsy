# burpsy-go — Rust parity gaps (verified)

> **UPDATED 2026-08-03.** This is the graph-and-source-verified gap ledger for the
> Go port, cross-checked against the Rust workspace with `codegraph` and
> `codebase-memory` MCP indexes plus direct reads. Its purpose is honest
> accounting: every gap below is a *nameable* difference with a status and a
> decline path where one exists — never a silent "100% COMPLETE". The stale
> self-assessment in `PORT_STATUS.md` (below the fold) is superseded by this file
> and by the "Recent Work — verified" sections.
>
> Evidence convention: Rust paths are crate-relative (`crates/scanner/...`);
> Go paths are repo-relative (`internal/scanner/...`).

## How the corpus was counted

- Corpus: `/root/.cache/BChecks` — **264 files**.
- Conformance: `go run ./cmd/conform /root/.cache/BChecks` → **264 parsed OK,
  0 failed, accept rate 100.0%** (run with the path argument; bare invocation
  reports `files: 0`).
- `given` clause distribution across the corpus — this bounds how many checks can
  actually *run* in live audit, independent of parse rate:

  | given family | files |
  |--------------|-------|
  | response     | 104   |
  | host         | 98    |
  | request      | 40    |
  | path         | 11    |
  | insertion point | 9  |

  A parse success is not a run success; files whose `given` family the engine
  cannot produce are recorded as skipped, not as passing.

---

## Plan

Each gap has a status: **DECLINED** (a real difference, consciously not ported,
with the reason named), **PARTIAL** (ported with a reduced scope, named), or
**OPEN** (difference exists, decision pending). Priority is P1/P2/P3.

| # | Gap | Status | Priority |
|---|-----|--------|----------|
| 1 | HTTP/2 support absent | OPEN | P1 |
| 2 | Scanner catalog + coverage absent | PARTIAL | P1 |
| 3 | Scanner audit engine far thinner | PARTIAL | P2 |
| 4 | JS vulnerability checks hand-rolled | PARTIAL | P2 |
| 5 | JWT weak-signature checks simplified | PARTIAL | P3 |
| 6 | Intruder payload sets absent | PARTIAL | P1 |
| 7 | Sequencer FIPS 140-2 absent | PARTIAL | P2 |
| 8 | `RequestEdit` absent as a type | OPEN | P2 |
| 9 | Store `verify_index` partial | PARTIAL | P3 |
| 10 | BCheck builtins partial | PARTIAL | P1 |
| 11 | Comparer no granularity/budget | PARTIAL | P3 |
| 12 | Session coordinator simplified | PARTIAL | P3 |

---

## Filled — the twelve gaps

### 1. HTTP/2 support absent — OPEN

**Rust:** a full `crates/http2` crate (pure framing/HPACK/normalisation over
bytes, no sockets) plus a relay/sender stack:

- `crates/http2/src/malformed.rs` — `stream_id_rules_are_judged_per_frame_type:820`,
  `a_frame_interleaved_inside_a_header_block_is_reported:995`,
  `padding_that_runs_past_the_frame_is_reported:1093`.
- `crates/http2/src/normalise.rs` — `render_request:69`, `render_response:103`.
- `crates/proxy/src/h2_relay.rs` (477 LOC), `crates/sender/src/h2req.rs` (418),
  `crates/sender/src/transport/h2.rs` (665).

**Go:** proxy and sender are HTTP/1.1-only; the CONNECT tunnel writes literal
`HTTP/1.1 200 Connection Established` at `internal/proxy/proxy.go:516,753`.
No H2 frames, HPACK, or stream handling.

**Decline path:** none recorded. This is the biggest functional difference; it
bounds which targets the proxy can audit (HTTP/2-only hosts are not intercepted
the way Burp does).

### 2. Scanner catalog + coverage absent — PARTIAL

**Rust:** `crates/scanner/src/catalog.rs` (447) + `catalog_data.rs` (5,775) +
`coverage.rs` (274) — the catalog of known checks, and per-check coverage
reporting (which checks ran, which declined, why).

**Go:** findings are ad-hoc strings emitted by the active scanner; there is no
catalog type and no coverage report. Graph query for catalog/coverage types
returns nothing.

**Decline path:** none for catalog (P1); coverage reporting follows if catalog
lands.

### 3. Scanner audit engine far thinner — PARTIAL

**Rust:** `crates/scanner/src/audit.rs` (931 LOC) — `AuditLedger:471`,
`DispatchScope:51`, `Disposition:159` (the budget/backpressure model that bounds
work instead of dropping findings), plus `native.rs` (146).

**Go:** `internal/scanner/scanner.go` `ActiveScanner` runs only
SQLi / XSS / path-traversal (`scanner.go:172,210,234`); no ledger, no
dispatch-scope budgets, no disposition machinery. Honest counting in the Rust
sense (resident set independent of work in flight) is not present.

**Decline path:** the Go side relies on simpler concurrency; the audit-budget
semantics are the parity loss.

### 4. JS vulnerability checks hand-rolled — PARTIAL

**Rust:** `crates/scanner/src/js_vulns.rs` (1,254 LOC) driven by the retire.js
repository data.

**Go:** `internal/scanner/scanner_checks.go:118` `checkJSVulns` matches a handful
of libraries (e.g. jquery) by name/version pattern. Coverage is a subset, not a
port.

**Decline path:** none; candidate for full retire.js data port.

### 5. JWT weak-signature checks simplified — PARTIAL

**Rust:** `crates/scanner/src/jwt_weak.rs` (999 LOC).

**Go:** `internal/scanner/scanner_checks.go:21-115` (~95 LOC) covers a subset
(known-algorithm/none checks).

**Decline path:** named subset; not a silent full port.

### 6. Intruder payload sets absent — PARTIAL

**Rust:** `crates/intruder/src/payload.rs` — `PayloadSet:115`, `Numbers:179`,
`Dates:207`, `BruteForce:221`, `CustomIterator:232`, with hard ceilings —
plus `plan.rs`, `limit.rs`, `hash.rs`, `process.rs`, `engine.rs` (bounded,
hashing-based attack plans).

**Go (engine now ported):** `internal/intruder/payload.go` now carries the
generator engine — `PayloadSource` (tagged JSON: list/numbers/dates/brute_force/
custom_iterator/null), `Numbers` (sequential/random, decimal/hex, sign-aware
zero-padding), `Dates` (strict YYYY-MM-DD, civil-date arithmetic exact across
the int64 range), `BruteForce` (character-based charset so a non-ASCII alphabet
is never split into byte fragments, odometer order shortest-first), `CustomIterator`
(2+ slots, last slot fastest), `Null`, and `Resolve(maxCount)` which caps at
`MaxPayloads` (200 000) applied to the allocation, never to a generated list —
honest `Total`/`TotalExact`/`Truncated`/`MaxCount`/`Skipped`/`Dropped` carried
on every set, plus a `PayloadError` refusal path that names the kind (zero step,
backwards range, empty charset/slot, bad length range, too few slots, item over
64 KiB). Covered by 25+ tests in `internal/intruder/payload_test.go`.

**Go (processing chain + byte codecs now ported):** `internal/intruder/process.go`
carries `RuleSpec` (tagged wire shape: add_prefix/add_suffix/replace/uppercase/
lowercase/encode/decode/hash/skip_if_matches), `NewChain` which compiles every
regex and resolves every layer/algorithm at construction (`RuleError` refuses an
unclosed group, `rot13`, `sha3` once, as an operator typo rather than N drops),
and `Chain.Apply`/`Chain.Run` run in rule order at resolve time — a skipped payload
is a shorter set, not a hole in the plan, with `set.Skipped` + grouped `Dropped`
accounting for every payload refused. Refuse-rather-than-mangle: a payload a rule
cannot process (hex `zz`, a partial decode, a payload a chain grows past 64 KiB)
is dropped with its reason, never passed through. The encode/decode rules reuse
`internal/tools/codec.go`, the byte-level layer port of `burpsy_tools::decoder`
(`Layer`/`ParseLayer` aliases, `Decode`/`Encode` returning the truncated flag and
the 64 MiB inflate cap, uppercase percent-encoding with `+` untouched, tolerant
base64, lowercase hex, gzip/raw-deflate fallback) so a payload encoded here is
byte-identical to one encoded in the Decoder tool. The hash step goes straight to
`crypto/md5`+`crypto/sha256` (lowercase hex), the stdlib being checked against
the same vectors as the Rust `hash.rs` copy that is scheduled for deletion. Named
subset: Go `regexp` is rune-oriented while Rust uses `regex::bytes`, so a
match/replace pattern over non-UTF-8 payload bytes can disagree; ASCII/UTF-8
payloads, which is what the whole test suite exercises, are identical. Covered by
14 tests in `internal/intruder/process_test.go` plus 18 in
`internal/tools/codec_test.go`.

**Go (web still behind):** `internal/web/api_tools.go:179` `generatePayloadPreview`
still returns hardcoded strings, and `handleIntruderRun` still accepts the legacy
materialised `payloads []string` + `positions []int` shape. The UI
(`internal/web/ui/src/intruder.ts`) posts the tagged `payload_sources` wire shape
plus `mode`/`points`/`max_payloads` and expects a `RunReport`
(`report`+`examples`+`payload_sets`) back; `handleIntruderPoints` likewise needs
the `msg_id`/`all` → `PointView[]` contract. That wiring needs the plan/limit/engine
machinery (`plan.rs`, `limit.rs`, `engine.rs` bucketing) to answer honestly, so it
is a named remaining piece rather than a stub.

**Go (scope/sender wiring now ported — Slice E):** `internal/core/scope.go` now
carries the two-layer authorisation model of `crates/core/src/scope.rs`
(`request_path:160`, `authorise_request:346`, `explain:369`): `requestPath` reads
both origin-form and absolute-form targets with the query dropped and a pathless
proxied request reading as `/`; `ScopeRule.PathPrefix` + `NewScopeRuleWithPath`
limit a rule to a path prefix; `MatchesRequest`, the path-aware `Contains`,
`Explain` (names the rule that refused, including the path), and
`AuthoriseRaw(host, port, tls, raw)` which checks the bytes actually going on the
wire — a payload spliced into a path position rewrites the request line, so the
named-target check is never enough. A request whose start line cannot be read is
refused, never waved through. `internal/sender/authorised.go` ports
`crates/sender`'s `AuthorisedSender`: scope gate bound at construction, per-send
check before the dial, refusals counted (`atomic.Int64`) and returned as the
send's error, transport never reached on refusal. `internal/httputil` gains
`ResponseStatus` (status from raw response bytes). Covered by
`scope_raw_test.go` (port of scope.rs:580-760), `authorised_test.go` (refusal
before dial on a closed port, in-scope send, spliced-path refusal while the host
stays in scope, race-checked concurrent counters), and
`internal/web/intruder_scope_test.go` (an attack whose payload rewrites the path
out of scope sends nothing to the target and counts the refusal honestly).
Named divergence (unchanged): the Go scope is excludes-first with default-allow,
the Rust scope is last-match-wins with default-deny.

**Decline path:** none; the engine half is ported and tested, the web half
(handlers + `RunReport` wire contract) is the remaining named piece.

### 7. Sequencer FIPS 140-2 absent — PARTIAL

**Rust:** `crates/sequencer/src/fips.rs` — monobit, runs, long-run, poker tests.

**Go:** `internal/sequencer` has entropy / Chi-square / serial / Monte-Carlo only.
The UI declares `FipsTest`/`FipsReport` interfaces at
`internal/web/ui/src/sequencer.ts:55,66` that no backend implements.

**Decline path:** none for FIPS; UI contract is currently unfilled.

### 8. `RequestEdit` absent as a type — OPEN

**Rust:** `crates/core/src/edit.rs` class at `:28` — `from_raw:54`, `target:119`,
`url:128`, `file:138`, `header:142`, `set_header:150`, `add_header:175`,
`add_query:180`, `to_raw`, dechunking, Content-Length recomputation. A single
first-class mutation type used across tools.

**Go:** only a private minimal `requestEdit` at
`internal/bcheck/insertion.go:381-388`; request mutation is scattered across
`internal/intruder/intruder.go` `injectPayload` (`:163`), `insertion.Apply`, and
intercept code. No public API matches the Rust edit model.

**Decline path:** none; the bcheck/insertion story would benefit from one editor.

### 9. Store `verify_index` partial — PARTIAL

**Rust:** `crates/core/src/lib.rs` — `verify_capture_dir:453`, `verify_index:782`
(index↔capture-dir consistency), `verify_segments:894`.

**Go:** `internal/core/store.go` has `VerifyCaptureDir:518` and
`verifySegmentFile:541` but **no** `verify_index` equivalent (in-memory index vs
on-disk segments cross-check).

**Decline path:** partial; capture-dir verification exists, index consistency does not.

### 10. BCheck builtins partial — PARTIAL

**Rust:** `crates/bcheck/src/funcs.rs` `java_backrefs:153` — rewrites Java
replacement spelling (`$1`, `$1.php`) into Rust regex form (`${1}`) so the
corpus's backrefs mean what Java means. Rust also has `random_str`.

**Go:** `internal/bcheck/bcheck.go:361-393` `resolveRef` implements
`to_lower`, `to_upper`, `base64_decode`, `regex_replace` — but not
`java_backrefs` and not `random_str`. The `regex_replace` comment at
`bcheck.go:388-390` claims "Go's replacement syntax is `$1`, which is also
Java's spelling — the corpus's backrefs work as written." **That is wrong for
`$1` immediately followed by an alphanumeric.** Verified: for
`"$1eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"` with regex
`^(Bearer )?[a-zA-Z0-9_\-]+` on input `"Bearer eyJ...rest"`,
Go produces `".rest"` (reads `$1eyJ...` as named group `1eyJ…`, absent → empty)
where Java/`java_backrefs` produces `"Bearer eyJ…rest"` (group 1 + literal).
This is exactly the corpus case at
`/root/.cache/BChecks/other/tokens/jwt-none-algorithm.bcheck:15` (the same file
whose insertion-point family was the `any` evidence in `PORT_STATUS.md`).
Conformance still reports 264/264 because the file *parses*; the runtime
rendering is wrong.

**Decline path:** none. `java_backrefs` is a required builtin for corpus
fidelity; P1.

### 11. Comparer no granularity/budget — PARTIAL

**Rust:** `crates/tools/src/comparer.rs` — `Granularity:34`, `Op:45`, `Diff:61`,
`diff:84`, `diff_with_budget:93` (bounded diff over large bodies, word/byte
granularity).

**Go:** `internal/tools/tools.go:207` `Compare` returns hunks; no
granularity, no diff budget.

**Decline path:** partial; large-body compare has no bound in Go.

### 12. Session coordinator simplified — PARTIAL

**Rust:** `crates/session/src/coordinator.rs` — named `MacroStepFailure:56`,
`RecoveryOutcome:95`, `UpdateMacroOutcome:132`, `ReloginCoordinator:191`
(`matching_rule:292`, `shared_jar:309`, `handle_response:320`,
`update_macro:508`, `send_with_jar:546`).

**Go:** a `Coordinator` **does exist** (`internal/session/session.go:281-296`)
with `RunMacro` (`:407-472`) that interpolates extractions, threads jar cookies,
absorbs Set-Cookie, runs extractions on 2xx/3xx, and evaluates the validity rule
against the last successful step. It is functional but *simpler*: it lacks the
Rust crate's named failure/recovery/update outcome types, and
update-macro/re-login logic lives in the web layer (`internal/web/api_session.go`)
rather than in the coordinator.

**Decline path:** accepted simplification; the re-login policy trait wiring
(`MacroSender`) is the documented Rust design this does not replicate.

---

## Not gaps (verified present)

These were suspected during review and confirmed **present** in Go:

- **SARIF / JSON / HTML report formats** — `internal/report/report.go`
  (JSON:27, `sarifLevel:35`, SARIF:49, HTML:86) and
  `internal/scanner/scanner_reports.go` (`ExportFormat:15`, `ExportResult:24`,
  `Report:31`, `sarifLog:42`, `sarifRun:47`, `sarifTool:51`, `sarifDriver:54`,
  `sarifRule:59`, `sarifDesc:66`, `sarifConfig:69`).
- **Session coordinator** — see gap 12; present but simplified.
- **Persist (SQLite mirror)** — `internal/persist`; no Rust crate counterpart
  (Go extra, documented in the port).

## Honest-counting guarantees

- Parse success ≠ run success: files whose `given` family is not producible are
  declined/skipped, never silently empty (`insertion.go` `[]Declined`).
- The 104 `given response` files are the largest family the live-audit pipeline
  must be able to feed; coverage of that family is reported, not assumed.
- `java_backrefs` (gap 10) is a *runtime* defect that conformance 264/264 does
  not surface; it is tracked here as P1 despite the green parse number.
