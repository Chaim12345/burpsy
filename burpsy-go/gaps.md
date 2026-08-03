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
| 7 | Sequencer FIPS 140-2 absent | COMPLETE | P2 |
| 8 | `RequestEdit` absent as a type | OPEN | P2 |
| 9 | Store `verify_index` partial | PARTIAL | P3 |
| 10 | BCheck builtins partial | COMPLETE | P1 |
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

### 6. Intruder payload sets absent — COMPLETE

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

**Go (web handlers now ported — Slice F):** `internal/web/api_tools.go`
`handleIntruderPoints` now answers `PointsReq{msg_id, all}` →
`PointView[]` (`index`/`kind`/`label`/`offset`/`len`/`current`, span text read
from the stored message) and `handleIntruderRun` answers `RunReq`
(`msg_id`/`target`/`all`/`point_index`/`payloads`/`mode`/`points`/`payload_sets`/
`payload_sources`/`payload_rules`/`max_payloads`/`grep_match`/`grep_extract`/
`pool`/`auto_throttle`/`rps`/`max_in_flight`/`max_requests`/`timeout_ms`) with the
full `RunView` (`report` + `examples` resolving each bucket's first ordinal to its
payload combination + `payload_sets` carrying honest `total`/`total_exact`/
`truncated`/`max_count`/`skipped`/`dropped`), or the flat `AttemptView[]` array
for the legacy one-position form. The legacy browser-side positional/§-marker
handlers (`findInsertionPoints`, `generatePayloadPreview`, the materialised
`payloads`+`positions` response) are deleted; the dead `s.intruder` web field and
`WithIntruder` are removed. Validation mirrors the Rust edge: bad mode, duplicate
or out-of-range point, wrong set count, bad payload rule, bad grep pattern,
over-long auto_throttle status list, and `rps < 0.01` are all 400s; a missing
message is 404; a host wholly out of scope is 403 via the new `MayContainHost`
pre-filter (a path-scoped exclude never disqualifies the host). Every spliced
request is judged per-send through the Slice E `AuthorisedSender` bound in the
handler, so a payload that rewrites the path out of scope is refused and counted,
never sent. The legacy flat form keeps its original 500-request cap; the report
form reports the operator's `max_requests` bound. The plan, limiter (default 20
rps / burst 1 / 10 in flight, `pool` echo, `auto_throttle`), and engine buckets
all run on the Slice C machinery. Named divergences: Go's `regexp` is RE2, which
bounds matching memory by construction, so the Rust `GREP_SIZE_LIMIT` has no knob
to turn; the legacy flat array keeps the browser-side `payloads` as a `PayloadSource`
list, which the report form already treats as one type. Covered by
`internal/web/intruder_api_test.go` — eight HTTP-level tests pinning the wire
shapes, including the per-attempt path-rewrite refusal end-to-end.

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

**Decline path:** none; the engine half is ported and tested, and the web half
(handlers + `RunReport` wire contract) is now ported with Slice F.

### 7. Sequencer FIPS 140-2 absent — COMPLETE

**Rust:** `crates/sequencer/src/fips.rs` — monobit, runs, long-run, poker tests;
`crates/sequencer/src/chars.rs` — alphabet and per-position entropy;
`crates/sequencer/src/lib.rs` — `SequencerReport` / `Grade` / `analyse_as`, the
five warnings, and the three verdict sentences.

**Go (now ported):** the FIPS engine was already in `internal/sequencer/fips.go`
(572 lines; `Encoding`, `BitStats`, `FipsTest`, `FipsReport`, `AnalyseFipsBits`,
every threshold with its FIPS 140-2 section, `Tests` marshalling to JSON null
when not one whole 20,000-bit block was supplied). What was missing — and is now
in `internal/sequencer/report.go` — is the report assembly the UI consumes:
`AnalyseChars` / `CharacterAnalysis` / `PositionStats` / `CharCount` (byte-level,
shorter tokens excluded rather than padded, per-position Shannon entropy,
`entropy_ceiling_bits` = log2(tokens), `max_possible_bits` = positions ×
log2(alphabet_size)), `SequencerReport` / `Grade` / `AnalyseAs` / `AnalyseReport`
/ `TokensFromText`, with the warnings and verdict sentences byte-for-byte the
Rust ones. `handleSequencerAnalyse` (`internal/web/api_tools.go:704`) now
mirrors the Rust `AnalyseReq` (text / pre-split tokens / optional forced
encoding) and returns the full `SequencerReport`, matching the interface
declared at `internal/web/ui/src/sequencer.ts:76`.

Tests mirror the Rust suite: engine tests in `internal/sequencer/report_test.go`
(pasted-block splitting, empty-sample report, healthy two-block pass with
hex detected, a counter-as-session-id caught at both levels, insufficient vs
fail, variable lengths, forced encoding) and handler tests in
`internal/web/sequencer_api_test.go` (one-call paste with `fips.tests` null on
12,800 bits, out-of-scope paste not gated, empty paste answered, neither
text-nor-tokens refused, unknown encoding named, tokens-array path, forced
encoding reported as chosen, whole-block pass).

**Not covered by this gap:** the live-capture *loop* — Rust
`crates/sequencer/src/capture.rs` (a background start/poll/stop job with a
`CaptureView`) — is still a stub in Go (`handleSequencerCapture` returns static
`{"capturing": false}` / `{"stopped": true}`), so the UI's "capture from a
request" pane cannot drive it. That is a separate nameable difference, not part
of the FIPS/report contract this gap existed to close, and it is not claimed
complete here.

### 8. `RequestEdit` absent as a type — COMPLETE

**Rust:** `crates/core/src/edit.rs` class at `:28` — `from_raw:54`, `target:119`,
`url:128`, `file:138`, `header:142`, `set_header:150`, `add_header:175`,
`add_query:180`, `to_raw`, dechunking, Content-Length recomputation. A single
first-class mutation type used across tools.

**Go:** ported to `internal/core/edit.go` as a public `RequestEdit` —
`ParseRequestEdit`, `Target`, `URL`, `File`, `Header`, `SetHeader`, `AddHeader`,
`AddQuery`, `ToRaw`, plus `dechunk` and `strictHeaderEnd`. All ten of edit.rs's
tests are ported one for one in `internal/core/edit_test.go`, so both
implementations are held to the same claims.

`internal/bcheck/insertion.go` now uses it and its private `requestEdit` is
deleted. That migration fixed two real defects the private copy had:

- **Chunked bodies were never decoded**, so a body insertion point spliced its
  payload into the chunk framing rather than the content.
- **Absolute-form targets were not split**, so a request captured from a proxy
  (`GET http://host/a`) was rebuilt with an absolute target and sent to an origin
  that expects origin-form.

It also tightened the header terminator from lenient to strict: the private copy
treated a terminator-less buffer as all head and no body, which meant rebuilding
and sending an attack from a head that had been guessed at.

Still outstanding, and deliberately left: `internal/intruder/intruder.go`
`injectPayload` (`:163`) still splices by byte position without recomputing
Content-Length. That is a separate gap from this one — it is about Intruder's
`§marker§` model, not about the absence of an edit type.

### 9. Store verification partial — PARTIAL (blocked on a segment format change)

**Rust:** `crates/core/src/lib.rs` — `verify_capture_dir:453`, `verify_index:782`,
`verify_segments:894`. Two mechanisms that deliberately do not subsume each other:
`verify_index` proves the in-memory index is self-consistent (and would still pass
if the bytes on disk had rotted, because it reads them *through* the index it is
checking), while `verify_segments`/`verify_capture_dir` re-read each file and
recompute every CRC, catching what appeared *after* the write.

**Go:** `internal/core/store.go` has `VerifyIndex` (position-is-the-id, the
cross-references between all three indexes, and — in segment mode — that every
message still resolves on disk to a payload of the length the index believes it
has) and `VerifyCaptureDir`/`verifySegmentFile`.

This entry claimed there was "**no** `verify_index` equivalent", which was wrong.
What is genuinely missing is the second mechanism's teeth: **the Go segment format
carries no per-record CRC**, so `verifySegmentFile` can only prove a segment is
readable end to end and report how many bytes it read. A byte flip that preserves
the file length is undetectable. `VerifyCaptureDir`'s doc comment now says so
explicitly rather than implying a guarantee it cannot make.

Two real defects here were fixed while porting Gap 8's neighbours:

- `VerifyCaptureDir` matched `segment-*.log` while the writer emits
  `segment_%d.dat`, so it examined **zero files and reported success**. The
  filename now comes from one shared `segmentNameFormat` constant.
- `verifySegmentFile` reported `size/1024` in a field named `Checked`, so a 2 MB
  segment claimed to have checked 2048 of something. It is now a byte count of
  what was actually read.

**Decline path:** adding a per-record CRC changes the on-disk layout that every
recorded `Location` is expressed against, and the SQLite mirror now persists those
spans. So this is a format migration, not a local fix — it needs its own change
with a version marker on the segment header. Note the Rust doc's constraint: the
CRC is corruption detection only, never to be described as an integrity control,
since anyone who can write to the capture directory can recompute it.

### 10. BCheck builtins partial — COMPLETE

**Rust:** `crates/bcheck/src/funcs.rs` `java_backrefs:153` — rewrites Java
replacement spelling (`$1`, `$1.php`) into Rust regex form (`${1}`) so the
corpus's backrefs mean what Java means. Rust also has `random_str`.

**Go (now ported):** `internal/bcheck/bcheck.go:509` `javaBackrefs` matches the
Rust walk byte-for-byte: a `$` followed by a digit consumes the *whole* run of
digits (Java `Matcher.replaceAll` semantics) and emits `${…}`, stepping over
non-references by whole runes so multi-byte replacement text survives; `${1}`
already in Go's form passes through untouched. `regex_replace` in `resolveRef`
(`bcheck.go:382`) feeds its replacement through `javaBackrefs` before
substituting, so the corpus's backrefs mean what Java means. `randomStr`
(`bcheck.go:542`) is the Rust `random_str` exactly: xorshift64* with the same
multiplier `0x2545F4914F6CDD1D`, same `(r >> 33) % len` alphabet selection, same
alphabet `"abcdefghijklmnopqrstuvwxyz0123456789"`, same 4096 length cap; seeded
lazily (`ensureRNG`) by FNV-1a over the first 512 bytes of the response, `| 1` to
keep the state off the all-zero xorshift lane. The seed matches the Rust
evaluator byte-for-byte (`crates/bcheck/src/eval.rs:198-211`: FNV-1a offset
basis `0xcbf29ce484222325` over `response.raw.iter().take(512)`, `| 1`), so
Go and Rust produce the *same* probe value for the same response — reproducible
per target so a finding is re-checkable.

The verified failure that drove this gap — Go reading `$1eyJ…` as a named group
`1eyJ…` and emptying the JWT header, the exact case at
`other/tokens/jwt-none-algorithm.bcheck:15` — is pinned RED-then-GREEN by
`TestJavaBackrefsMakesTheJwtHeaderSurviveReplacement` (the premise test proves
Go eats the untranslated form, then asserts the translated substitution keeps
group 1 + the literal). Covered by `bcheck_test.go`: `TestJavaBackrefsRewritesJavaGroupReferences`
(digits+letters, `.php`, `${1}` passthrough, bare `$`, `$12abc` all-digits),
`TestRegexReplaceAppliesJavaBackrefsToTheReplacement` (end-to-end through
`resolveRef` with the corpus's brace-wrapped quoted shape),
`TestRandomStrDrawsFromTheSafeAlphabet`, `TestRandomStrIsReproducibleForASeed`,
`TestRandomStrResolvesThroughTheEvaluator`, and `TestRandomStrIsSeededFromTheResponse`
(same body → same probe, different body → different probe).

**Decline path:** none; both builtins are ported and tested. Gap closed
(commit `060fc82`; this ledger entry was written up after the fact).

### 11. Comparer no granularity/budget — COMPLETE

**Rust:** `crates/tools/src/comparer.rs` — `Granularity:34`, `Op:45`, `Diff:61`,
`diff:84`, `diff_with_budget:93` (bounded diff over large bodies, word/byte
granularity).

**Go:** `internal/tools/comparer.go` (397 lines) has `Granularity`
(`GranularityByte`/`GranularityWord`), `Diff`, `DiffWithBudget`, a `Truncated`
flag, and `budgetFor` scaling the cap with input size (2048 ceiling, 64 floor),
over a Myers diff with `core.Span` tokens. `comparer_budget_test.go` mirrors
comparer.rs's own budget test.

This entry described `internal/tools/tools.go:207` and was stale — the dedicated
comparer already existed. Recorded here because the Go implementation is
*stronger* than the obvious alternative: bounding the edit-script size D rather
than the DP table means two large but similar bodies (the common case — compare
two responses differing in one field) still diff exactly, where a cell-count cap
would degenerate to whole-delete plus whole-insert.

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
