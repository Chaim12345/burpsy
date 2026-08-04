# burpsy-go — Rust parity gaps (verified)

> **UPDATED 2026-08-04.** ⚠️ **The 2026-08-03 note below claiming the build is
> broken is stale** — `go build ./...` and `go test ./...` are both clean across
> every package as of this update (verified directly, not inferred). The mid-flight
> refactor that note described has landed: **gap 1 (HTTP/2) and gap 2 (scanner
> catalog + coverage) are both substantially closed**, uncommitted in the working
> tree alongside this file. See their sections below, rewritten to match. Summary
> of what changed since 2026-08-03:
>
> - **Gap 1 (HTTP/2): OPEN → PARTIAL** *(later the same day: → COMPLETE, see the
>   third-round note below)*. `internal/http2` (normalise/parse),
>   `internal/proxy/alpn.go`+`tls_peek.go`+`tls_dial.go`+`h2_relay.go`, and
>   `internal/sender/h2.go` now give the proxy a real ALPN-negotiated HTTP/2 MITM
>   relay and HTTP/2 egress for Repeater/Intruder raw sends, built on
>   `golang.org/x/net/http2` rather than a hand-rolled frame layer. This closes
>   the "can't intercept HTTP/2 sites" half of the gap. It does **not** close the
>   "craft a deliberately malformed HTTP/2 frame / raw HPACK control" half —
>   that's `crates/http2/src/{frame,hpack,malformed}.rs` (712+1309+1259 LOC), a
>   different and much larger capability (manual low-level HTTP/2 editing for
>   desync/smuggling research, not transport), newly identified as its own
>   sub-gap. See the rewritten section 1 below.
> - **Gap 2 (Scanner catalog + coverage): OPEN → COMPLETE** *(the audit engine it
>   deferred to gap 3 has since landed too)*.
>   `internal/scanner/catalog.go`+`catalog_data.go` (generated, 183/183 issue
>   definitions transcribed from the same Burp jar source as the Rust catalog)
>   and `coverage.go` (a faithful port of `crates/scanner/src/coverage.rs`,
>   documented single divergence: no `native` field, since Go has no native
>   check set) are both real and tested, wired end-to-end: `passive.go` runs the
>   BCheck corpus (opt-in via new `--bchecks DIR` flag) with per-check coverage
>   tracked, `enrich.go` fills remediation from the catalog, and
>   `GET /api/scanner/coverage` (`internal/web/api_scanner_coverage.go`) serves
>   it. What's still open is the audit *engine* (ledger/dispatch-scope/budget
>   model) — that remains gap 3, unchanged and separate. See the rewritten
>   section 2 below.
>
>
> **Third round, same day — every remaining gap closed.** Gaps 3, 4, 5, 10 and
> the raw-frame half of gap 1 all landed, so **all thirteen entries in the Plan
> table below now read COMPLETE**. Verified together: `gofmt -l .` empty,
> `go build ./...`, `go vet ./...` and `go test ./...` all clean across 17
> packages, and — the check that actually matters — re-verified from a
> `git archive HEAD` extraction rather than from the working tree, which is how a
> committed-but-uncompilable test build was caught and fixed once already this
> session.
>
> - **Gap 1's raw frame layer** — `internal/http2/{frame,hpack,malformed}.go`
>   (1,849 lines against 1,640 of tests). The HPACK Huffman seam is *identical in
>   Rust* (`HuffmanNotImplemented`, "slice 2b's seam"), so it is parity rather
>   than a Go shortfall. No send path, deliberately.
> - **Gap 3 (audit engine)** — ledger, dispatch scope, dispositions, budgets and
>   both circuit breakers, wired into the real audit path. Its tests caught two
>   genuine semantic defects in the first implementation (inverted per-URL dedup;
>   a session breaker attributing its pause to the wrong item) — fixed in the
>   implementation, with no test weakened. Also fills `coverage.go`'s `native`
>   field, previously a documented omission.
> - **Gaps 4 and 5** — the retire.js corpus vendored and embedded, yielding the
>   *same* counts Rust asserts (76 components, 683 vulnerabilities), with real
>   version arithmetic rather than a prefix test, and everything not evaluable
>   counted rather than skipped — including the nine `filecontent` patterns that
>   exceed RE2's 1000-repeat ceiling, named individually in
>   `DatasetSummary.NarrowedPatterns`. Plus the full JWT weak-signature port.
> - **Gap 10** — a tolerant `base64_decode`, and the larger defect behind it:
>   all three single-argument builtins failed to resolve a quoted or
>   brace-wrapped argument, so `base64_decode` returned `""` for **every one of
>   the corpus's five calls** whatever decoder sat behind it. Corpus re-verified
>   at 264/264.
>
> **Same day, second round: gaps 9, 12, and 13 closed** by three parallel agents,
> each verified independently (`go build ./...`/`go test ./...` clean in
> isolation) and then re-verified together (whole-repo `gofmt -l .` clean,
> `go build ./...`/`go test ./...` clean, `go vet ./...` clean). All three found
> and fixed real bugs beyond their stated scope, not just documented gaps:
>
> - **Gap 13 (Query DSL): PARTIAL → COMPLETE.** Parens, `status in low..high`,
>   the five string escapes, and parse-time type checking (DSL-04) all landed in
>   `internal/query/query.go` (288 → 764 lines) with 24 new tests. Found and
>   fixed en route: `==` never matched anything (only `=` was handled), and an
>   absent `status`/`mime` was compared as a real value instead of "no match" —
>   both silent-false bugs indistinguishable from a query that legitimately
>   matched nothing. Deliberate behaviour change: `method` comparison is now
>   case-sensitive (RFC 7230) where `host`/`mime` stay case-insensitive,
>   matching Rust; previously all four fields used case-insensitive matching.
> - **Gap 9 (segment CRC32): PARTIAL → COMPLETE.** `internal/core/segment.go`
>   now writes the same 16-byte file header (magic `BURPSYSG` + version) and
>   17-byte per-record header (len/msg_id/direction/crc32) as
>   `crates/core/src/segment.rs`, byte-for-byte, verified against an
>   independently-hand-built Python/`zlib.crc32` reference encoder. `Append`'s
>   signature changed to take the message id and direction; `VerifyCaptureDir`
>   now walks records and recomputes every checksum instead of reading to EOF
>   and counting bytes, catching the exact same-length-byte-flip case the old
>   ledger entry named as undetectable.
> - **Gap 12 (session coordinator): PARTIAL → COMPLETE.** Config-time
>   `SessionRule` validation (mirroring `crates/session/src/rule.rs`) is wired
>   into every rule-install path, and `HandleRecovery`/`EnsureLoggedIn` are now
>   actually called from both `POST /api/session/login` and the
>   `burpsy session login` CLI command. Found and fixed en route (both were
>   silent, both shipped): (1) a session rule submitted with "allow all hosts"
>   scope could **never match any host**, because empty `ScopeHosts` was read
>   as "matches nothing" instead of Rust's "applies everywhere" default — every
>   such rule was silently dead on arrival while requests kept going out
>   unauthenticated; (2) `POST /api/session/rules` **silently dropped every
>   extraction** a caller submitted (the DTO shape didn't even match what the
>   UI sends), so the `{{name}}` token-scraping feature was broken end-to-end
>   through the web API; (3) `handleSessionLogin` reported `outcome: "recovered"`
>   unconditionally whenever a probe wasn't already valid, without ever running
>   the login macro — the exact "wiring" gap this wraps up.
>
> Full agent reports (files touched, byte layouts, test names, every named
> divergence) are preserved in this session's transcript; the sections below
> are the condensed ledger entries.

> **STALE — superseded by the update above.** ⚠️ **CURRENT
> BUILD STATE: the go-port HEAD does not compile.** A parallel refactor (scanner →
> bcheck-driven passive flow via `internal/scanner/passive.go`, and session recovery
> via `internal/session/recovery.go`) is mid-flight in the working tree: `go build
> ./...` fails (e.g. `scanner.go:414 undefined: bcheck`, `passive.go:180
> exchange.Timestamp`, `session` `TestUpdateMacro…` failing) and moves between
> snapshots. All COMPLETE/OPEN/PARTIAL verdicts below describe **feature presence**
> from source inspection, independent of the current broken build.
>
> This re-analysis supersedes the statuses in the Plan table below where they
> differ. Since gaps.md was last written, commit `ad36d0a` landed RequestEdit and
> the single-copy byte store (gaps 8/9), and a full source cross-check refreshed
> 6/7/10/11/12 and added a **new gap (13: Query DSL)**. The delta from the old table:
>
> | Gap | Old status | New status | Why |
> |-----|-----------|-----------|-----|
> | 6 Intruder payload sets | PARTIAL | **COMPLETE** | `PayloadSet`, Numbers/Dates/BruteForce/CustomIterator, all 9 process rules ported |
> | 7 Sequencer FIPS 140-2 | COMPLETE | COMPLETE | verified—all four §4.9.1 tests, matching thresholds |
> | 8 `RequestEdit` | OPEN | **COMPLETE** | landed (`internal/core/edit.go`, wired into bcheck) |
> | 9 Store verify_index | PARTIAL | PARTIAL | `VerifyIndex` fully ported w/ real on-disk resolution; on-disk CRC32 still missing (Rust has it) |
> | 10 BCheck builtins | COMPLETE | **PARTIAL** | `base64_decode` is strict (`StdEncoding`, rejected tests) vs Rust tolerant decoder |
> | 11 Comparer | PARTIAL(table)/COMPLETE(section) | **COMPLETE** | table was stale; `DiffWithBudget`/`Granularity`/`Truncated` all present |
> | 12 Session coordinator | PARTIAL | PARTIAL | `recovery.go` landed (outcome types, single-flight, update-macro); config-time rule validation + live auto-recovery still missing; currently non-compiling |
> | +13 Query DSL | n/a | **PARTIAL** | Go lacks parentheses, `in low..high`, string escapes, parse-time type safety (DSL-04) |
>
> Also **COMPLETE (verified): WebSocket relay** parity (`proxy/ws.go` vs
> `crates/proxy/src/ws.rs`, relay-first/capture-second, per-message scope) — the
> goroutine-vs-`select!` implementation difference is documented and equivalent.
> **Remaining OPEN (unchanged):** HTTP/2 (1), scanner catalog+coverage (2), scanner
> audit engine (3). `crates/http2` work exists on unmerged branches
> (`.worktrees/h2-egress`, `h2-mitm`) and has not reached master.

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
| 1 | HTTP/2 support absent | COMPLETE (relay+egress, and raw frame/HPACK/malformed crafting) | P1 |
| 2 | Scanner catalog + coverage absent | COMPLETE | P1 |
| 3 | Scanner audit engine far thinner | COMPLETE | P2 |
| 4 | JS vulnerability checks hand-rolled | COMPLETE | P2 |
| 5 | JWT weak-signature checks simplified | COMPLETE | P3 |
| 6 | Intruder payload sets absent | COMPLETE | P1 |
| 7 | Sequencer FIPS 140-2 absent | COMPLETE | P2 |
| 8 | `RequestEdit` absent as a type | COMPLETE | P2 |
| 9 | Store `verify_index` + on-disk checksum | COMPLETE | P3 |
| 10 | BCheck builtins (`base64_decode` fidelity) | COMPLETE | P1 |
| 11 | Comparer no granularity/budget | COMPLETE | P3 |
| 12 | Session coordinator simplified | COMPLETE | P3 |
| 13 | Query DSL (parens / `in` range / escapes / DSL-04) | COMPLETE | P2 |

---

## Filled — the twelve gaps

### 1. HTTP/2 support absent — PARTIAL (relay + egress landed 2026-08-04; raw frame/HPACK crafting still absent)

**Rust:** a full `crates/http2` crate (pure framing/HPACK/normalisation over
bytes, no sockets) plus a relay/sender stack:

- `crates/http2/src/frame.rs` (712 LOC) — a hand-rolled frame encoder covering
  every frame type, including the ability to write **spec-illegal** frames on
  purpose (wrong length, bad flags, malformed padding).
- `crates/http2/src/hpack.rs` (1,309 LOC) — a hand-rolled HPACK codec giving an
  operator control down to the header-block-fragment level.
- `crates/http2/src/malformed.rs` (1,259 LOC) — a `Malformation` vocabulary
  (`ClearFlags`, bad stream ids, unterminated header blocks, etc.) plus an
  `audit` function that judges a hand-built frame program against every rule it
  breaks, naming the RFC section. Explicitly a manual security-research tool
  ("this module does not send anything" — its own doc header says so): craft a
  deliberately malformed HTTP/2 request, see exactly which spec rules it
  violates, for desync/smuggling-style research. Not a transport layer.
- `crates/http2/src/normalise.rs` (235 LOC) — `render_request`/`render_response`,
  turning one H2 stream into HTTP/1-shaped bytes so existing history/tools work.
- `crates/proxy/src/h2_relay.rs` (477 LOC), `crates/sender/src/h2req.rs` (418),
  `crates/sender/src/transport/h2.rs` (665) — the relay/sender stack built on
  top of `frame.rs`/`hpack.rs`.

**Go (relay + egress now landed):** the proxy negotiates ALPN honestly instead
of assuming HTTP/1.1: `internal/proxy/tls_peek.go` peeks the client's ClientHello
for its offered protocols without consuming the handshake, `internal/proxy/alpn.go`
(`AlpnOffer`, `NegotiatedProtocol`, `ClientALPNProtos`) decides what to offer the
origin and what to hand back to the client, `internal/proxy/tls_dial.go` dials
upstream with that offer, and `internal/proxy/proxy.go`'s `interceptTLS`
(`:604-660`) replays the client's ClientHello (`peekClientALPN`'s `replay` conn)
into a real TLS server handshake advertising exactly what the origin chose —
never claiming an ALPN the origin didn't actually negotiate. When the negotiated
protocol is `h2`, `internal/proxy/h2_relay.go`'s `relayH2`/`relayH2Stream` drive
`golang.org/x/net/http2` on both decrypted legs (a `http2.Server` terminating the
client, a `http2.Transport`/`ClientConn` to the origin), rendering each stream
through `internal/http2/normalise.go`'s `RenderRequest`/`RenderResponse` (ported
from `normalise.rs`) into the same HTTP/1-shaped history bytes every other tool
already expects, and running the same passive-scan path (`runPassiveScan`) any
HTTP/1.1 exchange gets. `internal/sender/h2.go`'s `sendH2Raw` (dispatched from
`SendRaw` via `internal/http2/parse.go`'s `IsHTTP2Request`) gives Repeater/Intruder
raw-request replay a real HTTP/2 client path over TLS, round-tripping through
`http2.ClientConn` and rendering the response back through the same
`RenderResponse`. Tests: `internal/proxy/alpn_test.go`, `internal/proxy/h2_relay_test.go`,
`internal/http2/normalise_test.go`.

**The raw frame-crafting sub-gap — now also closed (2026-08-04).** The
capability `frame.rs`/`hpack.rs`/`malformed.rs` provide is *not* a smaller
version of the transport above it: `golang.org/x/net/http2` is a conformant
library and by design will not let a caller construct or transmit an illegal
frame. So it was ported as a deliberately parallel, hand-rolled layer alongside
the conformant one, stdlib-only:

- `internal/http2/frame.go` (417) — `FrameHeader` (`Encode`/`DecodeFrameHeader`,
  `StreamIDMasked`, `ReservedBitSet`), `FrameSpec` (`WithDeclaredLen`,
  `LengthIsDishonest`), `H2FrameProgram`, and `ReadFrames`/`StripPreface` with a
  `Tail` describing what was left over. Preserves whatever it is handed — an
  operator who sets the fields directly can put an illegal frame on the wire,
  which is the point.
- `internal/http2/hpack.go` (759) — `Encoder`/`Decoder` over the static and
  dynamic tables with the integer/string primitives, `HeaderField`, and
  `HpackError` naming the fault and its byte offset. One codec per (connection,
  direction), because a dynamic table is connection state that each `Decode`
  both reads and mutates.
- `internal/http2/malformed.go` (673) — the `Malformation` vocabulary
  (`ClearFlags`, `DeclareLength`, `SetStreamID`, …; applying one never refuses
  and never touches a field it does not name) plus `Audit`, which judges a
  program **client-to-server** and reports ~20 `ViolationKind`s each carrying
  the RFC section it breaks: missing preface (§3.4), length-field overflow and
  payload/length disagreement (§4.1), reserved bit set (§5.1.1), stream-id zero
  on a stream frame / non-zero on a connection frame, even stream id from a
  client, non-increasing stream id, fixed-length violations, SETTINGS length not
  a multiple of six, SETTINGS ACK with a payload, PUSH_PROMISE from a client
  (§8.4), CONTINUATION with nothing to continue / on another stream, a frame
  interleaved inside a header block (§6.2), a header block never terminated,
  DATA on an unopened stream, a frame after a stream closed, and padding faults
  (§6.1).

Rust's "what the audit does not check, and why" section is carried across
verbatim in intent (`malformed.go:54`) — `SETTINGS_MAX_FRAME_SIZE` (unknowable
without the peer's own SETTINGS), SETTINGS payload contents, flow control,
`GOAWAY`/`PRIORITY`/`RST_STREAM` payload semantics, and HPACK validity are all
named as unchecked rather than left to look covered.

**Named seam, identical in both languages:** a string literal with the Huffman
flag set reports `HpackHuffmanNotImplemented` rather than being decoded. Rust
does exactly the same (`crates/http2/src/hpack.rs:131`
`HpackError::HuffmanNotImplemented`, which its own docs call "slice 2b's seam"),
so this is parity, not a Go shortfall — the port carries the seam across so both
implementations decode the same inputs and refuse the same ones. Stated plainly
in the Go module docs because it bounds usefulness: real peers Huffman-code most
header strings, so decoding a *captured* block will often stop at this error;
blocks this package's own `Encoder` produced always decode, since it never sets
H=1.

**Deliberately no send path.** This layer emits octets and an audit report and
stops there. Rust is explicit that authorising a malformed frame program is a
harder problem than authorising a request — a program with a dishonest length or
an unterminated header block cannot have its `:path` fields authorised
individually, because the peer will not decode the block we decoded. Wiring it
to a socket needs that classifier first and is a separate slice in both
languages.

Covered by `frame_test.go` (382), `hpack_test.go` (703), `malformed_test.go`
(555) — 1,640 lines of tests against 1,849 of implementation, including Go
counterparts of the three Rust tests this ledger previously named
(`stream_id_rules_are_judged_per_frame_type`,
`a_frame_interleaved_inside_a_header_block_is_reported`,
`padding_that_runs_past_the_frame_is_reported`).

### 2. Scanner catalog + coverage absent — mostly COMPLETE (landed 2026-08-04; audit engine remains gap 3)

**Rust:** `crates/scanner/src/catalog.rs` (447) + `catalog_data.rs` (5,775) +
`coverage.rs` (274) — the catalog of known checks, and per-check coverage
reporting (which checks ran, which declined, why).

**Go (now ported):** `internal/scanner/catalog.go` (173 LOC) + `catalog_data.go`
(3,698 LOC, **generated** by `internal/scanner/tools/gen_catalog.py` — do not
hand-edit, regenerate instead) transcribe all **183/183** issue definitions from
the same Burp Suite jar source the Rust catalog uses (`IssueDefinition`:
`TypeIndex`/`DeclaredTypeIndex` kept verbatim even where they disagree in 2 of
183 cases, `TypicalSeverity`, `Description`, `Remediation` — empty exactly when
the source has none, never invented — `References`, `Classifications` with
`CWEs()`/`CAPECs()` parsed from titles; 169/183 carry a remediation, 227
references, 433 classifications — same counts as the Rust side). `coverage.go`
(328 LOC) is a documented-faithful port of `crates/scanner/src/coverage.rs`:
`ScanSkip` (why `Scan` returned before any check ran — no checks loaded, exchange
not found, out of scope, response not found), `CheckCoverage`/`CoverageState`
(errored beats a clean run in classification), `CoverageTracker`/`CoverageReport`
with one write-lock per scan (not per check) via a locally-built `ScanDelta`
buffer. The one named divergence: Rust's `CoverageReport` carries a `native`
field for a native check set Go doesn't have yet, so the field is omitted
rather than carried empty. `internal/scanner/passive.go` wires it all together:
`LoadDir` parses a `.bcheck` corpus, classifies it into passive/active/needs-
collaborator/needs-insertion-point buckets (`LoadReport`), and `scanBChecks`
runs the loaded passive set per response, folding a per-response `ScanDelta`
buffer into the tracker in one lock acquisition; `enrich.go`'s `EnrichFinding`
fills remediation from the catalog by exact name match without ever overwriting
a finding's own judged severity. Wired end-to-end: `cmd/burpsy/main.go` gained
`--bchecks DIR` (opt-in, matching the Rust CLI; without it the pre-existing
built-in header/cookie checks still run so old behaviour is preserved),
`internal/proxy/proxy.go`'s `runPassiveScan` now calls `scanner.EnrichFinding`
and attaches `Occurrences`, `internal/web/api_capture.go`'s `handleIssues` reports
`enabled`/`loaded` honestly instead of a hardcoded `false`, and a new
`GET /api/scanner/coverage` (`internal/web/api_scanner_coverage.go`) serves the
live `CoverageReport` (checks, skips, state partition) to the UI. Tests:
`internal/scanner/catalog_test.go`, `coverage_test.go`, `passive_test.go`,
`internal/web/issues_api_test.go`.

**Not closed by this — still gap 3:** the audit *engine* — Rust's
`crates/scanner/src/audit.rs` (931 LOC: `AuditLedger`, `DispatchScope`,
`Disposition`, the budget/backpressure model) has no Go counterpart yet; Go's
`ActiveScanner` still only runs the three hand-rolled active checks
(SQLi/XSS/path-traversal). Catalog/coverage closing gap 2 does not imply gap 3
is closed — they are genuinely separate subsystems in Rust too.

**Decline path:** none; both catalog and coverage are ported, generated from
the same source data, and wired into live traffic and the web API.

### 3. Scanner audit engine — COMPLETE (landed 2026-08-04)

**Rust:** `crates/scanner/src/audit.rs` (931 LOC) — `AuditLedger:471`,
`DispatchScope:51`, `Disposition:159` (the budget/backpressure model that bounds
work instead of dropping findings), plus `native.rs` (146).

**Go (now ported):** `internal/scanner/audit.go` (771) + `audit_engine.go` (911)
carry the whole model: `DispatchScope` (with `FromFrequency`, `IsReachable`,
`UnitKey`), `Disposition` whose every non-dispatch variant has a fixed
`Explanation()` so a skip is always nameable, `ItemState`, `AuditConfig` (default
120s budget) with the `BuiltInConfigs` table and lookup, `AuditLedger` whose
`Admit(unit, check)` is the single chokepoint that makes the resident set
independent of work in flight, and the `ItemBreaker`/`SessionBreaker` circuit
breakers. Wired into `ActiveScanner`'s audit path so it bounds real runs rather
than sitting as an uncalled library — the mistake this project has had to come
back and fix twice (Match & Replace, and the session coordinator's
`HandleRecovery`). Covered by `audit_test.go` + `audit_engine_test.go`, 24 tests.

**Worth recording, because it is the reason to write the tests first:** the
implementation initially *passed* the package suite only because its own tests
did not exist yet, and it was committed in that state (`4c087b2`). When the tests
landed they failed two real semantic defects — per-URL ledger dedup was inverted
(a second capture of one URL re-ran the per-URL checks instead of refusing them
as already covered) and `SessionBreaker` attributed a pause to the wrong item
(the item that tripped it was marked paused and the *following* item marked
failed, exactly backwards). Both were fixed in the implementation; neither test
was weakened to accommodate it. A green package is not evidence when the checks
that would go red have not been written.

`coverage.go`'s `native` field, previously documented as a deliberate omission
because Go had no native check set, is now populated.

**Decline path:** none; closed.

### 4. JS vulnerability checks — COMPLETE (landed 2026-08-04)

**Rust:** `crates/scanner/src/js_vulns.rs` (1,254 LOC) driven by the retire.js
repository data.

**Go (now ported):** `internal/scanner/js_vulns.go` (1,343) replaces the handful
of name/version pattern matches that used to live in `scanner_checks.go:118`. The
retire.js corpus is vendored at `internal/scanner/data/retirejs_repository.json`
(Apache-2.0, from Burp Suite 2026.7.1) and embedded rather than read from a
guessed install path, for the reason Rust gives: a scanner that cannot find its
data file has a new failure mode — "it found nothing because the file was
somewhere else" — which is the silent non-result this codebase exists to refuse.
`VendoredJsVulnDb()` and a loader for an operator-supplied fresher snapshot both
report *their own* identity and counts, so "no vulnerable libraries" is always
qualified by which corpus said so.

The corpus counts match Rust's own assertions exactly — **76 components, 683
vulnerabilities** (`js_vulns.rs:1083-1084` asserts the same two numbers), plus
120 URL patterns and 206 content patterns, all pinned by
`TestVendoredCorpusLoadsAndReportsWhatItCouldNotUse` so a snapshot that quietly
shrank fails loudly rather than weakening every negative result unnoticed.

Version comparison is real arithmetic on parsed versions, not a prefix test and
not semver — the dataset's own bounds include `2.0`, `1.11.0b1`, `3.0.0-rc1`,
`2.2.4-lite`, which a strict semver parser rejects. The trap is pinned by test:
a vulnerable `1.4.2` is flagged and an unaffected `1.40.0` is not, which a prefix
test gets backwards in both directions.

**Everything not evaluated is counted, not skipped** (`DatasetSummary`): 49
`func` extractors (need a JavaScript engine), 8 `filecontentreplace` extractors,
18 hash entries, and any component whose JSON did not have the corpus's shape
(`UnusableComponents`, empty for the vendored corpus).

**Named divergence, measured rather than assumed:** Go's `regexp` is RE2, whose
bounded repeats stop at 1000. **Nine** corpus `filecontent` patterns exceed that
(`{0,1800}`, `{1,5000}`, `{0,8000}`, …) and are recorded by name in
`DatasetSummary.NarrowedPatterns` rather than silently dropped — so the count of
patterns this engine could not use exactly as written is reportable, which is the
difference between "we checked every way retire.js knows how" and "we checked
most of them".

Remediation comes from Burp's shipped catalogue via `EnrichFinding`, asserted by
test, never written in this package.

**Decline path:** none; closed.

### 5. JWT weak-signature checks — COMPLETE (landed 2026-08-04)

**Rust:** `crates/scanner/src/jwt_weak.rs` (999 LOC).

**Go (now ported):** `internal/scanner/jwt_weak.go` (716) replaces the ~95-line
known-algorithm/`none` subset that used to live in `scanner_checks.go:21-115`,
with its own tests in `jwt_weak_test.go`. Findings carry the catalogued issue
name and take their remediation from the shipped catalogue rather than from this
package.

**Decline path:** none; closed.

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

### 9. Store verification — COMPLETE (per-record CRC32 landed 2026-08-04)

**Rust:** `crates/core/src/segment.rs` — a 16-byte segment file header
(`SEGMENT_MAGIC = b"BURPSYSG"` + `SEGMENT_FORMAT_VERSION`) plus a 17-byte
per-record header (`len:u32` + `msg_id:u64` + `direction:u8` + `crc32:u32`,
`RECORD_HEADER_LEN`) preceding every payload; `scan_segment_file` walks records
via these headers and recomputes each CRC. `crates/core/src/lib.rs` —
`verify_capture_dir:453`, `verify_index:782`, `verify_segments:894`: two
mechanisms that deliberately do not subsume each other — `verify_index` proves
the in-memory index is self-consistent (and would still pass if the bytes on
disk had rotted, because it reads them *through* the index it is checking),
while `verify_segments`/`verify_capture_dir` re-read each file and recompute
every CRC, catching what appeared *after* the write.

**Go (now ported):** `internal/core/segment_format.go` (new, 384 LOC) defines
the on-disk layout matching Rust byte-for-byte: `SEGMENT_MAGIC`/
`SEGMENT_FORMAT_VERSION`/`SEGMENT_FILE_HEADER_LEN` (16) and `RECORD_HEADER_LEN`
(17, same four fields, same little-endian layout), `RecordHeader` encode/decode,
and `ScanSegmentFile` which walks a sealed segment record-by-record recomputing
each CRC32 (Go `hash/crc32.ChecksumIEEE`, matching Rust's `crc32fast`/CRC-32
ISO-HDLC — cross-checked against an independently hand-built Python encoder
using `zlib.crc32`, so the two aren't just internally consistent with
themselves). `internal/core/segment.go`'s `SegmentLog.Append` now takes the
message id and direction (signature: `Append(id MsgId, direction Direction,
data []byte) (Location, error)`) and writes header-then-payload; `rotate()`
writes the file header once per new segment. `Location.Offset`/`Length` still
describe the payload span only, so the mmap/`ReadAt` path needed no change.
`internal/core/store.go`'s `VerifyCaptureDir`/`verifySegmentFile` now walk
records via `ScanSegmentFile` and report a typed `CorruptRecord` (short header
/ unknown direction / length overruns the segment / checksum mismatch) naming
the message id and byte offset, rather than a pass/fail byte count. Covered by
`internal/core/segment_format_test.go` (14 tests), including
`TestAFlippedPayloadByteIsCaughtEvenThoughTheLengthIsUnchanged` — the exact
same-length-byte-flip case this gap named as undetectable — and
`TestATruncatedFinalRecordIsReportedAsCorruptionNotAcceptedSilently`,
`TestRecordsRoundTripAcrossSegmentsAndEverySegmentVerifiesClean` (20 records,
forced rotation).

Two real defects were fixed earlier while porting Gap 8's neighbours (still
true): `VerifyCaptureDir` used to match `segment-*.log` while the writer emits
`segment_%d.dat` (fixed via the shared `segmentNameFormat` constant), and
`verifySegmentFile` used to report `size/1024` in a field named `Checked`. That
field is now gone entirely — `SegmentVerdict` carries `Records`/`PayloadBytes`
instead, since `Checked` had no way to say whether it meant bytes or records
and different callers read it as each.

Named divergences from the Rust layout, all documented in-file: Go's
`CorruptRecord` is one struct with a `Kind` field rather than Rust's four enum
variants; `ScanSegmentFile` streams in a 64 KB buffer rather than reading the
whole segment into memory (Go's default segment target is 100 MB vs Rust's
64 MB); a foreign/pre-existing file in the capture directory is named
per-file by `VerifyCaptureDir` rather than refusing to open the whole
directory, since Go's `SegmentLog` resumes an existing capture where Rust's
does not.

**Decline path:** none; closed. The CRC remains, as the Rust doc insists,
corruption detection only — never described as an integrity/tamper-evidence
guarantee, since anyone who can write to the capture directory can recompute
it.

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

### 12. Session coordinator — COMPLETE (validation + live wiring landed 2026-08-04)

**Rust:** `crates/session/src/coordinator.rs` — named `MacroStepFailure:56`,
`RecoveryOutcome:95`, `UpdateMacroOutcome:132`, `ReloginCoordinator:191`
(`matching_rule:292`, `shared_jar:309`, `handle_response:320`,
`update_macro:508`, `send_with_jar:546`); `crates/session/src/rule.rs`
`SessionRule::new:195-283` (config-time validation).

**Go:** the named outcome types landed first (`internal/session/recovery.go`:
`MacroStepFailure`, `LoginOutcome`, `RecoveryOutcome`, `UpdateMacroOutcome`,
single-flight `ensureLoggedIn`, `HandleRecovery`, `EnsureLoggedIn`). What
remained — config-time validation and live wiring — landed 2026-08-04:

- **Validation** (`internal/session/validate.go`, new): `ValidateRule` mirrors
  `SessionRule::new` — non-empty name, `max_attempts >= 1`, a non-empty macro,
  every step needing a method and a host-bearing URL, a `{{name}}` placeholder
  must be defined by a *strictly earlier* step, duplicate extraction names are
  refused rule-wide. Wired into `Coordinator.AddRule`/`UpdateRule` (both now
  return an error), so every install path is covered: the web API (400), the
  `session rules add` CLI, and `persist.Restore` (refusals logged and counted,
  one bad rule no longer takes the whole restore down).
- **Live wiring**: `POST /api/session/login` (`internal/web/api_session.go`'s
  `handleSessionLogin`) and the `burpsy session login` CLI command now both
  call `Coordinator.HandleRecovery`, mapping all seven `RecoveryOutcomeKind`
  variants to distinct results, instead of replaying the probe and reporting
  `"recovered"` unconditionally without ever running the login macro.

**Two real bugs found and fixed while closing this gap** (both pre-existing,
both silent):
1. `SessionRule.MatchHost` read an empty/nil `ScopeHosts` as "matches no host",
   the inverse of Rust's `scope: None` → "applies everywhere" default. Every
   session rule submitted with "allow all hosts" scope was therefore silently
   dead on arrival — enabled, listed in the UI, but never matched by
   `MatchingRule`, so requests to its target kept going out unauthenticated.
   Fixed: nil/empty `ScopeHosts` now matches every host; an explicitly-stated-
   but-empty scope (`{"allow_all": false, "rules": []}`) is still refused at
   validation, matching Rust's distinct treatment of the two cases.
2. `internal/web/api_session.go`'s `dtoToRule`/`ruleToDto` never read or wrote
   a step's `Extract` field at all — every extraction submitted via
   `POST /api/session/rules` was silently dropped in both directions, so the
   `{{name}}` token-scraping feature was broken end-to-end through the web API
   (it worked only for rules constructed directly in Go, e.g. in tests). Fixed
   by decoding the UI's actual extraction union shape (`from: "body" |
   {header}`, `how: {regex} | {json_path} | "whole"`) by hand; `json_path` is
   refused with a named-divergence message (regex-only in this port) rather
   than silently mis-run.

Named model divergence (unchanged, now precisely scoped): Rust holds
extractions inside each `MacroItem` (per-step); Go keeps a flat
`rule.Extractions` with each `Extraction` tagged by its owning `Step` — an
extraction now runs only against its own step's response (previously, before
this fix, every extraction ran against every response).

Covered by `internal/session/validate_test.go` (15 tests) and
`internal/web/session_api_test.go` (13 tests, including
`TestLoginProbeThatIsInvalidRunsTheMacroAndRetriesTheProbe`, which asserts the
login endpoint actually hits the target once — the assertion the old
rubber-stamp code fails).

**Decline path:** none; closed. Remaining named divergence: the re-login
policy trait wiring (`MacroSender`) is Rust design this doesn't replicate
one-for-one, and `persist.Restore` reassigns rule IDs across a restart
(pre-existing, unrelated to this gap).

---

## Updated delta details (independent re-analysis, 2026-08-03)

What changed since the filled-sections above were written, with evidence.

### Gap 9 — `verify_index` — CLOSED 2026-08-04, see section 9 above

Superseded: the per-record CRC32 this entry called for has landed
(`internal/core/segment_format.go`), matching Rust's byte layout exactly. See
the rewritten section 9 above for the full detail; this entry is kept only for
the historical record of what was missing before 2026-08-04.

### Gap 10 — BCheck builtins — CLOSED 2026-08-04 (and the real defect was worse than this entry said)

The builtin *set* was already 1:1 (to_lower/to_upper/base64_decode/regex_replace/
random_str on both sides; collaborator deliberately absent). This entry named the
`base64_decode` fidelity gap correctly:
- **Rust** `crates/bcheck/src/funcs.rs:184` is a tolerant decoder: it skips
  non-alphabet chars (`let Some(v) = val(c) else { continue }`) and stops at `=`,
  so `"SGVsbG8"` (no padding) and `"SGVs bG8="` (embedded space) both decode to
  `"Hello"` (test `funcs.rs:340-342`).
- **Go** used `base64.StdEncoding.DecodeString`, which requires padding and
  rejects whitespace, so both of the above decoded to `""`.

Both are now fixed — `base64DecodeTolerant` (`internal/bcheck/bcheck.go`) is the
Rust walk bit for bit — but investigating it surfaced a **strictly larger defect
this entry had not identified**: all three single-argument builtins resolved their
argument through `resolveRef`, which resolves a *reference* (a variable name or a
path) and answers `""` for the two argument shapes the corpus actually writes:

- a **quoted literal** — and *all five* `base64_decode` calls in the 264-file
  corpus are quoted literals (`base64_decode("DA==")`,
  `base64_decode("UwAGaXNSb290VHpOeg==")`, …). So `base64_decode` returned `""`
  for **every call in the entire corpus**, whatever decoder sat behind it. The
  padding fidelity issue was real but downstream of a call path that never
  delivered the argument at all.
- a **brace-wrapped reference** — the corpus writes
  `to_lower({crlf.response.headers})` and `to_lower({nonce})`, which also
  resolved to `""`.

Only a bare path (`to_lower(check1.response.body)`) ever worked. `regex_replace`
already routed its arguments correctly through `resolveCallArg`; these three did
not. All three now use `resolveCallArg`, so quoted literals, backtick templates,
brace references and bare paths all resolve. This is the same silent-`""` failure
class as gap 13's DSL bugs: the empty string a broken resolve returns is
indistinguishable from the empty string a check that legitimately matched nothing
returns.

**Divergence, with Go the stronger side:** Rust returns
`String::from_utf8_lossy`, so a genuinely binary decode becomes U+FFFD — its own
doc comment names this a known limitation, citing
`PathSuffix_WAF_Proxy.bcheck:32-34`, which decodes `"DA=="`/`"oA=="`/`"hQ=="` to
`\x0C`/`\xA0`/`\x85`. A Go string is a byte string, so those bytes survive and the
check means what it says; fixing it in Rust "means a byte-typed value throughout
the evaluator, not a change in this function."

Covered by four tests in `bcheck_test.go`:
`TestBase64DecodeIsTolerantOfPaddingAndWhitespace` (the three cases
`funcs.rs:339-342` pins, plus CRLF wrapping, `=`-terminated, empty, and
no-alphabet-characters), `TestBase64DecodeKeepsBinaryBytesRatherThanReplacingThem`
(the three corpus binary values, asserting the byte survives rather than becoming
U+FFFD), `TestSingleArgBuiltinsResolveEveryArgumentShapeTheCorpusWrites` (the
RED-then-GREEN pin for the resolve bug — quoted literal, brace-wrapped, and bare
path across all three builtins), and
`TestBase64DecodeOfTheCorpusBinaryValuesThroughTheEvaluator` (the exact three
calls at `PathSuffix_WAF_Proxy.bcheck:32-34`, as written). Corpus conformance
re-verified after the change: 264 parsed, 0 failed, 100.0%.

**Decline path:** none; closed.

### Gap 12 — Session coordinator — CLOSED 2026-08-04, see section 12 above

Superseded: config-time validation and live login/recovery wiring (the two
items this entry called "remaining") both landed. See the rewritten section 12
above for the full detail, including the two bugs found while closing it; this
entry is kept only for the historical record of what was missing before
2026-08-04.

### Gap 13 — Query DSL — CLOSED 2026-08-04

**Rust** `crates/query/src/` (~2020 LOC) is a typed lexer+parser+AST engine with:
parenthesised grouping; a `status in low..high` range operator; quoted-string
escapes (`\"`, `\\`, `\n`, `\t`, `\r`); and **parse-time field/operator type
checking** so `status > "abc"` is a parse error, never a silent non-match (DSL-04,
`lib.rs:59-63`).

**Go (now ported):** `internal/query/query.go` (288 → 764 lines, still one file
by design — this parser reads characters directly rather than materialising a
token slice, so Rust's five-file lexer/parser/ast/eval/error split would just
be four files of two functions each) gained all four items: a `parsePrimary`
level for `"(" or-expr ")"` grouping plus a new expect-EOF check at the end of
`Parse` (previously trailing junk like `status = 200)` was silently discarded,
running a different query than typed); `status in low..high` (inclusive both
ends, `..` a single token, digits-only, an inverted range parses and matches
nothing exactly like Rust); the same five string escapes, with an unrecognised
escape now a parse error instead of a dropped backslash; and parse-time
field/operator/value type checking in `parseCmp` (host/method/mime need a
string + `=`/`!=`/`~`, status needs a number + ordering ops or a range, body
only `~`) — `Expr`'s fields are now unexported so `Parse` is the only
constructor, mirroring Rust's private `Query(Expr)` wrapper; no ill-typed
comparison can reach `Match`, which stays a plain, non-failing `bool`. A new
`QueryError{At, Msg, Src}` + `Render()` ports Rust's caret-under-the-offending-
byte rendering. Covered by `internal/query/query_test.go` (new, 24 tests).

**Two silent-false bugs found and fixed en route** (both pre-existing, both a
direct instance of the DSL-04 failure mode this gap exists to close): `==` was
never handled by `evalCmp` (only `=`), so the web UI's own placeholder query
(`status == 200 and host ~ "api." and not method == "OPTIONS"`) parsed
successfully and then matched nothing, ever; and an absent `status`/`mime`
(`Status() == 0` / `Mime() == ""`) was compared as a real value rather than
read as "absent", so e.g. `status < 400` matched every request still awaiting
its response and `mime != "x"` matched every row in the web UI (whose `Mime()`
is hardcoded `""`).

Named divergences from Rust, deliberately kept: `=` is accepted as a synonym
for `==` (Rust rejects a lone `=`; Go has documented `=` since it was written);
an unquoted bare word is a valid string value (`host = example.com`) — Rust
requires quotes — though an all-digits bare word is still refused as a type
error; one `QueryError` type instead of Rust's ten-variant enum. **Behaviour
change worth flagging:** `method` comparison is now case-sensitive (RFC 7230
method token) while `host`/`mime` stay case-insensitive, matching Rust's
stated rationale — previously all four fields used `EqualFold` uniformly, so
`method = "get"` no longer matches `GET`.

**Decline path:** none; closed.

---

## Not gaps (verified present)

These were suspected during review and confirmed **present** in Go:

- **SARIF / JSON / HTML report formats** — `internal/report/report.go`
  (JSON:27, `sarifLevel:35`, SARIF:49, HTML:86) and
  `internal/scanner/scanner_reports.go` (`ExportFormat:15`, `ExportResult:24`,
  `Report:31`, `sarifLog:42`, `sarifRun:47`, `sarifTool:51`, `sarifDriver:54`,
  `sarifRule:59`, `sarifDesc:66`, `sarifConfig:69`).
- **Session coordinator** — see gap 12; closed 2026-08-04 (validation + live
  wiring landed).
- **Persist (SQLite mirror)** — `internal/persist`; no Rust crate counterpart
  (Go extra, documented in the port).

## Honest-counting guarantees

- Parse success ≠ run success: files whose `given` family is not producible are
  declined/skipped, never silently empty (`insertion.go` `[]Declined`).
- The 104 `given response` files are the largest family the live-audit pipeline
  must be able to feed; coverage of that family is reported, not assumed.
- `java_backrefs` (gap 10) was a *runtime* defect that conformance 264/264 did
  not surface; it was tracked as P1 despite the green parse number, and is now
  fixed. The same is true of the two defects gap 10 closed on 2026-08-04 — a
  strict `base64_decode` and, worse, all three single-argument builtins failing
  to resolve a quoted or brace-wrapped argument. **A 100% parse rate says nothing
  about whether a resolved value arrived**: every one of the corpus's five
  `base64_decode` calls parsed cleanly and evaluated to `""`. This is the
  standing argument for why this ledger counts runtime behaviour separately from
  `cmd/conform`'s number, and why a builtin's argument shapes get their own
  tests rather than being assumed from the corpus parsing.
