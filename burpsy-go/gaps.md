# burpsy-go — Rust parity gaps (verified)

> **2026-08-18 freshness pointer.** This ledger is complete as of 2026-08-04:
> all thirteen gaps read COMPLETE, and that stands. It is *not* a changelog —
> work done since (the crawler session gate, runtime coverage 21 → 145, the
> docs sweep) is tracked in the dated handoffs
> `docs/HANDOFF-2026-08-13.md` and `docs/HANDOFF-2026-08-18.md`, and in each
> package's `AGENTS.md`. One section below — Phase 6's "authenticated crawling
> is only weakly delivered" — was overtaken by events after this ledger was
> written; it carries its own dated correction in place. Read that note before
> quoting the paragraph.
>
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

> **Dated divergence — 2026-09-14: XML and multipart bodies are modelled, and the
> oracle is not.** Rust `crates/bcheck/src/insertion.rs`'s `body_points` refuses
> an XML or multipart body outright (`"body matches no modelled container
> (multipart, XML or plain text)"`), so a `given body insertion point` check
> against one is skipped in full and Intruder falls back to a single
> entire-body position (the Rust tree is frozen; this is not a
> "fix the oracle" note). Go now models both — `internal/bcheck/insertion.go`'s
> `multipartBodyPoints` (one point per part's content, plus its `name` and
> `filename` attributes) and `xmlPoints` (one point per text node and attribute
> value, named by element path) — and `internal/intruder/points_bcheck.go`
> adopts them, so the two consumers of the enumerator keep one container model.
> This is deliberate: a blunt entire-body position makes XML and multipart
> attacks noisier than Burp's, and the single-parser rule only holds if the
> containers live in `internal/bcheck`. Declines remain for a non-UTF-8 body, a
> plain-text body, and a multipart body whose framing cannot be read
> (burpsy-react-ui-63jg).
>
> **Dated divergence — 2026-08-19: HTTP history is proxy traffic, by attribution.**
> Rust leaks tool traffic into Proxy history: `repeater_send`
> (`crates/web/src/lib.rs:679`) calls `store.add_exchange` and `history`
> (`crates/web/src/lib.rs:565`) serves every exchange unfiltered — a Repeater
> resend shows up as a proxy row. Rust's `Exchange` has no attribution field at
> all. Go deliberately diverges: `core.Exchange.Source`
> (`internal/core/store.go`) names the producing surface, the repeater tags its
> exchange `SourceRepeater` (`internal/web/api_tools.go`), `/api/history` drops
> repeater/intruder/scanner-attributed rows (`internal/web/api_capture.go`), and
> `persist` round-trips the column so a restart cannot bring them back
> (`internal/persist/persist.go`). Burp's own split — Proxy history for proxied
> traffic, Logger for the tool's own sends — is the spec. The e2e suite pinned
> the leak as a deliberate red test before the fix; both the unit test
> (`history_source_filter_test.go`) and the browser suite now guard it.

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
| 14 | Scope protocol arm (Go ahead of the Rust oracle) | COMPLETE — deliberate divergence, Go-only | P2 |

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

**Insertion-point dispatch landed 2026-08-09** — the one scope this section
called complete before its wiring existed. `DispatchScopePerInsertionPoint` is
now reachable: a `given insertion point` / `send payload` (M3) check runs once
per point of one request with isolated `latest`, named bindings and
`insertion_point_base_value`, so a finding is attributable to one parameter —
and now carries that parameter with it, end to end, as `Finding.Param` through
the store (persisted as `findings.param`), the issues API and the UI's detail
panel. The corpus's active checks (`given host`/`path`/`request` plus the
insertion-point set) ride the same plan/ledger/disposition machinery as the
built-in table, wired from the same `LoadDir` by the server (`main.go` + the
web layer's lazy fallback) and the CLI (`newCLIContext`), so the two surfaces
cannot disagree about which corpus is in force. Every probe passes through
`AuthorisedSender` and the request budget, with send failures counted as
`DispositionSendFailed` rather than a clean miss.

Covered by `corpus_dispatch_test.go` (insertion-point dispatch against a live
target, the corpus switch, duplicate-capture collapse), the web fallback test
in `internal/web/corpus_audit_fallback_test.go`, and the CLI wiring test in
`cmd/burpsy/cli_scan_test.go`.

**Collaborator checks (burpsy-react-ui-ar8v, 2026-10-09):** the checks that call
`generate_collaborator_address()` or test `dns|http|smtp|any interactions` (27 of
the 264-file corpus per `docs/BCHECK-RESEARCH.md` §6 — a count from the research
pass, not re-measured: no corpus copy is in this tree) now dispatch too, on the
scan's out-of-band channel (`scanner/oob_channel.go`). Each call mints a unique
`<marker>.<domain>` address; an interactions condition with no callback yet is
*unknown* (Kleene logic), the run is recorded and handed to the pending registry,
and `FinishScan` replays it — from the recording, never sending — until the
callback arrives or the deadline makes it outstanding. With no channel
("Don't use Collaborator") each is refused per item with the reason (Skipped),
never run with an empty address.

Correction to the earlier record here: these checks were never actually counted
as skipped. `NeedsCollaborator` matched a condition shape the parser never emits,
so every parsed collaborator check was bucketed active/insertion-point, sent an
empty address and read its conditions as false — counted runnable and silently
clean. `LoadReport.Collaborator` was therefore 0 against the real corpus; it now
counts them, and they are no longer in the active/needs-insertion-point counts.

Known limits, each a miss and never a false positive: a condition that needs the
*absence* of a callback (`not(dns interactions)`) never fires — waiting never
turns "no callback yet" into "no callback" — and ends outstanding; a branch taken
only once a callback arrives that would send a new probe stops the replay
(`ActiveReplayDiverged`), outstanding too; a console "Run test" does not wait, so
an unanswered run there reports "awaiting interactions"; a `given response` check
with an interactions condition is counted but has no dispatch scope. Burp's own
behaviour with Collaborator disabled is to substitute a random string and skip
polling (`docs/BCHECK-M2-SEMANTICS.md`); burpsy refuses instead, by decision.

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

**Finding identity (landed 2026-09-27, burpsy-react-ui-7tc1).** A JWT weak-HMAC
finding now states its own identity via `core.NewFinding.MergeKey`, set to the
secret that was recovered. Burp's merger compares a fingerprint for exactly this
row (`Zbvp.java:53-56`, `Zu / Zxi().ZZ()`); keying on the target instead filed one
proven weakness as a separate High for every endpoint issuing tokens under it,
which is the shape a long crawl produces. The key replaces the target rather than
adding to it, and is still scoped by host: two hosts can each ship a JWT signed
with the string `secret`, and that is two findings, because the weakness is only
actionable on the application that issued the token.

Empty is every other row's behaviour, so path-scoped and host-scoped keying are
untouched. `core.NewFinding.MergeKey` is available to any future row whose identity
is not a location.

**Still not recovered:** Burp's merger has a *third* exemption clause — a
fingerprint compared against a string constant at `Zbvp.java:62` that the
obfuscator stripped. What it named is unrecoverable, and `dedup_policy.go` says so
rather than guessing at it.

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
Named divergences: the Go scope is excludes-first with default-allow, the Rust
scope is last-match-wins with default-deny. Since 2026-09-08 the *host-level
pre-filter* no longer amplifies that divergence: a host that matches no include
rule is refused by `MayContainHost` exactly as `Contains` and Rust's
`may_contain_host` refuse it (a path-scoped include still keeps the whole host
possible, because the pre-filter must stay open so an attack on an authorised
path can start). The residual difference is the empty-scope case only: Go keeps
default-allow — an empty scope contains everything — where Rust's
`may_contain_host` defaults false.

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

**Go-only addition with no Rust counterpart: the extended battery**
(`internal/sequencer/advanced.go` + `chi.go`, burpsy-react-ui-d2g). Burp's
Sequencer runs four further tests beside the FIPS four — character transition
analysis, the spectral test, the correlation test and the compression test — and
the Rust crate has none of them, so there is no oracle to port against and this
is Burp parity rather than Rust parity. It rides the report as
`SequencerReport.Advanced` (`advanced.tests[]`, `advanced.summary`,
`advanced.affects_grade: false`) and **cannot** move `Grade`, which stays the
Rust verdict byte-for-byte: `AffectsGrade` is on the wire so no reader has to
infer that from a comment. Each member either reports its statistic or refuses
with the reason the sample could not support it, mirroring the FIPS suite's
behaviour below one whole block, and the chi-square upper tail the significance
verdicts need is written out in `chi.go` rather than assumed. The p-values are
therefore **not** comparable with any Rust number — Rust prints none — and this
paragraph exists so a future parity audit does not read the extra field as
drift.

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

## Phase 6 (crawler + dashboard), and a Go-only chokepoint defect it exposed

Phase 6 of the Rust project's roadmap has no Rust implementation either — this is new
capability in the Go port, not a port. Recorded here because building it surfaced a
**security defect that existed only in Go**, and because the phase is delivered with a
named gap rather than as a clean sweep.

### The Go-only defect: two exported ways out, one unguarded

`internal/sender/authorised.go`'s `AuthorisedSender` guarded only the raw-bytes path
(`Send(ctx, raw []byte)` → `AuthoriseRaw` → dial). But `Sender.Send(ctx, *Request)` built a
URL and went straight to `client.Do` with **no scope check at all**. Compounding it:
`DefaultSenderConfig` set `FollowRedirects: true` and `CheckRedirect` was only installed on
the `!FollowRedirects` branch, so the stdlib silently followed up to 10 redirects **to
arbitrary authorities**, past any scope decision about the original target; `MaxRedirects: 10`
was written once and read nowhere, so the bound was the stdlib's coincidental default rather
than one we enforced. `Transport.Proxy: http.ProxyFromEnvironment` meant `HTTP_PROXY` could
re-route it too.

**Session macros used the unguarded path** (`internal/web/api_session.go`, with the server
field typed `*sender.Sender`), so login and recovery traffic was unauthorised egress with
redirect-following on. That is the "hostile target steers you to an internal service via a
redirect" vector, reachable from a feature marked complete.

**This is not a Rust parity gap — it is a Go regression against Rust.** `crates/web/src/routes/session.rs`
holds an `AuthorisedMacroSender` and cites HARD-03 explicitly at `:490`; `crates/web/src/session_sender.rs:10`
states that a macro step "is a constructed request in exactly the sense HARD-03 means". So the
Rust side had this right and the Go port lost it in translation. The Rust `.planning/REQUIREMENTS.md`
entry marking HARD-03 `[~]` with session macros still open is accurate *for Rust*; it was never
the wrong claim, and the earlier working assumption that it overstated completeness was itself
the error.

Fixed: `CheckRedirect` returns `http.ErrUseLastResponse` unconditionally (a redirect is now a
response the caller decides about per hop, re-authorising the new authority), both lying config
fields are deleted, `AuthorisedSender.SendRequest` is the authorised entry for a `*Request`, and
both the web and CLI session paths are repointed. Proven by three tests in
`internal/web/session_scope_test.go` that assert the target's own hit count is **zero** — a
refusal counter proves bookkeeping, only a silent target proves the dial did not happen. The
same lying-field defect was found and removed in `internal/intruder`'s `AttackConfig`.

### What Phase 6 delivers, and the one thing it does not

CRAWL-01..07, DASH-01..03 and DSL-03 each land with a test that pins them, including: the
crawler's own HARD-03 chokepoint test (target receives nothing); forms off by default;
destructive-link refusal reported per reason with the matched signal; a stop that names the
bound it hit and how many frontier URLs went unfetched; two-tier dedup (URL template + quota,
and a content fingerprint that keeps raw link targets so `/user/1` and `/user/2` do not merge);
and DSL-03 as two gates — a pre-fetch scope restricted to `host`/`method` and rejected *when the
operator sets it*, plus post-fetch retention over the full grammar.

**Named gap: authenticated crawling is only weakly delivered.** The crawler takes static
`Config.Headers`, so an operator can paste a session cookie and it works until that cookie
expires — after which the crawl quietly starts crawling the login page, with no re-login, no
recovery, and **no detection that it happened**. `session.Coordinator`'s `EnsureLoggedIn` and
`HandleRecovery` are not wired to it. Phase 6's stated goal is "crawl an authenticated target
continuously", so that goal is not met; wiring it also needs a re-login generation counter (the
coordinator's single-flight collapses *concurrent* callers but not sequential waves) and a
per-crawl re-login cap with its own stop reason, because CRAWL-04's destructive-link heuristic
can only ever be a heuristic and a self-inflicted logout will sometimes get through.

> **Superseded 2026-08-11.** This named gap is closed. The session gate landed
> with the crawler upgrade: `internal/crawler/session_gate.go` adds an optional
> `SessionCoordinator` (expiry detection via status-flip or login-page pattern,
> `recoverSession`, request rebuilding with a fresh cookie), `limits.go` carries
> the bounded re-login budget with its own stop reason, and the report surfaces
> relogin health. Commits: `c3c6538` (integrate the crawler upgrade),
> `5a43dd6`, `cc0a04b` (session-recovery tests that pin authenticated-crawl
> behaviour). The crawler `internal/crawler/AGENTS.md` documents the current
> shape. The paragraph above is retained as the record of what the ledger
> claimed on 2026-08-04; it is not the current state.

### Two capture defects found while collapsing the shared path

`scanner.Capture` was extracted so crawled and proxied traffic take one path (CRAWL-02), but
`proxy.go` never called it — four hand-rolled `core.Exchange` literals remained, and the two
copies had **already diverged**: `Capture.Record` set `Response` only when non-empty while the
proxy set it unconditionally. A nil-`Response` exchange permanently wedged the live-audit
sweep, which walks a monotonic cursor and stopped at that id for the life of the process while
`Swept()` kept reporting the number it had reached — silent, permanent coverage loss. Fixed at
both ends: `Record` now refuses to index a half-exchange at all (an invariant that holds for
callers that do not exist yet), and the sweep bounds its wait, steps over, and counts what it
gave up on as `skipped` — never folded into `swept`.

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

## Go extension: `run tool` (external security tools)

Landed 2026-08-10. Beyond Burp parity: PortSwigger's BCheck grammar has no way to
invoke an external scanner, so this is an **extension**, not a ported feature —
and it is built to the same refusal-by-default discipline as the rest of the
corpus engine.

**Grammar** (`internal/bcheck/parser.go`):

```bcheck
given request then
  run tool sqlmap called probe:
    args: "-u", {base.request.url}, "--batch"
  if {probe.exit_code} is "0" and {probe.stdout} contains "vulnerable" then
    report issue:
      name: "SQL injection"
      severity: "high"
      confidence: "firm"
  end if
```

The result binds under the `called` name as `{<name>.stdout}`, `{<name>.stderr}`
and `{<name>.exit_code}` (int). A non-zero exit is **data**, not an error — the
check decides via `{<name>.exit_code}`, exactly as it decides via a status code.

**The gate is the allowlist** (`internal/scanner/toolrunner.go`). A check names a
tool — `sqlmap`, not `/usr/bin/sqlmap` — and the caller maps names to binaries:

```
burpsy -bchecks DIR -tools sqlmap=/usr/bin/sqlmap,jwt_tool=/opt/jwt/jwt_tool scan audit -id 1
```

- A tool not on the allowlist is refused; the run is an error and the check
  abandons (nothing proved, nothing executed).
- The binary runs with the resolved args directly — **no shell** — so an arg
  that happens to contain shell metacharacters is data, not injection.
- Each run is bounded: `Timeout` (default 5m) kills a hung tool, and
  `MaxOutputBytes` (default 1 MiB) caps captured stdout/stderr so a noisy tool
  cannot balloon the process.
- Executing arbitrary binaries is operator policy, so tool execution is off by
  default and only the `-tools` flag (CLI or server) turns it on.

**Honest counting** (`internal/scanner/passive.go`). A check carrying `run tool`
is never passive — it executes an external process — and is counted at load in
its own bucket (`LoadReport.Tools`, printed in the `Summary` as "N need tools").
Without a configured runner the ActiveScanner's `corpusActiveChecks` excludes it
from the dispatch set rather than failing it on every exchange; with a runner it
dispatches and the allowlist decides each tool by name. A whole tool check run
directly without a runner is refused as `ActiveUnsupported` — the same bucket as
a check that needs a Collaborator.

**Files touched:** `internal/bcheck/{bcheck,parser,active}.go` (AST, parser,
evaluator, `ToolRunner` interface), `internal/scanner/{toolrunner,passive,
bcheck_runner,scanner}.go` (runner, load bucket, dispatch gate), `internal/web`
(`WithToolRunner`), `cmd/burpsy` (`-tools` flag).

## Go extension: MCP server transport (stdio) — `burpsy-react-ui-q31t`

Landed 2026-10-01. Beyond parity: the Rust oracle has no MCP server, and neither
does Burp itself (Burp AT's approval layer is architecturally separate from the
model, which is the shape this reuses). ZAP and Caido shipped MCP surfaces in
2026; burpsy already had the expensive half — a per-route risk class and a
server-side confirmation gate — and no transport to reach it.

**What ships.** A separate binary, `cmd/burpsy-mcp` (`burpsy-mcp -web
http://127.0.0.1:8081`), speaking newline-delimited JSON-RPC 2.0 on stdio. It is
a binary rather than a `burpsy mcp` subcommand because every `cmd/burpsy`
subcommand is built through `newCLIContext`, which opens the traffic store, loads
the bcheck corpus and builds the scanners before the command runs — a second
engine wired against the same database, built only to make HTTP calls to the
first. The console's own API is unchanged: no route is added to the manifest.

**tools/list** is derived from the manifest, one tool per route, through
`internal/web/mcp_export.go` (a wrapper file that adds names and changes no
existing line). Each tool carries the route's risk class in its description and
its annotations, plus MCP's four standard hints (`readOnlyHint`,
`destructiveHint`, `idempotentHint`, `openWorldHint`) taken from
`agent_tools.go`'s derivation — shared with the console's own agent-tool
registry rather than re-judged, because a descriptor that called an attack route
idempotent is exactly the drift the taxonomy exists to prevent. Names normalise
the pattern (`/api/crawl/start` → `api_crawl_start`); the manifest legitimately
holds both `/api/pools` and `/api/pools/`, so the subtree half of a collision is
named `_subtree` and a third collision is numbered.

**tools/call does not decide anything.** It forwards the call over HTTP to the
running console and returns what the server answers. The transport therefore has
no copy of the gate to drift from it: a gated mutating call with no confirmation
comes back as the server's own HTTP 428, surfaced as an `isError` tool result
with the gate's body verbatim; the confirmation travels as the
`X-Burpsy-Confirm` header, relayed from the caller and never minted by the
transport. Recovery is an explicit separate tool, `burpsy_confirm`, which POSTs
the console's own mint endpoint — separate precisely so the escalation is one
visible, approvable call in the host's transcript rather than a field the model
fills in. The gate's own comment states the limit honestly and the tool
description repeats it: an agent that can supply the confirm itself has learned
nothing from being asked, so the enforcement point is the host and the operator.

The one thing the transport refuses locally is a call whose path resolves to a
different route than the tool names — `/api/audit/` must not be able to reach
`/api/audit/selected` through the tool that names the subtree. It decides this
with `MCPRouteForPath`, which is the gate's own `routeRiskFor` longest-prefix
resolver, so the binding and the gate cannot disagree about which route a path
names.

**Verification.** `go build ./...`, `go vet`, `gofmt`, and 19 tests in
`internal/mcp` pass. The tests mount a real `web.NewServer`'s gated chain on an
`httptest` server, so the real `confirmStore` mints and spends the tokens — the
acceptance criterion forbids a second gate, and a fake store would pass whether
or not the production path exists. Four mutations were killed to prove the tests
bite: dropping the token relay, dropping the tool/route binding, reporting the
428 as success, and removing name-collision disambiguation each fail a named
test. A live stdio session against a running console was driven end to end:
`initialize` → `tools/list` (123 tools) → a `riskRead` call returning the real
catalogue (183 advisories) → a `riskAttack` call refused with 428 → `burpsy_confirm`
minting a token → the same call returning 200 → the same token replayed and
refused with 428 again.

**Known limits, stated rather than papered over.**

- Stdio only. No SSE/HTTP transport, which the bead allowed as optional.
- The gate's refusal text prints the manifest pattern, so for a subtree route the
  console's own message reads `POST /api/audit//confirm` — one slash too many.
  The transport prints the path it will actually POST to and says why the two
  differ; the message itself lives in `internal/web/confirm_gate.go`, which this
  change does not own and does not edit.
- A streaming route (`text/event-stream`) is refused with a reason rather than
  left to hang until the client timeout, and a response over 1 MiB is truncated
  with the cut reported in the result.
- `internal/web/mcp_export.go` also carries the export surface a second,
  concurrent implementation of this bead had written (its `MCPRouteInfo`,
  `MCPRoutes`, `MCPRouteRisk`, `MCPNeedsConfirm`, `MCPConfirmEndpoint`,
  `MCPGuarded` are preserved as written). This transport added only what it
  needed to those: `Tier`/`Hints` on the struct, `MCPRouteForPath`,
  `MCPMethodMutates`, `MCPConfirmTTLSeconds`.

**Files:** `internal/mcp/{mcp,tools}.go` (protocol, descriptors, call path),
`internal/mcp/mcp_test.go`, `internal/web/mcp_export.go`,
`cmd/burpsy-mcp/main.go`.

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

### Gap 14 — Scope protocol arm — CLOSED 2026-08-21 (deliberate divergence: Go ahead of the oracle)

**Rust** `crates/core/src/scope.rs` has no protocol arm: a rule matches host,
port and path prefix, and `may_contain_host`/`contains` carry no scheme. The
frozen tree stays that way — this gap is recorded here because the Go tree now
does something the oracle cannot express, and the next person diffing the two
deserves to read why rather than file it as drift.

**Go (ahead):** `internal/core/scope.go`'s `ScopeRule` gained `Protocol *string`
("http"/"https"; nil = either, which is what every rule built before the arm
means). The decision the arm rests on: scheme is the TLS state of the connection
a request actually uses, not a property of its URL string — so matching compares
against the `isTLS` every authorisation caller already passed (`Contains`,
`AuthoriseRequest`, `AuthoriseRaw`; the sender has handed a truthful flag across
every dial since it was written — the parameter simply died at the rule boundary
until now). `MayContainHost` treats a protocol-scoped exclude as partial: an
https-only exclude says nothing about http.

Persistence follows the v2 precedent exactly (`persist.go`): `scope_rules_v3`
adds the column; v3 is authoritative on load with fallback to v2 then legacy;
both older tables stay written because a downgraded build reading only its own
table must not find an empty scope — default-allow is the one failure direction
this file never accepts. A v2-era database restores scheme-wide, stated in the
loader doc and pinned by test. Wire: `ScopeRequest.Protocol` /
`scopeRuleView.Protocol`, unknown schemes refused 400 (a scheme no request can
speak builds a rule that silently matches nothing); the configuration bundle
round-trips the arm through export/import via `scopeRuleView`. UI: Protocol
select beside the port/path arms, column in the rules table, exact-tuple remove
carries it.

Pinned by `internal/core/scope_test.go` (include gates by scheme; exclude
removes only its scheme; armless rules match both), `scope_restore_test.go`
(protocol survives save/load; a v2-era database still restores), and
`server_test.go` (arm survives the wire and gates through `AuthoriseRaw`;
"gopher" is refused). Landed as de93912.

## Scanner-logic research declines (2026-09-17)

The Burp scanner-decision-layer research (2026-09-17 pass; the original
`/tmp/smartscan-report.md` is gone — the findings were re-derived from the Burp tree on
2026-09-27 and the load-bearing citations are now `Zfhb.java:81-83` (skip_ineffective),
`Zeze.java:17` (queue dedup), `Zm58.java:88-98` (admission cap), the
`project_options.resource_pools.*` keys (`map_root.tsv:17469-17504,23192-23213`) and
`Zrwf.java:74-84` (audit bus)) ported
the gaps that were worth porting and, per the honest-counting rule, records what it
deliberately did **not** port and why. Each entry names the Burp evidence, so a
future reader can re-open the decision rather than re-derive it.

### Decline 1 — ML in the engine core

**Burp has none.** The "statistical battery" in `burp.Zr8b`
(`map_root.tsv:5899-6035`) is classical FIPS monobit/long-run/runs tests,
chi-square, ZLIB-ratio, spectral and correlation tests — each computes a
significance level; `Zr8b:3999` itself says the tests "provide only an indicative
guide". That battery is **already ported** as the sequencer. The `"training"`
literals (`Zepn:8713-8719`) are the licence trial, not model training. Burp's
actual AI is **Burp AI**, an LLM post-scan issue investigator gated by
severity+confidence (Standard = High + Medium-tentative), which explicitly "does
not affect the crawl or audit phases"
(portswigger.net DAST, "Configuring AI-enhanced scanning", updated 2026-09-09).

**Why declined:** an in-engine model would add a nondeterministic verdict to a
scanner whose whole value is honest counting, needs a training corpus burpsy does
not have, and would not fix the current misses — the xsschallenge corpus is 23
vulnerable / 9 safe at **zero** false positives, so the misses (`hvez`, `2p9u`,
`1a3z`) are capability gaps, not precision gaps. The LLM half is tracked
separately (bead `ei0v`, "LLM post-scan second look") and needs an
operator-supplied endpoint before it can be built.

### Decline 2 — Session handling rules during audit

**Burp:** `scanner.session_handling_rules` (`map_root.tsv:2894, 5850-5851,
20198`) lets an audit invoke a named rule set to re-authenticate mid-scan.

**Why declined:** burpsy's session recovery lives in the crawler
(`internal/crawler/session_gate.go`); the audit engine does not own the macro /
session infrastructure, so adding the config key without the invocation path
would be a config row that decides nothing. Re-open when the session epic lands
the audit-side wiring — the breaker model itself is already richer than assumed
(both levels plus the session count/percentage breaker, with Burp's exact key
names, `audit_items.go:301-304`).

### Decline 3 — `LOW_VALUE` audit disposition

**Burp:** `Zwee.java:125-129` assigns `LOW_VALUE` to requests whose crawl action
was, e.g., a speculative navigation or a floating form. **Why declined:** the
disposition keys on crawler *action types* that burpsy's crawler does not record.
Porting the constant alone would be a label over nothing; port the metadata
first, then the disposition.

### Decline 4 — The full `crawl_optimization` tolerance-key family

**Burp:** `map_root.tsv:243-267` (`scanner.crawl_optimization.*` tolerance keys).
**Why declined:** the family decides whether two renders are "the same" by
comparing DOMs; burpsy's crawler captures wire bytes and has no rendered-DOM
comparator. A single tolerance number without the comparator is unenforceable.
(Related: bead `xuim` covers the rendered-DOM audit row, which is the
prerequisite for most of this family.)

### Decline 5 — HTTP/2 pseudo-header awareness

**Burp:** `Zee2.java:12-63` classifies `:scheme` / `:method` / `:path` /
`:authority` as a distinct header class (literals `map_root.tsv:10712-10715`),
used by `Ze0j.findInvalidHeaderNames` (`Ze0j.java:170-171`) to keep them out of
the ordinary-header insertion-point path.

**Why declined:** the sender is HTTP/1.1 `writeHTTP1` (`sender.go:597`) and
nothing in burpsy reads pseudo-headers, so there is no insertion-point class for
the rule to protect. Re-open if an HTTP/2 sender lands.

### Decline 6 — Name+value relocation matching

**Burp:** `InsertionPointBuilder.java:1035-1045` moves the matching URL parameter
to the corresponding body kind by matching **name and value**.

**Why declined:** burpsy already ships 2 of Burp's 6 relocation directions
(`insertion.go:381`); the remaining matching adds a comparison cost to a kind
that rarely fires. Re-open if a real target shows a relocation the blanket clause
move gets wrong.


## G-reflected-xss-header-reach — the reflected-XSS row could not probe headers

**Verified 2026-09-17 against HEAD, measured with `cmd/xsschallenge`.**

The three core injection rows (SQL injection, reflected XSS, file path traversal) named their
own insertion-point literal:

    var coreInjectionKinds = []string{"query", "body", "cookie"}   // checks_core_injection.go:52

Two consequences, both real:

1. **No `header`.** A value reflected out of an HTTP header was structurally unreachable by the
   reflected-XSS row, because no probe was ever sent into a header. `cmd/xsschallenge`'s
   `/x/header` case (User-Agent reflected into the body) is exactly this shape.
2. **The operator's configuration was ignored.** `scanner/insertion_point_types/*` reaches every
   other probe site through `cc.ProbeInsertionKinds()`, but these three passed the literal
   instead — so turning cookie insertion off changed what the audit queue displayed and not one
   byte of what these rows sent.

**Fix:** all three call sites now pass `cc.ProbeInsertionKinds()`, so the configured kinds govern
and `header` is in the default set (`DefaultProbeInsertionKinds` at probe_harness.go:40).

**Evidence — `cmd/xsschallenge`, before → after:**

| | before | after |
|---|---|---|
| `header-user-agent` | **MISS** | **hit** (Cross-site scripting (reflected)) |
| detection | 20/23 | **21/23 (91%)** |
| false positives | 0/9 | 0/9 |

The two remaining misses are unchanged and are separate capability gaps:

- `stored` — the batch-audit cycle cannot close (checks_stored.go's own header documents this);
  the deferred phase did not reach the `/x/stored/view` render in this run.
- `cookie-pref` — NOT YET DIAGNOSED. An earlier draft of this note claimed the cookie
  insertion point used a percent-encoding codec that escaped `<`/`>`; that is FALSE and was
  retracted before landing. `percentEscape` (bcheck/insertion.go:1871-1884) escapes only
  `& = + ; # %`, bytes `<= 0x20`, and bytes `>= 0x7f`. `<`, `>` and `"` are printable ASCII and
  pass through raw, so a cookie point does carry markup and the kind is enumerated. The miss has
  a different cause and needs its own diagnosis before anything is claimed about it.

### Decline 4b — Crawler default-bound divergence

**Burp:** `Preferences/CrawlDefaults.json` publishes `maximum_link_depth: 4`,
`maximum_crawl_time: 150`, `maximum_unique_locations: 1500`. It ships no template-visit
key at all (verified 2026-10-01: enumerating every leaf key in that file, none matches
`template`), so burpsy's 20 is a bound burpsy invented — a deliberate one, argued at
limits.go:159-163 — with nothing on Burp's side to diverge from.
**burpsy:** `internal/crawler/limits.go` defaults to depth 6, 5 minutes, 300 locations,
and 20 template visits. These are burpsy's chosen conservatism for a pentest tool,
not an oversight. `GET /api/crawl` now publishes both sets under
`default_limits` (burpsy's) and `burp_defaults` (Burp's) so a console can show the delta.

**One divergence the note above missed, and it is the largest of the four:** `maximum_request_count`
is **0** in `Preferences/CrawlDefaults.json`, which means Burp's crawler is UNBOUNDED on requests.
burpsy's is 500 (`limits.go:151`). A Burp crawl of a large application therefore keeps going while
burpsy's stops and says so — which is the difference an operator migrating a crawl will hit first, and
the one least likely to be recognised as a policy choice because a crawl that stops is not obviously a
crawl that was told to. It belongs beside the other three comparisons rather than with the invented
bounds below.

**Every other entry in `burp_defaults` is a burpsy-invented bound, and zero misreads as one.**
`maximum_frontier_size`, `maximum_links_per_page`, `maximum_parse_bytes`, `maximum_capture_bytes`,
`maximum_fingerprints`, `maximum_relogins` and `maximum_submissions_per_form` have no Burp
counterpart at all — the same enumeration that cleared the template key clears these. A console
rendering that table shows "Burp's frontier bound: 0", and 0 in that column is indistinguishable
from "Burp enforces no limit" when the truth is "Burp has no such setting". Separating the two needs
a change to `internal/web/api_crawl.go`, which is another session's working set; recorded here so the
distinction travels with the entry rather than being rediscovered.

### Decline 5 — HTTP/2 pseudo-header awareness

**Burp:** `Zee2.java:12-63` classifies `:scheme` / `:method` / `:path` /
`:authority` as a distinct header class (literals `map_root.tsv:10712-10715`),
used by `Ze0j.findInvalidHeaderNames` (`Ze0j.java:170-171`) to keep them out of
the ordinary-header insertion-point path.

**Why declined:** the sender is HTTP/1.1 `writeHTTP1` (`sender.go:597`) and
nothing in burpsy reads pseudo-headers, so there is no insertion-point class for
the rule to protect. Re-open if an HTTP/2 sender lands.

### Decline 6 — Name+value relocation matching

**Burp:** `InsertionPointBuilder.java:1035-1045` moves the matching URL parameter
to the corresponding body kind by matching **name and value**.

**Why declined:** burpsy already ships 2 of Burp's 6 relocation directions
(`insertion.go:381`); the remaining matching adds a comparison cost to a kind
that rarely fires. Re-open if a real target shows a relocation the blanket clause
move gets wrong.


## G-reflected-xss-header-reach — the reflected-XSS row could not probe headers

**Verified 2026-09-17 against HEAD, measured with `cmd/xsschallenge`.**

The three core injection rows (SQL injection, reflected XSS, file path traversal) named their
own insertion-point literal:

    var coreInjectionKinds = []string{"query", "body", "cookie"}   // checks_core_injection.go:52

Two consequences, both real:

1. **No `header`.** A value reflected out of an HTTP header was structurally unreachable by the
   reflected-XSS row, because no probe was ever sent into a header. `cmd/xsschallenge`'s
   `/x/header` case (User-Agent reflected into the body) is exactly this shape.
2. **The operator's configuration was ignored.** `scanner/insertion_point_types/*` reaches every
   other probe site through `cc.ProbeInsertionKinds()`, but these three passed the literal
   instead — so turning cookie insertion off changed what the audit queue displayed and not one
   byte of what these rows sent.

**Fix:** all three call sites now pass `cc.ProbeInsertionKinds()`, so the configured kinds govern
and `header` is in the default set (`DefaultProbeInsertionKinds` at probe_harness.go:40).

**Evidence — `cmd/xsschallenge`, before → after:**

| | before | after |
|---|---|---|
| `header-user-agent` | **MISS** | **hit** (Cross-site scripting (reflected)) |
| detection | 20/23 | **21/23 (91%)** |
| false positives | 0/9 | 0/9 |

The two remaining misses are unchanged and are separate capability gaps:

- `stored` — the batch-audit cycle cannot close (checks_stored.go's own header documents this);
  the deferred phase did not reach the `/x/stored/view` render in this run.
- `cookie-pref` — NOT YET DIAGNOSED. An earlier draft of this note claimed the cookie
  insertion point used a percent-encoding codec that escaped `<`/`>`; that is FALSE and was
  retracted before landing. `percentEscape` (bcheck/insertion.go:1871-1884) escapes only
  `& = + ; # %`, bytes `<= 0x20`, and bytes `>= 0x7f`. `<`, `>` and `"` are printable ASCII and
  pass through raw, so a cookie point does carry markup and the kind is enumerated. The miss has
  a different cause and needs its own diagnosis before anything is claimed about it.

## Crawler: out-of-scope resources — burpsy is stricter than Burp BY DEFAULT (2026-10-01, burpsy-react-ui-hgor)

**Declared divergence, and it is burpsy's side.** No default was changed and the chokepoint is
untouched; this records a difference an operator comparing against Burp cannot otherwise see.

Burp distinguishes *navigational* scope (what gets crawled and audited) from *resource* scope (what a
page may load to work at all), and **the second defaults to permissive**:

- `crawler.customization.allow_out_of_scope_resources` — Zxcp.java:123; constructor parameter in
  Zula.java:43,65; panel label "Fetch required resources and data from out-of-scope hosts"
  (Zrfn.java:159).
- Default **true** — `Preferences/CrawlDefaults.json`, `allow_out_of_scope_resources: true`
  (tree 2026.7.1, build 51467).
- Burp's own documentation states the consequence: *"This setting controls whether Burp Scanner
  issues requests to out-of-scope hosts where necessary. Websites often require the browser to load
  externally hosted subresources or fetch data from an API to function correctly. … Out-of-scope
  requests are not audited."* (`crawl-settings.html:273`, with the paired read-timeout
  `timeout_for_in_progress_resource_requests`, default 10, `CrawlDefaults.json`).

burpsy refuses. `enqueue`'s scope gate refuses an out-of-scope URL before the frontier sees it and
`sender.AuthorisedSender` refuses again on the wire — CRAWL-02, a deliberate design decision this
bead does not propose weakening. On a site whose fonts, app shell or API live on a CDN or a
third-party host, a burpsy crawl therefore reports far fewer locations than a Burp crawl of the same
seed, with no indication that the difference is a policy choice rather than a bug or a broken target.

**What landed, and what did not.** `SkipOutOfScopeResource` now distinguishes the case the crawler can
actually observe — a framed or embedded document (`iframe`, `frame`, `object`, `embed`) refused for
naming an out-of-scope host, as against a navigational link refused by the same rule. The count reaches
`Report.Limits.OutOfScopeResources` and is stated in the crawl's `Caveat` **even for a complete
crawl**, because a crawl that refused every CDN asset ran to completion within a narrower world than
the operator expects — and the pre-existing caveat only speaks when a bound was hit, which is exactly
the silence this bead is about.

**The larger half, still open.** For the subresources that dominate this scenario — `img`, `script`,
`link`, `source`, `video`, `audio` — burpsy produces **no ledger entry at all**, because it never
discovers them (`internal/crawler/discover.go:24`). It does not refuse them; it never looks at them.
Against Burp, which fetches them, a page served largely from a CDN reads as "found, no links". No skip
reason can express that, because nothing was refused. Two options, neither taken here and both real
work: record the discovered-but-not-queued subresource hosts as an explicit coverage statement on the
report (no new egress), or fetch them behind a switch that defaults off like Burp's. The first is the
honest one and is the smaller.

## Intruder and Repeater send settings (burpsy-react-ui-xixe.1, Phase 1, 2026-10-08)

Burp-parity, not Rust-parity: `crates/` has none of these. Recorded here because each one is a
place burpsy's defaults or reach differ from Burp's in a way an operator cannot see from the UI.

### Per-send response timeout (mmca)

**Burp:** `RequestOptions.withResponseTimeout` — "the timeout to be used while reading the response".
**burpsy:** `response_timeout_ms` on the Intruder run request and on Repeater's per-tab options. It
rides the send's context (`sender.WithSendOptions`) and `setDeadline` prefers it over
`NetworkSettings.readTimeout`, so one tab's slow time-based probe no longer means raising the global
read timeout for every tool. The shared settings are never mutated.

- Intruder keeps its existing `timeout_ms` as the TOTAL per-attempt deadline (redirect chain
  included). `response_timeout_ms` is clamped by it, and refused when it is longer than a `timeout_ms`
  the request also gave.
- Zero is refused rather than read as "no bound": the network settings use 0 for "no deadline of our
  own", and a field named for a bound must not be able to mean its opposite.
- Repeater's single-connection group mode shares one deadline across every request on the socket,
  so tabs that disagree about the timeout are refused by name rather than having all but one dropped.
- Not covered: the typed `Sender.Send` path (net/http's client). Nothing that offers the option sends
  through it.

### HTTP/1 connection reuse and the HTTP version override (xhqr)

**Burp:** Intruder settings "HTTP/1 connection reuse … can greatly increase the speed of your
attacks"; "HTTP version … Override the project-level HTTP/2 setting". Reuse is on by default: the
decompiled panel's reset (`Zruy.Zc5`) selects both `intruderOverrideHttp1KeepAliveSwitch` and
`intruderDefaultHttp1KeepAliveIfSupportedCheckbox`.
**burpsy:** `http1_connection_reuse` and `http_version` on the run request; `sender.ConnPool` +
`AuthorisedSender.SendReusing` (`internal/sender/connpool.go`). Every request is still authorised on
its own bytes before a connection is checked out. The report carries `connections_opened` and
`connections_reused` (both `null` when reuse is off, so "off" and "on but never reused" differ).

- **Default differs by surface, on purpose.** The bundled UI sends `http1_connection_reuse: true`
  (Burp's default). An API request that omits the field gets `false` — one connection per request,
  what every client got before this field existed — so no scripted attack changes behaviour silently.
- **h2 is not pooled.** Burp has a separate "HTTP/2 connection reuse"; burpsy does not. A send that
  offers h2 to an authority not already known to decline it dials fresh, and an h2 exchange closes
  its connection (counted as opened, never as reused). Against an h2 target with `http_version`
  negotiating, `connections_reused` is therefore 0 — reported, not hidden. Pin `http1` to reuse.
- **Stricter than Burp about what is reused.** A connection goes back only after a response delimited
  by its own framing (never read-to-close), with nothing buffered past it, no `Connection: close` or
  HTTP/1.0 on either side, a final status, and not after HEAD or CONNECT. An idle connection is
  probed (1 ms read) before reuse; one that died between the probe and the write is retried on a
  fresh connection only for an idempotent method (net/http's rule).
- `http1_connection_reuse` with `set_connection_close` is refused naming both: the pair asks for
  reuse that can never happen.
- Redirect hops (`follow_redirects`) dial their own connections and are in neither count.

### Update Host header to match target (ety8)

**Burp:** positions.html — "By default, Update Host header to match target is selected."
**burpsy:** `update_host_header` on the run request. Every request's Host header is rewritten to the
target authority (default port omitted, IPv6 bracketed, the typed name — never a resolved address)
after the payload splice, where the session jar is applied, so no span offset moves.

- **Default differs by surface, on purpose.** The bundled UI sends `true` (Burp's default); an API
  request that omits the field gets `false`, the captured Host as before, so no scripted attack
  changes the bytes it sends without saying so.
- Stood aside, and reported in `host_header_skipped`, when a selected position covers the Host
  header (the position being fuzzed wins — the jar's rule for fuzzed cookies) or the base request
  does not carry exactly one Host header (none to keep in step, or a duplicated-Host probe that a
  rewrite would defeat).
- A request a payload left with other than one Host header is sent as spliced and counted in
  `host_header_untouched`, rather than having one of two Host headers chosen for it.

## Intruder payload placement, grep and capture (burpsy-react-ui-xixe.1, Phases 2-3, 2026-10-08)

### Automatic payload placement: Append to base parameter value (1krs)

**Burp:** Settings > Tools > Intruder, "Automatic payload placement" (`configPanelIntruderAutomaticPayloadPlacement`,
`Zrv9`; the same radio pair in the Intruder tab menu, `Zcur`). Each automatic marker is built as
`Zswj(append ? valueEnd : valueStart, valueEnd)` (`Zrw7.Zz`, and the form walk `Zrw7.ZD`): under append the
marker is zero-length at the end of the value.
**burpsy:** `payload_placement` (`""`/`"replace"`/`"append"`) on both `POST /api/intruder/points` and
`POST /api/intruder/run`, which build the discovered list through one function so the positions shown are the
positions spliced. `PointView` gains `placement`; `current` stays the base value.

- **Per attack, not a user setting.** Burp stores the choice once for every tab; burpsy keeps it in the attack's
  configuration (persisted and saved with it), like every other Intruder setting here. Changing it rediscovers
  the positions so stale spans are never shown beside an attack that splices differently.
- **Values only.** URL, body and cookie parameter values and the body-container values (JSON, XML, multipart
  content, nested) append. burpsy's extra discovery families — parameter names, path segments, header values,
  multipart `name`/`filename` attributes and the entire body — are not in Burp's automatic placement at all, and
  keep replacing under either setting.
- **Nested values rebuild.** A base64/JSON/XML value nested in a parameter cannot be extended by concatenating
  onto its encoded text, so the payload is appended inside the decoded value and the outer value re-encoded
  (`bcheck.InsertionPoint.WireValueAppend`, the scanner's own appending branch). Every other value keeps its
  captured bytes exactly.
- **Touching counts as overlapping.** A zero-length insertion touching another position's edge is an overlap
  (`intruder.SpansOverlap`): the splice keeps the earlier-starting position, and a manual marker that touches an
  appended position is refused by name. The same predicate now also applies to an empty value at the very end
  of the entire body under replace, which used to splice both.

### Grep - Payloads (7qc3)

**Burp:** configure-attack/settings.html "Grep - payloads": Case sensitive match, Exclude HTTP headers,
Match against pre-URL-encoded payloads, and "a separate column … for each payload set". The panel (`Zruj`)
persists `payloadgrep.dogrep/casesensitive/excludeheaders/matchpreencoded`, reset off/off/off/**on**
(`Zruj.Zc5`). The engine (`Zu8d.Zb`) counts, per payload set, either the pre-encoding payload or the sent
one (`Zw_x.Zl(…, !matchpreencoded)`) — one form, not both — from the body offset when excluding headers.
**burpsy:** `grep_payloads {enabled, case_sensitive, exclude_headers, match_pre_url_encoded}` on the run
request; `reflected_counts` (one slot per set) on every attempt, `reflected_count_totals` on every bucket,
and the effective settings echoed as `report.grep_payloads`.

- **Default differs by surface, and from Burp.** Burp's search is off by default. burpsy's reflection check
  has always been on — it is a third of the result-bucket key — so the bundled UI sends it on, with Burp's
  other three defaults (case-insensitive, headers included, pre-URL-encoded). An API request that omits
  `grep_payloads` keeps the fixed check it always had: on, case-sensitive, headers included, matched as sent.
- **The settings change the buckets.** `reflected` stays the bucket key and is computed with the configured
  options, so turning the search off, or loosening it, can merge or split buckets. The per-set counts are
  reported, never keyed on.
- Case-insensitive matching folds ASCII letters only: a payload is a byte string, and Unicode folding can
  change a sequence's length. Counts are non-overlapping and capped at 10,000 per payload per response.
- "Pre-URL-encoded" means before Intruder's final "URL-encode these characters" pass, i.e. after the payload
  processing rules — the same point Burp takes it. Recursive-grep and Collaborator payloads are never
  URL-encoded, so both forms are the same bytes.
- Not exported to the CSV; the JSON report carries the counts.

### Define extract grep from response (df8r)

**Burp:** results workflow "Define extract grep from response — Open the response extraction rule dialog"; the
dialog (`Zh5c`) rebuilds its rule from a highlighted selection ("Update config based on selection"), growing a
start-after anchor and an end-at delimiter at token boundaries (6 to 200 characters) until each occurs first
against the selection, and offers it as `quote(prefix)(.*?)quote(suffix)`, or `$` with no suffix.
**burpsy:** the row menu's "Define extract grep from response" opens the row's stored response; highlighting
in the Raw view rebuilds the rule (`lib/intruder-extract.ts`), the rule is previewed against that response,
and it is saved into the attack's Grep extract field.

- **One rule, in regex form.** burpsy's Grep - Extract is a single regex (first group of the first match), not
  Burp's list of start/end items, so the rule is stored in Burp's regex-group form, and an existing rule is
  named and replaced deliberately.
- **`([\s\S]*?)`, not `(.*?)`.** A highlighted value can span lines, and neither Go's RE2 nor the browser's
  RegExp lets `.` cross a newline by default. The same pattern string runs in both: the browser preview and
  the engine are checked against shared golden cases (`intruder-extract.golden.json`, run through
  `/api/intruder/run` in `intruder_extract_golden_test.go`).
- **Anchors are cut at 200, not abandoned.** Burp gives up on a delimiter whose token runs past 200
  characters (a JWT, a base64 blob) and extracts to the end of the response; burpsy keeps the first 200
  characters, and the first-occurrence check decides whether that is enough.
- **Save requires the preview to extract exactly the highlighted text at the highlighted offset.** Only rows
  with a stored response offer the action (the bucket exemplar, or the attempt that opened its bucket).
- **Applies to the next attack.** Burp can re-run grep over stored results when full payloads are stored; the
  rows of an existing burpsy report keep what they extracted.
- The preview runs on the response as text; a response whose bytes are not valid UTF-8 can preview
  differently from what the engine matches.

### Results capture filter (ip2b)

**Burp:** results/filtering-results.html "Capture filter — Choose which items Intruder captures during the
attack to control resource usage": Discard items without responses, Capture by search term (regex, case
sensitive, negative search), Capture by status code, Capture by annotation. The predicates combine with AND
(`Zbjk.allMatch`): `Zpoo` (no response or a zero-length one), `Zht8` (2xx/3xx/4xx/5xx toggles; no response and
statuses outside 200-599 pass), `Zs3t` (the term in the response; no response does not contain it; negative
inverts), `Zefp` (annotation).
**burpsy:** `capture_filter {discard_no_response, term, regex, case_sensitive, negate, statuses}` on the run
request; the report carries `discarded` and echoes `capture_filter`; buckets gain `example_ordinal`.

- **Counts never shrink.** A discarded item is counted in sent/failed, its error group and its bucket, and in
  `discarded`; it leaves no results row and no stored request or response. Burp has no buckets; burpsy's are a
  summary of everything sent, so they keep counting.
- **A bucket's exemplar is its first captured response.** When the response that opened a bucket was
  discarded, the first captured response landing in it later is stored as the exemplar, and `example_ordinal`
  names it; a bucket with nothing captured has null example ids.
- **The row budget follows the filter.** Without a filter the attempts table keeps ordinals below
  `detail_limit`, as before. With one it keeps the first `detail_limit` captured items in completion order, so
  a filtered attack spends its rows on what the filter keeps. Under concurrency, which captured items fill the
  last rows can vary between runs.
- **Capture by annotation is not offered.** A burpsy result has no comment or highlight at capture time (row
  comments are typed in the browser afterwards), so the predicate could only ever discard everything.
- **Applied from launch.** Burp's filter can be changed mid-attack and "only impacts items generated after it's
  applied"; burpsy's is part of the attack's configuration.
- The session cookie jar still learns from discarded responses: it is fed by the engine's `Observe` hook on
  each bucket's opening response, not by the recorder.

### Store requests / Store responses (nqww)

**Burp:** configure-attack/settings.html "Store requests / responses - Specify whether the attack saves the
contents of individual requests and responses"; `intruderAttackConfigSettingsStoreRequests` /
`…StoreResponses` (`Zrua`), persisted as `storerequests` / `storeresponses` and read as on unless "false".
**burpsy:** `store_requests` and `store_responses` on the run request (absent = on); the report carries
`requests_stored` and `responses_stored`, and every null id of a half that was not stored is explained by them —
the results table, row menus, extractor columns and CSV say "not stored (attack setting)" rather than implying
nothing came back.

- What is stored differs from Burp by design: burpsy keeps each bucket's exemplar response plus the exact requests
  of the rows and exemplars (one response per distinct behaviour, the engine's memory contract), so these switch
  that set off rather than one request and response per result.
- Off, the attack is otherwise unchanged: every request is sent, bucketed, grepped and reflection-checked, and the
  session cookie jar still learns from the responses (the engine's `Observe` hook, independent of the recorder).
- Burp greys "Store responses" while denial-of-service mode is on; burpsy has no denial-of-service mode (see
  the fmxv note in the UI), so the two never interact.
## Scan-configuration selection: where burpsy diverges from Burp (saq3.1, 2hze, gmdk — 2026-10-07)

Burp's semantics are ported; these are the places the port knowingly differs, each one narrower than
Burp rather than wider:

- **A check is withheld only when every (type, method) pair it registers is disabled.** FIXED
  2026-10-08 (saq3.2.1): burpsy used to withhold a check on ANY declared-disabled method, which
  agreed with Burp (`Zwy6.java:170-184`) only while every check declared one method. The
  SQL-injection check now declares its five implemented methods on one descriptor, so the rule
  is Burp's own — kept while any pair is enabled — and the disabled METHOD's granularity is the
  probe gate (`ProbeHarness.withhold`), which declines it by name with the count of probes it
  withheld.
- **Detection methods burpsy does not implement cannot run**, whatever a configuration enables:
  Burp Infiltrator everywhere; for SQL injection Collaborator plus the Oracle and MySQL timing
  banks — their payload text is inside ZKM string decoders this tree does not run, so burpsy
  sends none rather than a guess (2026-10-08, saq3.2.1: Error messages, Boolean conditions,
  Time delays, PostgreSQL specific and SQL Server specific ARE implemented now, gated per
  technique inside the one SQL-injection check). They are declined by name
  (`AuditConfig.DeclinedDetectionMethods`, `AuditOutcome.MethodsDeclined`), never silently ignored.
- **SQL injection detection without a database**, by construction: the vulnapp blind endpoints
  recognise the SHAPE of an injected condition or sleep directive, never burpsy's own payload
  text, and the boolean differential the classifier needs is true-half-identical /
  false-half-different. A finding on the timing bank is a delay against the baseline, so an
  endpoint that sleeps for ANY reason can produce one; the confidence stays `firm` and the
  detail names the exact request. Recovered Burp payload banks are limited to PostgreSQL
  (`Zxpy`) and SQL Server (`Zuyg`) — see sqli_techniques.go's header for what is recovered
  versus documented.
- **Skip lists from a Burp file**: Burp's value is a list of match rules
  (`{parameter, item, match_type, expression}`). burpsy honours parameter NAMES set through
  `/api/scanner/configs`; a file's empty rule list is honoured and a non-empty one is reported unapplied.
- **Server-side-injection class, PROBABLE rows**: Perl, Ruby, Python and unidentified code injection
  take the code-injection family's class (`Zsn3.java:74-76`); their own Burp runner was not located.
- **No console route imports a Burp configuration file.** The import path is the `-scan-config` flag;
  the web console lists the six transcribed presets and saved configurations only.

## Per-run project-option overrides: where burpsy differs from Burp (o2p3 — 2026-10-07)

- **`follow_redirections` follows for the reflected-XSS check only.** Burp's documentation names that
  check as the reason for the setting; its per-check "where necessary" predicate was not located in the
  decompiled tree. Following inside every probe would break open redirection and header injection, which
  read the 30x itself. Reopen if Burp's predicate is found to cover other checks (stored XSS, error-based
  injection on an error page reached by redirect).
- **The hop budget and cookie replay of a followed chain are the engagement's network settings**
  (`redirects.max_hops`, default 5; `redirects.replay_cookies`), because Burp's scan configuration names
  neither.
- **Timeout overrides apply to the probes a run sends while it runs.** The deferred phase
  (`FinishScan`: stored re-fetch, out-of-band polling) runs after the run returns and uses the
  engagement's timeouts. A normal timeout plus a connect timeout above twenty minutes combined is capped
  at the sender's ceiling; either one alone above twenty minutes is refused at import, naming the limit.

## AMF bodies are not parsed — declined (2026-10-08, burpsy-react-ui-6v4d)
- **Burp:** classes `ContentType.AMF` / `MimeType.LEGACY_SER_AMF` and audits `PARAM_AMF` insertion
  points inside Action Message Format bodies (BlazeDS / GraniteDS, Flash and Flex remoting).
- **burpsy:** no AMF codec; an AMF body is opaque, and gets no parameter-level audit — only the
  entire-body point, which carries the scanner's payloads as raw bytes.
- **Decision: declined.** Flash reached end of life in 2020 and AMF remoting endpoints are now rare
  enough that an AMF0/AMF3 codec (object graphs, references, externalizable types) is not worth its
  maintenance. **Re-open** when an engagement brings a live AMF endpoint; the codec would slot in as a
  nested-point container beside JSON and XML in `bcheck/insertion.go`.

## Hidden-input guessing: where burpsy differs from Param Miner (2026-10-08, burpsy-react-ui-wlz8)
- **Burp:** Param Miner is a BApp (Extensions > Param Miner > Guess params: GET parameters, cookie
  parameters, headers, everything). Confirmed inputs are logged to its Output tab and raised as
  "Secret input" issues. burpsy builds it in as an on-demand row action ("Guess hidden inputs…",
  `POST /api/hidden-inputs`), never as part of an audit. The issues are filed as "Secret input: query
  parameter" / "Secret input: cookie" / "Secret input: header", Information severity, and resolve to
  the catalogue's Extension generated issue type (0x08000000). That type is the one Burp gives any
  extension's issue.
- **Wordlist:** about 450 hand-assembled names (229 query, 93 cookie, 135 header;
  `scanner/hidden_inputs_wordlist.go`). This is not Param Miner's list, which is far larger. Param
  Miner also mines names from the target (scope, responses, JS). burpsy does no mining, so it cannot
  find an input whose name is not on its list. The run summary says so.
- **Method:** two identical baselines must match, or the run stops ("the response varies on its own").
  Then, per kind:
  - A control batch of random names. If it changes the response, the kind stops and its names are
    counted as never sent.
  - Batches of 40 query parameters, 30 cookies or 20 headers.
  - Bisection of any batch that changes the response.
  - Confirmation of each candidate: with it the response differs, without it the baseline returns,
    and a second send with a fresh value differs again.

  Param Miner's own heuristics (attribute-level response diffing, its "fuzzy" mode, value-type
  guessing) are not ported. The fingerprint is status, Content-Type, Location and the
  whitespace-normalised body, with every run token stripped. A change confined to another response
  header (for example Set-Cookie or Vary) is missed.
- **Confidence:** Firm when both confirming sends changed the response identically. Tentative when both
  changed it but differently. A value that comes back in the response is also reported as Firm, but only
  after two single-name sends and only when the control's values did not come back. This grading is
  burpsy's. Param Miner's own confidence rules were not available to transcribe.
- **Cache safety:** on by default, a fresh `burpsycb=<random>` query parameter on every request,
  baselines included. It keys each guess to a cache entry nobody else requests, so a guessed unkeyed
  header cannot poison a shared cache. An application that rejects unknown query parameters can have it
  turned off in the dialog. Param Miner's cache-poisoning detection is not ported. The fixtures do not
  exercise a cache.
- **Bounds:** 500 requests by default (route cap 5000). A run that hits the bound says so (state
  `budget`) and counts the names it never sent. A scope refusal or a failed request stops the run
  instead of being counted as tested. Framing and routing headers (Host, Content-Length,
  Transfer-Encoding, Connection, TE, Upgrade, Expect, Proxy-*, …) and Cookie and Authorization are never
  sent as guesses. Method-override headers are sent only with random values, never a real verb.
- **Not built:** guessing body parameters (form or JSON). Param Miner offers "Guess body params"; the
  bead and Burp's tutorial name only the three kinds above. Also not built: multi-request
  selection (Burp lets one launch cover several selected requests; burpsy guesses one exchange per
  run).

## Scanner C: BCheck interpreter and console authoring (burpsy-react-ui-saq3.4, 2026-10-08)

### `removing` send-request actions (movb)
- **Burp:** `bcheck-definition-reference.html` — `removing headers|queries: <names>`, `removing query_string|path|method|body`.
- **burpsy:** all six. Two readings are burpsy's, because the BCheck engine is not in the decompiled tree:
  `removing queries` ("Removes the value of the specified query parameter(s)") drops each named parameter,
  name and value, rather than leaving `name=`; `removing path` ("Removes all path parameters") leaves the
  path `/` and keeps the query. `removing method` sends a request line with no method.
- The same pass fixed two mis-sends: `appending query_string` replaced the query, and `replacing queries`
  appended a duplicate instead of replacing the named parameter's value.

### Console authoring of custom scan checks (kbu1)
- **Burp:** `desktop/extend-burp/custom-scan-checks/` — Import, New (from templates), Validate, Format BCheck,
  Send to Custom scan checks editor + Run test, Export, Delete.
- **burpsy:** the Custom scan checks page gains New (three templates), Import .bcheck…, Validate (with the
  parse error's line and column), Run test against exchanges sent with "Send to custom scan check editor"
  (active drafts send through the audit sender's scope gate; nothing is filed), Save, Export, Delete, and
  Reload for the `--bchecks` directory. Console checks persist with the project (`scanner.custom_checks`).
- **Differences:** a check loaded from the directory is read-only in the console (edit the file and Reload),
  and Delete applies only to console checks, because the file would load it again. Format BCheck is not
  offered: burpsy has no canonical BCheck printer, and a formatter that re-wrote a working check is a risk
  the operator did not ask for. A test run against a Collaborator check needs a configured channel, like an
  audit.
- **Timeout overrides apply to every probe a run sends, its deferred phase included.** `FinishScan`
  (stored re-fetch, then the stored-DOM render) takes the run's configuration and re-fetches through the
  run's derived sender (saq3.3.4). Out-of-band polling sends nothing, so it has no timeout to apply. A
  normal timeout plus a connect timeout above twenty minutes combined is capped at the sender's
  ceiling; either one alone above twenty minutes is refused at import, naming the limit.

## JavaScript analysis keys: where burpsy differs from Burp (9mti — 2026-10-07)

- **Zero means no limit**, from Burp's documentation ("zero or a blank value"); Burp's settings panel
  itself bounds the fields at 1 and above (`Zrde.java:36-37`).
- **A limit keeps the partial result and counts the stop** (`javascript_analysis_skips`, and Skipped for
  a stopped DOM check). Burp "truncates analysis" and raises an alert naming the item; there is no
  separate alert channel here.
- **Reached by these keys since saq3.3.3 and saq3.3.4:**
  - the capture-time static pass (`Capture.ScanExchange`) obeys `use_static_analysis` and
    `max_static_time_per_item`, using the engagement's run configuration;
  - the deferred stored-DOM render in `FinishScan` refuses the browser when the run sets
    `use_dynamic_analysis` false, and counts the pages it declined (`Render.DeclinedByRun` in the deferred block).
- **Still not reached:** the crawl's rendered-location pass honours `use_dynamic_analysis` but not
  `max_dynamic_time_per_item`, because it has its own location cap.
- **`fetch_out_of_scope_resources` and `request_missing_dependencies` remain unapplied**, as before.

## Audit queue priority: Burp's documented rule, burpsy's constants (2026-10, burpsy-react-ui-ftk2)

`AuditSession` starts items in priority order (`internal/scanner/audit_priority.go`). The score is
0.8 × attack-surface exposure + 0.2 × interest level, the rule `scanner/auditing.html` documents.
Outcomes still come back in the order requested, and `start_order` reports the order and each item's
score. Where burpsy's version differs from Burp's:

- **The constants are burpsy's.** The decompiled tree has no readable scoring class.
  - Exposure is an item's new insertion points, identified by host, path, kind and name, as a share of
    the most any remaining item adds.
  - Interest is the mean of three factors: a state-changing method, structured content, and
    authentication (an Authorization or Cookie header).
- **Recalculation happens once per placement within a batch.** It is not repeated each time the crawl
  adds an item. Above 2,000 items, scoring is a single pass.
- **No cross-session memory.** Burp discounts points already audited in the current scan. burpsy does
  so only within one session, so a later sweep tick does not discount what an earlier tick covered.

## Light-audit tier: the response-shape half of "repetitive behaviour" (2026-10, burpsy-react-ui-vjjs)

7bkj implemented the type-occurrence half of Burp's "Skipped due to repetitive behavior" (`Zq5`) and
declined the content half, because the engine could not then say what it had compared. The probe
harness now records each probe's response shape. A point raises its type's repetition prior only when
both of these hold:
- it was clean, meaning no probe found evidence;
- every probe's response matched the baseline's status, with a body length within 2% or 32 bytes,
  whichever is larger (`ProbeHarness.inertSince`).

A point whose input changed the status or the page is behaving rather than repeating. It no longer
counts toward skipping later points of its type (`TestAPointWhoseInputChangesTheResponseIsNotRepetitive`).
Where this differs from Burp:
- **Shape, not content.** Status and length are compared, not a structural diff. Echoing the input back
  is repetition, the same behaviour for every point, so reflection alone does not break it.
- **The constants are burpsy's.** Burp's similarity measure is not in the readable decompiled tree.

## Platform decisions: Burp capability families mapped and declined (2026-10, burpsy-react-ui-4ep5)

This section is a **Burp-parity** ledger, not a Rust-parity one: it records Burp Suite capability
families that burpsy does not implement **by decision**, so the parity map has no silent holes and a
reader can tell "absent on purpose" from "not yet noticed". Burp evidence cites the decompiled tree
(Burp 2026.7.1, build 51467) unless stated; the installed Burp is 2026.7.3 (build 52685) — see
`/root/burp-re/SOURCE-OF-TRUTH.md` §1. Doc paths are relative to
`/root/burp-re/in/extract/resources/Documentation/burp/documentation/`. burpsy evidence is as of
master `b0f8ed2`; every "absent" below is a grep **and** a read of each hit, because a grep miss alone
is weak evidence.

The shared reason for most entries: burpsy is open source and single-operator. It has no vendor
backend, no licence, no PortSwigger account and no credit meter, so a capability whose substance is
"talk to PortSwigger's service" has nothing to talk to.

### Licensing and licence activation (burpsy-react-ui-9g5y)
- **Burp:** 14 licensing controls in the decompiled UI inventory
  (`out/ui_report/setname_inventory.tsv`: `licensingWizardActivateLicensePanel`,
  `licensingWizardActivateLicenseProxyCheckbox`, `wizardPanelProject1EnterLicenseAnchor`, …).
- **burpsy:** no licence or activation code. `grep -rliE 'licen[cs]e' burpsy-go/internal burpsy-go/cmd`
  hits only wordlists, vulnapp fixtures and unrelated prose; `grep -rniE 'activat'` hits UI
  row-activation handlers (`ui/table.tsx`), nothing licence-related.
- **Reason:** there is nothing to license. **Re-open:** never, unless burpsy acquires a paid tier.

### Update channel, early adopter, performance feedback (burpsy-react-ui-9g5y)
- **Burp:** `desktop/settings/suite/updates.html` ("The Updates settings enable you to control how
  often Burp updates"), `early-adopter.html` ("There are two release channels for Burp Suite: Early
  Adopter and Stable"), `performance.html` ("…share feedback to help improve performance").
- **burpsy:** already declined, with reasons, on the Suite settings page by
  **burpsy-react-ui-fyua** — `internal/web/ui/src/pages/settings.tsx:3134` (Performance feedback) and
  `:3147` (Early adopter channel: "there is one build, not a stable/early split"). Not restated here.
- **Re-open:** a release channel or telemetry endpoint exists for burpsy.

### PortSwigger account sign-in, Burp AI and AI credits (burpsy-react-ui-9g5y)
- **Burp:** `desktop/burp-ai/index.html` ("Using them requires AI credits"),
  `desktop/burp-ai/ai-credits.html` ("AI credits give you access to Burp Suite's AI-powered features
  and to Burp AT"), `desktop/burp-at/*`. The shipped default hotkeys include three Burp AI rows —
  `explain_this` Ctrl+E, `send_to_burp_at` Ctrl+G, `open_burp_at` Ctrl+Shift+G
  (`/root/burp-re/in/extract/resources/Preferences/UserDefaults.json`; no decompiled `.java` names
  them, the JSON is the citable source).
- **burpsy:** no sign-in and no credit meter. The **self-hosted** equivalents are tracked, not
  declined: the operator-configured LLM endpoint (burpsy-react-ui-ei0v, closed;
  `internal/scanner/triage.go`, `internal/web/api_triage.go` — "Burp AI's 'second look' shape"), the
  MCP server (q31t), and the open epics burpsy-react-ui-riw8 (Explainer, Explore Issue, agent
  workflows) and burpsy-react-ui-wiwh (`ai.prompt` for plugins).
- **Declined:** the PortSwigger account, the credit system, and the three hotkeys bound to Burp AI as a
  hosted service. ga7i/2czi cites this entry for those three rows.
- **Re-open:** the AI features themselves re-open through riw8 on the operator's endpoint; the account
  and credits never do.

### Enterprise / CI integration (burpsy-react-ui-9g5y)
- **Burp:** `out/clean/jdt_src/burp/Zeqc.java:945` — `"Names are not supported in the desktop
  product - this is an Enterprise-only feature"`.
- **burpsy:** already declined in `ROADMAP.md` "Deliberately out of scope" (row "Enterprise/CI
  features", ROADMAP.md:194). Not restated here.

### BApp Store account-side sharing (burpsy-react-ui-9g5y)
- **Burp:** BApp Store submission and the account-bound parts of extension distribution
  (`desktop/extend-burp/extensions/*`).
- **burpsy:** the BApp Store and the Java/Python/Ruby (Montoya) extension model are already declined by
  **burpsy-react-ui-wkkz** and ROADMAP.md "Loading Burp extensions — no JVM". burpsy's plugins are local
  JSON-RPC executables named on the command line, so there is no store to share through.

### Burp Infiltrator (burpsy-react-ui-azbh)
- **Burp:** `desktop/tools/infiltrator.html` — "Burp Infiltrator makes non-reversible changes to
  application bytecode"; "The application developer or administrator installs the Burp Infiltrator tool
  by running it on the machine containing the application bytecode"; its reports reach Burp through
  Collaborator ("Any Burp payloads containing Burp Collaborator domains are fingerprinted based on their
  unique structure").
- **burpsy:** `grep -rni infiltrator burpsy-go/internal burpsy-go/cmd` hits only the intruder wordlists
  (`burp-words-11-letter.txt`, `burp-words-12-letter.txt`) — no implementation.
- **Reasons:** it needs an agent installed into the target's JVM/.NET runtime, and burpsy has no JVM and
  no bytecode tooling (ROADMAP "Loading Burp extensions — no JVM"); its findings flow through a
  Collaborator server burpsy does not host (ROADMAP "Hosting a Collaborator server"); and instrumenting
  a client's runtime is outside what a black-box proxy engagement normally authorises.
- **Re-open:** a burpsy-hosted interaction server plus an operator-supplied agent contract.

### Shared Organizer collections (burpsy-react-ui-rzqc)
- **Burp:** `desktop/tools/organizer/collections.html` — "You can also share collections with other
  Burp users"; Swing controls `organiserCollectionShareButton`, `organiserCollectionSharedStatusLabel`
  (`ViewComponent0135`), `organiserCollectionShareMenuItem`, `organiserCollectionCopyLinkMenuItem`,
  `organiserCollectionUnlinkMenuItem` (`BurpClass5926`).
- **burpsy:** no sharing (`grep -rniE 'shared collection|unshare' burpsy-go/internal` hits only
  wordlists).
- **Decision: declined.** Sharing rides on PortSwigger accounts. burpsy is a single-operator local
  process whose console is deliberately loopback-only behind the same-origin gate
  (`internal/web/api_sameorigin.go`); multi-operator sharing would first need console authentication,
  a different and much larger design.
- **Near-term substitute:** export a collection to a file and import it elsewhere —
  **burpsy-react-ui-0ghj**. Today `pages/organizer.tsx` exports CSV only, which loses the message bytes.

## Scan launch, API scans and task control (burpsy-react-ui-cmx5, 2026-10-08)

### Crawl scope (501u)
- **Burp:** `desktop/running-scans/setting-pro-scope.html` — the crawl is restricted to the configured URLs'
  final directory by default; "Detailed scope configuration" takes URL prefixes or advanced matching rules.
- **burpsy:** seed directories (the New scan dialog's default), the engagement scope, or include/exclude URL
  prefixes — always inside the engagement scope, at the frontier and at the send gate. Burp's "advanced
  matching rules" (per-field host/port/file regexes) are not offered: the engagement scope already has that
  rule shape, and a second rule editor scoped to one crawl would duplicate it. An API caller that omits
  `scope` keeps the engagement scope alone, as before.

### Postman Collections for API scans (r39r)
- **burpsy:** Postman Collection v2.0/v2.1 is read into the same operation model as OpenAPI: folders walked in order,
  collection variables substituted (an undefined `{{var}}` is counted as a placeholder; an undefined leading
  `{{baseUrl}}` makes the request relative to the scan's base URL), disabled headers/query/body fields left out,
  bearer/basic/header-apikey auth inherited collection → folder → request with `noauth` overriding, and raw,
  urlencoded, form-data (text fields; a file part names a file on the author's machine and is skipped) and
  GraphQL bodies. Pre-request and test scripts are not run.
- **Not done:** SOAP WSDL on the API-only path is still refused by name — tracked as the rest of this bead.

### Isolated scans (13uw)
- **burpsy:** "Run isolated scan" in New scan (and `isolated: true` on `POST /api/crawl`) tags the crawl's traffic
  with the source `isolated-scan`; the site map skips those exchanges, and `/api/issues` / `/api/findings` omit
  findings whose every occurrence is on one (a finding also seen on ordinary traffic stays). The task's own view
  reads `/api/issues?include_isolated=1` and gets them flagged. Burp keeps an isolated scan's results in a store
  of their own; burpsy keeps them in the project, filtered by source, so they survive a restart and HTTP history
  still lists the traffic.
## Crawler B (burpsy-react-ui-re16.2, 2026-10-08)

### Recorded login sequences (burpsy-react-ui-xhtk) — built, with these differences from Burp

- **Burp:** `scanner/authenticated-scanning/recorded-login-sequences.html` ("a JSON-based 'script' that
  you can import"; "TOTP multi-factor authentication. WebAuthn."), `desktop/running-scans/configuring-app-logins/adding-recorded-logins.html`
  ("Replay existing logins", "See as JSON"), the editor's six event kinds (Zf50: Click, Type, TOTP,
  Key press, Go to, Wait), the TOTP generator (Zxf1, validated by Zhfe against `^[A-Za-z2-7]+=*$`) and
  the status check (Zg5_/Zrs3: URL + confirmation text, "Required when using TOTP steps").
- **burpsy:** `internal/session/recorded_login.go` (model, Burp Login Recorder and Chrome DevTools
  Recorder importers, redacted views), `internal/session/totp.go` (RFC 6238, SHA1/256/512),
  `internal/domexec/session.go` + `login.go` (isolated, scope-gated replay), `internal/crawler/recorded_login.go`
  (login before the first fetch, session jar on every request, Set-Cookie absorption, re-login on detected
  expiry within `max_relogins`, `Report.login`, stop `login-failed`), routes `/api/crawl/logins` and
  `/api/crawl/logins/replay`, `recorded_login` on `POST /api/crawl`, and the New scan dialog's
  "Application login" picker and library (`ui/recorded-logins.tsx`).
- **Difference — out-of-scope hosts during the login are REFUSED.** Burp: "When running a recorded login
  sequence, Burp Scanner can temporarily follow any out-of-scope links that are necessary to perform the
  login sequence." burpsy enforces scope on every request the replay browser sends — Fetch interception on
  the full URL in the tab, plus a per-browser-context proxy on the authority that also covers out-of-process
  iframes, popups and workers (`TestTheSessionProxyStopsWhatAnOutOfProcessFrameLoads` proved Fetch alone
  misses those). An SSO identity provider must be added to scope; every refused request is listed in the
  replay result and in `report.login.blocked`, so the failure is named rather than mysterious.
- **Difference — an empty scope refuses the replay** (409 on Replay, 400 on crawl start). In this build an
  empty scope means "everything"; a browser that follows redirects on its own is not run against that.
- **Declined — WebAuthn / passkeys.** Burp captures passkeys during recording and replays them through a
  virtual authenticator. burpsy imports no passkey material and offers no WebAuthn step; a recorded script
  whose login needs a passkey replays up to that point and fails at it, named. Re-open with CDP
  `WebAuthn.addVirtualAuthenticator` + `addCredential` and a credential-import format.
- **Declined — recording inside burpsy.** Burp's own browser has the Login Recorder extension
  pre-installed. burpsy imports the script that extension (installed in any Chrome) copies to the
  clipboard, plus Chrome DevTools Recorder exports, and provides the step editor, "See as JSON" and Replay.
  There is no in-console recorder. Re-open: inject a recorder over CDP into the operator browser
  (`internal/browser`) — `Runtime.addBinding` plus a capture script.
- **Import fidelity:** every recorded event that does not become a step is listed in the import reply
  (`notes`): `scroll`, `rightClick`, `userNavigate`/`clientSideRedirect` (re-happen on replay), iframe
  and shadow-DOM elements (not replayable here), new-tab actions (the replay runs in one tab). A typed
  6-8 digit code into a one-time-code-looking field is flagged as a probable TOTP step, as Burp DAST does.
- **Not captured to history:** the replay's own traffic goes from the headless browser to the target,
  scope-gated but not recorded as exchanges. The crawl's traffic after login is captured as before.
- **Remote CDP engines** (`-dom` pointing at obscura/lightpanda) are refused for recorded logins: browser
  contexts and per-context proxies were only verified against Chrome. Without `-dom`, burpsy starts its own
  headless Chrome for the login, as Burp uses its browser "even if you have not selected Use Burp's browser".
- **Rendered-DOM audit of an authenticated crawl is declined, with the reason on the report:** it renders
  logged out, and comparing those renders with logged-in wire bodies would report false script-only
  content. The crawl's own render pass (link discovery) does run inside the login's browser context.
- **Burp's "Browser settings" on a TOTP step** (three switches in Zrsc) are not represented; their meaning
  is not recoverable from the decompiled panel.
- **Verified vs ran.** A replay is `verified` only when its status check found the confirmation text.
  Without a status check (optional except with TOTP, as in Burp) a sequence whose password was rejected
  still "runs every step"; the replay result, the crawl's login card and `report.login.verified` say
  "not verified" rather than "logged in".
- **TLS:** the replay browser follows the operator's one certificate-verification setting (Settings →
  Network, `tls.verify`): verification on refuses a self-signed staging host on step 1, named; off accepts
  it — applied per tab, so the shared DOM-check browser keeps verifying.
- **Redaction:** reported URLs (per-step, final, refused) keep scheme, host, path and parameter NAMES and
  drop query values and fragments (`code=…`, `#…`), as cookie values are never reported.
- **Chrome's own traffic:** one `CONNECT www.google.com:443` per new browser window still appears in a
  replay's refusal list (it is refused; no page asked for it). Chrome-internal services that produced
  more such tunnels are switched off in `domexec.NewBrowser`.
- **Authenticated render pass:** requests the logged-in render pass's pages make are scope-gated too;
  refusals are reported in `report.login.render_blocked`, so a page whose script is on an out-of-scope CDN
  renders empty with the reason stated.
- **Burp's login crawl events** (Zwkv `RECORDED_SEQUENCE_STARTED/ERROR`, `PAGES_FOUND_AFTER_LOGIN` /
  `NO_PAGES_FOUND_AFTER_LOGIN`): each replay is a `crawl.login` event in the task's event log, and
  `report.login.pages_found_after_login` carries the count. `RECORDED_SEQUENCE_BROWSER_ERROR` is a 400 at
  launch (no browser, no crawl task). The credential-login events (`ATTEMPTING_TO_LOGIN`,
  `REGISTERING_USER`, login/registration page found) belong to burpsy-react-ui-uzil, not built here.

### Live crawl view (burpsy-react-ui-1l3x) — built, with these differences from Burp

- **Burp:** `desktop/running-scans/results/live-crawl-view.html` — "a rendered view of the page that Burp
  Scanner is currently crawling, as it would normally appear in a browser."
- **burpsy:** the crawl task's "Live crawl view" tab, fed by `GET /api/crawl/live?task=N` (riskRead):
  the phase (starting, logging in, fetching, rendering, finished), the request in flight (a new
  `crawler.Config.OnSend` hook — `OnFetch` fires only after capture), the last 50 fetches newest first,
  and a viewport JPEG taken by the render pass in the same tab that read the DOM.
- **Difference — a frame exists only when the crawl renders.** Burp's crawler is browser-driven, so every
  page has a picture. burpsy fetches over HTTP and renders only with `-dom`; frames come from that pass,
  throttled to one a second at the source (a render is not asked for a picture it would throw away).
  Without a browser `frame` is `null` and `frame_note` says why, and the console shows the last HTML
  page's WIRE bytes in a sandboxed iframe behind a deny-all Content-Security-Policy — labelled as wire
  HTML, not as what a browser would show, and loading nothing from the target.
- **Difference — polled, not streamed.** The console polls once a second while the crawl runs; there is
  no SSE/WebSocket route for frames.
- **No frame while a recorded login replays**, by design: the page on screen is credentials being typed.
- **Frames are not retained:** the one latest frame is dropped when the crawl finishes or is evicted; the
  fetch list stays with the run.
- **Measured fix recorded:** in this Chromium (147, headless) `Page.captureScreenshot` in a non-front tab
  hung until the 30 s tab timeout and failed the render; the capture now brings the tab to the front and
  is bounded at 3 s (`domexec.captureFrame`, `TestEveryRenderThatAsksForAFrameGetsOneQuickly`).
## Redirect types: JavaScript-driven is refused (2026-10-08, burpsy-react-ui-z9zi)
- **Burp:** Settings → Network → HTTP → Redirections, "Allowed redirect types": 3xx with Location,
  any status with Location, the Refresh header, the meta refresh tag, and JavaScript-driven. Defaults
  (`ProjectDefaults.json`, `project_options.http.redirections`): the first, third and fourth on.
- **burpsy:** `redirects.types` on `/api/network/settings` carries all five under Burp's key names,
  with Burp's defaults when unset. The first four are honoured by the sender's follower; a Refresh or
  meta-refresh hop is a bodiless GET.
- **Divergence:** `understand_javascript_driven: true` is refused by name. Following a script-driven
  redirect means executing the page's JavaScript, which the sender does not do; storing the flag
  would be a promise nothing keeps.

## HTTP/1 keep-alive reaches the raw send path only (2026-10-08, burpsy-react-ui-ry5n)
- **Burp:** Settings → Network → HTTP, "Use keep-alive for HTTP/1 if the server supports it" (off by
  default; idle connections closed after five seconds) "affects all Burp Suite tools", with per-tool
  overrides in Repeater ("Enable HTTP/1 connection reuse") and Intruder.
- **burpsy:** `http1.enable_keep_alive` on `/api/network/settings` drives a pool on the sender's raw
  path (`SendRawOutcome`, which Repeater, Intruder and the scanner's raw probes use): a connection the
  exchange left reusable is kept per authority and closed after five seconds idle. `http2.enable_http2`
  ("Default to HTTP/2") reaches both the raw path and the typed transport.
- **Divergence:** the typed `http.Transport` path keeps its own connection reuse whatever the switch
  says, because that transport also carries h2 and disabling keep-alive there would close h2
  connections too. The proxy's upstream leg is unaffected. Repeater's and Intruder's per-tool reuse
  overrides are not offered.

## Platform-authentication prompt does not replay the failed request (2026-10-08, burpsy-react-ui-3xnt)
- **Burp:** "Prompt for credentials on platform authentication failure" displays an interactive popup
  when a host challenges, and the request goes on with the credentials entered.
- **burpsy:** with `prompt_on_authentication_failure` on, every Basic/Digest/NTLM/Negotiate challenge
  that no rule answers (or that refuses the rule's credential) is recorded in netauth, where the sender
  and the proxy already report challenges; the console shows a prompt for the most recent one and saves
  the answer as a platform-authentication rule for that host.
- **Divergence:** the request that failed has already returned its 401 to its client and is not held or
  resent; the credential applies from the host's next request. A raw Repeater/Intruder send never
  consults platform authentication (the raw path sends the bytes as written), so it never prompts.
  Negotiate is recorded but cannot be answered by this build.

## Run-macro parameter update reads HTML forms and links only (2026-10-08, burpsy-react-ui-8gk8)
- **Burp:** after a "Run a macro" action, "update the current request with parameters matched from the
  final macro response" and "with cookies from the session handling cookie jar", each as all-except or
  only-the-following, plus "Tolerate URL mismatch when matching parameters".
- **burpsy:** all five choices, under Burp's keys (`update_with_params`, `match_params`, `params`,
  `tolerate_url_mismatch`, `update_with_cookies`, `match_cookies`, `cookies`). Parameters are derived
  from the final response's HTML forms (input, textarea, select against the form's action) and link
  query strings, and update only parameters the current request already carries in its query string or
  urlencoded body. A stored action without the fields behaves as before: no parameter update, the whole
  jar.
- **Divergence:** values in JSON, multipart bodies, or script are not derived or updated. The cookie
  choice applies to the re-sent current request; macro steps always carry the whole jar.

## Logging: unattributed traffic is not logged, and a project switch keeps the running logger's files (2026-10-08, burpsy-react-ui-nvfl)
- **Burp:** Project settings → Logging appends requests and/or responses from Proxy, Scanner, Repeater,
  Intruder, Sequencer and Extender (or All tools) to files.
- **burpsy:** `GET/PUT /api/project/logging` under Burp's keys (`requests` / `responses`, tool → absolute
  path, blank off), persisted with the project and applied at startup; every exchange the traffic store
  records is written by one background writer in Burp's log-file shape. The crawler counts as Scanner.
- **Divergence:** traffic this build does not attribute to a tool (Sequencer captures and extension
  sends among it) is not written, under All tools either. An in-console project switch does not re-apply
  the opened project's logging settings until the next start. A full writer queue drops entries and
  counts them (`stats.dropped`) rather than slowing the proxy.
## Proxy listener: in-browser interface and Miscellaneous switches (2026-10, burpsy-react-ui-beof, 0q9d)

- **The in-browser interface is plain HTTP only.** `http://burpsy`, `http://burpsuite` and the
  listener's own address answer with a welcome page and the CA certificate in DER at `/cert`. Requests
  to the interface are not recorded. `https://burpsuite` would need the CONNECT path to mint a
  certificate for a host that resolves nowhere and to answer without an upstream. The certificate is
  what makes HTTPS through the proxy work at all, so the HTTP page is the one that matters.
- **"Use HTTP/1.0 in requests to server" changes only the version token.** A chunked request body
  keeps its framing, which an HTTP/1.0 origin may refuse.
- **"Use HTTP/1.0 in responses to client" is applied with the other response options**, so history
  records the status line the browser received.
- **"Suppress error messages" covers burpsy's own explanatory replies:** scope and egress refusals, a
  failed CONNECT, an unattributable request, and a refused WebSocket retarget. The connection closes
  instead. An operator's intercept drop is not an error and still answers 403.
## MCP surface: divergences from Burp's agent tools (2026-10, burpsy-react-ui-2jrr.1)

Burp-parity entries for the MCP surface sub-epic. Each says what Burp does, what burpsy does, and why
the two differ. Burp evidence is the decompiled agent registry
(`/root/burp-re/out/deobf/ai_agentic/burp/agentic/`).

### Collaborator long-poll wait bound (burpsy-react-ui-myr2)
- **Burp:** `poll_for_collaborator_interactions` takes `wait_seconds` 1–300
  (`toolargs/PollForCollaboratorInteractionsArgs.java`, `@Range(min = 1L, max = 300L)`).
- **burpsy:** `POST /api/collaborator/poll` takes `wait_seconds` 0–60 (0 = return at once) and refuses
  61+ with 400 (`internal/web/api_collaborator_poll.go`, `maxCollaboratorWaitSeconds`).
- **Divergence:** a long-poll holds one HTTP request and one MCP tool call open for its whole wait;
  60 s sits well inside every client timeout on that path, where 300 s does not. A caller that needs
  longer polls again. burpsy also answers a fourth status, `unavailable`, when no channel is open or
  the log cannot be read, instead of waiting out the timer and reporting `empty`.

### Message windows: regex dialect and body source (burpsy-react-ui-yahm)
- **Burp:** `inspect_http_message` takes `pattern` as a **Java** regex and `case_insensitive` as Java's
  ASCII-only `CASE_INSENSITIVE` (`toolargs/InspectHttpMessageArgs.java`); it returns only the first
  match.
- **burpsy:** `GET /api/message/{id}?pattern=` compiles **RE2** (Go `regexp`): no backreferences or
  lookaround, linear time; `case_insensitive` prefixes `(?i)`, which is Unicode-aware. It returns the
  first match as the anchor and also lists up to 100 match offsets (`matches`) for paging. The window
  is over the wire bytes unless `decoded=true` asks for the body with chunking and Content-Encoding
  undone; a decode that is impossible is a 400, never a silent fall-back.
- **Divergence:** RE2 is the regex engine every other burpsy search uses (suite search, history search,
  scope `regex:` arms), and its linear time matters on a multi-megabyte body an agent chose the
  pattern for. A Java-only construct is refused with the compile error rather than approximated.

### Datasets: one route over burpsy's lists (burpsy-react-ui-co88)
- **Burp:** `search_dataset` / `summarize_dataset` work on a `dataset_id` that every `get_*`/`list_*` tool
  returns, with `pages` (1–10) × `page_size` (1–100), `wait_seconds` 1–300 and a Java regex
  (`toolargs/SearchDatasetArgs.java`, `InspectDatasetArgs.java`).
- **burpsy:** `GET /api/datasets/{source}` names the source directly (history, issues, sitemap,
  tool-log, ws-history, intruder/{task_id}) instead of a dataset id minted by an earlier call; one
  page of `limit` ≤ 500 per call; `wait_seconds` ≤ 60; RE2 regex; facets are top-20 values per column
  with `distinct` and `other` counts.
- **Divergence:** burpsy's lists are live views of the store, not snapshots, so there is no dataset to
  mint and expire — the source name is the handle, and `since` gives an incremental read instead.
  Organizer items, scan configurations and Burp's bulk-send results are not sources yet: the organizer
  route is riskLocal and carries operator notes, and burpsy has no bulk-send engine (its scripts
  arrive with burpsy-react-ui-wiwh). The wait bound is the one the collaborator poll states.

### Structured send edits (burpsy-react-ui-vuxy)
- **Burp:** `send_request` takes `request_id` / `url` / `host`, 15 edit ops and `http_version`
  `auto|http_1|http_2` (`toolargs/RequestSpec.java`, `EditOperation.java`, `HttpVersionSpec.java`).
- **burpsy:** `POST /api/repeater/send` with `from_message` / `from_exchange`, `edits`, `http_version`
  `auto|1.1|2`, `dry_run` (`internal/reqedit`, `internal/web/repeater_edits.go`). The 15 ops plus
  `set_json_field` (a dotted path; replaces that value's bytes or inserts the key into its parent).
- **Divergences, each on purpose:** no `url`/`host` builder (a typed `request` with `target` already
  does that); `set_query_param` / `set_body_param` insert the value **as written** (URL-encode it
  yourself — an encoder would decide for you what a parameter-pollution or encoding test sends;
  `set_form_fields` does encode); `set_header` replaces the **first** occurrence and leaves later
  duplicates (smuggling research needs them), while `delete_header` removes all; `raw_replace` replaces
  every occurrence and refuses when there is none; a body op on a chunked request is refused rather
  than re-framing it. A structured send is authorised on its final bytes including the path, which is
  stricter than the plain send's host-level gate.

### Task handles and pushed notifications (burpsy-react-ui-wdza)
- **Burp:** a 15 s sync window then a `TaskHandle` (uuid, status, `pollIntervalMs`, `ttlMs`)
  (`task/SyncWindow.java`, `TaskHandle.java`); MCP progress notifications; finished operations and
  High-severity issues "reported back automatically".
- **burpsy:** the transport applies the same 15 s window to any console call that answers 202 with a
  `task_id`, and starts an audit as such a call (`POST /api/audit/{id}` `{"async": true}`); the handle
  is the console task id (`GET /api/tasks/{id}`, `burpsy_task_status`); progress notifications for a
  call with a progress token; `notifications/message` for finished tasks and High/Critical issues.
- **Divergences:** the handle has no `ttlMs` — a finished task's row lives until the registry's
  500-row bound evicts it, and an async audit's full result body is kept for the last 64 tasks. The
  window applies to any call answering 202 with a `task_id` (crawl, API scan, selection audit), and
  the transport starts only `POST /api/audit/{id}` that way. Still synchronous through MCP: Intruder
  (its run returns its own report and can be stopped through `POST /api/intruder/attacks/{task}/stop`),
  the queue's "audit again" (`POST /api/scanner/audit-items/{id}/again`), and the legacy alias
  `POST /api/scanner/audit` (not on the grouped surface). Push is for tasks finished and issues found *after* the session
  started.

### Skills (burpsy-react-ui-ulsy)
- **Burp:** PortSwigger-packaged skills run with `run_skill_script` (`McpBurpTool.java`), delivering
  files to a code-execution sandbox (`toolargs/CodeExecutionMeta.java`); listed in the client with the
  tools they use (`desktop/burp-at/skills.html`).
- **burpsy:** an operator-named directory of JSON manifests (`-skills DIR`, `internal/skills`), served
  as MCP prompts with a banner naming the tools each skill calls; per-project disable in Settings.
- **Divergence:** prompt-only skills run; a script-bearing skill is listed as unavailable with its
  reason, because burpsy has no scripting runtime yet (burpsy-react-ui-wiwh). There is no packaged
  library — burpsy ships the mechanism, not PortSwigger's techniques. The per-project switch is its
  own setting (`skills.disabled`) rather than part of the per-tool policy store planned in
  burpsy-react-ui-2jig, which arrives in the second 2jrr PR.
## Repeater A: editor views, tab workflow, per-tab overrides, GraphQL actions (burpsy-react-ui-i9ti.1, 2026-10-08)

### Save entire history — the file format (pznm)
- **Burp:** `desktop/tools/context-menu.html` — "Save entire history — Saves the change history for the
  selected request to a file"; the menu item is `burp.Zgkb` ("Save entire history", action id 134832).
- **burpsy:** the tab context menu's *Save entire history* posts the tab's message ids to
  `POST /api/repeater/history-export` and downloads a JSON file, `format: "burpsy-repeater-history/1"`,
  with each send's request and response bytes base64-encoded from the store (byte-exact, binary bodies
  included), plus `skipped` (WebSocket sends, sends with no stored message) and `missing_responses`.
- **Divergence:** Burp's on-disk format for this file is not in the evidence — the serializer behind
  action 134832 could not be traced in the decompiled jar, and neither the string table nor the
  bundled docs describe it. burpsy writes its own declared format rather than guess at Burp's; a file
  saved by one cannot be loaded by the other. Re-open with a Burp-saved sample file.

### Unpack compressed responses — Brotli, and display-only (of0z)
- **Burp:** `settings/tools/repeater.html` — "By default, Burp automatically unpacks any gzip, deflate, and
  Brotli-compressed content received in responses."
- **burpsy:** on by default per tab (`unpack_responses`, off only when a tab says `false`); the send's answer
  carries `response_unpacked` beside the bytes that arrived, and the pane shows it with an "unpacked gzip"
  badge. gzip and deflate decode; a `br` response is shown as it arrived with `unpack_error` naming why.
- **Divergence:** no Brotli decoder in this build (`httputil.Unpackable`), and unpacking is display-only — the
  stored exchange keeps the compressed bytes, where Burp's Repeater message is the unpacked one.

### Streaming response timeout — which responses it applies to (of0z)
- **Burp:** `settings/tools/repeater.html` — "Streaming responses timeout … controls how long Repeater keeps a
  streaming connection open. By default, it's set to 600 seconds … To turn off the timeout, set it to 0";
  which responses are streaming is decided under Network > HTTP > Streaming responses.
- **burpsy:** the per-tab `streaming_timeout_ms` (0 = no cutoff) bounds a declared streaming host's read and,
  for that tab, also promotes a chunked/unframed `text/event-stream` response (whatever the network setting
  says) and any unframed read-until-close response (a held long-poll), over HTTP/1 and h2 (event streams).
- **Divergence:** the tab override widens what counts as streaming for that tab rather than only re-timing
  responses the global rule already recognises — an operator who sets a streaming window on a tab is asking for
  that endpoint to be read as a stream. A framed (Content-Length or non-event-stream chunked) response is never
  promoted.

### HTTP/2 connection reuse — off by default (adkx)
- **Burp:** `desktop/http2/index.html` — "By default, Repeater reuses the same connection for multiple HTTP/2
  requests"; `settings/tools/repeater.html` lists it under Connections, default on.
- **burpsy:** per-tab `h2_connection_reuse` keeps one h2 connection per (tab, target, SNI) open between sends
  (at most 32, closed after 60 s idle) and every answer says `h2_connection: "new" | "reused" | "not-h2"`. Off,
  every send dials fresh, so every request is the first on its connection.
- **Divergence:** the default is off where Burp's is on. Every raw send in burpsy has always dialled fresh, and
  turning reuse on silently would change what "this request's response" means for every existing tab; an
  operator turns it on per tab in Config. A failed send on a reused connection is reported, never retried.

### Response change highlighting — Raw view only (b4gt)
- **Burp:** "Burp Repeater highlights any changes between the new and original responses"
  (testing-for-reflected-xss.html), in the response editor.
- **burpsy:** the word diff against the previous send in the tab is painted on the response's Raw view; the
  header button counts the changes and says "· Raw view".
- **Divergence:** not painted on Pretty (which reformats the body, so diff positions would name the wrong
  characters) or on Hex/typed views. An HTML or JSON response opens on Pretty, so the operator switches to Raw
  to see the marks.
## Intruder B: attack tabs, Request item again, Collaborator interactions, anomaly ranking (burpsy-react-ui-xixe.2, 2026-10-08)

### Anomaly ranking (burpsy-react-ui-pglp)
- **Burp:** Montoya `ResponseVariationsAnalyzer` (33 `AttributeType`s: tag names, anchor labels, input names,
  word/line counts, cookie and header names, …) and `RankingUtils.rank(…, ANOMALY)`.
- **burpsy:** `internal/intruder/anomaly.go` reads 8 of them that one response yields cheaply and
  deterministically — status code, content type, body length, word count, line count, page title, Location,
  cookie names — plus the outcome of a failed send. Burp does not document its weights; burpsy's score is the
  sum of −ln(frequency) over the attributes that varied, dense-ranked (1 = least like the rest).
- **Re-open:** the remaining attribute types (tag/anchor/input names, header names, body content hashes) if
  ranks prove too coarse on real attacks.

### Attack tabs (burpsy-react-ui-9bv2)
- **Burp:** each attack tab runs its own attack, concurrently with the others.
- **burpsy:** tabs hold independent configurations and reports, but one attack runs at a time across all
  tabs (`canRun` requires no attack in flight; the menu says why). A report always lands in the tab that
  launched it. Open tabs are capped at 8, because every open tab's report is persisted in the browser and one
  500-row report is about 200K characters of a ~5M-character localStorage quota. The reopen stack is
  session-only, like Repeater's.
- **Re-open:** concurrent attacks need per-attack mutation state on the page (one `useIntruderRun` per tab)
  and per-tab running controls.

### Collaborator interactions per result (burpsy-react-ui-nib6)
- **Burp:** an Interactions column and an interaction-details panel under the selected result.
- **burpsy:** the column, and the details in a dialog opened from the count. The count dedupes one event's
  repeats (protocol, query type, client) within the attempt; the Collaborator page's own count does the same
  across the whole log, which undercounts when one resolver calls back for two payloads
  (burpsy-react-ui-vfqy).
- **Request item again (2rw7)** re-sends one row's stored request; that row's anomaly rank is cleared rather
  than recomputed, since the rank compares the row against the rest of the attack as it was.
## Burp-XML issue export: deliberate divergences (2026-10-08, burpsy-react-ui-m7dk)

The XML export reproduces Burp's grammar — the internal DTD verbatim from the decompiled writer
`burp.Zb2g.ZI`, the element sequence from `Zb2g.Zk`, the requestresponse shape from `Zpa6` — and
where burpsy's data model cannot fill a field the divergence is recorded here, not papered over.

- **burpVersion says "burpsy", not a Burp version number.** The attribute is CDATA and undocumented
  beyond its name; writing "2026.7.1" would be a false claim about which tool produced the file, and
  the DTD — the thing a consumer actually validates — is identical either way.
- **Messages are always `base64="true"`; the `base64="false"` variant is not offered.** Burp's own
  export notes that the raw variant leaves NULL bytes that "strictly break the XML syntax"
  (report-settings.html) and recommends Base64 for strict parsers; raw bytes also cannot round-trip
  through the text-node control-character mapping `Zfkt.ZG` applies (control chars become '.').
  Byte-identical decode is this bead's acceptance bar, and only base64 can meet it.
- **`host ip=""` is always empty.** Burp writes the resolved IP (`Zb2g.Zk`: `var1.ZDe().ZLo()`).
  burpsy's capture store records the host name, not the dialled address, per exchange; inventing an
  IP is worse than the attribute's own documented default. Re-open: record the remote address on
  `core.Exchange` at capture time.
- **No `responseRedirected` element.** Optional in the DTD; Burp writes the pair's redirect flag
  (`Zpa6.Zh`). burpsy does not track whether a stored response was redirect-followed, so the
  element is omitted rather than written with a guessed value.
- **Severity and confidence use burpsy's own grade names.** Burp's XML vocabulary is
  Information/Low/Medium/High/Undefined/False positive (`Ze1r.ZX`) and Undefined/Tentative/Firm/
  Certain (`Zeue.ZZ`). burpsy additionally has Critical (which Burp's enum lacks entirely) and
  Suppressed-negative, and says "Informational" where Burp says "Information". Remapping Critical
  down to High would understate a finding; emitting burpsy's real grade is the honest option.
- **Merged findings export as one `issue` element.** Burp holds one issue per host; burpsy's store
  merges same-issue observations across hosts into one `Row`. The first host leads the `host`
  element, and every occurrence's `requestresponse` still carries its bytes, so no evidence is lost
  — but a consumer tallying issues per host sees one row where Burp would show several.
- **`serialNumber` is the burpsy finding id.** Unique per finding instance for the life of the
  store, which is the property Burp documents ("unique to that individual issue instance"); it is
  not Burp's serial space and a consumer must not read burp-specific ranges into it.
- **`location` is synthesized.** Burp's issue classes build their own location strings
  (`Zco9.Zxy`); burpsy's rows carry the evidence host/path and the parameter set, so location is
  `host + path [param, …]` in Burp's own "[parameter]" shape. The path element (documented as
  query-excluded) and the location element (the entry point, query included) deliberately differ.
- **Advisory text arrives as plain text via a tag scanner, not an HTML parser.**
  `sanitisedHTMLToText` mirrors Burp's HTML strip (`net.portswigger.Zhs.Zq`) over input that is
  already `advisory.SanitisedHTML` output — allowed elements only, no attributes — which is what
  makes a scanner safe. Its contract is stated in its doc comment; widening the input would need a
  real parser.
- **The "relevant extract" message mode is the header block, not Burp's highlight window.** Burp
  extracts "the parts of the message that are highlighted in the in-tool results" plus context
  (report-settings.html); burpsy's findings carry no highlight spans — no producer populates
  `core.Occurrence.Span` — so those locations cannot be recovered. The header block (through the
  blank line) is the deterministic substitute, labelled "[relevant extract — body omitted]" in the
  HTML and carried as bytes in the XML. Re-open: populate Occurrence.Span at finding production.

### Report settings: query-string shape and the TOC clamp (burpsy-react-ui-a9qy)

- **The wizard is a query string, not a saved profile.** Burp's report settings are chosen in a
  wizard per export; burpsy's are parameters on `/api/report/html` and `/api/report/xml`
  (`title`, `organise_by`, `toc_depth`, `sections`, `message_mode`, `max_message_len`), so an
  export link carries its own configuration. There is no persisted settings store — each export is
  configured for itself, which is what Burp's wizard does too.
- **`toc_depth` is clamped to 2, not 3+.** Burp's wizard offers more levels; in burpsy's report the
  third level would repeat the same rows (groups, then findings, then the same findings again), so
  asking for more is clamped rather than rendered as fake depth.
- **`sections=` present but empty means every detail section is off.** Burp's wizard allows
  unticking all five detail options; a query string cannot otherwise distinguish "all off" from
  "parameter absent" (all on). The nil-vs-empty list split carries the two states; the renderer's
  `sectionOn` documents it.
- **"Affected parameters" is always printed, not a section.** Burp prints an issue's location and
  entry point beside the issue header, not under a detail section; burpsy's params list follows
  that, so it survives an all-off report the way the finding's name does.

## CSRF PoC techniques: the generator's four ways to replay one request (2026-10-08, burpsy-react-ui-0z10)

Burp's generator (generate-csrf-poc.html) is the ground truth for the technique set; where its
exact behaviour is not recoverable from the documentation, the divergence is recorded here.

- **Auto's choice is burpsy's reading of "most appropriate technique capable of generating the
  required request".** urlencoded gives the form; multipart gives the multipart form; anything
  else with an equals character gives the plain-text form (the exact-body technique that needs no
  CORS); anything else gives the cross-domain XHR. The docs say only that Auto picks the most
  appropriate technique, and that JSON/XML bodies "can only be generated using either a form with
  plain text encoding, or a cross-domain XHR" — which of the two Auto prefers for a given body is
  not stated, so burpsy prefers the one with no CORS dependency whenever the body splits at an
  equals.
- **"Test in browser" is one-shot.** Burp's URL keeps serving "the currently displayed HTML"; the
  epic's acceptance (and the security reading behind it) is that a token that keeps replaying an
  attack page outlives its purpose, so burpsy's PoC host spends the token on the first fetch and
  answers 410 after. Regenerating is one click.
- **The PoC page moved off the console origin.** burpsy's previous generator opened the PoC as a
  blob URL, which inherits the console's origin — the one surface attacker-shaped HTML must never
  run on. The dialog now shows the HTML, and Test in browser opens the PoC host's URL on its own
  port, which has no console routes and no console cookies.
- **No request editing.** Burp's panel lets the operator edit the request and Regenerate from the
  edit; burpsy's dialog generates from the captured exchange. The generated HTML is copyable and
  downloadable, which is the same capability by another path. Re-open: an editable request pane in
  the dialog.
- **The XHR technique sets withCredentials and every header the browser allows scripts to set.**
  The fetch specification's forbidden headers (Host, Cookie, Content-Length and kin) are omitted
  rather than set-and-ignored — a setRequestHeader the browser silently ignores is a PoC that lies
  about what the victim's browser will send. The docs' warnings (the CORS dependency, the
  application/json preflight, the no-reflected-XSS limit) are carried as notes verbatim in intent.
- **The plain-text form's trailing CRLF is accounted for.** The browser's text/plain submission
  appends a CRLF after every entry, so a captured body ending in CRLF reproduces byte-exactly
  (it is cut from the value and the browser puts it back) and one that does not gets a note saying
  the sent body is the captured one plus two bytes.

## Content discovery: the session shape (2026-10-08, burpsy-react-ui-dgbi)

Burp's "Discover content" builds a session, not one run (content-discovery.html); where its exact
algorithms are not in the documentation, burpsy's stated rules are recorded here.

- **The derivation rule set is burpsy's own.** Burp's docs give one example — "if Burp discovers
  the directory AnnualReport2018, it also checks for AnnualReport2019, AnnualReport2020" — and no
  algorithm. burpsy's deterministic set (see `deriveDiscoveryNames`): trailing-number +1 and +2,
  name + "_old", name + ".bak", and the all-lower and all-upper case variants of each discovered
  item's last path segment, swept in the directory the discovery was made in.
- **Recursion is breadth-first, not priority-ordered.** Burp "may add a task" per discovery and
  "new tasks are prioritized by how likely they are to discover new content"; burpsy sweeps each
  depth's discovered directories in the order they were found, one bounded ffuf run per directory,
  scope-checked before launch (which is also why ffuf's own -recursion is not used: it dials paths
  burpsy never checked against scope). Re-open: a priority ordering when there is evidence for one.
- **Observed names come from the capture store's exchanges on the target host** — the directory
  segments and filename stems burpsy has actually seen — where Burp reads its site map. The two
  stores agree for burpsy's purposes (the site map is built from the same exchanges); burpsy
  matches the host only, not the scheme or port, and sorts the names so the merged wordlist file is
  reproducible from the request by hand.
- **The built-in lists are the four Burp ships**: short/long file lists and short/long directory
  lists, from the bundled PortSwigger corpus (`internal/intruder/wordlists/burp-*`). A custom list
  is the operator's wordlist path, which merges with them.
- **Not implemented from Burp's Config tab**: "Test all extensions observed in use on target site,
  except for…" (the always-test extension list is the `extensions` field) and the case-sensitivity
  mode (ffuf matches paths as the target serves them). Neither is in this bead's scope; both are
  one-option follow-ups if an engagement needs them.
- **A running run's `by_status` serialises as []** — a pre-existing null that crashed the console's
  status chips the first time an e2e sweep rendered a running run (the tool had never been
  allowlisted in a browser suite before, so nothing had exercised the shape). Fixed at both ends:
  the server initialises the counts and the page tolerates an older server's null.

## Clickbandit is burpsy's own script (2026-10-08, burpsy-react-ui-g67w)
- **Burp:** top-level Burp Clickbandit copies a script to paste into the target page's console:
  Start, record clicks, Finish, then review (toggle transparency, reset, zoom, arrow keys) and Save
  the overlay as HTML; options Disable click actions and Sandbox iframe.
- **burpsy:** burpsy → Clickbandit offers the same workflow and options with its own script
  (`internal/web/clickbandit/clickbandit.js`, served at `/api/engagement/clickbandit.js`). PortSwigger's
  script is not reused. The saved proof of concept frames the target transparently and shows one decoy
  per recorded click, advancing when a click on the frame blurs the page.
- **Divergence:** recording needs the page to be same-origin with itself in a frame; a target that
  refuses framing (X-Frame-Options / frame-ancestors) cannot be recorded, which is itself the
  clickjacking defence working.

## Decoder digests: 23 of Burp's 62 DigestAlgorithm values (2026-10, burpsy-react-ui-7tgt)

Burp's `CryptoUtils.generateDigest` takes the 62-constant `DigestAlgorithm` enum
(`/root/burp-re/out/burp/api/montoya/utilities/DigestAlgorithm.java`, Montoya 2026.7). burpsy's hash
step (`internal/tools/digest.go`, one table; the UI list is test-pinned to it) computes the 23 that the
Go standard library and `golang.org/x/crypto` provide: MD4, MD5, SHA-1, RIPEMD-160, SHA-224/256/384/512,
SHA-512/224, SHA-512/256, SHA3-224/256/384/512, Keccak-256/512, SHAKE128-256, SHAKE256-512,
BLAKE2b-160/256/384/512 and BLAKE2s-256 — plus eight HMACs (MD5, SHA-1, SHA-224/256/384/512,
SHA3-256/512), which Burp exposes through its Decoder rather than this enum.

**Not offered (39), by name:** BLAKE2S_128, BLAKE2S_160, BLAKE2S_224, BLAKE3_256, DSTU7564_256/384/512,
GOST3411, GOST3411_2012_256/512, HARAKA_256/512, KECCAK_224/288/384, MD2, PARALLEL_HASH_128_256,
PARALLEL_HASH_256_512, RIPEMD_128/256/320, SKEIN (all 13 variants), SM3, TIGER, TUPLEHASH_128_256,
TUPLEHASH_256_512, WHIRLPOOL.

**Why:** Burp gets these from BouncyCastle. None is in Go's standard library or `x/crypto` (BLAKE2s
there exposes only the 256-bit and the keyed 128-bit form; legacy Keccak only 256/512), so each would be a
new third-party dependency in a security tool, for algorithms that rarely appear in a web engagement.
The route refuses every one by name (400 listing the supported set), never by falling back to SHA-256.
**Re-open:** a concrete engagement need for a specific algorithm, and a vetted pure-Go implementation.

## Sequencer per-position FIPS: Burp's pass rules, computed significance (2026-10, burpsy-react-ui-c0k3)

The FIPS battery now also runs at each bit position across tokens, as Burp's bit-level analysis does
(`internal/sequencer/fips_position.go`, report field `fips_positions`). The pass rules are Burp
2026.7.1's `Zpu3`, copied exactly:
- At N = 20,000 the FIPS 140-2 intervals apply.
- At other N a position passes when its significance exceeds 1e-4 (monobit, poker), 1.8e-5 (runs) or
  2.98e-4 (long run).
- A longest run under 12 always passes.
- The sample size is limited to Burp's range, 100 to 20,000 tokens.

The significance is **computed exactly at N**, not read from Burp's tables (`Zw_0`, `Zcmb` →
`Zx79`/`Zb74`/`Zgrh`/`Zxh7`/`Zi0_`, `Zphy`) and interpolated across their 28 sample sizes as
`Zc6a.ZH` does. Where the two differ, it is deliberate:

- **Monobit.** The tables equal the exact two-sided binomial tail to 8 digits, but they shift by one
  key at and above the centre. burpsy uses the symmetric exact value.
- **Runs counting.** Burp's counter pools zero-runs and one-runs in one histogram. It restarts the run
  length at 0 instead of 1 on a change, never counts the final run, and scores the "6 or more" bucket
  with its exactly-5 table. burpsy counts each symbol separately, as FIPS specifies, and scores each
  of the twelve cells against its exact distribution, with a dynamic programme checked against brute
  enumeration. Burp's run tables do match that distribution, verified on `Zxh7` and `Zi0_` at N = 100.
  A position's runs significance is its least likely cell.
- **Long run.** burpsy scores the exact upper tail P(longest ≥ l). Burp's `Zphy` rows do not match the
  exact distribution; they sit roughly one sample-size row off. They are also two-sided, which is why
  Burp needs the "under 12 always passes" rule. That rule is kept, but it never binds under a
  one-sided tail at N ≥ 100.
- **Poker.** Identical. Both use the two-sided chi-square with 15 df, floored at 1e-6 (`Zp2s.ZK`).

## Repeater B: HTTP/2 kettled requests and Inspector CRLF injection (burpsy-react-ui-i9ti.2, 2026-10-08)

### Inspector detail view and Shift+Return — how CR/LF is shown, and where it can be written (ln2a)
- **Burp:** `desktop/tools/inspector/modify-requests.html` — "Copy name or Copy value from the context menu",
  and the detail view where "Press Shift + Return. The carriage return and line feed characters are injected";
  `desktop/http2/performing-http2-exclusive-attacks.html` — drill into a header with the chevron and press
  Shift+Return in the Name or Value field "to enter the sequence \r\n".
- **burpsy:** every Inspector row has a context menu (right-click, the Menu key or Shift+F10) with *Copy name*,
  *Copy value* and *Open in detail view*, on read-only mounts too, and a chevron button opening the detail view
  for that item. In the detail view Shift+Return inserts CR LF at the caret and Return applies.
- **Divergence:** CR and LF are shown in the fields as the Control Pictures ␍ and ␊, not as the text `\r\n`: a
  browser `<input>` strips CR and LF and a `<textarea>` folds CR LF to LF before any script sees it, and `\r`
  as text would collide with a literal backslash-r in a value. An item that already contains ␍ or ␊ is shown but
  not written back from the detail view (the mapping would invent a CR). Shift+Return is offered on request
  *header* items only — a query, cookie or body parameter refuses it by name — and only where an HTTP/2 header
  list can be sent as written: on an HTTP/1 request it is refused with "This would split the header: only HTTP/2
  can carry CR/LF inside a header", and on the Proxy intercept, HTTP history and Target mounts it is refused with
  the reason that only a Repeater tab sends a kettled request. Burp's Proxy supports kettled requests; burpsy's
  intercept does not (it holds HTTP/1-shaped bytes). The detail view is a panel at the foot of the Inspector, not
  a drill-down page that replaces the item list.

### Kettled HTTP/2 requests — what is refused, what the editor shows, what the record says (jae5)
- **Burp:** `desktop/http2/index.html` "Kettled requests" — an Inspector edit HTTP/1 cannot represent (an uppercase
  letter or colon in a header name, a newline in a name or value, a modified `:scheme`, a space in `:path` or
  `:method`, a duplicate pseudo-header, "; " in a cookie value) kettles the request; the editor then shows "This
  request is kettled because:" with the reasons in place of the headers and keeps the body editable; reversing the
  edits or downgrading to HTTP/1 (with a warning that the changes are lost) unkettles it; Proxy, Repeater, Logger and
  Scanner support kettled requests, Intruder normalises them.
- **burpsy:** a Repeater tab kettles when a detail-view edit puts CR/LF into a header of an HTTP/2 draft (ln2a). The
  tab then carries the field list (`h2Headers`); the request pane shows the note — reasons from
  `POST /api/http2/kettle` (`internal/http2.KettleReasons`) — and the body editor; the Inspector's Request headers edit
  the list, pseudo-headers included. Send carries `h2_headers`, and `sender.AuthorisedSender.SendH2Fields` writes it as
  literal HPACK fields (no indexing, no Huffman) on a fresh h2 connection, acknowledging SETTINGS and PING, pacing DATA
  by flow control, and reading stream 1 to END_STREAM/RST_STREAM/GOAWAY, whichever is named.
- **How a tab becomes kettled:** from the Inspector's detail view, on an HTTP/2 draft with an https target —
  applying a header name or value that contains CR/LF (Shift+Return), or renaming a header to a name with an
  uppercase letter or a colon. Inline row edits on a draft that is still text keep writing the text (where an
  HTTP/2 send lowercases names), as before; once the tab is kettled every Inspector header edit writes the list,
  and Burp's remaining triggers (`:scheme`, a space in `:path`/`:method`, a duplicate pseudo-header) are reached by
  editing the pseudo-header rows that then appear. Burp kettles from any Inspector edit.
- **Paging back:** a kettled send's history entry keeps the list it sent; the request pane shows that list (CR/LF as
  ␍␊) labelled "sent … as a kettled HTTP/2 field list", and the Inspector reads the list read-only.
- **Decline — some of Burp's triggers are kettled but never sent.** A space (or CR/LF) in `:path`/`:method` and a
  duplicate pseudo-header are refused by the frame-program classifier (`http2/authorise.go`): the engagement-scope gate
  reads a request line, and a path with a space in it would be authorised up to the space and sent whole. A modified
  `:scheme` other than `http`/`https` is refused at send time by the sender's second scope check, which cannot read an
  authority under a scheme it cannot dial (`:scheme: http` on a TLS connection is authorised against the http authority
  and sends). There is no override, by design. For the classifier's refusals the note says "Sending it will be
  refused:" with the classifier's own sentence before Send; every refusal answers Send with 403 and the reason. Lifting this needs a scope
  check that authorises a raw `:path` without rendering it into a request line — a CEO-level decision, not made here.
- **The cookie trigger, read at the field level:** burpsy's kettled Inspector has no cookie list, so "; " in a cookie
  value is read as RFC 9113 §8.2.3 frames it — more than one `cookie` field, one of which contains "; " — because
  joining crumbs with "; " for HTTP/1 is exactly where that loss happens. A single `cookie` field containing "; " is
  one Cookie line and is not kettled.
- **burpsy addition:** a pseudo-header after a regular header is a kettle reason (HTTP/1 text cannot say where it
  sat). Burp's list does not name it.
- **Unkettling** is automatic only when HTTP/1 text provably carries the list unchanged (it re-seeds to the same
  fields) and nothing would refuse it; a list that is merely "not kettled by Burp's rules" but would still change
  (say, no `:path`) stays a field list and the note says so. The downgrade (Inspector > HTTP/1) asks first, then
  normalises: CR/LF removed, extra pseudo-headers and colon names dropped, cookie fields joined.
- **Raw text edits:** the request pane hides the head while kettled, as Burp does; any other path that rewrites the
  head of the text (a body-encoding transform, a GraphQL action) drops the list at the store chokepoint and the tab
  falls back to the normalised text, rather than sending a list the operator's edit no longer matches.
- **The stored exchange:** history stores HTTP/1-shaped bytes and a kettled list has none, so the stored request is
  a rendering with CR and LF inside a field written as the text `\r` `\n`, pseudo-headers folded into the request line
  and Host, and the exchange note lists every field as sent, Go-quoted, in order. Burp stores the HTTP/2 message.
- **Tab settings on a kettled send:** Override SNI, the response timeout, Unpack, the note, Process cookies, Strip
  Connection and Update Content-Length apply (the last three to the field list). Normalize line endings applies to the
  body only. HTTP/2 connection reuse does not (always a fresh connection) and redirects are not followed; each is named
  in the answer's `kettled.notes` and the result badge. A plain-HTTP target and an HTTP/1 protocol pin are refused
  (Repeater speaks HTTP/2 only over TLS).
- **Not supported elsewhere:** Proxy intercept, Logger and Scanner do not carry kettled requests (Burp's do); a group
  send refuses a kettled member by name; To Intruder refuses an unsent kettled tab and otherwise hands Intruder the
  stored rendering, saying so — Burp normalises.

## Platform authentication: NTLM is connection-bound on the sender only; Kerberos absent (2026-10-09, burpsy-react-ui-sel6)
- **Burp:** Settings → Network → Platform authentication offers Basic, NTLMv1, NTLMv2, Negotiate and Digest, and
  applies them to every tool's traffic, the proxy's included.
- **burpsy:** the typed sender (every `Sender.Send` caller; the raw-bytes paths are untouched) runs NTLM as a
  connection-bound handshake: NEGOTIATE, CHALLENGE and AUTHENTICATE on one dedicated HTTP/1.1 connection, verified
  through `httptrace`, never re-dialled mid-handshake, and closed when the exchange returns so the authenticated
  connection carries no other request. A `DOMAIN\user` username authenticates in that domain. A refused
  AUTHENTICATE, a bare offer, a SPNEGO/Kerberos Negotiate token and a connection closed after the challenge are each
  recorded as a platform-authentication failure; the credential is presented once.
  - **NTLMv2** is the default NTLM rule. **NTLMv1** is a separate rule scheme (`ntlmv1`), an explicit opt-in
    downgrade: never chosen for an `ntlmv2` rule and never a fallback when v2 fails. It uses NTLM2 session security
    (ESS) when the challenge sets the flag and plain v1 otherwise, and never computes or sends the LM hash. Every v1
    handshake records a weak-authentication warning (served on `/api/network/auth` and
    `/api/network/auth/failures`, shown on the Platform authentication panel), and the rule's row carries the warning
    where it is configured.
  - **Negotiate** is answered with raw NTLM inside `Authorization: Negotiate` (no SPNEGO), by whichever NTLM rule
    covers the host. The handshake starts in the NTLM header; a server that ignores it and offers Negotiate gets the
    same NEGOTIATE again in the Negotiate header on the same connection, and the host is remembered so its next
    handshake starts there.
- **Divergence:** Kerberos (a SPNEGO/Kerberos Negotiate token) is refused by name — it needs a ticket, not a
  password. One handshake per send — authenticated connections are not cached per rule. A server offering both NTLM
  and Negotiate is answered in the NTLM header it accepted, not moved to Negotiate. The proxy leg still uses the
  host-keyed NEGOTIATE/learned-challenge flow for `ntlmv2` only (NTLMv1 and the Negotiate wrapper are sender-only),
  which authenticates only against a server that does not bind its challenge to the connection. The raw-bytes paths
  (and the ry5n keep-alive pool) present no platform credential, as before. The NTLMv2 AUTHENTICATE carries no MIC:
  `micBitSet` reads AV-flag bit 0x4 rather than deciding from MsvAvTimestamp, and the MIC-present flag is never
  placed in the response's AV pairs, so a server that requires a MIC refuses it.

## Authentication logic: login rate limiting and username enumeration (2026-10-12)

Two burpsy-own rows (Burp's catalogue has neither; see `docs/SCANNER-COVERAGE.md`,
"burpsy's own rows"), both off by default: `check_login_rate_limit` and
`check_username_enumeration` (`internal/scanner/checks_auth_logic.go`). What they do NOT cover:

- **Lockout that only engages for real accounts.** The rate-limit burst uses an invented identity,
  so a per-account lockout without any per-identifier/per-client throttle reads as "not rate
  limited". Reported tentative for this reason; locking a real account to find out is refused.
- **OTP issuance and silent attempt caps.** Identity-only requests ("send me a code", "forgot
  password") are never repeated, because that mails a real person. An OTP check that caps attempts
  but answers the capped guess exactly like a wrong one is indistinguishable black-box from no cap.
  OWASP VulnerableApp's OTPVulnerability LEVEL_1-4 are both of these (seeded on the issuing endpoint;
  validation answers "Login unsuccessful" either way), so they stay FN.
- **Enumeration through reset / registration flows** (VulnerableApp PasswordReset LEVEL_4) and
  **timing-only enumeration**: latency is recorded in the evidence but never decides.
- **Login over GET** is not burst-tested (POST/PUT/PATCH only); enumeration covers any method.
- **Enumeration needs a real username in the captured request.** Against VulnerableApp's
  filtered benchmark seed (`username=admin`, not an account at Authentication LEVEL_7) there is
  nothing to compare; with the level's own account captured (`admin_enum`) it is found and the
  secure LEVEL_9 (`admin_secure`) stays quiet.

## HTTP request smuggling: timing only; Client-side desync declined (2026-10-12, burpsy-react-ui-0vzb.1)

`HTTP request smuggling` (`internal/scanner/checks_smuggling.go`, switch `check_request_smuggling`,
also admitted by `check_extended_active`) detects CL.TE, TE.CL, H2.TE and H2.CL by Burp's "Time
delays" method: an attack request complete under one framing rule and not the other times out twice,
interleaved with a consistently framed control (same headers, same Transfer-Encoding spelling) that is
answered in under half the read window both times. Twelve Transfer-Encoding spellings. The finding's
Param is the technique and spelling. What it does NOT do, on purpose or not yet:

- **Burp's "Back-end socket poisoning" method is declined.** Confirming by queueing a prefix for the
  next request on the back-end connection can land on another user's request. The previous runner did
  exactly that (a pipelined CL.TE/TE.CL pair, sent without a scope check, reporting the poisoned
  follow-up); it is gone. TE.CL is only sent for a spelling whose CL.TE probe was answered promptly,
  because a TE.CL probe against a CL.TE pair leaves one byte on the back end.
- **A front end that gives up on its back end quickly** (answers 5xx in under half the window, the
  window being 5x the baseline, at least 5 s) is not detected: the delay is not long enough to call a
  timeout. HTTP Request Smuggler reads such a delayed error as a signal; burpsy does not.
- **CL.0, TE.0, H2.0 and request tunnelling** are not probed. HTTP/2 downgrade probes run only where
  TLS ALPN negotiates h2 (no h2c), with the plain `transfer-encoding: chunked` spelling only.
- **One finding per host**: the run stops at the first confirmed technique and spelling.
- **`Client-side desync` declines** (errCheckUnsupported, nothing sent). Its proof — a body that is
  itself a request, answered on the same connection — poisons the back-end connection whenever a front
  end that honours Content-Length streams the request to a server that does not. No safe confirmation
  is implemented.
- Observed while building the fixture, not this check: `SMTP header injection` fires on the
  `/desync/clte` and `/desync/safe/compliant` listeners, whose back end answers one fixed page. Likely a
  differential on the strict front end's 400 for a CR/LF payload; not investigated.
## Host header attacks, CRLF depth, SMTP header injection evidence (2026-10-12)

`check_host_header` (burpsy row b5001000, `checks_host_header.go`), the rewritten "HTTP response
header injection" evaluator (`checks_crlf.go`) and the SMTP header injection fix (j1mk.41). Not done:

- **Routing-based SSRF in band.** Only the collaborator path exists (the External service interaction
  rows plant the collaborator as Host / absolute-form target). Brute-forcing internal Host values
  (`192.168.0.0/16` and friends) to spot a different back end is not attempted: it is a sweep of
  someone else's internal network through the target.
- **Virtual-host confusion without reflection.** A different site answering an unknown Host is not
  reported on its own; it is not a vulnerability without a URL, a cache or a route built from it.
- **Password-reset poisoning** is the password-reset work's (reset links are e-mailed, not in the
  response this check reads).
- **Connection-state Host attacks** (first request valid, second request on the same connection with
  a different Host) and **Host header SSRF to the collaborator through the override family** are not
  sent.
- **Duplicate Host / absolute-form** vehicles only matter behind a front end that accepts them; Go and
  Tomcat refuse duplicate Host and take the authority from an absolute-form target.
- **CRLF:** bare CR is sent but can only be confirmed if the server turns it into a line end (a bare
  CR does not end a header line for the parser used, which is the RFC 9112 reading). Raw CR/LF bytes
  are sent to request-header points only. No response-splitting beyond one injected header/cookie
  (no body injection payload).
- **SMTP header injection** is now reported only on a separator-specific mail-library error
  (tentative). A mailer that fails silently, or queues and fails later, is not seen; the collaborator
  SMTP route (Bcc to the collaborator domain) is not wired into this row.
## GraphQL (2026-10-12, burpsy-react-ui-0vzb.13)

Burp's four GraphQL rows were already wired; this round hardened their evidence and added three
burpsy-own rows (`check_graphql_hardening`, off by default) plus GraphQL argument insertion points.

- **Evidence changes to Burp's rows.** "GraphQL content type not validated" now asks under a fresh
  alias with only the captured cookie (what a cross-site form carries), and additionally reports
  when `mutation{<alias>:__typename}` executes over GET. "GraphQL suggestions enabled" probes ten
  near-misses of common root fields (graphql-js suggests within edit distance) instead of one
  nonsense name that is near nothing, and ignores a "suggestion" that only echoes a probe name.
  "GraphQL endpoint discovered" requires `data.__typename` to be a string, and also tries `/query`
  (gqlgen's default mount). Every GraphQL probe now carries the captured request's session headers
  (cookies, Authorization, API keys), minus framing and conditional headers.
- **Injection through arguments.** Each string-literal argument of a GraphQL document in a JSON
  body string, a form value or a query-string value is a nested insertion point
  (`bcheck/insertion_graphql.go`), so every server-side injection row reaches it; `variables`
  values were already JSON body points. Demonstrated for SQL injection (`/gql/api`
  `book(title:)`). NOT done: XSS through a GraphQL argument is probed but never demonstrated (a JSON
  response is not an HTML context); Int/Boolean/enum literals and block strings are not points
  (GraphQL type-checks the former before any resolver runs).
- **Not covered.** Depth needs introspection (no schema, no cycle to follow); a cycle only through
  a list field with no first/limit-style argument is never followed, so such schemas stay
  undecided. Batching sizes are fixed (10 / 100), so a limit above them reads as "not limited".
  Field-suggestion-driven schema recovery (clairvoyance), directive overloading, GraphiQL/IDE
  exposure and subscription (WebSocket) endpoints are not implemented. Stack-frame recognition
  covers JS, Java/Kotlin, .NET, Python, Ruby, PHP and Go formats only.

## NoSQL injection: operator and $where syntax injection, no timing (2026-10-12, burpsy-react-ui-v0ei.6)

Burp's catalogue has no NoSQL row. `NoSQL injection` is burpsy's own row (`b5002000`, CWE-943,
`internal/scanner/checks_nosqli.go`, switch `check_nosql_injection`, riding "Server-side JavaScript
code injection"). It replaces JSON string values with operator objects, re-sends query and form
parameters in bracket syntax (`name[$ne]=x`, `name[$in][]=x`), and breaks out of a JavaScript string
(`'||'x'=='x`, `'`, `"`, `\`). What it does NOT do:

- **No `$where` timing (`sleep(n)`).** It holds a database worker for the delay. Endpoints that show
  neither a result difference nor an error are not found.
- **Strings only.** Numbers and booleans in JSON bodies are not replaced by operators: `{"$gt": ""}`
  against a number compares by BSON type order, so the always-true class would disagree with itself.
  An integer PIN compared in a filter is not tested. Arrays in JSON bodies are not walked.
- **Reads and logins only.** A POST is probed only when its path names a read or an authentication
  step and no write. An injectable filter behind an update, delete or reset endpoint is never tested,
  on purpose: a match-everything operator there changes every record.
- **APIs that support filter operators by design** (Feathers, some REST query layers) answer the
  operator differential exactly as an injectable endpoint does, and are reported. Whether that is a
  flaw depends on whether the filter was meant to restrict the result set; the finding says what was
  evaluated, the reviewer decides.
- **Only MongoDB.** CouchDB, Cassandra CQL, Redis and Elasticsearch query syntaxes are not probed;
  the error bank is MongoDB/Mongoose/driver-specific.
- **A cookie or header value** is never re-sent as an operator (qs-style bracket parsing does not
  apply there).
- Observed while building the fixture, not this check: `SQL injection` fires on `/nosql/where` and
  `/nosql/report` from its error bank matching "unterminated string literal", the JavaScript engine's
  message inside the MongoServerError. The flaw is real but it is not SQL; the SQL error bank should
  not treat that JavaScript message as a SQL signature (`sqli_*` files are another agent's area).

## Cross-site WebSocket hijacking and spoofable client-IP headers (2026-10-12, burpsy-react-ui-0vzb.11, 0vzb.14)

`Cross-site WebSocket hijacking` (burpsy row `b5002400`, CWE-1385, `check_websocket_hijacking`, rides
"Cross-site request forgery"): for a captured 101 handshake with a Cookie, no Authorization and no
secret-shaped query value or subprotocol, three handshakes through the scope gate
(`AuthorisedSender.SendUpgrade`): as captured, with `Origin: https://<random>.invalid`, and without
cookies. Firm when the foreign Origin gets 101 and either the cookie-less control is refused or the
foreign socket's first message equals the authenticated one and differs from the cookie-less one
(digit runs masked); tentative when all three open and no socket says anything. Not done:

- **No client message is ever sent**, so a server that speaks only after the client does (a "READY"
  first message) gives no messages to compare: it is firm only when the cookie-less handshake is
  refused, and tentative when that handshake opens too.
- **SameSite is not evaluated**: a Lax/Strict session cookie would not be sent cross-site; the finding
  says so rather than looking up the Set-Cookie.
- Token detection in the URL and subprotocol is a shape heuristic (16+ URL-safe characters with a
  letter and a digit); a short ticket is not recognised as a defence.

Client-IP headers (`check_client_ip_spoofing`, rides "Broken access control"; each of X-Forwarded-For,
X-Real-IP, X-Client-IP, True-Client-IP, CF-Connecting-IP, X-Originating-IP, Forwarded for= as its own
probe; the finding's Param is the header):

- `Access control bypass via spoofed client IP header` (`b5002410`, CWE-290): safe-method request,
  baseline 401/403, 127.0.0.1 -> 2xx with a different body, a 203.0.113.x control not 2xx, loopback
  2xx again. Firm.
- `Rate limit bypass via spoofed client IP header` (`b5002420`, CWE-348): safe-method request or a
  captured login, baseline 429, a fresh documentation address not 429/5xx, the plain request still
  429, a second fresh address not 429. Firm.
- Burp's `Spoofable client IP address` (info): one probe with every header at a distinct random
  address plus an `X-Burpsy-Echo-Control` echo control; the address must come back as a whole token
  (parsed header value or body) and, sent alone with a fresh address, again. Firm.

Not done: loopback spellings other than `127.0.0.1` (`::1`, `localhost`, `127.1`, private ranges) are
not tried; only the first header that bypasses is reported; a refused state-changing request is never
replayed with a bypass. The rate-limit pair is not in the runtime corpus manifest (no Row): a route
that answers its captured request 429 puts every step of a whole audit behind the 2 s auto-backoff
(99 waits, 200 s measured), so `checks_ws_ip_test.go` audits it with only this switch on. The passive
`Spoofable client IP address` check still fires on any captured request that merely carries one of
these headers; that is unchanged here.
