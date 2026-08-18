# burpsy-go Port Status

> **UPDATED 2026-08-03:** The boilerplate below the fold is the original port's
> self-assessment and overstates reality — it claims "100% COMPLETE" for phases
> that are partial. This status document is being kept honest by the sections
> added above it. Read those first; the dated table below the line records what
> has been verified recently rather than what was claimed when the port shipped.
>
> **Parity gaps live in [`gaps.md`](gaps.md)** — a graph-and-source-verified
> ledger of the twelve known Rust↔Go differences, each with status, evidence,
> and decline path. Read it before relying on the parity tables below.

## Recent Work — verified

### 2026-08-03 — BCheck insertion-point enumeration (Go)

Ported `crates/bcheck/src/insertion.rs` (722 lines) to `internal/bcheck/insertion.go`:

- `Enumerate(req []byte, kinds []string)` returns one `InsertionPoint` per
  injectable place in fixed order — query, headers, cookies, body — plus a
  `[]Declined` naming the places the enumerator refused to splice into and why.
- Four DSL-namable families only: `query`, `body`, `cookie`, `header`. `any`
  includes headers (the `jwt-none-algorithm.bcheck` evidence). Nested points are
  not enumerated — a miss, never a false positive.
- A point is an offset into the base request, not a copy. `Apply` splices
  exactly one range and returns the rebuilt raw request with a corrected
  `Content-Length`; appending keeps the base value, replacing overwrites it.
- Encoding escapes only the bytes that decide how the container parses
  (percent-escape for form containers, JSON-escape inside string literals,
  nothing for header values). The base value is never re-encoded — that would
  rewrite bytes the check did not ask to change.
- Honest counting: a multipart, XML or non-UTF-8 body is **declined** (recorded
  as skipped), never silently empty. An unparseable request is also declined.
- 22 tests in `insertion_test.go` mirroring the Rust suite word for word
  (fixed order, no-`=` clauses skipped, JSON string-only points, reserved
  headers, mid-codepoint splice flooring, Content-Length following the body).

**Found and fixed along the way:** `messageFields` (the `{…response.body}` /
`{…request.body}` resolver in `bcheck.go`) and the new `parseRequest` both
sliced the header/body separator as a single `\r\n`, gluing the second half of
the blank line onto the body. `{base.response.body}` came back with a leading
`\r\n` no server sends. Both now skip the whole `\r\n\r\n` / `\n\n` separator;
regression test `TestResponseBodyHasNoLeadingBlankLine`.

**Known limitation (pre-existing, named):** conformance is 263/264. The one
rejection, `other/uuid-detected-guid-versions.bcheck`, is an `else if` chain
that the parser does not close — unrelated to insertion points, present before
this work.

### 2026-08-02 — BCheck engine correctness + live audit + WebSocket relay

- **`run for each` runs the full cartesian product** of its iterables, each
  combination in its own forked context (no binding leaks). Previously only the
  first iterable ran. 30.7% of the 264-file corpus uses this construct.
- **`report issue and continue` is now distinct from plain `report issue`.**
  The parser consumed the phrase and discarded it, so every report behaved as
  `and continue` — 253 of 264 corpus files got the wrong control flow. Plain
  `report issue` ends the whole check, every remaining iteration included; only
  11 files ask for `and continue`. The choice inside `run for each` is argued
  in the code and `docs/BCHECK-M2-SEMANTICS.md`.
- **`interpolate` fixed:** a `break` inside a `switch` bound to the switch, not
  the scan loop, so `{name}` references in backtick templates were emitted
  literally. Report detail/remediation lines are the main consumers.
- **Live active audit:** `internal/web/liveaudit.go` sweeps completed in-scope
  exchanges every 3s through the passive checks, `GET/POST /api/scanner/live`.
- **WebSocket relay:** real RFC 6455 relay in `internal/proxy/ws.go` with
  `WsMessage` recording; flat history (message-ID column) like Burp, plus a
  per-connection endpoint Burp lacks. `X-WebSocket-Extensions` stripping on by
  default (`WithStripWsExtensions`).

## Phase Status — where to read it now

The original per-phase parity tables that used to fill the rest of this file
claimed "100% COMPLETE" for every phase and reported a 3,640-line, 15-file,
12-package codebase. Both are false today — the tree is ~123k lines across ~30
`internal/` packages — and the "complete parity" framing is exactly the kind of
overstated result this project treats as a defect. The tables were removed on
2026-08-17 rather than left below a warning, because a reader who scrolled past
the warning would take a retracted claim as current.

Read the live status from the documents that are kept honest against the code:

| Question | Authoritative source |
|----------|----------------------|
| Which Rust↔Go behaviours still differ, with evidence and decline path | [`gaps.md`](gaps.md) |
| What the most recent work session changed and verified | the dated `docs/HANDOFF-*.md` (latest: `docs/HANDOFF-2026-08-13.md`) |
| Scanner catalog coverage (183-issue catalog, runnable vs declined) | [`docs/SCANNER-COVERAGE.md`](docs/SCANNER-COVERAGE.md) |
| Which scanner primitives are built and wired | [`docs/SCANNER-INFRA.md`](docs/SCANNER-INFRA.md) |
| BCheck coverage, parse conformance vs runtime | [`docs/BCHECK-COVERAGE.md`](docs/BCHECK-COVERAGE.md) |
| Per-package orientation (what each `internal/` package is for) | [`internal/AGENTS.md`](internal/AGENTS.md) and the per-package `AGENTS.md` |

The honest one-line summary: the Go port is the active implementation and covers
the whole feature surface of the Rust reference, but "parity" is a per-gap
judgement tracked in `gaps.md`, not a single headline percentage — and no such
percentage is published until Security Research (CS-11) re-verifies it.
