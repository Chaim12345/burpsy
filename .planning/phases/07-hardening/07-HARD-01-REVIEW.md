<!-- HARD-01 | line-by-line review of the three unreviewed merged branches | 2026-07-28 -->

# HARD-01: Line-by-line review of the three unreviewed merged branches

**Requirement**: *The three agent-written branches merged without line-by-line review have been
reviewed.*
**Success criterion**: *Each of the three previously-unreviewed merged branches has a documented
line-by-line review, and any defect found in it is fixed and tested.*

This document is the **review** half. It reports defects precisely enough to be fixed; it fixes
nothing. Every citation below was checked against the source at `HEAD` (`bbda1f8`), not against the
diff alone.

---

## Which three branches, and how they were identified

`git log --merges` shows **six** `worktree-agent-*` merges, not three, so the three had to be
established rather than assumed.

**Selection criterion: the three merges whose branch-tip commit does not appear in the repo's own
review tracker, `.git/sg-reviewed-shas`.**

That file holds six entries, which resolve to **three** branch tips recorded twice each — once under
a pre-rebase sha and once under the sha that was actually merged:

| Tracker sha | Resolves to | Branch | Merge |
|---|---|---|---|
| `32d24e6`, `981377c` | site map as a derived, incrementally-folded view of history | `worktree-agent-afdf55907098782e7` | `79549d3` |
| `ceebb07`, `ce52fa1` | intruder: rate-limited concurrency, pitchfork and cluster bomb | `worktree-agent-ab46b164e72aed9ea` | `9c25ed8` |
| `b616ef0`, `53d4337` | scanner: bound admitted audit work, and Burp's 183-issue catalog | `worktree-agent-ad17aaa2d16004b29` | `066ae5f` |

The remaining three merges have **no** tracker entry for their tip, and are therefore the subject of
this review:

| # | Merge | Branch | Sole commit |
|---|---|---|---|
| **A** | `c199a9b` | `worktree-agent-a141a80aa2dbee4d4` | `e764bce` proxy: request interception (hold/edit/forward/drop), failed-CONNECT history, connection reuse |
| **B** | `74b7b65` | `worktree-agent-ab86d03ab2337e69c` | `308310c` tools: Decoder, Comparer, Logger, Organizer, match-and-replace |
| **C** | `d835f3f` | `worktree-agent-a7b3aea4bb8527ba2` | `78b5406` bcheck: M3 — insertion points and send payload, plus two M2 corrections |

Three independent cross-checks agree with this selection:

1. `.planning/codebase/CONCERNS.md:200` — "three of the six merged branches still have no
   line-by-line review".
2. `.planning/PROJECT.md:131-132` — "A review of two of six merged branches found three defects…
   Three branches remain unreviewed." (The tracker records three tips, not two; the discrepancy is
   in the prose, not in the identity of the *unreviewed* set, which is the same either way.)
3. The three merges carry post-merge *lint* fixes only (`5431d2f`, `e96ab43`), consistent with
   scripted integration rather than a review pass — whereas `066ae5f` and `9c25ed8` are the ones the
   tracker marks.

**Confidence: high.** The three are determined by a repo artifact, not by inference.

### One caveat on line numbers

The working tree is dirty — other agents are concurrently editing `crates/http2`, `crates/scanner`,
`crates/query`, `crates/core`, `crates/web/src/lib.rs`, `crates/web/src/routes/sitemap.rs`,
**`crates/proxy/src/lib.rs`** and **`crates/web/src/routes/tools.rs`**.

Of the files cited below, two are live:

- `crates/proxy/src/lib.rs` (finding **A-4**) — cited by function name as well as line, because its
  numbers will shift.
- `crates/web/src/routes/tools.rs` (finding **B-1**) — re-verified after the concurrent edit; that
  edit added one line at `:855` inside `mod tests`, so every citation here (`:16`, `:79-94`,
  `:199-207`, `:348`, `:391`) is still exact at the time of writing.

The files carrying the other six findings — `crates/sender/src/transport/blocking.rs`,
`crates/tools/src/decoder.rs`, `crates/bcheck/src/insertion.rs`, `crates/bcheck/src/eval.rs` — are
untouched, so their line numbers are stable.

Note also that branch A's `crates/proxy/src/sender.rs` **no longer exists**: HARD-03 (`0f38f63`)
moved that code to `crates/sender/src/transport/blocking.rs`. Findings A-1..A-3 cite the new home,
which is where a fixer must go.

---

## Branch A — `c199a9b`, proxy request interception

**What it brought in.** A hold queue (`crates/proxy/src/intercept.rs`, new) that parks an in-scope
request on its own `oneshot` so an operator can rewrite, forward or drop it; failed-`CONNECT`
attempts recorded in history rather than dropped; and a keep-alive connection pool for scanner probes
with per-target framing classification (then `proxy/src/sender.rs`, now
`crates/sender/src/transport/blocking.rs`). Plus the API layer, an integration suite and
`e2e-intercept.sh`.

### A-1. MAJOR — a target promoted to keep-alive can never be demoted, contradicting the module's own stated invariant

**File**: `crates/sender/src/transport/blocking.rs:195-213` (and `:313`, `fn learn`)
**Confidence**: HIGH

The module header states the safety property plainly:

> "Anything else — chunked, unframed, truncated at the size cap, or a byte longer than it claimed —
> **pins the target to close-per-probe permanently**."

The code only ever does that on *first contact*. `self.pool.learn(...)` is called in exactly one
place — the `Framed::Unknown` arm at line 203. Once a key reaches `Framed::Exact`, `send` routes
every later probe to `keep_alive_probe` (line 196), which inspects `framing.reusable()` only to
decide whether to *re-pool the socket* (lines 155, 174) and never calls `learn`. There is no
transition out of `Framed::Exact`.

**Failure scenario.** A target answers the first probe `200` with an exact `Content-Length` →
promoted to `Framed::Exact`. A later probe in the same audit hits a path on the same
`(host, port, tls)` that answers **unframed** — no `Content-Length`, no `chunked`. That probe now
goes out with `Connection: keep-alive` (`force_keep_alive`, line 150). `response_complete` returns
`false` for an unframed response by design (line 558-559: "No framing: only EOF ends it"), the server
honours keep-alive and does not close, so the read blocks until the 10-second `read_timeout` armed at
line 119 fires → `ErrorKind::WouldBlock` → `ReadFail::loud` (line 474-479) → `Wire::Failed` → `Err`.
**The response is discarded entirely and the check reports an error, permanently, for every
subsequent unframed response to that target** — 10 seconds each, and with 127 active checks a
target with mixed framing loses both the wall clock and the findings.

**Fix**: in `keep_alive_probe`, call `self.pool.learn(key, Framed::CloseOnly)` whenever a response
comes back with `framing.exact_content_length == false`, so the documented demotion actually happens.

### A-2. MAJOR — `response_complete` has no notion of a bodiless response, so 204/304/HEAD stall to the read timeout on a pooled connection

**File**: `crates/sender/src/transport/blocking.rs:547-559`
**Confidence**: HIGH

`response_complete` decides completion from `Content-Length`, then `Transfer-Encoding: chunked`, then
gives up and returns `false`. It never looks at the status line. But `204 No Content`, `304 Not
Modified`, any `1xx`, and every response to a `HEAD` request are **complete with no body and
legitimately carry no `Content-Length`** — and they keep the connection persistent.

Grep confirms the file contains no reference to `204`, `304`, `HEAD`, or any bodiless-status concept.

**Failure scenario.** Target is `Framed::Exact`. A probe gets `HTTP/1.1 304 Not Modified\r\nETag:
"x"\r\n\r\n` and the server correctly holds the socket open. `head_end` is found; `response_complete`
returns `false` forever; the loop blocks until the read timeout; the exchange fails with "read
timeout after 47 bytes". A `304` is an extremely ordinary response, so this is not an edge case — and
because of **A-1** the target is never demoted, so it recurs for the rest of the audit.

This is the root cause and A-1 removes the recovery path; they should be fixed together, but either
fix alone leaves a real defect.

**Fix**: treat a `204`/`304`/`1xx` status, and any response to a `HEAD` request, as complete at
`head_end` when no `Content-Length` or `Transfer-Encoding` is present.

### A-3. MINOR — the test that appears to cover unframed origins cannot catch A-1

**File**: `crates/sender/src/transport/blocking.rs:822` (`an_unframed_origin_keeps_getting_a_fresh_connection_per_probe`), `Origin` enum at `:716-725`
**Confidence**: HIGH

The test name reads as coverage of the unframed case, and the `Origin` doc comment on `Unframed` says
"The case reuse must never break." But `Origin::Unframed` answers unframed from the **first** probe,
so the key learns `CloseOnly` at first contact and the demotion path in A-1 is never executed. There
is no `Origin` variant that answers framed first and unframed later, and line 744
(`|| mode != Origin::Framed`) makes the unframed server close after every response anyway — which is
precisely the condition that hides the hang.

So the suite proves first-contact classification and leaves the module's "permanently pinned" claim
untested. This is a test that asserts less than it appears to.

**Fix**: add an `Origin::FramedThenUnframed` that answers the first probe with an exact
`Content-Length` and later probes unframed **while honouring keep-alive**, and assert the later
probes still return their body.

### A-4. MINOR — an operator's edit is not re-checked against scope before the exchange is stored and passively scanned

**File**: `crates/proxy/src/lib.rs`, `forward_http` — scope test at ~`:224`, re-derive at ~`:256-262`, `spawn_scan` at ~`:326` *(file is being concurrently edited; locate by function name)*
**Confidence**: HIGH on the code path, MEDIUM on severity

`forward_http` tests scope once, on the pre-edit path (`cfg.scope.contains(&host_only, port, &path,
false)`), then holds the request. The operator may rewrite it. The code then deliberately re-derives
the start line from the edited bytes — `let (method, path) = start_line_parts(&upstream_req);` — and
stores and passively scans the exchange under the **new** path. Scope is never re-evaluated against
it.

**This is not an egress defect**, and I want to be precise about that: the proxy forwards
out-of-scope traffic by design (`ProxyConfig::scope` is documented at `:51-52` as gating what gets
*stored*, not what gets sent), and finding A-5 below confirms an edit cannot redirect the connection
to a different host. The consequence is narrower: an operator who edits a held request onto a path
the engagement **excludes** gets that exchange retained in the store and run through the passive
scanner, when the exclusion exists to prevent exactly that retention.

**Fix**: re-test `cfg.scope` against the post-edit path before `store.put`, and forward without
retaining if it now falls outside scope.

### A-5. Positive — the edit path deliberately cannot re-route the connection

Worth recording because it is the defect this branch was most likely to have. `forward_http`
re-derives the start line from the edited bytes for *indexing* but keeps the original upstream
address, with the reasoning stated in the comment at `crates/proxy/src/lib.rs:256-260`: "The upstream
host and port stay as originally addressed: editing the `Host` header changes what the origin is
told, not which origin we dial." An operator edit therefore cannot turn a held request into egress
toward an unauthorised host. `intercept.rs:63-66` similarly documents why `HeldView::raw` is lossy
UTF-8 and why an unedited forward is still byte-exact.

---

## Branch B — `74b7b65`, tools

**What it brought in.** Five new pure-transformation modules — a layered/smart decoder, a Myers
comparer over spans, a capped tool log, an organizer, and a match-and-replace rule engine — plus 940
lines of JSON API in `crates/web/src/routes/tools.rs`.

### B-1. MAJOR — the decoder reports a silently truncated decompression as a complete success

**File**: `crates/tools/src/decoder.rs:196-205` (`fn inflate`); surfaced via `crates/web/src/routes/tools.rs:199-207` and `:79-94` (`BytesView`)
**Confidence**: HIGH

```rust
fn inflate<R: Read>(r: R) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    match r.take(MAX_INFLATE).read_to_end(&mut out) {
        Ok(_) => Ok(out),
        Err(e) if out.is_empty() => Err(DecodeError::Compression(e.to_string())),
        Err(_) => Ok(out),
    }
}
```

Two distinct partial results are returned as unqualified `Ok`:

1. **The cap truncated the stream.** `r.take(MAX_INFLATE)` stops at 64 MiB and `read_to_end` returns
   `Ok(_)`. A body larger than the cap is indistinguishable from a body that ended there. The
   branch's own test `a_decompression_bomb_is_capped_rather_than_exhausting_memory`
   (`decoder.rs:1031-1040`) asserts `out.len() == MAX_INFLATE` and `decode(...).unwrap()` — i.e. it
   *pins* the behaviour that a truncated inflate reports success.
2. **A mid-stream error with partial output** (line 203). A corrupt or truncated gzip body that
   yields 40 bytes of a 4 000-byte body returns `Ok(40 bytes)`.

Nothing reaches the caller to say so. `DecodeError::Compression`'s own doc comment (`:123-124`)
describes the intent — "partial output is returned instead whenever any bytes decompressed" — but no
flag accompanies it, and the API's `BytesView` (`routes/tools.rs:79-94`) carries only `text`, `len`
and `utf8`. Its doc comment states the standard the code then fails to meet: *"Lossy text plus the
facts needed to know whether to trust it… silently handing back replacement characters would be a
lie."*

**Failure scenario.** An operator decodes a gzipped response body captured from a target that reset
the connection mid-transfer. The API returns `{"output":{"text":"…","len":40,"utf8":true}}` with HTTP
200. The operator reads 40 bytes, concludes the body does not contain the string they were looking
for, and moves on. The string was in the 3 960 bytes that never decompressed.

**This is the project's signature defect class**, and the same branch establishes the correct pattern
twice and violates it once:

| Module | Bound applied | Reported? |
|---|---|---|
| `logger.rs:111,139-141,241` | log evicts oldest at capacity | **Yes** — `dropped: AtomicU64`, surfaced by the API at `routes/tools.rs:391` (`"dropped": t.log.dropped()`), tested at `logger.rs:316-322` |
| `comparer.rs:134,198` | Myers gives up past `max_d` | **Yes** — `truncated: bool`, surfaced at `routes/tools.rs:348`, tested at `comparer.rs:523-527` |
| `decoder.rs:196-205` | inflate capped / fails mid-stream | **No** |

`crates/tools/src/lib.rs:18-20` states the discipline the decoder breaks: "**Refuse rather than
mangle.** Every module has at least one place where it declines to guess… the comparer says
`truncated` instead of pretending."

**Fix**: return the truncation fact alongside the bytes — e.g. `inflate` yields
`(Vec<u8>, bool /* truncated */)`, `decode` propagates it, and `BytesView` gains a `truncated` field
— and change the bomb test to assert the flag is set.

### B-2. MINOR — the `deflate` fallback masks the real error, and mis-handles a validly-empty zlib stream

**File**: `crates/tools/src/decoder.rs:164-167`
**Confidence**: HIGH on the control flow, MEDIUM on the empty-stream impact

```rust
Layer::Deflate => match inflate(flate2::read::ZlibDecoder::new(input)) {
    Ok(v) if !v.is_empty() => Ok(v),
    _ => inflate(flate2::read::DeflateDecoder::new(input)),
},
```

The `_` arm discards the zlib error unconditionally, so when both framings fail the caller is shown
the **raw-deflate** error for what was almost certainly a malformed zlib stream — a misleading
diagnostic for the common case the comment says is "what nearly every server sends".

Separately, the guard is `Ok(v) if !v.is_empty()`, so a *valid* zlib stream that legitimately
decodes to zero bytes (an empty body under `Content-Encoding: deflate`) falls through to the raw
deflate attempt on zlib-framed bytes and is reported as a decompression error rather than as an empty
body.

**What would settle the second half**: a unit test decoding `encode(Layer::Deflate, b"")`. I did not
run it (the workspace is mid-edit by other agents), so I am reporting the reasoning rather than an
observed failure — hence MEDIUM.

**Fix**: match on the zlib result explicitly, keep its error to report if the fallback also fails,
and distinguish "decoded to empty" from "failed".

---

## Branch C — `d835f3f`, bcheck M3

**What it brought in.** `crates/bcheck/src/insertion.rs` (new) — enumeration of query, header, cookie
and body insertion points as `(offset, len)` spans, with per-container escaping — plus `send payload`
and `given insertion point` expansion in `eval.rs`, and two M2 corrections.

### C-1. MAJOR — an insertion point the enumerator declines to build is indistinguishable from "there was nothing to test"

**Files**: `crates/bcheck/src/insertion.rs:181-192` (`body_points`), `crates/bcheck/src/eval.rs:572-575` (`run_active`)
**Confidence**: HIGH

`body_points` returns silently, contributing zero points, in three cases:

- `insertion.rs:190-192` — `let Ok(body) = std::str::from_utf8(&req.body) else { return; };` a
  non-UTF-8 body (protobuf, gzip, any binary upload).
- Per its own doc at `:181-185` — multipart, XML and plain-text bodies "yield nothing", deliberately,
  because splicing a container the code does not model would corrupt it.

That reasoning is sound. **The problem is that the decision is not reported.** `enumerate` returns a
bare `Vec<InsertionPoint>`, and its doc at `:124-125` explicitly conflates the two meanings: "An
empty result is normal (a bare `GET /` … has nowhere to inject) and means the check simply has
nothing to do here." `run_active` then completes the conflation at `eval.rs:572-575`:

```rust
// An empty point list is not an error: a bare `GET /` has nowhere to inject, and the check
// simply has nothing to do against this request.
for p in insertion::enumerate(&base, kinds) {
```

An empty list yields `Ok(vec![])` — the same value as "tested every point, found nothing".

**Failure scenario.** A `given body insertion point` check — an SQLi or SSTI probe — is run against a
`POST` carrying `Content-Type: multipart/form-data` or `application/x-protobuf`. `body_points`
contributes nothing, `run_active` returns `Ok(vec![])`, and the audit records the check as
**considered and clean**. The report tells the operator that parameter was tested. It never was, and
nothing anywhere counts it as skipped.

This is the same defect shape as the already-known `scanner` instance (an evaluator error swallowed
with `else { continue; }` and no counter), one layer further down, and it undermines two stated v1
requirements directly: **REPORT-04** ("Every report states what was not checked and why, so a clean
report cannot be mistaken for full coverage") and **DASH-03**.

I considered rating this CRITICAL. I have kept it MAJOR because it causes a false negative rather
than an unauthorised action or memory unsafety — but it is the highest-impact finding in this review,
because it is silent, it is on the scanner's main path, and the machinery to report it (`Unsupported`,
`AuditOutcome`'s disposition counters) already exists and is simply not reached.

**Fix**: have `enumerate` also return what it declined and why (e.g.
`(Vec<InsertionPoint>, Vec<Declined>)`), and have `run_active` surface a declined body as an
`Unsupported` disposition so the audit counts it as skipped rather than clean.

### C-2. MINOR — `splice` clamps to byte offsets without checking UTF-8 char boundaries

**File**: `crates/bcheck/src/insertion.rs:274-282`
**Confidence**: HIGH that the guard is missing, HIGH that it is currently unreachable

```rust
fn splice(s: &str, r: Range<usize>, new: &str) -> String {
    let start = r.start.min(s.len());
    let end = r.end.min(s.len()).max(start);
    ...
    out.push_str(&s[..start]);
```

`start` and `end` are clamped against `s.len()` but never against a char boundary, so `&s[..start]`
and `&s[end..]` panic if either lands mid-codepoint. `InsertionPoint::apply` is careful everywhere
else — `Loc::Header` uses `get_mut` (`:252`), `Loc::Body` clamps (`:262-263`) — so the omission looks
like an oversight rather than a decision.

**Why it cannot fire today**: the ranges come from `kv_pairs`/`json_string_values`, which locate
ASCII `=`, `;`, `&` and `"` bytes, so every boundary is a char boundary *in the string it was derived
from*; and `eval.rs:716` is the only production caller, applying one point to a request rebuilt fresh
from `base.request` each time (`eval.rs:27-28`). A panic needs a caller that applies two points to one
request, shifting later offsets. `apply` is `pub`, so that caller is a future edit away. There is no
`is_char_boundary` call anywhere in the workspace.

**Fix**: clamp with `floor_char_boundary` (or return `None` on a non-boundary offset) so the function
is safe independently of its callers.

### C-3. Positive — this branch gets the error-reporting discipline right where it matters most

Recorded deliberately, because it is the contrast that makes C-1 an oversight rather than a pattern.
`eval.rs` propagates every evaluation failure as a typed error instead of a default: `SendFailed`
abandons the check with the reasoning stated at `eval.rs:30-31` ("A failed send abandons the check.
Continuing would leave `{check.response.body}` absent and invite exactly the false positive the
absence rules exist to prevent"), `Unsupported::BadRegex` reports an uncompilable pattern
(`eval.rs:873-874`), `DiffersFrom` is refused rather than approximated with a comment explaining that
a quiet `false` "is indistinguishable from 'the responses were the same'" (`eval.rs:861-866`), and
the absence rule at `:858-859` is stated as "absence is not evidence". `RESERVED_HEADERS`
(`insertion.rs:103-117`) excludes `Content-Length`/`Transfer-Encoding` specifically because
`to_raw()` rewrites them and "a payload in them is discarded before it reaches the wire — a silent
no-op probe, which is worse than no probe". That is the exact class of reasoning C-1 is missing.

---

## Summary of findings

| ID | Severity | File | Defect |
|---|---|---|---|
| A-1 | MAJOR | `crates/sender/src/transport/blocking.rs:195-213` | Keep-alive target never demoted; contradicts module doc |
| A-2 | MAJOR | `crates/sender/src/transport/blocking.rs:547-559` | `response_complete` ignores bodiless statuses (204/304/HEAD) |
| A-3 | MINOR | `crates/sender/src/transport/blocking.rs:822` | Unframed-origin test cannot exercise the demotion path |
| A-4 | MINOR | `crates/proxy/src/lib.rs` (`forward_http`) | Edited path not re-scoped before store + passive scan |
| B-1 | MAJOR | `crates/tools/src/decoder.rs:196-205` | Truncated/failed decompression reported as complete success |
| B-2 | MINOR | `crates/tools/src/decoder.rs:164-167` | Deflate fallback masks zlib error; validly-empty zlib misreported |
| C-1 | MAJOR | `crates/bcheck/src/insertion.rs:181-192`, `eval.rs:572-575` | Declined insertion points indistinguishable from "nothing to test" |
| C-2 | MINOR | `crates/bcheck/src/insertion.rs:274-282` | `splice` byte-clamps without char-boundary check (latent) |

**CRITICAL: 0. MAJOR: 4. MINOR: 4.**

No CRITICAL finding. Specifically, **no unauthorised-egress defect was found in any of the three
branches** — see the coverage list below for what was checked to reach that conclusion.

Three of the four MAJOR findings (B-1, C-1, and A-1/A-2 in effect) are instances of the project's
signature defect class: a partial or failed result presented as a complete one.

---

## What was looked for and not found

Stated so the reader knows the shape of the coverage, not just the hits.

**Unauthorised egress / scope bypass — checked, not found.**
- `intercept.rs` contains no scope logic at all and needs none: the scope gate sits upstream in
  `forward_http:224` and is repeated in `hold_for_review:771` for the MITM path, with the reasoning
  documented at `:756-758`.
- An operator edit cannot redirect the connection to another host (A-5); host and port are taken from
  the original address, and only the start line is re-derived for indexing.
- `bcheck` still has no transport. `Sender` is a trait (`eval.rs:56-58`); the crate opens no socket.
- `tools` still has no clock, filesystem or socket, as `crates/tools/AGENTS.md` requires;
  `routes/tools.rs:16` states "Nothing in this file sends traffic" and the module holds to it.
- Branch A's pool code was later moved wholesale under `burpsy_sender` by HARD-03, so it is now
  behind `AuthorisedSender` and inside the `no_alternate_egress.rs` source scan.

**Panics on attacker-influenced input — checked, one latent case only (C-2).**
- The `hex_val(...).unwrap()` pair at `decoder.rs:801` is guarded by `is_percent_escape(b, end)` on
  the preceding line, which itself checks `i + 2 < b.len()` and both `hex_val(...).is_some()`
  (`:266-268`). Not a defect.
- `InsertionPoint::apply` is bounds-safe on every arm: `get_mut` for header and cookie indices
  (`:252`, `:257`), `.min()/.max()` clamping for the body range (`:262-263`).
- Decompression bombs are capped at 64 MiB (`decoder.rs:150,198`) with a test. The cap works; only
  its *reporting* is the defect (B-1).
- Axum's default body limit applies to the new tool endpoints; no unbounded buffering was found.

**ReDoS / regex compile abuse — checked, not applicable.**
`matchreplace.rs:265` and `eval.rs:873` use the `regex` crate, which is finite-automaton based
(linear time, no catastrophic backtracking) with a default 10 MB compile cap. `Rule::new` compiles at
construction, so nothing uncompiled reaches the proxy hot path (`lib.rs:21-22`). Not a finding.

**A lock held across an `.await` — checked, not found.**
`intercept.rs:9-13` documents the property and the mechanism that enforces it: `parking_lot::MutexGuard`
is `!Send`, so the compiler rejects it. Every `held.lock()` in `intercept.rs` (`:129`, `:140`, `:152`,
`:172`, `:191`, `:200`) is scoped to a map insert or remove, and the `rx.await` at `:164` is outside
any guard.

**`debug_assert` doing load-bearing work — checked; the known instance is pre-existing.**
`crates/scanner/src/lib.rs:497` is already recorded in `.planning/codebase/CONCERNS.md` and came from
`53d4337`, a *reviewed* branch, so it is outside this requirement.

**Off-by-one / span correctness in `insertion.rs` — checked, not found.**
`kv_pairs` (`:289-312`) loops `while i <= b.len()` but short-circuits on `i == b.len()` before any
indexing of `b[i]`, and emits `cs..cs+eq` / `cs+eq+1..i`, which are correct half-open ranges. Empty
names are dropped (`:303`), and a clause with no `=` is skipped with the reasoning stated at
`:284-288`.

**`to_raw` framing integrity — checked, correct.**
`crates/core/src/edit.rs:203-219` drops any inherited `Content-Length`/`Transfer-Encoding` and
rewrites the length from the actual body, so a body splice cannot leave a stale length that truncates
the payload.

**Pre-existing defects encountered but *not* attributable to these three branches** (recorded so the
next reader does not re-derive them, and deliberately not counted above):
- `crates/proxy/src/lib.rs:305` — `let n = upstream.read(&mut chunk).await.unwrap_or(0);` treats a
  read error as a clean EOF, so a response truncated by a reset is stored as complete with no flag.
  `git blame` attributes it to `cc40ebf`, the initial commit.
- `crates/bcheck/src/eval.rs:346` — `Regex::new(&pattern).ok()?` in `regex_replace` silently yields
  absent for an invalid pattern while `:873` reports the same condition as
  `Unsupported::BadRegex`. Also `cc40ebf` (`git log -S` confirms).
- The `verify.sh` "three skipped checks calling `ok`" instance named in the HARD-01 brief is
  **already fixed** by `22f456e` (HARD-02): `skip()` now counts into `SKIPPED`, prints
  `VERIFIED WITH GAPS`, and honours `STRICT=1` (`verify.sh:13-25,130-150`).

**Not verified by execution.** No build or test run was performed: other agents are concurrently
editing `crates/http2`, `crates/scanner`, `crates/query` and `crates/core`, and a `cargo` invocation
would have collided with them over `target/`. Every finding above therefore rests on source reading,
and each one states the reasoning so a fixer can confirm it independently. B-2's empty-zlib half is
the only finding whose impact is unconfirmed, and it says so.

---

## Requirement status

HARD-01's first half — *"each of the three previously-unreviewed merged branches has a documented
line-by-line review"* — is satisfied by this document.

The second half — *"any defect found in it is fixed and tested"* — is **not** satisfied. Eight
defects are open: four MAJOR, four MINOR. Suggested order, by ratio of impact to effort:

1. **C-1** — silent false negatives on the scanner's main path; undermines REPORT-04 and DASH-03.
2. **B-1** — silent truncation in the decoder; the fix is a flag through three call sites.
3. **A-2** then **A-1** — fix the bodiless-status root cause, then restore the documented demotion.
4. **A-3** — add the mixed-framing origin, which is the regression test for A-1 and A-2.
5. **A-4**, **B-2**, **C-2** — small and self-contained.
