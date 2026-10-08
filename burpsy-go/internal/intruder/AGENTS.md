<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# intruder

## Purpose

Insertion-point discovery and payload attacks — the Go port of `../../crates/intruder`. An
insertion point is a `core.Span` plus a kind, pointing into request bytes the store already owns;
a payload is applied by splicing once at send time rather than by cloning the request per position.
The taxonomy (`PointKind`, `AttackKind`) mirrors Burp's, recovered from its own method names.

The load-bearing design is the same as the Rust reference: a cluster bomb of 100,000 requests must
not hand back 100,000 bodies. `Run` returns an `AttackReport` whose `ResultBucket`s key on
`(status, response_len, reflected)` and count; one response per bucket is recorded via `RecordFn`
and everything else is referenced by ordinal, never held.

## Two APIs in this package (a Go-specific split)

Unlike the single Rust crate, this package carries **two** attack surfaces:

- **The faithful engine** (`engine.go`, `plan.go`, `payload.go`, `points.go`, `process.go`,
  `limit.go`, `breakdown.go`): `NewAttack(...).WithLimits(...).WithGrep(...)` then `Run(a, send, record)`,
  returning a bucketed `*AttackReport`. This is the memory-frugal port and the authority.
- **A legacy channel driver** (`intruder.go`): `NewIntruder(logger).WithSend(fn).Run(...)` returns a
  `<-chan *AttackResult`, one `AttackResult` per attempt (each carrying `StatusCode`, `Length`,
  `Words`, `Lines`). This materialises per-attempt rows and does not bucket. `AttackType`
  (Sniper/BatteringRam/Pitchfork/ClusterBomb) and `PayloadGenerator` live here.

New callers should prefer the engine. Treat `intruder.go` as the older, simpler surface.

## Key Files

| File | Description |
|------|-------------|
| `engine.go` | The bucketing engine: `Attack`, `Run`, `Sent`, `SendFn`, `RecordFn`, `Guard`, `Grep`, `ResultBucket`, `AttackReport`, the internal `collector`. Concurrency via goroutines gated on the `RateLimiter` |
| `plan.go` | `AttackPlan`, `AttackKind` — attack shapes generated lazily; `Fill(i, *Assignment)` reconstructs request `i` on demand. Saturating arithmetic for the combination count |
| `payload.go` | `PayloadSource` / `PayloadSet` — number, date, brute-force, custom-iterator and null generators that `Resolve(maxCount)` to a set. Own `splitMix64` PRNG for sampling |
| `points.go` | `PointKind`, `InsertionPoint`, `PointConfig`, `FindPoints`; `Apply`/`ApplyAll` splice payloads and `fixContentLength` rewrites the body length |
| `process.go` | `RuleSpec`, `Chain` — the per-payload processing rule chain applied at resolve time; `hashAlg` (MD5/SHA) via stdlib `crypto` |
| `limit.go` | `RateLimit`, `AutoThrottle`, `RateLimiter`, `Permit` — in-flight bound (a `slots` channel), rate reservation, opt-in per-status back-off |
| `breakdown.go` | Projects an `AttackReport` onto `dash.Breakdown` (Found/Errored/Skipped/Gated) for dashboard summaries |
| `intruder.go` | The legacy channel-based `Intruder`, `AttackConfig`, `AttackResult`, `AttackProgress`, `PayloadGenerator` |

## For AI Agents

### This package does not decide engagement scope — the sender does

Both surfaces refuse to invent an egress path. The engine takes a `SendFn` and the legacy
`Intruder` takes an `AttackSendFunc` (via `WithSend`); the caller closes it over an authorised
sender. `sendAttack` **fails closed** when `send` is nil (`errNoAuthorisedSender`) rather than
dialling directly — that fallback was the defect it replaced. The scope check judges the outbound
bytes, per request, because a payload spliced into a `PointURLPathFolder`/`PointURLPathFilename`
position rewrites the request line and may address something the named target never covered.

### How a spliced request reaches the wire is decided in `internal/web/intruder_send.go`

The engine hands each spliced request to a `SendFn`; the web layer's `buildIntruderSendPlan` builds
that function from the run request and refuses a bad setting before anything is sent. Every setting
that changes the wire rather than the payloads lives there: the session jar, follow-redirects, the
total `timeout_ms`, the per-request `response_timeout_ms` (carried on the context as
`sender.SendOptions`), `http_version`, HTTP/1 connection reuse (`sender.ConnPool` via
`AuthorisedSender.SendReusing`) and Update Host header to match target. A new wire setting belongs in
that plan, not in this package, so the engine stays a pure splice-send-bucket loop.

### Divergence from Rust: the `Guard` was kept, not removed

The Rust `AGENTS.md` says the `Option<Guard>` was deleted and must not be reintroduced. **The Go
`Attack` still has a `Guard` field and `WithGuard`** (`engine.go`). Its doc frames it as the one
place that sees the request a payload actually produced, and refusals are counted as errors, never
dropped silently. This is a real Rust↔Go difference — verify against `gaps.md` before "fixing" it in
either direction.

### A report, not a pile of bodies

`AttackReport` summarises. Results hold ordinals; `AttackPlan.Fill` regenerates the exact payload
combination behind ordinal `i`. The recorder fires once per bucket, so resident bytes scale with
distinct behaviours, not with requests sent. `DetailLimit` (default 500) bounds per-attempt rows and
`MaxBuckets` (default 2000) bounds distinct buckets; both caps are reported (`Truncated`,
`BucketsTruncated`, `Unbucketed`) so a cap never looks like checks that stopped firing.

### Body containers come from the scanner's enumerator, not from a second parser here

Form bodies are walked natively (wire-faithful, unescaped). Every other body container —
JSON string values, XML text nodes and attributes, multipart part contents and their
`name`/`filename` attributes, and the JSON/base64/XML nested inside any of them — is
enumerated by `internal/bcheck` and adopted through `bcheck.InsertionPoint.BodyWindow`
(`points_bcheck.go`). The enumerator also owns the escape for each container
(`WireValue`), so a payload Intruder sends is byte-identical to what the scanner would
send for the same container; a payload the container cannot hold (a multipart boundary
delimiter inside that part's content, a line break inside a header attribute) is refused
there and the position is skipped rather than spliced. Adding a container means adding it
in `internal/bcheck` — a parser here would be the second model of the same format, which
is the drift this design exists to prevent (burpsy-react-ui-33t, 63jg).

### Append placement is a zero-length span, and overlap has one definition

`PointConfig.Placement` is Burp's "Automatic payload placement" (1krs). Under `PlacementAppend`
every discovered parameter VALUE becomes a zero-length span at the end of the value (Burp's
`Zswj(valueEnd, valueEnd)`), with `BaseSpan()` still naming the value; a nested container keeps its
window and is rebuilt by `bcheck.InsertionPoint.WireValueAppend`, because base64 cannot be extended
by concatenation. Names, paths, headers, multipart attributes and the entire body keep replacing.
`SpansOverlap` is the one definition of "two positions compete": a zero-length span overlaps any
span it touches, edges included. `ApplyAll`'s earliest-span-wins skip and the web layer's
manual-vs-discovered refusal both use it — a second, strict-inequality copy is how a zero-length
insertion slips past one of them.

### Grep is reported but is not part of the bucket key

`Grep` holds two optional `regexp` patterns applied to every response. Matches and the extracted
capture are reported per attempt and per bucket (as an exemplar), but the key stays
`(status, response_len, reflected)` — keying on a grep result would silently double the bucket count
for any attack that turned a pattern on. `MAX_EXTRACT` (256) bounds the reported capture and a
truncated value is marked as such.

### Payloads and rules resolve before the attack, never inside it

`PayloadSource.Resolve` produces the set and `Chain` rewrites it in place before `Run`. `max_count`
**truncates** the list (flagged via `PayloadSet.Truncated`); an over-length item is **refused**, not
shortened — a shorter list is an honest subset, a shortened payload is a different payload.

### The auto-throttle is opt-in

`RateLimit` carries no `AutoThrottle` by default; `RateLimiter.Observe` and the throttle charge
short-circuit when it is absent. It is the one path every request passes through, so keep it free
when unconfigured.

## Testing Requirements

```bash
go test ./internal/intruder/...
```

Tests include real local listeners (`engine_net_test.go`) and timing-sensitive rate-limit tests
(`limit_test.go`) that assert bounds rather than exact timings.

## Dependencies

### Internal

- `internal/core` — `Span`, `StoredMessage`, the bytes attacks splice into and locate points within
- `internal/bcheck` — the single body-container enumerator (JSON, XML, multipart, nested) whose
  windows and escapes Intruder adopts (`points_bcheck.go`); it is a leaf here, never the reverse
- `internal/dash` — `Breakdown`/`Reason`, the shared dashboard count shape (`breakdown.go`)
- `internal/tools` — decoder codecs for the payload-processing encode/decode rules
- `internal/httputil` — request/response byte helpers

### External

- `go.uber.org/zap` — the legacy `Intruder`'s logger

Note: unlike the Rust crate there is no `tokio`; concurrency is goroutines bounded by the
`RateLimiter`'s slot channel, and regex/hash use the Go standard library (`regexp`, `crypto`).

<!-- MANUAL: -->
