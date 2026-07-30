<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# intruder (`burpsy-intruder`)

## Purpose

Insertion-point discovery and payload attacks. An insertion point here is a `Span` plus a kind — no
allocation, pointing into bytes the store already owns.

The contrast that shaped it: Burp's insertion-point engine (`burp.Zuq`, 1479 lines) materialises every
attack position as an object and threads it through all seven check-dispatch scopes. With
`requests × insertion points × checks` unbounded, it must shed load — `Zq5.LIMIT_EXCEEDED` exists for
exactly that. Building every position for a request is near-free here, and a payload is applied by
splicing once at send time rather than cloning the request per position per check.

The taxonomy mirrors Burp's, recovered from its own method names.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | `find_points`, `InsertionPoint`, `PointConfig`, `Attack`, `Assignment`, `AttackReport`, `SendFn`, `RecordFn`, `Sent` |
| `src/engine.rs` | Running an attack: bounded concurrency via `JoinSet`, and a summary instead of a pile of bodies. `Grep` |
| `src/plan.rs` | `AttackPlan`, `AttackKind` — attack shapes, generated lazily |
| `src/payload.rs` | `PayloadSource` — payload generators (numbers, dates, brute forcer, custom iterator, null) that resolve to a `PayloadSet` |
| `src/process.rs` | `RuleSpec`, `Chain` — the per-payload processing rule chain, applied at resolve time |
| `src/hash.rs` | MD5/SHA-256 for the chain's hash step. **Duplicated on purpose and scheduled for deletion** — see below |
| `src/limit.rs` | `RateLimit`, `AutoThrottle` — rate limiting, in-flight bounds and per-status back-off, over `tokio::sync::Semaphore` |

## For AI Agents

### This crate has no concept of engagement scope, and must not grow one

`engine.rs` says so in its own doc comment, and it is correct: an attack engine's job is to splice
payloads and bound concurrency, not to decide authorisation. The scope decision belongs to
`burpsy_sender::AuthorisedSender`, which the caller injects as the `SendFn`.

This used to be handled by an `Option<Guard>` closure the caller attached with `.with_guard(...)` — and
because it was optional, forgetting it compiled fine and sent unauthorised traffic. That guard has been
removed: the sender the caller hands in cannot skip the check. **Do not reintroduce a guard parameter**;
if a caller can send without authorisation, the fix is at the sender, not here.

### Why the scope check has to happen per spliced request

A payload landing in a `UrlPathFolder` or `UrlPathFilename` position **rewrites the path**. The request
that actually goes out may address something a host-level check never saw. This is why authorisation
judges the outbound bytes rather than the named target, and why it happens once per request rather than
once per attack.

### `tokio` features are narrowed here

Production gets `["rt", "sync", "time"]` — no `net`. Dev-dependencies restore `net`, `macros`,
`rt-multi-thread` and `io-util` for the crate's own listeners and helpers.

Be aware of the limit: this bites under `cargo build -p burpsy-intruder` but **not** under
`cargo build --workspace`, because cargo unifies features and other crates enable tokio's `full`. The
narrowing records intent and catches the mistake in an isolated build; the real guard is
`crates/sender/tests/no_alternate_egress.rs`. See `../sender/AGENTS.md` for the measured detail.

### A report, not a pile of bodies

`AttackReport` summarises. An attack of 200,000 requests must not accumulate 200,000 response bodies —
that is the memory failure this whole project exists to avoid. Responses are recorded into the store via
`RecordFn` (returning a `MsgId`) and referenced, never held.

### Payload generators and processing rules resolve *before* the attack, never inside it

`PayloadSource::resolve` hands back a `Vec<Bytes>` and `Chain::run` rewrites that `Vec` in place. The
engine's payload type never changed and `Attack::new` still takes `&[Vec<Bytes>]` — a generator is
another way to *produce* the set, not another kind of set.

That is load-bearing, not incidental:

- **A result row holds an ordinal and nothing else** because the payload behind ordinal `i` is still
  there to look up after the attack. A generator driven mid-flight would break that.
- **`skip-if-matches` drops a payload from the set**, so `plan.len()` is still the number of requests.
  Applying the skip in the engine would leave gaps in the ordinal space and every count in
  `AttackReport` would need a "plus N ordinals that were never requests" caveat.

The cost is stated in `payload.rs`'s module note: **Burp's Recursive grep cannot be a `PayloadSource`**
and is deliberately absent, because its next payload does not exist until the previous response has
come back. If it is wanted it is a new *attack shape* next to `AttackKind`, not a generator.

### Generators are bounded twice, and the two bounds behave differently

`max_count` (itself capped at `payload::MAX_PAYLOADS`) **truncates the list** and says so via
`PayloadSet::truncated` next to `total`. `MAX_ITEM_LEN` **refuses** — a shortened list is an honest
subset of the attack, a shortened payload is a different payload. Do not "fix" the refusal into a
truncation.

### `hash.rs` is knowing duplication

MD5/SHA-256 belong in `burpsy_tools::decoder` with every other codec, and that is where the Decoder's
own hashing landed. This copy exists because both were built in the same batch. **When consolidating:
delete `hash.rs` and point `process.rs` at the tools function** — the crate already depends on
`burpsy-tools`, so nothing else changes. Both implementations are checked against RFC 1321 and
FIPS 180-4 vectors, so the swap is verifiable.

### The auto-throttle is opt-in, and that is a safety property not a convenience

`RateLimit::auto_throttle` is `None` by default and every path in `limit.rs` short-circuits on it:
`charge_throttle` returns the rate untouched without taking a lock, and `RateLimiter::observe` returns
on one `Option` check. This is the one code path every request of every attack passes through, so
`with_no_auto_throttle_configured_nothing_observes_and_nothing_changes` asserts the *absence* of an
effect and should be treated as a regression gate.

`RateLimit` is no longer `Copy` (it owns a pool name), so `RateLimiter::new` takes it by reference.

`RateLimit::name` is an identifier the caller passes and gets back in `AttackReport::pool`. It does
**not** make two attacks share a bucket, and this crate keeps no registry of pools — cross-attack pool
state belongs to whoever owns the attacks, not to the thing that bounds one.

### Grep results are reported but are not part of the bucket key

`engine.rs`'s header says arbitrary grep patterns are "a separate feature, not part of the key", and
adding `Grep` did not change that. Keying on a grep result would silently double the bucket count for
any attack that turned a pattern on, and the same responses would collapse differently depending on
what was being searched for. So a bucket carries `grep_matches: usize` — how many of its responses
matched — which makes unanimity and a mixture distinguishable without splitting the bucket.
`ResultBucket::grep_extract` is the *exemplar's* value and its doc says so; the per-attempt rows carry
the rest.

### Testing Requirements

```bash
cargo test -p burpsy-intruder      # 86 tests
```

Tests use real `tokio::net` listeners (available via dev-dependencies). Rate-limit tests are timing
sensitive — they use short sleeps and assert bounds rather than exact timings.

### Common Patterns

- Plans are generated lazily; `payloads_at(plan, sets, ordinal, buf)` reconstructs an assignment on
  demand into a caller-supplied buffer rather than materialising the cross-product.
- Bounds are the operator's, and come back in the report either way, so a cap never looks like checks
  that stopped firing.

## Dependencies

### Internal

- `burpsy-core` — `Span`, `StoredMessage`, the bytes attacks splice into
- `burpsy-tools` — `decoder`'s codecs, for the payload-processing encode/decode rules. A sibling edge
  under `core`: `tools` reaches for nothing but `core`, so this adds no cycle and is clear of the two
  edges `crates/AGENTS.md` forbids

### External

- `tokio` (narrowed: `rt`, `sync`, `time`), `bytes`, `serde`, `parking_lot`, `regex` (payload
  match/replace and skip rules, and result grepping — `regex::bytes`, because a payload and a response
  body are both bytes)

<!-- MANUAL: -->
