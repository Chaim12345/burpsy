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
| `src/engine.rs` | Running an attack: bounded concurrency via `JoinSet`, and a summary instead of a pile of bodies |
| `src/plan.rs` | `AttackPlan`, `AttackKind` — attack shapes, generated lazily |
| `src/limit.rs` | `RateLimit` — rate limiting and in-flight bounds, over `tokio::sync::Semaphore` |

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

### Testing Requirements

```bash
cargo test -p burpsy-intruder      # 34 tests
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

### External

- `tokio` (narrowed: `rt`, `sync`, `time`), `bytes`, `serde`, `parking_lot`

<!-- MANUAL: -->
