# Phase 1: Store & Scope Chokepoint - Context

**Gathered:** 2026-07-27
**Status:** Ready for planning

<domain>
## Phase Boundary

Captured traffic becomes durable on disk in sealed, self-describing segments whose RAM cost is
bounded by one active segment rather than by the size of the capture; the store's integrity becomes
something an operator can *check* rather than infer; and every constructed request that reaches a
socket routes through exactly one authorising type.

**In scope:** STORE-01 (segmented, sealed, mmap-backed persistence), STORE-05 (two distinct
verification mechanisms plus the operator-facing command), HARD-03 (the `AuthorisedSender`
chokepoint, including the per-crate `tokio` feature narrowing and the source-scan backstop test).

**Already landed — re-verify, do not rebuild.** Commit `d8fe387` ("core: make position the id, and
give an exchange a related slot") implements STORE-02, STORE-03 and STORE-04 against the in-memory
store: position-is-the-id with bounds-checked O(1) `get`/`exchange`, the id assigned under the same
write lock that appends (closing the `AtomicU64::fetch_add`-then-parse-then-push race), `counts()`
reading a maintained byte tally instead of walking the log, `Exchange.related: Vec<ChildRef>`, and
`verify_index()`. Four tests cover it, including 8 threads x 400 concurrent appends asserting each
issued id resolves to that caller's own bytes. Phase 1 carries these forward and must keep them true
through the segment port; it does not re-derive them.

**Explicitly out of scope:** reloading a prior capture on startup (the record format makes it
possible; the reload path lands with the phase that needs it), and per-surface chokepoint
verification for the crawler, session macros, plugins, WebSockets, MCP and the browser — each lands
in its own later phase.

</domain>

<decisions>
## Implementation Decisions

### Segment Store & On-Disk Format (STORE-01)

- **Segment size is a 64 MiB target, not a hard cap.** A tunable `const` plus a config knob, not a
  hardcoded magic number. The number bounds the active (unsealed, RAM-mirrored) segment, which is
  what makes it a RAM ceiling rather than merely a rotation cadence. Kafka's 1 GiB default is the
  wrong anchor to import — its segments are not held resident the way the active one here is; use it
  only as an order-of-magnitude check that tens of MiB is a sane regime.
- **Roll to a new segment at a completed-message boundary, never mid-write.** One message's bytes
  must never span two segments — that invariant is what lets `Bytes::from_owner(mmap).slice()` work
  per segment.
- **A single message larger than the target is accepted into its own oversized segment**, sealed
  immediately after. Never rejected, never truncated, never split. This is a deliberate divergence
  from Kafka (which refuses records above `message.max.bytes`): refusing to capture a large response
  would silently violate the capture-everything premise this subsystem exists to serve, and mmap
  does not require uniform segment sizes — only that a live mapping is never remapped. Document it
  as a decision so it does not read as an oversight.
- **One-byte format version lives in the segment *file* header, not the per-record header.** Cheap
  insurance against the one thing that is genuinely expensive to retrofit. Do not build a
  migration-between-format-versions story in Phase 1.
- **Records are self-describing:** a small fixed header carrying payload length, `MsgId`, direction
  and a CRC32, followed by the payload. This makes each segment sequentially scannable, which is what
  the checksum scan reads back against and what a future reload path would rebuild from.
- **Startup recovery is deferred.** Criterion 1 is about a multi-GB capture staying bounded by disk
  rather than RAM — not about resumability. The format ships in Phase 1; rescanning sealed segments
  to rebuild the index on startup lands with the phase that needs it. Do not half-build it.
- **Segment lifecycle, never remapped:** buffered `File::write` to `segment-NNNNNN.log.tmp` while
  active (never mapped); on seal `fsync` → close → rename to `segment-NNNNNN.log` → verify every
  record's CRC → *then* `mmap` read-only and wrap once in `Bytes::from_owner`. A segment is always in
  exactly one of two states, never written-to and mapped simultaneously.
- **Bounds-check every resolved span against the segment's actual mapped length before slicing**,
  mirroring the existing `StoredMessage::slice` guard. A malformed record header is a
  refuse/report-corruption case, never a silent skip.

### Verification & the Operator Command (STORE-05)

- **Two mechanisms, distinctly named, never conflated.** They catch different failure classes and a
  plan with one "verify the store" task instead of two is the failure mode to avoid.
  - **Mechanism A — differential parity.** Drive an identical sequence of operations
    (`put`/`get`/`add_exchange`/`set_response`, including concurrent interleavings) against the
    current in-memory implementation and the new segment-backed one in the same test binary, and
    assert every observable result is identical at every step. Proves the port preserved behaviour.
    Runs in CI on every subsequent change.
  - **Mechanism B — per-record checksum scan.** Walk every stored id, resolve its bytes through the
    live store, recompute the CRC, compare against the header. Proves nothing has silently corrupted
    since it was written — torn writes, a stale mapping outliving a segment's supposed immutability,
    truncation. Only this mechanism can catch corruption introduced by disk/OS failure rather than by
    a logic bug in the port.
- **There is no pre-existing on-disk store to migrate from.** `TrafficStore` is `Vec<StoredMessage>`
  in RAM today; nothing under `crates/core` writes a file. STORE-05's "migrated capture" therefore
  means "the new representation is provably equivalent to the old one, and provably intact going
  forward" — not "convert existing files," because none exist.
- **Operator entry point is a `burpsy store verify` CLI subcommand**, a thin wrapper over the
  verification logic in `core`. This is the literal "operator can run a migration check" of
  criterion 4.
- **Output names every mismatch.** A per-record verdict identifying each mismatching id *and the
  reason*, a summary line (`checked N, M mismatches`), and a non-zero exit when any mismatch is
  found. Never a bare bool, never summary-only, never first-mismatch-then-abort — the criterion's
  whole point is that success is not inferred from the absence of a crash.
- **`proptest` is added as a new dev-dependency** for the differential test, so op sequences are
  generated rather than hand-picked. It is not currently in the workspace; size the phase for it.

### The Authorising Chokepoint (HARD-03)

- **Three senders migrate in, not two.** `proxy::sender::NetSender`, `scanner::Metered` **and**
  `repeater::send`. Criterion 5's "the existing proxy and scanner senders" reads as an illustrative
  minimum, not a closed list: `repeater::send` is a second, already-in-production transport with zero
  scope awareness of its own, whose two call sites (`web::repeater_send` and the intruder attack
  handler's `Guard` wiring) rely entirely on each caller remembering to check. Leaving it out means
  the phase's own acceptance test cannot honestly pass, because an alternate egress path demonstrably
  still exists.
- **The chokepoint lives in a new small crate** (`crates/sender` or similar): `AuthorisedSender` is
  the only public entry point, with the transports in a private module. Keeps `crates/core` free of
  network dependencies.
- **One facade type, two transport implementations behind it** — a blocking path for the scanner's
  deliberately-synchronous BCheck evaluator (whose own doc comment explains why making it async would
  force `Box::pin` through `exec`/`eval_bool` for no benefit), and an async path for
  repeater/intruder. "One authorising sender *type*" is a requirement about the scope-check-and-egress
  point being singular, not about there being one wire-level implementation.
- **Counters are `AtomicU32`, not `Cell<u32>`.** The existing `Metered` uses `Cell` and compiles only
  because it is constructed fresh per audit item and never shared. A chokepoint held behind one shared
  `Arc` across concurrent callers will not compile with `Cell` — it is not `Sync`. Get this right from
  the start rather than carrying the pattern over unchanged and having it break late.
- **Enforcement is a private-field newtype, plus per-crate `tokio` feature narrowing, plus a
  source-scan backstop test — with the bound stated honestly.** Narrow `tokio` in
  `intruder`/`bcheck`/`scanner` `[dependencies]` (restoring `net` under `[dev-dependencies]` so
  existing test helpers still compile) so `tokio::net` genuinely does not exist in their production
  namespace. Then state plainly, in the plan and in the doc comments: `std::net::TcpStream` is part
  of the standard library and remains reachable from any crate regardless of Cargo features, so the
  feature narrowing closes the async path structurally while the source-scan test covers the residual
  `std::net` surface. Do not write "compile error, not convention" without that qualification —
  overclaiming what was fixed is exactly the honesty failure this project rejects elsewhere.
- **Do not seal the `Sender` trait.** It is deliberately implemented by test doubles
  (`SlowSender`/`RecordingSender`/`FailingSender` in scanner, `TargetSpy`/`MockSender` in
  `bcheck::eval`) precisely so tests can prove traffic did or did not reach a socket. Sealing it would
  destroy the mechanism that makes this feature testable. The property to enforce is "nothing can
  reach a *real* socket except through `AuthorisedSender`" — a newtype-with-private-field property,
  not a sealed-trait one.
- **Reduce `repeater`'s public surface** so it no longer exports a bare `send()` that opens a socket
  unconditionally; its call sites construct and use an `AuthorisedSender` instead.

### Scope Boundaries & Already-Landed Work

- **Phase 1 plans STORE-01, STORE-05 and HARD-03.** STORE-02/03/04 landed in `d8fe387` and are
  carried forward: the plan re-verifies them (they must survive the segment port) rather than
  rebuilding them.
- **Keep the `ChildRef` shape that shipped:** `Exchange.related: Vec<ChildRef>` with `MsgId` payloads
  and `#[serde(default)]` for backward compatibility, and `msg()` to read the id whatever the variant.
  Both `WsFrame` and `H2Frame` variants already exist, so Phase 2 (HTTP/2) does not have to extend a
  shipped enum. This supersedes the research document's `Vec<Vec<ChildRef>>`-keyed-by-exchange-id
  sketch with `usize` payloads — the landed shape keeps the children with the record that owns them
  and carries real `MsgId`s rather than indices into a table that does not exist yet.
- **The proxy's MITM upstream forwarding stays outside the chokepoint**, as a considered boundary
  rather than an omission. It relays the client's *own* bytes for ordinary browsing — not a
  constructed request in the sense criterion 5 means — and `Scope` there gates whether a request is
  paused for operator review, never whether it is forwarded. Say so explicitly in the plan.
- **Skip `loom` in Phase 1.** Making it work requires swapping `parking_lot::RwLock` for a
  `loom`-compatible abstraction under `cfg(loom)`, which is non-trivial. The evidence for
  "closed, not narrowed" is that the id is now assigned under the same lock that appends — a
  structural argument, not a statistical one — backed by the landed 8x400-thread test and
  `verify_index()`. Revisit if the invariant ever grows more complex.

### Claude's Discretion

- Exact crate name and module layout for the chokepoint, and the precise `Transport` enum/trait shape
  behind the facade.
- Record header field order and encoding, and the segment filename scheme.
- CLI subcommand argument surface beyond `burpsy store verify` itself.
- Whether `crc32fast` is depended on directly by `crates/core` or reached another way (it is already
  a transitive dependency via `flate2`, so this adds no new supply-chain surface either way).
- How the source-scan backstop test is hosted (a `#[test]` walking relative paths is simpler than an
  `xtask` crate and consistent with this workspace having no existing `xtask`).

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`Scope::authorise_request(host, port, tls, raw)`** in `crates/core/src/scope.rs` — already the
  single scope *decision* function, and already correct: it authorises the request that is actually
  being sent rather than the target that was named (commit `ced8e22`), and refuses rather than waving
  through a request with no readable start line. The chokepoint wraps this; it does not replace or
  re-implement it.
- **`scanner::Metered`** in `crates/scanner/src/lib.rs` — already does exactly the right thing (wrap
  a `Sender` plus a `Scope`, check scope on the actual outbound bytes, delegate only on success) and
  is already tested. It is crate-private, so nothing outside `scanner` can use it. The work is to
  promote this pattern to a shared public type, with the `Cell` → `AtomicU32` correction.
- **`proxy::sender::NetSender`** — blocking `std::net`/`rustls` transport with a keep-alive
  connection pool, implementing `burpsy_bcheck::eval::Sender`. Deliberately transport-only, no scope
  awareness. Becomes an inner collaborator of the chokepoint, not a public entry point.
- **`bytes::Bytes::from_owner`** — `bytes` 1.12.1 is already the resolved workspace version and the
  signature is confirmed: `pub fn from_owner<T>(owner: T) -> Self where T: AsRef<[u8]> + Send +
  'static`. `Mmap` already satisfies those bounds, so no `Arc<Mmap>` wrapper is needed.
- **`crc32fast` 1.5.0** — already in `Cargo.lock` as a transitive dependency via `flate2`
  (`crates/tools`), so depending on it directly adds no new supply-chain surface.
- **`StoredMessage::slice`'s bounds guard** (`if s.end() > self.raw.len() { return Bytes::new(); }`)
  — the discipline to mirror for segment-backed spans.

### Established Patterns

- **`cargo test` only** — plain `#[test]`/`#[tokio::test]`, no `proptest`/`quickcheck`/`criterion`
  anywhere in the workspace today, and no test config files. `proptest` is a genuinely new addition.
- **Tests are named as claims and carry the requirement id** in a doc comment (e.g.
  `ids_and_insertion_order_agree_under_concurrent_puts`, `/// STORE-03.`), and assertion messages
  say what a failure *means* ("id {id:?} resolved to another thread's message") rather than restating
  the comparison. Doc comments explain *why*, including what the previous implementation got wrong.
- **Invariants are made checkable, not merely asserted in prose** — `verify_index()` returns the first
  disagreement it finds and names the id. Extend this posture to segment integrity.
- **`parking_lot::RwLock` around a single `StoreInner`**, with expensive work (parsing) kept outside
  the critical section and the id assigned inside it.
- **Refuse-by-default on unparseable input** — `scope.rs`'s own test suite asserts a request with no
  readable start line is refused, not waved through.
- **The workspace declares `tokio = { features = ["full"] }`**, which is why `tokio::net` compiles
  today inside `intruder` (its own `tcp_sender` test proves it). Narrowing is per-crate.

### Integration Points

- **`TrafficStore`'s public API is the seam**: `put`/`get`/`add_exchange`/`set_response`/`exchange`/
  `exchanges`/`counts` (+ the new `add_related`/`related`/`verify_index`). No consumer touches
  `StoreInner` directly, so the segment backing can land underneath an unchanged public API.
- **Exchange construction sites** in `proxy`, `scanner`, `web` and `core::sitemap` now pass
  `related: Vec::new()` — the places that will eventually attach children.
- **`crates/cli/src/main.rs`** — where the `store verify` subcommand hangs off.
- **`web::repeater_send` and the intruder attack handler** in `crates/web/src/lib.rs` — the two call
  sites that currently wire scope checks by hand around scope-unaware transports, and therefore the
  two that must switch to `AuthorisedSender`.
- **`crates/intruder/src/engine.rs`** — documents in its own doc comment that the engine has no
  concept of engagement scope and should not grow one. That stays true; the point is that its `Guard`
  is `Option`al, so a caller who forgets `.with_guard(...)` compiles fine and sends unauthorised
  traffic. The chokepoint is what removes that possibility.

</code_context>

<specifics>
## Specific Ideas

- Sequence the store work as three internally-independent steps so the risky I/O lands on an
  already-proven index: (1) the race-free O(1) index — **already done in `d8fe387`**; (2) the
  segment/mmap backing underneath that index (STORE-01); (3) checksums plus the two-mechanism
  verification story (STORE-05). HARD-03 is a parallel track with no dependency on the segment work
  and can proceed concurrently.
- The phrase to hold the plan to on HARD-03: *"the work is disciplined generalisation of things that
  already exist and already work, not invention from nothing."* `Metered` is the pattern, `memmap2` +
  `Bytes::from_owner` is the stack, `crc32fast` is already in the tree.
- Two named pitfalls worth restating in the plan because both are already realised in the codebase
  rather than hypothetical: `repeater::send`'s total absence of scope awareness, and `Metered`'s
  `Cell<u32>` counters that will not survive being shared.

</specifics>

<deferred>
## Deferred Ideas

- **Startup recovery / capture resumability** — rescanning sealed segments to rebuild the index and
  exchange table on process start. The self-describing record format ships in Phase 1 to make it
  possible; the reload path itself belongs to whichever phase first needs a capture to survive a
  restart.
- **`loom`-based exhaustive interleaving verification** — needs a `cfg(loom)` abstraction over
  `parking_lot::RwLock`. Revisit if the store's locking invariant grows beyond
  "the id is assigned under the lock that appends."
- **Per-surface chokepoint verification** for the crawler (Phase 6), plugins (Phase 8), WebSockets
  (Phase 9), MCP (Phase 10) and the browser (Phase 12), plus session macros (Phase 5) — each phase
  proves its own surface routes through `AuthorisedSender`. Criterion 5 explicitly scopes Phase 1 to
  the senders that exist today.
- **A migration story between on-disk format versions** — Phase 1 writes a version byte as cheap
  insurance and stops there.
- **Segment compaction, retention, or deletion policy** — nothing in this milestone asks for capture
  eviction; the store grows until the operator removes the directory.

</deferred>
