# Phase 1: Store & Scope Chokepoint - Research

**Researched:** 2026-07-27
**Domain:** Rust append-only mmap storage migration + capability-scoped network sender design
**Confidence:** MEDIUM-HIGH — segment/index design and the chokepoint design are grounded directly
in this codebase's own source (primary source, read this session); segment-size number and the
exact Rust enforcement mechanism are reasoned recommendations flagged where they are not fully
verified.

> **No CONTEXT.md exists for this phase** — the operator planned without a discuss-phase pass, so
> the design questions this file leaves open are the planner's to decide, not the operator's to
> have already answered. Flag these clearly rather than picking silently.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| STORE-01 | Captured traffic persists to disk in fixed-size sealed segments | Segment lifecycle design (below), segment-size recommendation, `Don't Hand-Roll` (memmap2) |
| STORE-02 | Any message resolves to its bytes in constant time | Race-free index design (Pattern 1) — same fix as STORE-03, one critical section |
| STORE-03 | A message id always resolves to the message stored under it under concurrent capture | Race-free index design (Pattern 1); Validation Architecture's concurrent-stress/loom guidance |
| STORE-04 | A record carries references to related child records | `ChildRef`/`related` slot design (below), concretely shaped, not left for the planner to invent |
| STORE-05 | Operator can verify a migrated capture is byte-identical to the previous store | Corrected framing: no on-disk store exists to migrate from (Runtime State Inventory) — two distinct verification mechanisms recommended (differential parity test + per-record checksum) |
| HARD-03 | Every request-originating surface authorised through one shared chokepoint, verified by a test per surface | Chokepoint design grounded in `NetSender`/`Metered`/`repeater::send` source (below); "checkable, not conventional" mechanism with an honestly-stated bound |
</phase_requirements>

## Summary

Prior research (`STACK.md`, `ARCHITECTURE.md`, `PITFALLS.md`) already settled the shape of both
halves of this phase: `memmap2` + `Bytes::from_owner` for sealed, never-remapped segments; a single
critical section that assigns the id and writes the location together to close the concurrency race;
and a capability-scoped chokepoint answering Pitfall 4. This document does not re-litigate those —
it answers the three questions that research explicitly left open, using this session's direct reads
of `crates/core/src/lib.rs`, `crates/core/src/scope.rs`, `crates/proxy/src/sender.rs`, and
`crates/scanner/src/lib.rs` as primary evidence, corroborated with targeted web research on Kafka
segment sizing, append-only checksum practice, and Rust visibility patterns.

Three findings correct or sharpen the prior research rather than confirming it:

1. **There is no on-disk capture store today.** `TrafficStore` is `Vec<StoredMessage>` in RAM —
   confirmed by reading `crates/core/src/lib.rs` and grepping for any `File::create`/`OpenOptions`/
   `fs::write` in `crates/core` (none exist). STORE-05's "migrated capture" therefore cannot mean
   "convert an existing on-disk file format" — there is no such file. It means: prove the new
   segmented implementation is behaviourally identical to the current in-memory implementation for
   the same sequence of operations, and prove segment integrity going forward. These are two
   different checks and the plan needs both, not one (see Architecture Patterns, Pattern 3).
2. **The HARD-03 chokepoint is not "build something new from scratch" — it is "promote an existing,
   crate-private pattern to a shared, public type."** `crates/scanner/src/lib.rs`'s `Metered` already
   does exactly the right thing (wraps a `Sender`, calls `Scope::authorise_request` on the actual
   outbound bytes before delegating) — but it is a private `struct` inside `scanner`, unusable by
   anything else. `crates/repeater/src/lib.rs::send()` is a second, independent transport
   implementation with **no scope awareness of its own at all** — every caller (`web::repeater_send`,
   and the `SendFn`/`Guard` wiring for intruder attacks) is individually responsible for calling
   `scope.authorise_request` before invoking it. That is precisely Pitfall 4's failure mode, already
   present in the codebase today, not merely a future risk.
3. **Criterion 5's phrase "the existing proxy and scanner senders" names two concrete, already-read
   types** — `crates/proxy/src/sender.rs::NetSender` (blocking `std::net`/`rustls`, used by the
   scanner's audit path) and `scanner::Metered` (which wraps it). It should be read as *at minimum*,
   not *at most*: a chokepoint that leaves `repeater::send()` outside it does not satisfy "the only
   path from a constructed request to a socket," because `repeater::send()` demonstrably is a second,
   already-existing path today.

**Primary recommendation:** Sequence Phase 1 in three internally-independent steps against the
*existing* public API (`put`/`get`/`add_exchange`/`set_response`/`exchange`/`exchanges`/`counts` —
no consumer touches `StoreInner` directly, confirmed by grepping every crate that imports
`TrafficStore`): (1) race-free O(1) index over the current in-memory `Vec` — pure logic, no I/O,
independently testable, fixes STORE-02/03; (2) segment/mmap backing store underneath that index —
STORE-01, the risky I/O work landing on an already-proven index; (3) checksums + the two-mechanism
verification story — STORE-05. HARD-03 (the chokepoint) is a separate, parallel track with no
dependency on the segment work, and should migrate `repeater`'s transport into the chokepoint too,
not just `NetSender`/`Metered`.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Segment file I/O (append, seal, mmap) | Database/Storage (`burpsy-core`) | — | Owns the one storage abstraction every other crate depends on |
| Location/id index | Database/Storage (`burpsy-core`) | — | In-process index over the segment layer; not a separate service |
| `related`/`ChildRef` slot | Database/Storage (`burpsy-core`) | — | Extends the exchange index schema, same reason as above |
| Migration/integrity verification | Database/Storage (`burpsy-core`) | API/Backend (`crates/cli`, exposed as an operator command) | Verification logic lives with the store; the operator-facing entry point is a thin CLI wrapper |
| Authorising sender (chokepoint) | API/Backend (new crate or `burpsy-core`) | — | Mediates between every attack-originating surface and the network; not UI, not storage |
| `NetSender` (blocking transport) | API/Backend (`crates/proxy`) | — | Existing blocking `std::net`/`rustls` transport; becomes an inner collaborator of the chokepoint, not a public entry point itself |
| `repeater::send` (async transport) | API/Backend (`crates/repeater`) | — | Existing async `tokio`/`tokio-rustls` transport; same treatment as `NetSender` |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `memmap2` | 0.9.11 | mmap sealed segment files | [VERIFIED: crates.io, `cargo add --dry-run` run this session against `crates/core`] — resolves to 0.9.11. Confirmed by prior project research (`STACK.md`); not re-litigated, only re-verified against the live registry this session. |
| `bytes` | 1.12.1 (already a workspace dependency) | `Bytes::from_owner(mmap)` per sealed segment | [VERIFIED: local vendored source] — `Cargo.lock` already resolves `bytes` to 1.12.1, and `~/.cargo/registry/src/.../bytes-1.12.1/src/bytes.rs:242` was read directly this session: `pub fn from_owner<T>(owner: T) -> Self where T: AsRef<[u8]> + Send + 'static`. No version bump needed — this is already the resolved version in the lockfile today. |
| `crc32fast` | 1.5.0 | Per-record checksum for corruption detection (torn writes, stale mappings, silent truncation) | **New finding, not in prior research.** [VERIFIED: `cargo tree -i crc32fast -p burpsy-tools` run this session] — `crc32fast` is **already a transitive dependency** of this workspace today, pulled in by `flate2` (`crates/tools/Cargo.toml`). Depending on it directly from `crates/core` adds no new supply-chain surface — it is already being built, already vetted by virtue of being upstream of `flate2`, which this project already pinned deliberately (`rust_backend`/`miniz_oxide`, no `cc` dependency). Same "dependency, not hand-roll" argument as `flate2` itself: CRC over attacker-influenced/arbitrary captured bytes is exactly the class of thing this project already reserves for a dependency. |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `proptest` or a hand-written multi-thread stress harness | `proptest` 0.10+ (current, [VERIFIED: crates.io check this session, OK verdict]) | Differential/property testing of the old vs. new store implementations, and concurrent `put`/`add_exchange` stress testing for STORE-03 | See Validation Architecture. Not currently a workspace dependency (`grep` this session found no `proptest`/`quickcheck`/`criterion` anywhere in the workspace) — this is a genuinely new addition, size the phase for it. |
| `loom` | 0.7+ ([VERIFIED: crates.io check this session, OK verdict]) | Exhaustive interleaving check that the id-assignment race is *closed*, not merely *rare* | Optional, higher-assurance alternative/supplement to a plain concurrent stress test — see the cost caveat in Validation Architecture before committing to it for Phase 1. |

### Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|--------------------------|
| `crc32fast` (CRC32, already in the tree) | `blake3` or a cryptographic hash | Never for this use case — corruption detection needs to catch accidental bit-flips/torn writes cheaply per record on every capture, not resist a malicious adversary constructing a collision. A crypto hash is the wrong tool and a new, heavier dependency for no benefit. |
| A single shared `AuthorisedSender` type wrapping both `NetSender` and `repeater::send` | Two separate chokepoints (one blocking, one async) | Only if unifying the blocking/async transport split turns out to be more invasive than the phase can afford — document as a fallback, not the default, since two chokepoints reintroduces exactly the "which one did this fifth sender use" ambiguity HARD-03 exists to remove. |

**Installation:**
```bash
cd crates/core && cargo add memmap2 crc32fast
cd crates/core && cargo add --dev proptest   # or workspace-level if shared across crates/core and the chokepoint's own tests
```

**Version verification:** run at implementation time, not assumed from this document:
```bash
cargo add memmap2 --dry-run   # crates/core
cargo add crc32fast --dry-run # crates/core — will already be in Cargo.lock via flate2
```

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|--------------|---------|-------------|
| `memmap2` | crates.io | ~6 years (first published 2020-01-18) | ~5.0M/week | github.com/RazrFalcon/memmap2-rs | OK | Approved |
| `bytes` | crates.io | ~11 years (first published 2015-01-30) | ~15.8M/week | github.com/tokio-rs/bytes | OK | Approved (already a workspace dependency) |
| `crc32fast` | crates.io | ~7 years (first published 2018-11-13) | ~10.0M/week | github.com/srijs/rust-crc32fast | OK | Approved — already a transitive dependency via `flate2` |
| `proptest` | crates.io | ~9 years (first published 2017-06-18) | ~3.2M/week | github.com/proptest-rs/proptest | OK | Approved |
| `loom` | crates.io | ~7 years (first published 2018-12-07) | ~0.7M/week | github.com/tokio-rs/loom | OK | Approved, optional |

All five verdicts came from `gsd-tools query package-legitimacy check --ecosystem crates`, run this
session. **Ecosystem note for the planner:** the same check run with `--ecosystem npm` reports
`memmap2` and `crc32fast` as `SLOP` ("does-not-exist") — a direct, concrete illustration of the
cross-ecosystem confusion vector the verification protocol warns about. Always check Rust packages
against `crates`, never `npm`.

**Packages removed due to `[SLOP]` verdict:** none.
**Packages flagged as suspicious `[SUS]`:** none.

## Architecture Patterns

### System Architecture Diagram

```
                         ┌─────────────────────────────────────────────┐
                         │  crates/core — TrafficStore (unchanged API)  │
                         │                                               │
  put(raw, dir) ────────▶│  parse() — lock-free, pure fn of raw bytes   │
                         │       │                                       │
                         │       ▼                                       │
                         │  ONE write-lock critical section:            │
                         │   - assign id                                │
                         │   - append to active segment (buffered write)│
                         │   - write locations[id] = (segment, span)    │
                         │       │                                       │
                         │       ▼                                       │
                         │  active segment: buffered File + in-RAM mirror│
                         │  (served from RAM while unsealed)            │
                         │       │  size threshold reached at a message │
                         │       │  boundary (never mid-write)          │
                         │       ▼                                       │
                         │  seal: fsync → rename .tmp → mmap read-only  │
                         │        → Bytes::from_owner(mmap), once        │
                         │        → verify per-record CRC before trusting│
                         └───────────────┬───────────────────────────────┘
                                         │ get(id) → locations[id] → segment.slice()
                                         ▼
                    proxy · repeater · intruder · scanner · web (readers, unchanged)

  ─── separately: the chokepoint (HARD-03) ───

  scanner audit / repeater send / intruder attack / (future) crawler, plugins, MCP
                         │  constructed request bytes
                         ▼
              AuthorisedSender::send(target, raw)
                         │  scope.authorise_request(host, port, tls, raw) — mandatory, structural
                         ▼ (only path forward)
         private transport (NetSender blocking / repeater async) ──▶ socket
```

### Recommended Project Structure

```
crates/core/
├── src/lib.rs          # TrafficStore: add locations index + related slot; put()/set_response() fixed
├── src/segment.rs       # NEW — Segment enum (Active|Sealed), seal lifecycle, mmap wrapping, CRC
└── src/scope.rs         # unchanged — Scope::authorise_request stays the single decision function

crates/<sender-crate>/    # NEW, small — OR added to crates/core if the planner prefers fewer crates
├── src/lib.rs            # pub struct AuthorisedSender — the only public entry point
└── src/transport.rs      # private module: houses (or wraps) NetSender/repeater's socket code
```

### Pattern 1: Race-free segmented store with a self-describing record format (STORE-01/02/03)

**What:** Confirmed directly from `crates/core/src/lib.rs` this session — the current `put()`:

```rust
// crates/core/src/lib.rs:302-317 (current)
pub fn put(&self, raw: Bytes, direction: Direction) -> MsgId {
    let id = MsgId(self.next_msg.fetch_add(1, Ordering::Relaxed));   // (1) outside any lock
    let shape = parse(&raw, direction).unwrap_or(...);                // (2) variable duration, no lock
    self.inner.write().messages.push(StoredMessage { id, raw, shape }); // (3) separate lock
    id
}
```

Steps (1) and (3) are not one critical section; (2) sits between them with duration proportional to
message size. This is a real race (two concurrent proxy connections can push messages whose index
order and id order diverge), not just the O(n²) `get`/`set_response` linear scan PROJECT.md names.
The fix (already specified in prior research, confirmed correct by this session's read): do the
lock-free work (`parse`) first, then assign the id, append to the active segment, and write the
location inside **one** critical section:

```rust
pub fn put(&self, raw: Bytes, direction: Direction) -> MsgId {
    let shape = parse(&raw, direction).unwrap_or_else(|| default_shape(&raw, direction));
    let mut inner = self.inner.write();                 // one critical section
    let id = MsgId(inner.next_msg);
    inner.next_msg += 1;
    let loc = inner.active_segment_mut().append(&raw, id, direction); // buffered write, returns Location
    inner.locations_set(id, loc);
    id
}
```

Apply identically to `add_exchange`/`set_response`. `counts()` (`crates/core/src/lib.rs:362-366`,
currently `g.messages.iter().map(|m| m.raw.len()).sum()`) is a fourth linear scan not previously
named — it must become an incrementally-maintained counter (updated inside the same critical
section), not resolved by iterating every message on every call.

**Self-describing record format — an explicit decision, not an implication.** Because the location
index (`Vec<Location>`) lives in RAM, the store needs a stated answer to "what happens to the index
across a process restart, given segments are meant to be durable (STORE-01: bounded by disk, not
RAM)": each record on disk should carry its own length, id, and checksum in a small fixed header —

```rust
// One record inside a segment file, conceptually:
struct RecordHeader {
    len: u32,        // payload length in bytes
    msg_id: u64,      // the MsgId this record holds
    direction: u8,    // Request | Response
    crc32c: u32,      // crc32fast::hash(payload) — checksum of the payload only
}
// followed by `len` bytes of payload
```

This makes every segment **self-describing and sequentially scannable**: on startup, if segment
files exist from a prior run, the store rebuilds `locations`/`exchanges` by reading each sealed
segment's records in order, rather than requiring a separate index file that can drift out of sync
with the segments themselves. The in-memory `Vec<Location>` remains the fast path for every `get()`
during normal operation; the on-disk header is what makes recovery-by-rescanning possible and what
STORE-05's verification reads back against. State this decision explicitly in the plan — retrofitting
a header format onto already-written segments is exactly the kind of expensive-to-undo choice
`ARCHITECTURE.md` already flags for the `related` slot (Pattern 2 below), and this is the same class
of decision for the record layout itself.

**Segment lifecycle (never remapped):** write to `segment-NNNNNN.log.tmp` via ordinary buffered
`File::write` while active (never mapped); on seal, `fsync`, close, rename to `segment-NNNNNN.log`
(atomic on the same filesystem), verify every record's CRC in the sealed file, *then* `mmap` read-only
and wrap once in `Bytes::from_owner(mmap)`. A segment is always in exactly one of two states — never
written to *and* mapped at the same time — which is what prevents the dangling-pointer hazard named
in `STACK.md`/`ARCHITECTURE.md` (`remap()` moving a mapping while slices are outstanding). Not
re-litigated here; only the size/rotation policy below is new.

### Segment size and rotation policy (open question 1 — answered)

**Recommendation:** a **target, not a hard cap**, of **64 MiB per segment** [ASSUMED — reasoned
recommendation, not independently benchmarked against burpsy's traffic; treat as a tunable constant
+ config knob, not a hardcoded magic number]. Roll to a new segment once the target is reached **at
a completed-message boundary**, never mid-write. A single message whose own size already exceeds the
target does not get split, rejected, or crash the capture: it is written into its own segment, sized
to fit exactly that one record, sealed immediately after — the invariant that matters ("one message's
bytes never span two segments," required for `Bytes::from_owner(mmap).slice()` to work per segment)
is preserved regardless of whether a segment ends up at the 64 MiB target or larger to fit one big
download.

**Why 64 MiB, not Kafka's 1 GiB default** [MEDIUM confidence, corroborated across Strimzi/Redpanda/
Conduktor/2minutestreaming — cached this session]: Kafka's default is sized for a use case where
segment bytes are *not* held resident in the broker's own memory the way burpsy's **active, unsealed**
segment is — `ARCHITECTURE.md`'s Pattern 1 already specifies that the active segment is served from
an **in-memory mirror `Bytes`** while unsealed, so the target segment size directly bounds the RAM
cost of whatever is currently being captured, not just a rotation cadence. A 64 MiB active-segment
ceiling keeps that bound small and predictable at proxy/crawler capture rates (hundreds of bytes to
low-single-digit megabytes per exchange is the stated traffic profile), while a multi-GB capture
still only produces on the order of dozens to low hundreds of segment files — well inside any
reasonable open-file/mmap-count limit, and small enough that a crash loses at most one target-size
segment's worth of not-yet-sealed capture (bounding the blast radius of an unclean shutdown). Kafka's
1 GiB figure is the wrong anchor to import directly; use it only as an order-of-magnitude sanity
check that "tens of MiB" is a reasonable regime for a segmented log, not as the number itself.

**What happens to one oversized message** [MEDIUM confidence, corroborated across Confluent/
Conduktor/Red Hat docs on Kafka's `message.max.bytes` vs `log.segment.bytes`]: the append-only-log
precedent (Kafka) is to *refuse* an oversized record outright (`message.max.bytes` must stay below
`log.segment.bytes`) rather than let a segment grow past its nominal size. That answer is wrong for
burpsy specifically: refusing to capture a large response would silently violate the "capture
everything" premise this whole subsystem exists to serve, for no correctness benefit (mmap does not
actually require a fixed segment size — only "never remap a live mapping," which an occasionally
larger, still-immutable-once-sealed segment satisfies just as well as a target-size one). Recommend
diverging from Kafka here deliberately: **accept the oversized message into its own larger segment**,
never reject or truncate it, and document this divergence so it reads as a decision, not an oversight.

### Pattern 2: `related`/`ChildRef` slot (STORE-04) — a concrete shape, not a placeholder

**What:** `ARCHITECTURE.md` already established that a `related: Vec<Vec<ChildRef>>` slot indexed by
exchange id must exist now, even though nothing in this milestone's Phase 1 populates it, because
retrofitting a 1:N relation onto an already-shipped 1:1-only schema is the expensive mistake to avoid.
This research adds the concrete shape the planner should use, since leaving it abstract risks two
different phases (H2 in Phase 2, WS in Phase 9) each inventing an incompatible variant:

```rust
/// A child record hung off one parent exchange. Reserved now; only WS (Phase 9) and H2
/// (Phase 2) populate it, in that requirement order — H2 needs this slot sooner than WS, since
/// ROADMAP.md sequences HTTP/2 as Phase 2 and WebSockets as Phase 9 (this reverses the build-order
/// prior ARCHITECTURE.md research suggested, which sequenced WS before H2 for proxy-connection-model
/// reasons — ROADMAP.md's operator-locked phase order takes precedence; note this explicitly to the
/// planner rather than silently following the older research).
pub enum ChildRef {
    WsFrame(usize),   // index into a future ws_frames table
    H2Frame(usize),   // index into a future per-connection raw-frame-stream table
}

pub related: Vec<Vec<ChildRef>>  // indexed by exchange id; empty Vec for every exchange in Phase 1
```

**Why this matters for sequencing:** ROADMAP.md's actual phase order (Phase 2 = HTTP/2, Phase 9 =
WebSockets — an operator decision recorded in STATE.md's Key Decisions, overriding
`SUMMARY.md`'s/`ARCHITECTURE.md`'s suggested WS-before-H2 build order for a named reason: "an
h1-only ALPN offer silently downgrades every h2-capable target") means `ChildRef::H2Frame` is the
variant that gets populated *first*, chronologically, even though `ARCHITECTURE.md`'s Pattern 2
discussion was written assuming WS would land first. Define both variants now so Phase 2 does not
have to extend a shipped enum.

### Pattern 3: STORE-05's two distinct verification mechanisms

**Corrected framing (see Summary, finding 1): there is no pre-existing on-disk store to migrate.**
`TrafficStore` today is `Vec<StoredMessage>` in RAM; nothing under `crates/core` calls `File::create`,
`OpenOptions`, or `fs::write` (confirmed by grep this session). `PITFALLS.md`'s Pitfall 10 (torn
writes, stale mappings, SIGBUS) and `STACK.md`'s framing both write as though an "old append-only
store" already exists on disk — it does not. This changes what "byte-identical to what the previous
store held" (STORE-05's own wording) can mean in practice, and the plan needs **two** separate
mechanisms, because they catch two different failure classes:

**Mechanism A — differential/parity test (proves the refactor is behaviour-preserving).** Since both
the current `Vec`-based implementation and the new segment-based implementation exist as Rust types
in the same codebase during this phase, the strongest and most re-runnable form of "migration
verification" is a property/differential test that drives an **identical sequence of operations**
(`put`/`get`/`add_exchange`/`set_response`, including concurrent interleavings) against both
implementations in the same test binary and asserts every observable result (returned `MsgId`s,
resolved byte slices, exchange fields) is identical at every step. This is not a one-shot migration
tool an operator runs once against a static file — it is a test that runs in CI on every subsequent
change, which is strictly stronger than the literal "operator runs a migration check" framing in
Phase 1 success criterion 4, while still satisfying it (see Mechanism B for the operator-facing
piece).

**Mechanism B — per-record checksum, verified on an operator-triggered scan (proves storage integrity
in production, catches the failure modes PITFALLS.md's Pitfall 10 actually names).** The self-
describing record header (Pattern 1) carries a `crc32c` field written at append time. An operator
command — the literal "migration check" success criterion 4 asks for — walks every stored id,
resolves its bytes through the live store, recomputes the checksum, and compares against the header:

```rust
pub struct VerifyReport {
    pub checked: usize,
    pub mismatches: Vec<(MsgId, String)>,  // id + reason, never just a bool
}

pub fn verify_all(store: &TrafficStore) -> VerifyReport { /* iterate ids, compare, name every miss */ }
```

A mismatch here is a real corruption signal — a torn write, a stale mapping surviving past a
segment's supposed immutability, or (on Unix) the aftermath of a `SIGBUS`-adjacent event on a
truncated file — and success criterion 4's exact wording ("emits a per-record byte-equality verdict
naming any mismatching id") maps directly onto `VerifyReport.mismatches`. **Do not conflate Mechanism
A and B into one check** — a differential test proves "the new code is correct today"; the checksum
scan proves "nothing has silently corrupted since it was written," which only matters once real
segment files exist and only Mechanism B can catch corruption introduced by disk/OS failures rather
than by a logic bug in the port.

### Pattern 4: The authorising sender (HARD-03) — grounded in what already exists

**What already exists, read directly this session:**

- `crates/proxy/src/sender.rs::NetSender` — a blocking `std::net::TcpStream`/`rustls::StreamOwned`
  transport with its own keep-alive connection pool, implementing `burpsy_bcheck::eval::Sender`.
  **Has no scope awareness of its own** — it is deliberately transport-only.
- `crates/scanner/src/lib.rs::Metered<'a>` (private `struct`, not `pub`) — wraps `&dyn Sender`
  (in practice, a `NetSender`) plus `&Scope`; its `Sender::send` impl calls
  `scope.authorise_request(host, port, tls, raw)` **first**, and only delegates to the inner sender
  on success. This is the *correct* pattern, already built, already tested (`crates/scanner/src/lib.rs`'s
  own test suite exercises it) — but it is crate-private, so nothing outside `scanner` can reuse it.
- `crates/repeater/src/lib.rs::send()` — a free async function (`tokio::net::TcpStream`/
  `tokio_rustls::TlsConnector`) with **zero scope awareness**. Every call site is individually
  responsible: `crates/web/src/lib.rs::repeater_send` (line ~313) calls
  `s.scope.authorise_request(...)` manually, immediately before calling `send()`; the intruder attack
  handler (`crates/web/src/lib.rs`, ~line 658) builds a `Guard` closure around
  `scope.authorise_request` and attaches it via `Attack::with_guard`, and `crates/intruder/src/engine.rs`
  documents (in its own doc comment, line ~78) that "the engine has no concept of engagement scope and
  should not grow one" — a deliberate, reasonable design for the *intruder crate itself*, but it means
  the `Guard` is `Option<Guard>` (optional!) and a caller that forgets `.with_guard(...)` compiles fine
  and sends unauthorised traffic.

**This means Criterion 5's phrase "the existing proxy and scanner senders" names an incomplete set.**
`repeater::send()` is a second, already-existing, already-in-production transport with no structural
scope enforcement, reachable from two production call sites that currently rely entirely on
programmer discipline — exactly Pitfall 4's failure mode, already realised, not hypothetical. **The
recommendation is to migrate `repeater`'s transport into the chokepoint in Phase 1 too**, not to
treat "proxy and scanner" as an exhaustive scope boundary. The proxy's own upstream-forwarding
`TcpStream::connect` calls (`crates/proxy/src/lib.rs`, for MITM interception of live browsing traffic)
are correctly **outside** this chokepoint — they relay the client's own bytes for ordinary browsing,
which is not "a constructed request" in the sense Criterion 5 means, and Scope there gates
interception/pausing behaviour, not socket access (confirmed by reading `crates/proxy/src/lib.rs`:
`cfg.scope.contains(...)` only gates whether a request is paused for operator review, never whether
it is forwarded). State this distinction explicitly in the plan so it reads as a considered boundary,
not an omission.

**Recommended shape:**

```rust
/// The only public constructor. `scope` is bound at construction, never swapped out, never
/// bypassed — there is no other public path to the private transport field.
pub struct AuthorisedSender {
    scope: Arc<Scope>,
    transport: Transport,      // private field — wraps NetSender and/or repeater's async transport
    sent: AtomicU32,           // NOT std::cell::Cell — must be Sync if this is ever shared via Arc
    refused: AtomicU32,
}

impl AuthorisedSender {
    pub fn new(scope: Arc<Scope>, transport: Transport) -> Self { /* ... */ }

    pub fn send(&self, target: &Target, raw: &[u8]) -> Result<Vec<u8>, String> {
        self.scope.authorise_request(&target.host, target.port, target.tls, raw)
            .inspect_err(|_| { self.refused.fetch_add(1, Ordering::Relaxed); })?;
        self.sent.fetch_add(1, Ordering::Relaxed);
        self.transport.send(target, raw)
    }
}
```

**Note the `Cell<u32>` → `AtomicU32` correction against the existing `Metered` pattern:**
`crates/scanner/src/lib.rs`'s current `Metered` uses `std::cell::Cell<u32>` for its `sent`/`refused`
counters (`crates/scanner/src/lib.rs:590-611`), which is fine only because `Metered` is constructed
fresh per audit item and never shared across threads. A chokepoint type meant to be held behind one
shared `Arc` across concurrent scanner/repeater/intruder/future-crawler callers **must** use
`AtomicU32` (or an equivalent `Sync` counter) instead — `Cell` is not `Sync` and will not compile
under concurrent sharing. This is an easy detail to carry over unchanged from `Metered` and have it
break late; flag it explicitly in the plan.

**Making "no alternate egress path" a checkable property — with an honest bound stated:**

1. **Privatise the transport, don't seal the trait.** `bcheck::eval::Sender` is deliberately
   implemented by test doubles (`scanner`'s own `SlowSender`/`RecordingSender`/`FailingSender`,
   `bcheck::eval`'s own `TargetSpy`/`MockSender` — all confirmed by grep this session) precisely so
   tests can prove traffic did or did not reach a socket. **Do not seal `Sender`** — sealing it would
   break every one of those test doubles and remove the exact mechanism that makes this feature
   testable. The property to enforce is "nobody can construct something that reaches a *real* socket
   except through `AuthorisedSender`," which is a newtype-with-private-field property (the pattern
   confirmed this session: a private inner field plus a single controlled constructor prevents
   callers from extracting or reconstructing the wrapped value any other way [MEDIUM confidence,
   corroborated across the Rust API Guidelines' future-proofing page and multiple independent
   newtype-pattern write-ups]), not a sealed-trait property.
2. **Narrow `tokio`'s feature set per crate, not workspace-wide.** Confirmed this session:
   `crates/intruder/Cargo.toml` depends on `tokio = { workspace = true }`, and the workspace declares
   `features = ["full"]` — so `tokio::net::TcpStream::connect` compiles inside `intruder` *today*
   (its own test at `crates/intruder/src/engine.rs:809`, `tcp_sender`, proves it). Change
   non-transport crates (`intruder`, `bcheck`, `scanner`) to depend on a narrowed feature set in
   `[dependencies]` — e.g. `tokio = { version = "1", features = ["sync", "time", "macros", "rt"] }`,
   with `net` restored under `[dev-dependencies]` only, so existing test helpers (`tcp_sender`,
   `probe_server`) still compile. After this change, `tokio::net` genuinely does not exist in those
   crates' production namespace, and a socket-opening line there is a compile error, not a review
   miss. Only `crates/proxy`, `crates/repeater` (or wherever the transport ends up living after this
   migration), and the new chokepoint crate keep full `tokio` net features.
3. **State the honest bound: `std::net::TcpStream` is reachable from any crate regardless of feature
   flags**, since it's part of the standard library, not gated by a Cargo feature. Feature-narrowing
   closes the `tokio`-based async path; it does not and cannot close `std::net` by itself. The
   remaining backstop is a source-scanning test (a `#[test]` that greps `crates/*/src` for
   `TcpStream::connect`/`TlsConnector::connect`/`ClientConnection::new` outside the chokepoint crate's
   own module and fails the build if a new hit appears) — this is a real, CI-enforced, immediately-
   drift-detecting check, but it is a backstop for the residual `std::net` surface, not the primary
   mechanism. **State this bound explicitly in the plan rather than claiming "compile error, not
   convention" without qualification** — overclaiming exactly what was fixed is the kind of honesty
   failure this project's own Constraints section elsewhere rejects (PITFALLS.md's "looks done but
   isn't" pattern), and a reviewer who later finds a `std::net::TcpStream::connect` in a fourth crate
   should read that as "the backstop test should have caught this — check why it didn't," not as "the
   compile-time guarantee was broken."
4. **Migrate `repeater::send()`'s body into the chokepoint's private transport module** and reduce
   `repeater`'s own public surface so it no longer exports a bare `send()` that opens a socket
   unconditionally — `web::repeater_send` and the intruder attack handler should construct/use an
   `AuthorisedSender` instead of calling `repeater::send` (or building a raw `SendFn`/`Guard`) by
   hand. This is the concrete step that turns "the existing proxy and scanner senders" into "every
   existing sender," satisfying Criterion 5 as literally stated.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| Safe mmap of a sealed segment file | A hand-rolled `unsafe` wrapper over raw `mmap`/`MapViewOfFile` | `memmap2` | Getting raw mmap safety wrong is a memory-safety bug; already the project's own stated bar for taking a dependency (mirrors the `flate2` decision). |
| Refcounted zero-copy slices over a mapped region | A custom `Arc<Mmap>` + manual slice-bounds wrapper | `bytes::Bytes::from_owner(mmap)` | Already does the refcount-and-drop-on-last-clone bookkeeping; `Mmap` already satisfies `AsRef<[u8]> + Send + 'static`, no `Arc` wrapper needed. |
| Per-record corruption detection | A hand-rolled checksum or "trust the OS" | `crc32fast::hash`/`Hasher` | Already in the dependency tree via `flate2`; CRC32 over arbitrary/attacker-influenced captured bytes is the same "dependency, not hand-roll" argument as `flate2` itself. |
| Proving the id-assignment race is closed, not just rare | A single ad hoc multi-thread stress test that happens to pass | `proptest`/`loom`-based concurrent test (see Validation Architecture) | A stress test that passes ten times can still hide a narrow interleaving; the whole point of STORE-03 is "closed, not narrowed" — a test that can only demonstrate absence-of-failure-so-far does not prove that. |
| A second, independent "is this in scope" check inside a new transport type | Any new sender re-implementing its own call to `Scope::authorise_request` | `AuthorisedSender` (Pattern 4) | This is the exact anti-pattern Pitfall 4 names — a fifth sender that is *individually* wired correctly is still a fifth place the wiring can be gotten wrong; one shared type is the fix. |

**Key insight:** every "don't hand-roll" item above already has a proof-of-concept living in this
exact codebase — `memmap2`/`Bytes::from_owner` are already specified by prior research and confirmed
against the actual resolved dependency versions this session; `crc32fast` is already silently present
via `flate2`; the "wrap a sender, check scope first" pattern is already built and tested as `Metered`.
The work in Phase 1 is disciplined generalisation of things that already exist and already work, not
invention from nothing.

## Runtime State Inventory

> Included because this phase is explicitly framed as a migration (STORE-05: "verify a migrated
> capture is byte-identical to what the previous store held").

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | **None.** `TrafficStore` is `Vec<StoredMessage>`/`Vec<Exchange>` held entirely in process RAM — confirmed by reading `crates/core/src/lib.rs` and by grepping `crates/core/src/*.rs` and `crates/cli/src/main.rs` for `File::create`, `OpenOptions`, `fs::write`, `.json"`, `.db"`, `.log"` (no hits outside an unrelated doc-comment in `sitemap.rs`). There is no existing on-disk capture file in any format to migrate. | None — see Pattern 3 for what "migration verification" means instead. |
| Live service config | None applicable — this project has no external services whose configuration lives outside git (confirmed by `ARCHITECTURE.md`'s own "Integration Points / External Services: None" finding, re-affirmed here). | None. |
| OS-registered state | None — `burpsy` runs as an operator-invoked CLI process (`crates/cli/src/main.rs`), with no OS task-scheduler, `pm2`, or `launchd` registration found anywhere in the repo. | None. |
| Secrets/env vars | None specific to the store migration — `Scope`/config are constructed in-process (`crates/cli/src/main.rs`); no secret or env-var name references the store's internal representation. | None. |
| Build artifacts | None stale as a result of this migration — no compiled artifact or installed package embeds the current `Vec`-based store's shape; a `cargo build` after the change picks up the new internals transparently through the unchanged public API. | None — reinstall/rebuild is the ordinary `cargo build`, nothing special. |

**Nothing found in any category** — this migration has no legacy on-disk data, no external service
state, no OS registration, no secret references, and no stale build artifact to reconcile. This is
itself the load-bearing finding for STORE-05 (see Pattern 3): "migrated capture" cannot mean
"convert pre-existing files," because none exist; it means "the new in-process representation must
be provably equivalent to the old one, and provably intact going forward."

## Common Pitfalls

> `PITFALLS.md` already catalogues Pitfall 4 (scope re-derivation across new senders) and Pitfall 10
> (mmap migration corruption/unverifiable) in general terms. The items below are Phase-1-specific
> sharpenings grounded in this session's direct source reads, not restatements.

### Pitfall: `Cell<u32>` counters break the moment the chokepoint is shared

**What goes wrong:** `Metered`'s existing `Cell<u32>` counters (`crates/scanner/src/lib.rs:590-611`)
compile today only because `Metered` is constructed fresh, single-threaded, per audit item. Copying
that pattern verbatim into a shared `AuthorisedSender` behind an `Arc` fails to compile the moment
two callers hold the same instance — `Cell` is not `Sync`.
**How to avoid:** use `AtomicU32` (or an equivalent `Sync` counter type) from the start in the shared
type, even though the existing `Metered` code this is modelled on uses `Cell`.
**Warning signs:** a compile error mentioning `Sync` the first time a test tries to share an
`AuthorisedSender` across `tokio::spawn` boundaries.

### Pitfall: treating "proxy and scanner" as the literal, exhaustive scope of Criterion 5

**What goes wrong:** reading ROADMAP.md's Criterion 5 wording ("the existing proxy and scanner
senders") as a closed list, migrating only `NetSender`/`Metered`, and leaving `repeater::send()`
untouched — which means the phase's own acceptance test ("a test proves no alternate egress path
exists") cannot actually pass, because `repeater::send()` is a real, already-existing, already-in-
production alternate egress path today.
**How to avoid:** migrate `repeater`'s transport into the chokepoint in Phase 1, and treat "proxy and
scanner" as an illustrative minimum the roadmap author had directly in mind, not an exhaustive
boundary — cross-check against source (as this document did) rather than the roadmap prose alone.
**Warning signs:** the "no alternate egress" test passes only because it was scoped to skip
`crates/repeater`.

### Pitfall: claiming the compile-time guarantee closes more than it does

**What goes wrong:** after narrowing `tokio`'s feature set per crate, describing the result as "no
crate other than the chokepoint can open a socket" without qualification — which is false for
`std::net`, always reachable from any crate regardless of Cargo features.
**How to avoid:** state the bound honestly in the plan and in any test/doc comment: the feature
narrowing closes the `tokio`-async path structurally; the residual `std::net` surface is covered by
a source-scanning backstop test, not by the type system.
**Warning signs:** a plan or doc comment that says "compile error" with no accompanying note about
`std::net`'s reachability.

### Pitfall: conflating differential parity with storage-integrity checksums

**What goes wrong:** building only one verification mechanism for STORE-05 — e.g., a checksum scan
alone (which cannot prove the *refactor* preserved behaviour, only that bytes-on-disk match a header
written by the same new code) or a differential test alone (which cannot catch corruption introduced
after the fact by disk/OS failure, since it runs once against fresh, uncorrupted data).
**How to avoid:** build both Mechanism A (differential/parity test, re-runnable in CI) and Mechanism
B (per-record checksum scan, operator-triggerable) as described in Pattern 3, and be explicit about
which failure class each one catches.
**Warning signs:** a plan with exactly one "verify the store" task instead of two with distinct
names and distinct failure-mode coverage.

## Code Examples

### Reusing the already-confirmed `Bytes::from_owner` signature

```rust
// Source: local vendored crates.io source, bytes-1.12.1/src/bytes.rs:242 (read this session)
pub fn from_owner<T>(owner: T) -> Self
where
    T: AsRef<[u8]> + Send + 'static
```

### `crc32fast` usage (already resolved in `Cargo.lock` via `flate2`, confirmed this session)

```rust
// Source: local vendored crates.io source, crc32fast-1.5.0/src/lib.rs (read this session)
let checksum = crc32fast::hash(record_payload_bytes);
// or, for a streaming/incremental checksum across a large body:
let mut hasher = crc32fast::Hasher::new();
hasher.update(record_payload_bytes);
let checksum = hasher.finalize();
```

### The pattern already correct in this codebase — `Metered` (model for `AuthorisedSender`)

```rust
// Source: crates/scanner/src/lib.rs:613-632 (read this session) — the shape to promote and share,
// not the shape to copy verbatim (note the Cell<u32> → AtomicU32 correction above)
impl burpsy_bcheck::eval::Sender for Metered<'_> {
    fn send(&self, target: &burpsy_bcheck::eval::Target, raw: &[u8]) -> Result<Vec<u8>, String> {
        if let Err(why) = self.scope.authorise_request(&target.host, target.port, target.tls, raw) {
            self.refused.set(self.refused.get().saturating_add(1));
            return Err(why);
        }
        self.sent.set(self.sent.get().saturating_add(1));
        self.inner.send(target, raw)
    }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-------------------|---------------|--------|
| `Vec<StoredMessage>` linear scan for `get`/`set_response`/`exchange`/`counts` | O(1) `Vec<Location>` index, id assigned inside the same critical section as the append | This phase | Closes both the O(n²) cost PROJECT.md names and the id-assignment race Pattern 1 identifies (a distinct, previously-undocumented bug) |
| No persistence at all (pure in-RAM store) | Segmented, sealed, mmap-backed, self-describing (length+id+CRC per record) durable log | This phase | First time captured traffic survives a process restart; also the first time "migration verification" has any on-disk artifact to check |
| Per-crate ad hoc scope enforcement (`Metered` in scanner, manual calls in `web`, an optional `Guard` in intruder) | One shared `AuthorisedSender`, the only public path to a real socket for constructed/attack requests | This phase | Removes three independently-maintained call sites that could each individually drift; makes "did this new surface remember to check scope" a question the type system, not a reviewer, answers for constructed requests |

**Deprecated/outdated:** `repeater::send()` and `scanner::Metered` as independently-callable public
transports are superseded by `AuthorisedSender` — they should end up as private implementation detail
behind it, not parallel public APIs.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | 64 MiB target segment size | Segment size and rotation policy | Wrong in either direction is a tuning problem, not a correctness one (segments are still sealed-then-mapped, never remapped, regardless of the number) — low risk, cheap to change since it's a `const`/config knob, not baked into the on-disk format itself. |
| A2 | Two separate transport implementations (blocking `NetSender`, async `repeater::send`) should be unified under one `AuthorisedSender` rather than kept as two chokepoints | Pattern 4 | If unification proves more invasive than the phase can afford, falling back to two chokepoints is a real regression against "one authorising sender type" (Criterion 5) — flag this explicitly to the planner as a scope-vs-schedule tradeoff, not a silent descope. |
| A3 | `proptest` (rather than a hand-written randomized harness) is the right tool for the differential/concurrent tests | Validation Architecture, Don't Hand-Roll | Low risk — `proptest` is well-established and already legitimacy-checked; the only cost is a new dev-dependency, and a hand-written harness remains a fallback if `proptest`'s async/concurrency ergonomics prove awkward. |

## Open Questions

1. **Should the segment/record header format be versioned from day one (a format-version byte),
   given it is the one thing PITFALLS.md-style research already flags as expensive to retrofit?**
   - What we know: the `related`/`ChildRef` slot precedent (Pattern 2) shows this project already
     treats "cheap now, expensive later" schema decisions seriously.
   - What's unclear: whether a version byte is worth the complexity for a single-operator tool that
     is not expected to run mixed old/new binary versions against the same capture directory.
   - Recommendation: include a one-byte format version in the segment file header (not the per-record
     header) as cheap insurance; do not over-engineer a full migration-between-format-versions story
     for Phase 1.

2. **Does unifying `NetSender` (blocking) and `repeater::send` (async) under one `AuthorisedSender`
   require making the chokepoint itself async, with the scanner's blocking evaluator crossing an
   async boundary — and is that an acceptable cost given `crates/proxy/src/sender.rs`'s own doc
   comment explains *why* the evaluator is deliberately synchronous?**
   - What we know: `NetSender`'s doc comment (read this session) states the BCheck evaluator is
     synchronous/recursive by design, and making it async would force `Box::pin` through `exec`/
     `eval_bool` for no benefit.
   - What's unclear: whether the chokepoint can present a synchronous `send()` facade to the scanner
     while internally using an async transport for repeater/intruder callers, without forcing a
     blocking-runtime bridge that undoes the reasoning in that doc comment.
   - Recommendation: keep two transport *implementations* behind one `AuthorisedSender` facade type
     (a blocking path for the scanner's synchronous evaluator, an async path for repeater/intruder),
     rather than collapsing to one implementation — the "one authorising sender **type**" requirement
     is about the scope-check-and-egress-point being singular, not about there being exactly one
     wire-level implementation underneath it.

## Environment Availability

No external services or runtime dependencies beyond the existing Rust toolchain are introduced by
this phase. `rustc 1.92.0` / `cargo 1.92.0` are present in this environment (checked this session)
and comfortably exceed `memmap2`'s MSRV (1.65, per prior `STACK.md` research). No database, cache, or
network service dependency is introduced — everything in this phase is local-process file I/O and
in-memory data structures.

**Missing dependencies with no fallback:** none.
**Missing dependencies with fallback:** none.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `cargo test` (standard library `#[test]`/`#[tokio::test]`) — confirmed as the only test tooling in the workspace this session; no `proptest`/`quickcheck`/`criterion`/config file found anywhere in `Cargo.toml`s |
| Config file | none — plain `cargo test` per crate, consistent with every existing crate in the workspace |
| Quick run command | `cargo test -p burpsy-core` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|--------------|
| STORE-01 | Segments seal at a message boundary, never remap, capture bounded by disk | unit + integration | `cargo test -p burpsy-core segment` | ❌ Wave 0 — `crates/core/src/segment.rs` and its tests are new |
| STORE-02 | `get`/`set_response`/`exchange`/`counts` are O(1), not linear-scan | unit (can assert call-count/instrumentation, or structurally by construction) | `cargo test -p burpsy-core` | ❌ Wave 0 — extend existing `crates/core/src/lib.rs` test module |
| STORE-03 | id assignment and index population never observed out of order under concurrent `put`/`add_exchange` | concurrent stress test (`tokio::test(flavor = "multi_thread")` or `std::thread` fan-out), optionally `proptest`/`loom` for exhaustive interleaving | `cargo test -p burpsy-core concurrent` | ❌ Wave 0 — new test, this is the one place a plain stress test alone is weaker evidence than the requirement's own wording ("closed, not narrowed") implies; recommend at minimum a high-iteration multi-thread stress test, `loom` as a stretch goal given its integration cost (requires swapping `parking_lot::RwLock` for a `loom`-compatible abstraction under `cfg(loom)`, non-trivial — size this as optional, not mandatory, for Phase 1) |
| STORE-04 | `related`/`ChildRef` slot exists, empty by default, addressable per exchange id | unit | `cargo test -p burpsy-core related` | ❌ Wave 0 |
| STORE-05 | Mechanism A (differential parity) + Mechanism B (checksum scan naming mismatches) | property/differential test (`proptest`) + unit (checksum scan) | `cargo test -p burpsy-core verify` | ❌ Wave 0 — both mechanisms are new; `proptest` itself is a new dev-dependency |
| HARD-03 | `AuthorisedSender` is the only path to a socket for every current constructed-request sender; source-scan backstop test catches new `std::net`/`tokio::net` call sites outside it | unit (chokepoint logic) + a workspace-level source-scan test | `cargo test -p <sender-crate>` plus a dedicated `cargo test --workspace no_alternate_egress` | ❌ Wave 0 — the source-scan test in particular has no existing precedent in this workspace to extend |

### Sampling Rate

- **Per task commit:** `cargo test -p burpsy-core` (and `-p <sender-crate>` for HARD-03 tasks)
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** full workspace suite green, plus the source-scan "no alternate egress" test passing,
  before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `crates/core/src/segment.rs` — new module, no existing file to extend
- [ ] `crates/core` test module additions for the race-free index, `related` slot, and both STORE-05
      verification mechanisms
- [ ] New chokepoint crate (or `crates/core` addition) plus its own test module for
      `AuthorisedSender`
- [ ] A workspace-level source-scan test with no existing precedent — decide where it lives (a new
      `xtask`-style crate, or a `#[test]` inside the chokepoint crate that walks `../../` relative
      paths — the latter is simpler and consistent with this workspace having no existing `xtask`)
- [ ] `proptest` added as a dev-dependency where the differential/concurrent tests live
- [ ] Cargo.toml feature-narrowing for `intruder`/`bcheck`/`scanner` (`tokio` features restricted in
      `[dependencies]`, restored under `[dev-dependencies]`) — a config change, not a test file, but
      belongs in the same wave as the source-scan test since it's the structural half of the same
      guarantee

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|--------------------|
| V2 Authentication | No | This phase has no authentication surface — `Scope` is engagement-authorisation, not user auth |
| V3 Session Management | No | Not applicable to this phase |
| V4 Access Control | Yes | `Scope::authorise_request` is the access-control decision for outbound traffic; HARD-03's whole point is making this decision structurally unbypassable rather than convention-based — this **is** the ASVS V4 control for this phase |
| V5 Input Validation | Yes | `request_path`/`parse()` already treat unparseable bytes as "refuse," never "nothing to check" (confirmed in `crates/core/src/scope.rs`'s own test suite, read this session: `a_request_with_no_readable_start_line_is_refused_not_waved_through`) — Phase 1 must preserve this refuse-by-default posture in every new sender path, and the segment/record header parser must apply the same discipline (a malformed record header is a refuse/report-corruption case, never a silent skip) |
| V6 Cryptography | Yes (narrowly) | `crc32fast` is explicitly **not** a cryptographic control — it is a corruption-detection checksum, not an integrity guarantee against a malicious actor; do not present it as one in any operator-facing text. No new cryptographic primitive is introduced by this phase. |

### Known Threat Patterns for This Phase's Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|------------------------|
| A new sender bypasses `Scope::authorise_request` by constructing its own socket | Tampering / Elevation of Privilege | `AuthorisedSender`'s private-field newtype + narrowed `tokio` features + source-scan backstop (Pattern 4) |
| A malformed/adversarial record header (length lies about payload size) causes an out-of-bounds read when resolving a `Span` | Tampering / Denial of Service | Bounds-check every resolved span against the segment's actual mapped length before slicing (mirrors `StoredMessage::slice`'s existing `if s.end() > self.raw.len() { return Bytes::new(); }` guard, confirmed in `crates/core/src/lib.rs:98-103` — apply the same discipline to segment-backed spans) |
| A segment file truncated externally (by another process, a bug, or disk failure) causes `SIGBUS` when mapped and accessed past the new EOF | Denial of Service | Exclusive ownership of segment files (only this process creates/renames/deletes them) — already specified in prior `STACK.md` research, not re-litigated; the CRC scan (Mechanism B) is the detection half, exclusive ownership is the prevention half |
| An `AuthorisedSender` shared via `Arc` across threads without `Sync`-safe counters causes a compile failure late, or (if a non-atomic type were used unsafely) a lost/racing counter | Tampering (data integrity of the sent/refused audit counters) | `AtomicU32`, not `Cell<u32>` — see Pattern 4's explicit correction |

## Sources

### Primary (HIGH confidence — direct source reads this session)

- `crates/core/src/lib.rs` — `TrafficStore::put`/`get`/`add_exchange`/`set_response`/`counts` full
  source; confirms the id-assignment race and the fourth (`counts`) linear scan not previously named
- `crates/core/src/scope.rs` — `Scope::authorise_request`/`request_path`/`may_contain_host` full
  source and test suite
- `crates/proxy/src/sender.rs` — `NetSender` full source; confirms it implements `Sender` with no
  scope awareness of its own
- `crates/scanner/src/lib.rs` — `Metered`, `PassiveScanner::audit_item`, `plan`, `AuditOutcome` full
  source; confirms `Metered` is crate-private and uses `Cell<u32>`
- `crates/repeater/src/lib.rs` — `send()` full source; confirms it is a second, scope-unaware
  transport with a caller-side-only scope check
- `crates/intruder/src/engine.rs` — `SendFn`/`Guard`/`Attack` full source; confirms the guard is
  optional and the engine is deliberately scope-agnostic; confirms `tokio::net::TcpStream` compiles
  in this crate today via its own test
- `crates/web/src/lib.rs` — `repeater_send`, the intruder attack handler's `sender`/`guard`
  construction; confirms both call sites individually wire scope checks around otherwise-unaware
  transports
- `Cargo.lock`, `crates/*/Cargo.toml` — confirmed resolved versions (`bytes` 1.12.1, `crc32fast`
  1.5.0 via `flate2`), confirmed per-crate dependency edges (`intruder`'s unnarrowed `tokio = "full"`,
  `repeater`'s direct `tokio-rustls` dependency, `scanner`/`bcheck` having no net dependency at all)
- Local vendored crates.io source (`~/.cargo/registry/src/.../bytes-1.12.1/src/bytes.rs`,
  `.../crc32fast-1.5.0/src/lib.rs`) — confirmed `Bytes::from_owner` signature and `crc32fast`'s API
  directly from the exact versions this workspace resolves to
- `gsd-tools query package-legitimacy check --ecosystem crates` (this session) — verdicts for
  `memmap2`, `bytes`, `crc32fast`, `proptest`, `loom`; also demonstrated the `npm`-ecosystem
  cross-confusion false-`SLOP` result as a concrete illustration for the planner

### Secondary (MEDIUM confidence — web search, corroborated across ≥2 independent sources this session)

- Kafka segment size/rotation defaults and rationale: [Strimzi blog](https://strimzi.io/blog/2021/12/17/kafka-segment-retention/), [Redpanda guide](https://www.redpanda.com/guides/kafka-performance-kafka-logs), [Conduktor](https://conduktor.io/blog/understanding-kafka-s-internal-storage-and-log-retention), [2minutestreaming](https://blog.2minutestreaming.com/p/kafka-log-segment-files-explained)
- Oversized-record-vs-segment-size handling: [Confluent](https://www.confluent.io/learn/kafka-message-size-limit/), [Conduktor](https://www.conduktor.io/kafka/how-to-send-large-messages-in-apache-kafka), [Red Hat Streams for Apache Kafka docs](https://docs.redhat.com/en/documentation/red_hat_streams_for_apache_kafka/2.9/html/kafka_configuration_tuning/con-config-large-messages-str)
- Append-only log CRC/torn-write detection practice: [Building an Append-only Log From Scratch](https://eileen-code4fun.medium.com/building-an-append-only-log-from-scratch-e8712b49c924), [Building a Corruption-Proof WAL in Go](https://unisondb.io/blog/building-corruption-proof-write-ahead-log-in-go/), USPTO torn-write-detection technical literature
- Rust sealed-trait pattern (consulted, then deliberately **not** applied to `Sender` per this
  session's advisor-flagged correction): [A definitive guide to sealed traits in Rust](https://predr.ag/blog/definitive-guide-to-sealed-traits-in-rust/), [Rust API Guidelines — future-proofing](https://rust-lang.github.io/api-guidelines/future-proofing.html)
- Rust newtype-with-private-field pattern (applied instead, to the transport, not the trait):
  [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/future-proofing.html), [Newtype — Rust Design Patterns](https://rust-unofficial.github.io/patterns/patterns/behavioural/newtype.html)

### Tertiary (LOW confidence — not relied on for any Phase 1 recommendation above)

- None carried forward — every web-sourced claim above was corroborated across ≥2 independent
  sources before being used.

### Prior project research (build on, not re-decided)

- `.planning/research/STACK.md`, `.planning/research/ARCHITECTURE.md`, `.planning/research/PITFALLS.md`
  — memmap2/`Bytes::from_owner` stack decision, segment-pattern architecture, and the general shape of
  Pitfall 4/10, all treated as settled per this task's instructions; this document's job was the three
  questions those left open, plus corrections surfaced by direct source reading this session.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every version claim verified directly against `Cargo.lock`, local vendored
  source, or a live `cargo add --dry-run`/package-legitimacy check this session
- Architecture (segment lifecycle, index race fix): HIGH — grounded in direct reads of
  `crates/core/src/lib.rs` this session, consistent with and extending prior research
- Architecture (chokepoint/HARD-03): HIGH on what exists today (direct source reads across
  `proxy`/`scanner`/`repeater`/`intruder`/`web`); MEDIUM on the exact enforcement mechanism's Rust
  idiom (corroborated web research, not yet implemented/compiled in this codebase)
- Segment size number (64 MiB): LOW-MEDIUM — reasoned from Kafka precedent plus this codebase's own
  active-segment-in-RAM design constraint, not independently benchmarked against real burpsy traffic;
  explicitly flagged `[ASSUMED]` and recommended as a tunable constant, not a fixed decision
- Pitfalls: HIGH for the ones grounded in this session's source reads (`Cell` vs `Atomic`,
  `repeater::send`'s missing scope awareness); MEDIUM for the general mmap-corruption pitfalls
  inherited from prior `PITFALLS.md` research

**Research date:** 2026-07-27
**Valid until:** 30 days (stable domain — Rust storage/mmap patterns and this codebase's own
structure do not move quickly; re-verify package versions if this phase's execution slips past that
window)
