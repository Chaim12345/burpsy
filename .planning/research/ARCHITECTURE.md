# Architecture Research

**Domain:** Rust web-security testing platform — integration architecture for the remaining
(Platform + Agent-surface + deferred) milestone features onto the existing 9-crate workspace
**Researched:** 2026-07-27
**Confidence:** MEDIUM-HIGH on the store/segment design and the H2 verdict (grounded directly in
this codebase's own source plus corroborated external prior art — Kafka segments, mitmproxy/Caido
plugin boundaries); MEDIUM on plugin-boundary specifics and WebSocket/crawler integration (design
extrapolated from this codebase's existing patterns, not yet built); LOW-MEDIUM on any specific
segment-size or lock-sharding numbers (flagged as Gaps, not blocking).

This document does not re-describe the current system — see `.planning/codebase/ARCHITECTURE.md`
for that. It does not re-litigate dependency choices — see `.planning/research/STACK.md`. It answers
one question: **how do the remaining features integrate, and in what order**, given the single
invariant everything here is judged against: a message is stored once as immutable bytes plus span
offsets, and nothing downstream ever clones a body.

## Standard Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  crates/cli  — composition root (unchanged role, more wiring)                    │
│  builds TrafficStore (segmented), Scope, TlsPolicy, PassiveScanner, PluginHost,  │
│  crawler on_exchange hook; spawns proxy + web + (new) crawler tasks              │
└───────┬──────────────────────┬───────────────────────┬──────────────┬───────────┘
        │                      │                       │              │
        ▼                      ▼                       ▼              ▼
┌───────────────┐   ┌───────────────────┐   ┌───────────────────┐  ┌──────────────┐
│ burpsy-proxy   │   │ burpsy-crawler     │   │ burpsy-plugins    │  │ burpsy-web    │
│ (+ h2 demux,   │   │ (NEW) frontier,    │   │ (NEW) extism host │  │ (+dashboard,  │
│  WS upgrade)   │   │ link/form extract, │   │ + JSON-RPC child  │  │  reporting,   │
│                │   │ reuses NetSender   │   │ process host      │  │  MCP mount)   │
└───────┬────────┘   └─────────┬──────────┘   └─────────┬─────────┘  └──────┬───────┘
        │                      │                          │                  │
        └──────────┬───────────┴──────────┬───────────────┴──────────────────┘
                    ▼                      ▼
        ┌───────────────────────────────────────────────────┐
        │  burpsy-core  (the one thing everything depends on) │
        │  ┌─────────────────────────────────────────────┐   │
        │  │ TrafficStore — segmented, mmap-backed         │  │
        │  │  segments: Vec<Segment>  (Active | Sealed)    │  │
        │  │  locations: Vec<Location>  (id → segment+span)│ │
        │  │  exchanges: Vec<Exchange> (id → row, direct)  │  │
        │  │  related:   Vec<Vec<ChildRef>> (1:N sidecar)  │  │
        │  │  ws_frames: Vec<WsFrame> (lightweight, no     │  │
        │  │             MessageShape)                     │  │
        │  └─────────────────────────────────────────────┘   │
        │  Scope · SiteMap · FindingStore · edit.rs · (NEW)   │
        │  bambda.rs (rhai filter eval)                       │
        └──────────────────────────┬───────────────────────────┘
                                    │ read: bcheck, scanner, repeater, intruder, tools
                                    ▼
                         unchanged consumer crates
```

New/modified components, in one sentence each:

- **`burpsy-core` grows a segment/location layer** underneath the existing `MsgId`/`Span`/`Bytes`
  API — every existing caller (`StoredMessage::slice`, `.body()`, `.header()`) is unchanged.
- **`burpsy-http2`** (new, small) sits *above* `TrafficStore::put`, not inside it: it terminates
  HPACK/frame demultiplexing and hands the store the same shape of input (one logical message's
  bytes) it already accepts, plus writes a raw per-connection frame sidecar for the malformed-frame
  research path.
- **`burpsy-crawler`** (new) is a fetch-and-extract loop that writes into `TrafficStore` through the
  exact same `put`/`add_exchange`/`set_response` calls the proxy uses, and calls the same
  `on_exchange` hook the proxy calls — it does not talk to the scanner directly.
- **`burpsy-plugins`** (new) hosts the extism/WASM tier and a JSON-RPC child-process tier behind one
  capability-scoped API; it is invoked from the proxy hot path (observe hooks, off-thread) and from
  the web layer (on-demand hooks), never the reverse.
- **`burpsy-web` gains** a dashboard event feed, a reporting endpoint, an `rmcp` mount, and WS
  session routes — additive routers, per the existing "one file per feature area" convention.

## Component Responsibilities

| Component | Responsibility | Proposed location |
|-----------|-----------------|--------------------|
| Segment | One fixed-size, append-only backing file; `Active` (buffered `File` writes, in-memory mirror `Bytes` for not-yet-sealed reads) or `Sealed` (mmap'd once, read-only, wrapped in one `Bytes::from_owner`) | `crates/core/src/segment.rs` (new) |
| Location index | `Vec<Location>` mapping `MsgId` → `(segment, Span)`, and `Vec<Exchange>`/`Vec<WsFrame>` indexed directly by their own sequential id — the O(1) replacement for every linear scan in the store | `crates/core/src/lib.rs` (extended) |
| Attachment relation | `related: Vec<Vec<ChildRef>>` indexed by exchange id — an ordered list of child records (WS frames today, an h2 raw-frame-stream reference later) hung off one parent exchange | `crates/core/src/lib.rs` (new field) |
| WsFrame | Lightweight per-frame record (segment, span, direction, opcode, ordinal, timestamp) — deliberately not a `StoredMessage`/`MessageShape` | `crates/core/src/ws.rs` (new) |
| Bambda filter eval | Compile-once `rhai::AST` per saved filter, evaluated against `Exchange` + on-demand header/body accessors, behind cheap native predicates (host/status/method/MIME) as a short-circuit | `crates/core/src/bambda.rs` (new) or `crates/web` if kept UI-local |
| HTTP/2 ingest normalizer | Per-connection HPACK decode + DATA reassembly → canonical HTTP/1-shaped byte buffer handed to the existing `parse()`/`put()`; separately, raw frame bytes captured per connection for the malformed-frame path | `crates/http2/src/lib.rs` (new crate) |
| Plugin host (WASM tier) | Loads extism plugins, exposes a capability-scoped hook API (observe/modify), marshals only declared fields, exposes a bounded `read_span` host call | `crates/plugins/src/wasm.rs` (new crate) |
| Plugin host (IPC tier) | JSON-RPC over stdio/socket to a child process, same capability-scoped contract as the WASM tier | `crates/plugins/src/ipc.rs` |
| Crawler frontier | Seed → fetch (via `NetSender`) → extract links/forms → enqueue, with disposition counters for every bound applied | `crates/crawler/src/lib.rs` (new crate) |
| `on_exchange` hook | Capability closure, same shape as the existing `AuditHook`, called once per newly-completed exchange by *both* the proxy and the crawler | `crates/cli/src/main.rs` (wiring), type defined in `crates/web` or `crates/core` |
| Reporting | Render `FindingStore` (+ optional `AuditOutcome` history) to HTML/JSON/SARIF | `crates/reporting/src/lib.rs` (new crate, depends only on `burpsy-core`) |
| Dashboard | Task list, progress, event/activity log fed by `on_exchange`, plugin events, and crawl disposition counters over a broadcast channel | `crates/web/src/routes/dashboard.rs` (new) |
| MCP server | `rmcp` `StreamableHttpService` mounted onto the existing `axum::Router`, re-exposing the JSON API as MCP tools | `crates/web/src/routes/mcp.rs` (new) |

## Recommended Structure

```
crates/
├── core/
│   ├── src/lib.rs          # TrafficStore extended: segments, locations, related, put()/set_response() fixed
│   ├── src/segment.rs       # NEW — Segment enum, seal lifecycle, mmap wrapping
│   ├── src/ws.rs            # NEW — WsFrame, WsSession, opcode
│   ├── src/bambda.rs        # NEW — rhai AST cache, Scope-safe accessor functions
│   └── src/edit.rs          # unchanged
├── http2/                   # NEW crate — HPACK/frame demux, canonical-buffer normalization,
│                             #   raw-frame sidecar for the malformed-frame feature
├── crawler/                  # NEW crate — frontier, extraction, disposition counters
├── plugins/                  # NEW crate — extism host (wasm.rs) + JSON-RPC child host (ipc.rs)
├── reporting/                 # NEW crate — pure rendering over FindingStore, no I/O side effects
├── proxy/                    # extended: h2 demux loop, WS upgrade handling, on_exchange call site
├── web/                      # extended: dashboard.rs, reporting.rs, mcp.rs, ws.rs routes
├── bcheck/ scanner/ repeater/ intruder/ tools/   # unchanged crate boundaries
└── cli/                      # extended wiring only
```

### Structure Rationale

- **`http2`, `crawler`, `plugins`, `reporting` as separate crates**, not modules bolted onto `core`
  or `proxy`: this preserves the existing dependency-direction discipline (`burpsy-scanner` must not
  depend on `burpsy-proxy`; new crates should not become a second place that discipline can leak).
  Each depends only on `burpsy-core` plus what it strictly needs (`http2` may need `proxy`'s
  connection types; `crawler` needs `proxy::sender::NetSender`; `plugins` needs nothing beyond
  `core` and `extism`/`wasmtime`).
- **`segment.rs`/`ws.rs`/`bambda.rs` inside `core`, not new crates**: these are extensions of the
  one storage abstraction every other crate already depends on: splitting them out would just add
  an extra crate boundary around code that has no meaningful reuse outside `TrafficStore`.

## Architectural Patterns

### Pattern 1: Segmented store with an explicit, race-free location index

**What:** Replace the current `Vec<StoredMessage>` (linear-scan `get()`) and `Vec<Exchange>`
(linear-scan `set_response()`/`exchange()`) with: (a) fixed-size rolling segment files, each either
`Active` (ordinary buffered `File` writes, served from an in-memory `Bytes` mirror while open) or
`Sealed` (mmap'd exactly once, read-only, wrapped in one `Bytes::from_owner(mmap)` per segment); and
(b) a `Vec<Location>` indexed directly by `MsgId`, and `exchanges`/`ws_frames` indexed directly by
their own id — both populated inside the *same* lock critical section that performs the append, not
via a separate atomic counter racing a later push.

**Why this is a *new* finding, not just "the O(n²) fix":** the current code has a real race, not
just an inefficiency:

```rust
// crates/core/src/lib.rs — current put()
let id = MsgId(self.next_msg.fetch_add(1, Ordering::Relaxed));   // (1) outside any lock
let shape = parse(&raw, direction).unwrap_or(...);               // (2) variable duration, no lock
self.inner.write().messages.push(StoredMessage { id, raw, shape }); // (3) separate lock acquisition
```

Steps (1) and (3) are not one critical section, and (2) sits between them with duration proportional
to message size. Two concurrent proxy connections can interleave so that the message pushed at index
5 carries an id assigned *after* the message pushed at index 6 — meaning "index equals id" is false
today, not merely slow. `add_exchange`/`set_response` have the analogous shape. This means the O(n²)
defect PROJECT.md names is real, but a naive "just index by position" fix would introduce a second,
subtler bug (wrong slice returned for a given id under concurrent load) rather than actually fixing
anything.

**The correct fix:** do the expensive, lock-free part (`parse(&raw, direction)`, which is a pure
function of the input bytes) *before* taking the lock, then take the write lock once and, inside
that single critical section, assign the id, append to the active segment, and write the location —
so id assignment and index population can never be observed out of order:

```rust
pub fn put(&self, raw: Bytes, direction: Direction) -> MsgId {
    let shape = parse(&raw, direction).unwrap_or_else(|| default_shape(&raw, direction));
    let mut inner = self.inner.write();                 // one critical section
    let id = MsgId(inner.next_msg);
    inner.next_msg += 1;
    let loc = inner.active_segment_mut().append(&raw);   // buffered write; returns Location
    inner.locations_set(id, loc);                        // resize-then-set, not push
    inner.messages_meta.push(MessageMeta { id, shape });  // ~100 bytes, no raw-byte duplication
    id
}
```

`get(id)` becomes `inner.locations.get(id.0 as usize)` → resolve `Location{segment, span}` →
`segment.bytes().slice(span.offset..span.end())` — O(1), and correct under concurrency because the
lock, not id arithmetic, is what makes assignment-and-indexing atomic. Apply the identical pattern to
`add_exchange`/`set_response`/`exchange()`. This is the direct, load-bearing fix for the debt
PROJECT.md names, and it also happens to be exactly the index the segment migration needs to know
*which file* a `MsgId`'s bytes live in — one piece of work serves both purposes, not two.

**Segment lifecycle (answering the "what happens on remap" hazard):** never remap a live mapping.
Write a segment as `segment-NNNNNN.log.tmp` via ordinary buffered `File::write` while active; on
seal (size threshold reached, or explicit rotation), `fsync`, close the write handle, rename to
`segment-NNNNNN.log` (atomic on the same filesystem), *then* `mmap` the now-immutable file read-only
and swap in `Bytes::from_owner(mmap)`. A segment is therefore always in exactly one of two states —
"being appended to, never mapped" or "sealed, mapped, never written to again" — so there is no window
in which an outstanding `Bytes` slice's backing mapping can move or shrink. This is the same shape as
Kafka's active-vs-frozen segment split and LMDB's fixed-`mapsize`-reserved-up-front discipline; the
segment-per-file version is the better fit here specifically because captures are open-ended
(multi-GB is the explicit goal), so "one segment, occasionally sealed and replaced" avoids LMDB's
eventual stop-the-world remap entirely. `SIGBUS` on external truncation is mitigated the same way
STACK.md already specifies: this process is the sole owner/creator of its segment files.

**When to use:** this is the foundational change; everything else in this document either depends
on it or benefits from it (see Build Order).

### Pattern 2: Ingest-time protocol normalization, with a raw sidecar for wire-fidelity features

**What:** `MessageShape`/`Span` do not change to accommodate HTTP/2. Instead, a new layer
(`burpsy-http2`) sits strictly *above* `TrafficStore::put`: it decodes HPACK (connection-scoped
dynamic table, never persisted — it's decode-time-only state), reassembles DATA frames per stream,
and synthesizes a canonical HTTP/1-shaped byte buffer (`METHOD SP :path SP HTTP/2\r\n` + headers +
body) that is hard to distinguish from a normal HTTP/1.1 message once it reaches `parse()`. The exact
same synthesis happens for WebSocket handshakes (already HTTP/1.1 on the wire, no change needed) and
would be the model for any future h3/QUIC support.

**Why:** every downstream consumer of a stored message — `edit.rs`'s Content-Length/chunked
handling, the insertion-point engine, the BCheck evaluator, Intruder's payload splicing, Repeater's
byte-exact resend — currently assumes a message's `raw: Bytes` *is* a linear, self-framing HTTP/1.1
wire buffer. Normalizing at ingest means none of that code needs to learn about frames, streams, or
HPACK; the entire "spans assume HTTP/1 framing" surface area is confined to one new, small crate that
runs once, before the existing store boundary.

**The cost this defers, made explicit now:** normalization means the stored bytes for an h2 exchange
are *not* the literal wire bytes — this breaks the project's stated "all other bytes preserved" /
byte-exact invariant for h2 specifically (HTTP/1 is unaffected). h2 therefore also needs a raw,
per-connection frame capture stored *alongside* the normalized exchange, which the deliberately-
malformed-frame research feature needs anyway. That raw stream is not 1:1 with one exchange — it's
1:N (one connection's frame stream relates to many exchanges, and conversely one exchange may want a
reference back into that stream). WebSockets need the same shape of relation (one handshake exchange,
many frames). **This is the concrete design decision to make now, even though h2 itself is deferred:**
give `Exchange` a `related: Vec<ChildRef>` slot in the segment/location schema during the mmap
migration (Pattern 1), populated by WS frames first and by h2's raw-frame references later. Retrofitting
a parent-child relation into an already-shipped 1:1-only index/segment layout is the one thing that
would make "h2 late" genuinely expensive; designing the slot for it during Pattern 1 costs a field and
an empty `Vec` for every exchange that doesn't use it.

**When to use:** any framing that doesn't already look like HTTP/1.1 on the wire (h2 now; h3/QUIC if
ever considered, though that is out of current scope).

### Pattern 3: Capability-scoped plugin boundary (headers by default, spans on request)

**What:** A plugin never receives a whole body by default. A plugin manifest declares, per hook it
registers (`observe_request`, `observe_response`, `modify_request`, `modify_response`, ...), which
fields it needs. The host marshals exactly those fields:

- **Metadata-only hooks** (the common case — a filter predicate, an "is this an API key" scanner, a
  highlight rule) receive method/path/status/headers/MIME as a small serialized struct. No body span
  is touched, no copy happens, regardless of body size.
- **Body-declaring hooks** receive `MsgId` + `Span` (or, for the WASM tier, a handle) and call a
  bounded host function `read_span(msg_id, offset, len) -> bytes` for the byte ranges they actually
  need — this turns "copy the whole 500MB response into WASM linear memory" into "copy the 200 bytes
  the plugin's regex actually looks at." **`read_span` must be bounded to the message(s) the plugin
  was invoked for** (the current exchange's request/response ids, and nothing else it wasn't handed) —
  otherwise the host function becomes a store-enumeration primitive, i.e. a plugin sandbox escape into
  every other captured message. This is a scope-of-authority bug in the same family as the confirmed
  Scope fail-open already fixed elsewhere in this codebase (a payload rewriting a path onto an
  excluded prefix) — same lesson, different boundary: never grant broader read access than the
  specific capability being exercised.
- **Modify hooks** cannot avoid a copy: WASM guest memory can't alias host `Bytes`, so a plugin that
  rewrites a request returns new bytes, which the host writes via `TrafficStore::put` as a *new*
  `MsgId` — the stored original is never mutated. This mirrors `edit.rs`'s existing
  take-apart/reassemble-a-new-buffer discipline exactly; it is not a new pattern, just a new caller
  of an existing one. **Scope must be re-checked against the plugin's returned bytes before anything
  reaches the wire** — same requirement, same reasoning, as Intruder's per-request `Guard` and the
  BCheck `Sender`'s scope re-check on spliced payloads: a plugin that rewrites a path is exactly as
  capable of moving a request onto an excluded prefix as an Intruder payload is.
- The JSON-RPC child-process tier applies the identical discipline over IPC: headers-only by default,
  an explicit "give me bytes N..M" RPC call for anything more, never a whole-body field by default.

**Why:** mitmproxy addons and Caido plugins both accept "one whole-body copy into the plugin's own
process/runtime" as their normal cost (`flow.response.content` is a full Python bytes copy; Caido's
`onInterceptRequest` hands a whole `Request` object across the Node backend boundary) — that is an
acceptable design for those tools because copying isn't in conflict with their storage model. It is
in direct conflict with this project's reason to exist. The span-handle-plus-bounded-read-callback
design is the version of "least copy that is still useful": read-only hooks cost zero body bytes
unless the plugin actually asks for them, and even then cost only the bytes asked for, not the whole
message.

**When to use:** all plugin hooks. There is no tier where "just pass the whole body" is the right
default, even though it is the industry-standard shortcut.

### Pattern 4: One `on_exchange` hook, two callers

**What:** Extract the "a new exchange just got its response" moment — currently inlined in the
proxy's capture path (`crates/proxy/src/lib.rs`, right after `set_response`, deciding whether to
`tokio::spawn` a passive scan) — into a capability closure of the same shape as the existing
`AuditHook`: `type OnExchange = Arc<dyn Fn(u64) + Send + Sync>`, built once in `crates/cli/src/main.rs`
and handed to *both* the proxy and the crawler. The crawler fetches pages through the same
`burpsy_proxy::sender::NetSender` already used for active-audit probes, writes results through the
same `put`/`add_exchange`/`set_response` calls the proxy uses (optionally tagging `Exchange.source:
Proxy | Crawler` for UI/dispatch grouping, the same way failed `CONNECT`s already get a synthetic
marker today), and calls the identical `on_exchange` hook afterward.

**Why:** this is the direct answer to "without duplicating dispatch logic" — there is exactly one
place that decides what happens when an exchange completes, and it does not know or care whether the
exchange came from a live proxy connection or a crawler fetch. "Live passive crawl" is this hook
already existing and being called from a second call site; nothing new needs to be invented for it.
"Live audit" (operator-opted-in *active* auditing of freshly-crawled items) reuses the existing
`AuditHook`/`audit_item` dispatch-scope grouping the exact same way — call it from `on_exchange` only
when the operator has explicitly enabled that mode for the crawl, never by default. This preserves
the existing, already-load-bearing safety property ("two scan paths must not be conflated... active
path only triggered by explicit operator action") rather than quietly widening what "automatic"
means.

**When to use:** any future traffic source (a future "replay a saved collection" feature, for
instance) should plug into `on_exchange` rather than growing a third bespoke dispatch path.

## Data Flow

### Ingestion (proxy or crawler → store → dispatch)

```
proxy connection / crawler fetch
        │  raw bytes (Bytes, owned once)
        ▼
TrafficStore::put(raw, direction)
        │  parse() runs lock-free, pure fn of raw bytes
        │  single write-lock section: assign id, append to active segment, set locations[id]
        ▼
MsgId  ──────────────────────────────► Exchange row (id-indexed, metadata only)
        │
        ▼
on_exchange(exchange_id)   ← called by BOTH proxy and crawler after set_response
        │
        ├─► PassiveScanner::scan  (automatic, off hot path, no traffic sent)
        ├─► [if crawl "live audit" opted in] AuditHook → PassiveScanner::audit (sends probes)
        ├─► Dashboard event feed (broadcast channel)
        └─► Plugin observe hooks (extism/IPC, off hot path, headers by default)
```

### WebSocket capture

```
HTTP/1.1 Upgrade handshake  →  ordinary Exchange (request/response pair, status 101)
        │
        ▼
connection becomes a WS session; each frame:
        │
        ▼
TrafficStore::put_frame(raw) → Segment.append() (same primitive as put(), no parse(), no MessageShape)
        │
        ▼
WsFrame { location, direction, opcode, ordinal, ts } appended to ws_frames
        │
        ▼
related[handshake_exchange_id].push(ChildRef::WsFrame(frame_idx))
```
`/api/history` is unaffected — the handshake shows up once, like any other exchange. A new
`/api/ws/{exchange_id}` endpoint resolves `related[...]` into the ordered frame list on demand,
slicing frame bytes only when a frame is actually opened — same "index rows first, bytes on demand"
discipline the existing `/api/history` → `/api/message/{id}` split already uses.

### Plugin invocation

```
exchange or explicit operator action
        │
        ▼
PluginHost.dispatch(hook_kind, declared_fields)
        │  marshal only declared_fields (headers/status/etc — no body span touched by default)
        ▼
guest (WASM) or child process (IPC)
        │  optional: read_span(msg_id, offset, len) — bounded to this invocation's message ids
        ▼
observe: nothing returned to store          modify: new bytes → Scope re-check → TrafficStore::put (new MsgId)
```

### Crawler frontier

```
seed URLs → frontier (bounded queue, disposition counters: enqueued / fetched / truncated / out-of-scope)
        │
        ▼
NetSender.send(request)  ← Scope-checked before the byte leaves the process, same as repeater/intruder
        │
        ▼
TrafficStore::put/add_exchange/set_response  → on_exchange(...)
        │
        ▼
link/form extraction over the response body (Span-sliced, not copied wholesale) → new frontier entries
```
Frontier bounds (max depth, max pages, max pages/host) are enforced the same way the audit engine's
budgets are: refuse the *next* enqueue and increment a disposition counter, never silently drop a
completed fetch — the same "bounds must be observable" constraint PROJECT.md already states for the
scanner applies verbatim to the crawler; give it its own `CrawlOutcome`/`Disposition`-shaped counter
set rather than a single opaque "crawl finished" boolean.

## Scaling Considerations

This project's scaling axis is capture size and exchange/frame count, not concurrent users — there is
no multi-tenant dimension.

| Capture scale | What holds | What needs attention |
|---|---|---|
| ~100MB, <10k exchanges | Current in-memory `Vec` design works fine even with linear scans; no urgency | None |
| ~10GB, ~1M exchanges | Linear scans (`get`, `set_response`, `exchange`) become real CPU cost, and — the actual forcing function — an all-in-RAM `Vec<StoredMessage>` risks pinning most of 10GB in process RSS, since `Bytes` today are heap-owned, not disk-backed | Segments + O(1) location index (Pattern 1) is the fix; sealed segments' bytes live in the OS page cache, not pinned RSS, so a 10GB capture no longer requires ~10GB resident |
| ~100GB, tens of millions of exchanges/frames | The location index itself becomes a real allocation: `Vec<Location>` at ~24 bytes/entry × 50M messages ≈ 1.2GB just for the index, still resident. A single global `RwLock<StoreInner>` write lock also becomes a single-writer bottleneck once proxy, crawler, WS frames, and plugin writes are all appending concurrently | Not solved by this milestone — flagged as a Gap. Candidate future directions: page or mmap the location index itself; shard the write lock per-segment rather than per-store. Do not build this speculatively now; the current single-lock, in-memory-index design is the right size for this milestone's stated goal ("multi-GB captures viable") |

### Scaling Priorities

1. **First bottleneck: RSS growth from an all-in-memory message log at multi-GB scale.** Fixed by
   Pattern 1 (segments + mmap). This is why it must ship before crawler/h2/WS, all three of which are
   volume generators (see Build Order).
2. **Second bottleneck (next milestone, not this one): single-writer lock contention** once
   proxy + crawler + WS frames + plugin-driven writes all append concurrently. Name it now so it isn't
   rediscovered as a surprise; do not build a sharded-lock design speculatively.

## Anti-Patterns

### Anti-Pattern 1: Treating "index by id" as sufficient without fixing the id-assignment race

**What people do:** Read the O(n²) `set_response` linear scan, conclude "just look it up by id
directly," and ship `Vec` indexing without checking whether id assignment and vec insertion are the
same critical section.
**Why it's wrong:** as shown in Pattern 1, they aren't, today — the fix must move id assignment
*inside* the same lock as the location write, not simply add indexing on top of the existing
assign-then-push shape.
**Do this instead:** parse (or any other variable-duration, lock-free work) before acquiring the
write lock; assign the id and write the location in one uninterrupted critical section.

### Anti-Pattern 2: Reusing `StoredMessage`/`MessageShape` for WebSocket frames

**What people do:** Route every WS frame through the existing `TrafficStore::put`/`parse()` path
because "it's already zero-copy."
**Why it's wrong:** `parse()` cannot populate a meaningful `MessageShape` for a WS frame (no
request/status line, no header block) — it falls through to the degenerate whole-body span, while
still paying for a `Vec<HeaderSpan>` allocation and the full `MessageShape` struct per frame. At
10,000 frames in one chatty WS session, that metadata overhead is the same class of blowup this
project exists to avoid, just relocated from bodies to per-record structs.
**Do this instead:** a lightweight `WsFrame` record (segment, span, direction, opcode, ordinal,
timestamp) sharing only the segment-append primitive, never `parse()` or `MessageShape`.

### Anti-Pattern 3: An unbounded `read_span` host function

**What people do:** Expose `read_span(msg_id, offset, len)` to a plugin as a generic store-read
primitive, for implementation convenience.
**Why it's wrong:** a plugin invoked for one exchange gains the ability to read *any* other captured
message in the store — a sandbox escape structurally identical to the Scope fail-open this codebase
already fixed elsewhere (authorizing on the wrong scope of information).
**Do this instead:** bind `read_span` to the specific `MsgId`s the plugin was invoked with; reject
reads against any other id at the host boundary, not the guest's.

### Anti-Pattern 4: Silent frontier truncation

**What people do:** Cap crawl depth/page count/pages-per-host and simply stop enqueuing once the cap
is hit, the way Burp's own `LIMIT_EXCEEDED` silently drops work.
**Why it's wrong:** this is exactly the anti-pattern this codebase already named and fixed for the
scanner (`AuditOutcome`/`Disposition`) — a caller cannot tell "crawled everything reachable" from
"gave up at page 500 of a much bigger site."
**Do this instead:** a `CrawlOutcome`-shaped disposition counter set, on the same model as
`AuditOutcome`, so every frontier bound is visible, not silent.

### Anti-Pattern 5: One mutable mmap that grows

**What people do:** Reach for `MmapMut::remap(may_move: true)` on a single ever-growing file because
it's less code than segment rotation.
**Why it's wrong:** `remap` can move the mapping; every `Bytes` built from the old base address
becomes a dangling pointer the instant that happens — undefined behavior, not a panic, in a subsystem
whose entire premise is safely handing out refcounted slices.
**Do this instead:** fixed-size, sealed, never-remapped segments (Pattern 1).

## Integration Points

### External Services

None. Every remaining feature in this milestone is local-process integration (WASM runtime, child
process, embedded JS/rhai engines) — there is no network service dependency introduced by this
milestone (Collaborator, which would be one, is explicitly out of scope).

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `burpsy-core` ↔ everything | Direct function calls over `Arc<TrafficStore>` | Unchanged shape; only the internals of `TrafficStore` change |
| `burpsy-proxy` ↔ `burpsy-http2` | `burpsy-proxy` calls into `burpsy-http2`'s demux per h2 connection; `burpsy-http2` calls back into `burpsy-core::put` | New dependency edge; keep `unstable` `h2` feature usage scoped to this crate only, per STACK.md |
| `burpsy-crawler` ↔ `burpsy-proxy::sender` | `crawler` depends on `proxy` for `NetSender` only, not the reverse | Mirrors the existing scanner/proxy dependency-direction rule — `crawler` must not become something `proxy` depends back on |
| `burpsy-plugins` ↔ `burpsy-core`/`burpsy-web` | Capability closures + a bounded read API, not a shared-memory or shared-state boundary | No crate should depend on `burpsy-plugins` for correctness-critical logic — a plugin failing to load must never break capture/scan |
| `burpsy-web` ↔ `rmcp` | `rmcp::StreamableHttpService` mounted as a `tower::Service` on the existing `axum::Router` | Additive; no change to existing JSON routes |
| `on_exchange` hook | `Arc<dyn Fn(u64) + Send + Sync>`, called by `burpsy-proxy` and `burpsy-crawler` | Same capability-closure idiom as the existing `AuditHook` — do not let either caller depend on the other |

## Build Order

Ordered by genuine dependency, not by the milestone-scope grouping in PROJECT.md (which groups by
"kind of work," not "what blocks what"). Reasoning follows each step; items marked *parallelizable*
have no ordering dependency on the step they're listed under and can be resourced concurrently.

**1. Segmented mmap store + race-free O(1) location index (Pattern 1).**
Foundational and self-contained inside `burpsy-core`. Every subsequent volume-generating feature —
crawler, WebSockets, HTTP/2 — either depends on this or inherits and amplifies the current defect
(a real concurrency bug, not just an inefficiency, per Anti-Pattern 1). Must also lock in the `related`
1:N sidecar slot now (Pattern 2), even though only WS frames use it in this milestone — this is the
one design decision that is cheap now and expensive to retrofit into a shipped segment/index format.

**2. Self-contained tool-parity leftovers** — *parallelizable with step 1 and with each other*:
Intruder payload processing/grep-match-extract, Sequencer, Repeater tabs, scanner data files
(RetireJS/JWT wordlist/scan configs), and Reporting. None of these touch `TrafficStore`'s internals or
generate exchange volume; Reporting in particular has zero coupling to any platform work (it renders
`FindingStore`, which already exists) despite being grouped under "Platform" in PROJECT.md — pull it
forward rather than waiting for step 4-7's platform work to land. Proxy history filters (Bambda/rhai)
belong here too for correctness, but want the O(1) exchange index from step 1 before they're evaluated
against large history — sequence just after step 1, not step 2's other items.

**3. Session handling (macros, recorded logins, cookie jar, re-auth)** — moved earlier than its
PROJECT.md position. Coupling reason: a crawler without session/cookie-jar support can only usefully
reach the unauthenticated surface of a target, which defeats most of the point of crawling a real
application. Build this before or alongside step 4, not after it.

**4. Crawler (frontier, extraction) + shared `on_exchange` hook + live-passive/live-audit wiring**
(Pattern 4). Depends on step 1 (crawler is, by design, a volume generator — the question's "must the
mmap migration precede the crawler" is answered yes, unambiguously). Also the right place to stress-
test the `on_exchange` hook and the O(1) index under realistic multi-thousand-exchange load, before
WebSockets and HTTP/2 both also become callers of that same hook.

**5. Plugin API (extism tier first, JSON-RPC child-process tier as a follow-on)** *parallelizable
with step 4*. Depends on step 1 only so that the `read_span` host call is built against the final,
stable segment-backed `Span` resolution rather than the in-memory-`Vec` version and reworked later.
Low coupling to the crawler — plugins are a hook mechanism, not a volume generator — so this can run
on a separate track alongside step 4 if resourced separately.

**6. WebSockets** (Pattern 2's WS-specific half, Anti-Pattern 2). Depends on step 1 for the same
volume reason as the crawler (session frame counts are exactly the "many small records" case the
segment/index design must handle well), and is sequenced after steps 4-5 so the `on_exchange`/plugin
hook shapes only have to accommodate one new record kind (WS frames) at a time, rather than being
designed concurrently against three moving targets.

**7. HTTP/2** (Pattern 2). Depends on step 1 for the same volume argument as steps 4 and 6 — h2
multiplexing lets one connection carry far more concurrent requests than serial HTTP/1.1 keep-alive,
so h2 is itself a volume generator, independent of anything it does to the store's shape. Sequenced
after WebSockets specifically because both change the proxy's per-connection state machine (WS
introduces a persistent post-handshake tunnel; h2 introduces N-way multiplexed streams per
connection) — building WS first, then h2, means the proxy's connection-handling loop is generalized
once, at the end, rather than partially generalized for WS and then re-generalized for h2.

**On "is doing h2 late more expensive than early" — answered directly:** No, *provided* Pattern 2's
ingest-time normalization is the design, which this document commits to now regardless of when h2
ships. At the parse/span layer, late is not more expensive: `edit.rs`, insertion points, BCheck, and
Intruder never need to learn about frames or HPACK either way, because h2 is normalized to the
existing canonical `MessageShape` before it reaches any of them. At the proxy connection-model layer,
late is actually *cheaper*: WebSockets, session handling, and the plugin observe-hook timing all get
built once against a proxy that already generalizes "more than one logical thing can be happening on
this connection" (from WS), rather than being built against a strictly-serial one-request-at-a-time
model and then reworked when h2's multiplexing arrives. The one way late h2 *would* become expensive
is if the segment/location index schema were built 1:1-only in step 1 and needed a parent-child
relation retrofitted after the fact — which is exactly why Pattern 2's `related` slot is specified as
part of step 1, not step 7. With that slot in place, PROJECT.md's existing "sequenced late" decision
is confirmed, not just accepted.

**8. Dashboard.** Depends on step 4 (crawl disposition counters) and step 5 (plugin events) for
something real to surface on its event feed — building it earlier means inventing a speculative event
model that gets rebuilt once real events exist.

**9. MCP server.** Last by design, matching PROJECT.md: it re-exposes the JSON API, so it should be
built once that surface has stopped changing under steps 1-8, not maintained as a second consumer of
a moving target throughout.

**10. DOM/JS analysis.** Last, per PROJECT.md, unchanged by this analysis — needs its own JS engine
plus a hand-built DOM/BOM shim (per STACK.md, no off-the-shelf crate provides one), and is explicitly
the lowest-priority, most-slip-tolerant item in the milestone.

## Sources

- `.planning/codebase/ARCHITECTURE.md` (this repo, 2026-07-27) — current system structure; primary
  source for every "current behavior" claim in this document.
- `/root/burpsy/crates/core/src/lib.rs` (direct read) — `TrafficStore::put`/`get`/`add_exchange`/
  `set_response` source, confirming both the O(n²) `set_response` scan named in PROJECT.md and the
  additional id-assignment race identified in Pattern 1/Anti-Pattern 1 (not previously documented).
  HIGH confidence — primary source, own codebase.
- `/root/burpsy/crates/proxy/src/lib.rs` (direct read) — confirmed no existing h2/WebSocket/Upgrade
  handling; current proxy loop is a strictly serial one-request-at-a-time splice per connection,
  supporting the Build Order step 6/7 sequencing argument. HIGH confidence.
- `.planning/research/STACK.md` (this repo, 2026-07-27) — dependency decisions (memmap2, extism, h2
  unstable, rhai, boa_engine, rmcp) this document builds on directly; segment/mmap hazard analysis in
  Pattern 1 extends STACK.md's "Mmap Store — Decision" section rather than repeating it.
- mitmproxy documentation (`docs.mitmproxy.org/stable/api/events.html`, addon examples, GitHub
  discussions #6996/#5282) — confirms addon hooks receive whole buffered `flow.request.content`/
  `flow.response.content`, and that streaming large bodies makes content empty at hook time — used in
  Pattern 3 as the "industry-standard shortcut" this design deliberately does not copy. LOW confidence
  (web search, uncorroborated beyond mitmproxy's own docs, but directly on point).
- Caido developer docs (`developer.caido.io/concepts/package.html`, `.../guides/components/backend_events.html`,
  `.../plugins/guides/request.html`) — confirms backend/frontend plugin split, `onInterceptRequest`/
  `onInterceptResponse` event shape, whole-object marshaling — used the same way as the mitmproxy
  citation above. LOW confidence (web search).
- Kafka storage internals (multiple corroborating sources: Strimzi engineering blog, Conduktor,
  AutoMQ, GeeksforGeeks deep-dive) — confirms the active/frozen segment split and offset→byte-offset
  index file pattern cited in Pattern 1's segment lifecycle design. LOW-MEDIUM confidence (web search,
  but corroborated across independent sources agreeing on the same mechanism).
- Burp Suite WebSockets documentation (PortSwigger, `portswigger.net/burp/documentation/desktop/...`)
  and mitmproxy's `mitmproxy.websocket` API docs — confirms both tools model a WS session as one
  handshake exchange plus a growing ordered list of reassembled frame messages, corroborating the
  `related`/`WsFrame` design in Pattern 2/Data Flow. LOW-MEDIUM confidence (web search, corroborated
  across two independent tools' documentation agreeing on the same shape).
- Advisor review (this session) — identified the id-assignment race in the current `put()`/
  `add_exchange()` shape (Anti-Pattern 1), the need for a 1:N `related` slot to avoid an expensive h2
  retrofit (Pattern 2), the WS-frame-metadata-overhead anti-pattern (Anti-Pattern 2), and the
  plugin-scope/crawl-disposition gaps (Pattern 3, Anti-Pattern 3/4). Treated as HIGH confidence: it is
  reasoning directly over this codebase's own source, not an external claim.

---
*Architecture research for: Rust web-security testing platform — platform/plugin milestone remaining
features*
*Researched: 2026-07-27*
