<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# core (`burpsy-core`)

## Purpose

The HTTP message model, the append-only traffic store, and the engagement-authorisation decision.
This is the crate every other crate holds, and it depends on no other burpsy crate — deliberately, so
the memory model can be tested in isolation without a network or a parser in the graph.

Parsing yields **spans, not strings**: a parsed message costs a fixed ~100 bytes regardless of a
multi-megabyte body. `StoredMessage::slice` hands out `Bytes`, which is a refcount bump rather than a
copy, so giving one request to Repeater, an Intruder attack and the UI simultaneously costs three
pointers.

## Key Files

| File | Description |
|------|-------------|
| `lib.rs` | `MsgId`, `Span`, `Direction`, `MessageShape`, `StoredMessage`, `parse`, `Exchange`, `ChildRef`, and `TrafficStore` itself. Also `SegmentVerdict` and `verify_capture_dir` |
| `segment.rs` | Sealed, mmap-backed segment storage: `SegmentLog`, `RecordHeader`, `CorruptRecord`, `scan_segment_file`. The disk half of the store |
| `scope.rs` | `Scope` / `ScopeRule` — which hosts and paths the engagement may touch. `authorise_request` is the one decision function |
| `sitemap.rs` | The host → path tree the UI navigates, folded from the traffic index. A view over the store, never a second copy |
| `findings.rs` | Finding storage and deduplication (dedup belongs to storage, not display) |
| `edit.rs` | `RequestEdit` — editable requests layered over immutable stored bytes |

## For AI Agents

### The one invariant — read this before touching `TrafficStore`

**Position is the id.** `messages[i].id == MsgId(i)` and `exchanges[i].id == i`, always. Every lookup
is a bounds-checked index, not a scan, and that is *only* sound because ids are handed out by the same
lock acquisition that appends the record.

This used to be false in a way nothing caught: `put` took its id from an `AtomicU64::fetch_add`, then
parsed (unlocked), then took the write lock to push — so two threads could reserve 7 and 8 and push in
the order 8, 7. Lookups scanned for `.id`, so they stayed correct and the defect was invisible. If you
move the id assignment out of the append critical section, you reintroduce it. Parsing stays *outside*
the lock on purpose — it needs nothing from the store and is the expensive part.

`verify_index()` is what makes the invariant checkable rather than merely asserted. Run it in any test
that exercises the store concurrently.

### Two store modes, one API

- `TrafficStore::new()` — everything resident in RAM. The historical behaviour, fine for tests.
- `TrafficStore::with_capture_dir(dir, target_bytes)` — payloads append into sealed segments; only a
  `Location` per message stays in memory, so a multi-GB capture is bounded by disk.

Both present an identical public API, which is what lets one differential test drive both and assert
they agree (`a_disk_backed_store_is_indistinguishable_from_an_in_memory_one`). **If you add a method
to `TrafficStore`, add it to that test's `drive()` sequence** — otherwise the parity claim silently
stops covering it.

`with_capture_dir` refuses a directory that already holds a capture. There is no startup-recovery path
yet, so reusing one would overwrite it.

### Segments: the two-state rule

A segment is either being written through a buffered `File` and **never mapped**, or mapped read-only
and **never written again**. There is no state where both hold. This is not a performance choice —
remapping a live mapping while `Bytes` slices into it are outstanding leaves those slices pointing at
moved memory, which is a dangling pointer, not a stale read.

Seal order *is* the safety argument and is spelled out in `seal_active`: flush → fsync → drop the
writer → rename → scan every CRC → only then map. Reordering any two steps reintroduces either the
remap hazard or a trusted-corrupt-segment hazard. A segment that fails its own scan is never mapped.

The 64 MiB target is a **target, not a cap**. A message larger than the whole target gets its own
oversized segment rather than being refused, truncated or split — Kafka refuses oversized records, and
that answer is wrong here because dropping captured traffic violates the premise the store exists to
serve.

**The CRC is corruption detection only** — torn writes, bit rot, truncation. It is not a cryptographic
integrity control and must never be described as one in a doc comment, error string, or operator-facing
text. Anyone who can write to the capture directory can recompute a CRC.

### Two verification mechanisms, never conflated

- `verify_index()` proves the in-memory index is self-consistent. It would still pass if the bytes on
  disk had rotted, because it reads them through the index it is checking.
- `verify_segments()` / `verify_capture_dir()` re-read each file and recompute every CRC, catching what
  appeared *after* the write.

Neither subsumes the other. A change that merges them loses a failure class.

### Testing Requirements

```bash
cargo test -p burpsy-core            # 83 tests
cargo test -p burpsy-core segment    # the segment module alone
```

Temp capture directories come from the `segment::test_support::TempCapture` helper, which removes
itself on drop. Do not add a `tempfile` dev-dependency — the workspace has none.

### Common Patterns

- Bounds-check before slicing. `StoredMessage::slice` returns an empty `Bytes` past the end;
  `SegmentLog::resolve` returns `None` so a caller can tell "out of bounds" from "genuinely
  zero-length". Mirror whichever discipline fits.
- New fields on serialised types get `#[serde(default)]` so an older capture still deserialises —
  see `Exchange.related` and the test that loads a pre-`related` exchange.
- A malformed record header is a report-corruption case, never a silent skip.

## Dependencies

### Internal

None. This is the root of the graph and must stay that way.

### External

- `bytes` — `Bytes` refcounted slices, and `Bytes::from_owner(mmap)` for sealed segments
- `memmap2` 0.9.11 — read-only mapping of sealed segments
- `crc32fast` 1.5.0 — per-record corruption detection (already transitively present via `flate2`)
- `parking_lot` — the single `RwLock<StoreInner>`
- `serde`, `anyhow`; `serde_json` as a dev-dependency

<!-- MANUAL: -->
