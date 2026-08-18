<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# core

## Purpose

The HTTP message model, the append-only traffic store, and the engagement-authorisation decision —
the Go port of `crates/core`. This is the package every other `internal/` package holds, and it
imports no other burpsy package, so the memory model stays testable in isolation.

Parsing yields **spans, not strings**: `Parse` turns raw bytes into a `MessageShape` of
`(offset, len)` spans, and `StoredMessage` hands out sub-slices of the one stored byte slice
rather than copies. Unlike the Rust crate, the sitemap is **not** here — it lives in
`internal/sitemap` as its own package.

## Key Files

| File | Description |
|------|-------------|
| `store.go` | `MsgId`, `Span`, `Direction`, `MessageShape`, `StoredMessage`, `Exchange`, `ExchangeDuration`, `Source`, `ChildRef`, and `TrafficStore` itself (messages, exchanges, and WebSocket indexes). Also `VerifyIndex`, `SegmentVerdict`, `VerifyCaptureDir` |
| `parser.go` | `Parse(raw, direction) (MessageShape, error)` — raw bytes to spans, with typed `ParseError` codes |
| `segment.go` | `SegmentLog`: append, rotate, resume, `ReadAt` (mapping-first with `pread` fallback), `Sync`, `Close`, and `abandonAfterTornWrite` |
| `segment_format.go` | The on-disk framing: segment file header, per-record `RecordHeader` with CRC32, `CorruptRecord`, `ScanSegmentFile` |
| `segment_map_unix.go` / `segment_map_other.go` | Build-tagged mmap support. On platforms without it, `Mappable()` is false and reads go through `pread` / resident copies |
| `shape_codec.go` | `EncodeShape` / `DecodeShape` — varint codec (~50 bytes/message) so the durable mirror persists shapes instead of re-parsing every payload on restore. No Rust equivalent |
| `scope.go` | `Scope` / `ScopeRule` / `SharedScope`, `AuthoriseRequest`, `AuthoriseRaw` (reads the path out of raw request bytes), `Explain`, `ParseHostPort`. Rules can be scoped to a port and a path prefix |
| `edit.go` | `RequestEdit` — parse, mutate (headers, target, query, body), and `ToRaw` rebuild with Content-Length recompute and chunked-body decoding |
| `findings.go` | `Severity`, `Confidence`, `Finding`, `FindingStore` with `OnChange` signal, `SetPersistenceSink`, and `Restore` |
| `websocket.go` | RFC 6455: `WsOpcode`, `ParseWsFrameHeader`, `WsUnmask`, `WsReassembler` (bounded by `maxMessageBytes`), `IsWsUpgradeRequest`/`IsWsUpgradeResponse`, `StripWsExtensionsHeader`, `WsMessage`, `WsCloseStatus` |

## For AI Agents

### Position is the id — the Go variant of the invariant

`messages[i].id == MsgId(i)`, `exchanges[i].ID == i`, `wsMessages[i].ID == i`. `Put` reads
the id and appends under the **same** lock acquisition, and — the comment block at
`store.go:488` records the bug this fixed — the id is consumed only after the parse and segment
write both succeed. Incrementing first meant a rejected `Put` burned an id, shifting every later
message one slot past itself and silently re-labelling the rest of the capture. `Restore` sets
`nextID = len(messages)` and so assumes the same contiguity. `VerifyIndex` makes the invariant
checkable; run it in tests that exercise the store concurrently (see `verify_test.go`).

### Disk-backed vs resident is decided per message

With a capture dir, `Put` appends the payload to the `SegmentLog` and keeps only a disk-backed
`StoredMessage` — **but only when** the append yielded a location *and* `Mappable()` is true.
Otherwise it falls back to a resident copy: better to spend the memory than hold a span the store
cannot resolve. The previous implementation held both and paid disk *and* heap for the same capture.

### Differences from the Rust reference (verified in source)

- `DefaultSegmentTargetBytes` is **100 MB**, not the Rust crate's 64 MiB target.
- `SegmentLog` has a `resume()` path (`segment.go:110`); the Rust store refuses a directory
  that already holds a capture.
- The store supports a durable mirror the Rust crate does not have: `SetPersistenceSinks` installs
  write-through hooks for messages and exchanges, and `Restore` is the SQLite load path. Restore
  must run **before** any exchange observers register — replaying to observers would double-count.
- WebSocket payloads do **not** go through `Put`: `AddWsMessage` copies the payload once into a
  resident `wsPayloads` slice, so ws payloads are never disk-backed, and `Restore` deliberately
  clears the ws indexes (the mirror has no row for them).
- The sitemap moved out to `internal/sitemap`.

### Callbacks run under the store's write lock

`ObserveExchanges` observers and the `OnWsChange` signal fire while the lock is held, on the
capture path. Keep them O(1) and allocation-light — a relay pumping a busy socket waits behind them.
`OnWsChange` is a single slot (re-install replaces) and signals *that* something changed, not what.

### `ExchangeDuration`: the zero value is "unmeasured"

`{Us, Measured}` — the zero value is honest (untimed, not instantaneous). A negative duration
clamps to zero but stays measured. `Millis()` is the lossy legacy shape; never test it against
zero to decide whether an exchange was timed — check `Measured`.

### Scope refuses by default

A request whose start line cannot be read is refused, never waved through
(`scope_raw_test.go`). Path-prefix rules cannot be smuggled past via the query string
(`dropQuery`), and `Explain` names the rule that refused. `SharedScope` is the shared,
lock-guarded handle subsystems hold so a runtime scope edit reaches all of them — share the handle,
never copy the `Scope` value into a subsystem.

### Corruption is reported, never skipped

`decodeRecordHeader` / `ScanSegmentFile` return a typed `CorruptRecord` naming the offset and
kind. The CRC32 is corruption detection only (torn writes, truncation, bit rot) — never describe it
as an integrity control. `VerifyIndex` (index self-consistency) and `VerifyCaptureDir` (re-read
files, recompute every CRC) catch different failure classes; neither subsumes the other.

## Testing Requirements

```bash
cd burpsy-go
go test ./internal/core/...
```

Tests are named as full sentences stating a claim (e.g.
`TestARequestWithNoReadableStartLineIsRefusedNotWavedThrough`). Coverage includes the segment
format round-trip (`segment_format_test.go`), store id assignment (`store_msgid_test.go`),
shape codec round-trip, WebSocket reassembly, and request editing.

## Dependencies

### Internal

None. This is the root of the `internal/` graph and must stay that way.

### External

Standard library only: `hash/crc32` (record checksums), `encoding/binary` (shape codec),
`syscall` (mmap, unix-only build tag). There is no `bytes`-crate equivalent — slices of the
read-only mapping or of the resident copy serve that role.
