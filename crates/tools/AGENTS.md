<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# tools (`burpsy-tools`)

## Purpose

The supporting tools — Decoder, Comparer, Logger, Organizer, and match-and-replace. Pure
transformations over bytes and stored messages, deliberately free of any I/O so they can be exercised
directly in tests and reused by the proxy, the UI and a future MCP server alike.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | Crate root; the "free of I/O" discipline and what it costs callers |
| `src/decoder.rs` | Encode/decode chains — the largest module here (1.2k lines) |
| `src/matchreplace.rs` | Match-and-replace rules over requests and responses |
| `src/comparer.rs` | Diffing two messages |
| `src/logger.rs` | Request/response logging views |
| `src/organizer.rs` | Grouping and annotating captured items |

## For AI Agents

### No clock, no filesystem, no sockets — and that is the point

Timestamps are **parameters** (`logger::Started::started_ms`, `organizer::Organizer::add`) rather than
reads of `SystemTime`. This is mildly inconvenient at two call sites and it makes every test here
deterministic and every module trivially reusable from a context with its own idea of time.

If you find yourself wanting `SystemTime::now()` or `std::fs` in this crate, that is a signal the
responsibility belongs to a caller. Thread the value in.

### Testing Requirements

```bash
cargo test -p burpsy-tools      # 77 tests
```

Because there is no I/O, every test is a pure function call — there should be no fixtures, no temp
directories, and no sleeps in this crate's tests.

### Common Patterns

- Codec probing uses a named function-pointer array type rather than an inline type, so the table reads
  as a table.
- Transformations are total where they can be: an undecodable input yields a stated failure, not a
  silently unchanged buffer.

## Dependencies

### Internal

- `burpsy-core` — `StoredMessage`, `Span`, the message model being transformed

### External

- `flate2`, pinned `default-features = false, features = ["rust_backend"]` — the one job here that
  earns a dependency. A correct inflate is a few thousand lines of Huffman decoding, and getting it
  wrong on attacker-controlled bytes is a memory-safety bug rather than a cosmetic one. `rust_backend`
  resolves to `miniz_oxide`: pure Rust, no C toolchain, no libz. Pinned explicitly so a future default
  change cannot pull in a `cc` build.
  This is also how `crc32fast` is already in the workspace lockfile transitively, which is why
  `burpsy-core` depending on it directly added no new supply-chain surface.
- `regex` — pattern matching in match-and-replace
- `bytes`, `serde`, `serde_json`, `parking_lot`

<!-- MANUAL: -->
