<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# tools

## Purpose

Pure byte and string transformations reused by the intruder, the proxy and the web UI: the human-facing Decoder/Hasher tools, the exact byte-level codecs the payload-processing chain runs on, and the budgeted message Comparer. Like the Rust `burpsy-tools` crate, everything here is a total function over bytes with no clock, filesystem or sockets — so every test is a plain function call. Unlike Rust, match-and-replace and the organizer are **not** here: they are their own Go packages (`internal/matchreplace`, `internal/organizer`).

## Key Files

| File | Description |
|------|-------------|
| `codec.go` | Byte-level encode/decode layers (`url`, `html`, `base64`, `base64url`, `hex`, `gzip`, `deflate`, `jwt`). `Decode`/`Encode`/`ParseLayer`/`AllLayers`; the byte transforms the intruder relies on |
| `comparer.go` | Myers diff between two messages at word or byte `Granularity`, with a per-size budget (`Diff`, `DiffWithBudget`, `DiffResult`). A line-for-line port of `crates/tools/src/comparer.rs` |
| `tools.go` | The human-facing `Decoder` (base64/hex/url/html/JWT/ASCII/ROT13/reverse), `Hasher` (MD5/SHA-1/SHA-256/SHA-512), `Compare`, and `Grep`/`ExtractRegex` |

## For AI Agents

- **A failed or partial decode is named, never passed through.** `codec.Decode` returns `([]byte, bool, error)`; the bool is the *truncated* flag (inflate hit `MaxInflate` = 64 MiB), and an undecodable input is a `*DecodeError`, not a silently unchanged buffer. The intruder is built on this: a rule that could not run must not look like a rule that ran and changed nothing.
- **`codec.go` byte semantics are lifted from Rust for byte-identity:** uppercase percent-encoding, `+` left untouched by `URLDecode` (the context-free primitive never guesses; a smart caller decides by context), tolerant base64, the 64 MiB inflate cap.
- **The Comparer's whole trick is the budget, not the diff.** `budgetFor` shrinks from a 2048 ceiling on small inputs to a 64 floor on large ones (~200 KB), so two large bodies differing in one place bail cheaply instead of running an O(n·m) diff. Do not remove the budget to "get a complete diff".
- **Two decode surfaces coexist on purpose:** `tools.go`'s `Decoder` is a string-based convenience; `codec.go` is the exact byte layer. They are not redundant — do not collapse one into the other.
- **No external crypto/compression dependency.** Where Rust pulls in `flate2`, `md-5`, `sha1`, `sha2`, the Go port uses the standard library (`compress/flate|gzip|zlib`, `crypto/md5|sha1|sha256|sha512`). This is a real Rust↔Go divergence worth knowing.

## Testing Requirements

```bash
go test ./internal/tools/...
```

Tests are pure function calls — no fixtures, temp dirs or sleeps. Many name their Rust source directly (e.g. `TestURLDecodeLeavesPlusAloneSoBase64InAQuerySurvives` ports the Rust test of the same name), and `comparer_test.go` rebuilds `b` from the diff ops to prove the spans.

## Dependencies

- Internal: `internal/core` (`comparer.go` uses `core.Span`). `codec.go` and `tools.go` are stdlib-only.
- External: none beyond the Go standard library.
