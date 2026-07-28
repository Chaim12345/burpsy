# Phase 2 (HTTP/2) — Library Research

**Scope:** Rust HTTP/2 + HPACK crate landscape for burpsy's dual requirement: correct h2 for
ordinary proxy/resend, and deliberately malformed h2 for request-smuggling/desync research.
**Research only.** No files under `crates/` were touched. This document supersedes and closes the
open "h2 unstable frame-constructor validation depth" gap flagged in
`.planning/research/STACK.md` — that gap is now answered from primary source, not assumed.

**Method note:** every version/download/date claim below comes from one of: the vendored source
under `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/` (read directly), `cargo add
--dry-run --package burpsy-tools <crate>` run from `/root/burpsy` (resolves against the live
crates.io index without modifying any file), the crates.io JSON API (`https://crates.io/api/v1/crates/<name>`),
or `gh api` against GitHub. Every claim is tagged `[VERIFIED: source]` or `[ASSUMED]`. Today's date
for freshness/staleness judgments is 2026-07-28.

---

## Recommendation

**Use `h2` 0.4.15 with the `unstable` Cargo feature, scoped to the smallest crate that needs it,
for everything except hand-crafted HPACK header blocks.** For the narrow slice of malformed-HPACK
research that needs caller-chosen indexing/Huffman/ordering, hand-roll a minimal encoder (RFC 7541's
primitives are small and static) rather than depending on any of the four standalone HPACK crates
surveyed — all four are stale, thin, or both. rustls's existing ALPN API (already in the tree, no
new dependency) answers requirement H2-04 directly.

**Answer to "can h2 emit malformed frames?": yes, but only frame-header-level and stream-id-level
malformation, and only by bypassing `Codec`'s `Sink` and writing raw bytes.** Confirmed directly
against the vendored source (not inferred):

- `frame::Head::encode(&self, payload_len: usize, dst: &mut T)` takes `payload_len` as a bare,
  caller-chosen `usize` with **no validation** that it matches the number of payload bytes actually
  written afterward — only a `debug_assert!` on destination capacity, which is compiled out in
  release builds. A caller can write a 9-byte frame header claiming any length, then write a
  different number of payload bytes, directly to the socket. `[VERIFIED: h2-0.4.15 src/frame/head.rs]`
- `frame::StreamId::from(u32)` only panics if the **reserved top bit** is set
  (`assert_eq!(src & STREAM_ID_MASK, 0, ...)`); it does **not** reject `0` or even values. `[VERIFIED:
  h2-0.4.15 src/frame/stream_id.rs]`
- `frame::Headers::new(stream_id, pseudo, fields)` performs **no stream-id assertion at all**, so
  `Headers::new(StreamId::from(0), ...)` or an even client-initiated id both construct successfully
  and can be handed straight to `Codec::buffer()` / `Sink::start_send`, which does not re-validate
  parity/zero before encoding and sending. (Contrast: `frame::Data::new()` *does*
  `assert!(!stream_id.is_zero())` — that one frame type panics on stream 0 at construction; `Headers`
  does not.) `[VERIFIED: h2-0.4.15 src/frame/headers.rs, src/frame/data.rs]`
- HPACK-level malformation (chosen indexing, chosen Huffman on/off, chosen pseudo-header order) is
  **not reachable through h2 at all, even under `unstable`** — see "Capability question 2" below.
  This is the one place this research corrects rather than confirms STACK.md's optimistic framing.

---

## Decision Table

| Need | Recommendation | Why | Confidence |
|---|---|---|---|
| Well-formed h2 client + server (proxy, resend/Repeater) | `h2` 0.4.15, default features (no `unstable` needed for this half) | Correct-by-construction; 710M+ downloads, hyperium/tokio-rs org, actively released `[VERIFIED: crates.io API]` | HIGH |
| Malformed **frame headers** (lying length, illegal/reused stream id, undefined frame type, reserved bits) | `h2` 0.4.15 + `unstable` feature, using `frame::Head`/`frame::StreamId`/`frame::Headers` directly, writing raw bytes past `Codec`'s Sink | Confirmed via source: these constructors do not validate what this feature needs to violate `[VERIFIED, see above]` | HIGH |
| Malformed **HPACK header blocks** (chosen indexing/Huffman/pseudo-order, CONTINUATION-flood shapes) | Hand-roll a minimal HPACK encoder (~150-300 lines); do **not** add a standalone HPACK crate | h2's own HPACK types are permanently crate-private (not just gated by `unstable`) — unreachable regardless of feature flags `[VERIFIED, see below]`. All 4 standalone HPACK crates surveyed are stale/thin (see per-crate detail) | HIGH on the h2-unreachability claim; MEDIUM on "hand-roll is better than forking fluke-hpack" (engineering judgment, not sourced) |
| Decoding a hostile/attacker-influenced header block without crashing | `h2`'s own decode path (used internally by `Codec`/`proto`) returns `Result` for the malformed cases reviewed, with one narrow residual `panic!` in dynamic-table bookkeeping and a **separate, more reachable panic risk in burpsy's own code** if it calls the exposed low-level `Head::parse`/`StreamId::parse` on attacker bytes shorter than 9/4 bytes without a length guard | See "What the implementation must not promise" | MEDIUM — panic surface reviewed, not exhaustively fuzzed |
| Standalone frame codec (no full connection state machine) | `h2`'s `frame` module *is* this, once `unstable` is on — `Head`, `Headers`, `Data`, `Settings`, etc. can be constructed/parsed independently of `proto`'s connection state machine | Directly confirmed by module structure: `frame` and `proto` are separate, both gated by the same `unstable` flag, but nothing forces using `proto` to touch `frame` | HIGH |
| ALPN negotiation (ordinary + honest downgrade detection, H2-04) | `rustls` 0.23.42 / `tokio-rustls` 0.26.4, already in the tree — no new dependency | `ClientConfig`/`ServerConfig::alpn_protocols` + `CommonState::alpn_protocol()`, see dedicated section below | HIGH — verified against vendored source |
| hyper with h2 enabled | Not viable for this feature; do not add | Sits a layer above `h2` specifically to hide framing (axum/hyper already in the tree, and h2 is currently **absent** from `Cargo.lock` — hyper's `http2` feature isn't enabled anywhere today) | HIGH |
| `fluke` / `h2-sans-io` as a shortcut | Not recommended today | Both are single-maintainer, low-download, and (for `h2-sans-io`) 5 months old; see supply-chain section | HIGH on the legitimacy call |

---

## Per-Crate Detail

### `h2` (hyperium/h2) — the well-formed layer, and the frame-header malformation layer

- **Version resolved:** 0.4.15 `[VERIFIED: cargo add --dry-run --package burpsy-tools h2, and matches
  crates.io max_stable_version]`
- **First published:** 2017-03-09 `[VERIFIED: crates.io API]`
- **Latest release date:** 2026-06-15 `[VERIFIED: crates.io API, updated_at]`
- **Downloads:** 710,992,689 all-time; 150,842,739 in the trailing 90 days per crates.io's
  `recent_downloads` field, which is **not** a literal weekly figure — dividing by ~12.86 weeks gives
  a derived estimate of roughly **11.7M/week** `[VERIFIED: crates.io API for the raw numbers;
  weekly figure is ASSUMED/derived by this document, not a field crates.io exposes directly]`
- **Source repo:** https://github.com/hyperium/h2 `[VERIFIED]`
- **MSRV:** `rust-version = "1.63"` `[VERIFIED: vendored Cargo.toml at
  ~/.cargo/registry/src/.../h2-0.4.15/Cargo.toml]`
- **Maintenance:** hyperium org (same authors/org as `hyper`/`tokio`), actively released. Already
  compatible with the workspace's `http = "1.4.2"` (h2 requires `http = "1.1"`) `[VERIFIED: Cargo.lock]`.
- **Not currently in the dependency graph:** `grep -c '^name = "h2"' Cargo.lock` returns 0 — despite
  `hyper` 1.11.0 already being present (pulled in by `axum` 0.8.9 in `crates/web`), nothing in the
  workspace currently enables hyper's `http2` feature, so h2 has never been resolved. Adding it
  directly is a clean new edge, not a version-unification problem `[VERIFIED: Cargo.lock, grep]`.

**Capability question 1 — can it emit a frame the spec forbids?**
Yes, at the frame-header/stream-id level, confirmed directly from source (see Recommendation section
above for the three concrete mechanisms: `Head::encode`'s unchecked `payload_len`, `StreamId::from`'s
narrow assert, `Headers::new`'s absence of any stream-id assert). The **visibility mechanism** that
makes this reachable at all:
- `src/lib.rs`: `mod codec;` and `mod hpack;` are private by default; `#[cfg(feature = "unstable")]
  pub mod frame;` and `#[cfg(feature = "unstable")] pub mod proto;` make those two modules public
  only under `unstable`; `#[cfg(feature = "unstable")] pub use codec::{Codec, SendError,
  UserError};` re-exports the codec types at the crate root, also only under `unstable`
  `[VERIFIED: h2-0.4.15 src/lib.rs lines 108-140]`.
- Without `unstable`, none of `frame`, `proto`, or `Codec` are nameable from outside the crate at
  all — this is the entire reason STACK.md correctly ruled out stable `h2` for the malformed-frame
  feature.
- The everyday, non-malformed send path (`Codec` as `Sink<Frame<B>>`) *does* compute lengths
  correctly and automatically: `EncodingHeaderBlock::encode()` writes a zero-length placeholder
  header, writes the payload, then patches the real 3-byte length back in
  `[VERIFIED: src/frame/headers.rs "impl EncodingHeaderBlock"]`. To emit a lying length you must
  skip `Codec`'s `Sink` and call `Head::new(...)`/`Head::encode(payload_len, dst)` yourself with
  your own `AsyncWrite`, writing a different number of actual bytes — exactly the "~10-line
  hand-rolled frame-header writer" STACK.md already anticipated, now confirmed as the concrete,
  necessary mechanism rather than a guess.

**Capability question 2 — can HPACK be driven manually?**
**No — and this is a correction, not a confirmation, of STACK.md's framing**, which treated this as
an open gap ("Gap: h2 unstable frame-constructor validation depth... needs a small spike"). That
spike is this review, and the answer is definitive:
- `src/lib.rs` has `mod hpack;` with **no** `#[cfg(feature = "unstable")] pub mod hpack;` variant
  anywhere — unlike `frame`/`proto`, the `hpack` module has no public form at any feature
  configuration `[VERIFIED: h2-0.4.15 src/lib.rs, full grep for "mod hpack"]`.
- `src/hpack/mod.rs` does `pub use self::decoder::{Decoder, DecoderError, NeedMore}; pub use
  self::encoder::Encoder; pub use self::header::{BytesStr, Header};` — but under Rust's visibility
  rules, an item is only reachable from outside a crate if **every** module in its path is public.
  Since the containing `hpack` module itself is private, `Encoder`/`Decoder`/`Header` are **not
  part of the public API at any feature configuration**, regardless of the `pub use` inside
  `[VERIFIED: h2-0.4.15 src/hpack/mod.rs]`. Only `BytesStr` escapes, via a second re-export:
  `src/frame/mod.rs` (which *is* `pub` under `unstable`) has `pub use crate::hpack::BytesStr;` —
  that one type only `[VERIFIED: h2-0.4.15 src/frame/mod.rs line 66]`.
- Confirmed this isn't just a naming/reachability technicality by reading what `Encoder::encode()`
  actually does even if you *could* call it: it fully automates the indexing decision through an
  internal `Table` lookup (`self.table.index(header)` → `Index::Indexed`/`Name`/`Inserted`/
  `InsertedValue`/`NotIndexed`), and `encode_str()` **unconditionally** Huffman-encodes every
  non-empty string with no plain-literal branch in the public function. The only caller-influenceable
  axis is `HeaderValue::set_sensitive(true)` (forces the RFC 7541 §6.2.3 "never indexed" literal
  representation) — everything else (indexed-vs-literal, Huffman on/off) is the encoder's decision,
  not the caller's `[VERIFIED: h2-0.4.15 src/hpack/encoder.rs, full file read]`.
- Pseudo-header emission order is hardcoded, not configurable: `frame::headers::Iter::next()`
  drains a fixed sequence — method, scheme, authority, path, protocol, status — before regular
  fields, unconditionally `[VERIFIED: h2-0.4.15 src/frame/headers.rs "impl Iterator for Iter"]`.
- `Headers::encode(self, encoder: &mut hpack::Encoder, dst)` is `pub`, but its second parameter type
  is the same unreachable `hpack::Encoder` — an external caller cannot even name a value of that
  type to pass in, so this function is uncallable from outside the crate regardless of the `pub`
  keyword `[VERIFIED: h2-0.4.15 src/frame/headers.rs line 277]`.
- **Bottom line:** the only way to produce HPACK-encoded bytes with h2 at all is `Codec`'s
  `Sink<Frame<B>>`, which owns the encoder invisibly and makes every encoding decision itself. There
  is no lever, public or private-but-reachable, for chosen indexing/Huffman/pseudo-order. Anything
  needing that must come from outside h2 entirely — hand-rolled or a different crate.

**Capability question 3 — decode hostile input without panicking?**
Reviewed `src/hpack/decoder.rs` and `src/hpack/huffman/` for `panic!`/`unwrap`/`expect`/`assert*`
outside `#[cfg(test)]`:
- Exactly one production `panic!` found: `src/hpack/table.rs` (via decoder.rs's dynamic-table
  consolidation), `"Size of table != 0, but no headers left!"` — an internal bookkeeping invariant
  check inside `consolidate()`, reached from `queue_size_update`/`set_max_size` when decoding a
  Dynamic Table Size Update instruction. Nothing in this review found a byte sequence that violates
  the invariant (the surrounding `insert`/`reserve` logic appears to maintain it correctly), but it
  is a live `panic!`, not a returned `DecoderError`, so it is not fully ruled out as a DoS vector by
  static reading alone `[VERIFIED: h2-0.4.15 src/hpack/decoder.rs line 572, source read; NOT fuzzed]`.
- Every other malformed-input path reviewed (invalid table index 0, out-of-range dynamic table
  index, invalid UTF-8, invalid header value) returns `Result<_, DecoderError>`
  `[VERIFIED: same file]`.
- **A separate and more directly relevant risk for this project specifically:** the low-level,
  `unstable`-exposed `frame::Head::parse(header: &[u8]) -> Head` indexes `header[3]`, `header[4]`,
  and calls `StreamId::parse(&header[5..])`, which itself does `let mut ubuf=[0;4];
  ubuf.copy_from_slice(&buf[0..4]);` — **none of this checks the input slice's length first**. In
  ordinary `Codec` usage this is safe because h2's internal `FramedRead` loop always buffers exactly
  `HEADER_LEN` (9) bytes before calling `Head::parse` — but that guarantee lives in the *caller*
  (h2's internal framing loop), not in `Head::parse` itself `[VERIFIED: h2-0.4.15 src/frame/head.rs,
  src/frame/stream_id.rs, src/frame/mod.rs "pub const HEADER_LEN: usize = 9"]`. **If burpsy writes
  its own raw-frame reader against attacker-controlled bytes** — which the malformed-frame research
  feature's receive side plausibly needs, e.g. to inspect how a target mis-parses its own malformed
  responses — calling `Head::parse`/`StreamId::parse` on a slice shorter than 9/4 bytes will panic
  (index-out-of-bounds / `copy_from_slice` length mismatch), not return an error. This guard is
  burpsy's own responsibility to add; h2 does not provide it at this layer.

**Capability question 4 — usable standalone frame codec?**
Yes. Under `unstable`, `frame` (types: `Head`, `Kind`, `Headers`, `Data`, `Settings`, `Ping`,
`GoAway`, `Reset`, `WindowUpdate`, `Priority`, `Continuation`, `StreamId`, the `Frame<T>` enum) is a
separate public module from `proto` (the connection state machine) — both are gated by the same
`unstable` flag but nothing requires using one to use the other `[VERIFIED: h2-0.4.15 src/lib.rs]`.
This *is* the "standalone frame codec, separate from a full connection state machine" the task asks
about — it does not need to be sourced from elsewhere.

**Capability question 5 — ALPN ownership?**
h2 assumes ALPN has already happened; it has no ALPN-related code at all (not searched further given
this is a well-known, uncontested fact about h2's scope — it operates purely on an already-negotiated
byte stream). ALPN is entirely owned by the TLS layer (`rustls`/`tokio-rustls` here) — see the
dedicated section below.

---

### The four standalone HPACK crates — none recommended as a live dependency

| Crate | Version | First published | Latest release | Downloads (total / 90-day) | Repo | Verdict |
|---|---|---|---|---|---|---|
| `hpack` | 0.3.0 | 2015-03-13 | **2015-12-16** | 1,448,966 / 102,185 | github.com/mlalic/hpack-rs | Abandoned ~10.5 years. Do not use. |
| `hpack-patched` | 0.3.0 | 2023-09-15 | 2023-09-15 (only release ever) | 36,426 / 13,117 | github.com/sno2/hpack-rs-patched | Single release, single maintainer, ~2.9 years with no follow-up. Thin patch fork, not a maintained project. |
| `fluke-hpack` | 0.3.1 | 2023-10-03 | 2024-05-28 | 219,962 / 81,284 | github.com/bearcove/fluke | Best of the four (forked specifically to pass h2spec conformance), but ~2y2m stale as of 2026-07-28 and tied to `fluke`, itself effectively stalled (see below). |
| `httlib-hpack` | 0.1.3 | 2020-10-15 | 2020-11-17 | 56,183 / 21,881 | github.com/xpepermint/httlib-rs | ~5.7 years stale. Corroborates STACK.md's prior "~5 years stale" claim independently. Do not use. |

`[VERIFIED: crates.io API for every field in this table; all four fetched directly]`

All four fail this project's own stated legitimacy bar (the one applied to `crc32fast`/`memmap2`):
none is under active maintenance, and the newest (`fluke-hpack`) is a small side-project of a
larger, itself-stalled experimental HTTP stack. **If a phase-4 spike concludes a standalone HPACK
crate really is necessary** (rather than hand-rolling, see Recommendation), `fluke-hpack` is the
least-bad choice — vendor/fork it rather than take a live `^0.3` dependency on a project with no
release in over two years, so an upstream disappearance doesn't silently break the build.

**`fluke` itself** (the parent project, not just its HPACK sibling): 0.1.1, first published
2023-10-03, last updated 2024-05-28, only 2,907 total downloads — an experimental io_uring-based
HTTP implementation, not something burpsy would depend on directly; only surfaced here because it's
the origin of `fluke-hpack` and because STACK.md cited it as a "standalone frame codec" precedent.
`[VERIFIED: crates.io API]`

---

### `h2-sans-io` — exists, not recommended (too young)

Surfaced during this research as directly on-topic (description: "A minimal, sans-I/O HTTP/2 frame
codec for WASM and async-free environments") and matching the task's "standalone frame codec"
question almost exactly — but:
- **First published: 2026-02-15** — under 6 months old as of today `[VERIFIED: crates.io API]`
- **Downloads: 940 total, 476 in the trailing 90 days** `[VERIFIED: crates.io API]`
- **Single maintainer** (GitHub user `ariel42`), repo `github.com/ariel42/h2-sans-io`
  `[VERIFIED: crates.io API owner/repo field]`

This is exactly the profile the task asks to flag: young, low-download, single-maintainer, no track
record. Interesting to know it exists (the "sans-IO" pattern is the right shape for a codec that
needs to emit malformed bytes without a connection state machine in the way), but not recommendable
today by this project's own stated bar. Worth a second look in a year if it gains adoption.

---

### `hyper` with h2 enabled

Not independently re-researched in depth here — STACK.md already covered this correctly ("hyper's
h2 support sits a layer above h2 specifically to hide framing details — the opposite of what's
needed") and this review's own findings about h2 reinforce rather than contradict it: h2 itself
already hides its HPACK internals from *everyone*, including `unstable`-feature h2 callers; hyper
(which doesn't expose h2's `unstable` feature or raw frames at all) cannot expose more than its own
foundation does. `hyper` 1.11.0 is already resolved in `Cargo.lock` (pulled in by `axum` 0.8.9 in
`crates/web`), but confirmed via `grep -c '^name = "h2"' Cargo.lock` → 0 that **h2 is not currently
part of the build at all** — hyper's `http2` Cargo feature isn't enabled anywhere in the workspace
today `[VERIFIED: Cargo.lock direct read]`.

---

## `rustls` ALPN mechanics (H2-04) — verified against the vendored source in this tree

Versions in the workspace today: `rustls` 0.23.42, `tokio-rustls` 0.26.4 (both already workspace
dependencies in `crates/proxy/Cargo.toml` and `crates/sender/Cargo.toml`)
`[VERIFIED: Cargo.lock, crates/proxy/Cargo.toml, crates/sender/Cargo.toml]`. MSRV of both:
`rust-version = "1.71"` in each vendored `Cargo.toml` `[VERIFIED]`.

**Offering both protocols, both sides:**
- `rustls::ClientConfig::alpn_protocols: Vec<Vec<u8>>` — public field
  `[VERIFIED: rustls-0.23.42/src/client/client_conn.rs:167]`
- `rustls::ServerConfig::alpn_protocols: Vec<Vec<u8>>` — public field
  `[VERIFIED: rustls-0.23.42/src/server/server_conn.rs:338]`
- Set both to `vec![b"h2".to_vec(), b"http/1.1".to_vec()]` (order matters — see selection logic
  below).

**Selection logic — server preference wins, not client preference (a fact worth stating precisely,
since it's easy to assume the opposite):**
`src/server/hs.rs::process_common()` iterates the **server's own** `alpn_protocols` list, in the
server's configured order, and returns the first entry that also appears anywhere in the client's
offered list:
```rust
cx.common.alpn_protocol = our_protocols
    .iter()
    .find(|ours| their_protocols.iter().any(|theirs| theirs.as_ref() == ours.as_slice()))
    .map(|bytes| ProtocolName::from(bytes.clone()));
```
`[VERIFIED: rustls-0.23.42/src/server/hs.rs lines 98-108]`. So: to prefer h2 whenever a connecting
client supports it at all, list `h2` before `http/1.1` in **`ServerConfig::alpn_protocols`** — the
client's own ordering in its ClientHello is not what decides the outcome against this server.

**Hard-fail vs. silent no-negotiation — the distinction the H2-04 requirement needs:**
- If the server's `alpn_protocols` is non-empty **and** the client did send an ALPN extension, but
  no overlap exists, rustls sends a fatal TLS alert (`AlertDescription::NoApplicationProtocol`) and
  the handshake **errors** — this is a hard failure, not a silent fallback
  `[VERIFIED: rustls-0.23.42/src/server/hs.rs lines 114-118]`.
- If the client did **not** send an ALPN extension at all (`hello.protocols` is `None`), the whole
  block is skipped and `alpn_protocol` simply stays `None` — the handshake proceeds normally. This
  is the legitimate "target doesn't do ALPN" case, and it is the one an implementation must detect
  explicitly and treat as "fall back to HTTP/1.1 honestly," rather than assuming h2 succeeded just
  because the handshake didn't error.

**Reading back what was actually negotiated, after the handshake:**
- `rustls::CommonState::alpn_protocol(&self) -> Option<&[u8]>` — the exact accessor
  `[VERIFIED: rustls-0.23.42/src/common_state.rs:148]`.
- `tokio_rustls::TlsStream<T>` (the unified enum wrapping both `client::TlsStream<T>` and
  `server::TlsStream<T>`) exposes `pub fn get_ref(&self) -> (&T, &CommonState)`
  `[VERIFIED: tokio-rustls-0.26.4/src/lib.rs:81]`. So, on either the client or server accept path:
  ```rust
  let (_io, common) = tls_stream.get_ref();
  match common.alpn_protocol() {
      Some(b"h2") => { /* speak HTTP/2 */ }
      Some(b"http/1.1") => { /* speak HTTP/1.1 */ }
      Some(other) => { /* unexpected — treat as error, do not guess */ }
      None => { /* no ALPN exchanged at all — fall back to HTTP/1.1, and log it as a real
                   downgrade rather than silently proceeding as if h2 had been requested */ }
  }
  ```
  This is the precise mechanism requirement H2-04 needs to avoid a silent downgrade: check
  `alpn_protocol()` explicitly rather than inferring protocol from handshake success alone.
- Client-side equivalent confirmed too: `src/client/hs.rs::process_alpn_protocol()` sets
  `common.alpn_protocol = selected.map(ToOwned::to_owned)` from the server's `ServerHello` ALPN
  extension `[VERIFIED: rustls-0.23.42/src/client/hs.rs lines 597-606]` — same `CommonState`
  accessor reads it back on the client side.

---

## What the implementation must not promise

**1. It must not promise decoding never panics.** h2's own HPACK decoder (used internally by
`Codec`/`proto` on received bytes, even though the `Decoder` type itself is unreachable from outside
the crate) is `Result`-returning for the malformed-input paths this review checked, with one narrow
exception: a `panic!` in dynamic-table-size-update bookkeeping (`src/hpack/table.rs`,
`"Size of table != 0, but no headers left!"`) that was not proven unreachable, only not found to be
reachable in this review. Separately, and more concretely: **if burpsy hand-rolls its own frame
reader** using the exposed low-level `frame::Head::parse`/`frame::StreamId::parse` (which the
malformed-frame research feature's receive/inspection side plausibly needs), those functions index
raw byte slices with **no length check** and will panic on inputs shorter than 9 (resp. 4) bytes.
h2 does not guard this for a caller who bypasses `Codec`; burpsy's own code must add the length
check itself before calling them, on every code path that hands them attacker-influenced bytes.

**2. It must not promise byte-exact replay of a captured h2 request — the honest answer, not
softened.** HPACK's dynamic table is connection-scoped, mutable, and order-dependent: whether a
given header is encoded as an indexed reference, a literal-with-indexed-name, or a full literal
depends on what has already been inserted into *that specific connection's* table by prior header
blocks — confirmed directly in `h2`'s own encoder (`self.table.index(header)` consults a `Table`
that is intrinsic, mutable, per-`Encoder`-instance state; the same logical header list produces
different bytes depending on that state). Concretely, for burpsy specifically:
- **Capturing already re-encodes once.** burpsy's proxy terminates HTTP/2 on both sides — it is a
  server to the client and a client to the server, not a byte-for-byte relay. Forwarding a captured
  request necessarily means decoding the client's HPACK block (against the client-connection's
  table) and re-encoding a new HPACK block (against the server-connection's own, independent table)
  to send it onward. The bytes captured in history are therefore already the *proxy's own*
  re-encoding, not the original client's wire bytes, before any replay feature even runs.
- **Resending (Repeater) re-encodes again, against whatever table state exists at resend time** —
  on a new connection (empty table, so every header re-encodes as if for the first time,
  independent of how the original was encoded) or, in principle, the same still-open connection
  (table state has moved on by however many other header blocks were exchanged since capture,
  including from unrelated concurrent streams on that same connection).
- **What can honestly be preserved:** the *logical* header list — names, values, and (if the
  implementation chooses to preserve it explicitly, since h2's automatic pseudo-header ordering is
  fixed rather than replayable-as-captured) pseudo-header order. What **cannot** be promised is
  identical on-wire HPACK bytes (index numbers, indexed-vs-literal choices, Huffman-encoded lengths)
  across a decode/re-encode boundary. The implementation should describe its replay guarantee as
  "same headers, same values, same order" — never as "the same bytes," because the same bytes are
  not achievable in principle once a dynamic table is involved, not merely as an unimplemented
  feature.

**3. It must not promise caller-controlled HPACK indexing/Huffman/ordering via `h2` at any feature
configuration.** This was an open question in STACK.md; it is now closed. `h2`'s HPACK module is
permanently private regardless of Cargo features, its encoder makes every indexing and Huffman
decision internally, and pseudo-header emission order is hardcoded. Any feature promising "operator
chooses indexed vs. literal vs. never-indexed, Huffman on/off per field, and pseudo-header order"
needs code written outside `h2` — hand-rolled per the Recommendation above, not sourced from any
crate surveyed here without first forking it to strip out exactly this automation.

---

## Corrections to prior research (flagged explicitly, per this project's own freshness standard)

- **STACK.md's claim that GitHub issue hyperium/h2#294 "remains open/unresolved" is incorrect.**
  Verified via `gh api repos/hyperium/h2/issues/294`: the issue was **closed on 2019-02-22**, with
  the reporter commenting "We found a different way of doing things so at least to me, this issue
  is resolved" `[VERIFIED: gh api, direct GitHub API read]`. The issue's resolution has no
  connection to h2's later `unstable` Cargo feature (added independently) — it was closed because
  the original requester solved their own problem differently, not because hyperium added the API
  being requested. This does **not** change this document's own recommendation, which was verified
  independently against the vendored source (Cargo.toml `[features] unstable = []`, and the
  `#[cfg(feature = "unstable")]` gates in `lib.rs`) rather than through the issue tracker — but the
  issue-tracker citation itself should not be reused as evidence in future research.

---

## Supply-chain legitimacy summary

Applying the same bar this project already used for `crc32fast`/`memmap2`:

| Crate | Verdict | Basis |
|---|---|---|
| `h2` 0.4.15 | **Passes, comfortably.** Same tier as `crc32fast`/`memmap2` or higher. | 710M+ downloads, 9-year-old hyperium project, actively released `[VERIFIED]` |
| `rustls` 0.23.42 / `tokio-rustls` 0.26.4 | Already in the tree; no new legitimacy question. | n/a |
| `hpack` 0.3.0 | **Fails.** Abandoned ~10.5 years. | `[VERIFIED: crates.io]` |
| `hpack-patched` 0.3.0 | **Fails.** One release ever, single maintainer, ~2.9 years silent since. | `[VERIFIED: crates.io]` |
| `fluke-hpack` 0.3.1 | **Marginal — fork/vendor if used, don't take a live dependency.** Best of the four, but ~2y2m stale and tied to a stalled parent project. | `[VERIFIED: crates.io]` |
| `httlib-hpack` 0.1.3 | **Fails.** ~5.7 years stale. | `[VERIFIED: crates.io]` |
| `h2-sans-io` 0.9.2 | **Fails today.** 5 months old, 940 downloads, single maintainer. Revisit in a year. | `[VERIFIED: crates.io]` |
| `fluke` 0.1.1 | **Fails / not applicable.** Experimental, 2,907 downloads, stalled since 2024-05-28; not something to depend on directly. | `[VERIFIED: crates.io]` |
| `hyper` 1.11.0 | Legitimacy is fine (huge, well-established); architecturally wrong tool for this specific feature. | See "hyper with h2 enabled" section |

**Net recommendation for what to actually add:** `h2 = { version = "0.4", features = ["unstable"] }`,
scoped to the smallest crate that needs frame-level access, exactly as STACK.md already proposed —
this research adds the confirmation that its scope must stop at frame-header/stream-id
malformation, plus a hand-rolled (not dependency-sourced) HPACK path for header-block-level
malformation. No new HPACK crate is recommended for addition at this time.

---
*Library research for: Phase 2 (HTTP/2), burpsy*
*Researched: 2026-07-28*
