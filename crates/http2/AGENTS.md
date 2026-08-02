<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-02 | Updated: 2026-08-02 -->

# http2 (`burpsy-http2`)

## Purpose

HTTP/2 framing, HPACK, and HTTP/1 normalisation — three jobs that live together because all three
are pure functions over bytes, and because a compliant library is incapable of any of them. The
crate's reason to exist includes request-smuggling research, which is exactly what compliant
libraries refuse to enable.

1. **A frame layer that corrects nothing** (`frame`), and a vocabulary for breaking the spec on
   purpose (`malformed`). Emitting a frame the spec forbids is a requirement here, not an escape
   hatch. A compliant library refuses — correctly — and also cannot tell you *which* rules your
   probe broke, which is `malformed::audit`'s job: an accidental malformation and a deliberate one
   produce the same `RST_STREAM`.
2. **HPACK** — because a compliant library will not *show* you a malformed header block either. It
   resets the stream before the octets reach you, and for a proxy whose reason to exist includes
   smuggling, seeing what a peer sent is worth as much as sending it. The external `h2` crate's
   encoder and decoder are unreachable from outside that crate at every feature configuration, so
   there is no third option.
3. **Normalisation** to and from an HTTP/1-shaped serialisation (`normalise::render_request` /
   `render_response`), so an h2 exchange sits in history in the same shape as an HTTP/1 one and
   every existing tool keeps working on it unchanged.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | Re-exports; the crate-level honesty argument lives here |
| `src/frame.rs` | `FrameHeader`, `RawFrame`, `H2FrameProgram`, `read_frames`, `strip_preface`, frame types |
| `src/hpack.rs` | `Decoder`, `Encoder`, `HpackError` |
| `src/malformed.rs` | `Malformation`, `Violation`, `audit` — names every rule a program breaks, with the RFC section |
| `src/normalise.rs` | HTTP/1-shaped serialisation both ways |

## For AI Agents

### No sockets, deliberately

Nothing here opens a connection. The one authorising path from a constructed request to a socket is
`burpsy_sender::AuthorisedSender`, and `crates/sender/tests/no_alternate_egress.rs` fails the build
if that changes. This crate produces and consumes bytes; something else decides whether they are
allowed to leave.

### The honest limit of "byte-exact"

Byte-exact **emission** is available. Byte-exact **replay of a captured header block** is not, and
any interface that implies it is lying. A HEADERS frame's octets encode indices into a dynamic table
the two endpoints built together over the life of the connection; replaying those octets against a
different peer, or the same peer at a different moment, decodes to something else. So "resend exactly
these bytes" — which HTTP/1 Repeater offers and which is meaningful there — has **no h2 analogue for
headers**.

What is total instead is **header-list-exactness**: the ordered list of fields, including duplicates,
unusual casing, and pseudo-headers in whatever order they appeared, is preserved and re-encodable.
For frames this crate emitted itself on a connection it owned from its first octet, the stronger
property does hold — the table starts empty and only we write to it, so a program's octets are a
pure function of the program.

### Testing Requirements

```bash
cargo test -p burpsy-http2      # 72 tests, all inline
cargo test --workspace
```

No sockets means no network in tests — everything is byte vectors.

## Dependencies

### Internal

None. This is a leaf — `sender` and `proxy` depend on it, it depends on nothing in the workspace.

### External

`bytes` — and nothing else. The framing error types are hand-rolled; the point is a pure byte crate
with no runtime-heavy surface.

<!-- MANUAL: -->
