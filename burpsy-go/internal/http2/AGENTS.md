<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# http2

## Purpose

HTTP/2 framing, HPACK, deliberate malformation, and HTTP/1-shaped normalisation — pure functions
over bytes, no sockets. It exists for request-smuggling research: a compliant library corrects or
refuses the very constructs this package must emit and inspect, and it cannot tell you *which* rules a
probe broke. The compliant HTTP/2 path itself runs on `golang.org/x/net/http2`; this layer does not
replace it, it sits a level down.

## Key Files

| File | Description |
|------|-------------|
| `frame.go` | `FrameHeader`, `FrameSpec`, `H2FrameProgram`, `RawFrame`, `Tail`, `ReadFrames`, `StripPreface`, `TypeName`. The writer corrects nothing: a dishonest declared length or an even client stream id is emitted as written |
| `hpack.go` | `Decoder`, `Encoder`, `HeaderField`, `HpackError` — a hand-rolled HPACK codec that will decode a malformed block rather than reset the stream, which `x/net/http2/hpack`'s conformant decoder will not do |
| `malformed.go` | `Malformation`, `MalformationKind`, `Violation`, `ViolationKind`, `Audit` — a vocabulary for breaking the spec on purpose plus a report naming every rule broken, with its RFC section |
| `authorise.go` | `Authorise`, `Authorisation`, `ProgramRequest`, `Refusal`/`RefusalKind`, `ProgramVerdict` — decodes a program's header blocks so `:authority`/`:path` can be checked, or refuses by name when it cannot be decided |
| `normalise.go` | `RenderRequest`/`RenderResponse` (h2 exchange → HTTP/1-shaped bytes), `Header`, `HeadersFromHTTP`, `IsHopHeader` |
| `parse.go` | `IsHTTP2Request`, `ParseRequest`, `ParsedRequest` — reads `RenderRequest`-shaped bytes back into fields |

## For AI Agents

- **No sockets, deliberately.** Nothing here opens a connection; `internal/sender` is the one
  authorising path out. `malformed.go` states this explicitly: nothing in `internal/sender` or
  `internal/proxy` calls `Audit` or `Encode`, because a program with a dishonest length or raw
  header-block fragment cannot have its `:path` authorised (the peer will not decode what we decoded).
  `Audit` is the capability an operator can actually reach from here; an emitted program has no route
  to a socket, and saying otherwise would be an overclaim.
- **The writer preserves; `malformed` names intent.** `FrameSpec` fields can be set to anything and
  are emitted verbatim, so an illegal frame is already possible. `Malformation` (e.g.
  `ClearFlags(FlagEndHeaders)`, `DeclareLength(n)`) exists so a *deliberate* malformation is
  distinguishable from an accidental one, and `Audit` names every rule broken so a `RST_STREAM` can be
  attributed. Applying a `Malformation` never refuses and never touches an unnamed field.
- **Two corrections cannot be removed, only reported.** The length field is 24 bits, so a
  `DeclaredLen` above the max loses its top bits and an over-long payload cannot be described
  honestly; `ViolationLengthFieldOverflowed` and `ViolationPayloadExceedsLengthField` report the one
  place the writer cannot do as told rather than hiding it.
- **`Audit` judges client-to-server only.** An even stream id (`ViolationEvenStreamIDFromClient`) and
  a PUSH_PROMISE (`ViolationPushPromiseFromClient`) are violations because this layer only emits the
  client direction; the mirror rule set for captured server frames does not exist here.
- **Go-vs-Rust shape difference (recorded in `malformed.go`).** Rust's `Malformation`/`Violation` are
  enums with per-variant fields; Go has no such thing, so a `Malformation` is a struct with a `Kind`
  discriminator and flat fields, and a `Violation` for a `Kind` with no frame index still has a
  zero-valued `Frame`. Because every field is comparable, a `Violation` compares with `==`.
- **Byte-exact emission, not byte-exact header replay.** `normalise.go` renders an h2 exchange into
  HTTP/1-shaped bytes so history and every existing tool keep working; `Content-Length` is
  recomputed and re-emitted. Replaying a captured HEADERS block against a different peer decodes to
  something else, because HPACK octets index a dynamic table both endpoints built together — there is
  no h2 analogue of HTTP/1 Repeater's byte-exact resend for headers. What is preserved is the ordered
  header list (duplicates, casing, pseudo-header order).
- **`ParseRequest` refuses a message with no `Host` header** and strips `Content-Length` on both
  render and parse, so the recomputed length is the only one that survives.

## Testing Requirements

```bash
go test ./internal/http2/...
```

No sockets means no network in tests — everything is byte vectors.

## Dependencies

### Internal

None. This is a leaf; `internal/sender` depends on it.

### External

Standard library only (`bytes`, `fmt`, `strings`, `textproto`). The framing and HPACK error types
are hand-rolled — the point is a pure byte package that does not pull in a runtime-heavy or
conformant HTTP/2 surface.
