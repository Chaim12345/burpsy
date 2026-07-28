# Phase 2: HTTP/2 — Design

**Written:** 2026-07-28
**Status:** Design only. No code in this document is intended to be typed as written.
**Requirements:** H2-01 (proxy/view/resend), H2-02 (same shape as HTTP/1), H2-03 (deliberately
malformed frames), H2-04 (use h2 when the target supports it)

## The problem, stated once

H2-03 requires emitting octets that violate RFC 9113 and RFC 7541. H2-01 and H2-04 require ordinary,
correct HTTP/2 on two proxy legs and one egress leg. A spec-compliant library refuses the first and is
very good at the second — and a hand-rolled stack is the reverse. Every design that pretends this is
one problem produces either a proxy that hangs a browser or a research tool that silently corrects the
payload you asked it to send.

The resolution below splits the work along **who owns the connection state machine**, not along
"correct versus malformed". That distinction is what makes one frame writer serve both requirements.

---

## 1. Decision: framing strategy

**Chosen: (b), drawn along the connection-ownership axis.**

| Surface | Who drives the connection | Who writes the frames |
|---|---|---|
| Egress (Repeater resend, Intruder, scanner, H2-03) | us — single-stream client in `sender` | our verbatim writer |
| Proxy client-facing leg (browser → burpsy) | the external `h2` crate, server half | the library |
| Proxy upstream leg (burpsy → target) | the external `h2` crate, client half | the library |
| Frame capture on both proxy legs | nobody — a passive tap | n/a, read-only |

Three claims make this coherent rather than a compromise:

**1. There is exactly one frame writer, and correctness is a property of its input.** The ordinary
resend path does not have its own encoder. An `H2Request` (ordered header list + body) is *lowered*
into an `H2FrameProgram` — preface, SETTINGS, one HEADERS with END_HEADERS, DATA with END_STREAM — and
that program goes through the same verbatim writer an operator's deliberately broken program goes
through. So the writer is exercised on every ordinary resend, not only on the research path. This is
the answer to the standard objection to (b): the two paths cannot drift, because below the lowering
function there is only one path.

**2. Owning the browser-facing h2 *server* buys no pentest capability.** That leg faces the operator's
own browser, which is a well-behaved h2 client that will nonetheless exercise SETTINGS negotiation and
acknowledgement, connection- and stream-level flow control on large uploads, CONTINUATION, priority,
GOAWAY on tab close, and `MAX_CONCURRENT_STREAMS` backpressure. A bug there manifests as a hung tab.
There is no smuggling technique we gain by writing it ourselves. This is the whole of the argument
against **(a) hand-rolled throughout** — not that HPACK is hard (it is not; see slice 2), but that a
bidirectional multiplexer with flow control on both legs is a phase of its own and pays nothing back.

**3. A compliant library cannot *observe* malformedness either, which is why the raw layer is not
optional and cannot be a shim over the library.** `h2` will RST_STREAM or GOAWAY on an uppercase header
name, a duplicate `:path`, a pseudo-header after a regular field, or CONTINUATION abuse — and we will
never see the bytes. For a proxy whose reason to exist includes request smuggling, *seeing* what a peer
sent is worth as much as sending it. The tap (slice 5) exists for exactly this: the library drives the
connection, our decoder reads the same octets, and the record is built from ours.

### The precedent, and where it stops transferring

`crates/sender/src/transport/net.rs:7-13` argues against `hyper` on the grounds that it "normalises
header casing and ordering, rewrites `Content-Length`/`Transfer-Encoding`, and rejects malformed
requests" [VERIFIED: read the doc comment]. Every clause of that transfers to the egress path and is
why the egress path is ours. **It does not transfer to the proxy legs, and the reason is HPACK.**

Under HTTP/1 "relay the client's own bytes" is achievable and the proxy does it — `rewrite_target` at
`crates/proxy/src/lib.rs:691` changes the request target and preserves every other byte, deliberately
[VERIFIED: read the function]. Under HTTP/2 there is no equivalent: a HEADERS frame's octets encode
indices into a dynamic table the two endpoints built together, so a proxy cannot forward a header block
it did not encode against *its own* peer's table state. Forwarding h2 means decoding and re-encoding,
whoever writes the code. The library therefore costs us nothing that a hand-rolled proxy would have
preserved.

### The stated cost of choosing (b)

- **The proxy is not byte-transparent for h2.** burpsy becomes a normalising element in the path. A
  test whose validity depends on the target receiving the browser's exact octets must use the egress
  frame-program path, not the proxy. This must be said in operator-facing text, because a tester who
  assumes transparency will attribute burpsy's re-encode to the target's front end.
- **Two frame-layout implementations exist in the dependency graph** — ours and the library's. Ours is
  the only one that writes on the egress path and the only one that reads for the record, so the
  library's is never the source of truth for anything an operator sees. That containment is the reason
  the duplication is tolerable.
- **`crates/sender/tests/no_alternate_egress.rs`'s `ALLOWED` entry becomes partly false.** Its stated
  reason is that the proxy "relays the client's *own* bytes" [VERIFIED: read the constant]. On an h2
  leg it relays the client's own *request*, re-encoded. The authorisation half of the argument survives
  intact — gating browsing traffic would still turn the proxy into a blocklist — but the byte-identity
  half does not. Slice 5 must rewrite that reason rather than leave a comment that has quietly stopped
  being true.

**Rejected: (a) hand-rolled throughout** — for reason 2 above. **Rejected: library throughout** — for
reason 3. **Rejected: library on egress with a raw "escape hatch" for malformed sends** — the escape
hatch cannot share the library's connection (its HPACK encoder state is not ours to write into), so it
is a second connection and therefore a second implementation anyway, arrived at by accident instead of
on purpose.

---

## 2. What byte-honesty means under HPACK

This is the section the plan must not get wrong, because the implementation would otherwise promise
something impossible.

**"Send exactly these bytes" and "send this header list" are different operations with different
guarantees. The API must have two entry points rather than one that pretends.**

### What we can honestly claim

1. **Wire-exact emission on a connection we own from its first octet.** Our HPACK encoder's dynamic
   table starts empty and only we write to it, so an `H2FrameProgram`'s octets are a *pure function of
   the program*. Emission is byte-exact, and re-running the program reproduces the wire bytes exactly.
2. **Wire-exact capture.** Every frame crossing a TLS-terminated proxy leg can be stored as its exact
   9-octet header plus exact payload (subject to the retention mode in §5).
3. **Header-list-exact round trip.** The ordered sequence of `(name, value)` fields — duplicates and
   pseudo-headers included — survives capture → parent record → operator edit → re-encode. This is the
   guarantee every downstream tool actually consumes, and it is total.
4. **Byte-exact replay of frames *we* emitted.** Because an egress program's HPACK state starts empty
   and is written only by that program, its stored frame children replay to identical wire octets. This
   asymmetry matters and is the crux of the whole section: **frames we emitted on a fresh connection
   replay byte-exactly; frames we captured mid-connection do not.**

### What is impossible, and must never be offered

1. **Byte-exact replay of a *captured* header block.** A HEADERS frame's octets are meaningful only
   relative to its connection's dynamic table at that instant. Indices shift with every field emitted
   with incremental indexing on *any* stream, so the encoding of stream 5's headers depends on what
   crossed streams 1 and 3. Replaying those octets on a fresh connection decodes to different headers
   or fails outright. **The HTTP/1 Repeater guarantee — "resend the exact bytes we captured" — has no
   h2 analogue for headers.** The only way to recover it is to replay the entire connection from its
   first frame, which changes the unit of replay from a request to a connection. That is a coherent
   future feature; it is not this phase, and the UI must not imply it exists.
2. **Preserving the HPACK *representation* across a resend.** Huffman versus literal, indexed versus
   literal, never-indexed, and the exact table-size-update sequence are encoder choices. Capture
   records them in the child octets; re-encoding cannot reproduce them. The correct path therefore
   picks a representation and must **say which** in the record, rather than leaving the operator to
   assume fidelity it did not get.
3. **Preserving header-name case through a compliant peer.** RFC 9113 forbids uppercase names, so a
   well-behaved peer never sent any and nothing is lost. But this cuts the other way for research: an
   uppercase name is a thing the operator *wants* to send, and our writer must emit it unchanged
   rather than lowercasing it "helpfully". We do not normalise; we report (see §7).
4. **A self-describing captured frame.** A stored HEADERS frame cannot be decoded in isolation. §5
   states how the decode is recovered — by replaying that connection's header-carrying frames in
   `MsgId` order — and what it costs.

### Where "malformed" lives, layer by layer

The operator surface in §7 must reach all three, or H2-03 is only partly met:

- **Frame layer** — declared length disagreeing with the payload written; unknown/reserved type;
  reserved flag bits; stream id 0 on a stream frame or an even id from a client; a stream id with the
  reserved high bit set; CONTINUATION with no preceding HEADERS; HEADERS after END_STREAM; a frame
  interleaved inside an unterminated header block.
- **HPACK layer** — an index into an empty or short dynamic table; a dynamic-table size update above
  the peer's `SETTINGS_HEADER_TABLE_SIZE`; a Huffman string with invalid padding or an EOS symbol; a
  declared string length that overruns the block; a multi-byte integer continuation that never
  terminates.
- **Message layer** — uppercase name; connection-specific fields (`connection`, `keep-alive`,
  `transfer-encoding`, `upgrade`); `te` with a value other than `trailers`; duplicate, missing, or
  out-of-order pseudo-headers; `content-length` disagreeing with the DATA total. This last one is the
  h2 analogue of the CL/TE conflict, and note the shape difference: **h2 has no chunked encoding**, so
  the classic CL/TE desync becomes "CL that disagrees with DATA" plus the h2→h1 downgrade class at the
  target's own front end.

---

## 3. Module placement

### A new crate: `crates/h2` → `burpsy-h2`

Depends on `burpsy-core` only, plus `bytes`, `anyhow`, `tracing`. **No `tokio`, no `rustls`, no socket
of any kind.** It is a codec, positioned exactly the way `bcheck` is "a pure interpreter with no
transport" [VERIFIED: `crates/AGENTS.md` says so].

```
core ──► bcheck ──► scanner ──► proxy ──► web ──► cli
  │        │                      ▲        ▲       ▲
  ├────────┴──► sender ───────────┤        │       │
  ├──► h2 ──────────────────────► ┴────────┴───────┤   (new: sender, proxy, web)
  ├──► intruder ────────────────────────────────► │
  └──► tools ───────────────────────────────────► │
```

`h2` sits beside `bcheck` as a second crate that depends only on `core`. Consumers: `sender` (writer +
the authorisation rendering), `proxy` (tap + normalisation), `web` (rendering a captured frame). No new
edge points at `proxy`, so the `scanner → proxy` cycle the workspace forbids is not approached.

Contents:

| Module | Responsibility |
|---|---|
| `frame.rs` | The 9-octet frame header; `FrameSpec`; a **verbatim writer** (program → octets, correcting nothing); a **boundary reader** that splits a byte stream into whole frames and reports a truncated tail as incomplete rather than dropping it |
| `hpack/` | Static table, Huffman tables, integer/string primitives; a connection-scoped `Decoder` with a dynamic table; an `Encoder` with an explicit representation strategy |
| `normalise.rs` | h2 ⇄ HTTP/1-shaped bytes, both directions (§5) |

**Why not put the codec in `core`.** `crates/core/AGENTS.md` states that core "depends on no other
burpsy crate and must stay that way… giving it a network or a parser dependency would make the memory
model untestable in isolation" [VERIFIED: read it]. A frame codec is a parser. The normalisation output
is plain `Bytes`, which `core::parse` already consumes, so nothing forces the coupling.

**Naming.** `burpsy-h2` sits next to the external crate named `h2` in `proxy`'s manifest. That is legal
but reads badly in imports. `burpsy-http2` is the safer name; the plan should pick one and not
relitigate it.

### The h2 transport lives inside the egress chokepoint

`crates/sender/src/transport/h2.rs`, `pub(crate)` like its siblings — a **single-stream** h2 client:
connect, preface, SETTINGS, one HEADERS (+ CONTINUATION as needed), DATA, then read frames until
END_STREAM or a deadline. No multiplexing, no priority, no push; flow control satisfied by advertising
a large initial window and answering with generous WINDOW_UPDATEs. That is why the egress client is
ours and the proxy's is not: this is a fraction of a general h2 client.

The facade gains two methods, and the transport-mismatch discipline at `crates/sender/src/lib.rs:234`
extends to a third `Transport` variant:

- `send_h2(&self, target, &H2Request) -> Result<SendResult, SendError>` — the correct path.
- `send_h2_program(&self, target, &H2FrameProgram) -> Result<H2ProgramResult, SendError>` — H2-03.

Both authorise before touching the transport (§4). Placement is not a preference: an h2 transport
beside the proxy would trip `crates/sender/tests/no_alternate_egress.rs`, and correctly so.

The external `h2` crate is a dependency of **`proxy` only**. It takes an `AsyncRead + AsyncWrite`
rather than owning a socket [ASSUMED — needs confirming; if it dials internally, the egress scan and
its `ALLOWED` argument both need revisiting], so it introduces no new connect site.

### `core` changes: two, both additive

1. **`Exchange.protocol: Protocol`** (`Http1` | `Http2`), `#[serde(default)]` so pre-Phase-2 captures
   still deserialise — the same pattern `related` used [VERIFIED: `crates/core/src/lib.rs:307`].
   *Why not `notes`.* `notes` already carries `"intercepted"`, `"passthrough: …"` and drop reasons
   [VERIFIED: `crates/proxy/src/lib.rs:416`, `:562`], and it is free prose a filter cannot key on.
   Honest counting requires history to state the protocol, and the Repeater must route on it rather
   than sniffing the version token out of the record text.
   *Cost:* `GET /api/history` and `GET /api/exchange/{id}` gain a JSON field (additive, no consumer
   breaks); the seven existing `related: Vec::new()` producers gain a second explicit field; and the
   differential parity test's `drive()` sequence must cover it, per `crates/core/AGENTS.md`.
2. **`Scope::authorises_whole_host(host, port, tls) -> bool`** — see §4.

`ChildRef::H2Frame(MsgId)` already exists and gets its first producer here. No parallel mechanism is
introduced [VERIFIED: `crates/core/src/lib.rs:274`; the variant currently has zero producers].

---

## 4. Scope authorisation for h2

`Scope::authorise_request` extracts the path via `request_path(raw)`, which reads an HTTP/1 start line
and returns `None` for anything else — and `None` means **refuse**, deliberately
[VERIFIED: `crates/core/src/scope.rs:127-149`, `:245-249`]. Hand it a HPACK block and every h2 send is
refused. This must be solved, not worked around.

### The mechanism: authorise the value the encoder will encode

**No sibling entry point that takes a caller-supplied path.** That is the tempting fix and it is wrong:
`authorise_request`'s own doc comment exists because "a caller can name an in-scope host and then write
a request line for somewhere else" [VERIFIED: `crates/sender/src/lib.rs:210-212`]. A `path: &str`
parameter reintroduces exactly that gap, with the compiler's blessing.

Instead, **the egress API takes a value, not bytes.** `send_h2` receives an `H2Request` holding the
ordered pseudo-header and header list plus the body. The chokepoint renders that value through
`burpsy_h2::normalise::render_request` — the *same* function §5 uses for the history record — and calls
the existing `Scope::authorise_request` on the rendered bytes. One authoriser, one path extractor, no
new decision function.

The binding is structural, by the same argument the crate already makes: `H2Request` is the sole input
to the encoder, the encoder is `pub(crate)` inside `sender`, and there is no public path that reaches
it. Authorisation and transmission read the same field of the same value, so they cannot disagree.

**Make it checkable rather than asserted**, following `verify_index`: a test that for every
`H2Request`, the path the authoriser extracted appears as a `:path` field value in the octets the
writer produced. A prose claim that the two derivations agree is worth less than a test that proves it.

### The guarantee, restated honestly

The one-sentence version today is "Scope authorises the exact octets that go on the wire." After this
phase it is two sentences, and the second one is new:

- For HTTP/1, and for h2 requests expressed as a header list: **Scope authorises the canonical HTTP/1
  rendering of the same value the encoder encodes.** Exactly one such value exists per send.
- For h2 sends whose header block cannot be decoded into a path: **Scope authorises the host as a
  whole**, and the send is refused unless *every* path on that host is in scope.

### The hard case: a frame program

H2-03 lets the operator send things that have no single readable path. Three rules, all fail-closed:

1. **Header block expressible as a field list (even an illegal one).** Extract *every* `:path` field —
   there may be several, that being the point of the payload. **Authorise all of them; refuse if any is
   out of scope.** Not the first, not the last. A smuggling payload's premise is that different parsers
   pick different ones, so scope must hold for every interpretation. This is the same reasoning
   `may_contain_host`'s doc comment already makes: one arbitrary path cannot answer a question about a
   host [VERIFIED: `crates/core/src/scope.rs:196-207`]. No `:path` at all → refuse, mirroring
   `request_path` returning `None`.
2. **Opaque header block** (operator-supplied raw HPACK octets, or a deliberately truncated one). The
   path is unreadable, and "unreadable means refuse" is the existing rule. Rather than inventing a
   trust-the-operator hole, require that the unreadable path *cannot escape scope*:
   **`Scope::authorises_whole_host(host, port, tls)`** — true only when the host's effective verdict is
   Include and no path-scoped rule for that host could change it. An opaque block is authorised iff
   every path on that host is authorised. A researcher targeting a lab host adds a whole-host include,
   which is what they would have done anyway; a researcher pointed at a production host with
   `exclude … /admin` is refused, correctly.
   *The alternative considered and rejected:* let the operator declare the path they intend, authorise
   that, and annotate the record "authorised against a declared path; the bytes sent were not checked".
   That is honest labelling of a real hole — a declared `/allowed` whose octets encode `/admin` — and a
   hole with a label is still a hole.
3. **Frames with no header block at all** (a lone DATA on a bogus stream id, a malformed SETTINGS, a
   PING flood). There is no path; the target *is* the host. Whole-host authorisation, as rule 2.

Refusals reuse `Scope::explain` verbatim so the operator gets the same sentence they get for HTTP/1
[VERIFIED: `crates/core/src/scope.rs:261`], and refusals increment `refused` without touching `sent`,
so the counters keep meaning what they mean.

---

## 5. H2-02 normalisation: an h2 stream → `Exchange` + `MessageShape` + `related`

### The parent record: a synthesised HTTP/1 serialisation

**Request bytes**, in this order:

```
{:method} {:path} HTTP/2\r\n
host: {:authority}\r\n            (only if the stream carried :authority)
{every regular field, in observed order, name and value verbatim}\r\n
\r\n
{DATA payloads concatenated}
```

- **The version token is `HTTP/2`, not `HTTP/1.1`.** Writing `HTTP/1.1` would be a lie in the one place
  a reader most trusts. `HTTP/2` is safe through every parser in the workspace [VERIFIED by reading
  each: `core::parse`'s `split3` splits on spaces and validates nothing
  (`crates/core/src/lib.rs:243`); `scope::request_path` takes token 2 and discards token 3
  (`scope.rs:133-136`); `RequestEdit::from_raw` uses `split_whitespace` for method/target/version
  (`crates/core/src/edit.rs:62`); `parse_status` takes the token after the first space
  (`crates/proxy/src/lib.rs:730`); `web`'s `first_token`/`second_token` whitespace-split
  (`crates/web/src/lib.rs:741-752`)]. The token is a **label**; transport routing comes from
  `Exchange.protocol`, never from the token.
- **Fields are emitted in observed order, verbatim, duplicates preserved as separate lines.** No
  comma-joining. `MessageShape.headers` is a `Vec<HeaderSpan>`, so duplicates are representable
  [VERIFIED: `crates/core/src/lib.rs:81`], and joining is the kind of normalisation that hides the
  interesting case.
- **`:authority` → `host:`.** If the stream carried *both* `:authority` and a `host` field, emit both,
  in observed order. The duplication is a finding, not a mess to tidy.
- **A field value containing CR or LF is refused, not emitted.** Emitting it would inject headers into
  our own record and desynchronise every downstream parser. Refuse and name the field; this is a real
  h2-to-h1 smuggling primitive and the *record* is the wrong place to reproduce it — the child frame
  already holds the octets, and §7 is the surface for sending it deliberately.
- **No `content-length` is synthesised.** `MessageShape.body` is the authoritative extent and is what
  `find_points` and the passive scanner read [VERIFIED: `crates/intruder/src/lib.rs:224`]. Fabricating
  a header the peer never sent would then be re-sent by `RequestEdit::to_raw`, which rewrites
  `Content-Length` unconditionally [VERIFIED: `crates/core/src/edit.rs:218`], turning a synthesised
  value into a transmitted one.

**Response bytes:** `HTTP/2 {:status}\r\n` then fields then body. No reason phrase, ever — h2 does not
carry one. `core::parse` tolerates a missing third token [VERIFIED: `split3`'s `None` arm,
`crates/core/src/lib.rs:254-258`] and `parse_status` reads the code.

**Source of truth for the parent is our tap's decode, not the library's typed view.** `h2` surfaces an
`http::Request`, whose `HeaderMap` cannot represent a duplicate `:path`, an out-of-order pseudo-header,
or an uppercase name, and whose iteration order is not wire order [ASSUMED for the ordering claim —
needs confirming]. The tap reads the same octets the library reads, so agreement is the normal case; a
tap decode failure (dynamic-table desync) is recorded as a fault on the exchange naming the frame and
offset, and the record falls back to the library's view with that note attached. A silently-wrong
header list is the one outcome that is not acceptable.

### The children: exact frame octets

Each retained frame is `store.put(frame_bytes, direction)` where `frame_bytes` is the **complete 9-octet
header plus exact payload**, and the resulting `MsgId` is attached with
`store.add_related(exchange_id, ChildRef::H2Frame(id))`. `Direction::Request` for client→server,
`Direction::Response` for server→client.

This costs nothing in core: `TrafficStore::put` catches a `parse` failure and stores a shape whose body
spans the whole record [VERIFIED: `crates/core/src/lib.rs:490-497`]. **But the resulting
`MessageShape` on a frame child is meaningless** — occasionally `parse` will find a stray `\n` and two
spaces and produce a plausible-looking nonsense shape. The web layer must therefore render an
`H2Frame` child through the frame decoder, keyed on the `ChildRef` variant, and never as HTTP text.
Related: `GET /api/message/{id}` returns `String::from_utf8_lossy(&m.raw)` [VERIFIED:
`crates/web/src/lib.rs:279`], which destroys binary frame bytes — a frame child needs a route that
returns the octets losslessly plus a decoded view.

**Retention modes, because this is where the memory thesis is at risk.** Storing every frame *and* the
normalised parent stores an h2 exchange's bytes roughly twice. Three modes:

- `ControlOnly` (**recommended default**) — retain every frame except DATA payloads; a DATA frame is
  stored as its 9-octet header with the elided payload length noted. Keeps the entire
  smuggling-relevant surface (HEADERS, CONTINUATION, SETTINGS, RST_STREAM, WINDOW_UPDATE, PING,
  GOAWAY, PRIORITY) at near-zero cost, because DATA dominates volume.
- `All` — full byte capture, ~2× the bytes. For a research session against a small target.
- `None` — parent records only.

`ControlOnly` means DATA payloads are not byte-captured at the frame level. Say it once, plainly, in
operator-facing text; the parent's body is the record.

### Connection-level frames get their own exchange

SETTINGS, PING, GOAWAY and stream-0 WINDOW_UPDATE belong to no stream. Attaching them to whichever
stream happened to be open would misattribute them. Instead: **one synthetic connection `Exchange` per
h2 connection** carrying them as `related`, exactly mirroring the existing `CONNECT host:port\r\n\r\n`
marker exchange [VERIFIED: `crates/proxy/src/lib.rs:400-417`], with `method: "H2"` and an empty path.

**Open, and deliberately not decided here:** a stream exchange cannot point at its connection exchange,
because `ChildRef` carries a `MsgId` and not an exchange id. This phase records the linkage in `notes`
(`"h2 conn 7 stream 3"`) and accepts that it is textual. The clean fix is a `ChildRef::H2Stream(u64)`
variant, which is a `core` schema decision better made when the WebSocket phase needs the same shape —
Phase 9 is already documented as reusing this machinery [VERIFIED: `.planning/ROADMAP.md:139`]. Naming
it here so it is not reinvented.

### What is lost, honestly

1. **HPACK representation** — Huffman/indexed/never-indexed choices. Present in the child octets, absent
   from the parent, not reproducible on resend.
2. **Byte-exact header replay** — §2, claim 1 of the impossible list.
3. **`:scheme` and `:protocol`** are not in the parent record. They have no HTTP/1 header equivalent,
   and emitting `:scheme: https` as a header line would parse to name `""` / value `"scheme: https"`
   because `core::parse` splits on the *first* colon [VERIFIED: `crates/core/src/lib.rs:175`].
   Recoverable from the child HEADERS frame and from `Exchange.tls`.
4. **Trailers** (a second HEADERS after DATA) are not in the parent — HTTP/1 trailers require chunked
   framing, and synthesising chunked framing to carry them would misrepresent the wire. Child frame
   plus a note.
5. **Reason phrase** — h2 has none. Nothing to lose, but tools that display one will show blank.
6. **`cookie` field splitting.** RFC 9113 permits a client to split `cookie` across several fields. We
   emit them as separate `cookie:` lines rather than joining with `"; "`, because joining is exactly
   the normalisation that hides the interesting case. **This is the riskiest fidelity choice in the
   section** — see §9.
7. **Server push.** PUSH_PROMISE frames are captured on the connection exchange; no pushed-response
   exchange is synthesised this phase.
8. **Flow-control and priority signals** are children, not parent fields.

### What is preserved for free, and worth knowing

**Global frame ordering across streams is recoverable** without storing a timestamp per frame, because
position is the id: `MsgId` is monotonic and assigned under the append lock
[VERIFIED: `crates/core/src/lib.rs:316-328`]. Sorting children by `MsgId` yields wire order across the
whole connection.

**A captured HEADERS block's decode is recoverable on demand** by replaying that connection's
header-carrying children in `MsgId` order to rebuild the dynamic table. Cost: O(frames on the
connection) to render one frame's headers — acceptable for a UI, and it means we do not have to store a
decoded copy beside the octets. This is only sound because complete frames are stored in order, which
is a reason not to weaken `ControlOnly` into "drop CONTINUATION".

---

## 6. ALPN negotiation and the bridging question

Today the client-facing `ServerConfig` offers only `http/1.1` because "h2 needs a framing layer to stay
byte-honest", and the upstream `ClientConfig` matches it "so we never bridge h2 downstream to http/1.1
upstream" [VERIFIED: `crates/proxy/src/tls.rs:233`, `:350-351`]. Phase 2 builds the framing layer, so
the first comment is discharged. **The second invariant is not discharged — it is preserved, by a
stronger mechanism.**

### Replacement invariant: mirror, never bridge

**The proxy offers the client exactly the one protocol the upstream already chose.** Reorder `mitm`:

1. `CONNECT host:port` arrives. Dial upstream and complete its TLS handshake **first**, offering
   `["h2", "http/1.1"]`. Learn what the target chose.
2. Build the client-facing `ServerConfig` offering **only** that protocol, then accept the client
   handshake. The `SniResolver` still mints the leaf from the real ClientHello
   [VERIFIED: `crates/proxy/src/tls.rs:268-282`]; the CONNECT authority is all step 1 needs.
3. Run the leg pair for the negotiated protocol. There is no code path in which the two legs speak
   different protocols, so bridging is not "avoided" — it is unrepresentable.

This satisfies H2-04 in the strong form: the tool uses h2 whenever the *target* supports it, and the
absence of a downgrade is structural rather than a check someone has to remember.

**Costs, stated:** the upstream connection is opened before the client handshake completes, so a client
that aborts mid-handshake leaves one wasted upstream connection; and the upstream handshake moves onto
the latency path ahead of the client seeing a certificate. The existing code already connects upstream
immediately after accepting [VERIFIED: `crates/proxy/src/lib.rs:463`, `:477`], so this is a reordering,
not a new cost.

### Protocol mismatch: refuse loudly

The one case mirroring cannot serve is an h1-only client against an h2-only target. Then:

- If the target offered `http/1.1` as well, re-handshake upstream forcing `http/1.1` and mirror that.
- If the target is genuinely h2-only, **refuse the tunnel and record an exchange saying exactly why** —
  "target negotiated h2; this client offered only http/1.1; not bridged". This reuses
  `record_failed_connect`'s discipline: a CONNECT that never reached its origin still leaves a trace,
  because "unreachable" and "never visited" must not both look like an empty history
  [VERIFIED: `crates/proxy/src/lib.rs:11-14`]. Every current browser speaks h2, so this is a corner.

**Why not bridge, put plainly.** h2→h1 downgrade is *the* h2 smuggling class, and it happens at the
target's front end. If burpsy performs the downgrade itself, the operator can never observe the target
performing it — burpsy's translation and the target's become indistinguishable. Refusing to bridge is
not pedantry; without it H2-03 tests our own code.

`TlsAction::Passthrough` connections are untouched — no ALPN decision is ours to make there.

### Cleartext

**No h2c on the proxy's plain-HTTP path.** Browsers do not offer it, prior-knowledge h2c on port 80
would break every ordinary HTTP/1 request, and the `Upgrade: h2c` dance is deprecated. The plain path
stays HTTP/1.

**Yes to prior-knowledge h2c on egress.** A researcher legitimately points Repeater or a frame program
at an h2c back end, so `send_h2` and `send_h2_program` accept a cleartext target and send the preface
directly. No upgrade negotiation, no sniffing — the operator asserted h2, so we speak h2.

### Interception is out of scope for h2 this phase

`hold_for_review` parks the whole connection task while an operator edits
[VERIFIED: `crates/proxy/src/lib.rs:759-773`, `intercept::Interceptor::hold` at
`crates/proxy/src/intercept.rs:145`]. On a multiplexed connection, holding stream 3 would freeze streams
1 and 5. Per-stream parking is a real change to `intercept.rs`'s model and H2-01 asks for proxy, view
and resend — not intercept. Out of scope, named here so it is not discovered mid-slice. An h2 connection
must be recorded as "not interceptable in this build" rather than silently ignoring an enabled hold
queue.

---

## 7. H2-03: the malformed-frame surface

### Shape: a frame program

An ordered list of frame descriptors, executed on one fresh connection, then read until the peer closes
or a deadline expires.

```
H2FrameProgram { preface: bool, frames: [FrameSpec], read_for_ms: u64 }

FrameSpec {
  ty:           u8,            // numeric. Unknown and reserved types are research targets
  flags:        u8,            // raw bits, reserved bits included
  stream_id:    u32,           // raw. 0 on a stream frame, even from a client, reserved bit set
  declared_len: Option<u32>,   // None = the true payload length. Some = write this instead
  payload:      Payload,
}

Payload = Raw(bytes)
        | HeaderList { fields: [(name, value)], encoding: HpackEncoding }
        | Data(bytes)
```

**Every field is the raw wire field.** `ty` and `flags` are integers, not enums. `stream_id` is not
validated. `declared_len` is permitted to lie. `preface` may be omitted. Field lists preserve order and
duplication verbatim, including pseudo-headers out of order or repeated. This is where the
`net.rs` precedent transfers exactly: the writer must not correct you.

`HpackEncoding` (`Literal`, `LiteralHuffman`, `IndexedWherePossible`, `NeverIndexed`) lets the operator
control representation without hand-writing HPACK; `Payload::Raw` covers hand-written and deliberately
corrupt blocks. Together these reach all three malformedness layers enumerated in §2.

### Coexistence with the correct path

`H2Request` **lowers** to an `H2FrameProgram`. One writer, and the writer never inspects its input for
legality. Consequences worth stating:

- Every ordinary resend exercises the writer, so the research path is not a rarely-run branch.
- The correct path is a *function*, so it is testable without a socket: assert that lowering a given
  `H2Request` produces exactly the expected octets.
- The writer's tests are negative tests: "emits a length field that disagrees with the payload it
  wrote", "emits stream id 0 on a DATA frame", "emits CONTINUATION with no preceding HEADERS", "emits an
  uppercase header name unchanged". Each of these is a test that the writer did *not* help.

### Recording an attempt

- Parent record: the HTTP/1 rendering of the first decodable HEADERS block if there is one; otherwise a
  synthetic marker, mirroring the CONNECT marker precedent.
- `related`: every frame the program emitted, plus every frame read back.
- `Exchange.protocol = Http2`, `notes` naming it as a frame program.
- **These children replay byte-exactly** (§2, claim 4), because an egress program's HPACK state starts
  empty and is written only by that program. The stored frames *are* the reproducible artifact. This is
  the one place in the system where "resend exactly these bytes" is an honest offer for h2.

### Repeater on an h2 exchange (H2-01)

The operator edits the HTTP/1-shaped parent record text — so the existing Repeater UI works unchanged,
which is H2-02 paying off. On send, if `Exchange.protocol == Http2`, the edited text is parsed back into
an `H2Request` (start line → `:method`/`:path`, `host` → `:authority`, `Exchange.tls` → `:scheme`,
fields verbatim in order, body after CRLFCRLF) and lowered.

- `SendReq` gains `protocol: Option<Protocol>` [VERIFIED: `SendReq` is `{ target, raw, timeout_ms }` at
  `crates/web/src/lib.rs:292`]. Default from the exchange, **operator-overridable** — sending the same
  request over h1 and h2 and comparing is a core smuggling technique, so the override is a feature, not
  a convenience.
- The text surface cannot express HPACK representation or frame-level malformation. That is what the
  frame-program surface is for, and the UI should say so rather than let an operator infer otherwise.
- An uppercase header name typed into the box is sent uppercase. We do not normalise; we annotate the
  response record ("sent a header name with uppercase characters, which RFC 9113 §8.2.1 makes
  malformed") and record whatever came back, including RST_STREAM or GOAWAY.

---

## 8. Slice plan

Dependency order. Each slice is independently implementable, independently testable, and states what it
does *not* yet deliver. `QUICK=1 ./verify.sh` clean with zero warnings is an acceptance criterion for
every slice and is not repeated below.

### Slice 1 — `burpsy-h2` crate + frame layer
Crate skeleton (added to the workspace `members` list, or cargo will not see it), frame header codec,
`FrameSpec`, verbatim writer, boundary reader. No HPACK. Pure; no socket.
**Accepts when:** a program whose `declared_len` disagrees with its payload emits exactly those octets;
stream id 0 on a DATA frame and an even client stream id are emitted unchanged; reserved flag bits
survive; the reader splits a concatenated stream at frame boundaries and reports a truncated tail as
*incomplete* rather than dropping it; write→read round-trips a compliant program; the egress source scan
finds no connect call in the new crate.
**Does not yet deliver:** anything an operator can see.

### Slice 2 — HPACK
Static table, Huffman tables, integer/string primitives, connection-scoped `Decoder` with dynamic table,
`Encoder` with an explicit representation strategy. Pure.
**Accepts when:** the RFC 7541 Appendix C vectors encode and decode byte-exactly, including the
dynamic-table-evolution sequences and the Huffman variants [ASSUMED that Appendix C is a sufficient
corpus — confirm before planning]; an invalid index, an oversized table-size update, and a truncated
string each return an error naming the offset rather than panicking; the `Literal` strategy inserts
nothing into the dynamic table, so its output is position-independent.
**Does not yet deliver:** anything an operator can see. **Highest-risk slice** — see §9.

### Slice 3 — Normalisation + `Exchange.protocol` (H2-02's core)
`normalise.rs` both directions; `Exchange.protocol` with `#[serde(default)]`; parity-test coverage.
**Accepts when:** a decoded field list renders to bytes whose `core::parse` shape yields the same
ordered list with duplicates intact; the round trip list → h1 bytes → list is identity; a value
containing CR or LF is refused and names the field; `HTTP/2` in the start line still yields the right
`request_path`, `RequestEdit::from_raw`, `first_token`/`second_token` and `parse_status`; a `:status`-only
response with no reason phrase parses; a pre-Phase-2 serialised `Exchange` still deserialises.
**Does not yet deliver:** any h2 traffic.

### Slice 4 — Scope + the egress transport (H2-01 resend half, H2-03 wire half)
`Scope::authorises_whole_host`; `sender/src/transport/h2.rs`; `send_h2`, `send_h2_program`; `H2Request`
lowering; TLS-ALPN and prior-knowledge cleartext.
**Accepts when:** an out-of-scope `H2Request` is refused with nothing reaching a socket and `refused`
incremented while `sent` is not; a program with two `:path` fields is refused unless **both** are in
scope; an opaque header block is refused when the host carries any path-scoped rule and allowed when the
host is wholly in scope; a program with no header block requires whole-host authorisation; the
authoriser's extracted path is present as a `:path` in the writer's octets (the checkable-invariant
test); `no_alternate_egress` still passes; tests touch no DNS (use `127.0.0.1` and a closed port, per
`crates/sender/AGENTS.md`).
**Does not yet deliver:** proxied h2.

### Slice 5 — ALPN mirroring + the frame tap (H2-04)
Reorder `mitm` to dial upstream first and mirror ALPN; protocol-mismatch refusal with a recorded
exchange; when h2 is negotiated on both legs, **splice the plaintext blind** and tap it — connection
exchange plus frame children, retention modes. Rewrite the `no_alternate_egress` `ALLOWED` reason text.
**Accepts when:** against an h2-capable local server both legs negotiate h2 and neither bridges; against
an h1-only upstream the client is offered only `http/1.1`; an h1-only client against an h2-only upstream
is refused with an exchange stating why; a proxied h2 connection yields a connection exchange whose
`related` children are the exact frame octets in `MsgId` order; `ControlOnly` elides DATA payloads and
records the elided length; `verify_index` passes on the resulting store; `./e2e-tls.sh` passes.
**Does not yet deliver:** per-stream exchanges — so filters, Repeater and the scanner do not yet see
proxied h2 exchanges. History must say so rather than imply completeness.

### Slice 6 — Per-stream reconstruction (H2-01 proxy half, H2-02 delivered)
Drive both legs with the external `h2` crate; build one `Exchange` per stream from the tap's decode;
record tap desync as a fault; record h2 connections as not interceptable.
**Accepts when:** a proxied h2 request yields an `Exchange` whose parent record parses to the right
method, path and ordered fields, whose `related` holds that stream's frames, and which `find_points`,
the passive scanner, match-and-replace, and `RequestEdit` all consume unchanged; a forced tap desync
produces a fault note and a library-view fallback rather than a wrong header list;
`./e2e-intercept.sh` and `./e2e-tls.sh` pass.

### Slice 7 — Operator surface
Frame-program route and editor; a lossless frame-bytes route plus a decoded view (replaying the
connection's header-carrying children to rebuild the table); `SendReq.protocol`; history showing
`Exchange.protocol`.
**Accepts when:** a posted frame program appears in history with its frames; a captured HEADERS child
renders its decoded fields via replay; an out-of-scope program returns `Scope::explain`'s sentence
unchanged; the Repeater sends an h2 exchange over h2 by default and over h1 when overridden, both
distinguishable in history; a frame child's octets survive the API without lossy UTF-8.

---

## 9. Risks and open questions

Flagged rather than silently decided.

1. **The external `h2` crate's fidelity is the load-bearing unknown for slice 6.** What must be true:
   (i) it accepts an `AsyncRead + AsyncWrite` rather than dialing itself; (ii) both server and client
   halves are usable; (iii) it will forward a response header list we hand it without rejecting fields
   we need preserved. If (i) is false, the egress scan and its `ALLOWED` argument both need revisiting.
   If (iii) is materially false, slice 6's fallback is our own multiplexer — which is a different phase
   and should trigger a replan, not be absorbed. A parallel agent is researching the crate landscape;
   do not plan slice 6 before that lands.
2. **`http::HeaderMap` iteration order** is `[ASSUMED]` not to be wire order. If true, the design is
   already correct (the tap is authoritative for the parent). Confirm anyway, because if the library
   *does* preserve order, slice 6 gains a cheap differential check against the tap.
3. **`cookie` splitting: preserve as observed, or join with `"; "`?** The design preserves. Risk: a
   BCheck check or the passive scanner may expect exactly one `cookie` header —
   `bcheck::insertion::RESERVED_HEADERS` names `cookie` explicitly [VERIFIED:
   `crates/bcheck/src/insertion.rs:111-118`]. Check the corpus before slice 3 rather than after. If
   splitting breaks checks, the fallback is join-in-the-parent and record the split in the child frame —
   which is still honest, just less direct.
4. **Hand-rolled HPACK is the highest-defect-density component in the phase.** Mitigations: RFC 7541
   Appendix C vectors as a conformance corpus (matching the project's instinct to run a published corpus
   unmodified), plus a differential fuzz against a reference decoder added as a **dev**-dependency only,
   so it never enters the production graph. The crate-landscape research should name a candidate.
5. **The 2× store cost for `All` retention** is a real regression against "raw bytes are written once
   and never copied". `ControlOnly` reduces it to near-nothing and is the recommended default, but the
   thesis is weakened in a way the root `AGENTS.md` should eventually acknowledge. Not a blocker;
   do not let it go unstated.
6. **Tap backpressure is unbounded as described.** The tap should append on a spawned task, the way
   `spawn_scan` keeps scan cost off the proxy's latency path [VERIFIED:
   `crates/proxy/src/lib.rs:326`, `:604`]. What that queue's bound is, and what happens when it fills
   (drop and count, versus apply backpressure to the connection), is **undecided**. Counting a drop is
   the project-consistent answer; confirm in planning.
7. **`RequestEdit::to_raw` rewrites `Content-Length` unconditionally** [VERIFIED:
   `crates/core/src/edit.rs:218`]. So the active-audit and intercept-forward paths will inject a
   `content-length` into an h2-derived request that did not carry one. Harmless for h1 egress; for h2
   re-lowering, decide explicitly whether a `content-length` field is carried into the header list
   (RFC 9113 permits it and requires it to match the DATA total) or dropped. **Undecided.**
8. **Extended CONNECT / WebSockets over h2 (RFC 8441)** is out of scope, and Phase 9 will collide with
   it. The `:protocol` pseudo-header is already listed as lost in §5; the collision is worth noting in
   the Phase 9 context rather than rediscovering.
9. **Naming:** `burpsy-h2` versus `burpsy-http2`, given the external crate is named `h2`. Pick in
   planning; do not relitigate during implementation.
10. **`Protocol` as a two-variant enum** assumes no HTTP/3 in this milestone. If h3 is anywhere on the
    roadmap the field should be an enum from the start rather than a bool named `is_h2`. It is an enum
    here for that reason; confirm the roadmap agrees.
