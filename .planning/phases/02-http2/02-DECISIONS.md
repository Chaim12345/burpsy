# Phase 2: HTTP/2 — Adjudicated Decisions

**Date:** 2026-07-28
**Status:** Binding. Where this file and `02-DESIGN.md` / `02-LIBRARY-RESEARCH.md` disagree, **this file
wins** — the same precedence `01-CONTEXT.md` held over `01-RESEARCH.md` in Phase 1.

Produced by an adversarial review of the design and the library research. The review returned
**REVISE**: the framing decision is right, its stated justification is wrong, and §4 of the design
contained five ways to get an unauthorised request onto a socket. Six CRITICAL findings.

Every claim below marked `[VERIFIED]` was re-read from source at the time this file was written, not
carried from an earlier note. That distinction matters here because the review found **six** wrong
`[VERIFIED]` tags in the design (see §9), which devalues the tag unless it is re-earned.

---

## 1. Framing strategy — decision upheld, argument replaced

**Keep:** we own the frame codec, HPACK and normalisation in a new crate, plus the whole egress path.
The external `h2` crate drives only the proxy's two legs.

**Drop `h2`'s `unstable` feature.** Dependency is `h2 = "0.4"` at default features, in `proxy` only.

**Replace §1's rejection paragraph.** The design rejected "library on egress with a raw escape hatch"
because the hatch "would be a second connection and therefore a second implementation". That argument
is wrong: a malformed-frame probe *wants* a fresh connection with an empty dynamic table — that is
precisely what makes its octets a pure function of the program, as the design's own §2 argues. A
second connection is the requirement, not a cost.

The correct reasons, both from the research's own evidence:

1. `Headers::encode` takes `&mut hpack::Encoder`, a type no external caller can name, and `mod hpack`
   has no public form at **any** feature configuration. So an escape hatch must already supply its own
   encoded header block. What `unstable` then contributes to the malformed path is `Head::encode`
   writing nine octets and a `StreamId` newtype — the research itself calls this "the ~10-line
   hand-rolled frame-header writer". A semver-exempt feature gate in the crate that opens sockets is a
   bad trade for ten lines.
2. **The tap forces a hand-rolled HPACK decoder regardless of the framing choice.** `h2`'s `Decoder`
   is equally unreachable. Neither document said this: the research's recommendation is silent on the
   tap, so it pays the same HPACK cost as the design's path without admitting it.

**The argument that does hold, and is the real reason to own a writer:** there is no second well-formed
encoder that can drift from the malformed one. On a malformed path you cannot distinguish a bug in your
own writer from a finding at the target — a RST_STREAM looks identical either way. One writer makes a
class of self-inflicted false positives impossible.

**Do not repeat this overclaim:** the design said the writer "is exercised on every ordinary resend, not
only on the research path". Ordinary lowering exercises only the well-formed subset (`declared_len:
None`, legal stream ids, `END_HEADERS` set). The malformed branches are exactly what ordinary traffic
never touches; they are covered by slice 1's negative tests and nothing else.

---

## 2. Minimum viable HPACK — decoder complete, encoder literal-only

This is the single largest risk reduction available in the phase. The design's slice 2 (full encoder
with Huffman and dynamic-table-aware indexing) was its own self-declared highest-defect-density
component.

**Required — decoder, complete:**
- §5.1 integer primitive, with a continuation-octet cap so a non-terminating integer errors rather than loops
- §5.2 string primitive, declared length bounds-checked against the remaining block
- Huffman **decode** table (Appendix B); reject an EOS symbol in the payload, and padding that is not all-ones or is ≥ 8 bits
- static table, 61 entries
- dynamic table: insert, `name.len + value.len + 32` accounting, eviction, §6.3 size update bounded by the peer's `SETTINGS_HEADER_TABLE_SIZE`
- all five representations: §6.1 indexed, §6.2.1 incremental, §6.2.2 without-indexing, §6.2.3 never-indexed, §6.3 size update
- errors carry a byte offset; no panics; bounded allocation
- **one instance per (connection, direction)** — see §5 below

**Required — encoder, minimal:**
- literal-without-indexing, no Huffman, every field including pseudo-headers, order and duplicates preserved, name emitted **verbatim** (no lowercasing)
- never-indexed as a per-field flag

**Cut:** the Huffman **encode** table and bit-packing writer; dynamic-table-aware index selection.

**Why this loses no requirement.** The design's own HPACK-layer malformation list is: an index into an
empty or short table; a size update above the peer's limit; a Huffman string with bad padding or an EOS
symbol; a declared string length overrunning the block; a non-terminating multi-byte integer. **A
correct encoder cannot produce any of them.** Every one is reachable only through `Payload::Raw`, which
slice 1's verbatim writer emits unchanged. The cut strategies deliver zero H2-03 targets — they were
ergonomics for well-formed variation.

Two side benefits: a literal-only encoder writes nothing into the dynamic table, so "a program's octets
are a pure function of the program" becomes unconditionally true; and §4's checkable-invariant test
survives as a substring search (under indexed encoding, `:path: /` becomes static index 4 and the
literal `/` never appears in the octets).

**Slice 2's acceptance criterion is restated** — the old one ("Appendix C vectors encode *and* decode
byte-exactly") cannot be met without the cut code, because C.3/C.5 use incremental indexing and
C.4/C.6 use Huffman. New criterion: decode every Appendix C vector byte-exactly including the
dynamic-table-evolution and Huffman sequences; encode **C.2.2 and C.2.3** byte-exactly; plus a
round-trip property that field list → literal encode → decode is identity for arbitrary names and
values, including duplicates, empty values and non-ASCII bytes.

---

## 3. Scope authorisation — five fail-open paths, closed

The section carrying Phase 1's guarantee forward had the most holes. Root cause: it reasoned about an
`H2Request` (one value, one path) and then extended that reasoning to a frame program (a byte stream
with N paths and a mutable frame layout). Those are different authorisation problems.

**The governing principle, stated plainly: a frame program is authorised as a HOST, not as a request.**
Per-`:path` authorisation is a strictly optional narrowing, available only for the fully-honest subset.

### C1 — multi-`:path` rendering. CRITICAL
`render_request` has one `{:path}` slot; rule 1 required authorising *every* `:path`. A two-`:path`
program rendered to one start line, so an implementer authorises the first and sends both — the exact
fail-open the rule existed to prevent, on the single most important payload shape in h2 smuggling.

**Fix:** render once **per `:path` field** and call `authorise_request` on each rendering; refuse if any
refuses. One authoriser, one path extractor — the principle survives, it just has to be said. Test: a
two-`:path` program whose second path is excluded.

### C2 — a lying `declared_len` guarantees authoriser/peer divergence. CRITICAL
`declared_len` "is permitted to lie" and the authoriser reads the decoded field list. The peer parses
exactly `declared_len` octets: set it short and the peer sees a truncated block; set it long and the
peer consumes the following frame's octets into the block. A `Payload::Raw` frame after an inflated
HEADERS lets an operator make the peer decode `:path: /admin` from bytes the authoriser classified as a
separate DATA frame.

**Fix:** rule 1's field-list authorisation is sound **only when the frame layout is honest**. A
dishonest layout falls to whole-host authorisation. See C4's trigger list.

### C3 — CR/LF in `:method` fabricates the authoriser's request line. CRITICAL
`request_path` reads to the first `\r`/`\n`, then takes tokens 1 and 2 [VERIFIED:
`crates/core/src/scope.rs:127-136`, re-read]. With `:method = "GET /allowed HTTP/2\r\nPOST"` and
`:path = "/admin"`, the rendering is `GET /allowed HTTP/2\r\nPOST /admin HTTP/2\r\n`, `request_path`
returns `/allowed`, and the wire carries `/admin`. Scope authorises a path the request does not contain.

**Fix:** `render_request` must **reject** CR, LF and NUL in every name and value **including
pseudo-headers**, as a returned error, before rendering. Not strip, and not only for regular fields —
the design's refusal bullet sat among bullets about regular fields while pseudo-headers went through
the start-line template.

Three adjacent cases verified **fail-closed** and worth preserving: an empty or absent `:path` renders
`GET  HTTP/2`, whose `split(' ').filter(non-empty)` yields target `HTTP/2` which matches no rule →
refused; likewise an empty `:method`; and a space inside `:path` cannot escape scope, because rules are
prefixes and appending after a space cannot move a path out of an include prefix or into an exclude one.

### C4 — the composition rule was unstated, and both readings were wrong. CRITICAL
Rule 3 ("frames with no header block → whole-host") read per-frame makes **every ordinary resend**
require whole-host authorisation, because a lowered `H2Request` contains SETTINGS and DATA frames that
have no header block — breaking `send_h2` against any path-scoped host. Read per-program it is silent
on mixed programs, and the natural implementation lets a `Payload::Raw` block ride along beside an
in-scope `HeaderList`. Two competent implementers pick different readings and one is fail-open.

**Fix — one rule with an explicit trigger set.** A program requires **whole-host** authorisation if any
of these is present:
- a `Payload::Raw` header-block fragment
- a `declared_len` that disagrees with the payload actually written
- a CONTINUATION frame
- a header block not terminated by `END_HEADERS`
- no header block anywhere in the program

Otherwise every `:path` in every reassembled `HeaderList` block must be individually authorised, and any
refusal refuses the whole program.

Also state explicitly: **`send_h2` authorises the `H2Request` and then lowers.** (Lowering first and
going through `send_h2_program`'s rules is the other readable option and does not work.)

### C5 — CONTINUATION reassembly. MAJOR (was CRITICAL)
A header block spans HEADERS plus N CONTINUATION frames, and the design lists "a frame interleaved
inside an unterminated header block" as a research target, so fragments will not always be adjacent. An
in-scope `:path` in the HEADERS fragment plus an out-of-scope one in a CONTINUATION fragment is
authorised if only the first is decoded. Downgraded only because C4's trigger list closes it as a side
effect. Test it explicitly regardless.

### M1 — `authorises_whole_host` was specified too loosely to implement
`Scope` is last-match-wins [VERIFIED: `crates/core/src/scope.rs:186-190`], and the prose spec captured
no ordering. Hand the implementer the algorithm:

> If `allow_all`, true. Otherwise take the rules matching `(host, port, tls)` via `matches_host`, in
> order. Find the **last** rule with `path_prefix == None`. If there is none, or it is an Exclude,
> return **false**. Otherwise return true iff no rule with `path_prefix == Some(_)` appears after it.

Fail-closed in the absent case. Table-driven test over the ordering permutations; reuse `scope.rs`'s
existing `shop()` helper. Note wildcard patterns compound this — a path-scoped `exclude("*.test")`
matches `shop.test` through `matches_host`.

### Pre-existing bound to restate, not a new hole
`authorise_request` pairs the path it reads with the host the **caller named**, not one derived from the
request [VERIFIED: `crates/sender/src/lib.rs:324-330`]. So an `H2Request` with `:authority: prod.test`
sent to an in-scope target is authorised on the target host. Identical to the HTTP/1 `Host`-header
bound, so Phase 2 does not weaken it — but the design's guarantee sentence reads as though the whole
rendering is checked, and the rendering includes a `host:` line the authoriser ignores. Say so, or the
sentence overclaims.

---

## 4. ALPN, interception, and the handshake ordering

### C6 — ALPN mirroring would silently remove interception from most real traffic. CRITICAL
Today `server_config` offers only `http/1.1` [VERIFIED: `crates/proxy/src/tls.rs:241`], so every browser
exchange is HTTP/1 and interceptable. Mirroring the target's choice makes every h2-capable target — most
of the web — produce connections the design declares not interceptable. The shipped "intercepting proxy
with full capture" capability becomes conditionally false for most traffic, and `./e2e-intercept.sh`
cannot catch it because its origin is HTTP/1.

Disclosure is necessary but does not restore a working feature. Honest counting is not a licence to
remove capability as long as you say so.

**Fix:** make the h2 offer **conditional on the interception queue**. Interception enabled → mirror
`http/1.1` on **both** legs (still mirroring, still no bridge, and the downgrade is operator-caused and
operator-visible, which satisfies H2-04's "rather than *silently* downgrading"). Interception disabled →
mirror the target's choice. State the switch in operator-facing text; add an e2e case proving an
h2-capable target is served over h1 while the hold queue is on.

### M2 — the stated handshake ordering is unimplementable; the fix is source-verified
The design ordered it: dial upstream → learn the target's protocol → build the client-facing
`ServerConfig` → accept the client handshake. But the fallback ("if the target offered http/1.1 as well,
re-handshake upstream forcing http/1.1") needs the client's offer, which is unknowable until the
ClientHello is read — by which point the config is committed and rustls has already sent a fatal
`NoApplicationProtocol` alert.

**Fix, now verified available:**
- `tokio_rustls::server::LazyConfigAcceptor` [VERIFIED: `tokio-rustls-0.26.4/src/server.rs:70`]
- `StartHandshake::client_hello() -> rustls::server::ClientHello` [VERIFIED: `:217`]
- `StartHandshake::into_stream(config)` — the `ServerConfig` is chosen **after** the peek [VERIFIED: `:221`]
- `ClientHello::alpn() -> Option<impl Iterator<Item = &[u8]>>` [VERIFIED: `rustls-0.23.40/src/server/server_conn.rs:187`]

**New ordering:** peek the ClientHello → learn the client's offer → dial upstream offering the
intersection → build the `ServerConfig` for the negotiated protocol → complete the client handshake.
This makes the fallback reachable and removes the upstream re-handshake entirely.

`alpn()` returning `Option` is also the **ALPN-`None` arm the design never handled** — a target sending
no ALPN extension must be treated as an honest HTTP/1.1 fallback, never as assumed-h2. This is not
hypothetical: `e2e-tls.sh`'s Python origin sets no ALPN, so `None` is the case the project's own gate
exercises on every run.

### M6 — the mitm reorder has a real cost; do not deny it
The design claimed "this is a reordering, not a new cost". False: today `accept` precedes
`TcpStream::connect` [VERIFIED: `crates/proxy/src/lib.rs:463` then `:477`], so a client that aborts the
TLS handshake costs **zero** upstream connections. The dominant abort cause is the burpsy CA not being
trusted yet — the code says so. A first-run browser loading thirty subresources would open thirty real
connections to the target while proxying none.

The M2 restructure fixes this for free: the ClientHello peek is cheap and needs no upstream dial, so the
abort case still costs zero. **Delete the "not a new cost" sentence.**

---

## 5. H2-02 normalisation and the tap

### M4 — the replay-decode algorithm was wrong twice
(a) **HPACK dynamic tables are per direction.** The design replayed "that connection's header-carrying
children in `MsgId` order" with no direction filter, which mixes request- and response-direction blocks
into one table and yields garbage indices or silently wrong headers — the outcome the design itself calls
unacceptable. Must be **two decoders, filtered on the child's `Direction`**, and PUSH_PROMISE header
blocks belong in the response-direction replay because they mutate the server's encoder table.

(b) **The linkage was recorded in `notes` prose** (`"h2 conn 7 stream 3"`), so the decode capability
depended on parsing free text — after the design had already rejected `notes` for exactly that reason
("it is free prose a filter cannot key on"). Direct self-contradiction.

**Fix, no schema change:** attach **every** header-carrying frame of a connection to the *connection*
exchange's `related` **in addition to** the stream exchange's. A `ChildRef` is a `MsgId`, so this
duplicates a reference and zero bytes. Replay then reads one exchange's `related`, filtered by
direction, and never touches `notes`. Also state what replay does under retention `None`.

### M5 — slices 5 and 6 described two different proxies. Resolve before either is written
Slice 5 said "splice the plaintext blind and tap it"; slice 6 said "drive both legs with the external
`h2` crate". A blind splice is a byte-transparent relay with a passive observer; driving both legs
terminates h2 twice. Slice 6 discards slice 5's data path.

**Decision: terminate** — consistent with §1's table, which assigns both legs to the library.

**Consequence the design never named:** once you terminate, the client-leg and upstream-leg octets are
*different* HPACK encodings, so "our decoder reads the same octets" requires an interposing **tee**
between the TLS stream and `h2::server::handshake` / `h2::client::handshake`. That wrapper is the
load-bearing component of the tap and appears nowhere in the design. Specify it in slice 5b; drop
"blind splice" from slice 5's text.

### M3 — the parser sweep is incomplete
The design checked five parsers; H2-02's requirement is "every existing tool works unchanged". Missing:
`bcheck`'s request handling and `bcheck::insertion`'s start-line parsing, `core::sitemap`'s host/path
folding, and `tools`' match-and-replace. Add all three to slice 3's acceptance, plus at least one BCheck
corpus check that matches on the request line, run against a synthesised `HTTP/2` record.

---

## 6. Requirement coverage — H2-04 is Partial

| Req | Delivered | Verdict |
|---|---|---|
| H2-01 | slices 5b/6/7 | Complete (subject to C6's interception decision) |
| H2-02 | slices 3/6 | Complete, once M3's sweep is widened |
| H2-03 | slices 1/4/7 | Complete, and still complete under the minimal-HPACK cut |
| H2-04 | slice 5 | **Partial** |

**H2-04 is Partial for two independent reasons.** The requirement says "the tool uses it"; no slice makes
`AuthorisedSender::send`/`send_async` protocol-aware, so the scanner's audit path and Intruder still
speak HTTP/1.1 to an h2-capable target, and against an h2-only target every audit item fails. The
ROADMAP's narrower criterion ("the *proxy* negotiates it") **is** met — so this is a
requirement/roadmap divergence, not a plan defect. But "the tool silently sends h1 to an h2 target" is
what the requirement names. Second reason: the ALPN-`None` arm (M2).

Record it, following HARD-03's precedent:

```
| H2-04 | Phase 2 | Partial — the proxy mirrors the target's ALPN and never bridges; scanner and
Intruder egress remain HTTP/1.1-only, and protocol-aware audit egress is not in this phase |
```

**On the two named scope reductions:** "the proxy is not byte-transparent for h2" is **acceptable** —
H2-02 is shape-based, and the HPACK argument is dispositive; it must reach operator-facing text. "h2
interception out of scope" is **not acceptable as stated** — see C6.

---

## 7. Slice plan — 7 becomes 11

| # | Slice | Notes |
|---|---|---|
| 1 | `burpsy-http2` crate + frame layer | unchanged; right size |
| 2a | HPACK primitives + static/dynamic table + decoder, non-Huffman Appendix C (C.2, C.3, C.5) | |
| 2b | Huffman decode table + C.4/C.6 + literal encoder + round-trip property | the 257-entry table's failure mode is independent of decoder logic; combining them means two wrong entries and a decoder bug you cannot separate |
| 3 | Normalisation + `Exchange.protocol` | **parallelisable with 2** — `render_request` takes a decoded field list, so it has no HPACK dependency. Add M3's three parsers and C3's CR/LF/NUL refusal |
| 4a | `authorises_whole_host` (M1 algorithm), the frame-program authorisation classifier (C4 trigger list), `H2Request` lowering, the checkable-invariant test, C1/C2/C3/C5 negative tests | pure, no socket. **The security-critical pass; deserves its own review** |
| 4b | `sender/src/transport/h2.rs`, `send_h2`, `send_h2_program`, `H2ProgramResult`, TLS ALPN, prior-knowledge h2c | |
| 5a | ClientHello peek (M2), mitm reorder, ALPN mirroring, the `None` arm, the interception interaction (C6), mismatch refusal with a recorded exchange, the four ALPN test updates | an h2-negotiated connection is refused-and-recorded until 5b — honest and shippable |
| 5b | the tee wrapper (M5), the tap, connection exchange, frame children, retention modes, queue bound, `ALLOWED` rewrite | |
| 6a | drive both legs with `h2`, forwarding correctly, tap capturing, no per-stream exchanges | do not plan before the crate-integration question is closed |
| 6b | per-stream `Exchange` reconstruction, tap-desync fault + library fallback, tool-compatibility acceptance | |
| 7a | frame-program route, lossless frame-bytes route, decoded-view route (M4 direction-filtered replay), `SendReq.protocol` | |
| 7b | frame-program editor UI, protocol column, operator-facing text for "not byte-transparent" / "not interceptable" / `ControlOnly`'s elided DATA | |

**Ordering note worth acting on:** slices 1–5 ship no operator-visible h2 capability except the frame
program. If the phase is interrupted, the useful artifact is the egress path (1, 2, 3, 4). That argues
for 4a/4b earlier and 5 later.

---

## 8. Blocking decisions — resolved here

| Item | Resolution |
|---|---|
| Frame-program authorisation composition (C4) | The trigger list in §3. Slice 4a cannot be written without it |
| Splice vs terminate (M5) | **Terminate.** Specify the tee wrapper in 5b |
| Crate naming | **`burpsy-http2`.** `burpsy_h2` next to `h2` in `proxy`'s manifest produces a confusing import block. Settled; do not relitigate |
| Tap queue bound (blocks 5b) | Bounded channel with a **byte** budget, not a frame count — one 16 MiB DATA frame is not one frame's worth of memory. **Drop-and-count** on overflow, count exposed on the connection exchange so an operator sees an incomplete capture rather than a clean one. **Do not apply backpressure to the connection** — that makes the tap alter the timing of a smuggling probe, corrupting the measurement the tool exists to make |
| `cookie` split vs join | **Preserve the split.** The stated risk does not materialise: `RESERVED_HEADERS` means "never insert a payload into these" [VERIFIED: `crates/bcheck/src/insertion.rs:111-117`], so `cookie` is skipped whether it is one line or five. Residual risk is a check whose match expression names `Cookie:` — grep the corpus inside slice 3 |
| `Content-Length` into h2 re-lowering | **Carry it.** The design's premise was wrong: `to_raw` strips any existing CL/TE unconditionally and regenerates from the actual body [VERIFIED: `crates/core/src/edit.rs:203-218`], so its value always agrees with the DATA total — exactly what RFC 9113 requires. Deliberate CL/DATA disagreement stays reachable only through the frame program, which is correct |

**Still open, and genuinely blocking slice 6:** whether the external `h2` crate will forward a response
header list we hand it without rejecting fields we need preserved. If materially false, the fallback is
our own multiplexer — a different phase, and cause for a replan rather than absorption.

---

## 9. Citation corrections to `02-DESIGN.md`

Six `[VERIFIED]` tags were wrong. In every case the conclusion drawn survives, so these are
citation-hygiene defects rather than reasoning defects — but six in one document means the tag is worth
less than it claims, and future documents should distinguish claims re-read at write time from claims
carried forward.

| Design claim | Actual |
|---|---|
| `to_raw` rewrites `Content-Length` unconditionally | Gated on `!body.is_empty() \|\| POST\|PUT\|PATCH`; what is unconditional is *stripping* CL/TE [VERIFIED: `edit.rs:203-218`] |
| "the seven existing `related: Vec::new()` producers" | **17** [VERIFIED: grep] |
| `ChildRef::H2Frame` has "zero producers" | **Two**, both in `#[cfg(test)]` [VERIFIED: `core/src/lib.rs:885`, `:975`] — and one is inside the differential parity test's `drive()`, so `drive()` already exercises it; the new work there is `Exchange.protocol`, not `related` |
| Two ALPN sites | **Four** — two production (`tls.rs:241`, `:351`) plus two test assertions (`:362`, `:429`) that pin the invariant slice 5 replaces [VERIFIED] |
| Drop reasons at `proxy/src/lib.rs:562` | `:562` is `notes: Some("intercepted")`; drop-reason literals are near `:833`/`:871` |
| `record_failed_connect` doc at `proxy/src/lib.rs:11-14` | That is the module-level `//!`; the function's own doc is near `:840-845` |

Two more to fix in the plan:
- `#[serde(default)]` on `Protocol` needs `#[derive(Default)]` with `#[default] Http1`, or it will not
  compile. State that `Http1` is the default so a pre-Phase-2 capture reads as HTTP/1, not unknown.
- Slice 1's "the egress source scan finds no connect call in the new crate" is **vacuous** — a codec with
  no socket cannot fail that scan. Note also that `ALLOWED` is keyed per *file*, not per line
  [VERIFIED: `no_alternate_egress.rs:47-54`], so anything added to `crates/proxy/src/lib.rs` is already
  exempt.

---

## 10. Missing prerequisites

- **No h2-capable test origin exists anywhere in the tree.** Slices 5 and 6 both require one;
  `e2e-tls.sh` uses Python `http.server` (HTTP/1.1, no ALPN). Provisioning it — the `h2` crate's server
  half as a dev-dependency, or a `hypercorn`/`h2` origin in the e2e script — is a prerequisite that
  appears in **no slice**. Add it to 5a.
- **No acceptance criterion asserts that nothing reached a socket** on a refused frame *program*. The
  well-formed path has one; given C1–C5 the program path is where it is needed. Mirror
  `the_async_path_refuses_out_of_scope_bytes_before_connecting` [VERIFIED: `sender/src/lib.rs:369-392`],
  including its assertion that the error does not mention `connect`.
- **The tap's fault surface is unspecified.** `Exchange` has no fault field and none was proposed. Either
  a third `core` change or `notes` prose — which the design already rejected. Decide in 5b.
- **`ControlOnly` + honest counting.** The default elides DATA payloads. Recording the elided length is
  necessary but nothing requires history to *display* that a frame child's payload is absent. A child
  rendered without its payload and without a marker is a partial result that looks complete — this
  project's own definition of a defect.
- **No slice retires the h1 assumption in `read_message`.** The mitm loop calls `read_message`,
  `start_line_parts`, `hold_for_review`. Slice 5/6 must branch on the negotiated protocol before that
  loop, and the design never says where the branch lives.
- **`H2ProgramResult` is named and never defined.** Slice 4b has to invent it; `SendResult`'s shape is
  h1-oriented.
