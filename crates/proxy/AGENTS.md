<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# proxy (`burpsy-proxy`)

## Purpose

The intercepting HTTP/HTTPS proxy: the thing a browser is actually pointed at. It captures exchanges
into the shared `TrafficStore`, optionally holds requests for operator editing, and optionally
terminates TLS with a locally generated CA.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | `ProxyConfig`, the accept/forward loop, CONNECT handling, capture into the store |
| `src/intercept.rs` | `Interceptor`, `Verdict`, `HeldView` — hold a request or a response, let an operator rewrite it, then forward or drop. Also `InterceptRules`/`InterceptRule`/`MatchField`: the two ordered condition lists that decide what gets held |
| `src/tls.rs` | `CertAuthority`, `TlsEngine`, `load_or_generate_ca`, `default_ca_dir`, `alpn_offer`, `negotiated_protocol`. CA generation/persistence, on-demand leaf signing, SNI resolution, ALPN decision |
| `src/tls_policy.rs` | `TlsPolicy`, `TlsAction` — which hosts get intercepted and which are tunnelled blind |
| `src/ws.rs` | `WsCapture`, `WsStats`, `relay` — the frame pump that takes over a connection after a `101`. Framing itself lives in `burpsy_core::ws` |
| `tests/interception.rs` | Integration tests driving the real HTTP API |
| `tests/websocket.rs` | A real handshake, a real origin and real client sockets through `serve` |
| `tests/alpn.rs` | ALPN negotiation through the real proxy against real TLS origins (h2-capable, http/1.1-only, no-ALPN) |
| `examples/intercept_e2e.rs` | Harness the e2e shell scripts drive; also probes the blocking transport to compare probe count against accepted TCP connections |

## For AI Agents

### This crate's socket calls are the documented exception

`src/lib.rs` opens sockets directly (four `TcpStream::connect` sites) and is the single entry in the
`ALLOWED` list of `crates/sender/tests/no_alternate_egress.rs`. The argument: it relays the client's
*own* bytes for ordinary browsing, which is not a constructed request, and `Scope` here governs whether
an exchange is **paused for operator review**, never whether it is forwarded. Gating browsing traffic
would turn the proxy into a blocklist.

Anything in this crate that builds a *new* request rather than relaying one must go through
`burpsy_sender::AuthorisedSender` instead. Do not widen the allowlist entry to cover that.

### Holding a response means buffering it, so the choice is made before it arrives

A byte already written to the client cannot be recalled, so `forward_http` and `mitm` each ask
`Interceptor::may_hold_response` *before* reading the response and only then decide between the
streaming relay (byte-identical to what they always did) and buffering the whole thing. That predicate
answers every response condition whose field is a request fact for real, and treats a condition only
the response can settle — its status code, its content type — as "maybe". Erring that way costs
latency on a route the rules name; erring the other way streams past a rule the operator wrote.

The response list is **inactive by default** while the request list is unconditional. That asymmetry is
deliberate: burpsy has never held a response, so flipping the master switch must not start. Every
pre-existing test in `tests/interception.rs` forwards a request and then awaits the client's response —
a blanket response default would hang all of them, which is the clearest possible statement of why. Two
things protect that default and both have tests: an omitted `active` on the wire is inferred from the
conditions rather than defaulted to true, and "blanket" means the list is *empty*, not that nothing in
it is enabled. Unticking the last box holds nothing; only deleting the rows means everything.

Because holding is what makes framing load-bearing, `response_complete_len` has to get three things
right that a streamed relay could survive getting wrong: a bodiless status (`204`, `304`) is checked
**before** `Content-Length`, a `HEAD` answer is complete at its head, and interim `1xx` heads are
stepped over before anything is framed, matched or recorded. Each has a test in `tests/interception.rs`
driven by `spawn_keepalive_origin`, which never closes — `spawn_origin` closes after one response, so
tests using it pass whether or not framing works at all. The same conclusions, reached first, are in
`crates/sender/src/transport/net.rs`; the two copies are separate because framing sits on each crate's
hot path and neither crate depends on the other.

### Passthrough exists because MITM genuinely breaks things

`TlsPolicy` is not a convenience. MITM breaks certificate-pinned clients, TLS client-auth, and
non-HTTP-over-TLS outright. IP-literal CONNECTs are always passed through — there is no SNI hostname to
sign for. Passthrough decisions are recorded and annotated in history rather than silently applied.

### CA material is written only when interception is requested

A plain HTTP session must not write key material to disk it does not need. `load_or_generate_ca` is
called from the CLI only under `--intercept-tls`. `/ca/`, `*.pem` and `*.key` are gitignored — never
commit generated CA material.

### HTTP/2 is negotiated and relayed

ALPN is decided from the **client's own offer**, peeked out of the ClientHello with
`LazyConfigAcceptor` before anything is dialled. The target chooses from that list, and the
client-facing config then offers exactly the one protocol the target picked — so the two legs never
carry different protocols. `Exchange.protocol` records what was actually negotiated.

A connection that lands on `h2` is **relayed** by `h2_relay::relay_h2`: the `h2` crate drives both
legs, every stream is forwarded to the origin and back, and each round trip is recorded as an
`Exchange` with `protocol: Protocol::Http2`. The stored bytes are a re-rendering in HTTP/1 shape
(start line + headers + body), not the wire octets — HPACK makes byte-exact replay impossible.
Interception (the hold queue) is not wired for h2 yet; streams are forwarded and recorded, not held.
Switching interception on makes the offer `http/1.1` only, which restores interception at the price
of a downgrade the operator caused and can see.

Three things that are easy to get wrong here:

- The switch is `Interceptor::is_enabled()`, not "an interceptor is attached". Keying on attachment
  would make a wiring decision look like an operator decision.
- Nor is it "a rule matched". Interception has ordered condition lists now (`InterceptRules`), and the
  ALPN offer must stay keyed on the master switch alone: the offer is settled from the ClientHello,
  before any request exists for a condition to match against. So an operator whose rules name one host
  still pays the downgrade on every host — that is inherent, not a bug to fix by consulting rules at
  handshake time. `is_enabled()` is a bare atomic load for exactly this reason, and
  `intercept::tests::conditions_do_not_move_the_switch_that_decides_alpn` fails if anyone changes it.
- A target sending **no** ALPN extension is HTTP/1.1, not assumed-h2. `e2e-tls.sh`'s Python origin
  sets no ALPN, so that arm runs on every gate.

### WebSocket: captured and relayed, not yet intercepted

An `Upgrade: websocket` request whose origin answers `101` hands the connection to `ws::relay`, which
pumps frames both ways and indexes each message into the store (`TrafficStore::add_ws_message`). This
works on both legs — plain HTTP and MITM — and the gate is the *request*: a request that did not ask
to upgrade takes byte-for-byte the path it always took.

Four rules here are load-bearing, in the order they matter:

1. **Relay before capture, always.** Every byte read is written to the far side *before* the decoder
   sees it, and the bytes written are the bytes read. No parse result and no cap can change what the
   two peers see. `tests/websocket.rs` asserts this against a frame the parser deliberately cannot
   handle.
2. **Capture is unmasked, the wire is not.** Client→server frames are masked; history shows the
   payload, the origin gets the mask. Conflating the two either fills history with noise or rewrites
   traffic.
3. **Desynchronisation stops the index, never the connection.** The one unrecoverable frame header
   (a 64-bit length with the reserved MSB set) ends capture for that direction, writes a marker
   exchange saying so, and keeps relaying. An inspection tool must not be the cause of an outage.
4. **Truncation is counted.** Messages are indexed up to `ws::DEFAULT_MAX_MESSAGE_BYTES` and the
   shortfall is on the row (`dropped`). The relay is unaffected — the cap bounds memory, not traffic.

What is **not** here yet: interception (a hold point with separate client→server / server→client
toggles) and WebSocket match-and-replace. Both plug in at the same place — after a message is
assembled, before it is forwarded — and both need something `Reassembler` deliberately does not
provide: frame boundaries with the original bytes preserved, so a held-but-unedited message can be
re-emitted byte-exact and an oversized frame can be streamed through unheld rather than mangled.
That is a `FrameSplitter` in `burpsy_core::ws`, and it is the first thing to build for phase 2.
Do not try to hold messages using `Reassembler`: it truncates, so a message over the cap could not be
forwarded at all after being withheld, and silently corrupting a live socket is the one outcome worse
than not intercepting it.

### `NetSender` used to live here

`src/sender.rs` was moved (via `git mv`, history preserved) to
`crates/sender/src/transport/blocking.rs`. The proxy's lib never used it; only the CLI constructed it.
If you are looking for the blocking transport with the keep-alive pool, it is in the sender crate now.

### The dev-dependency cycle is intentional

`proxy` dev-depends on `web`, while `web` depends on `proxy` for real. Cargo permits this precisely for
this case: the integration tests and the e2e example need to drive the real HTTP API. Do not try to
"fix" it by moving the tests.

### Testing Requirements

```bash
cargo test -p burpsy-proxy               # lib + integration tests (interception, alpn, websocket)
./e2e-intercept.sh                       # interception end-to-end
./e2e-tls.sh                             # TLS interception end-to-end
```

The e2e scripts are skipped by `QUICK=1 ./verify.sh` — run them directly when touching interception or
TLS.

### Common Patterns

- Failed CONNECTs are recorded in history rather than dropped, so a target that refuses is visible.
- Connection reuse is measurable, which is what `examples/intercept_e2e.rs`'s probe endpoint exists for.

## Dependencies

### Internal

- `burpsy-core` — the store, scope, message model
- `burpsy-bcheck` — check types on the scan handoff path
- `burpsy-scanner` — passive scanning off the hot path
- dev: `burpsy-web` (API for tests), `burpsy-sender` (the example measures the blocking transport)

### External

- `tokio`, `rustls`, `tokio-rustls`, `rcgen`, `rustls-pemfile`, `rustls-pki-types`, `time`
- `bytes`, `parking_lot`, `anyhow`, `tracing`, `serde`

<!-- MANUAL: -->
