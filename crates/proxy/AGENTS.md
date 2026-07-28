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
| `src/intercept.rs` | `Interceptor`, `Verdict`, `HeldView` — hold a request, let an operator rewrite it, then forward or drop |
| `src/tls.rs` | `CertAuthority`, `TlsEngine`, `load_or_generate_ca`, `default_ca_dir`, `alpn_offer`, `negotiated_protocol`. CA generation/persistence, on-demand leaf signing, SNI resolution, ALPN decision |
| `src/tls_policy.rs` | `TlsPolicy`, `TlsAction` — which hosts get intercepted and which are tunnelled blind |
| `tests/interception.rs` | Integration tests driving the real HTTP API |
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

### Passthrough exists because MITM genuinely breaks things

`TlsPolicy` is not a convenience. MITM breaks certificate-pinned clients, TLS client-auth, and
non-HTTP-over-TLS outright. IP-literal CONNECTs are always passed through — there is no SNI hostname to
sign for. Passthrough decisions are recorded and annotated in history rather than silently applied.

### CA material is written only when interception is requested

A plain HTTP session must not write key material to disk it does not need. `load_or_generate_ca` is
called from the CLI only under `--intercept-tls`. `/ca/`, `*.pem` and `*.key` are gitignored — never
commit generated CA material.

### HTTP/2 is negotiated and recorded, but not forwarded

ALPN is decided from the **client's own offer**, peeked out of the ClientHello with
`LazyConfigAcceptor` before anything is dialled. The target chooses from that list, and the
client-facing config then offers exactly the one protocol the target picked — so the two legs never
carry different protocols. `Exchange.protocol` records what was actually negotiated.

A connection that lands on `h2` is recorded (`Protocol::Http2`, plus a note) and closed, because
relaying it needs an h2 driver on both legs and a frame tap between them. The cost, which belongs in
operator-facing text and not just here: **while interception is switched off, an h2-capable origin
cannot be browsed through this proxy.** Switching interception on makes the offer `http/1.1` only,
which restores browsing and capture at the price of a downgrade the operator caused.

Two things that are easy to get wrong here:

- The switch is `Interceptor::is_enabled()`, not "an interceptor is attached". Keying on attachment
  would make a wiring decision look like an operator decision.
- A target sending **no** ALPN extension is HTTP/1.1, not assumed-h2. `e2e-tls.sh`'s Python origin
  sets no ALPN, so that arm runs on every gate.

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
cargo test -p burpsy-proxy               # 23 lib + 6 integration tests
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
