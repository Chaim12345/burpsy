<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# transport

## Purpose

The private transports. Everything here is `pub(crate)`: reaching a socket means going through
`crate::AuthorisedSender`, which checks scope first. **This visibility is the only part of the HARD-03
guarantee that the type system actually enforces** — do not make anything here `pub`.

## Key Files

| File | Description |
|------|-------------|
| `blocking.rs` | `NetSender` — blocking `std::net::TcpStream` + `rustls::StreamOwned`, with a keep-alive connection pool and framing learning. Implements `burpsy_bcheck::eval::Sender`. Moved from `crates/proxy/src/sender.rs` |
| `net.rs` | The async `tokio` + `tokio-rustls` transport, plus `SendResult` and response framing (`Content-Length`, chunked). Moved from the deleted `repeater` crate |
| `tls.rs` | `insecure_client_config()` — the one outbound no-verify TLS config, shared by both |

## For AI Agents

### Why there are two, and why that is not drift

The BCheck evaluator is deliberately synchronous and recursive; making it async would force `Box::pin`
through every `exec`/`eval_bool` for no benefit, and `blocking.rs`'s own doc comment explains that.
Repeater and Intruder are already inside a tokio runtime. HARD-03 asks for one authorising *type* — one
place the scope decision is made and one way out to the network — not one wire implementation underneath
it.

Do not unify them by bridging the sync path onto the async one with a blocking runtime call. That would
undo the reasoning rather than satisfy the requirement.

### `NetSender` is the one `pub` re-export, and only because callers must construct it

`crate::NetSender` is re-exported so `AuthorisedSender::blocking(scope, NetSender::default())` is
callable. That is the whole reason. Its `send` still only does anything useful when reached through the
facade, and the workspace egress scan is what catches anyone using it as a standalone transport.

### Certificate verification is off, deliberately

`tls.rs` does not verify server certificates: a testing proxy has to reach staging hosts with
self-signed, expired or mismatched certs, and refusing them would make the tool useless for most real
work. The security boundary is not certificate validation — it is that burpsy is an explicit local tool
the operator aimed at targets they are authorised to test, and `AuthorisedSender` enforces the second
half of that.

This config existed **twice** before the crate was created — once in the proxy's `tls` module for the
blocking leg, once in the repeater for the async one, with identical `NoVerify` boilerplate. Two copies
of a certificate-verification decision is one more than anyone should have to audit. Keep it at one.

### Framing matters for keep-alive

Both transports honour `Content-Length` and `Transfer-Encoding: chunked` so a keep-alive server does not
stall until timeout, falling back to read-to-EOF. `blocking.rs` additionally *learns* framing per
host/port/tls key (`Framed::Unknown` → close-per-probe → learn) and only pools connections it can frame
exactly. A pooled socket the server reaped while idle yields zero bytes, which is retried once on a
fresh connection — and only a zero-byte failure qualifies, so a probe that got a partial response is
never silently sent twice.

### Testing Requirements

```bash
cargo test -p burpsy-sender
```

`net.rs` keeps framing/status unit tests inline. Prefer pure-function tests over real sockets here; the
socket-level behaviour is covered by the facade's tests in `../lib.rs` and by `proxy`'s e2e example,
which measures probe count against accepted TCP connections.

## Dependencies

### Internal

- `burpsy_bcheck::eval::{Sender, Target}` — the trait the blocking transport implements, and the shared
  target type
- `burpsy_core::edit::RequestEdit` — used on the blocking path

### External

- `std::net` + `rustls` (blocking), `tokio` + `tokio-rustls` (async)
- `parking_lot` for the pool, `bytes`, `anyhow`, `tracing`

<!-- MANUAL: -->
