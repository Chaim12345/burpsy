<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# sender (`burpsy-sender`)

## Purpose

The one authorising path from a constructed request to a socket. `AuthorisedSender` checks
`Scope::authorise_request` against the **actual outbound bytes** and only then reaches a transport,
which it owns as a private field.

Before this crate existed, three independent places had to remember the same thing: the scanner did it
correctly in a crate-private wrapper, and `repeater::send` was a public async function with no scope
awareness at all whose two callers hand-wired a check around it — one inline, one through an
`Option`al guard closure that compiled perfectly well when you forgot to attach it. Forgetting was a
valid program. That is what this crate removes.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | `AuthorisedSender`, `SendError`, `Target`, `parse_target`, `DEFAULT_SEND_TIMEOUT`. The scope decision lives in one private `authorise` method |
| `src/transport.rs` | Module declarations only, plus the note on why there are two transports |
| `src/transport/blocking.rs` | `NetSender` — blocking `std::net` + `rustls` with a keep-alive connection pool. Serves the synchronous BCheck evaluator. Moved here from `proxy` |
| `src/transport/net.rs` | The async `tokio` + `tokio-rustls` transport and `SendResult`. Moved here from the deleted `repeater` crate |
| `src/transport/tls.rs` | The single outbound no-verify client config, shared by both transports |
| `tests/no_alternate_egress.rs` | Workspace-wide source scan: fails the build if a new connect call appears outside this crate |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `src/transport/` | The two private transports and the shared TLS config (see `src/transport/AGENTS.md`) |

## For AI Agents

### What the guarantee actually is — do not overclaim it

This is the part most likely to be got wrong, because the intuitive answer is false here.

- **Structural, at the type level:** the transports are `pub(crate)`. Nothing outside this crate can
  construct or reach them, so a caller cannot skip the scope check by forgetting.
- **Not structural for `std::net`:** `std::net::TcpStream` is in the standard library, reachable from
  any crate, ungated by any Cargo feature.
- **Not structural for `tokio::net` either.** `intruder` narrows its `tokio` features so `net` is
  absent, and that *does* fail `cargo build -p burpsy-intruder`. It does **not** hold under
  `cargo build --workspace`: cargo unifies features across the graph, `web`/`sender`/`cli` all enable
  tokio's `full`, so one tokio rlib is compiled with `net` present and any crate linking it can name
  `tokio::net` again. This was measured — a `tokio::net::TcpStream::connect` planted in `intruder`
  compiles cleanly in a workspace build.

So `tests/no_alternate_egress.rs` is the **primary** mechanism for both, not a supplement covering only
`std::net`. It is a test, which is weaker than a compile error, and no comment here should describe it
as one. Earlier planning notes for this phase claimed the feature narrowing was a structural guarantee;
that claim was wrong and is corrected in `.planning/phases/01-*/01-CONTEXT.md`.

### The boundary that is deliberately outside

The proxy's MITM upstream forwarding does **not** go through this crate, and that is a considered
decision rather than an omission. It relays the client's *own* bytes for ordinary browsing — not a
constructed request — and `Scope` there governs whether an exchange is paused for operator review,
never whether it is forwarded. Gating browsing traffic would turn the proxy into a blocklist. It is the
one entry in the egress test's `ALLOWED` list, with that argument attached.

### Two transports, not interchangeable

One facade type, two wire implementations. The BCheck evaluator is deliberately synchronous and
recursive, and making it async would force `Box::pin` through every `exec`/`eval_bool` for no benefit;
Repeater and Intruder are already inside a runtime. HARD-03 asks for one authorising *type* — one place
the decision is made — not one wire implementation.

Calling the wrong one returns an error and **does not touch the counters**: they describe traffic
decisions, and a request that was never eligible to go anywhere is neither sent nor refused.

### `check_scope` is a query, not the gate

It exists for the one caller that needs the answer before it acts — the web repeater records to history
first, and an out-of-scope request should not land there. Skipping it changes what gets logged; it
cannot get an unauthorised request onto the wire, because the binding check runs inside every send
regardless.

### Counters are `AtomicU32`, not `Cell`

The wrapper this generalises used `Cell<u32>`, which compiled only because it was built fresh per audit
item and never shared. This type is meant to live behind one `Arc` across concurrent callers, and
`Cell` is not `Sync`. There is a test that shares one across four threads so the regression is a
compile error rather than a silent race.

### Do not seal the `Sender` trait

`burpsy_bcheck::eval::Sender` stays open. It is implemented by test doubles across the workspace
precisely so tests can prove traffic did or did not reach a socket; sealing it would destroy the
mechanism that makes this feature testable. The property worth enforcing is "nothing reaches a *real*
socket except through here", which is a private-field property, not a sealed-trait one.

### Testing Requirements

```bash
cargo test -p burpsy-sender                          # 32 lib tests + 3 egress-scan tests
cargo test -p burpsy-sender --test no_alternate_egress
```

The egress test is only worth having if it can fail. To confirm it still bites, plant a
`std::net::TcpStream::connect` in another crate's production `src/` and check that it reports the file
and line, then remove it.

Tests here must not touch DNS. Use `127.0.0.1` with a closed port for "scope allowed it, the network
said no", and `check_scope` for the in-scope case that should not send. A hostname like `shop.test`
costs a real resolver timeout — one such test took 15 seconds before it was changed.

## Dependencies

### Internal

- `burpsy-core` — `Scope` for the decision
- `burpsy-bcheck` — the `Sender` trait and `Target`, so the scanner's audit path can consume an
  `AuthorisedSender` directly

### External

- `tokio`, `tokio-rustls` — the async transport
- `rustls` — the blocking transport's TLS
- `bytes`, `parking_lot`, `anyhow`, `tracing`

<!-- MANUAL: -->
