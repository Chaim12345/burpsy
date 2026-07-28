<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# web (`burpsy-web`)

## Purpose

The JSON API and a single-page UI. Browser-based rather than a native GUI for the reason Caido gets
right: the perceived slowness of Burp is largely Swing, and a web front end also makes the tool usable
headless or over SSH.

The API deliberately returns **index rows** for history — `Exchange`, which holds `MsgId`s and lengths —
and fetches message bytes only when a specific message is opened. Listing 100k exchanges therefore
never touches a single body.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | `AppState`, the router builders (`router` … `router_audit`), the `serve*` entry points, and the history / message / repeater / intruder / scope / issues / audit handlers |
| `src/routes/` | One module per feature area (see `src/routes/AGENTS.md`) |

## For AI Agents

### `AppState` holds an `AuditHook`, not a scanner

```rust
pub type AuditHook = Arc<dyn Fn(u64) -> serde_json::Value + Send + Sync>;
```

A closure rather than a scanner handle, so this crate needs no dependency on the scanner: the binary
owns that wiring and the web layer only needs "given an exchange id, audit it". Keep it that way — a
direct `burpsy-scanner` dependency here would invert the intended direction.

### Scope checks are no longer written in handlers

Both attack surfaces used to hand-wire authorisation. They now use
`burpsy_sender::AuthorisedSender`, which cannot be asked to send without checking:

- `repeater_send` builds one and calls `send_async`. It *also* calls `check_scope` up front — not as
  the gate, but so an out-of-scope request never reaches history, since the handler records the request
  before sending. `SendError::is_refused()` is what distinguishes 403 from 502; collapsing them would
  make an out-of-scope request look like a broken server.
- `intruder_run` builds one `AuthorisedSender` for the whole attack and injects it as the `SendFn`. The
  old `Attack::with_guard(...)` call is gone — the guard was `Option`al, so forgetting it compiled.

**Do not add a bare scope check to a new handler.** Route the send through the chokepoint; that is what
makes the check unforgettable rather than conventional.

### Blocking work must be offloaded

`run_audit` uses `tokio::task::spawn_blocking` because the BCheck evaluator is synchronous and each check
may open several connections. Running it on a runtime worker would stall every other request. Any new
handler that calls into the scanner or the blocking transport needs the same treatment.

### The router builders are a deliberate ladder

`router` → `router_with_ca` → `router_full` → `router_all` → `router_audit`, each adding one capability
and delegating. Same for `serve*`. Add new capability at the bottom of the ladder and let the shorter
forms keep working; do not change an existing signature.

### Testing Requirements

```bash
cargo test -p burpsy-web       # 22 tests (lib + route modules)
```

Tests open real `tokio::net` listeners inside `#[cfg(test)]` modules, which is why the egress source scan
strips test modules before scanning — see `crates/sender/tests/no_alternate_egress.rs`.

### Common Patterns

- Handlers return `impl IntoResponse` and build errors as `(StatusCode, String)`.
- History and message endpoints are separate on purpose. If you find a handler resolving bodies to build
  a list, that is the regression this API shape exists to prevent.

## Dependencies

### Internal

- `burpsy-core` — store, scope, findings
- `burpsy-sender` — `AuthorisedSender`, `parse_target`; the only path to a socket for repeater/intruder
- `burpsy-intruder` — attack planning and execution
- `burpsy-tools` — decoder/comparer/logger/organizer endpoints
- `burpsy-proxy` — interception state for the intercept routes

### External

- `axum` 0.8 — routing and extraction
- `tokio`, `bytes`, `serde`, `serde_json`, `parking_lot`, `anyhow`, `tracing`

<!-- MANUAL: -->
