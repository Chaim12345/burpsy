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
| `src/lib.rs` | `AppState`, the router builders (`router` … `router_intercept`), the `serve*` entry points, and the history / message / repeater / intruder / scope / issues / audit handlers |
| `src/routes/` | One module per feature area (see `src/routes/AGENTS.md`) |
| `src/ui.rs` | Serves the built UI: `include_str!`s `ui/index.html`, `ui/style.css`, and the Bun-bundled `ui/dist/app.js` (via `build.rs` + `OUT_DIR`) |
| `ui/` | The UI itself: TypeScript source in `ui/src/` (one module per tab, `common.ts` for shared helpers), bundled by Bun — see `build.rs` and `ui/src/AGENTS.md` if present |

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

### Scope is editable at runtime, and `AppState.scope` is a handle

`AppState.scope` is a `burpsy_core::SharedScope`, not an `Arc<Scope>`. `POST /api/scope/rules` and
`DELETE /api/scope/rules/{id}` edit it while the process runs, and because the binary hands every
subsystem a clone of the same handle, an edit reaches the proxy's capture gate, the scanner and both
senders at once. A handler that needs a scope decision calls `s.scope.contains(..)` / `may_contain_host`
directly — those forward through the read lock and return; do not hold `s.scope.read()` across an
`.await`.

Those two endpoints are the *only* things in this crate that mutate scope, and nothing else may call
them. Widening scope grants new authorisation, so it stays an explicit operator action with a
confirmation step in front of it — the same shape as Burp's own "add to scope" dialog. It must never
become a side effect of a scan, a redirect, or a captured request. The reasoning, including which of
the original objections to runtime mutation actually applied, is in `burpsy_core::scope`'s module docs.

`GET /api/scope`, and both mutations, answer with the same body (`scope_body`), so a mutation's response
*is* the new state and the UI never reconciles a partial update against a re-fetch.

### Payloads are generated, processed and counted here — before the engine sees them

`intruder_run` turns `payloads` / `payload_sets` / `payload_sources` into one `Vec<PayloadSource>`,
resolves each to a `PayloadSet`, and runs the `payload_rules` chain over it. All of that finishes before
`AttackPlan::new` is called, which is what makes `plan.len()` the number of requests: a payload a
`skip_if_matches` rule dropped never occupies an ordinal. See `crates/intruder/src/payload.rs` for why
that placement is load-bearing rather than convenient.

Two consequences for anything added here:

- **Every cap reports itself.** `RunView::payload_sets` carries `total` / `truncated` / `skipped` /
  `dropped` per set, because a set that was capped at 10 out of 200, or whose rules dropped half of it,
  must not look like a set the operator typed. Do not add a bound without a field that shows it.
- **Operator regexes compile at the edge.** `grep_match`, `grep_extract` and the rule patterns are all
  built here with a size limit, so a typo is one 400 rather than an attack that runs and reports
  nothing. `regex::bytes`, not `regex` — a response body is bytes.

### Blocking work must be offloaded

`run_audit` uses `tokio::task::spawn_blocking` because the BCheck evaluator is synchronous and each check
may open several connections. Running it on a runtime worker would stall every other request. Any new
handler that calls into the scanner or the blocking transport needs the same treatment.

### The router builders are a deliberate ladder

`router` → `router_with_ca` → `router_full` → `router_all` → `router_audit` → `router_export` →
`router_session` → `router_intercept`, each adding one capability and delegating. Same for `serve*`.
Add new capability at the bottom of the ladder and let the shorter forms keep working; do not change
an existing signature.

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
