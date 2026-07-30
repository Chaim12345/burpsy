<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# routes

## Purpose

Route modules, one per feature area.

The split answers a workflow problem, not an aesthetic one: every new tool wants to add endpoints, and a
single `lib.rs` route table makes that a serialised edit — two features landing at once collide on the
same lines. Each area owns a file and exports `routes()`, and `lib.rs` merges them. **Adding a tool means
adding a file, not editing a shared one.**

## Key Files

| File | Description |
|------|-------------|
| `mod.rs` | Declares the modules and exposes `all()`, which merges every area's `routes()` |
| `tools.rs` | Decoder / Comparer / Logger / Organizer / match-and-replace endpoints (the largest area) |
| `intercept.rs` | Held-request endpoints: view, edit, forward, drop |
| `sitemap.rs` | The host → path tree the UI navigates |
| `websockets.rs` | `/api/ws/history`, `/api/ws/message/{id}`, `/api/ws/connections` — a parallel history for upgraded connections, keyed by the handshake exchange |

## For AI Agents

### Adding a feature area

1. Create `<area>.rs` exporting `pub fn routes() -> Router<AppState>`.
2. Declare it in `mod.rs` and merge it in `all()`.
3. Do **not** add routes to `crates/web/src/lib.rs` — that is the collision this layout removes.

State comes from the shared `AppState` (`crate::AppState`), so a new area gets the store, scope,
findings, audit hook and intercept state for free. If your area needs new shared state, add a field to
`AppState` rather than threading a second extractor.

### Anything that sends must go through the chokepoint

These modules are handlers, so the rule from `../../AGENTS.md` applies here too: a new endpoint that
constructs and sends a request uses `burpsy_sender::AuthorisedSender`, never a bare transport and never a
hand-written `scope.authorise_request` call before one.

### Testing Requirements

```bash
cargo test -p burpsy-web
```

Each module keeps its tests inline in a `#[cfg(test)]` module and stands up a real listener where it needs
one. That is legitimate and expected — it is also why the workspace egress scan strips test modules.

### Common Patterns

- One `routes()` per file, merged centrally; no cross-module route registration.
- Handlers stay thin: parse, delegate to `core`/`tools`/`sender`, shape the response. Logic that is worth
  testing without HTTP belongs in the crate that owns it.

## Dependencies

### Internal

- `crate::AppState` — the shared handler state
- `burpsy-core`, `burpsy-tools`, `burpsy-proxy`, `burpsy-sender` via the parent crate's dependencies

### External

- `axum`, `serde`, `serde_json`, `tokio`

<!-- MANUAL: -->
