<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# crates

## Purpose

The nine workspace crates. The split is not cosmetic — it enforces the dependency direction that
keeps the memory model intact. `core` owns the store and knows nothing about networks; `bcheck` is a
pure interpreter with no transport; `sender` is the only crate that opens a socket for a constructed
request. A crate boundary here is a statement about what a component is *not* allowed to reach.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `core/` | HTTP message model, the append-only store, segments, scope, sitemap, findings (see `core/AGENTS.md`) |
| `bcheck/` | Parser and evaluator for PortSwigger's BCheck DSL (see `bcheck/AGENTS.md`) |
| `scanner/` | Passive scanning, the active audit engine, Burp's issue catalog (see `scanner/AGENTS.md`) |
| `sender/` | The one authorising path from a constructed request to a socket (see `sender/AGENTS.md`) |
| `proxy/` | Intercepting HTTP/HTTPS proxy, CA, TLS policy (see `proxy/AGENTS.md`) |
| `intruder/` | Insertion-point discovery and payload attacks (see `intruder/AGENTS.md`) |
| `tools/` | Decoder, Comparer, Logger, Organizer, match-and-replace (see `tools/AGENTS.md`) |
| `web/` | JSON API and single-page UI (see `web/AGENTS.md`) |
| `cli/` | The `burpsy` binary that wires everything together (see `cli/AGENTS.md`) |

## For AI Agents

### Working In This Directory

**Adding a crate** means adding it to the workspace `members` list in the root `Cargo.toml`. Cargo
will not discover it otherwise.

**Adding a dependency edge** — check the direction first. The rule is that a crate may only depend
downward in the graph in the root `AGENTS.md`. Two edges in particular must not be added:

- Nothing may depend on `proxy` except `web` and `cli`. `proxy` already depends on `scanner`, so a
  `scanner → proxy` edge would be a cycle.
- `core` depends on no other burpsy crate and must stay that way. It is the one thing every other
  crate holds, and giving it a network or a parser dependency would make the memory model
  untestable in isolation.

**Anything that opens a socket for a constructed request belongs in `sender/`.** There is a test
(`sender/tests/no_alternate_egress.rs`) that scans every crate's production `src/` and fails the
build if a new `TcpStream::connect` / `TlsConnector::connect` / `ClientConnection::new` appears
outside it. If your new code genuinely is not a constructed request — the way the proxy's MITM
forwarding is not — add it to that test's `ALLOWED` list *with the argument for why*.

### Testing Requirements

Per crate during development, whole workspace before claiming done:

```bash
cargo test -p burpsy-<crate>
cargo test --workspace
```

Every crate keeps its tests inline in `#[cfg(test)] mod tests`, except `proxy` (which has
`tests/interception.rs` plus an `examples/intercept_e2e.rs` harness) and `sender` (which has
`tests/no_alternate_egress.rs`, a workspace-wide source scan that has to live outside the lib).

### Common Patterns

- Every crate's `lib.rs` opens with a `//!` header explaining **why the crate is shaped this way**,
  usually by naming what Burp does and why it was rejected. Read that header before changing a crate;
  it is where the design constraints are recorded.
- Several crates deliberately refuse capabilities they could easily have: `bcheck` has no transport,
  `intruder`'s engine documents that it "has no concept of engagement scope and should not grow one",
  `tools` has no clock or filesystem. Those refusals are load-bearing — do not "fix" them.

## Dependencies

### Internal

See the graph in the root `AGENTS.md`. Summarised: `core` is the root, `cli` is the leaf.

### External

Declared once in the root `Cargo.toml` `[workspace.dependencies]` and referenced as
`{ workspace = true }`. Crate-specific pins (`rustls`, `rcgen`, `axum`, `memmap2`, `crc32fast`,
`regex`) live in the individual manifests.

<!-- MANUAL: -->
