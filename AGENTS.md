<!-- Generated: 2026-07-28 | Updated: 2026-08-05 -->

# burpsy

## Purpose

A memory-frugal HTTP testing proxy with a web UI. It exists to run PortSwigger's published BCheck
corpus — unmodified and honestly counted — against real traffic without the memory cost that forces
Burp to discard scan work.

The whole architecture follows from one thesis: **raw bytes are written once and never copied.**
Everything downstream (history rows, insertion points, attack results, findings) holds a `MsgId` plus
`(offset, len)` spans. Burp's audit engine bounds cost by *discarding* work (`LIMIT_EXCEEDED`)
because `requests × insertion points × checks` is unbounded when each of those is a materialised
object. Here the resident set does not scale with work in flight, so the cap becomes backpressure
rather than dropped findings.

### Two codebases

This repo holds **two implementations** of the same system:

| | Rust (`crates/`) | Go (`burpsy-go/`) |
|---|---|---|
| Role | Reference implementation, stable since 2026-07-28 | **Active development line** |
| Language | Rust 2024 (workspace, 13 crates) | Go 1.26 (24 packages) |
| Tests | 1,032 | 1,029 |
| Status | Feature-complete for Phases 1–5, 7; partial 2/4/9 | All 13 Rust-parity gaps closed; Phases 1–7, 11 complete |

The Rust tree proved the architecture and is the reference for the memory model, scope chokepoint, and
the egress-authorisation design. New features land in Go. Planning docs (`.planning/`) name which
language satisfies each requirement — "Complete" without qualification means both.

## Key Files

| File | Description |
|------|-------------|
| `Cargo.toml` | Workspace manifest. Edition 2024, resolver 3, thirteen member crates |
| `verify.sh` | **The gate** (Rust). Build with zero warnings, clippy, unit tests, BCheck corpus conformance, e2e suites. `QUICK=1` skips e2e |
| `ROADMAP.md` | Top-level feature roadmap (the working plan lives in `.planning/`) |
| `serve.sh` | Launch the proxy + web UI locally |
| `integrate.sh` | Integration harness |
| `e2e.sh`, `e2e-audit.sh`, `e2e-intercept.sh`, `e2e-scan.sh`, `e2e-tls.sh` | End-to-end suites (Rust), driven by `verify.sh` unless `QUICK=1` |
| `burpsy-go/` | The Go port — active development line. `go test ./...` runs 1,029 tests |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `crates/` | All thirteen workspace crates (see `crates/AGENTS.md`) |
| `burpsy-go/` | The Go port — 24 packages, active development (see `burpsy-go/AGENTS.md`) |
| `docs/` | Reverse-engineering and protocol research notes (see `docs/AGENTS.md`) |
| `.planning/` | GSD planning state — roadmap, requirements, per-phase context/plans/research. Not code; read it to understand *why* something is being built |
| `.omc/` | Operational agent state. Gitignored, never edit by hand |

### Where AGENTS.md files live, and where they deliberately do not

There are 20, one per meaningful unit: this root, `crates/`, each of the thirteen crates, `docs/`,
`burpsy-go/`, and two nested directories that carry their own rules (`crates/web/src/routes/`,
`crates/sender/src/transport/`).

There is deliberately **no** `AGENTS.md` in `crates/*/src/` — a crate's `src/` *is* the crate, and a file
there would duplicate the crate-level one. Same for the single-purpose directories
(`crates/bcheck/src/bin/`, `crates/proxy/{tests,examples}/`, `crates/sender/tests/`,
`crates/scanner/tools/`), which are covered by their crate's document. If you are regenerating this
hierarchy, do not "fill the gaps" — the gaps are the design, and boilerplate in them would dilute the
files that carry real content.

## For AI Agents

### Working In This Directory

- **`verify.sh` is the definition of done.** It treats build warnings as failures. Do not declare
  work complete without running it.
- **Commit messages here are unusually substantive** — they explain why a change is right and what
  the obvious alternative gets wrong. Match that; a one-line summary will look out of place.
- Never commit CA material or keys. `.gitignore` already excludes `/ca/`, `*.pem`, `*.key`.
- The project's stated value is **honest counting**. Coverage numbers, skipped checks and unverifiable
  results are reported, never hidden. Code that makes a partial result look complete is a defect here
  even when it passes tests.

### Testing Requirements

```bash
# Rust
cargo test --workspace          # 1032 tests
cargo build --workspace         # must produce ZERO warnings
QUICK=1 ./verify.sh             # full gate minus e2e
./verify.sh                     # everything

# Go
cd burpsy-go && go test ./...   # 1029 tests, 23 packages
```

### Known environment gotcha: clippy toolchain mismatch

This machine has **two Rust installations**. `/usr/bin/cargo` and `/usr/bin/rustc` are Debian
packages at 1.92.0 and win on `PATH`; `cargo-clippy` and `clippy-driver` exist only under rustup
(currently 1.95). Running plain `cargo clippy` mixes them and every crate fails with `E0514`
("found crate X compiled by an incompatible version of rustc").

`verify.sh` already handles this and documents it at length: it invokes clippy through rustup's own
`cargo`, pins `RUSTC` explicitly (cargo resolves `rustc` by bare `PATH` lookup otherwise), and uses a
separate `CARGO_TARGET_DIR=target/clippy` because clippy sets `RUSTC_WORKSPACE_WRAPPER` and would
otherwise thrash the shared fingerprint. A `rust-toolchain.toml` would **not** fix it — that is a
rustup feature and `/usr/bin/cargo` ignores it. Use `verify.sh`, not bare `cargo clippy`.

### Common Patterns

- **Doc comments explain *why*, including what the previous implementation got wrong.** See
  `crates/core/src/lib.rs`'s "The one invariant" or `crates/sender/src/lib.rs`'s guarantee section.
- **Tests are named as full sentences that state a claim** (`an_oversized_message_gets_its_own_segment_rather_than_being_refused`),
  carry their requirement id in a doc comment, and assert messages say what a failure *means* rather
  than restating the comparison.
- **Invariants are made checkable, not asserted in prose.** `TrafficStore::verify_index` and
  `verify_capture_dir` both return the first disagreement they find and name the id.
- Refuse-by-default on unparseable input. A request whose path cannot be read is refused, never
  waved through.

## Dependencies

### Internal — crate order (depend only downward)

The spine has not changed — every edge drawn here is real and current:

```
core  ──►  bcheck  ──►  scanner  ──►  proxy  ──►  web  ──►  cli
  │           │                          ▲         ▲         ▲
  ├──────────►└──►  sender  ─────────────┴─────────┤         │
  ├──►  intruder  ───────────────────────────────► │         │
  └──►  tools  ──────────────────────────────────► │         │
```

Crates added since this diagram was drawn (all real edges, `path = "../<crate>"` in the manifests):

- **`http2`** — a leaf with no burpsy dependencies; `sender` and `proxy` depend on it. Pure
  framing/HPACK/normalisation over bytes, no sockets.
- **`query`** — a leaf; `core`, `tools`, and `web` depend on it. Typed filter grammar.
- **`session`** — depends on `core`; consumed by `web`. Re-login policy as a trait (`MacroSender`),
  not a call into `sender` — the HARD-03 chokepoint wiring lives in `cli`/`web`, not here.
- **`sequencer`** — depends on `core` and `sender`; consumed by `web`.
- Edge additions to the spine: `intruder` also depends on `tools`; `tools` also depends on `query`;
  `web` also depends on `session`, `sequencer`, and `query`; `sender` and `proxy` also depend on
  `http2`; `cli` also depends on `scanner`.

`proxy` additionally dev-depends on `web` — cargo permits that cycle because it is dev-only, and it
exists so the proxy's integration tests can drive the real HTTP API.

### External

**Rust:**

- `tokio` 1.x (workspace: `features = ["full"]`) — async runtime
- `bytes` 1.12 — refcounted zero-copy slices; the whole memory model rests on it
- `rustls` 0.23 / `tokio-rustls` 0.26 / `rcgen` — TLS, both legs
- `axum` 0.8 — web API
- `memmap2` 0.9, `crc32fast` 1.5 — sealed segment storage
- `parking_lot` — locks
- `regex`, `serde`, `anyhow`, `tracing`

**Go:**

- `golang.org/x/net/http2` — HTTP/2 transport (conformant relay)
- Standard library only for the hand-rolled frame/HPACK/malformed layer

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
