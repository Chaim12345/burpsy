<!-- Generated: 2026-07-28 | Updated: 2026-08-17 -->

# burpsy

## Purpose

A memory-frugal HTTP testing proxy with a web UI. It exists to run PortSwigger's published BCheck
corpus — unmodified and honestly counted — against real traffic without the memory cost that forces
Burp to discard scan work.

The whole architecture follows from one thesis: **raw bytes are written once and never copied.**
Everything downstream (history rows, insertion points, attack results, findings) holds a message id
plus `(offset, len)` spans. Burp's audit engine bounds cost by *discarding* work (`LIMIT_EXCEEDED`)
because `requests × insertion points × checks` is unbounded when each of those is a materialised
object. Here the resident set does not scale with work in flight, so the cap becomes backpressure
rather than dropped findings.

## Two trees: which one to work in

This repository holds **two implementations of burpsy**, and the distinction is the first thing to
get right:

| Tree | Language | Status | Work here? |
|------|----------|--------|------------|
| `burpsy-go/` | Go (module `github.com/burpsy-go/burpsy`) | **The active implementation.** All new feature work, the shipping binary, and the React web UI live here | **Yes — this is where changes land** |
| `crates/` | Rust (Cargo workspace, 13 crates) | **Frozen reference.** The original implementation, kept as the parity oracle the Go port is measured against | Read for behaviour and design intent; do not build new features here |

The Go port is measured against the Rust reference in `burpsy-go/gaps.md` — a source-verified ledger of
every known Rust↔Go difference. When behaviour is ambiguous, the Rust crate is the specification and
the Go package is the thing being made to match it. **Do not "fix" the Rust tree to track the Go one**;
it is deliberately frozen so it stays a stable oracle.

Because both trees exist side by side, be explicit about which one a path belongs to: `crates/scanner`
is Rust, `burpsy-go/internal/scanner` is Go, and they are different code with the same job.

## Key Files

| File | Description |
|------|-------------|
| `burpsy-go/` | **The Go implementation — the primary tree.** See `burpsy-go/AGENTS.md` |
| `crates/` | The Rust reference implementation, frozen (see `crates/AGENTS.md`) |
| `Cargo.toml` | Rust workspace manifest. Edition 2024, resolver 3, thirteen member crates |
| `verify.sh` | The Rust gate: build with zero warnings, clippy, unit tests, BCheck corpus conformance, e2e suites. `QUICK=1` skips e2e |
| `e2e-go.sh` | End-to-end smoke test that runs the **Go** binary — the Go analogue of `e2e.sh`, ports offset by 100 so the two suites cannot collide |
| `e2e-ui.sh` | End-to-end suite for the React web UI served by the Go binary |
| `ROADMAP.md` | Top-level feature roadmap / Burp teardown reference (the working plan lives in `.planning/`) |
| `DESIGN.md` | The design-system contract between the Figma source and the React UI in `burpsy-go/internal/web/ui/` |
| `serve.sh`, `integrate.sh` | Launch / integration harness for the Rust tree |
| `e2e.sh`, `e2e-audit.sh`, `e2e-intercept.sh`, `e2e-scan.sh`, `e2e-tls.sh` | Rust end-to-end suites, driven by `verify.sh` unless `QUICK=1` |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `burpsy-go/` | The Go implementation: `cmd/` binaries, `internal/` packages, `docs/`, and the React UI under `internal/web/ui/` (see `burpsy-go/AGENTS.md`) |
| `crates/` | The thirteen Rust reference crates (see `crates/AGENTS.md`) |
| `docs/` | Rust-side reverse-engineering and protocol research notes (see `docs/AGENTS.md`). Go-side docs live in `burpsy-go/docs/` |
| `.planning/` | GSD planning state — roadmap, requirements, per-phase context/plans/research. Not code; read it to understand *why* something is being built. Authored against the Rust tree; the Go port's live status lives in `burpsy-go/PORT_STATUS.md`, `burpsy-go/gaps.md`, and the dated `burpsy-go/docs/HANDOFF-*.md` |
| `.omc/`, `.superpowers/`, `.codebase-memory/` | Operational agent state. Gitignored or machine-generated; never edit by hand |

### Where AGENTS.md files live

There are two hierarchies, one per tree:

- **Rust** — one `AGENTS.md` per meaningful unit: this root, `crates/`, each of the thirteen crates,
  `docs/`, and two nested directories that carry their own rules (`crates/web/src/routes/`,
  `crates/sender/src/transport/`). There is deliberately **no** `AGENTS.md` in `crates/*/src/` — a
  crate's `src/` *is* the crate — nor in the single-purpose directories. Those gaps are the design;
  do not fill them with boilerplate.
- **Go** — `burpsy-go/AGENTS.md` at the tree root, `burpsy-go/cmd/AGENTS.md`, `burpsy-go/internal/AGENTS.md`
  as the package index, and one `AGENTS.md` per meaningful `internal/` package. The trivial
  single-file helper packages (`internal/httputil`, `internal/toollog`) are covered by
  `internal/AGENTS.md` rather than carrying their own — same "one per meaningful unit, don't dilute"
  rule as the Rust side.

## For AI Agents

### Working In This Directory

- **Default to the Go tree.** Unless a task is explicitly about the Rust reference, new work goes in
  `burpsy-go/`. Check `burpsy-go/gaps.md` before assuming a capability is missing — it may already be
  ported.
- **The Go gate is `go build ./... && go vet ./... && gofmt -l . && go test ./...`, all clean, plus
  `e2e-go.sh` / `e2e-ui.sh`.** The Rust gate is `verify.sh`. Run the gate for the tree you touched;
  do not declare work complete without it.
- **Commit messages here are unusually substantive** — they explain why a change is right and what
  the obvious alternative gets wrong. Match that; a one-line summary will look out of place.
- Never commit CA material or keys, and never commit compiled binaries (a 13 MB `crawl-scan-demo`
  and the 33 MB `burpsy-go/burpsy` binary have both been staged by mistake). `.gitignore` already
  excludes CA material, `*.pem`, `*.key`, and the build outputs.
- The project's stated value is **honest counting**. Coverage numbers, skipped checks and
  unverifiable results are reported, never hidden. Code — or a doc — that makes a partial result look
  complete is a defect here even when the tests pass. This is why coverage figures are stated as
  *parse conformance* vs *runtime coverage* separately, and why a single headline number is not
  published until Security Research (CS-11) re-verifies it.

### Testing Requirements

Go (the active tree):

```bash
cd burpsy-go
go build ./...                 # must be clean
go vet ./...                   # must be clean
gofmt -l .                     # must print nothing
go test ./...                  # unit tests across every package
../e2e-go.sh                   # end-to-end against the Go binary
../e2e-ui.sh                   # end-to-end for the React UI
```

Rust (the frozen reference):

```bash
cargo test --workspace          # ~1032 tests
cargo build --workspace         # must produce ZERO warnings
QUICK=1 ./verify.sh             # full gate minus e2e
./verify.sh                     # everything
```

### Known environment gotcha: clippy toolchain mismatch (Rust only)

This machine has **two Rust installations**. `/usr/bin/cargo` and `/usr/bin/rustc` are Debian
packages at 1.92.0 and win on `PATH`; `cargo-clippy` and `clippy-driver` exist only under rustup
(currently 1.95). Running plain `cargo clippy` mixes them and every crate fails with `E0514`. Use
`verify.sh`, which invokes clippy through rustup's own `cargo`, pins `RUSTC`, and gives clippy its own
`CARGO_TARGET_DIR`. A `rust-toolchain.toml` would not fix it — `/usr/bin/cargo` ignores it. This
affects only the Rust tree; the Go toolchain has no such split.

### Common Patterns (shared by both trees)

- **Doc comments explain *why*, including what the previous implementation got wrong.** See
  `crates/core/src/lib.rs`'s "The one invariant" or `burpsy-go/docs/DATA-MODEL.md`'s identity-hazard
  section (two dense id spaces that both count from zero).
- **Tests are named as full sentences that state a claim** and assert messages that say what a
  failure *means* rather than restating the comparison.
- **Invariants are made checkable, not asserted in prose** — `verify_index` / `VerifyIndex` both
  return the first disagreement they find and name the id.
- Refuse-by-default on unparseable input. A request whose path cannot be read is refused, never
  waved through.

## Dependencies

### Rust — crate order (depend only downward)

```
core  ──►  bcheck  ──►  scanner  ──►  proxy  ──►  web  ──►  cli
  │           │                          ▲         ▲         ▲
  ├──────────►└──►  sender  ─────────────┴─────────┤         │
  ├──►  intruder  ───────────────────────────────► │         │
  └──►  tools  ──────────────────────────────────► │         │
```

Leaves added later, all real edges: `http2` (used by `sender`, `proxy`), `query` (used by `core`,
`tools`, `web`), `session` (depends on `core`; used by `web`), `sequencer` (depends on `core`,
`sender`; used by `web`). `proxy` dev-depends on `web` (dev-only cycle, so integration tests can
drive the real HTTP API).

### Go

The Go tree is a single module (`github.com/burpsy-go/burpsy`, `go 1.26`) whose packages live under
`internal/`. The dependency direction mirrors the Rust spine — `core` is the root every package
holds, `sender` is the one authorising path to a socket — but is enforced by Go's package graph
rather than by crate manifests. See `burpsy-go/internal/AGENTS.md` for the package map. Notable
external dependencies: `golang.org/x/net/http2`, `chromedp`/`cdproto` (headless DOM confirmation),
`dop251/goja` (JS execution), `PuerkitoBio/goquery`, `projectdiscovery/wappalyzergo`,
`modernc.org/sqlite` (pure-Go SQLite mirror), `mvdan.cc/sh` (the `run tool` shell substrate),
`go.uber.org/zap` (logging).

### External (Rust)

- `tokio` 1.x — async runtime · `bytes` 1.12 — refcounted zero-copy slices · `rustls` 0.23 /
  `tokio-rustls` 0.26 / `rcgen` — TLS · `axum` 0.8 — web API · `memmap2` 0.9, `crc32fast` 1.5 —
  sealed segment storage · `parking_lot`, `regex`, `serde`, `anyhow`, `tracing`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
