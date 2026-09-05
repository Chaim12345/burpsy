<!-- Generated: 2026-07-28 | Updated: 2026-09-04 -->

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

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:970c3bf2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale. Codex 0.129.0+ can load Beads context automatically through native hooks; use `/hooks` to inspect or toggle them.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.
<!-- END BEADS CODEX SETUP -->

## Beads issue tracker (bd)

Issues live in Beads (`bd`), Dolt-backed, remote-synced via `sync.remote` in `.beads/config.yaml`.
The Dolt DB is the source of truth; `.beads/issues.jsonl` is a possibly-stale export (2026-08-27:
146 open there vs 182 open in the DB — trust `bd`, not the JSONL).

- `bd` CLI (npm `@beads/bd`) — not preinstalled; sandbox install: `npm config set prefix ~/.npm-global && npm i -g @beads/bd` (global prefix `/usr/local` is root-owned).
- First-time DB setup in a fresh clone: `bd bootstrap --yes` (needs non-interactive git creds for the dolt refs fetch, and `chmod 700 .beads`). If `dolt clone` fails with `Error 1007: database exists`, rename `dolt_database` in `.beads/metadata.json` to a fresh name, `rm -rf .beads/embeddeddolt`, re-run bootstrap (bd v1.2.2 pre-creates the DB dir then collides with itself).
- `bd bootstrap`/`bd init` prompt `[Y/n]` on stdin — in non-interactive shells pass `--yes` or they hang forever with no output.
- Triage snapshot 2026-09-04: 258 total, 182 open (0 blocked, 100 ready; 13 open P1 = 5 epics + 8 tasks), 15 issues carry `decision-needed`. No duplicate titles detected. P1 claims spot-verified against code (intruder §-markers, proxy listener editor, logger bytes, intruder payload column all genuinely missing). Next up per `bd ready`: P1 intruder trio (33t, fvx, mun) under epic i4fa.
- Closed so far, one per commit: 33t (intruder payload positions via bcheck single-parser), fvx (intruder payload column), mun (manual § markers), 5bl (logger exchange links + detail viewer). Remaining P1 tasks per `bd ready`: 77m (proxy listener editor), 6rb (WS extensions toggle), vlf (history search checkboxes), t2s (scanner config keys) — each under its P1 epic.
