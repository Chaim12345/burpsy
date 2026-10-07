<!-- Generated: 2026-08-17 | Updated: 2026-08-17 -->
<!-- Parent: ../AGENTS.md -->

# burpsy-go

## Purpose

The active implementation of burpsy, and where all new work lands. It is a Go port of the Rust
reference in `../crates/`; that tree is frozen and kept only as the parity oracle this port is
measured against (`gaps.md`). The two-tree rule — which one to edit, and why the Rust one must not
be "fixed" to track this one — lives in `../AGENTS.md`. This file is about working *inside* the Go
tree.

The thesis is unchanged from the Rust side: **raw bytes are stored once and never copied**, and
everything downstream (history rows, insertion points, attack results, findings) holds a message id
plus `(offset, len)` spans. `docs/DATA-MODEL.md` is the authoritative statement of the entities and
the identity hazard the types exist to prevent — two dense id spaces that both count from zero. Read
it before touching `internal/core`.

## Layout

| Path | What |
|------|------|
| `cmd/` | Binaries: the `burpsy` server+CLI, plus dev/test drivers (`conform`, `demo-target`, `crawl-scan-demo`, `live-test`). See `cmd/AGENTS.md` |
| `internal/` | The engine — one package per capability, dependency direction rooted at `core`. See `internal/AGENTS.md` for the package map |
| `internal/web/ui/` | The React web UI (TypeScript, bun-bundled, `go:embed`-ed into the binary). The design-system contract is `../DESIGN.md` |
| `pkg/` | The one piece meant to be importable outside the module (`graphqlmap`) |
| `bench/` | Traffic-store benchmarks (`realstore`, `storage`) |
| `docs/` | Go-side operator and coverage docs — start at `docs/README.md` |

## Module

A single module, `github.com/burpsy-go/burpsy`, `go 1.26`. Everything real is under `internal/`, so
nothing outside the module can import it — the engine surface is deliberately not a public API yet.

## The gate

```bash
go build ./...        # clean
go vet ./...          # clean
gofmt -l .            # prints nothing
go test ./...         # unit tests across every package
../e2e-go.sh          # end-to-end against the built binary
```

Anything under `internal/web/ui/` adds the live browser pass, which is the UI gate:

```bash
../ui-live.sh         # boots the real console, seeded, and prints the pass to drive
                      # with agent-browser; the definition is docs/UI-VERIFICATION.md
```

The playwright suite (`../e2e-ui.sh`) is still in the tree and still runs, but it is no longer the
gate — see `docs/UI-VERIFICATION.md` for why.

Do not declare work done without the gate for whatever you touched. `gofmt -l .` printing a path is
a failure, not a suggestion.

## For AI Agents

- **Honest counting is the project value.** A doc or a result that makes a partial state look
  complete is a defect here even when the tests pass. This is why coverage is always split into
  *parse conformance* vs *runtime coverage*, and why no single headline parity percentage is
  published until Security Research (CS-11) re-verifies it. The retracted "100% COMPLETE" claim the
  old `PORT_STATUS.md` carried is the anti-pattern to avoid.
- **Where the live status actually lives:** `gaps.md` (the source-verified Rust↔Go parity ledger),
  `PORT_STATUS.md` (recent verified work plus pointers), the dated `docs/HANDOFF-*.md` (latest
  wins), `docs/SCANNER-COVERAGE.md` and `docs/BCHECK-COVERAGE.md`. When these disagree with an
  older claim, they win.
- **`internal/sender` is the one authorised path to a socket.** Repeater, Intruder and active audit
  all send through an authorising sender that checks scope against the bytes actually going on the
  wire. Do not open a raw connection to reach a target from a new surface; route it through `sender`
  so the scope check is unforgettable rather than conventional.
- **When behaviour is ambiguous, the Rust crate is the specification.** Each `internal/<pkg>`
  usually mirrors `../crates/<pkg>`; match it, and record any deliberate difference in `gaps.md`.
- **Never commit the built binary.** A 33 MB `burpsy` and a 13 MB `crawl-scan-demo` have both been
  staged by mistake; `.gitignore` covers them, keep it that way.

## AGENTS.md within this tree

This root, `cmd/AGENTS.md`, `internal/AGENTS.md` (the package index), and one `AGENTS.md` per
meaningful `internal/` package. The two single-file helper packages (`internal/httputil`,
`internal/toollog`) are covered by `internal/AGENTS.md` rather than carrying their own — same "one
per meaningful unit, do not dilute" rule the Rust side follows.
