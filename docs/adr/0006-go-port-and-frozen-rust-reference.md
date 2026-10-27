# ADR 0006 — burpsy-go is the product; crates/ is a frozen parity oracle

- **Status:** Accepted (recorded retroactively, 2026-10-27; Bead: adr-backfill)
- **Context artefacts:** `AGENTS.md` (the two-tree table), `burpsy-go/gaps.md`, `scripts/review-gate.sh` (crates/ refused), ADR 0001

## Context

burpsy was first written in Rust (`crates/`, 13 crates, ~68k lines). The Go port in `burpsy-go/` overtook it:
the console, the scanner corpus and every feature since 2026-10-12 exist only in Go. Two trees that both
look buildable invite work in the wrong one, and the release workflow still built the Rust CLI until
`release-ships-rust` (ce12d6b).

## Decision

1. `burpsy-go/` is the only implementation that ships and the only one that receives features.
2. `crates/` is frozen: it is read as the specification when Go behaviour is ambiguous, and measured
   against through `burpsy-go/gaps.md` (ADR 0001). The review gate refuses any change under `crates/`.
3. Releases build the Go binaries (`cmd/burpsy`, `cmd/burpsy-mcp`), stamped with the tag (`internal/buildinfo`).

## Consequences

- The Rust crate boundaries ("the crate split enforces the dependency direction") no longer enforce
  anything; the Go layering is enforced by `internal/archtest` and the core/sender import tests instead.
- `verify.sh` and the root `e2e*.sh` suites still drive the Rust binary (bead `legacy-e2e-rust`).
