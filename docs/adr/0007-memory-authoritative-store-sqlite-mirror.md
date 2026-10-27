# ADR 0007 — Memory is authoritative; SQLite is a durable mirror

- **Status:** Accepted (recorded retroactively, 2026-10-27; Bead: adr-backfill)
- **Context artefacts:** `burpsy-go/docs/DATA-MODEL.md` §"Memory is authoritative", `internal/core/store.go`, `internal/persist`, `internal/web/api_project_open.go`

## Context

Capture is the hot path: every proxied exchange is stored before the next keep-alive request is read.
A database round trip on that path, or a database as the read model for history, would put SQLite in
front of every console read and every capture.

## Decision

1. `core.TrafficStore` and `core.FindingStore` are the source of truth while the process runs. Reads
   never go to SQLite.
2. `persist.Store` mirrors writes through sinks installed on the stores, and restores them on open.
   A failed mirror write is the mirror's failure, logged, not the capture's.
3. A project switch is serialised against capture by one lock taken before the stores' own mutexes
   (`core.CaptureGate`, `switch-deadlock`), and one exchange's writes are one hold (`core.CaptureHold`,
   `capture-split`), so a switch never splits an exchange across projects.
4. With `-capture-dir` message bytes live in mmap'd segments; without it they are resident.

## Consequences

- Restart correctness depends on every setting having a Save/Load pair and a restore call in
  `cmd/burpsy` (pinned by `TestSettingsWithNoTestSurviveAReopen` and `uat-cli.sh` step 6).
- The mirror still runs synchronously under the store lock (bead `store-global-lock`); resident mode
  grows the heap for the life of the process.
- Bodies are durable in two places (SQLite `messages.raw` and segments); ADR 0011 must decide which.
