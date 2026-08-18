<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# organizer

## Purpose

The UI's in-memory "shortlist" of saved exchanges — the Go analogue of the Rust `burpsy-tools` organizer, split out into its own package. Deliberately ephemeral: state lives for the process lifetime only and is never persisted, so the web layer and the CLI share one implementation instead of drifting.

## Key Files

| File | Description |
|------|-------------|
| `organizer.go` | `Item` (id, exchange, title, note, highlight) and `Store`: `Add`, `List`, `Update`, `Remove`, `SetBaseID`, `Restore` |

## For AI Agents

- **The lock is a `chan struct{}` of capacity one, not a `sync.Mutex`.** That is a deliberate choice to keep the package dependency-free (no import block at all) while staying safe to call from HTTP handlers. Do not "simplify" it to `sync.Mutex` without reason — the point is zero dependencies.
- **A new `Item`'s `Highlight` defaults to `"none"`, not empty string** (see `Add`; the round-trip test pins it). Callers and the UI rely on that literal.
- **`SetBaseID`/`Restore` exist for rehydration** — restoring a prior list and continuing the id sequence — since nothing is persisted here. The persistence, if any, is the caller's job.
- **Ids count from 1**, assigned by an internal `next` counter.

## Testing Requirements

```bash
go test ./internal/organizer/...
```

## Dependencies

- Internal: none — a leaf package.
- External: none (no imports at all).
