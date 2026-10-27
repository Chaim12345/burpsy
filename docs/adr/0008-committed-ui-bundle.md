# ADR 0008 — The console bundle is committed and embedded

- **Status:** Accepted (recorded retroactively, 2026-10-27; Bead: adr-backfill)
- **Context artefacts:** `internal/web/ui/dist/`, `internal/web/ui.go` (`go:embed`), `.github/workflows/go.yml` (`ui` job, bundle freshness), `CLAUDE.md` gotchas

## Context

The Go binary serves the React console from `go:embed`. `go install` and `go build` from a checkout must
produce a working console without a JavaScript toolchain.

## Decision

1. `dist/app.js` and `dist/style.css` are committed.
2. Only the lead rebuilds them, once per round, with the pinned bun (1.4.2); implementing agents never
   commit them.
3. CI rebuilds and fails when the committed bundle differs (`ui` job, bundle freshness).

## Consequences

- Every UI change round carries one bundle commit (~2.7 MB file; 34 of the visible commits touch it).
- A stale bundle cannot merge, and a Go-only contributor never needs bun.
- Alternative rejected: build in CI and release only, embedding a stub otherwise — it breaks `go install`.
