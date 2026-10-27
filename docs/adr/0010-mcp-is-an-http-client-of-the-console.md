# ADR 0010 — MCP is an HTTP client of the console, its tools derived from the route manifest

- **Status:** Accepted (recorded retroactively, 2026-10-27; Bead: adr-backfill)
- **Context artefacts:** `internal/mcp`, `cmd/burpsy-mcp`, `internal/web/route_manifest.go`, `internal/mcp/groups.go`, `burpsy-go/docs/MCP.md`

## Context

An agent driving burpsy must be held to the same scope, confirmation and audit rules as the console.
A second implementation of those rules for MCP would drift from the first.

## Decision

1. `burpsy-mcp` forwards every tool call over HTTP to a running console; it holds no state and makes no
   decision the console does not also make.
2. Its tools are generated from the route manifest; every manifest route is in exactly one MCP group or
   explicitly `notExposed`.
3. Confirmation-worthy routes need the console's one-time, call-bound token (`burpsy_confirm`).

## Consequences

- `internal/mcp` imports `internal/web` for the manifest only, so the thin client links the whole
  console (a known layering violation, bead `route-statements`: move the manifest to a leaf package).
- MCP cannot do anything the console's HTTP API refuses.
