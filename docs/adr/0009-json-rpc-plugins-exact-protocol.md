# ADR 0009 — Extensions are JSON-RPC child processes with an exact protocol version

- **Status:** Accepted (recorded retroactively, 2026-10-27; Bead: adr-backfill)
- **Context artefacts:** `internal/extension/protocol.go` (`ProtocolVersion = 1`), `internal/extension/host.go`, `-plugins` allowlist, route class `riskExecute`

## Context

Burp's extensions run in-process with the tool's privileges. burpsy needs extensions without a plugin
ABI, without loading foreign code into the proxy's process, and without an API surface that lets a
caller start arbitrary binaries.

## Decision

1. An extension is a child process speaking JSON-RPC over stdio; `internal/extension` imports no other
   package of this module.
2. The host announces `ProtocolVersion` in `initialize` and requires an exact match: a mismatched
   extension is refused, not adapted.
3. Only binaries named in the `-plugins` allowlist can be started; the API names an allowlist key,
   never a path. Starting one is `riskExecute`, which is outside the confirmation set because the
   operator authorised the binary on the command line (pinned by
   `TestRiskExecuteIsExcludedFromTheConfirmationSetWithItsReason`).

## Consequences

- A protocol change is a version bump that every extension must follow; there is no negotiation.
- A crashing extension cannot take the proxy down with it.
