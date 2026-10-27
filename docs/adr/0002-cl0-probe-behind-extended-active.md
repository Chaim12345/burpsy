# ADR 0002 — The CL.0 smuggled-prefix probe runs only under CheckExtendedActive

- **Status:** Accepted
- **Date:** 2026-10-27
- **Context artefacts:** PR #363 review (`checks_smuggling.go:346`), commits `393d2ed1`, `324fa6f0`

## Context

`CheckRequestSmuggling` promises that nothing is queued on a back-end connection: CL.TE, TE.CL and
the HTTP/2 downgrades are detected by timing against a consistently framed control. The CL.0
smuggled-prefix probe (`checks_smuggling_cl0.go`) is different. The scanner owns only the
client-side socket; behind a front end that pools back-end connections and honours
`Content-Length`, the smuggled canary's answer can wait on a SHARED back-end connection and arrive
in the response slot of another user's request.

Backlog work re-enabled the probe inside the plain smuggling run, with a finding text claiming
"nothing was queued for any other user's connection".

## Decision

1. The CL.0 probe is not part of `CheckRequestSmuggling`. It runs only under
   `CheckExtendedActive`, the opt-in that already admits "Client-side desync", and the
   `ScanConfig` doc for that switch names the shared-connection risk.
2. The two rows that read the probe share one result per endpoint (`cl0Probes`), so the prefix is
   sent once, however many rows report from it.
3. Finding and code comments say plainly that the probe can leave a response on a pooled back-end
   connection. They never claim it stays on the scanner's connection.

## Consequences

- A plain smuggling run no longer reports CL.0. Operators who want it opt into extended active.
- `TestCL0NeedsTheExtendedActiveOptIn` and `TestCL0ProbeIsSentOncePerEndpoint` pin both rules.
