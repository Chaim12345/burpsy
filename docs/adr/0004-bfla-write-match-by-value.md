# ADR 0004 — A BFLA write is judged by value, with per-call values left out

- **Status:** Accepted
- **Date:** 2026-10-27
- **Context artefacts:** PR #363 review (`checks_bfla.go:103`), PR #364 code review, commits `83586df0`, `324fa6f0`

## Context

Under `CheckBFLA` + `CheckAPIWrites` the scanner replays a captured state-changing admin request
(POST/PUT/PATCH) as a low-privilege identity. Comparing answers by JSON shape alone reported a
`200 {"success":false,...}` refusal as a successful write, because the refusal envelope has the
success answer's shape. Comparing every value instead dropped real findings, because a write's
answer carries per-call values (a created id, a timestamp, a request id) that differ between any
two writes.

## Decision

1. B's answer must match the audited identity's answer **by value** on every stable leaf.
   Booleans and null are verdict leaves and always compared. Leaves that are per-call by name
   (`id`, `*_at`, `createdAt`, `requestId`, `version`, `etag`, ...) or by form (numbers,
   timestamps, UUIDs, long hex or base64 tokens) are left out (`bflaVolatileLeaf`).
2. The anonymous control for a write is judged the same way. A 200 refusal envelope answered to
   an anonymous caller is not "served anonymously".
3. DELETE is never replayed. The docs state that a captured write can reach the target up to three
   times: the harness baseline, the low-privilege replay and the anonymous control.

## Consequences

- Fixtures `/api/envelope/admin/settings` and `/api/anon-envelope/admin/settings` pin rules 1–2.
- A verdict key whose name looks per-call (for example a status field called `updated_at`) is not
  compared. The name rule is deliberately narrow (snake_case suffixes, camelCase capitalised
  suffixes) so that keys such as `action` and `session` still count.
