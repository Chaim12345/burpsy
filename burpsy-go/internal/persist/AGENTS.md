<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# persist

## Purpose

The durable layer for burpsy's state. The runtime model is deliberately asymmetric: the in-memory
stores are authoritative and fast, and SQLite is a **write-through mirror**. Every mutation the
stores make — messages, exchanges, findings, scope rules, match & replace rules, session rules,
organizer items, tool log — is written to the database; on startup the database is loaded back into
the in-memory stores. Nothing is read from SQLite at runtime except the one-time `Restore`. A failed
write is logged, never fatal: traffic must not be dropped because the durable mirror hiccuped. There
is no Rust counterpart crate — persistence is a Go-tree concern.

## Key Files

| File | Description |
|------|-------------|
| `persist.go` | Everything: `Store`, `Open`, `migrate`/`addColumn`, per-store `Save*`/`Load*` pairs, and `Restore` which fans loaded rows back into the in-memory stores |

## For AI Agents

- **The mirror never copies payload bytes twice.** `messages` gained `(segment, offset, length,
  shape)` columns so a disk-backed message stores its span, not its bytes: with a capture directory
  the bytes are already durable in a segment file. On a 419 MB capture this was a 2.7 MB database vs
  436 MB, and a restart of 288ms/22 MB vs 3.1s/623 MB. `raw` stays `NOT NULL` (SQLite can't relax it
  via ALTER); a span row writes a zero-length blob. `LoadMessages` requires a `*core.SegmentLog` to
  resolve spans and **refuses** a span row with no segment log rather than reading it as empty.
- **Schema evolution is additive, and old rows must still load.** `migrate` runs `CREATE TABLE IF
  NOT EXISTS` then `addColumn` (idempotent, checks `PRAGMA table_info` first). A row written by an
  older build carries no new column and reads back as NULL — and every NULL fallback is chosen so the
  legacy reading is *honest*, not guessed:
  - `exchanges.duration_us`: NULL = unmeasured. A legacy row has only `duration_ms`; `LoadExchanges`
    reads `ms > 0` as measured-at-ms-precision and `ms == 0` as *unmeasured* (not a measured zero),
    the same fail-safe direction as treating an unrecorded check as never dispatched.
  - `tool_log.response_len`: NULL = no response measured (a failed send), a different fact from zero
    bytes.
  - `findings.param` / `exchanges.highlight`: NULL reads as empty, correct because a legacy row and
    an unset value mean the same thing.
- **`session_rules.ord` exists because evaluation order is data.** `Coordinator.MatchingRule` returns
  the *first* rule covering a host, so order decides which login runs. Before `ord`, load had no
  `ORDER BY` and a restart could silently promote a different rule to first. Legacy rows (`ord` NULL)
  order by id, the order they were written in.
- **`Restore` keeps going past a bad session rule** rather than returning, so one unrestorable rule
  doesn't take the organizer and tool log down with it. It calls `session.RestoreRule` (which keeps
  ids) not `AddRule`, and counts validation refusals and `ErrDuplicateRuleID` collisions *separately*
  — two different faults with different fixes; each is logged with a message spelling out that the
  affected hosts now go out unauthenticated.
- **Scope has two tables.** `scope_rules` (legacy, `(kind, pattern)` PK) and `scope_rules_v2`
  (ordered, with `path_prefix`). `SaveScope` mirrors to both; `LoadScope` prefers v2 and falls back
  to the legacy table, and reports a legacy row this build did not write (divergence check).
- **Single writer.** `Open` sets `SetMaxOpenConns(1)`, WAL, `synchronous=NORMAL`,
  `busy_timeout=5000` — SQLite is single-writer; writes serialise through one connection.

## Testing Requirements

```bash
go test ./internal/persist/...
```

Tests cover round-trips per store, duration precision (`duration_test.go`), span storage vs resident
bytes (`spans_test.go`), scope legacy/v2 handling (`scope_restore_test.go`), session-rule id/order
preservation (`session_restore_test.go`), and idempotent re-open.

## Dependencies

Internal: `core` (`TrafficStore`, `SegmentLog`, `StoredMessage`, `Exchange`, `Finding`, `Scope`,
message shapes), `matchreplace` (`Rule`, `RuleSet`), `organizer` (`Item`, `Store`), `session`
(`SessionRule`, `Coordinator`, `RuleID`, `ErrDuplicateRuleID`), `toollog` (`Entry`, `ToolLog`).

External: `modernc.org/sqlite` (pure-Go SQLite driver, imported blank via `database/sql`),
`go.uber.org/zap` (mirror-write diagnostics).
