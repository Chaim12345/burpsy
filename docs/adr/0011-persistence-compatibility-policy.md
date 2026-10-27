# ADR 0011 — Persistence compatibility: user_version is the only mechanism

- **Status:** Proposed (needs the owner's decision; Bead: persistence-compat-policy, adr-backfill)
- **Context artefacts:** `internal/persist/migrate.go`, `persist.go` `SaveScope` (scope_rules v3/v2/legacy), the 27 JSON settings blobs, `scanconfig-persist-format` (8edc098)

## Context

Two strategies coexist. `migrate.go` has one step and refuses a database newer than the build. Schema
changes have instead been made by writing parallel tables (`scope_rules_v3`, `_v2`, legacy) on every save
so older builds can still read them. Twenty-seven settings are unversioned JSON blobs; one of them
(`scanconfig.overrides`, Go field names, decoded onto a zero struct) silently turned new default-on
scan switches off.

## Proposal

1. SQLite `user_version` is the only compatibility mechanism. Opening is forward-only: a build refuses a
   newer file, and migrates an older one after copying it to `<db>.bak-v<N>`.
2. No more parallel `_vN` tables. The first real migration step drops the `_v2`/legacy scope writes.
3. Every JSON blob carries `{"v": N}` and is decoded onto the current defaults, so an absent key keeps its
   default (the rule 8edc098 applied to the scan configuration).
4. Decide which store is durable for message bodies (SQLite or the segment log) and stop writing both.

## Consequences if accepted

- Downgrading a project file needs the `.bak` copy, not the old build.
- Each schema change is one reviewed migration step with a reopen test.
