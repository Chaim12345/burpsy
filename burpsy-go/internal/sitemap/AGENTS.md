# sitemap

<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

## Purpose

Aggregates recorded HTTP exchanges into a navigable tree of hosts → paths → methods/statuses for the
web UI's site-map view. It mirrors the Rust `burpsy-core` sitemap module in intent (there is no
standalone `crates/sitemap` crate), but the Go version carries an extra requirement, CRAWL-05: the
map is built from traffic **continuously, with no separate crawl action**.

## Key Files

| File | Description |
|------|-------------|
| `sitemap.go` | The whole package: `SiteMap`, `HostNode`, `PathNode`, and the `New`/`Sync`/`Follow`/`Add` lifecycle, snapshot cloning, and the sorted accessors the UI reads. |
| `concurrent_test.go` | The two tests that matter here: reads are safe while traffic arrives, and a returned snapshot does not change when more traffic lands. |

## For AI Agents

- **`Follow` is the continuous path; `Sync` is only backfill/repair.** Registering the map as a
  store observer (`store.ObserveExchanges(sm.Add)`) is what makes CRAWL-05 real — an exchange lands in
  the tree as it is recorded, not when someone opens the tab. The GET /api/sitemap handler
  deliberately does **not** call `Sync`; if it did, a broken observer would be invisible — the exact
  "ported but never called" failure this project has shipped before.
- **Call `Follow` once per map, before traffic flows and after any Restore.** Following the same
  store twice subscribes twice and double-counts every later arrival. `ObserveExchanges` is one call
  (subscribe + drain the backlog) precisely so there is no window to miss or double-count.
- **Lock ordering is load-bearing, not incidental.** `Sync` snapshots the store (`store.Exchanges()`,
  which takes `ts.mu`) *before* taking `sm.mu`. The live path already holds `ts.mu` when it calls
  `Add` → `sm.mu`; taking `sm.mu` first here and then reaching into the store would be the AB-BA
  inversion that permanently deadlocks the capture path. `Add` only ever takes `sm.mu` and never
  reaches back into the store, which is why it is safe to call from the store's append path.
- **`Hosts()` returns a deep clone, and it must stay one.** `clone` copies the two count maps and the
  `ExchangeIDs` slice by value; copying the maps by reference would reintroduce exactly the crash the
  snapshot exists to prevent, because the append path mutates those maps in place under the lock.
- **Accessors sort on read** (`Hosts`, `PathsSorted`, `MethodsSorted`, `StatusesSorted`) so the UI gets
  stable ordering without the tree carrying it.

## Testing Requirements

```bash
go test ./internal/sitemap/...
```

`TestReadingTheTreeWhileTrafficArrivesIsSafe` and `TestASnapshotDoesNotChangeWhenMoreTrafficArrives`
are the invariants; run with `-race` when touching the locking. The full-tree gate still applies.

## Dependencies

Internal: `core` only — `TrafficStore` (`Exchanges`, `ObserveExchanges`), `Exchange`, and
`ExchangeID`. No external dependencies; even int/bool-to-string formatting is done in-package
(`intToStr`, `boolToStr`) rather than pulling in `strconv`.
