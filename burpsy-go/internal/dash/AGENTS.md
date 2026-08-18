<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# dash

## Purpose

The dashboard's shared vocabulary and the runtime state behind the operator-facing view of
long-running work. It exists so that the project value — honest counting — is a property of the
*surface* rather than a per-feature accident: every count on the dashboard has one shape that says
what it did not look at, and every long-running thing announces itself while it is still running
instead of only at the end.

Three concerns live here: `Breakdown`/`Summary` (the one count shape, DASH-03), the task `Registry`
(work-in-flight, DASH-01), and the `EventLog` (what the tool did, DASH-02).

## Key Files

| File | Description |
|------|-------------|
| `breakdown.go` | `Bucket` (found/skipped/errored/gated), `Reason`, `Breakdown` (four buckets, custom Marshal/UnmarshalJSON), and `Summary`/`NewSummary` — the count shape every pane projects into |
| `tasks.go` | The task `Registry`, `Task`, `Handle`, `Kind` (audit, crawl, intruder, sequencer-capture, …) and `TaskState`. Start/advance/finish, capacity eviction, cancellation, and the aggregate `Breakdown`/`Reasons` over live work |
| `events.go` | `EventLog`, `Event`, and a second `Severity` (info/warn/error). Bounded newest-first ring, drop counting, restore-from-snapshot, and `Registry.WithEvents` wiring |
| `dash_test.go`, `events_test.go` | Tests for the breakdown/summary/registry invariants and the event log + task-lifecycle emission |

## For AI Agents

- **There is deliberately no total.** `Found` is in the summary's `Unit` (issues, URLs); `Skipped`/
  `Errored`/`Gated` are in `WorkUnit` (units of work with no verdict). They are never summed —
  "12 issues plus 3 checks that never ran" is not a number. Do not add a `Total()`. `Complete()` and
  `Unaccounted()` are the sanctioned derived values.
- **`Breakdown.MarshalJSON` writes all four buckets with no `omitempty`, plus derived
  `unaccounted`/`complete`/`summary`.** A zero `Breakdown` still emits every key, so a UI cannot lose
  a caveat just because it happened to be zero. Keep that asymmetry with the struct.
- **`NewSummary` refuses to let a caveat travel nameless.** A non-`Complete` breakdown with no
  reasons gets a synthetic `unattributed` reason (`unattributedDetail`) rather than a silent gap —
  the missing projection is meant to be visible, not papered over. Zero-count reasons are dropped.
- **`*Handle` (and `*Registry`) methods are nil-safe by design.** A caller with no registry wired
  gets a nil handle and calls `Advance`/`Finish` unconditionally; the alternative is a forgotten nil
  check panicking mid-audit. Preserve this when adding methods.
- **The registry observes, it does not schedule.** It owns no goroutines. If a caller dies without
  finishing, the task stays visible as `TaskRunning` — the honest outcome. It **never evicts a
  running task**; it overshoots capacity rather than drop live work. The first terminal state wins
  (no second `finished` event), and `Restore` brings a previously-running task back as `TaskStopped`,
  not done and not absent.
- **`Kind` is a plain string with named constants** so the registry never imports the packages whose
  work it tracks (the crawler registers `KindCrawl` while this package knows nothing of crawling). An
  unknown kind renders under its own name, never dropped.
- **The event log must not be fed from a store observer.** `core.TrafficStore.ObserveExchanges` runs
  under the store's write lock on the append path; recording events there would make the store lock a
  proxy-latency tax. Events are recorded by explicit calls at the point they happen. This is also why
  `dash` is not `internal/toollog`: that log's unit is one *sent request*, and most events are not
  requests.
- Note two independent `Severity` types in the tree: this package's event `Severity` (int,
  info/warn/error) is distinct from `advisory.Severity` (string, issue class).

## Testing Requirements

```bash
go test ./internal/dash/...
```

## Dependencies

No other `internal/` packages — `dash` is intentionally a leaf that the tracked packages depend on,
not the reverse. Standard library only (`context`, `encoding/json`, `sync`, `time`). There is no
matching Rust crate under `crates/` — this package is Go-only.
