<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# web

## Purpose

The JSON API and the embedded single-page UI. Browser-based rather than a native GUI so the tool
stays usable headless or over SSH, and so the front end is not on the memory-critical path.

The API returns **index rows** for history — `ExchangeView`, which carries message ids and byte
lengths, never payloads — and fetches message bytes only when a specific message is opened
(`/api/message/{id}`). Listing 100k exchanges therefore touches no body. This is the same shape as
the Rust reference: History and message endpoints are separate on purpose, and a handler that
resolves bodies to build a list is the regression this split exists to prevent.

Unlike the Rust `web` crate — whose `AppState` holds an `AuditHook` closure to avoid depending on
the scanner — the Go `Server` imports `internal/scanner` directly and holds `*scanner.ActiveScanner`
/ `*scanner.PassiveScanner` fields. The dependency inversion the Rust doc insists on is not present
here; do not assume it.

## Key Files

| File | Description |
|------|-------------|
| `server.go` | `Server` struct, `NewServer`, the `With*` option chain, `setupRoutes` (the full route table), and `ListenAndServe` (wraps every request body in a 16 MiB `MaxBytesReader`) |
| `ui.go` | `//go:embed ui/index.html ui/style.css ui/dist/app.js` and `uiHandler`: root serves index.html, `/app.js` serves the bun-bundled `dist/app.js`, everything else falls through to the embedded tree |
| `api_types.go` | The wire shapes (`ExchangeView`, `MessageView`, `StatsView`, `FindingView`) and target-parsing helpers (`targetParts`, `splitHostPort`) |
| `events.go` | The LIVE-01 change-event hub behind `/api/events`: producers call `notify(kind)` (one atomic add, one non-blocking send), a fan-out goroutine coalesces over a 150ms window into "kind X changed, count N" frames |
| `api_toolkit.go` | Largest handler file (~1200 lines) — the decoder/encoder/hash/compare/organizer toolkit endpoints |
| `api_session.go` | Session rules, cookies, and the login-macro runner (builds its own `AuthorisedSender`) |
| `api_tools.go` | Repeater send and intruder points/run (the intruder builds one `AuthorisedSender` for the whole attack) |
| `api_extensions.go` | The EXTENDER surface (`/api/extensions/*`): list, load, unload, the two consoles, the protocol contract, and one invocation. Six exact patterns rather than a subtree, and deliberately no BApp Store route — see the file's own comment |
| `api_ws.go` | The WebSocket capture surface (`/api/ws/*`): index rows only, mirroring `wshistory.ts` |
| `api_sequencer_capture.go`, `api_dashboard.go`, `api_capture.go`, `liveaudit.go` | Sequencer capture runs, dashboard summary counts, history/message/stats, and live-audit state |
| `api_crawl.go` | The crawl surface (`/api/crawl`): the retained run reports, and the two scan kinds — `crawl`, and `crawl-audit` which audits the exchanges that crawl itself fetched (a second `audit-session` task, not a phase of the crawl's own row). An unknown kind is a 400 that names the accepted pair; the kind is echoed in the 202 and on the retained run, so a launch that audits nothing cannot look like one that ran |
| `ui/` | The React UI: TypeScript source in `ui/src/`, bun-bundled to `ui/dist/app.js`. Owned elsewhere (see `../DESIGN.md`); do not add wire fields no consumer reads |

## For AI Agents

### `Server` is built by a `With*` option chain, and some options re-wire live signals

`NewServer(store, scope)` takes only the two shared stores; everything else — logger, sender,
scanner, findings, intercept engine, persistence, tasks, event log — arrives through chained
`With*` setters. Several of them (`WithFindings`, `WithIntercept`, `WithToolLog`, `WithEvents`) call
`followLive()` again after swapping a store, because the live-update hub installs its change hook on
a single slot per store: re-installing replaces rather than adds. A store replaced after
construction keeps its old hook pointing at the same hub — bounded, silent waste that is documented
as deliberately not worth an unsubscribe protocol (see `WithSitemap`).

### The send chokepoint is per-handler, not central — and the repeater is a deliberate exception

`Server.sender` is the raw network layer and authorises nothing. Every request-originating handler
binds it into a `sender.AuthorisedSender` for that request's own authority before dialing: the
intruder (`api_tools.go`) and the session macro runner (`api_session.go` / `loginRuns`) both do.
The repeater is the one stated exception and uses a weaker host-level check where it makes it. Do
not open a raw connection from a new surface — route it through an `AuthorisedSender` so the scope
check is unforgettable rather than conventional.

### Live change frames carry what changed, never the change

`events.go`: a frame is a `changeKind` (`changeHistory`, `changeIssues`, `changeDashboard`,
`changeIntercept`, `changeOrganizer`, `changeWS`) plus a count — never a row. Serialising an
exchange into the stream would duplicate the wire shape `/api/history` already owns, and two
producers of one shape drift. The client is told which endpoint is stale and re-fetches it. `notify()`
runs under the traffic store's write lock (it is a `core.TrafficStore` exchange observer), so it is
atomics-only: no lock, no allocation, no formatting. All expensive work happens on the fan-out
goroutine. The 150ms coalescing window is chosen from both ends — the intercept queue is the
latency-critical case (someone waits on a held request), and the browser render loop is the ceiling.

### Lazy and nil-tolerant subsystems are supported states, reported honestly

`advisories` (issue catalogue) nil means findings fall back to their own description — `/api/issues`
reports the catalogue size so an operator can tell "no catalogue loaded" from "no definition for
this check". `captures` (sequencer) is built on first use via `captureOnce`, because a session that
never captures should not allocate the table and because tests construct `Server` directly.
`caCertPEM` nil makes `/ca.crt` report interception is off rather than serving an empty file.
`toolRunner` nil means `run tool` checks are counted at load and never admitted — tool execution is
operator policy supplied from the command line, never built by the server.

### Route registration relies on ServeMux longest-match, not order

`/api/sequencer/capture` (exact, starts a capture) and `/api/sequencer/capture/` (subtree, reads or
stops one) are two operations on two patterns; the comment notes they are registered exact-first for
readability only, since `ServeMux` picks the longest matching pattern regardless of order. Several
routes carry legacy aliases (`/api/exchanges/` → `/api/exchange/`, `/api/findings` → `/api/issues`,
`/api/scanner/audit` → `/api/audit/`). `/ca.crt` is deliberately not under `/api` to match the Rust
route so the shipped frontend's CA link works unchanged.

### `duration_ms` is deliberately frozen on the wire

`ExchangeView.DurationMs` predates `core.ExchangeDuration` and stays a millisecond count: a measured
sub-millisecond exchange and an unmeasured one both render as 0. The finer distinction is available
in the store, the DB (`exchanges.duration_us`, NULL when unmeasured), and via
`core.Exchange.Duration.Measured` — but is intentionally not surfaced on the wire, because a JSON
field no UI consumer reads is a shape change bought for nothing.

## Testing Requirements

```bash
go test ./internal/web/...
```

The package is test-heavy (roughly one `*_test.go` per feature area — see `route_manifest_test.go`,
`dashboard_api_test.go`, `session_api_test.go`, `liveaudit_coverage_test.go`, etc.). Tests construct
`Server` directly rather than through the full binary wiring, which is why nil-tolerant subsystems and
lazy construction (`captureOnce`) matter. As part of the whole-tree gate: `go build ./...`,
`go vet ./...`, `gofmt -l .`, then `../e2e-go.sh`.

A change to the React console (anything under `ui/`) additionally takes the live browser pass —
`../ui-live.sh` (paths here are relative to the module root) boots the real console on seeded traffic
and prints it; the pass itself is `docs/UI-VERIFICATION.md`. That pass, not the playwright suite, is
the UI gate: the suite is still runnable (`../e2e-ui.sh`) and still generates the screenshots, but a
green spec run is no longer what a UI claim has to survive.

## Dependencies

### Internal

Imports broadly across the engine — `core` (store, scope, findings), `sender` (the authorising send
path), `scanner` (active + passive, held directly), `bcheck` (`ToolRunner`), `intercept`, `session`,
`sitemap`, `matchreplace`, `organizer`, `toollog`, `persist`, `dash` (task registry + event log),
and `advisory`. This is the top of the dependency spine — nearly every capability package is wired
in here.

### External

`go.uber.org/zap` for logging; otherwise the Go standard library (`net/http`, `embed`) for the
server and the embedded UI.
