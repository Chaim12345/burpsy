<!-- Generated: 2026-08-17 | Updated: 2026-08-17 -->
<!-- Parent: ../AGENTS.md -->

# cmd

## Purpose

The binaries. `cmd/burpsy` is the product — the proxy, web UI and a full CLI in one executable — and
owns *all* the wiring: one shared `TrafficStore`, one `FindingStore` and one `Scope` handed to every
subsystem, so traffic the proxy captures is available to Repeater, Intruder and the scanner without
copying bodies between them. The other commands are development and conformance drivers, not shipped
tools.

This is the only place that constructs concrete implementations and hands them to the packages that
declared interfaces for them — the same inversion the Rust `cli` crate keeps: `web` stays
independent of `scanner`, and `scanner` independent of any transport.

## Key Files

| File | Description |
|------|-------------|
| `burpsy/main.go` | Flag parsing, store/scope/CA/scanner/proxy/web wiring, the live-audit sweep, and shutdown that `Sync`s (not `Close`s) the capture tail so unwinding handlers keep their mapped spans |
| `burpsy/cli.go` | The CLI dispatcher: every subcommand is a direct engine driver, never an HTTP call to the running server |
| `burpsy/cli_capture.go` | `history`, `message`, `exchange`, `stats` — read the same `-db` the server writes |
| `burpsy/cli_tools.go` | `repeater`, `intruder`, `scan`, plus the decoder/comparer/report tooling |
| `burpsy/cli_scope.go`, `cli_session.go`, `cli_state.go` | Scope editing, session handling, and state inspection |
| `conform/` | The BCheck corpus conformance runner (three-valued verdict — see below) |
| `demo-target/`, `crawl-scan-demo/` | Start the deliberately-vulnerable app from `internal/vulnapp` for manual and end-to-end scanner exercise |
| `live-test/`, `_rows/` | Ad-hoc live smoke test, and a catalog-row printer for manifest authors |

## For AI Agents

### There is exactly one `Scope`, and every subsystem gets the same handle

`main.go` builds one `core.Scope` and passes it to the proxy, both scanners, the senders and the web
layer. Scope is editable at runtime (`POST /api/scope/rules`), so handing a subsystem a *copy* would
leave it authorising by the startup rules while the UI showed the edited ones — a real fail-open,
not a style issue. Wire a new request-originating surface with this same handle.

### The CLI drives the engines, not the HTTP API

Every subcommand exercises the same packages the web routes reach, directly. The engines are the
source of truth and HTTP is only one consumer, so a subcommand must never shell out to the running
server. Global server flags still parse first, so `burpsy -db data.db history` reads the same
database the proxy writes.

### Read-only and resolve-early work happens before the servers start

`-store-verify` and `-scan-config list` print and exit; a `-scan-config NAME` that does not resolve
is fatal at the command line, not a warning that starts the process under a configuration the
operator did not ask for. A malformed `-tools` allowlist is likewise a construction error before any
listener opens — a typo must never surface mid-scan as checks that silently cannot run. Keep new
validate-early logic in the same place.

### `run tool` is operator policy

The `-tools name=path` allowlist is the only way a BCheck `run tool` statement can invoke an external
binary; a check naming a tool not on the list is refused, the same gate as the egress chokepoint.
Tool execution runs arbitrary binaries, so it stays an explicit operator grant.

### CA material is written only under `-intercept-tls`

A plain-HTTP session must not leave key material on disk it never needed. An unreadable `ca.crt` is a
warning, not fatal — interception still works for a client that already trusts the CA, and the UI
reports the missing `/ca.crt` download with a reason rather than hiding the link.

### The vulnerable app has exactly one home

`demo-target` and `crawl-scan-demo` both start `internal/vulnapp`; neither carries its own copy of
the vulnerable endpoints. A second copy drifted once — it kept branching on the scanner probe strings
after `vulnapp` stopped — and the copy the tests did not use was the one that lied. The
`internal/scanner` runtime test starts the same `vulnapp`, so a target change is proven by a test
rather than asserted.

### `conform` is three-valued on purpose

PASS (0) / FAIL (1) / SKIPPED (2). The corpus is a PortSwigger fixture absent from most machines;
answering an absent corpus with `0 files, 0 failed, exit 0` would be byte-for-byte the shape of a
clean run. Exit 2 keeps "never ran" distinct from "ran and passed" — do not fold a skip into 0 or 1.

## Testing Requirements

```bash
go test ./cmd/...        # CLI scope/session/tools/scan unit tests
../e2e-go.sh             # drives the built binary end to end
```

Wiring regressions usually still compile, so run at least one e2e suite after changing `main.go`.

## Dependencies

### Internal

Nearly all of `internal/` — this is the wiring layer, and that breadth is expected and belongs only
here: `core`, `proxy`, `web`, `scanner`, `sender`, `bcheck`, `intercept`, `persist`, `intruder`,
`sequencer`, `session`, `matchreplace`, `organizer`, `tools`, `toollog`, `report`, `query`.

### External

`go.uber.org/zap` (logging). Everything else arrives through the internal packages.
