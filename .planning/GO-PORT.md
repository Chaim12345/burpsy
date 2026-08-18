# GO-PORT — the Go port's authoritative status home

> Created 2026-08-18. This file exists because the Rust-era planning records in this
> directory (STATE.md, ROADMAP.md, REQUIREMENTS.md) stopped describing the active
> implementation. It is the single place that points at the Go tree's live status
> documents, so a reader of the planning directory is never left believing the
> phase tables.

## The two-tree rule (unchanged)

`burpsy-go/` (Go, module `github.com/burpsy-go/burpsy`) is **the active
implementation** — all new feature work, the shipping binary, and the React web UI
live there. `crates/` (Rust, 13 crates) is the **frozen reference**, kept only as
the parity oracle the Go port is measured against. Do not build new features in the
Rust tree; do not "fix" it to track the Go one.

## Where the live status lives

| Question | Document |
|---|---|
| Which Rust↔Go behaviours still differ, with evidence | `burpsy-go/gaps.md` — all 13 gaps COMPLETE (2026-08-04); freshness pointer at top |
| What the most recent work session changed and verified | `burpsy-go/docs/HANDOFF-2026-08-18.md` (latest; earlier dated handoffs retained) |
| Scanner catalog coverage | `burpsy-go/docs/SCANNER-COVERAGE.md` — 183 registered / 145 runtime-demonstrated / 0 declined |
| Scanner infrastructure primitives | `burpsy-go/docs/SCANNER-INFRA.md` — 24 primitives, 139 rows wired (test-pinned) |
| BCheck corpus coverage | `burpsy-go/docs/BCHECK-COVERAGE.md` — 264/264 parse conformance; runtime pending CS-11 |
| Per-package orientation | `burpsy-go/internal/AGENTS.md` and each package's `AGENTS.md` (29 packages) |
| Recent verified work | `burpsy-go/PORT_STATUS.md` |

## Honest numbers as of 2026-08-18

- **183 / 183** catalog rows registered as runnable; **0** declined.
- **145 / 183** demonstrated end-to-end against a live target (pinned by
  `wantDemonstrated` in `internal/scanner/runtime_coverage_test.go`). The exact
  38 registered-only rows, grouped by reason, are in HANDOFF-2026-08-18.
- **264 / 264** BCheck corpus files parse; runtime confirmation pending CS-11.
- **0 / 1300** UAT cases run (`burpsy-go/docs/ui-map/uat/`).
- No headline parity percentage is published until Security Research (CS-11)
  re-verifies.

## Rust-era phase status vs Go reality

The Rust planning records list twelve phases with several "not started". Go reality:

- **Phase 6 (crawler + dashboard): BUILT in Go** — crawler with session gate
  (`internal/crawler/session_gate.go`), honest dashboard (`internal/dash`).
- **Phase 9 (WebSockets): BUILT** — real RFC 6455 relay (`internal/proxy/ws.go`).
- **Phase 7 (hardening): substantially delivered** — the sender chokepoint,
  destructive-crawl refusal, named limits (see crawler AGENTS.md).
- **Phase 11/12 (DOM static/dynamic): delivered as `internal/jsexec` (goja) +
  `internal/domexec` (headless Chrome taint harness)** — the split the roadmap
  argued for, built in Go.
- **Phase 8 (plugin API) and Phase 10 (MCP): deliberately NOT shipped in Go.**
  MCP status is documented honestly in `burpsy-go/docs/MCP.md` ("not yet
  shipped").

## Open work (from HANDOFF-2026-08-18)

- UAT suite: 0 of 1300 cases run.
- CS-11 re-verification before any headline percentage.
- `checkHiddenHTTP2`: recorded defect (fires on every modern HTTPS site as
  written); needs a real paired-ALPN implementation before it gets a fixture.
- 38 registered-only catalog rows, each needing a fixture (OOB and smuggling
  families need harness capabilities, not just endpoints).
- Go CI/release workflow (documented, not authored).
- ghauri SQLi port plan (`burpsy-go/docs/plans/2026-08-13-ghauri-go-port.md`)
  unexecuted.
