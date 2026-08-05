<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-05 -->

# burpsy-go

## Purpose

The Go port of burpsy — the active development line. All new features land here; the Rust tree
(`crates/`) is the stable reference implementation. This port closed all 13 Rust-parity gaps and has
delivered Phases 6 (crawler + dashboard) and 11 (DOM static analysis), which the Rust tree has not.

Module path: `github.com/burpsy-go/burpsy`. Requires Go 1.26+.

## Structure

```
burpsy-go/
├── cmd/
│   ├── burpsy/      # Main binary — CLI + proxy + web UI
│   ├── conform/     # BCheck corpus conformance checker
│   ├── demo-target/ # Test origin server for e2e
│   └── live-test/   # Manual live-traffic harness
├── internal/        # Application code (24 packages)
├── pkg/
│   └── models       # Shared public types
└── go.mod
```

## Packages (24)

| Package | Purpose | Rust equivalent |
|---------|---------|-----------------|
| `alpn` | ALPN negotiation, ClientHello peeking | `crates/proxy` (TLS peek) |
| `bcheck` | BCheck DSL parser + evaluator | `crates/bcheck` |
| `core` | Store, segments, scope, findings, sitemap | `crates/core` |
| `crawler` | Frontier crawl, link/form extraction, destructive-action refusal | *(none — Go-only)* |
| `dash` | Task progress, event log, disposition breakdown | *(none — Go-only)* |
| `http2` | Frame/HPACK/malformed crafting, normalisation | `crates/http2` |
| `httputil` | HTTP helper functions | *(shared utilities)* |
| `intercept` | Conditional request/response holding | `crates/proxy` |
| `intruder` | Insertion-point attacks, payload engine | `crates/intruder` |
| `matchreplace` | Ordered match-and-replace rules | `crates/tools` |
| `organizer` | Starred/annotated requests | `crates/tools` |
| `persist` | Project/state persistence | *(none yet)* |
| `proxy` | Intercepting HTTP/HTTPS proxy, MITM, WS relay | `crates/proxy` |
| `query` | Typed filter grammar | `crates/query` |
| `report` | HTML/JSON/SARIF export | `crates/scanner` |
| `scanner` | Passive + active scanning, audit engine, DOM analysis | `crates/scanner` |
| `sender` | Authorised egress (the HARD-03 chokepoint) | `crates/sender` |
| `sequencer` | FIPS 140-2 entropy analysis | `crates/sequencer` |
| `session` | Re-login coordination, cookie jar | `crates/session` |
| `sitemap` | Host → path → param tree | `crates/core` |
| `toollog` | Structured tool event log | *(none yet)* |
| `tools` | Decoder, comparer, codecs | `crates/tools` |
| `mcp` | MCP server — 18 tools over stdio | *(none — Go-only)* |
| `web` | JSON API + UI serving | `crates/web` |
| `web/ui` | TypeScript single-page UI (Bun-built) | — |

## For AI Agents

### Working In This Directory

- **`go test ./...` is the gate.** 1,029 tests across 23 packages, all must pass. `go vet ./...` must
  be clean. `gofmt -l .` must be empty.
- **Commit messages follow the Rust convention** — they explain why a change is right and what the
  obvious alternative gets wrong. Match that; one-line summaries look out of place here.
- The project's stated value is **honest counting**. Coverage numbers, skipped checks and unverifiable
  results are reported, never hidden.
- Refuse-by-default on unparseable input. A request whose path cannot be read is refused, never
  waved through.
- The egress chokepoint is `sender.AuthorisedSender`. Every request-originating surface — crawler,
  scanner, intruder, repeater, session — must route through it. A workspace source scan in the Rust
  tree enforces this for Rust; in Go it is asserted by test (`sender/authorised_test.go`).

### Testing Requirements

```bash
go test ./...                # all 1,029 tests
go test -v ./internal/x/...  # verbose, one package
go vet ./...                 # static analysis
gofmt -l .                   # should be empty
go build ./...               # must compile clean
```

Tests are named as full sentences that state a claim, carry their requirement id in a doc comment,
and assert messages say what a failure *means* rather than restating the comparison.

### Common Patterns

- **`internal/` packages are not importable outside this module.** The `pkg/models` package is the
  only public surface.
- **The UI is TypeScript** under `internal/web/ui/`, built with Bun. `dist/` is generated; edit
  `src/` and rebuild.
- **HTTP/2 has two layers:** `internal/http2` with `golang.org/x/net/http2` (conformant relay) and
  a hand-rolled `frame`/`hpack`/`malformed` layer (spec-illegal frame crafting for research). The
  hand-rolled layer has no send path — `AuthorisedSender.SendFrameProgram` sends through the
  conformant layer.
- **RE2 vs regexp:** Go's `regexp` is RE2 (bounded memory, no backrefs). Where Rust uses
  `regex::bytes`, this can diverge on non-UTF-8 input. ASCII/UTF-8 inputs are identical.

### Dependencies

**External:**

- `golang.org/x/net/http2` — HTTP/2 transport (conformant relay)
- `github.com/mark3labs/mcp-go` — MCP protocol server (stdio transport for `cmd/mcp/`)
- Standard library only for everything else

Two third-party dependencies. Both are deliberate — the Rust tree's dependency list is longer,
and the Go port proves the architecture needs almost nothing beyond the stdlib.

## Status

| Phase | Status | Notes |
|-------|--------|-------|
| 1 — Store & Scope | **DONE** | Scope chokepoint, authorised sender |
| 2 — HTTP/2 | **DONE** | Relay, egress, raw-frame crafting, ALPN |
| 3 — Query DSL + Tools | **DONE** | Full grammar, all 4 intruder modes |
| 4 — Scanner + Reporting | **DONE** | Catalog, Retire.js, JWT, HTML/JSON/SARIF, SCAN-03 selector |
| 5 — Session | **DONE** | Macros, re-login, cookie jar |
| 6 — Crawler + Dashboard | **DONE** | Frontier, destructive-action refusal, limits; tasks, events, breakdown |
| 7 — Hardening | **DONE** | HARD-01 review closed, HARD-03 egress closed |
| 8 — Plugins | **TODO** | Not started |
| 9 — WebSockets | **PARTIAL** | Capture + scope done; interception/resend pending |
| 10 — MCP | **DONE** | `cmd/mcp/` — 18 tools, stdio, mark3labs/mcp-go |
| 11 — DOM Static | **DONE** | Source-to-sink taint, wired into live scan |
| 12 — DOM Dynamic | **TODO** | Not started |

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
