# Remaining Go Port Work

**Branch:** `go-arch-opt` → `origin/go-architecture-optimization-fe362` (commit `9a7cf94`)
**Date:** 2026-08-02

---

## ✅ Completed This Session

### New Packages Added
| Package | Purpose |
|---------|---------|
| `internal/session` | Session manager: cookie jars, login macros, validity rules (Kleene 3VL) |
| `internal/sequencer` | Token randomness: entropy, chi-square, serial correlation, Monte Carlo π, pattern detection |
| `internal/query` | DSL parser/evaluator for traffic filtering (host, method, status, mime, body) |
| `internal/sitemap` | Aggregates exchanges into host→path tree for web UI navigation |
| `internal/matchreplace` | Compiled regex rewrite rules (Burp-compatible rule_type taxonomy) for proxy hot path |
| `internal/toollog` | Bounded log of tool-originated requests (Repeater/Intruder/Scanner/Sequencer/Comparer) |

### Scanner Extensions
- `internal/scanner/scanner_checks.go`: JWT weak secret detection + vulnerable JS library checks
- `internal/scanner/scanner_reports.go`: Report export in JSON, SARIF 2.1.0, and HTML formats

### Proxy Enhancements
- MatchReplace wired into both plain HTTP and MITM flows (request + response)
- Removed stub `Interceptor`/`MatchReplaceRules` types; now uses `matchreplace.RuleSet`

### Web API Routes Added
| Route | Handler |
|-------|---------|
| `GET/POST /api/session/rules` | Session rule CRUD |
| `PUT/DELETE /api/session/rules/{id}` | Session rule detail |
| `GET /api/session/cookies` | Cookie jar inspection |
| `GET /api/sitemap` | Site map tree |
| `GET/PUT /api/tools/rules` | Match/replace rule management |
| `GET /api/tools/log` | Tool activity log |
| `GET /api/scanner/report?format=json\|sarif\|html` | Scanner report export |

### CLI Enhancements
- `store-verify DIR` subcommand: verify capture directory segments
- `--tls-passthrough PATTERN` (repeatable): host patterns to passthrough
- `--tls-passthrough-port PORT` (repeatable): ports to passthrough
- `--tls-defaults`: preload common pinned hosts (Apple, Google, Microsoft, GitHub, Cloudflare, etc.)
- `TlsPolicy.AddPassthroughPort()`, `TlsPolicy.WithCommonDefaults()` added

### Build & Test Status
- `go build ./...` ✅
- `go vet ./...` ✅
- `go test ./...` ✅ (6 packages)
- `go test -race ./...` ✅

---

## 🔄 Remaining Work (Priority Order)

### 1. WebSocket Upgrade Relay in Proxy
- Detect `Upgrade: websocket` in request/response
- Hijack connection and relay frames bidirectionally
- Record frames in `core.WsCapture` (already exists in `internal/core/websocket.go`)
- Add `/api/websockets` route in web server

### 2. ALPN / HTTP/2 Relay via `golang.org/x/net/http2`
- Configure `tls.Config.NextProtos = []string{"h2", "http/1.1"}`
- On CONNECT, if ALPN negotiates `h2`, use `http2.ConfigureServer` / `http2.ConfigureTransport`
- Relay h2 frames on both legs, record pseudo-headers as HTTP/1 shape in store
- See Rust `h2_relay.rs` and `crates/http2` for reference

### 3. BCheck DSL Completeness
- `internal/bcheck/funcs.go`: Built-in string functions (uppercase, lowercase, trim, replace, concat, hash, base64, url, html, jsonpath, xpath, jwt decode, time formatting)
- `internal/bcheck/insertion.go`: Insertion point handling (HEADERS, BODY, URL, PARAM_*) for `send_request` statements

### 4. Query DSL Integration in Web History
- Extend `GET /api/history?query=...` to use `query.Parse()` + `Match()` against exchanges

### 5. Session Macros Runtime
- Wire `session.Coordinator.RunMacro()` into web API (`POST /api/session/rules/{id}/run`)
- Use `sender.AuthorisedSender` (scope-chokepoint sender) for macro steps
- Add extractions from macro responses to subsequent step interpolation

### 6. Live Audit Background Sweep
- Port Rust `burpsy_web::routes::liveaudit::LiveAuditState`:
  - Background goroutine every 3s
  - Walk new in-scope exchanges with complete responses
  - Run `scanner.AuditSession()` bounded batch (200 at a time)
  - Expose `GET /api/liveaudit/status`, `POST /api/liveaudit/enable`, `POST /api/liveaudit/disable`

### 7. Intercept (Request Hold Queue) Full Implementation
- Re-add `Interceptor` with condition lists (request + response)
- `GET/POST /api/intercept/enable`, `GET /api/intercept/held`, `POST /api/intercept/held/{id}/release`
- Integrate with proxy flow (holds request before forward, holds response before client)

### 8. Scanner Coverage & Passive BCheck Runner
- `scanner.PassiveScanner.LoadDir()` to load BCheck files from `--bchecks` flag
- `checkCoverage()` reporting which of 264 PortSwigger checks are loaded/active
- Passive runner for `given response` checks

### 9. Report HTML/JSON/SARIF Routes Polish
- Add `ExportHook` to web server for `GET /api/report?format=...`
- Scope snapshot at export time
- Retained audit log inclusion

### 10. Verify Capture Dir Robustness
- Implement full `segment::scan_segment_file()` logic in `verifySegmentFile()`:
  - Read segment file, verify CRC32 per record
  - Count records, detect truncation/corruption
  - Return detailed verdict per segment

---

## 📦 Files to Touch for Remaining Work

| Area | Files |
|------|-------|
| WebSocket | `internal/proxy/proxy.go` (handleConnection), `internal/web/server.go` (routes), `internal/core/websocket.go` |
| HTTP/2 | `internal/proxy/proxy.go` (ALPN config), `internal/sender/sender.go` (h2 transport) |
| BCheck | `internal/bcheck/funcs.go`, `internal/bcheck/insertion.go`, `internal/bcheck/bcheck.go` |
| Query | `internal/web/server.go` (handleHistory) |
| Session | `internal/web/server.go` (session routes), `internal/session/session.go` (RunMacro) |
| Live Audit | `internal/web/server.go` (liveaudit routes), `internal/scanner/scanner.go` (AuditSession) |
| Intercept | `internal/proxy/proxy.go` (Interceptor type + hold queue), `internal/web/server.go` (intercept routes) |
| BCheck Passive | `internal/scanner/scanner.go` (LoadDir, passive runner) |
| Reports | `internal/web/server.go` (report route), `internal/scanner/scanner_reports.go` |

---

## 🧪 Test Commands

```bash
# Full verification
cd /root/burpsy/burpsy-go
go build ./... && go vet ./... && go test ./... && go test -race ./...

# Quick test
QUICK=1 ./verify.sh   # (from /root/burpsy if verify.sh updated for Go)
```

---

## 📝 Notes

- All new packages follow Go 1.19 compatibility (no range-over-int, no generics beyond what 1.19 supports)
- Proxy matchreplace uses `matchreplace.RuleSet` (compiled regex, applied on hot path)
- Scanner reports use SARIF 2.1.0 schema (compatible with GitHub Code Scanning, VS Code, etc.)
- CLI `store-verify` exits non-zero on any segment fault (scriptable)
- TLS passthrough patterns support `*.example.com` wildcard prefix only
- Branch tracks `origin/go-architecture-optimization-fe362` (not `go-arch-opt` on remote)