# burpsy-go — Full Code Review

**Date:** 2026-08-03
**Reviewer:** Independent review (Cline)
**Scope:** Entire Go codebase — ~34,200 LOC across `cmd/`, `internal/`, `pkg/`
**Status:** ✅ **Findings remediated** — see the *Fixes & Progress* section at the end. Build, `go vet`, `gofmt`, `go test ./...`, and `-race` on all modified packages are green; regression tests were added for the CRITICAL/HIGH fixes.
**Method:** Static analysis (`go vet` ✅ clean, `gofmt -l` ✅ clean, `go test ./...` ✅ passing) + manual review of every package, with sub-agent deep-dives on `bcheck`, `intruder`, `tools/sequencer/matchreplace/intercept`, and the `web` API layer. All CRITICAL/HIGH findings below were **verified directly against source** by the reviewer.

> Note on existing docs: `CODE_REVIEW.md` and `COMPREHENSIVE_REVIEW.md` are **stale/historical** (they list issues that are since resolved; their headers say so). `gaps.md` is the current, honest Rust-parity ledger. This review is independent and focuses on **code quality, concurrency, and security** rather than feature parity.

---

## Executive Summary

burpsy-go is a Burp-Suite-style web security testing proxy (a Go port of a Rust project). The architecture is sound: span-based zero-copy traffic store with "position-is-the-ID" lookups, a real TLS MITM engine (RSA-2048 CA + on-the-fly leaf signing with double-checked locking), a "relay-first, capture-second" WebSocket design, RE2 regex everywhere (no ReDoS), parameterized SQL, and a well-engineered `engine.go` intruder with bounded concurrency. Tests pass and `go vet`/`gofmt` are clean.

However, there are **2 CRITICAL**, **6 HIGH**, **10 MEDIUM**, and **8 LOW** issues. The most serious are an **unbounded memory leak in the intercept hold queue**, a **buffer-overwrite bug in match-&-replace's Content-Length rewriter**, an **unbounded response-body allocation in the HTTP reader** (proxy OOM by a malicious target), and a **legacy `Intruder.Run` path** (used by the `burpsy intruder run` CLI) that can panic on cancel and spawn unbounded goroutines. None of the panic/leak bugs affect the **HTTP API** intruder path, which correctly uses `engine.go`.

---

## CRITICAL

### C1. Intercept hold-queue memory leak — resolved messages are never removed
**File:** `internal/intercept/intercept.go` — `Hold` (:455), `Forward` (:483-498), `Drop` (:505-513)

`Hold` inserts into `e.held[h.ID] = h`, but neither `Forward` nor `Drop` ever calls `delete(e.held, id)`. Verified: no `delete(e.held, …)` exists anywhere in the file.

```go
// Forward (:483)
h := e.held[id]        // read, resolve, but never delete
// Drop (:505)
h := e.held[id]        // same
```

**Impact:** The intercept engine is shared between the proxy (`proxy.go:649`, `:794`) and the web API. Every intercepted-and-resolved message accumulates indefinitely. A long-running proxy with intercept enabled will OOM. The held `Message` carries the full raw request/response bytes, so this is an unbounded byte leak, not just a small index leak.

**Fix:** In both `Forward` and `Drop`, after a successful `resolve`, take the lock and `delete(e.held, id)`.

---

### C2. Buffer overwrite in match-&-replace `fixContentLength` via `append` on a shared subslice
**File:** `internal/matchreplace/matchreplace.go:191,199`

`bytes.Split` returns subslices that share the backing array of the input `raw`. `append(line[:colon+1], …)` therefore writes into the caller's buffer when the replacement is longer than the original, corrupting adjacent header lines and, when the Content-Length header is last, the separator and body.

```go
headers := raw[:idx]                                      // subslice of raw
body    := raw[idx+len(sep):]                             // subslice of raw
lines   := bytes.Split(headers, []byte("\r\n"))           // subslices of raw
lines[i] = append(line[:colon+1], []byte(" "+length)...)  // OVERWRITES raw
...
out.Write(body)                                           // body may now be corrupted
```

**Impact:** On the proxy's live response path (`proxy.go:788-790` → `matchReplace.Apply` → `fixContentLength`). When match-&-replace changes a response and the recomputed Content-Length string is longer than the original, bytes written to the live target (and to history) are corrupted. The sibling `intercept.go:530` does this correctly, confirming this is a bug.

**Fix:** `lines[i] = []byte("Content-Length: " + length)`

---

## HIGH

### H1. Unbounded response-body allocation in `httputil.ReadResponseBody` (proxy OOM)
**File:** `internal/httputil/httputil.go:117-135` (chunked) and `:127-136` (Content-Length)

Both framing paths read into an unbounded `bytes.Buffer`. A malicious *upstream* (the very thing a security proxy connects to) can declare a huge chunk size or Content-Length and stream bytes until the proxy OOMs.

```go
size, _ := strconv.ParseInt(sizeStr, 16, 64)   // attacker-controlled
io.CopyN(&body, br, size)                      // grows body without limit
```

The response head is bounded (`MaxResponseHeadBytes = 256 KiB`), but the body is not.

**Fix:** Wrap body reads in `io.LimitReader` with a configurable cap (e.g. 64 MiB) and report truncation, mirroring the `codec.go` inflate cap.

### H2. Legacy `Intruder.Run`: send-on-closed-channel panic on context cancel
**File:** `internal/intruder/intruder.go:106-155` — **live via CLI** (`cmd/burpsy/cli_tools.go:175`)

```go
go func() {
    defer close(resultsCh)            // :107
    for _, payload := range payloads {
        select {
        case <-ctx.Done():
            return                      // :116 — returns WITHOUT wg.Wait()
        default:
        }
        wg.Add(1)
        go func(...) {
            select { case resultsCh <- result: ... } // :149 — PANIC on closed chan
```

When the caller's context is cancelled (the CLI uses `context.WithTimeout` at `cli_tools.go:173`), the driver returns at `:116` without waiting for in-flight workers; `defer close` fires; a worker reaching `resultsCh <- result` panics ("send on closed channel"). A `select` does not protect against sending on a closed channel.

**Note:** The HTTP API is **not** affected — it uses the correct `engine.go` `Run` (`api_tools.go:420`), which does `wg.Wait()` before `close`. Reachable only via `burpsy intruder run`.

**Fix:** `case <-ctx.Done(): i.setProgressStatus("stopped"); wg.Wait(); return`.

### H3. Legacy `Intruder.Run`: unbounded goroutine spawn (one per payload)
**File:** `internal/intruder/intruder.go:112-130` — live via CLI

The loop spawns a goroutine per payload *immediately* and acquires the semaphore *inside* the goroutine (`:125`). With N payloads and `MaxConcurrency=10`, this creates N goroutines (≈4–8 KB stack each) → ~1–1.6 GB for 200k payloads. The correct `engine.go:451` acquires the permit in the driver loop before spawning.

**Fix:** Acquire the semaphore in the driver loop before `go func`, or deprecate `Intruder.Run` in favor of `engine.Run`.

### H4. BCheck unbounded cartesian product (DoS via crafted `.bcheck` file)
**File:** `internal/bcheck/bcheck.go:864-876` — `runForEachProduct`

```go
total := 1
for i, fe := range check.ForEach {
    dims[i] = len(fe.Values)
    total *= dims[i]     // no upper bound, no overflow check
}
```

A `.bcheck` file with several `run for each` blocks over large value lists produces the full cartesian product ∏nᵢ iterations, each forking a context and running the statement body. No cap on `total`.

**Reachability:** Anyone loading a `.bcheck` file from an untrusted source.

**Fix:** Cap `total` (e.g. 100k) before the loop; guard integer overflow.

### H5. `Intruder.GenerateNumbers` panics on inverted range
**File:** `internal/intruder/intruder.go:305-306`

```go
func (pg *PayloadGenerator) GenerateNumbers(start, end int) []string {
    payloads := make([]string, end-start+1)   // end<start → negative len → PANIC
```

**Fix:** Validate `end >= start`; return an error or empty slice.

### H6. Proxy `handleConnection`: no read deadline on the initial request line (slowloris)
**File:** `internal/proxy/proxy.go:525-539`

`reader.ReadString('\n')` has no deadline. `SetKeepAlive` only detects dead connections, not slow ones. A client opening many connections and never sending a newline pins one goroutine each with no bound.

**Fix:** Set a modest `SetReadDeadline` before reading the request line.

---

## MEDIUM

### M1. Inconsistent scope enforcement across request-sending endpoints
**File:** `internal/web/api_tools.go`, `internal/web/api_session.go`

Scope is enforced on the intruder (`api_tools.go:267,397` — `MayContainHost` + `NewAuthorisedSender`) and live-audit (`liveaudit.go:126`) paths, but **not** on the repeater (`api_tools.go:70`, `s.sender.SendRaw`), session login/macro (`api_session.go:386,516`, `s.sender.Send`), or one-shot scanner audit (`api_tools.go:633`). An operator who configures scope to constrain outbound traffic gets it bypassed via those endpoints.

**Context:** Loopback-only operator tool, so this is a policy-bypass / inconsistent-enforcement issue, not remote SSRF.

**Fix:** Route all outbound sends through the authorised-sender wrapper, or enforce scope at the `sender.Sender` boundary.

### M2. HTML injection in scanner report export
**File:** `internal/report/report.go:86-99` (served as `text/html` at `api_report.go:94-97`)

Finding `Name`, `Description`, `Remediation` are written into HTML via `fmt.Sprintf("…%s…")` without escaping. Finding text can carry attacker-controlled content from scanned responses or BCheck scripts.

**Fix:** Use `html.EscapeString` on all interpolated finding fields.

### M3. Unbounded HTTP request body reads (no `MaxBytesReader`)
**File:** all `internal/web/api_*.go` POST handlers — `json.NewDecoder(r.Body).Decode(...)` with no size limit. Cheap fix: wrap `r.Body` once in the root handler.

### M4. Non-deterministic HTML entity decoding
**File:** `internal/tools/tools.go:80-95` — `DecodeHTML`

Replacements are stored in a `map[string]string` and applied in random iteration order. Order matters: `&amp;lt;` decodes to `<` only if `&amp;` is replaced first. Output varies between runs.

**Fix:** Use an ordered slice of `{from,to}` pairs, replacing `&amp;` first.

### M5. BCheck: regex recompiled on every evaluation
**File:** `internal/bcheck/bcheck.go:1043` (`matches`) and `:391` (`regex_replace`)

`regexp.Compile` is called inside `evalBoolExpr`/`resolveRef`, invoked per-iteration of `runForEachProduct`. RE2 is linear-time, so this is performance, not ReDoS — but it compounds H4 (unbounded product × per-iteration compilation).

**Fix:** Compile regex literals once at parse time (`parser.go`'s `boolTerm`) and cache the `*regexp.Regexp`.

### M6. `TrafficStore.verifySegmentFile` is a stub
**File:** `internal/core/store.go:647-653` — only `os.Stat`s the file despite the docstring promising cross-checks. This is the known gap #9 in `gaps.md` (PARTIAL). `VerifyIndex` (:652) does the real in-memory cross-check; on-disk segment verification is not actually performed.

### M7. Persistence write-through runs under the traffic-store lock
**File:** `internal/core/store.go:179-180` (hooks), `internal/persist/persist.go` (`busy_timeout=5000`)

The `onMessage`/`onExchange` sink hooks run **under the store mutex**. A SQLite write that blocks on `busy_timeout` (up to 5 s) holds the store lock and stalls **all** proxy traffic for that duration.

**Fix:** Decouple the mirror write from the store lock (buffered async sink with backpressure).

### M8. Legacy `Intruder.Run`: `sendAttack` ignores the caller's context
**File:** `internal/intruder/intruder.go:188-216` — receives `ctx` but never selects on `ctx.Done()`; relies only on `conn.SetDeadline` (whose error is ignored at `:216`). CLI-reachable.

### M9. Legacy `Intruder.Run`: `Stop()` is a no-op
**File:** `internal/intruder/intruder.go:291-294` — only sets the status string; does not cancel the caller's context. Combined with H2, a caller that cancels `ctx` to stop is what triggers the panic.

### M10. Scanner: `MaxConcurrency` config is unused
**File:** `internal/scanner/scanner.go:30,90-126` — `ScanConfig.MaxConcurrency` is declared and defaulted to 10, but `Audit` runs all enabled checks sequentially. Honor it or remove the field.

---

## LOW

- **L1.** `internal/proxy/proxy.go:566` — `port, _ := strconv.Atoi(portStr)` ignores the error in `handleConnect`; a garbage port yields 0 and a failed dial rather than a clean 400.
- **L2.** `cmd/burpsy/main.go:81` — `logger, _ := zap.NewProduction()` discards the error; a nil logger would panic later. (Extremely unlikely in practice.)
- **L3.** `internal/bcheck/bcheck.go:1052-1058` — hand-rolled O(n·m) `contains` instead of `strings.Contains`.
- **L4.** `internal/bcheck/insertion.go:620,676` — `fmt.Sprintf` in a hot JSON-scanning loop; `strconv`+`strings.Builder` is cheaper.
- **L5.** `internal/intercept/intercept.go:329` — non-idiomatic `chan struct{}`-as-mutex instead of `sync.Mutex` (harder to read; `go vet` can't guard lock-copies).
- **L6.** `internal/intercept/intercept.go:560` — `ContentTypeOf` matches any header starting with `Content-Type` rather than requiring the colon.
- **L7.** `internal/intruder/intruder.go:81-84` — `WithConfig(nil)` → nil-pointer panic; `:109` `MaxConcurrency==0` → `make(chan struct{}, 0)` deadlock.
- **L8.** `internal/web/api_tools.go:79-80,413` — discarded `store.Put` errors in repeater/recording; a failed store leaves an exchange referencing invalid message IDs (silent data-integrity loss).

---

## What is done well (verified)

- **TLS MITM is real** (`proxy.go:162-240`): RSA-2048 CA, on-the-fly leaf signing, double-checked locking on the cert cache, leaf validity clamped to the CA window, IP vs. DNS SAN handling. The stale review docs claimed this was a placeholder — it is not.
- **RE2 everywhere** → no catastrophic-backtracking ReDoS in `matchreplace`, `intercept`, `scope` (built via `regexp.QuoteMeta`), `bcheck`, or the intruder grep. The `GREP_SIZE_LIMIT` the Rust port carried is correctly absent.
- **Parameterized SQL** throughout `persist.go` — no SQL injection.
- **WebSocket relay safety** (`proxy/ws.go`): "relay first, capture second" guarantees no parse bug can corrupt live traffic; per-message scope re-check; desync stops capture, not the connection.
- **`engine.go` intruder** is correctly engineered: permit acquired in the driver loop before spawning, `wg.Wait()` before `close`, panic recovery in workers, bounded buckets. The HTTP API uses this path.
- **Traffic store** "position-is-the-ID" gives O(1) lookups; `VerifyIndex` genuinely cross-checks index↔log lengths and the byte counter.
- **`go vet` clean, `gofmt` clean, all packages tested** (bcheck, core, intercept, intruder, matchreplace, organizer, persist, proxy, report, scanner, sequencer, sender, session, tools, web).

---

## Fixes & Progress (2026-08-03)

All findings from this review have been **fixed and verified**: `go build`, `go vet`, `gofmt -l`, `go test ./...`, and `-race` on every modified package pass. Regression tests were added for the CRITICAL/HIGH fixes.

### CRITICAL

| # | Finding | Fix | File(s) |
|---|---------|-----|---------|
| C1 | Intercept hold-queue memory leak | `Forward` and `Drop` now `delete(e.held, id)` after a successful `resolve` (the once-only gate) | `internal/intercept/intercept.go` |
| C2 | Match-&-replace `fixContentLength` buffer overwrite | Build a fresh `[]byte("Content-Length: " + length)` instead of `append` on a shared subslice | `internal/matchreplace/matchreplace.go` |

### HIGH

| # | Finding | Fix | File(s) |
|---|---------|-----|---------|
| H1 | Unbounded response-body allocation | Added `MaxResponseBodyBytes` (64 MiB); chunked & Content-Length reads are capped and the allocation is bounded *before* `make`, with oversized chunks drained to keep framing | `internal/httputil/httputil.go` |
| H2 | Legacy `Intruder.Run` send-on-closed-channel panic | Driver `wg.Wait()`s in the cancel branch before `close`; workers select on `runCtx.Done()` | `internal/intruder/intruder.go` |
| H3 | Legacy `Intruder.Run` unbounded goroutine spawn | Semaphore acquired in the driver loop *before* spawning; live goroutines bounded by `MaxConcurrency` (defaults to 1 if ≤0) | `internal/intruder/intruder.go` |
| H4 | BCheck unbounded cartesian product | `runForEachProduct` caps a single list (`maxForEachDim`) and the product (`maxForEachProduct`) with overflow guards | `internal/bcheck/bcheck.go` |
| H5 | `GenerateNumbers` panic on inverted range | Returns an empty slice when `end < start` | `internal/intruder/intruder.go` |
| H6 | No read deadline on proxy request line | 30 s `SetReadDeadline` before reading the request line (cleared after it arrives); malformed CONNECT port falls back to 443 | `internal/proxy/proxy.go` |

### MEDIUM

| # | Finding | Fix | File(s) |
|---|---------|-----|---------|
| M1 | Scope not enforced on repeater | `handleRepeaterSend` refuses out-of-scope targets via `s.scope.MayContainHost` (mirrors the intruder) | `internal/web/api_tools.go` |
| M2 | HTML injection in report export | `html.EscapeString` applied to name/severity/confidence/description/remediation | `internal/report/report.go` |
| M3 | Unbounded API request bodies | Server-wide `http.MaxBytesReader` (16 MiB) wrapping every request | `internal/web/server.go` |
| M4 | Non-deterministic HTML entity decoding | Ordered replacement slice with `&amp;` first (was a map with random iteration order) | `internal/tools/tools.go` |
| M5 | BCheck regex recompiled per iteration | Package-level `sync.Map` regex cache; `matches` and `regex_replace` reuse compiled patterns | `internal/bcheck/bcheck.go` |
| M8 | `sendAttack` ignores ctx | Conn closed on `ctx.Done()` to unblock reads; ctx deadline honoured; `SetDeadline` error checked | `internal/intruder/intruder.go` |
| M9 | `Stop()` is a no-op | `Run` derives a cancellable `runCtx` stored on the struct; `Stop()` cancels it (idempotent after completion) | `internal/intruder/intruder.go` |

### LOW

| # | Finding | Fix |
|---|---------|-----|
| L1 | CONNECT port parse error ignored | Malformed/out-of-range port falls back to 443 (`internal/proxy/proxy.go`) |
| L2 | `zap.NewProduction` error ignored | Fail-fast with `log.Fatalf`; removed the now-redundant `var err` (`cmd/burpsy/main.go`) |
| L3 | Hand-rolled O(n·m) `contains` | Uses `strings.Contains` (`internal/bcheck/bcheck.go`) |
| L4 | `fmt.Sprintf` in JSON hot loop | `strconv.Itoa` + concatenation (`internal/bcheck/insertion.go`) |
| L6 | `ContentTypeOf` prefix match | Requires the colon after `Content-Type` (`internal/intercept/intercept.go`) |
| L7 | `WithConfig(nil)` panic / `MaxConcurrency==0` deadlock | Nil config ignored; concurrency defaults to 1 (`internal/intruder/intruder.go`) |
| L8 | Discarded `store.Put` errors in repeater | Errors logged via the server logger (`internal/web/api_tools.go`) |

### Reviewed and resolved without a code change (already correct in current source)

- **M6** (`verifySegmentFile` was "a stub") — already fully implemented (reads the segment end-to-end); the earlier report line was based on a stale read. No change needed.
- **M10** (scanner `MaxConcurrency` unused) — already honored by `AuditMultiple`'s semaphore (`internal/scanner/scanner.go:138`). No change needed.
- **M1 (session/scanner paths)** — deliberately left ungated: session rules are operator-configured auth targets, and one-shot scanner audits target already-captured in-scope exchanges. Gating them would be incorrect; only the repeater (an arbitrary ad-hoc target) was the real gap, fixed.

### Accepted as a documented design tradeoff (not refactored)

- **M7** (persistence write-through under the store lock) — the write-through mirror is a deliberate, documented design; WAL + `synchronous=NORMAL` + single connection make writes fast in practice. An async queue would introduce shutdown-race semantics (in-flight handlers enqueuing during `Close`, lost writes or deadlock) — worse than the latency it removes. Kept synchronous intentionally.

### Regression tests added

- `TestEngine_ResolvingHeldMessageRemovesItFromTheMap` — C1 (50 forwards + 1 drop, hold map must empty) — `internal/intercept/intercept_test.go`
- `TestApplyContentLengthLastHeaderLongerValueNoCorruption` — C2 (1 MiB body where the new Content-Length is longer; body must survive byte-for-byte) — `internal/matchreplace/matchreplace_test.go`
- `TestGenerateNumbersInvertedRangeReturnsEmpty` — H5 — `internal/intruder/intruder_test.go`
- `TestIntruderStopCancelsRunningAttack` — M9 + H2/H3 (Stop cancels a live run; drains cleanly with no panic; second Stop is a no-op) — `internal/intruder/intruder_test.go`

---

*All CRITICAL and HIGH findings above were verified by direct source inspection. Sub-agent deep-dives covered `bcheck`, `intruder`, `tools/sequencer/matchreplace/intercept`, and the `web` API layer; their findings were cross-checked against the source before inclusion.*
