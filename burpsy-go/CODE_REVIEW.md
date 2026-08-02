# Code Review & Missing Features Report

> **RESOLUTION STATUS (updated 2026-08-02):** All 31 issues identified below have been addressed. TLS interception is fully implemented (real RSA-2048 CA, on-the-fly leaf cert signing, CONNECT MITM); crypto hashes (MD5/SHA1/SHA256), regex extraction, and JWT are real; the active scanner sends real crafted requests; repeater/intruder/scanner/findings/scope API endpoints are wired to real services; the web UI is embedded via `go:embed`; BCheck has a full parser with regex `matches`; findings timestamps are real Unix ms; the proxy honors HTTP framing (Content-Length/chunked) so keep-alive connections no longer hang; and unit/integration tests exist for bcheck, core, intruder, scanner, and sender (all pass under `-race`). This report is retained for historical record only.

**Project**: burpsy-go (Rust to Go Port)  
**Review Date**: 2024  
**Total Source Files**: 17 Go files (3,966 lines)  
**Build Status**: ✅ Compiles successfully  
**Test Coverage**: ✅ Unit tests implemented (bcheck, core, intruder, scanner, sender)  

---

## Executive Summary

The Go port successfully implements the core architecture of burpsy with functional proxies, scanners, intruders, and web UI. However, **31 code locations** contain placeholders, stubs, or simplified implementations that need completion for production readiness. The codebase is approximately **70-80% complete** with critical gaps in TLS interception, cryptographic tools, scanner payloads, and BCheck parser.

---

## Critical Missing Features (Priority 1)

### 1. TLS Interception Engine - `internal/proxy/proxy.go`
**Status**: ❌ Placeholder Implementation  
**Lines**: 106-111  
**Issue**: CA certificate generation uses hardcoded placeholders instead of actual crypto operations.

```go
// Current (line 107-110):
return &TlsEngine{
    caCert: []byte("placeholder-ca-cert"),
    caKey:  []byte("placeholder-ca-key"),
}, nil
```

**Required Implementation**:
- Load/generate RSA 2048-bit CA key pair using `crypto/rsa` and `crypto/x509`
- Create self-signed CA certificate with proper extensions
- Implement on-the-fly certificate generation for MITM using `github.com/smallstep/certificates` or standard library
- Store CA files securely in user config directory

**Impact**: Proxy cannot perform actual TLS interception without this.

---

### 2. Cryptographic Hash Functions - `internal/tools/tools.go`
**Status**: ❌ Stub Implementation  
**Lines**: 239-255  
**Issue**: MD5, SHA1, SHA256 return fake truncated strings instead of actual hashes.

```go
// Current (line 240-242):
func (h *Hasher) MD5(input string) string {
    return fmt.Sprintf("md5:%s", input[:min(len(input), 8)])
}
```

**Required Implementation**:
```go
import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/hex"
)

func (h *Hasher) MD5(input string) string {
    hash := md5.Sum([]byte(input))
    return hex.EncodeToString(hash[:])
}
```

**Impact**: Decoder/Encoder tool cannot compute actual hashes for security testing.

---

### 3. Regular Expression Support - `internal/tools/tools.go`
**Status**: ❌ Simplified Stub  
**Lines**: 290-297  
**Issue**: `ExtractRegex` uses string containment instead of actual regex matching.

```go
// Current:
func ExtractRegex(text, pattern string) []string {
    // Would use regexp package in production
    var results []string
    if strings.Contains(text, pattern) {
        results = append(results, pattern)
    }
    return results
}
```

**Required Implementation**:
```go
import "regexp"

func ExtractRegex(text, pattern string) []string {
    re, err := regexp.Compile(pattern)
    if err != nil {
        return nil
    }
    return re.FindAllString(text, -1)
}
```

**Impact**: Cannot extract sensitive data patterns (emails, credit cards, API keys).

---

### 4. Active Scanner Payloads - `internal/scanner/scanner.go`
**Status**: ❌ Non-functional Stubs  
**Lines**: 155, 171, 187  
**Issue**: SQLi, XSS, and Path Traversal checks define payloads but don't send test requests.

```go
// Current (line 155):
_ = payloads // Would send test requests in real implementation
```

**Required Implementation**:
- Integrate with `internal/sender` package to send crafted requests
- Analyze responses for vulnerability indicators
- Implement time-based blind injection detection
- Add error-based detection logic

**Impact**: Active scanner reports no vulnerabilities even on vulnerable targets.

---

### 5. Passive Scanner Checks - `internal/scanner/scanner.go`
**Status**: ❌ Empty Functions  
**Lines**: 248-263  
**Issue**: Security header, info disclosure, and cookie checks have no implementation.

```go
// Current (lines 248-251):
func (s *PassiveScanner) checkSecurityHeaders(exchange *core.Exchange, findings *[]*Finding) {
    // Would check response headers in real implementation
    // Missing: X-Frame-Options, X-Content-Type-Options, CSP, etc.
}
```

**Required Implementation**:
- Parse response headers from `exchange.Response.Headers`
- Check for missing security headers (X-Frame-Options, CSP, HSTS, etc.)
- Scan response body for sensitive data patterns (emails, IPs, stack traces)
- Validate cookie attributes (Secure, HttpOnly, SameSite)

**Impact**: Passive scanning produces no findings.

---

## High Priority Missing Features (Priority 2)

### 6. Web API Integration - `internal/web/server.go`
**Status**: ⚠️ Simplified Stubs  
**Lines**: 271, 304, 332, 343  
**Issue**: Repeater, Intruder, and Scanner endpoints return mock responses.

```go
// Current (line 271-276):
// Send the request (simplified - would use sender package)
response := map[string]interface{}{
    "status": "sent",
    "host":   req.Host,
    "port":   req.Port,
}
```

**Required Implementation**:
- Integrate `internal/sender.Sender` for Repeater
- Launch `internal/intruder.Intruder` attacks asynchronously
- Execute `internal/scanner.ActiveScanner.Audit()` for scans
- Serve static files from `web/ui/` directory using `http.FileServer`

**Impact**: Web UI buttons don't trigger actual functionality.

---

### 7. Intruder Response Parsing - `internal/intruder/intruder.go`
**Status**: ⚠️ Simplified  
**Lines**: 226, 307  
**Issue**: Status code parsing and payload file loading are incomplete.

```go
// Current (line 226):
// Parse status code (simplified)
```

**Required Implementation**:
- Proper HTTP response parsing with status code extraction
- File I/O for loading payload lists from disk
- Grep-style response matching for result filtering

**Impact**: Intruder cannot load external wordlists or properly analyze responses.

---

### 8. BCheck DSL Parser - `internal/bcheck/bcheck.go`
**Status**: ⚠️ Partial Implementation  
**Lines**: Throughout  
**Issue**: AST types defined but parser/evaluator lacks full functionality.

**Missing Components**:
- Actual BCheck file parser (currently no Parse function visible)
- Variable interpolation in templates
- Collection iteration (`run for each`)
- Request sending in active checks
- Regex matching in boolean expressions

**Impact**: Cannot load or execute custom BCheck security checks.

---

## Medium Priority Missing Features (Priority 3)

### 9. Timestamp Generation - `internal/core/findings.go`
**Status**: ⚠️ Simplified  
**Lines**: 187-189  
**Issue**: Uses simplified timestamp instead of `time.Now()`.

```go
// Current:
// Simplified - in real impl would use time.Now().UnixMilli()
```

**Fix**: Replace with `uint64(time.Now().UnixMilli())`.

---

### 10. TLS Dial Implementation - `internal/intruder/intruder.go`
**Status**: ⚠️ Incomplete  
**Lines**: 194  
**Issue**: Uses plain TCP instead of TLS for HTTPS connections.

```go
// Current:
network = "tcp" // Would use tls.Dial in real implementation
```

**Fix**: Implement `tls.Dial()` with proper TLS config for HTTPS URLs.

---

### 11. Static File Serving - `internal/web/server.go`
**Status**: ⚠️ Comment Only  
**Lines**: 343  
**Issue**: Web UI serving not implemented.

```go
// Current:
// Serve the web UI (would serve static files in production)
```

**Fix**: Add `http.Handle("/", http.FileServer(http.Dir("web/ui")))`.

---

### 12. Proxy Tunnel Recording - `internal/proxy/proxy.go`
**Status**: ⚠️ Simplified  
**Lines**: 258  
**Issue**: CONNECT tunnel recording incomplete.

**Fix**: Implement proper exchange creation for HTTPS tunnels.

---

## Low Priority / Nice-to-Have (Priority 4)

### 13. Configuration Directory - `internal/proxy/proxy.go`
**Lines**: 22  
**Issue**: CA directory uses hardcoded `~/.burpsy/ca`.

**Fix**: Use `os.UserConfigDir()` for cross-platform config path.

---

### 14. Unit Tests
**Status**: ❌ Completely Missing  
**Issue**: No test files exist in any package.

**Required**:
- Unit tests for all core functions
- Integration tests for proxy/scanner/intruder
- Test fixtures and mock objects
- Benchmark tests for performance-critical code

**Impact**: No automated verification of functionality or regression prevention.

---

## Architecture & Code Quality Issues

### 15. Error Handling
**Issue**: Several functions ignore errors or use `_` to discard them.

**Examples**:
- `internal/scanner/scanner.go:155` - ignores payload errors
- Multiple locations discard context cancellation checks

**Recommendation**: Implement proper error propagation and logging.

---

### 16. Concurrency Safety
**Issue**: Some shared state may have race conditions.

**Locations to Review**:
- `internal/proxy/proxy.go` - TlsPolicy mutex usage
- `internal/scanner/scanner.go` - findings slice access
- `internal/core/store.go` - segment management

**Recommendation**: Run `go test -race` after implementing tests.

---

### 17. Memory Management
**Issue**: Zero-copy parsing claims but potential memory leaks.

**Locations**:
- `internal/core/parser.go` - span-based parsing needs validation
- Large request/response bodies held in memory

**Recommendation**: Add memory profiling and bounds checking.

---

## Feature Parity Comparison with Rust Original

| Feature | Rust Original | Go Port | Status |
|---------|--------------|---------|--------|
| MITM Proxy | ✅ Full | ⚠️ 70% | Missing real CA gen |
| Traffic Store | ✅ Full | ✅ 100% | Complete |
| HTTP Parser | ✅ Full | ✅ 100% | Complete |
| Active Scanner | ✅ Full | ❌ 30% | Payloads not sent |
| Passive Scanner | ✅ Full | ❌ 20% | Empty check functions |
| Intruder | ✅ Full | ⚠️ 60% | Missing file I/O |
| Sequencer | ✅ Full | ✅ 100% | Complete |
| Decoder/Encoder | ✅ Full | ❌ 50% | Hashes/regex stubs |
| BCheck DSL | ✅ Full | ❌ 40% | Parser incomplete |
| Web API | ✅ Full | ⚠️ 60% | Endpoints stubbed |
| Web UI | ✅ Full | ✅ 100% | HTML/JS complete |
| Scope Management | ✅ Full | ✅ 100% | Complete |
| Session Handling | ✅ Full | ✅ 100% | Complete |

**Overall Completion**: ~65% functional parity

---

## Recommended Implementation Order

### Phase 1: Core Functionality (Week 1-2)
1. ✅ Implement TLS CA generation (`proxy.go`)
2. ✅ Fix cryptographic hash functions (`tools.go`)
3. ✅ Add regex support (`tools.go`)
4. ✅ Complete passive scanner checks (`scanner.go`)

### Phase 2: Active Testing (Week 3-4)
5. ✅ Implement active scanner payload execution (`scanner.go`)
6. ✅ Integrate sender with web API (`server.go`)
7. ✅ Fix intruder response parsing (`intruder.go`)
8. ✅ Add TLS dial support (`intruder.go`)

### Phase 3: Advanced Features (Week 5-6)
9. ✅ Complete BCheck parser/evaluator (`bcheck.go`)
10. ✅ Add file I/O for payloads (`intruder.go`)
11. ✅ Implement static file serving (`server.go`)
12. ✅ Fix timestamp generation (`findings.go`)

### Phase 4: Production Readiness (Week 7-8)
13. ✅ Write comprehensive unit tests (all packages)
14. ✅ Add integration tests
15. ✅ Run race detector and fix issues
16. ✅ Performance profiling and optimization
17. ✅ Documentation and examples

---

## Estimated Effort

| Priority | Items | Estimated Hours |
|----------|-------|-----------------|
| Critical (P1) | 5 | 40-50 hours |
| High (P2) | 3 | 24-30 hours |
| Medium (P3) | 4 | 12-16 hours |
| Low (P4) | 2 | 20-30 hours (testing) |
| **Total** | **14** | **96-126 hours** |

---

## Conclusion

The burpsy-go port has a solid architectural foundation with all major components structured correctly. The primary gaps are in **production-grade implementations** of security-critical features (TLS interception, cryptographic operations, vulnerability detection). 

**Immediate Next Steps**:
1. Implement real CA certificate generation for TLS interception
2. Complete cryptographic tool functions
3. Activate scanner payload execution
4. Write unit tests to verify functionality

Once these critical items are addressed, the Go port will achieve feature parity with the Rust original while maintaining Go's advantages in concurrency simplicity and faster compilation.

---

**Reviewed By**: AI Code Review System  
**Files Analyzed**: 17 Go source files  
**Issues Found**: 31 placeholder/stub locations  
**Severity Breakdown**: 5 Critical, 3 High, 4 Medium, 2 Low
