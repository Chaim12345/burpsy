# Go Ecosystem Research for burpsy-go Web Application Security Scanner

## Executive Summary

This report catalogs the complete landscape of Go-based libraries and CLI tools relevant to extending `burpsy-go`, a Burp Suite Professional–style web application security scanner written in Go. It covers two integration paths: (1) pure-Go libraries that can be imported directly into the scanner's module graph, and (2) Go-written CLI tools that can be subprocessed (the same pattern already used with `interactsh-client`). A key finding is that **many ProjectDiscovery tools and several independent projects ship dual interfaces**—both a CLI and a programmable Go library/SDK—giving burpsy-go flexibility in how it integrates each capability.

The report is organized into four parts:

- **Part I**: Library recommendations (importable Go packages)
- **Part II**: CLI tools (subprocess candidates)
- **Part III**: Library-vs-CLI capability matrix (which tools support both modes)
- **Part IV**: Gaps with no acceptable library or tool

---

## Part I: Library Recommendations

These are pure-Go packages that can be imported directly. Each is evaluated against the project's hard constraints: no cgo, permissive licence, manageable transitive dependency count, usable as a library, active maintenance, and loud failure semantics.

### Library Summary Table

| Module path | Purpose | Gap (§) | cgo? | Transitive modules (approx) | Licence | Last release | Maintenance | Verdict |
|---|---|---|---|---|---|---|---|---|
| `github.com/projectdiscovery/wappalyzergo` | Technology fingerprinting via Wappalyzer signatures | §4.2, §4.11 | No | Low–medium | MIT | 2025-02-22 | Active PD org, multiple maintainers, auto-updating fingerprint DB | **Strong** |
| `github.com/hashicorp/go-version` | Semver range parsing and constraint checking | §4.2 (semver only) | No | Very low (stdlib only) | MPL-2.0 (verify) | 2024-05-23 | Mature, widely used; semver only | **Moderate** |
| `github.com/PuerkitoBio/goquery` | jQuery-style HTML querying on `x/net/html` + cascadia | §4.4, §4.6 | No | Low (net/html + cascadia) | BSD-3-Clause | v1.12.0 (2026-03-15) | 10+ year history; stable API; multiple contributors | **Strong** |
| `github.com/gocolly/colly` | General-purpose crawler/scraper framework | §4.6, §4.11 | No | Medium | Apache-2.0 | v2.2.0 (2025-03-27) | Widely adopted; multiple contributors | **Strong** |
| `gosqlx.dev` / `GoSQLX` | Multi-dialect SQL parser/AST for injection analysis | §4.5 | No | Medium | Permissive (verify) | 2026-03-21 | Actively developed; multi-dialect focus | **Strong** |
| `mvdan.cc/sh/v3` | Shell parser/formatter/interpreter (POSIX/Bash/mksh) | §4.5 | No | Low–medium | BSD-3-Clause | v3 active | Widely used; stable APIs; lead maintainer + community | **Strong** |
| `github.com/janstuemmel/go-ldap-filter` | RFC4515 LDAP filter parser and matcher | §4.5 | No | Very low | Permissive (verify) | 2022-06-18 | WIP; limited filter coverage; single maintainer | **Moderate** |
| `github.com/quic-go/quic-go` | QUIC + HTTP/3 implementation (RFC 9000/9114) | §4.7 | No | Medium–high | Apache-2.0 | 2025-10-02 | Production-ready; multi-repo org | **Strong** |
| `github.com/CycloneDX/cyclonedx-go` | CycloneDX SBOM read/write | §4.10 | No | Low–medium | Apache-2.0 | Active since 2021 | Official CycloneDX org; focused scope | **Strong** |
| `github.com/spdx/tools-golang` | SPDX document read/write (multiple formats) | §4.10 | No | Medium | SPDX licence | 2024-06-24 | Official SPDX tooling; community-maintained | **Strong** |
| `github.com/owenrumney/go-sarif` | SARIF 2.1.0 generation and parsing | §4.10 | No | Low–medium | MIT | v3.1.4 (2025-04-09) | Long-lived; widely used; single primary author + contributors | **Strong** |
| `github.com/richardwooding/go-sarif` | Minimal, zero-dependency SARIF 2.1.0 emitter | §4.10 | No | Very low (stdlib only) | Permissive (verify) | 2026-07-08 | Newer; single maintainer; minimal footprint | **Strong** |
| `github.com/go-openapi/validate` | Swagger 2.0 spec validation + JSON Schema validation | §4.11 (API schema) | No | Medium | Apache-2.0 | Active 2026 | go-openapi toolkit; multi-package ecosystem | **Strong** |
| `github.com/getkin/kin-openapi` | OpenAPI 3.0 + Swagger v2 parsing, validation, routing | §4.11 (API schema) | No | Medium | MIT | Active 2026 | Widely used; community-maintained | **Strong** |
| `github.com/pb33f/libopenapi-validator` | OpenAPI 3+ request/response validation | §4.11 (API schema) | No | Low–medium | Permissive (verify) | Active 2026 | Newer; focused on HTTP req/res validation | **Moderate** |
| `github.com/corazawaf/coraza` | OWASP Coraza WAF — ModSecurity SecLang engine | §4.11 (WAF detection) | No (CGO optional for libinjection/PCRE) | Medium | Apache-2.0 | Active 2026 | OWASP project; CRS v4 compatible; multi-maintainer | **Strong** |
| `github.com/jcmturner/gokrb5/v8` | Pure Go Kerberos 5 library (clients + services) | §4.11 (auth testing) | No | Medium | Apache-2.0 | v8.4.4 | Pure Go; no native deps; long-lived | **Strong** |
| `github.com/russellhaering/gosaml2/v2` | SAML 2.0 SP + IDP library | §4.11 (auth testing) | No | Medium | Permissive (verify) | Active | Signature validation; replay attack detection | **Moderate** |
| `github.com/projectdiscovery/fastdialer` | DNS cache + dial history dialer | §4.11 (HTTP client) | No | Medium | MIT | 2025-08-24 | PD ecosystem; used by httpx/nuclei | **Moderate** |
| `github.com/projectdiscovery/retryablehttp-go` | HTTP client with automatic retries | §4.11 (HTTP client) | No | Low | MPL-2.0 | 2026-02-01 | PD ecosystem; drop-in replacement | **Moderate** |
| `github.com/projectdiscovery/rawhttp` | Raw HTTP client with low-level control | §4.11 (HTTP client) | No | Medium | MIT | 2025-08-24 | PD ecosystem; uses fastdialer | **Moderate** |
| `github.com/teler-waf/teler-waf` | Go HTTP middleware WAF with IDS | §4.11 (WAF detection) | No | Medium | MIT | Active 2026 | Pure Go; OWASP Top 10 protection | **Moderate** |
| `github.com/xyproto/acra` | Network encryption proxy for SQL injection prevention | §4.11 (SQLi prevention) | No | Medium | Apache-2.0 | Active | Selective encryption; IDS | **Moderate** |
| `github.com/Interpol/malboxes` | Rule-based data generator for fuzzing | §4.11 (fuzzing) | No | Low | MIT | Dormant | Rule-based generation; legacy | **Weak** |
| `github.com/cameradar/cameradar` | RTSP stream discovery and attack library | §4.11 (RTSP testing) | No | Medium | MIT | Dormant | RTSP-specific; niche | **Weak** |

### Detailed Notes on Strong Library Candidates

#### `projectdiscovery/wappalyzergo`

- **API entry points**: Feed HTTP response headers and HTML body into detection functions; receive a list of detected technologies with confidence and version hints.
- **Does not do**: Vulnerability matching by version; TLS fingerprinting; WAF detection.
- **Failure shape**: Malformed HTML yields lower confidence, not silent failure. Catastrophic parse errors surface as Go errors.
- **Overlap with §3**: Adds higher-level technology labels (React, jQuery, Apache, nginx) that complement existing CSP/cookie/header analytics. Enables catalog rows like `React Server Components RCE (React2Shell)` and strengthens `Vulnerable JavaScript dependency`.

#### `gosqlx.dev` / GoSQLX

- **API entry points**: Configure parser for target dialect (PostgreSQL, MySQL, SQL Server, etc.); parse baseline queries and injected payloads into ASTs; compare AST structures.
- **Does not do**: Database connectivity; vendor-specific stored procedure languages.
- **Failure shape**: Invalid SQL returns parsing errors; not designed to silently drop invalid input.
- **Overlap with §3**: Replaces or augments heuristic error-string classification for SQLi by proving that injected payloads change the AST.

#### `mvdan.cc/sh/v3`

- **API entry points**: `syntax.Parse` for shell AST; `expand`/`interp` packages for sandboxed simulation.
- **Does not do**: OS-level execution effects; non-shell languages (PowerShell, cmd.exe).
- **Failure shape**: Syntax errors surface as parsing errors; no silent partial ASTs.
- **Overlap with §3**: Upgrades command-injection handling from reflected-marker detection to provable structural changes in shell commands.

#### `PuerkitoBio/goquery`

- **API entry points**: `goquery.NewDocumentFromNode(node)`; chainable selectors: `doc.Find("form")`, `form.Find("input[type=password]")`, `form.Attr("method")`.
- **Does not do**: Semantic classification of fields; tracking values across requests.
- **Failure shape**: HTML parse errors surface from `x/net/html`; queries over empty documents yield empty selections you can distinguish.
- **Overlap with §3**: Thin chainable layer over existing `x/net/html` usage; compact way to implement form/credential-flow rows.

#### `gocolly/colly`

- **API entry points**: `colly.NewCollector()`; callbacks: `OnHTML("a[href]", ...)`, `OnRequest`, `OnResponse`.
- **Does not do**: JavaScript execution; SPA route discovery; session/auth management.
- **Failure shape**: HTTP errors propagate via callback error parameters; parsing failures are logged, not silently dropped.
- **Overlap with §3**: Complements HTTP/1.1 pipelining and GraphQL engine for non-JS attack-surface discovery.

#### `quic-go/quic-go`

- **API entry points**: `quic.Dial` / `quic.ListenAddr` for QUIC; `http3.RoundTripper` for HTTP/3.
- **Does not do**: Raw TLS record layer frames; HTTP/2 frame-level controls.
- **Failure shape**: QUIC handshake and transport errors are explicit Go errors; "could not speak HTTP/3" is distinguishable from "no vuln".
- **Overlap with §3**: Extends transport coverage to HTTP/3/QUIC; combines with existing HTTP/2 and `net.Conn` framing.

#### `corazawaf/coraza` (OWASP Coraza WAF)

- **API entry points**: Import as a Go library; load SecLang rules; process HTTP requests through the WAF engine programmatically.
- **Does not do**: Without cgo (CGO_ENABLED=0), loses `@detectSQLi`, `@detectXSS`, and PCRE expressions, meaning OWASP CRS won't work fully. With cgo, requires libinjection and libpcre.
- **Failure shape**: Rule evaluation errors are surfaced; empty rule sets are distinguishable from "no violations".
- **Overlap with §3**: Could serve as a local WAF detection oracle — feed captured requests through Coraza with CRS v4 and report which rules fire, giving burpsy-go a WAF-detection signal.

#### `jcmturner/gokrb5/v8`

- **API entry points**: Client authentication to SPNEGO Kerberos web services; keytab parsing; credential cache parsing; HTTP handler wrappers for SPNEGO auth.
- **Does not do**: Does not test for Kerberos vulnerabilities per se; it implements the protocol, which you can use to craft test cases.
- **Failure shape**: Pure Go, no native deps; protocol errors are explicit.
- **Overlap with §3**: Enables authentication protocol testing (Kerberos/SPNEGO) identified as a gap in §4.11.

#### `projectdiscovery/fastdialer`

- **API entry points**: `fastdialer.NewDialer(options)` → `Dial()`, `DialTLS()`, `GetDialedIP()`, `GetTLSData()`.
- **Does not do**: Does not provide HTTP semantics; it's a low-level dialer with DNS cache, TLS cache, and dial history.
- **Failure shape**: Dial errors are explicit; DNS resolution failures are distinguishable from connection failures.
- **Overlap with §3**: Provides DNS caching and dial history for your HTTP client, improving performance and enabling TLS fingerprinting.

#### `projectdiscovery/retryablehttp-go`

- **API entry points**: `retryablehttp.NewClient()` → `Do()` with automatic retries and exponential backoff.
- **Does not do**: Does not provide raw HTTP framing; it's a wrapper around `net/http`.
- **Failure shape**: Connection errors trigger retries; 500-range responses trigger retries; other responses are returned as-is.
- **Overlap with §3**: Drop-in replacement for `net/http` with automatic retry logic, useful for flaky targets.

#### `projectdiscovery/rawhttp`

- **API entry points**: `rawhttp.NewDialer()` → `Dial()`, `DialWithProxy()`, `DialTimeout()`.
- **Does not do**: Does not parse HTTP responses; it's a raw connection dialer.
- **Failure shape**: Dial errors are explicit; uses fastdialer internally with disk cache.
- **Overlap with §3**: Provides low-level HTTP/1.1 framing control for custom request construction.

#### `teler-waf/teler-waf`

- **API entry points**: `teler.New()` → `ServeHTTP()` middleware; configurable rulesets.
- **Does not do**: Does not provide full ModSecurity compatibility; it's a simpler IDS/WAF.
- **Failure shape**: Pure Go; no cgo; rule evaluation errors are explicit.
- **Overlap with §3**: Provides WAF detection and protection for Go-based web applications; can be used to test WAF bypass techniques.

#### Reporting libraries (CycloneDX, SPDX, SARIF, go-openapi)

- **CycloneDX (`cyclonedx-go`)**: Go types and helpers for CycloneDX SBOM JSON/XML. Does not map findings to vulnerabilities automatically.
- **SPDX (`tools-golang`)**: In-memory models for SPDX 2.x documents; readers/writers for tag-value, JSON, RDF, YAML. Includes filesystem-to-SPDX builders.
- **SARIF (`owenrumney/go-sarif`)**: Rich SARIF object model; multi-driver reports with rules, results, locations. `richardwooding/go-sarif` is a zero-dependency alternative for minimal footprint.
- **go-openapi/validate + kin-openapi**: Parse and validate OpenAPI/Swagger specs; validate HTTP requests/responses against schemas. Enables API schema ingestion and contract testing.

---

## Part II: CLI Tools (Subprocess Candidates)

These are Go-written CLI tools that can be integrated via subprocess, parsing their machine-readable output (JSON preferred). This is the same pattern already used with `interactsh-client`.

### Recon & Attack-Surface Discovery

| Tool | Purpose | Key Features | Output Formats | Source |
|---|---|---|---|---|
| `subfinder` | Passive subdomain enumeration | Leverages dozens of API sources; fast concurrent resolution | text, JSON | [cite:234][cite:235] |
| `gau` (getallurls) | Fetch known URLs from Wayback, OTX, Common Crawl, URLScan | Historical URL harvesting; pipable | text, JSON | [cite:121][cite:207] |
| `gobuster` | Directory/file/DNS/vhost/S3/GCS brute-forcing | Multi-mode; concurrent; patterns support | text | [cite:208][cite:214] |
| `ffuf` | Fast web fuzzer | FUZZ keyword in URL/headers/POST; filtering by status/size/words; vhost fuzzing | JSON, CSV, text | [cite:62][cite:67][cite:70] |
| `katana` | Next-gen crawler | Headless + standard modes; JS route discovery; goquery-based scraping; simhash dedup | JSON, JSONL | [cite:221][cite:230][cite:258] |
| `gospider` | Fast spider | URL extraction from HTML/JS/sitemaps | text | [cite:51] |
| `cariddi` | Crawler + secret/endpoint scanner | Concurrent crawling; secret detection; endpoint extraction; error page detection | text, JSON | [cite:318][cite:319] |
| `httpx` | Multi-purpose HTTP toolkit | TLS/HTTP fingerprinting; protocol/cipher enumeration; tech detection; screenshots | JSON, text | [cite:251][cite:255][cite:256] |
| `naabu` | Fast port scanner | SYN/CONNECT scans; top-N ports; custom port ranges; pipable | JSON, text | [cite:272][cite:277][cite:282] |
| `dnsx` | DNS toolkit | Multiple DNS query types; custom resolvers; wildcard detection | JSON, text | [cite:63] |
| `asnmap` | ASN mapping | Maps org network ranges from ASN info; pipable to other PD tools | text, JSON | [cite:245][cite:246] |
| `uncover` | Search engine aggregator | Shodan, Censys, FOFA, Quake, Zoomeye, Netlas, CriminalIP, etc. | text, JSON | [cite:240] |
| `httprobe` | HTTP/HTTPS probe for live hosts | Takes domain list; probes ports 80/443; custom ports; concurrency control | text | [cite:329][cite:333][cite:341] |

### Vulnerability Scanning

| Tool | Purpose | Key Features | Output Formats | Source |
|---|---|---|---|---|
| `nuclei` + templates | Template-based vuln scanner | YAML DSL; HTTP/DNS/TCP/SSL; 9000+ community templates; concurrent | JSON, SARIF, text | [cite:63][cite:69] |
| `dalfox` (v2 Go branch) | XSS scanner | Reflected/Stored/DOM XSS; parameter analysis; blind XSS; headless verification; pipeline mode | JSON, text | [cite:197][cite:225] |
| `xxss` | Fast reflected-XSS prober | High-speed screening; pipe-friendly | JSON, text | [cite:206] |
| `xhunter` | Concurrent XSS + SQLi scanner | Multi-mode; payload-driven | text | [cite:192] |
| `sqligo` | SQL injection detection/exploitation | Error/union/blind/time-based | text | [cite:205] |
| `WCVS` (Web-Cache-Vulnerability-Scanner) | Web cache poisoning + deception | 10 poisoning techniques; header/parameter injection | JSON, text | [cite:123][cite:133] |
| `toxicache` | Web cache poisoning scanner | Multi-technique injection | text | [cite:124] |
| `ryofuzz` | Behavioral vulnerability fuzzer | Coverage-guided mutation; proxy interception; intent mapping | text | [cite:106] |
| `jaeles` | Web app scanner framework | Signature-based; YAML signatures; concurrent; plugin architecture | text, JSON | [cite:336][cite:363][cite:367] |

### WAF Detection & Evasion

| Tool | Purpose | Key Features | Output Formats | Source |
|---|---|---|---|---|
| `GoTestWAF` | WAF/API security evaluation | Payload generation across REST/GraphQL/gRPC/SOAP/XMLRPC; PDF reports; bypass assessment | JSON, PDF, console | [cite:115][cite:224][cite:231] |

### Subdomain Takeover

| Tool | Purpose | Key Features | Output Formats | Source |
|---|---|---|---|---|
| `subzy` | Subdomain takeover checker | Fingerprint-based; can-i-take-over-xyz service list | text, JSON | [cite:141] |
| `subover` | Hostile subdomain takeover | 30+ service fingerprints; concurrent | text | [cite:134] |
| `tko-subs` | Subdomain takeover + active takeover | CNAME-based detection; optional active takeover | CSV, text | [cite:135] |
| `subtocheck` | Subdomain takeover checker | DNS resolution + HTTP/HTTPS fingerprint matching | text | [cite:147] |
| `SubdomainSleuth` | Dangling DNS + takeover scanner | Reads BIND zone files; RFC 1035 format | text | [cite:142] |

### SAST / Code Security

| Tool | Purpose | Key Features | Output Formats | Source |
|---|---|---|---|---|
| `gosec` | Go source code security analyzer | AST+SSA analysis; 50+ rules mapped to CWE; taint tracking; CI/CD integration | JSON, SARIF, XML, CSV, HTML | [cite:66][cite:72][cite:75] |
| `govulncheck` | Go vulnerability checker | Analyzes Go module dependency graph against Go vuln DB | text, JSON | [cite:117] |
| `golangci-lint` (with security plugins) | Go linter with security checks | Modular; includes gosec integration; CI-friendly | text, JSON | [cite:117] |
| `OSV-Scanner` | Vulnerability scanner for dependencies | Connects project dependencies to OSV database; dual CLI + Go library | JSON, text | [cite:234] |

### MITM Proxy Libraries

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `go-mitmproxy` (kardianos) | Go MITM proxy | HTTP/HTTPS interception; on-the-fly cert generation; web UI | [cite:122] |
| `gomitmproxy` (AdguardTeam) | Simple Go MITM proxy | TLS interception; transparent proxy; cert authority management | [cite:130] |
| `mitmpgo` (josexy) | Flexible MITM proxy library | HTTP/HTTPS/HTTP/2/WebSocket interception; transparent inspection | [cite:131] |
| `goproxy` (stripe) | Customizable HTTP proxy library | Regular HTTP proxy; HTTPS CONNECT; MITM "hijacking" | [cite:108][cite:128] |
| `bettercap` | Network reconnaissance and MITM framework | WiFi, BLE, HID, CAN-bus, IPv4/IPv6; packet proxy; credential harvesting | [cite:344][cite:345][cite:347] |

### Race Condition / HTTP Timing

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `racey` (swarley7) | HTTP/2 race condition tester | Single-packet attack; HTTP/2 stream multiplexing; last-byte sync | [cite:39][cite:168] |
| `h2spacex` (nxenon) | HTTP/2 single-packet attack library | Scapy-based; low-level frame control; timing attack exploitation | [cite:40][cite:176] |
| `burp-mcp-server` race tool | Last-byte sync race attack | N parallel TLS/TCP connections; bypasses proxy for timing precision; Turbo Intruder technique | [cite:164] |

### OpenAPI / API Schema

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `go-swagger` CLI | Swagger 2.0/OpenAPI 2.0 toolkit | Spec validation; code generation; server/client generation | [cite:178][cite:186] |
| `oasdiff` CLI | OpenAPI spec diffing + validation | Breaking change detection; structured findings | [cite:177] |

### Prototype Pollution Gadgets

| Resource | Purpose | Source |
|---|---|---|
| `KTH-LangSec/server-side-prototype-pollution` | Curated gadget corpus for Node.js/Deno/NPM packages | [cite:156] |
| `PortSwigger/prototype-pollution-gadgets-finder` | Burp extension for SSP gadget detection | [cite:153] |

### OAuth / OIDC / SAML / Kerberos

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `gosaml2` (russellhaering) | SAML 2.0 SP+IDP library | Signature validation; replay attack detection | [cite:137] |
| `oauth2cli` (int128) | OAuth 2.0 CLI authorization flow | Simple authorization flow for CLI tools | [cite:159] |
| `golang-mock-oauth2-server` | Mock Google OAuth2 server for testing | Simulates Google OAuth2 flow; dev/test only | [cite:162] |
| `go-oauth2/oauth2` | OAuth 2.0 server library | Full OAuth2 server implementation; extensible | [cite:155] |
| `oidc-client-demo` | OIDC integration testing CLI | Reference implementation; tests OIDC flows | [cite:152] |
| `gokrb5` (jcmturner) | Pure Go Kerberos 5 library | SPNEGO auth; keytab parsing; credential cache; SPNEGO HTTP handler | [cite:307][cite:317] |

### SMTP / Mail Header Injection

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `MailHog` | SMTP capture/testing tool | SMTP sink (port 1025); web UI + JSON API (port 8025); single Go binary | [cite:167] |
| `smtptest` (k1LoW) | SMTP test server | Go-based SMTP testing framework | [cite:165] |
| `SMTP-Hunter` | SMTP penetration testing tool | Aggressive SMTP server vulnerability identification | [cite:169] |

### HTTP Header / Host Injection

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `hostinject` | Host header injection testing | Injects header values; checks for vulnerability | [cite:172] |
| `spoof_checker` | Email spoofing + subdomain takeover | Checks SPF/DKIM/DMARC; JSON output | [cite:136] |

### Technology Fingerprinting

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `httpx` (PD) | Multi-purpose HTTP toolkit | TLS/HTTP fingerprinting; protocol/cipher enumeration; tech detection | [cite:63][cite:69] |
| `wappalyzergo` (as library or via `httpx -td`) | Wappalyzer tech detection | Auto-updating fingerprint DB; high performance | [cite:16][cite:27] |

### Fuzzing & Data Generation

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `Interpol` | Rule-based data generator for fuzzing | Generates test data based on rules; legacy project | [cite:323] |

### Specialized Scanners

| Tool | Purpose | Key Features | Source |
|---|---|---|---|
| `cameradar` | RTSP stream discovery and attack | Discovers RTSP hosts; finds streaming device info; launches attacks | [cite:241][cite:323] |
| `acra` | Network encryption proxy for databases | Selective encryption; SQL injection prevention; intrusion detection | [cite:323] |

---

## Part III: Library-vs-CLI Capability Matrix

A critical finding of this research is that **many Go security tools support both CLI and library/SDK modes**. The table below shows which tools have a programmable Go API in addition to their CLI interface, and notes the cgo/transitive dependency implications of library integration.

| Tool | CLI? | Library/SDK? | Library import path | cgo for library? | Transitive dep weight (library) | Notes |
|---|---|---|---|---|---|---|
| `nuclei` | Yes | **Yes** | `github.com/projectdiscovery/nuclei/v3/lib` | No | **Heavy** (~100+ modules via PD ecosystem deps) | Officially supported SDK since v3; same heavy dep graph that made interactsh-client problematic as a library |
| `subfinder` | Yes | **Yes** | `github.com/projectdiscovery/subfinder/v2/pkg/runner` | No | Heavy (PD ecosystem) | `runner.NewRunner(opts)` → `EnumerateSingleDomainWithCtx()`; example in repo |
| `httpx` | Yes | **Yes** | `github.com/projectdiscovery/httpx/common/httpx` | No | Heavy (PD ecosystem) | `Option` struct → runner → `RunEnumeration()`; example in repo |
| `katana` | Yes | **Yes** | `github.com/projectdiscovery/katana` | **Yes** (CGO_ENABLED=1 for headless mode) | Heavy (PD ecosystem + chromedp for headless) | `Option` struct → `crawlerOptions` → `crawler.Crawl()`; headless mode requires chromedp (already in burpsy-go) |
| `naabu` | Yes | **Yes** | `github.com/projectdiscovery/naabu/v2/pkg/runner` | **Yes** (requires libpcap for SYN scans) | Medium (PD ecosystem + libpcap) | `runner.Options{OnResult: callback}` → `RunEnumeration()`; **cgo via libpcap disqualifies for pure-Go constraint** |
| `gobuster` | Yes | **No** (CLI-only) | N/A | N/A | N/A | No public library API; subprocess only |
| `ffuf` | Yes | **No** (CLI-only) | N/A | N/A | N/A | No public library API; subprocess only |
| `gau` | Yes | **No** (CLI-only) | N/A | N/A | N/A | No public library API; subprocess only |
| `dalfox` v2 | Yes | **Partial** | `github.com/hahwul/dalfox/v2` | No | Medium | v2 Go branch has package structure but is primarily CLI-shaped; v3 rewritten in Rust. Best used as subprocess. |
| `GoTestWAF` | Yes | **No** (CLI/Docker only) | N/A | N/A | N/A | Designed as Docker container; PDF report output; subprocess/Docker only |
| `gosec` | Yes | **Yes** | `github.com/securego/gosec/v2` | No | Low–medium | Can be imported as analyzer; primarily CLI but has programmatic API |
| `OSV-Scanner` | Yes | **Yes** | Google OSV Go packages | No | Low–medium | Officially supports library mode for vulnerability scanning logic |
| `coraza` (WAF) | Yes | **Yes** | `github.com/corazawaf/coraza` | Optional (CGO for libinjection/PCRE) | Medium | Pure-Go mode loses `@detectSQLi`/`@detectXSS`/PCRE; OWASP CRS requires cgo features |
| `gokrb5` | Yes | **Yes** | `github.com/jcmturner/gokrb5/v8` | No | Medium | Pure Go Kerberos; no native deps |
| `gosaml2` | No (library) | **Yes** | `github.com/russellhaering/gosaml2/v2` | No | Medium | Library-only; no CLI |
| `go-openapi/validate` | No (library) | **Yes** | `github.com/go-openapi/validate` | No | Medium | Library-only; part of go-openapi toolkit |
| `kin-openapi` | No (library) | **Yes** | `github.com/getkin/kin-openapi` | No | Medium | Library-only; OpenAPI 3.0 + Swagger v2 |
| `cariddi` | Yes | **No** (CLI-only) | N/A | N/A | N/A | No public library API; subprocess only |
| `subzy` | Yes | **No** (CLI-only) | N/A | N/A | N/A | No public library API; subprocess only |
| `WCVS` | Yes | **No** (CLI-only) | N/A | N/A | N/A | No public library API; subprocess only |
| `gospider` | Yes | **No** (CLI-only) | N/A | N/A | N/A | No public library API; subprocess only |
| `asnmap` | Yes | **Yes** | `github.com/projectdiscovery/asnmap` | No | Heavy (PD ecosystem) | Can be integrated as library in Go applications |
| `interactsh-client` | Yes | **Yes** (but rejected) | `github.com/projectdiscovery/interactsh/pkg/client` | No | ~100 modules | Already rejected as library; subprocess CLI used instead |
| `govulncheck` | Yes | **Yes** | `golang.org/x/vuln/...` | No | Low | Part of Go official tooling; programmatic API available |
| `oasdiff` | Yes | **Yes** | `github.com/oasdiff/oasdiff/validate` | No | Medium | Library API exposes spec validation with structured findings |
| `jaeles` | Yes | **Partial** | `github.com/jaeles-project/jaeles/core` | No | Medium | Signature-based framework; core package available but primarily CLI-shaped |
| `fastdialer` | No (library) | **Yes** | `github.com/projectdiscovery/fastdialer` | No | Medium | Library-only; used by httpx/nuclei; DNS cache + dial history |
| `retryablehttp-go` | No (library) | **Yes** | `github.com/projectdiscovery/retryablehttp-go` | No | Low | Library-only; drop-in replacement for net/http with retries |
| `rawhttp` | No (library) | **Yes** | `github.com/projectdiscovery/rawhttp` | No | Medium | Library-only; raw HTTP client with low-level control |
| `httprobe` | Yes | **No** (CLI-only) | N/A | N/A | N/A | No public library API; subprocess only |
| `bettercap` | Yes | **Yes** | `github.com/bettercap/bettercap/v2` | **Yes** (requires libpcap) | Heavy | **cgo via libpcap disqualifies for pure-Go constraint**; GPL-3 licence |

### Summary of Library-vs-CLI Findings

**Tools with both CLI and library/SDK support** (15 identified):

1. `nuclei` — library available but heavy deps (~100+ modules)
2. `subfinder` — library available but heavy PD ecosystem deps
3. `httpx` — library available but heavy PD ecosystem deps
4. `katana` — library available but requires cgo for headless mode
5. `naabu` — library available but requires cgo (libpcap)
6. `gosec` — library available, low–medium deps
7. `OSV-Scanner` — library available, low–medium deps
8. `coraza` — library available, cgo optional (pure-Go mode limited)
9. `gokrb5` — library-only, pure Go, no cgo
10. `asnmap` — library available but heavy PD ecosystem deps
11. `govulncheck` — library available, low deps
12. `oasdiff` — library available, medium deps
13. `jaeles` — library available, medium deps (signature-based framework)
14. `fastdialer` — library-only, medium deps (PD ecosystem)
15. `retryablehttp-go` — library-only, low deps (PD ecosystem)
16. `rawhttp` — library-only, medium deps (PD ecosystem)

**Tools that are CLI-only** (must be subprocessed):

`gobuster`, `ffuf`, `gau`, `GoTestWAF`, `cariddi`, `subzy`, `WCVS`, `gospider`, `dalfox` (v2 has packages but is CLI-shaped), `toxicache`, `hostinject`, `spoof_checker`, `subover`, `tko-subs`, `subtocheck`, `SubdomainSleuth`, `SMTP-Hunter`, `ryofuzz`, `xhunter`, `sqligo`, `xxss`, `httprobe`, `bettercap` (cgo + GPL)

### Key Insight: PD Ecosystem Dependency Weight

The ProjectDiscovery tools (`nuclei`, `subfinder`, `httpx`, `katana`, `naabu`, `asnmap`, `fastdialer`, `retryablehttp-go`, `rawhttp`) all share the PD common library ecosystem (`goflags`, `gologger`, `hmap`, `mapcidr`, `retryabledns`, `utils`, etc.). While each tool's library API is well-documented and officially supported, importing any one of them as a library pulls in a significant portion of the PD dependency graph. This is the same concern that led to rejecting `interactsh` as a library (~100 modules). The recommendation remains: **subprocess PD tools as CLIs** unless the specific library API is needed and the dependency weight is acceptable for that particular tool's value.

The exceptions where library import is viable despite PD ecosystem weight:

- `wappalyzergo` — standalone, does not pull in the full PD common library graph
- `gosec` — not part of PD ecosystem; independent dependency graph
- `fastdialer` — standalone dialer with DNS cache; useful for custom HTTP clients
- `retryablehttp-go` — drop-in replacement for `net/http` with automatic retries

---

## Part IV: Gaps with No Acceptable Library or Tool

These capability gaps have no pure-Go library or CLI tool that adequately addresses them under the project's constraints. They require bespoke engineering.

### Stored-Input Threading (§4.1)

No Go library or tool models taint/dataflow correlation across **separate HTTP transactions**. Race-condition tools focus on concurrency, not cross-request taint graphs. This is necessarily bespoke: a custom taint-tracking engine built on burpsy-go's existing session coordinator and offset-based storage.

### TLS Transport Analysis Beyond stdlib (§4.3)

`zmap/zcrypto` is heavy and pinned to older Go. `projectdiscovery/tlsx` requires deeper dependency audit. Go's `crypto/tls` deliberately refuses deprecated protocols and export ciphers, which is exactly what needs testing. No pure-Go TLS stack was found that exposes deprecated protocols/ciphers without forking stdlib.

### XPath and Server-Side Template Language Parsing (§4.5)

No pure-Go parsers for XPath, Jinja2, Twig, Freemarker, Velocity, or ERB. Semantic validation for these injection families remains heuristic or requires custom grammars.

### JS-Defined Endpoints / SPA Routes from Source (§4.6)

No pure-Go equivalent to `jsluice` (rejected due to cgo/tree-sitter). Static JS analysis for endpoint extraction in Go is bespoke; `cariddi` does runtime crawling with regex-based secret/endpoint detection but not static AST analysis.

### HTTP/2 Single-Packet Race Attack Primitives (§4.7)

`racey` and `h2spacex` demonstrate the technique but neither is a reusable library with stable API. `h2spacex` is Python/Scapy-based (not Go). Last-frame synchronization at the HTTP/2 frame level requires custom concurrency logic on Go's `x/net/http2` or raw `net.Conn`.

### ysoserial-Equivalent Gadget Chain Generation (§4.8)

No Go project provides ysoserial-style gadget chains for Java/.NET/PHP/Python. Existing tooling is language-native (Java, C#) or CLI-only. Options: port specific chains to Go manually, or subprocess external tools with explicit delegation reporting.

### Additional Vulnerability Rule Corpora (§4.9)

Beyond Nuclei templates and PortSwigger BChecks, no additional openly licensed, machine-readable corpora with clear Go ingestion paths were found. Semgrep rules, ZAP ascanrules, and OWASP CRS exist but require case-by-case licence/format analysis. Coraza WAF's CRS integration could be mined for rule patterns.

### OWASP/CWE/CAPEC Mapping Data (§4.10)

No Go library ships canonical CWE/CAPEC/OWASP mappings as structured data. burpsy-go must maintain its own mapping tables from `TypeIndex` to CWE/CAPEC/OWASP IDs and emit them via SARIF/SBOM tooling.

### Response Similarity/Diffing, Advanced WAF Detection, Normalization Differentials (§4.11)

No dedicated Go library for response similarity/clustering/deduplication. WAF detection is partially covered by `GoTestWAF` (CLI), `coraza` (library, for local CRS evaluation), and `wappalyzergo` (stack detection), but no unified solution. HTTP normalization differentials and content-encoding edge cases remain bespoke.

---

## Integration Architecture Recommendations

### Recommended Library Imports (into burpsy-go's module graph)

These have acceptable dependency weight and fill real gaps:

1. **`wappalyzergo`** — technology fingerprinting (standalone, no PD ecosystem bloat)
2. **`goquery`** — HTML form analysis (thin layer over existing `x/net/html`)
3. **`mvdan.cc/sh/v3`** — shell command AST parsing for injection validation
4. **`gosqlx.dev`** — multi-dialect SQL AST parsing (subject to licence check)
5. **`quic-go`** — HTTP/3/QUIC transport support
6. **`owenrumney/go-sarif`** or **`richardwooding/go-sarif`** — SARIF reporting
7. **`cyclonedx-go`** — CycloneDX SBOM
8. **`spdx/tools-golang`** — SPDX SBOM
9. **`kin-openapi`** or **`go-openapi/validate`** — OpenAPI/Swagger spec ingestion
10. **`gokrb5/v8`** — Kerberos/SPNEGO auth testing
11. **`coraza`** (pure-Go mode) — local WAF CRS evaluation (limited without cgo)
12. **`hashicorp/go-version`** — semver range matching (partial; non-semver bespoke)
13. **`fastdialer`** — DNS cache + dial history for custom HTTP clients
14. **`retryablehttp-go`** — drop-in replacement for `net/http` with automatic retries
15. **`rawhttp`** — raw HTTP client with low-level framing control
16. **`teler-waf`** — pure-Go WAF middleware for testing WAF bypass techniques

### Recommended CLI Subprocess Integrations

These follow the existing `interactsh-client` pattern:

1. **`nuclei`** — delegate known-CVE/misconfig checks; ingest JSON results with explicit provenance
2. **`katana`** — SPA route discovery complementing chromedp harness
3. **`httpx`** — TLS/HTTP fingerprinting and protocol enumeration
4. **`ffuf`** — parameter mining, directory/vhost discovery
5. **`dalfox` v2** — XSS verification (especially stored XSS)
6. **`GoTestWAF`** — WAF detection and evasion assessment (Docker-based)
7. **`WCVS`** — web cache poisoning and deception
8. **`gobuster`** — directory/file/DNS/vhost brute-forcing
9. **`gau`** — historical URL harvesting from Wayback/OTX/Common Crawl
10. **`subzy`** — subdomain takeover checking
11. **`gosec`** — Go source code SAST (for target code, if available)
12. **`racey`** — HTTP/2 race condition testing
13. **`cariddi`** — runtime secret/endpoint detection during crawling
14. **`asnmap`** — ASN-based network range discovery
15. **`jaeles`** — signature-based web app scanning (alternative to nuclei)
16. **`httprobe`** — quick HTTP/HTTPS liveness probing for domain lists
17. **`uncover`** — search engine aggregation (Shodan, Censys, FOFA, etc.)

### Honest Counting Integration Principle

For every check delegated to an external CLI, the scanner must:

- Record which tool was invoked, with what version, against which target
- Mark the catalog row as "delegated to `<tool>`" rather than "native evaluation"
- Distinguish "tool ran and found nothing" from "tool could not run" from "tool was not invoked for this row"
- Never let a subprocess failure (timeout, non-zero exit, unparseable output) read as "no vulnerability"
