# Research Brief: Go Libraries for a Web Application Security Scanner

Hand this document to an external research agent verbatim. It is self-contained — the reader
is assumed to have **no access to our repository** and no prior context.

---

## 1. What we are building

`burpsy-go` is a **web application security scanner** written in Go, structurally modelled on
Burp Suite Professional. It proxies HTTP traffic, records exchanges, enumerates *insertion
points* (query params, body params, cookies, headers, path segments, JSON/XML/base64-nested
values) within each request, and dispatches security checks against them.

It implements a **183-issue catalog** transcribed from Burp's shipped knowledge base. Each
issue has a stable numeric `TypeIndex`. Every issue is in exactly one state:

- **runnable** — a native Go evaluator exists and executes (currently **29**)
- **declined** — no evaluator; the row carries an explicit machine-readable reason naming the
  *missing capability* (currently **154**)

A core project value is **honest counting**: a scan must never let "we did not look" read as
"we looked and found nothing". Code that makes a partial result look complete is treated as a
defect even if its tests pass. This shapes what libraries are acceptable: anything that can
silently return "no findings" when it actually failed is a liability.

A second core value is **memory frugality**: the scanner is designed so resident memory does
not scale with work in flight (raw bytes written once, everything downstream holds offsets).
Heavyweight dependencies are viewed with suspicion.

---

## 2. Current dependency state — exact

Go **1.26.2**. Direct and indirect, complete:

```
go.uber.org/zap                  # logging
golang.org/x/net                 # v0.57.0 — html, publicsuffix available
golang.org/x/text                # v0.40.0 — encoding/htmlindex available
modernc.org/sqlite               # pure-Go SQLite (no cgo)
github.com/chromedp/chromedp     # v0.16.0 — headless Chrome via CDP
github.com/chromedp/cdproto
github.com/chromedp/sysutil
github.com/dop251/goja           # pure-Go ECMAScript interpreter
github.com/dlclark/regexp2/v2
github.com/go-sourcemap/sourcemap
github.com/go-json-experiment/json
github.com/gobwas/ws             # websocket (transitively, via chromedp)
github.com/gobwas/httphead
github.com/gobwas/pool
github.com/google/pprof
github.com/google/uuid
github.com/mattn/go-isatty
github.com/ncruces/go-strftime
github.com/remyoudompheng/bigfft
github.com/stretchr/testify
go.uber.org/multierr
golang.org/x/sys
modernc.org/{libc,mathutil,memory}
```

We also shell out to one **external binary**: `interactsh-client` (ProjectDiscovery) for
out-of-band interaction callbacks.

---

## 3. Capabilities we have already built — do NOT recommend replacements unless clearly better

Each is a working, tested Go package. State plainly if a library would beat one of these; do
not merely re-suggest what we have.

| Capability | How we did it |
|---|---|
| CSP directive parser | Hand-written; full CSP3 fallback chain, nonce/hash and `strict-dynamic` neutralisation rules |
| Flash/Silverlight cross-domain policy parser | `encoding/xml` |
| ASP.NET ViewState decoder + MAC heuristic | Hand-written; documented as heuristic |
| Java/.NET/PHP/Python serialized-object recogniser | Magic-byte detection, raw + base64 |
| Cookie security analyser | Hand-written + `x/net/publicsuffix` for registrable-domain boundary |
| Response/header attribute analyser | Hand-written; `net/http.DetectContentType`, `x/text/encoding/htmlindex` |
| Information-disclosure pattern bank | Package-level regexes; Luhn-validated cards, structurally validated JWKS |
| SMTP mail-header injection probes | Separator × encoding matrix |
| JWT forgery | `crypto/*`: none-alg, self-signed JWK, arbitrary `jku`/`x5u`, RS256→HS256 confusion, JWKS private-material detection |
| GraphQL engine | Introspection, suggestion-probe, content-type probes |
| XXE / entity-expansion payload generation | Bounded expansion; `encoding/xml` for well-formedness only |
| HTTP/1.1 keep-alive + pipelining | Raw `net.Conn`, explicit framing (CL vs chunked), reports undelimitable responses |
| Authenticated-vs-anonymous differential | Own session coordinator |
| Out-of-band interactions | Subprocess wrapper over `interactsh-client` |
| Headless DOM taint harness | `chromedp`; 15 instrumented sinks, 5 sources, injected before page scripts |
| DOM-less JS execution | `goja`; prototype-pollution testing, sandboxed snippet evaluation |

---

## 4. What we still cannot do — the actual research targets

Ordered by how many catalog rows each blocks.

### 4.1 Second-order / stored-input threading — blocks ~24 rows
Submit input in one HTTP exchange, observe it rendered in a *later, different* exchange.
Affects all `(stored …)` variants: stored XSS, stored DOM-based families, `Input returned in
response (stored)`, `Open redirection (stored)`, `Suspicious input transformation (stored)`,
`Password returned in later response`.
**Question:** is there any Go library for taint/dataflow correlation across separate HTTP
transactions, or is this necessarily bespoke?

### 4.2 Technology and version fingerprinting — blocks ~3 rows, enables many
Need to identify frameworks and **versions** (React, Next.js, jQuery, server software) from
responses, then match versions against vulnerable ranges. Blocks `React Server Components
RCE (React2Shell)`, and would strengthen `Vulnerable JavaScript dependency`.
**Question:** best-maintained pure-Go fingerprinting library, and best pure-Go version-range
matcher (semver plus non-semver schemes)?

### 4.3 TLS / transport analysis — blocks ~5 rows
`TLS certificate`, `Unencrypted communications`, `Strict transport security not enforced`,
`Cacheable HTTPS response`, plus cipher-suite and protocol-version enumeration. Go's
`crypto/tls` refuses to speak deprecated versions and export ciphers, which is exactly what
needs testing.
**Question:** what is the current best pure-Go option? We know of `zmap/zcrypto` (forks
stdlib crypto — heavy) and `projectdiscovery/tlsx`. Are there better-maintained alternatives?

### 4.4 Form and credential-flow analysis — blocks ~5 rows
`Cleartext submission of password`, `Password submitted using GET method`, `Password returned
in URL query string`, `Password field with autocomplete enabled`, `Password value set in
cookie`. Needs locating password inputs in HTML and tracking their values across requests.
**Question:** any Go library for structured HTML form extraction and semantic classification,
beyond raw `x/net/html` traversal?

### 4.5 Injection-payload semantic validation
We classify SQLi from error strings and response diffs, and command injection from reflected
markers. We would prefer to **prove a payload changes the parse** of the target language.
**Question:** best pure-Go parsers for SQL (multi-dialect), shell, LDAP filters, XPath, and
server-side template languages (Jinja2, Twig, Freemarker, Velocity, ERB)? Note
`pganalyze/pg_query_go` is cgo and therefore excluded.

### 4.6 Attack-surface discovery
Our crawler misses SPA routes and JS-defined endpoints.
**Question:** best pure-Go crawling library usable as a *library* (not a CLI), that handles
JS-rendered routes; and any pure-Go library to extract endpoints/paths/secrets from
JavaScript source? (We know `BishopFox/jsluice` but it is cgo tree-sitter.)

### 4.7 Race conditions and modern transports
We have HTTP/1.1 pipelining and HTTP/2. Missing: HTTP/2 single-packet-attack timing
primitives and HTTP/3/QUIC.
**Question:** pure-Go libraries giving low-level frame control for last-frame-synchronisation
timing attacks, and the current best QUIC/HTTP/3 library for adversarial testing?

### 4.8 Deserialization exploitation
We detect serialized blobs but have no gadget chains.
**Question:** does any Go project provide ysoserial-equivalent gadget chain generation for
Java/.NET/PHP/Python?

### 4.9 Rule corpora as data
We already parse PortSwigger's 264-file BCheck corpus.
**Question:** what other **openly licensed machine-readable vulnerability rule corpora** could
be ingested as data (not as an engine)? Nuclei templates are the obvious one — what else?

### 4.10 Reporting and interchange
**Question:** current best pure-Go libraries for SARIF 2.1.0 emission, CycloneDX/SPDX SBOM,
and OWASP/CWE/CAPEC mapping data?

### 4.11 Open-ended — the most valuable part of this request
**What are we not even asking about?** We want categories of Go tooling that a mature scanner
should use and that are absent from this document entirely. Response-similarity/diffing for
deduplication, WAF detection and evasion, content-encoding edge cases, HTTP request
normalisation differentials, parameter mining, authentication protocol testing (OAuth/OIDC/
SAML), GraphQL-specific attack tooling, API schema ingestion (OpenAPI/Postman), cloud
metadata SSRF targets, prototype-pollution gadget corpora — these are examples of the *kind*
of answer wanted, not a checklist. Please add whatever we have missed.

---

## 5. Hard constraints — a recommendation violating these is not useful

1. **Pure Go only. No cgo.** Non-negotiable. This rules out tree-sitter bindings and
   `pg_query_go`. State cgo status explicitly for every recommendation.
2. **Dependency weight matters and must be reported.** We rejected importing
   `projectdiscovery/interactsh/pkg/client` because its `pkg/client` imports `pkg/server` and
   `pkg/storage`, dragging a DNS server, SMTP server, LDAP server, FTP server, certmagic/ACME,
   leveldb, buntdb and bbolt — roughly **100 modules into a ~25-module project**. We shell out
   to their CLI instead. Report the transitive module count for each suggestion.
3. **Usable as a library**, not only as a CLI. If it is CLI-only, say so and note whether
   subprocessing it is viable (stable machine-readable output, e.g. JSON).
4. **Licence must be permissive** (MIT / BSD / Apache-2.0). Report the licence. Flag AGPL/GPL
   explicitly — those are disqualifying for us.
5. **Maintenance must be real.** Report last commit date, release cadence, open-issue count,
   and whether a single maintainer is the bus factor. We rejected `robertkrimen/otto` partly
   for dormancy.
6. **Must fail loudly, never silently.** A library that returns an empty result where it
   should error is dangerous here — it would let "we could not test" masquerade as "no
   vulnerability". Note anything you spot with this shape.

---

## 6. Output format requested

A table, one row per recommendation:

| Module path | Purpose | Which gap (§ number) | cgo? | Transitive modules | Licence | Last commit | Maintenance notes | Verdict |
|---|---|---|---|---|---|---|---|---|

Then, for each recommendation you rate **strong**, add a short paragraph covering:
- the exact API entry points we would call;
- what it does *not* do, so we do not over-claim capability from it;
- any known correctness caveat or CVE history;
- whether it duplicates something in §3 and if so why it is better.

Finally, a short list of anything in §4 for which you found **no acceptable library**, so we
know those gaps are genuinely bespoke work rather than unsearched.

---

## 7. Things we already evaluated and rejected — do not re-suggest without new information

| Rejected | Reason |
|---|---|
| `robertkrimen/otto` | Dominated by goja: slower, ES5-only, dormant |
| `BishopFox/jsluice` | cgo tree-sitter |
| `pganalyze/pg_query_go` | cgo |
| `projectdiscovery/interactsh` as a library | ~100 transitive modules; we subprocess its CLI instead |
| `zmap/zgrab2` | Application, not a library |
| `esbuild` internal parser | `internal/` package, no stable API |
| `trufflehog` / `gitleaks` as libraries | Application-shaped; trufflehog verification makes live network calls. We would port rule *patterns* instead |
| `rod` | Not rejected on merit — we chose `chromedp` first. Only revisit with a concrete advantage |
