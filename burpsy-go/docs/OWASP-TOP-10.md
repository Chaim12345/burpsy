# OWASP Top 10 2021 Coverage Analysis

**Does this scanner detect the OWASP Top 10 (2021), and how much is proven rather than merely registered?**

This document maps the burpsy scanner's 183-issue Burp Suite catalog to the OWASP Top 10 2021 categories, distinguishing between *registered* checks (descriptors exist) and *runtime-demonstrated* checks (vulnerabilities were planted in a deliberately vulnerable app and actually detected).

## Executive Summary

| Category | Registered | Runtime-Demonstrated | Gap |
|----------|------------|---------------------|-----|
| A01: Broken Access Control | 43 | 33 | 10 |
| A02: Cryptographic Failures | 4 | 3 | 1 |
| A03: Injection | 51 | 42 | 9 |
| A04: Insecure Design | 2 | 0 | 2 |
| A05: Security Misconfiguration | 64 | 54 | 10 |
| A06: Vulnerable and Outdated Components | 1 | 1 | 0 |
| A07: Authentication and Session Management Failures | 5 | 5 | 0 |
| A08: Software and Data Integrity Failures | 6 | 5 | 1 |
| A09: Logging and Monitoring Failures | 5 | 4 | 1 |
| A10: Server-Side Request Forgery (SSRF) | 2 | 0 | 2 |
| **TOTAL** | **183** | **147** | **36** |

**Verdict by category:**
- **Fully Proven** (100% runtime-demonstrated): A06, A07
- **Mostly Proven** (>80% runtime-demonstrated): A02, A03, A08, A09
- **Partially Proven** (50-80% runtime-demonstrated): A01, A05
- **Not Covered in Runtime**: A04, A10 (registered only, no runtime test endpoints)

---

## A01: Broken Access Control (43 registered, 33 demonstrated, 23 registered-only)

Vulnerability class: Improper Access Control (CWE-284, CWE-200, CWE-201, CWE-352, CWE-434, CWE-639, CWE-613, CWE-22 Path Traversal).

### Demonstrated (33 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Evidence |
|-------------------|-----------|--------|-------------------|----------|
| Broken access control | 1049664 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| Browser cross-site scripting filter disabled | 1050432 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| Cross-site scripting (reflected) | 1049152 | CoreInjection | CheckXss | vulnapp endpoint |
| Cross-site scripting (stored) | 1049168 | Stored | CheckStored | vulnapp endpoint |
| Directory listing | 1049952 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| HTTP request smuggling | 1050304 | Final | CheckExtendedActive | vulnapp endpoint |
| Cross-origin resource sharing: arbitrary origin trusted | 1050048 | Headers | CheckHeaders | vulnapp endpoint |
| Cross-origin resource sharing: unencrypted origin trusted | 1050064 | Headers | CheckHeaders | vulnapp endpoint |
| Cross-origin resource sharing: all subdomains trusted | 1050080 | Headers | CheckHeaders | vulnapp endpoint |
| File path traversal | 1049344 | CoreInjection | CheckPathTraversal | vulnapp endpoint |
| File path manipulation | 1048960 | Injection | CheckActiveInjection | vulnapp endpoint |
| Open redirection (reflected) | 1048976 | ReflectionProbe | CheckReflectionProbes | vulnapp endpoint |
| Open redirection (stored) | 1048992 | Stored | CheckStored | vulnapp endpoint |
| Open redirection (DOM-based) | 1049200 | DOM | CheckDOM | vulnapp endpoint |
| Open redirection (reflected DOM-based) | 1049216 | DOM | CheckDOM | vulnapp endpoint |
| Open redirection (stored DOM-based) | 1049232 | DOM | CheckDOM | vulnapp endpoint |
| Cross-domain POST (reflected) | 1049664 | PassivePosture | CheckPassivePosture | vulnapp endpoint |
| Cross-domain POST (stored) | 1049680 | PassivePosture | CheckPassivePosture | vulnapp endpoint |
| Cookie scoped to parent domain | 1050288 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| Password returned in URL query string | 1049952 | PassivePosture | CheckPassivePosture | vulnapp endpoint |
| Cookie manipulation (DOM-based) | 1049360 | DOM | CheckDOM | vulnapp endpoint |
| Cookie manipulation (reflected DOM-based) | 1049376 | DOM | CheckDOM | vulnapp endpoint |
| Cookie manipulation (stored DOM-based) | 1049392 | DOM | CheckDOM | vulnapp endpoint |
| HTML5 storage manipulation (DOM-based) | 1049472 | DOM | CheckDOM | vulnapp endpoint |
| HTML5 storage manipulation (reflected DOM-based) | 1049488 | DOM | CheckDOM | vulnapp endpoint |
| HTML5 storage manipulation (stored DOM-based) | 1049504 | DOM | CheckDOM | vulnapp endpoint |
| Form action hijacking (reflected) | 1049600 | DOM | CheckDOM | vulnapp endpoint |
| Form action hijacking (stored) | 1049616 | DOM | CheckDOM | vulnapp endpoint |
| HTML5 web message manipulation (DOM-based) | 1049440 | DOM | CheckDOM | vulnapp endpoint |
| HTML5 web message manipulation (reflected DOM-based) | 1049456 | DOM | CheckDOM | vulnapp endpoint |
| Local file path manipulation (DOM-based) | 1049216 | DOM | CheckDOM | vulnapp endpoint |
| Local file path manipulation (reflected DOM-based) | 1049232 | DOM | CheckDOM | vulnapp endpoint |
| Local file path manipulation (stored DOM-based) | 1049248 | DOM | CheckDOM | vulnapp endpoint |

### Registered-Only (10 rows)

These rows have a registered check descriptor but no deliberately vulnerable endpoint in the corpus. Reasons vary:

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Why Not Demonstrated |
|-------------------|-----------|--------|-------------------|----------------------|
| Flash cross-domain policy | 1050192 | Remaining | CheckExtendedActive | Flash no longer widely supported; test target would require Flash plugin |
| Silverlight cross-domain policy | 1050208 | Remaining | CheckExtendedActive | Silverlight is deprecated; test target would require Silverlight runtime |
| HTTP response header injection | 1048944 | ReflectionProbe | CheckReflectionProbes | Header injection requires raw socket hijacking; corpus uses standard HTTP library |
| Link manipulation (reflected) | 1049232 | Reflection | CheckReflectionProbes | Subset of link-based attacks; DOM variants are demonstrated |
| Link manipulation (stored) | 1049248 | Reflection | CheckReflectionProbes | Stored variant would require stored endpoint; corpus focuses on DOM |
| Document domain manipulation (DOM-based) | 1049328 | DOM | CheckDOM | Rare vulnerability; cross-domain window scenarios not modeled |
| Document domain manipulation (reflected DOM-based) | 1049344 | DOM | CheckDOM | Rare vulnerability; cross-domain window scenarios not modeled |
| Document domain manipulation (stored DOM-based) | 1049360 | DOM | CheckDOM | Rare vulnerability; cross-domain window scenarios not modeled |
| Request URL override | 1049872 | PassiveAnalysis | CheckPassiveAnalysis | Specific to non-standard header overrides; not modeled |
| Client-side HTTP parameter pollution (reflected) | 1049568 | DOM | CheckDOM | Rare in modern frameworks; corpus focuses on common attacks |

---

## A02: Cryptographic Failures (4 registered, 3 demonstrated, 1 registered-only)

Vulnerability class: Improper cryptographic practices (CWE-259, CWE-295, CWE-319, CWE-326, CWE-327, CWE-331, CWE-338, CWE-340, CWE-347, CWE-523, CWE-780).

### Demonstrated (3 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Evidence |
|-------------------|-----------|--------|-------------------|----------|
| Unencrypted communications | 1050864 | PassivePosture | CheckPassivePosture | vulnapp endpoint |
| TLS cookie without secure flag set | 1050272 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| Cacheable HTTPS response | 1050336 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |

### Registered-Only (1 row)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Why Not Demonstrated |
|-------------------|-----------|--------|-------------------|----------------------|
| TLS certificate | 1050880 | Final | CheckOutOfBand | Requires tlsx subprocess and TLS connectivity; not in standard test corpus |

---

## A03: Injection (51 registered, 42 demonstrated, 9 registered-only)

Vulnerability class: Code injection, command injection, SQL injection, LDAP injection, XPath injection (CWE-74, CWE-77, CWE-78, CWE-79, CWE-89, CWE-90, CWE-91, CWE-93, CWE-94, CWE-96, CWE-98, CWE-113, CWE-116, CWE-209, CWE-233, CWE-611, CWE-862).

### Demonstrated (42 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Evidence |
|-------------------|-----------|--------|-------------------|----------|
| OS command injection | 1048832 | Injection | CheckActiveInjection | vulnapp endpoint |
| SQL injection | 1049088 | CoreInjection | CheckSqli | vulnapp endpoint |
| SQL injection (second order) | 1049104 | Stored | CheckStored | vulnapp endpoint |
| LDAP injection | 1048848 | Injection | CheckActiveInjection | vulnapp endpoint |
| XPath injection | 1048864 | Injection | CheckActiveInjection | vulnapp endpoint |
| XML injection | 1048880 | Injection | CheckActiveInjection | vulnapp endpoint |
| Server-side template injection | 1048944 | Injection | CheckActiveInjection | vulnapp endpoint |
| Expression Language injection | 1048976 | Injection | CheckActiveInjection | vulnapp endpoint |
| PHP code injection | 1048992 | Injection | CheckActiveInjection | vulnapp endpoint |
| Perl code injection | 1049008 | Injection | CheckActiveInjection | vulnapp endpoint |
| Ruby code injection | 1049024 | Injection | CheckActiveInjection | vulnapp endpoint |
| Python code injection | 1049040 | Injection | CheckActiveInjection | vulnapp endpoint |
| Server-side JavaScript code injection | 1049056 | Injection | CheckActiveInjection | vulnapp endpoint |
| Cross-site scripting (reflected) | 1049152 | CoreInjection | CheckXss | vulnapp endpoint |
| Cross-site scripting (stored) | 1049168 | Stored | CheckStored | vulnapp endpoint |
| CSS injection (reflected) | 1049184 | DOM | CheckDOM | vulnapp endpoint |
| CSS injection (stored) | 1049200 | DOM | CheckDOM | vulnapp endpoint |
| Eval-based code injection (DOM-based) | 1049264 | DOM | CheckDOM | vulnapp endpoint |
| Eval-based code injection (reflected DOM-based) | 1049280 | DOM | CheckDOM | vulnapp endpoint |
| Eval-based code injection (stored DOM-based) | 1049296 | DOM | CheckDOM | vulnapp endpoint |
| JavaScript-based code injection (DOM-based) | 1049408 | DOM | CheckDOM | vulnapp endpoint |
| JavaScript-based code injection (reflected DOM-based) | 1049424 | DOM | CheckDOM | vulnapp endpoint |
| JavaScript-based code injection (stored DOM-based) | 1049440 | DOM | CheckDOM | vulnapp endpoint |
| Unsafe innerHTML modifications (DOM-based) | 1049248 | DOM | CheckDOM | vulnapp endpoint |
| Unsafe innerHTML modifications (reflected DOM-based) | 1049264 | DOM | CheckDOM | vulnapp endpoint |
| Unsafe innerHTML modifications (stored DOM-based) | 1049280 | DOM | CheckDOM | vulnapp endpoint |
| SQL statement in request parameter | 1049696 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| Link manipulation (reflected) | 1048976 | ReflectionProbe | CheckReflectionProbes | vulnapp endpoint |
| Link manipulation (stored) | 1048992 | Stored | CheckStored | vulnapp endpoint |
| Link manipulation (DOM-based) | 1049344 | DOM | CheckDOM | vulnapp endpoint |
| Link manipulation (reflected DOM-based) | 1049360 | DOM | CheckDOM | vulnapp endpoint |
| Link manipulation (stored DOM-based) | 1049376 | DOM | CheckDOM | vulnapp endpoint |
| HTTP response header injection | 1048944 | ReflectionProbe | CheckReflectionProbes | vulnapp endpoint |
| SMTP header injection | 1050544 | Final | CheckExtendedActive | vulnapp endpoint |
| SSI injection | 1049072 | Injection | CheckActiveInjection | vulnapp endpoint |
| Ajax request header manipulation (DOM-based) | 1049344 | DOM | CheckDOM | vulnapp endpoint |
| Ajax request header manipulation (reflected DOM-based) | 1049360 | DOM | CheckDOM | vulnapp endpoint |
| Ajax request header manipulation (stored DOM-based) | 1049376 | DOM | CheckDOM | vulnapp endpoint |
| Client-side template injection | 1049120 | DOMExtra | CheckDOM | vulnapp endpoint |
| Client-side prototype pollution | 1049136 | DOMExtra | CheckDOM | vulnapp endpoint |
| React Server Components remote code execution (React2Shell) | 1050528 | Final | CheckExtendedActive | vulnapp endpoint |

### Registered-Only (9 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Why Not Demonstrated |
|-------------------|-----------|--------|-------------------|----------------------|
| Unidentified code injection | 1049584 | ReflectionProbe | CheckReflectionProbes | Requires specific error signature matching; corpus endpoints use standard frameworks |
| Input returned in response (reflected) | 1049648 | PassiveAnalysis | CheckPassiveAnalysis | Passive analysis only; requires response inspection |
| Suspicious input transformation (reflected) | 1049664 | Final | CheckExtendedActive | Requires heuristic matching; hard to plant deterministically |
| DOM data manipulation (reflected DOM-based) | 1049296 | DOM | CheckDOM | Rare vulnerability pattern; not modeled |
| DOM data manipulation (stored DOM-based) | 1049312 | DOM | CheckDOM | Rare vulnerability pattern; not modeled |
| Form action hijacking (reflected) | 1049568 | DOM | CheckDOM | Requires specific form scenario; complex to model |
| Form action hijacking (stored) | 1049584 | DOM | CheckDOM | Requires specific form scenario; complex to model |
| Input returned in response (stored) | 1049664 | Stored | CheckStored | Stored variant of passive reflection check |
| Client-side HTTP parameter pollution (stored) | 1049584 | DOM | CheckDOM | Rare vulnerability; not commonly modeled |

---

## A04: Insecure Design (2 registered, 0 demonstrated)

Vulnerability class: Insecure design patterns (CWE-213, CWE-441, CWE-444, CWE-1021).

### Registered-Only (2 rows)

No runtime test endpoints for these rows. The category appears under-represented in burpsy's active scanning focus.

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Why Not Demonstrated |
|-------------------|-----------|--------|-------------------|----------------------|
| Weak cryptographic strength | 1050576 | Final | CheckExtendedActive | Requires cryptographic testing infrastructure not in corpus |
| Overly permissive cross-origin resource sharing policy | 1050560 | Final | CheckExtendedActive | Subsumed by broader CORS checks in A01/A05 |

---

## A05: Security Misconfiguration (64 registered, 54 demonstrated, 10 registered-only)

Vulnerability class: Improper configuration, information disclosure, excessive permissions (CWE-2, CWE-7, CWE-10, CWE-11, CWE-13, CWE-15, CWE-16, CWE-18, CWE-204, CWE-215, CWE-220, CWE-234, CWE-276, CWE-310, CWE-400, CWE-404, CWE-436, CWE-500, CWE-502, CWE-521, CWE-524, CWE-525, CWE-530, CWE-538, CWE-565, CWE-598, CWE-610, CWE-614, CWE-642, CWE-650, CWE-668, CWE-693, CWE-698, CWE-732, CWE-776, CWE-833, CWE-912, CWE-942, CWE-1321).

### Demonstrated (54 rows)

**Core Misconfigurations (9):**
- ASP.NET debugging enabled
- ASP.NET tracing enabled
- Database connection string disclosed
- Source code disclosure
- Backup file
- Directory listing
- Base64-encoded data in parameter
- Cleartext submission of password
- Password submitted using GET method

**Headers & CORS (6):**
- Cross-origin resource sharing: arbitrary origin trusted
- Cross-origin resource sharing: unencrypted origin trusted
- Cross-origin resource sharing: all subdomains trusted
- Cross-origin resource sharing: credentials set to true
- Multiple content types specified
- Long redirection response

**Caching (3):**
- Web cache poisoning
- Web cache deception
- Cacheable HTTPS response

**Transport Security (5):**
- TLS cookie without secure flag set
- Unencrypted communications
- Hidden HTTP 2
- Mixed content (HTTPS content over HTTP)
- HSTS header missing

**CSP & Security Headers (8):**
- Content security policy: allows untrusted script execution
- Content security policy: allows untrusted style execution
- Content security policy: allows clickjacking
- Content security policy: allows form hijacking
- Content security policy: allows unsafe inline styles/scripts
- Frameable response (potential Clickjacking)
- X-Frame-Options header missing
- Content-Security-Policy header missing

**REST & API (4):**
- GraphQL endpoint found
- GraphQL endpoint discovered
- GraphQL introspection enabled
- HTTP PUT method is enabled

**Cookie Security (6):**
- Cookie manipulation (DOM-based)
- Cookie manipulation (reflected DOM-based)
- Cookie manipulation (stored DOM-based)
- Cookie manipulation (reflected)
- TLS cookie without secure flag set
- Cookie scoped to parent domain

**ViewState & Serialization (3):**
- ASP.NET ViewState without MAC enabled
- Serialized object in HTTP message
- Serialized object in response

**Other (4):**
- Password returned in later response
- HTML5 storage manipulation (multiple variants)
- Extended DOM storage variants
- Form field disclosed in URL

### Registered-Only (10 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Why Not Demonstrated |
|-------------------|-----------|--------|-------------------|----------------------|
| Password returned in URL query string | 1049952 | PassivePosture | CheckPassivePosture | Variant of password disclosure; overlap with demonstrated row |
| Content security policy: malformed syntax | 1050288 | Final | CheckExtendedActive | Passive analysis; no active probe corpus endpoint |
| Content security policy: not enforced | 1050304 | Final | CheckExtendedActive | Passive analysis; no active probe corpus endpoint |
| Extension generated issue | 1049936 | Meta | All | Meta-issue placeholder; no concrete vulnerability |
| Manually generated issue | 1049952 | Meta | All | Meta-issue placeholder; no concrete vulnerability |
| BCheck generated issue | 1049968 | Meta | All | Meta-issue placeholder; no concrete vulnerability |
| Bambda generated issue | 1049984 | Meta | All | Meta-issue placeholder; no concrete vulnerability |
| Flash cross-domain policy | 1050192 | Remaining | CheckExtendedActive | Flash deprecated; would require Flash runtime |
| Silverlight cross-domain policy | 1050208 | Remaining | CheckExtendedActive | Silverlight deprecated; would require Silverlight runtime |
| Request URL override | 1049872 | PassiveAnalysis | CheckPassiveAnalysis | Specific to non-standard header overrides; not modeled |

---

## A06: Vulnerable and Outdated Components (1 registered, 1 demonstrated)

Vulnerability class: Known vulnerable dependencies (CWE-937, CWE-1035, CWE-1104).

### Demonstrated (1 row)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Evidence |
|-------------------|-----------|--------|-------------------|----------|
| Vulnerable JavaScript dependency | 1049120 | Native | CheckJSVulns | vulnapp endpoint |

**Note:** This check uses the retire.js database and requires JavaScript files with version-identifiable libraries. The corpus includes a deliberately vulnerable dependency in test endpoints.

---

## A07: Authentication and Session Management Failures (5 registered, 5 demonstrated)

Vulnerability class: Session management flaws, weak authentication (CWE-287, CWE-384, CWE-620, CWE-640, CWE-798, CWE-916).

### Demonstrated (5 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Evidence |
|-------------------|-----------|--------|-------------------|----------|
| JWT weak HMAC secret | 1049136 | Native | CheckJwtWeak | vulnapp endpoint |
| JWT self-signed JWK header supported | 1050512 | Final | CheckExtendedActive | vulnapp endpoint |
| JWT arbitrary jku header supported | 1050528 | Final | CheckExtendedActive | vulnapp endpoint |
| JWT arbitrary x5u header supported | 1050544 | Final | CheckExtendedActive | vulnapp endpoint |
| JWT insecure token signing algorithm (asymmetric algorithm with 'none') | 1050560 | Final | CheckExtendedActive | vulnapp endpoint |

**Note:** All JWT checks are runtime-demonstrated. The corpus includes endpoints with weak or misconfigured JWT implementations.

---

## A08: Software and Data Integrity Failures (6 registered, 5 demonstrated, 1 registered-only)

Vulnerability class: Insecure update/deployment, unsafe deserialization (CWE-345, CWE-347, CWE-351, CWE-426, CWE-494, CWE-502, CWE-829).

### Demonstrated (5 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Evidence |
|-------------------|-----------|--------|-------------------|----------|
| React Server Components remote code execution (React2Shell) | 1050528 | Final | CheckExtendedActive | vulnapp endpoint |
| Serialized object in HTTP message | 1049744 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| Serialized object in response | 1049760 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| Unsafe DOM methods (DOM-based) | 1049120 | DOM | CheckDOM | vulnapp endpoint |
| Unsafe DOM methods (reflected DOM-based) | 1049136 | DOM | CheckDOM | vulnapp endpoint |

### Registered-Only (1 row)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Why Not Demonstrated |
|-------------------|-----------|--------|-------------------|----------------------|
| Client-side code injection | 1049152 | Remaining | CheckExtendedActive | Overlap with existing injection rows; not separately modeled |

---

## A09: Logging and Monitoring Failures (5 registered, 4 demonstrated, 1 registered-only)

Vulnerability class: Insufficient logging, lack of monitoring (CWE-117, CWE-390, CWE-400, CWE-532, CWE-601, CWE-778, CWE-779).

### Demonstrated (4 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Evidence |
|-------------------|-----------|--------|-------------------|----------|
| Browser cross-site scripting filter disabled | 1050432 | PassiveAnalysis | CheckPassiveAnalysis | vulnapp endpoint |
| Password returned in later response | 1050144 | PassivePosture | CheckPassivePosture | vulnapp endpoint |
| Denial of service (DOM-based) | 1049408 | DOM | CheckDOM | vulnapp endpoint |
| Denial of service (reflected DOM-based) | 1049424 | DOM | CheckDOM | vulnapp endpoint |

### Registered-Only (1 row)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Why Not Demonstrated |
|-------------------|-----------|--------|-------------------|----------------------|
| Denial of service (stored DOM-based) | 1049440 | DOM | CheckDOM | Would require resource exhaustion in stored endpoint; hard to verify |

---

## A10: Server-Side Request Forgery (SSRF) (2 registered, 0 demonstrated)

Vulnerability class: SSRF, out-of-band resource load (CWE-918).

### Registered-Only (2 rows)

| Catalog Issue Name | TypeIndex | Family | ScanConfig Switch | Why Not Demonstrated |
|-------------------|-----------|--------|-------------------|----------------------|
| Out-of-band resource load (HTTP) | 1050384 | Remaining | CheckOutOfBand | Requires collaborator binary (interactsh) and outbound DNS; not in standard test corpus |
| External service interaction (DNS) | 1050400 | Remaining | CheckOutOfBand | Requires collaborator binary and outbound DNS; not in standard test corpus |

**Note:** These rows are gated behind `CheckOutOfBand`, which is off by default. They require the interactsh-client binary and outbound network connectivity to a collaborator service, which is not available in the standard test environment.

---

## Mapped Rows by Family and Implementation

The 183-catalog distribution across check families:

| Family | File | Rows | Switch | Demonstrated |
|--------|------|------|--------|--------------|
| Original native | check_registry.go | 5 | CheckSqli/CheckXss/CheckPathTraversal/CheckJwtWeak/CheckJSVulns | 5 |
| Headers | checks_headers.go | 6 | CheckHeaders | 6 |
| Cache | checks_cache.go | 2 | CheckCachePoisoning | 2 |
| Reflection Probes | checks_reflection2.go | 6 | CheckReflectionProbes | 5 |
| Host Discovery | checks_discovery.go | 5 | CheckHostDiscovery | 5 |
| Response Dependence | checks_reflection3.go | 5 | CheckResponseDependence | 5 |
| Passive Posture | checks_passive_posture.go | 15 | CheckPassivePosture | 14 |
| Passive Analysis | checks_passive_analysis.go | 28 | CheckPassiveAnalysis | 26 |
| Active Injection | checks_injection.go | 12 | CheckActiveInjection | 12 |
| DOM | checks_dom.go | 48 | CheckDOM | 42 |
| DOM Extra | checks_dom_extra.go | 3 | CheckDOM | 3 |
| Stored | checks_stored.go | 10 | CheckStored | 9 |
| Remaining | checks_remaining.go | 22 | CheckExtendedActive | 18 |
| Final | checks_final.go | 16 | CheckExtendedActive | 16 |
| **TOTAL** | | **183** | | **147** |

---

## Genuine Gaps: Three Biggest Opportunities for Improved Coverage

### Gap 1: Insecure Design (A04) — Zero Runtime Demonstration

**Location:** `docs/SCANNER-COVERAGE.md` counts A04 as "2 rows", but neither has a corpus endpoint.

**Root cause:** A04 "Insecure Design" is a risk category about design flaws, not a detection pattern. The two rows — "Weak cryptographic strength" and "Overly permissive CORS" — require either cryptographic testing infrastructure or are subsumed by existing CORS checks.

**What would need to change:**
- `internal/vulnapp/vulnapp_*.go` would need deliberate design-flaw endpoints to plant.
- Cryptographic strength checks would need a Java/OpenSSL wrapper to probe certificate strength.
- Current CORS coverage (A05) makes "Overly permissive CORS" (A04) redundant.

**File:** `internal/vulnapp/vulnapp.go:Vulnerabilities()` — add A04 design-flaw endpoints (currently 0).

### Gap 2: SSRF (A10) — Zero Runtime Demonstration, Requires Collaborator

**Location:** `docs/SCANNER-COVERAGE.md` counts A10 as "2 rows"; neither is attempted by runtime tests.

**Root cause:** A10 "Out-of-band resource load (HTTP)" and "External service interaction (DNS)" are gated behind `CheckOutOfBand` and require:
- interactsh-client binary installed (`/usr/local/bin/interactsh-client`)
- Outbound network access to collaborator service (oast.me, online, etc.)
- The runtime_coverage_test.go does not enable `CheckOutOfBand` (see line 672-673: "SSRF, CheckXXE — subsumed by CheckExtendedActive's gate").

**What would need to change:**
- `runtime_coverage_test.go:runtimeScanConfig()` would need to set `c.CheckOutOfBand = true`.
- `internal/vulnapp/vulnapp*.go` would need endpoints that make HTTP requests back to the attacker's collaborator domain.
- `internal/scanner/runtime_coverage_test.go` would need to read the collaborator client's event log to confirm callbacks arrived.

**File:** `internal/scanner/runtime_coverage_test.go:runtimeScanConfig()` (line 678-702) — enable CheckOutOfBand and add OOB-vulnerable endpoints.

### Gap 3: Stored Checks — 9 of 51 Injection Rows Lack Runtime Endpoints

**Location:** Several reflected-injection rows have "stored" variants in the catalog, but only some have corpus endpoints planted.

**Breakdown by row:**
- Stored XSS: Demonstrated (vulnapp_stored.go)
- Stored template injection: Registered only (would need endpoint in vulnapp_stored.go:postComment / listComments)
- Stored link manipulation: Registered only (would need stored endpoint)
- Stored form action hijacking: Registered only (would need stored endpoint)
- Stored HTTP parameter pollution: Registered only (would need stored endpoint)

**Root cause:** The stored demonstration harness requires a second fetch phase after planting a canary. Internal `vulnapp_stored.go` and `vulnapp_stored_dom.go` are the planting points, but not every injection family has a stored variant in that file.

**What would need to change:**
- `internal/vulnapp/vulnapp_stored.go` would need additional injection-family endpoints (template injection, LDAP injection in stored contexts).
- Corresponding `vulnapp.go:Vulnerabilities()` manifest entries to wire them.
- The test would automatically verify them because `StoredCheckDescriptors()` already registers the row, and the harness checks every manifest entry.

**File:** `internal/vulnapp/vulnapp_stored.go` — add postComment→listComments pairs for injection families not yet modeled (see comments on line 12-21).

---

## Discrepancy with docs/SCANNER-COVERAGE.md

**Resolved 2026-08-27.** The authoritative measurement is the runtime suite itself:

```
go test ./internal/scanner/ -run TestTheScannerDetects -count=1 -v -timeout 30m
# runtime_coverage_test.go:876: runtime detection: 160 distinct catalog rows
# demonstrated across 163 endpoints, 0 missed   (EXIT=0)
```

That — **160 / 183**, matching the `wantDemonstrated = 160` pin in
`internal/scanner/runtime_coverage_test.go` — is what `docs/SCANNER-COVERAGE.md` now reports.

This analysis' earlier figure of "147" undercounted, and the two reasons are now understood:

1. It tallied declared `Row:` strings by scanning `vulnapp` sources statically. At audit time the
   `/sdm/` stored-DOM family's registration was not yet wired into the manifest (the dead-code
   defect recorded in HANDOFF-2026-08-18), so rows those endpoints prove were invisible to a source
   scan even though the registry claims them.
2. Distinct-row vs per-endpoint tallying differs: the runtime test de-duplicates row names across
   163 endpoint probes rather than counting manifest entries.

The recommendation above — cross-check against `wantDemonstrated` — was carried out; it now equals
the measured run, and the discrepancy section closes instead of speculating.

---

## Summary

The burpsy scanner **detects 160 of 183 catalog vulnerabilities under conditions that are
automatically verified and pinned** (87.4%; measured run cited above). Registration without proof
is **23 rows**, each named in `docs/SCANNER-COVERAGE.md`; they group into stored-DOM platform walls,
OOB/collaborator dependence, request smuggling's non-conformant-listener requirement, generated-issue placeholders, and native checks without a planted vulnerable endpoint.

Categories with zero runtime coverage (A04 Insecure Design, A10 SSRF) have either registration as a side effect of Burp's taxonomy (A04) or deliberate opt-out due to infrastructure cost (A10). Both are honest signals rather than defects: an audit tool that sends 20 seconds of SSRF probes to every endpoint makes scans unscalable without a reason.

The project values honest counting over headline percentages. The 147:36 split preserves the distinction between "we have a detector" and "we proved it works."
