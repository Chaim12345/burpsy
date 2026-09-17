# OWASP Top 10 (2021) Coverage Analysis

**Which OWASP Top 10 categories do the 183 catalog rows cover, and how much is runtime-demonstrated rather than merely registered?**

This document is **derived, not asserted**: every issue name below was extracted from the 183-row catalog (`internal/scanner/catalog_data.go`), every TypeIndex cross-checked against it, every demonstrated row taken from the `Row:` strings the runtime harness actually asserts (`internal/vulnapp/*.go`), and every category assignment read from a code-verified mapping. A previous revision of this file named 19 issues that do not exist in the catalog and misprinted 12 of 15 sampled TypeIndexes; that revision was the defect class this project calls out in others — a partial result presented as complete — and this rewrite is the correction. Where this file and `docs/SCANNER-COVERAGE.md` both speak, SCANNER-COVERAGE is authoritative for the runtime split; this file adds only the OWASP axis.

## Mapping rationale (stated once)

Burp's catalog carries no OWASP tag, so every category assignment is a judgement. The mapping below was produced by reading each catalog row's own name, description and CWE references and picking the single OWASP category the check actually tests, not the category its side effects touch: "External service interaction (DNS)" is A10 SSRF because the check's subject is the server's outbound request; the four generated-issue rows ("BCheck/Extension/Manually/Bambda generated issue") are provenance placeholders, not vulnerabilities, and are counted as their own meta group so they never inflate a category. Rows no category fits without distortion would be unmapped; there are none — every row has a defensible home, though for a handful (the WebSocket URL-poisoning family, HTTP request smuggling, client-side desync) the home is A05 security misconfiguration by the "the flaw is in how the server handles the input" reading rather than A03's "the input becomes code" one. Disagreement with Burp's own taxonomy on such rows is expected; the mapping is reproducible from the names below.

## Category summary

| Category | Registered rows | Runtime-demonstrated | Registered-only |
|---|---:|---:|---:|
| A01: Broken Access Control | 43 | 38 | 5 |
| A02: Cryptographic Failures | 6 | 5 | 1 |
| A03: Injection | 56 | 51 | 5 |
| A04: Insecure Design | 0 | 0 | 0 |
| A05: Security Misconfiguration | 61 | 57 | 4 |
| A06: Vulnerable and Outdated Components | 1 | 1 | 0 |
| A07: Identification and Authentication Failures | 4 | 4 | 0 |
| A08: Software and Data Integrity Failures | 4 | 4 | 0 |
| A09: Security Logging and Monitoring Failures | 0 | 0 | 0 |
| A10: Server-Side Request Forgery | 4 | 0 | 4 |
| Meta (generated-issue provenance rows) | 4 | 0 | 4 |
| **Total** | **183** | **160** | **23** |

The 160/23 split is not this file's claim to defend: it is the runtime suite's, measured and pinned by `wantDemonstrated = 160` in `internal/scanner/runtime_coverage_test.go` (see `docs/SCANNER-COVERAGE.md`, "Runtime demonstration"). This file inherits it and distributes it across categories.

## A01: Broken Access Control (43 registered, 38 demonstrated, 5 registered-only)

CWE-284 improper access control and its path-traversal, CSRF-referenced and privilege cousins.

### Demonstrated (38 rows)

| Catalog Issue Name | TypeIndex |
|---|---:|
| Broken access control | 1050704 |
| Content security policy: allows clickjacking | 2098439 |
| Cookie manipulation (DOM-based) | 5245696 |
| Cookie manipulation (reflected DOM-based) | 5245697 |
| Cookie manipulation (stored DOM-based) | 5245698 |
| Cross-origin resource sharing | 2098688 |
| Cross-origin resource sharing: all subdomains trusted | 2098691 |
| Cross-origin resource sharing: arbitrary origin trusted | 2098689 |
| Cross-origin resource sharing: unencrypted origin trusted | 2098690 |
| Cross-site request forgery | 2098944 |
| Cross-site scripting (DOM-based) | 2097936 |
| Cross-site scripting (reflected DOM-based) | 2097937 |
| Cross-site scripting (reflected) | 2097920 |
| Cross-site scripting (stored DOM-based) | 2097938 |
| Cross-site scripting (stored) | 2097408 |
| File path manipulation | 1051392 |
| File path traversal | 1049344 |
| Form action hijacking (reflected) | 5248256 |
| Form action hijacking (stored) | 5248257 |
| Frameable response (potential Clickjacking) | 5245344 |
| HTML5 storage manipulation (DOM-based) | 5246720 |
| HTML5 storage manipulation (reflected DOM-based) | 5246721 |
| HTML5 storage manipulation (stored DOM-based) | 5246722 |
| HTML5 web message manipulation (DOM-based) | 5246464 |
| HTML5 web message manipulation (stored DOM-based) | 5246466 |
| Link manipulation (DOM-based) | 5246976 |
| Link manipulation (reflected DOM-based) | 5246977 |
| Link manipulation (reflected) | 5246979 |
| Link manipulation (stored DOM-based) | 5246978 |
| Link manipulation (stored) | 5246980 |
| Open redirection (DOM-based) | 5243152 |
| Open redirection (reflected DOM-based) | 5243153 |
| Open redirection (reflected) | 5243136 |
| Open redirection (stored) | 5243137 |
| Password returned in URL query string | 4195328 |
| Password returned in later response | 4194816 |
| Session token in URL | 5244672 |
| Web cache deception | 2098768 |

### Registered-only (5 rows)

A registered check descriptor exists; no deliberately vulnerable endpoint in the runtime corpus exercises it (the corpus's own `Row:` strings are the arbiter of demonstrated):

| Catalog Issue Name | TypeIndex |
|---|---:|
| HTML5 web message manipulation (reflected DOM-based) | 5246465 |
| Local file path manipulation (DOM-based) | 2098000 |
| Local file path manipulation (reflected DOM-based) | 2098001 |
| Local file path manipulation (stored DOM-based) | 2098002 |
| Open redirection (stored DOM-based) | 5243154 |

## A02: Cryptographic Failures (6 registered, 5 demonstrated, 1 registered-only)

CWE-310/327 cryptographic practice failures.

### Demonstrated (5 rows)

| Catalog Issue Name | TypeIndex |
|---|---:|
| Cacheable HTTPS response | 7340288 |
| Mixed content | 16778240 |
| Strict transport security not enforced | 16777984 |
| TLS cookie without secure flag set | 5243392 |
| Unencrypted communications | 16777728 |

### Registered-only (1 rows)

A registered check descriptor exists; no deliberately vulnerable endpoint in the runtime corpus exercises it (the corpus's own `Row:` strings are the arbiter of demonstrated):

| Catalog Issue Name | TypeIndex |
|---|---:|
| TLS certificate | 16777472 |

## A03: Injection (56 registered, 51 demonstrated, 5 registered-only)

CWE-74/78/79/89 injection families.

### Demonstrated (51 rows)

| Catalog Issue Name | TypeIndex |
|---|---:|
| Ajax request header manipulation (DOM-based) | 5245952 |
| Ajax request header manipulation (reflected DOM-based) | 5245953 |
| Ajax request header manipulation (stored DOM-based) | 5245954 |
| CSS injection (reflected) | 5247744 |
| CSS injection (stored) | 5247745 |
| Client-side HTTP parameter pollution (reflected) | 5248000 |
| Client-side HTTP parameter pollution (stored) | 5248001 |
| Client-side JSON injection (DOM-based) | 2098032 |
| Client-side JSON injection (reflected DOM-based) | 2098033 |
| Client-side JSON injection (stored DOM-based) | 2098034 |
| Client-side XPath injection (DOM-based) | 2098016 |
| Client-side XPath injection (reflected DOM-based) | 2098017 |
| Client-side XPath injection (stored DOM-based) | 2098018 |
| Client-side prototype pollution | 2097942 |
| Client-side template injection | 2097928 |
| DOM data manipulation (DOM-based) | 5247488 |
| DOM data manipulation (stored DOM-based) | 5247490 |
| Denial of service (DOM-based) | 5246208 |
| Denial of service (reflected DOM-based) | 5246209 |
| Denial of service (stored DOM-based) | 5246210 |
| Document domain manipulation (DOM-based) | 5247232 |
| Document domain manipulation (reflected DOM-based) | 5247233 |
| Document domain manipulation (stored DOM-based) | 5247234 |
| Expression Language injection | 1052448 |
| HTTP response header injection | 2097664 |
| Input returned in response (reflected) | 4197376 |
| Input returned in response (stored) | 4197120 |
| JavaScript injection (DOM-based) | 2097952 |
| JavaScript injection (reflected DOM-based) | 2097953 |
| JavaScript injection (stored DOM-based) | 2097954 |
| LDAP injection | 1049856 |
| OS command injection | 1048832 |
| PHP code injection | 1051648 |
| Path-relative style sheet import | 2097960 |
| Perl code injection | 1052160 |
| Python code injection | 1052432 |
| React Server Components remote code execution (React2Shell) | 1053184 |
| Ruby code injection | 1052416 |
| SQL injection | 1049088 |
| SQL injection (second order) | 1049104 |
| SQL statement in request parameter | 4195456 |
| SSI injection | 1052928 |
| Server-side JavaScript code injection | 1051904 |
| Server-side template injection | 1052800 |
| Suspicious input transformation (reflected) | 4197632 |
| Suspicious input transformation (stored) | 4197888 |
| Unidentified code injection | 1052672 |
| XML entity expansion | 4196096 |
| XML external entity injection | 1049600 |
| XML injection | 1050368 |
| XPath injection | 1050112 |

### Registered-only (5 rows)

A registered check descriptor exists; no deliberately vulnerable endpoint in the runtime corpus exercises it (the corpus's own `Row:` strings are the arbiter of demonstrated):

| Catalog Issue Name | TypeIndex |
|---|---:|
| Client-side SQL injection (DOM-based) | 2097968 |
| Client-side SQL injection (reflected DOM-based) | 2097969 |
| Client-side SQL injection (stored DOM-based) | 2097970 |
| DOM data manipulation (reflected DOM-based) | 5247489 |
| SMTP header injection | 2099200 |

## A04: Insecure Design (0 rows)

No catalog row maps to this category. CWE-209 informational disclosure patterns.

## A05: Security Misconfiguration (61 registered, 57 demonstrated, 4 registered-only)

CWE-16 configuration, headers, caching and deserialization exposure.

### Demonstrated (57 rows)

| Catalog Issue Name | TypeIndex |
|---|---:|
| ASP.NET ViewState without MAC enabled | 4195840 |
| ASP.NET debugging enabled | 1050624 |
| ASP.NET tracing enabled | 1049216 |
| Backup file | 6291672 |
| Base64-encoded data in parameter | 7340544 |
| Browser cross-site scripting filter disabled | 5245360 |
| Cleartext submission of password | 3145984 |
| Content security policy: allowlisted script resources | 2098435 |
| Content security policy: allows form hijacking | 2098440 |
| Content security policy: allows untrusted script execution | 2098436 |
| Content security policy: allows untrusted style execution | 2098437 |
| Content security policy: malformed syntax | 2098438 |
| Content security policy: not enforced | 2098441 |
| Content type incorrectly stated | 8389632 |
| Content type is not specified | 8389888 |
| Cookie without HttpOnly flag set | 5244416 |
| Credit card numbers disclosed | 6292736 |
| Cross-domain POST | 4195584 |
| Cross-domain Referer leakage | 5243904 |
| Cross-domain script include | 5244160 |
| Database connection string disclosed | 6291584 |
| Directory listing | 6291712 |
| Duplicate cookies set | 4196864 |
| Email addresses disclosed | 6291968 |
| Flash cross-domain policy | 2098176 |
| GraphQL content type not validated | 2098452 |
| GraphQL endpoint discovered | 2098449 |
| GraphQL endpoint found | 2098448 |
| GraphQL introspection enabled | 2098450 |
| GraphQL suggestions enabled | 2098451 |
| HTML does not specify charset | 8389120 |
| HTML uses unrecognized charset | 8389376 |
| HTTP PUT method is enabled | 1050880 |
| HTTP TRACE method is enabled | 5245440 |
| Json Web Key Set disclosed | 6293248 |
| Long redirection response | 4196352 |
| Multiple content types specified | 8388864 |
| OpenAPI definition found (active scan check) | 6293760 |
| OpenAPI definition found (passive scan check) | 6293761 |
| Password field with autocomplete enabled | 5244928 |
| Password submitted using GET method | 4195072 |
| Password value set in cookie | 5245184 |
| Private IP addresses disclosed | 6292224 |
| Private key disclosed | 6292816 |
| Referer-dependent response | 4194560 |
| Request URL override | 4198144 |
| Robots.txt file | 6292992 |
| Serialized object in HTTP message | 4196608 |
| Silverlight cross-domain policy | 2098432 |
| Social security numbers disclosed | 6292480 |
| Source code disclosure | 6291632 |
| Spoofable client IP address | 4194576 |
| User agent-dependent response | 4194592 |
| Web cache poisoning | 2097536 |
| WebSocket URL poisoning (DOM-based) | 2097984 |
| WebSocket URL poisoning (reflected DOM-based) | 2097985 |
| WebSocket URL poisoning (stored DOM-based) | 2097986 |

### Registered-only (4 rows)

A registered check descriptor exists; no deliberately vulnerable endpoint in the runtime corpus exercises it (the corpus's own `Row:` strings are the arbiter of demonstrated):

| Catalog Issue Name | TypeIndex |
|---|---:|
| Client-side desync | 2097473 |
| Cookie scoped to parent domain | 5243648 |
| HTTP request smuggling | 2097472 |
| Hidden HTTP 2 | 16778496 |

## A06: Vulnerable and Outdated Components (1 registered, 1 demonstrated, 0 registered-only)

CWE-1104 known-vulnerable dependencies.

### Demonstrated (1 rows)

| Catalog Issue Name | TypeIndex |
|---|---:|
| Vulnerable JavaScript dependency | 5243008 |

## A07: Identification and Authentication Failures (4 registered, 4 demonstrated, 0 registered-only)

CWE-287/347 JWT and token validation.

### Demonstrated (4 rows)

| Catalog Issue Name | TypeIndex |
|---|---:|
| JWT none algorithm supported | 2099457 |
| JWT private key disclosed | 6293504 |
| JWT signature not verified | 2099456 |
| JWT weak HMAC secret | 2099459 |

## A08: Software and Data Integrity Failures (4 registered, 4 demonstrated, 0 registered-only)

CWE-502/494 update and deserialization integrity.

### Demonstrated (4 rows)

| Catalog Issue Name | TypeIndex |
|---|---:|
| File upload functionality | 5245312 |
| JWT arbitrary jku header supported | 2099460 |
| JWT arbitrary x5u header supported | 2099461 |
| JWT self-signed JWK header supported | 2099458 |

## A09: Security Logging and Monitoring Failures (0 rows)

No catalog row maps to this category. CWE-778 logging failures.

## A10: Server-Side Request Forgery (4 registered, 0 demonstrated, 4 registered-only)

CWE-918 SSRF.

### Registered-only (4 rows)

A registered check descriptor exists; no deliberately vulnerable endpoint in the runtime corpus exercises it (the corpus's own `Row:` strings are the arbiter of demonstrated):

| Catalog Issue Name | TypeIndex |
|---|---:|
| External service interaction (DNS) | 3146240 |
| External service interaction (HTTP) | 3146256 |
| External service interaction (SMTP) | 3146272 |
| Out-of-band resource load (HTTP) | 1051136 |

## Meta: generated-issue provenance rows (4 rows, not OWASP-mappable)

These four rows are where a finding's origin is recorded when burpsy itself did not detect it — a BCheck run, an extension, a manual operator entry, a Bambda. They are catalog rows because Burp's issue model needs them, not because they are vulnerabilities:

| Catalog Issue Name | TypeIndex |
|---|---:|
| BCheck generated issue | 150994944 |
| Bambda generated issue | 151027712 |
| Extension generated issue | 134217728 |
| Manually generated issue | 134250496 |

## How to re-derive this file

```
1. Catalog:   TypeIndex + Name from internal/scanner/catalog_data.go (183 rows)
2. Demonstrated: the distinct `Row:` strings across internal/vulnapp/*.go (160)
3. Categories: read each row's name/description/CWEs; assign one OWASP category
4. Check: demonstrated + registered-only per category sums to the runtime pin
```

A mismatch in step 4 means this file drifted from the code and must be regenerated, not patched by hand.

