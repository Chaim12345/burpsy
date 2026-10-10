# Reference-tool parity — 2026-10-10

Each vulnerability class gets an industry-standard reference tool used as the comparison and
validation oracle for burpsy's scanner: run both on the same targets, diff the findings, and turn
every reference-only hit into a burpsy gap (or a delegated case) and every burpsy-only hit into a
verified true positive or a false-positive fix. Epic `j1mk`, label `reference-parity`. Reference
tools run as external processes; GPL tools are fine now that burpsy is GPL-3.0-or-later. Check each
tool's maintenance status and pin a version when its bead starts.

## Harness (j1mk.1)

Targets: burpsy's `internal/vulnapp` (declares what each endpoint is vulnerable to), OWASP Benchmark
(21k labelled cases, about half deliberately not vulnerable), reinforced WAVSEP, DVWA, OWASP Juice
Shop, and per-class lab containers. Normalise findings to (endpoint, parameter, class, technique);
report both / reference-only / burpsy-only plus precision and recall; nightly, under
`scripts/capped-run.sh`, pinned and hash-checked tools.

## Class → reference tool

| Bead | Class and reference | P |
|---|---|---|
| j1mk.2 | SQL injection vs sqlmap (and ghauri) | 1 |
| j1mk.3 | reflected and stored XSS vs dalfox (and XSStrike) | 1 |
| j1mk.4 | DOM XSS / client-side sources and sinks vs DOM Invader and domdig | 2 |
| j1mk.5 | OS command injection vs commix | 1 |
| j1mk.6 | server-side template injection vs SSTImap | 1 |
| j1mk.7 | NoSQL injection vs nosqli / NoSQLMap | 2 |
| j1mk.8 | XXE vs XXEinjector (and manual OOB XXE) | 2 |
| j1mk.9 | SSRF vs SSRFmap with interactsh | 1 |
| j1mk.10 | path traversal / LFI vs dotdotpwn (and ffuf traversal wordlists) | 1 |
| j1mk.11 | HTTP request smuggling vs smuggler and Burp's HTTP Request Smuggler | 1 |
| j1mk.12 | web cache poisoning/deception vs Web Cache Vulnerability Scanner (WCVS) and Param Miner | 1 |
| j1mk.13 | hidden parameter discovery vs Arjun and x8 | 2 |
| j1mk.14 | CORS misconfiguration vs Corsy | 2 |
| j1mk.15 | CRLF / header injection vs crlfuzz | 2 |
| j1mk.16 | open redirect vs OpenRedireX / Oralyzer | 2 |
| j1mk.17 | JWT attacks vs jwt_tool | 1 |
| j1mk.18 | GraphQL vs graphql-cop (CI checks) and InQL (manual) | 2 |
| j1mk.19 | insecure deserialization vs ysoserial / ysoserial.net (DNS-only gadgets) | 2 |
| j1mk.20 | server-side prototype pollution vs PortSwigger's SSPP scanner technique | 2 |
| j1mk.21 | client-side prototype pollution vs ppmap / ppfuzz | 2 |
| j1mk.22 | race conditions vs Turbo Intruder (single-packet) and h2spacex | 2 |
| j1mk.23 | known CVEs, exposures and misconfiguration vs nuclei (already integrated) and nikto | 2 |
| j1mk.24 | TLS/SSL configuration vs testssl.sh and sslyze | 2 |
| j1mk.25 | secrets in responses/JS vs gitleaks and trufflehog | 2 |
| j1mk.26 | content discovery vs ffuf and feroxbuster | 2 |
| j1mk.27 | crawler coverage vs ZAP spider/AJAX spider and katana | 2 |
| j1mk.28 | whole-scanner baseline vs OWASP ZAP active scan | 2 |
| j1mk.29 | subdomain takeover vs nuclei takeover templates and subjack | 3 |
| j1mk.30 | LLM / prompt injection vs garak and promptfoo red-team | 3 |
| j1mk.31 | OAuth/OIDC and host-header classes — no single standard tool; use PortSwigger labs-style containers + nuclei templates | 3 |

Gap epics these feed: `v0ei` (SQL injection), `0vzb` (other classes).

## Sources

- [OWASP WSTG: SSTI (SSTImap as tplmap's maintained successor)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection_Testing/18-Testing_for_Server-side_Template_Injection)
- [graphql-cop / InQL comparison](https://escape.tech/blog/best-graphql-security-tools/), [graphql-cop](https://hub.docker.com/r/dolevf/graphql-cop)
- [OWASP Benchmark design](https://contrastsecurity.com/hubfs/DocumentsPDF/WPtechbriefbenchmark0117.pdf?hsLang=en), [ZAP/Arachni/Wapiti on reinforced WAVSEP](https://ruor.uottawa.ca/bitstreams/11add7f9-dd00-4e35-bc44-ac1f68a2fc94/download), [DAST precision study](https://arxiv.org/pdf/2208.01595)
- [sqlmap licence (GPL-2+)](https://metadata.ftp-master.debian.org/changelogs/main/s/sqlmap/stable_copyright)
