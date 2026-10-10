# Scanner detection gaps — 2026-10-10

Research of the scanner (code, catalogue, beads, gaps docs) against sqlmap and modern web-scanner
coverage (PortSwigger research 2023–2026, OWASP WSTG / API Top 10, nuclei). All 183 rows of Burp's
catalogue are registered (`docs/SCANNER-COVERAGE.md`), so the gaps are classes with **no row** and
rows that cover only the **oldest variant**. Two epics: `v0ei` (SQL injection) and `0vzb`
(everything else). Labels: `sqli`, `detection-gap`.

## SQL injection (epic v0ei)

Today (`scanner/checks_core_injection.go`, `sqli_techniques.go`, `infra_injection_payloads.go`):
6 error probes against 40 error signatures recovered from Burp; one boolean true/false pair family;
time delays for **PostgreSQL and SQL Server only** (Burp's MySQL/Oracle timing payloads were not
recoverable and the policy was to send only recovered payloads — the owner has lifted that);
second-order SQLi exists (`checks_stored.go`). No OOB, UNION, stacked, NoSQL or sqlmap hand-off.

| Bead | Gap | P |
|---|---|---|
| v0ei.1 | MySQL/MariaDB, Oracle, SQLite, DB2 time-delay probes with multi-delay statistical confirmation | 1 |
| v0ei.2 | burpsy-authored DBMS + driver/ORM error-signature bank; report the identified DBMS | 1 |
| v0ei.3 | Out-of-band SQLi via the OOB channel (xp_dirtree, UTL_INADDR/UTL_HTTP, LOAD_FILE UNC, COPY/dblink) | 1 |
| v0ei.4 | Robust boolean detection: similarity ratio with dynamic-content removal, more condition shapes, ORDER BY/LIKE/IN/JSON contexts | 2 |
| v0ei.5 | UNION column-count and stacked-query detection (evidence only, no extraction) | 2 |
| v0ei.6 | NoSQL injection (Mongo operators, `$where`, JSON/query-string operators, error signatures) | 2 |
| v0ei.7 | sqlmap hand-off from Repeater/issues as an extscan tool (`-r` request file, `--batch`, pre-filled param/DBMS/technique, scope enforced, traffic through the proxy; optional sqlmapapi) | 2 |
| v0ei.8 | Opt-in WAF-evasion variants (comments, case, encodings, JSON-SQL syntax) | 3 |

**Licence: decided 2026-10-10 — burpsy is GPL-3.0-or-later** (`LICENSE`). sqlmap is GPL-2.0-or-later
("version 2 (or later)" with clarifications), so burpsy may read and embed sqlmap's data files
(`xml/errors.xml`, `xml/payloads/*.xml`, `xml/boundaries.xml`, `xml/queries.xml`) and execute sqlmap
and parse its results. Keep sqlmap's copyright notices with any embedded data, and record what was
taken and from which sqlmap version. The Go dependencies (MIT/BSD/Apache-2.0) are GPL-3 compatible.

## Other classes (epic 0vzb)

| Bead | Gap | Status today | P |
|---|---|---|---|
| 0vzb.1 | Request smuggling: CL.0, client-side desync, TE.0/chunk-ext, 0.CL/Expect, then H2.CL/H2.TE | one CL.TE + TE.CL pipelined pair, "not a confirmed desync" | 1 |
| 0vzb.2 | Cache poisoning/deception: more unkeyed inputs; 2024 delimiter/normalisation deception | 3 headers, 1 suffix | 1 |
| 0vzb.3 | Server-side prototype pollution (json spaces / status techniques) | absent | 1 |
| 0vzb.4 | Path traversal encodings and `..;/` normalisation bypasses | 4 payloads | 1 |
| 0vzb.5 | Host-header attacks, routing SSRF, reset poisoning (opt-in) | absent | 1 |
| 0vzb.6 | Cloud-metadata SSRF (in-band), redirect and rebinding variants | OOB only | 1 |
| 0vzb.7 | JWT `kid` injection; alg-confusion as a real row | partial | 1 |
| 0vzb.8 | Race conditions (single-packet), opt-in | Repeater only | 2 |
| 0vzb.9 | OAuth/OIDC misconfiguration | absent | 2 |
| 0vzb.10 | Active DNS-only deserialization probes | passive only | 2 |
| 0vzb.11 | CSWSH | absent | 2 |
| 0vzb.12 | BOLA/BFLA/mass assignment in the scan | separate tool | 2 |
| 0vzb.13 | GraphQL batching/alias, GET/CSRF | partial | 2 |
| 0vzb.14 | Spoofable client IP, active | passive only | 2 |
| 0vzb.15 | File upload exploitation | passive only | 2 |
| 0vzb.21 | Bundle a curated BCheck corpus by default | needs `-bchecks DIR` | 2 |
| 0vzb.16 | CRLF payload depth | unverified | 3 |
| 0vzb.17 | Subdomain takeover | absent | 3 |
| 0vzb.18 | LLM / prompt injection | absent | 3 |
| 0vzb.19 | Cookie prefixes / tossing | absent | 3 |
| 0vzb.20 | Passive ReDoS, timing enumeration | absent | 3 |

Already tracked elsewhere: client-side prototype-pollution gadgets (c67v), DOM clobbering (7beu),
postMessage (k13f, wl94), normalisation tell (r78q), BCheck collaborator coverage (s70o).

## Sources

- sqlmap: [techniques and options](https://terminal.guide/linux/security-tools/sqlmap),
  [REST API](https://ohotnik.duckdns.org/sqlmapproject/sqlmap/wiki/REST-API),
  [FAQ/licence](https://github.com/sqlmapproject/sqlmap/wiki/faq),
  [licence clarifications (Debian)](https://metadata.ftp-master.debian.org/changelogs/main/s/sqlmap/stable_copyright)
- OOB SQLi: [pentest.blog](https://pentest.blog/data-ex-filtration-with-dns-in-sqli-attacks/),
  [Invicti](https://www.invicti.com/learn/out-of-band-sql-injection-oob-sqli)
- PortSwigger: [desync](https://portswigger.net/research/browser-powered-desync-attacks),
  [HTTP/1.1 must die](https://portswigger.net/research/http1-must-die),
  [cache deception](https://portswigger.net/research/gotta-cache-em-all),
  [SSPP](https://portswigger.net/research/server-side-prototype-pollution),
  [race conditions](https://portswigger.net/research/smashing-the-state-machine),
  [Web Security Academy](https://portswigger.net/web-security) (traversal, host header, SSRF, JWT,
  OAuth, deserialization, WebSockets, GraphQL, file upload, NoSQL, LLM attacks)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/),
  [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/),
  [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
