# Juice Shop benchmark: burpsy vs OWASP ZAP (2026-10-10)

A behavioural test, not a parity count: both scanners pointed at the same deliberately vulnerable
application, and the question is which real vulnerabilities each one reports. Target: OWASP Juice
Shop (`bkimminich/juice-shop:latest`, SQLite-backed). burpsy built from master at `f4cde23`;
ZAP 2.17.0 (`ghcr.io/zaproxy/zaproxy:stable`).

## How it was run

| Run | Command / API | Notes |
|---|---|---|
| ZAP | `zap-full-scan.py -t http://127.0.0.1:3000 -j -m 10` | AJAX spider on. The DOM XSS rule (40026) was skipped by hand after 18 min stuck at 99%; burpsy's DOM checks were also off (`dom_checks: false`), so the comparison is like for like. |
| burpsy crawl and audit | `POST /api/crawl` `{"kind":"crawl-audit","submit_forms":true,"request_speculative":true}` | Ran concurrently with ZAP in the first pass; that load explains the probe timeouts below. |
| burpsy seeded audit | the three known-vulnerable requests sent through the proxy, then `POST /api/audit/{id}` | Quiet target, no concurrent scanner. This isolates detection from crawling. |

## Results

| Vulnerability | ZAP | burpsy crawl and audit | burpsy seeded (master) | burpsy seeded (this fix) |
|---|---|---|---|---|
| SQL injection, `GET /rest/products/search?q=` | **High** | not reached | **missed** | **High, Firm** — "introduced SQLITE_ERROR" |
| SQL injection, `POST /rest/user/login` (JSON `email`) | missed | not reached | missed | missed |
| Open redirect, `GET /redirect?to=` | **High** | not reached | missed | missed |
| Application error / debug message disclosure | Medium / Low | partial | – | – |
| Sensitive data in responses (emails, password hashes, card numbers) | partial | **better than ZAP** | – | – |

The search injection is trivially real: `q='))` returns a 500 page titled
`SQLITE_ERROR: near ")": syntax error`, and `q=xyz')) OR 1=1--` returns all 56 products.

On master, the seeded audit of that exact request ran all 58 checks and reported
`"4 found, and nothing was skipped, errored or gated"` — every dispositional counter at zero,
`complete: true`. A full audit of a textbook injection said clean.

## Findings

### F1 — No SQLite error signatures (fixed in this change, `burpsy-react-ui-71rs`)

`SQLErrorSignatures` (`burpsy-go/internal/scanner/infra_injection_payloads.go`) was recovered from
Burp's `Ze2s` and covers Oracle, MySQL, MSSQL, PostgreSQL, Access, DB2 and Informix. It had no
SQLite wording, so the error-message technique saw no evidence in Juice Shop's error page, and the
boolean/timing techniques did not fire on a `LIKE '%…%'` clause either.

Fix: add `SQLITE_ERROR`, `SQL logic error` (`sqlite3_errstr(SQLITE_ERROR)`, which
modernc.org/sqlite and others print), `SQLiteException`, `sqlite3.OperationalError`,
`SQLite3::SQLException` and `unrecognized token:`. `ClassifyErrorEvidence` still requires the
signature to be absent from the baseline, so the broader entries cannot fire on a page that merely
mentions SQLite.

Regression tests (`internal/scanner/sqli_sqlite_test.go`) run Juice Shop's query shape against a
real in-memory SQLite database through a full `AuditSession`, with a parameterized twin as the
negative control. Both the end-to-end test and the classifier test fail on master and pass with
the fix.

### F2 — Failed probes still label an item "Audited" (open, `burpsy-react-ui-8dnu`)

During the crawl and audit, SQL injection and reflected XSS probes on `/api/Hints`,
`/rest/memories` and one more item failed with `no baseline response: … i/o timeout`. The audit
items recorded `send_failures: 2` and `unit_abandoned: 4`, yet each showed
`status_label: "Audited"`. The timeouts were induced by ZAP's concurrent load, but the labelling is
burpsy's: this is the "reports success for work it did not do" class from
`BURP_PARITY_GAP_ANALYSIS.md` §1, still live.

### F3 — The crawler gives an SPA's audit nothing to inject into (open, `burpsy-react-ui-8e0q`)

The crawler read Juice Shop's JavaScript well (146 locations, 140 fetches), but every discovered
API URL is a bare GET with no parameters, and no form was found (`forms_found: 0`). The crawl and
audit therefore never reached `search?q=` or the login body. The crawl did find the OpenAPI
definition (`/api-docs/swagger-ui-init.js`, reported as Informational); using it to seed
parameterized requests is the obvious lever.

### F4 — Login SQL injection in a JSON body is missed (open, `burpsy-react-ui-g6nt`)

Juice Shop's login answers `email: "x'"` with a bare `<title>Error</title>` (no database text), so
only a blind technique can see it, and `' OR 1=1--` flips 401 to 200. The audit item reports
`points_judged_ineffective: 10` and no finding. Either the JSON-body points were judged out before
the boolean technique ran, or the boolean technique does not treat a 401→200 flip as a
differential. Needs investigation; ZAP misses this one too.

### F5 — Open redirect not detected (open, `burpsy-react-ui-bo04`)

`/redirect?to=https://…` returns a 302 to the attacker-chosen host. ZAP reports it High. burpsy
reported nothing on the seeded request. Its check (`checkOpenRedirect`,
`internal/scanner/checks_reflection2.go`) replaces the value with `http://a<token>/` and its
bypass variants, which Juice Shop's allow-list rejects: the allow-list only asks that the URL
*contain* an allowed string. ZAP's winning payload kept the original value as a suffix
(`…?https://github.com/juice-shop/juice-shop`). A variant that carries the base value in the path
or query would catch this whole class of substring allow-list.

### F6 — `/api/issues` returns `issue_name: null` for every finding (open, minor, `burpsy-react-ui-p5wt`)

The field is documented as "the human title" (`internal/web/api_capture.go`, `issueFindingView`),
but all 375 findings in the crawl run carried `null`; consumers have to fall back to `check_name`.

## Test-environment notes

- Juice Shop and ZAP ran in Docker with `--network host`; the session's `NO_PROXY` covers
  `127.0.0.1`, so `curl -x` needs `--noproxy ''` to actually traverse burpsy's proxy.
- The scanner suite needs Chrome on `PATH` (Playwright's Chromium works); `internal/web`'s
  `TestDiscoveryCapabilityWasExercised` needs `ffuf`. Without them those tests fail on master too.
