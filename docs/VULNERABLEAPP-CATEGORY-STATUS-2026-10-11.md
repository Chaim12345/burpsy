# VulnerableApp category status — 2026-10-11

Per-category detection status against OWASP VulnerableApp, measured with `scripts/bench/run_vulnapp.py
--full-profile` (every check family on except DOM/corpus) on the live target.

## Score

| Run | TP | FN | TN | FP | strict |
|---|---|---|---|---|---|
| original hand-run baseline (master) | 19 | 128 | 21 | 0 | 12.9% |
| harness, default profile (a harness bug) | 7 | 134 | 21 | 0 | 4.3% |
| harness, true full profile | 26 | 115 | 21 | 0 | 16.0% |
| + path traversal fix (`j1mk.35`) | — | — | — | — | 16.0% → path traversal 12/15 |
| + JWT carrier fix (`j1mk.7`) | 32 | 109 | 21 | 0 | **19.8%** |

`0 FP` is still an artefact of CWE matching hiding off-target findings; precision is not yet measured.

## Categories that detect

| Category | TP/FN | Note |
|---|---|---|
| BLIND_SQL_INJECTION | 2/0 | complete |
| UNION_BASED_SQL_INJECTION | 2/0 | complete |
| ERROR_BASED_SQL_INJECTION | 2/3 | levels 3–4 missed (j1mk.36) |
| OPEN_REDIRECT_3XX_STATUS_CODE | 7/1 | one level missed (j1mk.36) |
| PATH_TRAVERSAL | 12/3 | was 0/15; fixed (j1mk.35) |
| **SERVER_SIDE_VULNERABLE_JWT** | **6/0** | **was 0/6; fixed (j1mk.7)** |
| PASSWORD_RESET_TOKEN_EXPOSED_VIA_REFERRER | 1/0 | |

## Categories that do not detect, and why

Three distinct causes. Only the first is a scanner defect.

### 1. Reachable, not yet detected — scanner work

| Category | FN | Cause |
|---|---|---|
| REFLECTED_XSS / PERSISTENT_XSS | 18 / 13 | the endpoints answer `text/plain` and the page's own JS writes the body with `innerHTML`, so the reflected markup never appears in the HTTP response. These are DOM-only (j1mk.38): scoring them needs the DOM engine driving the app's HTML templates, not an audit of the API exchange. |
| CLIENT_SIDE_VULNERABLE_JWT | 10 | token leak to the client and cookie security attributes (CWE-522) — a different class from the forgery checks, which now cover SERVER_SIDE. No check exists. |
| INSECURE_CONFIGURATION_JWT | 3 | alg confusion / expired / `kid` handling (CWE-1188); `ForgeAlgConfusion` exists but is not wired to a row (0vzb.7). |
| UNRESTRICTED_FILE_UPLOAD | 7 | active upload checks absent (0vzb.15) |
| LDAP_INJECTION | 4 | check exists but does not confirm on these levels |
| INSECURE_DIRECT_OBJECT_REFERENCE | 4 | no IDOR check (0vzb.12) |
| SIMPLE_SSRF | 4 | in-band metadata SSRF absent (0vzb.6) |
| WEB_CACHE_POISONING | 4 | shallow unkeyed-input set (0vzb.2) |
| HEADER_INJECTION | 1 | depth unverified (0vzb.16) |
| REMOTE_CODE_EXECUTION | 1 | — |
| DENIAL_OF_SERVICE / UNCONTROLLED_RESOURCE_CONSUMPTION | 1 / 1 | passive only (0vzb.20) |

### 2. Logic classes with no active check — scanner work, larger

`CLICKJACKING` (5), `NO_LOGIN_RATE_LIMITING` (6), the password-reset token family (7),
`SESSION_FIXATION`/`PREDICTABLE_SESSION_ID`/`MISSING_LOGOUT_INVALIDATION` (3), `USERNAME_ENUMERATION`
(2), `WEAK_PASSWORD_HASHING` (5), `PLAINTEXT_PASSWORD_STORAGE` (2), `WEAK_CRYPTOGRAPHIC_HASH` (5),
`USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM` (3), `INSECURE_CRYPTOGRAPHIC_STORAGE` (2),
`WEAK_RANDOM_NUMBER_GENERATION` (3), `INSECURE_DESERIALIZATION` (3), `IMPROPER_AUTHORIZATION` (1).

These are behavioural/logic checks (does the app rate-limit logins, is the reset token reusable,
is the session id rotated on login). Some are cheap passive observations; others are multi-request
state machines. Grouped under `0vzb` and the reference-parity rows.

## Biggest levers, in order

1. **DOM engine for the XSS families (31 FN).** A harness change plus the DOM check family against
   the app's HTML templates, not the API exchange.
2. **Logic classes (34 FN).** New checks, each its own bead.
3. **CLIENT_SIDE_JWT (10)** and **INSECURE_CONFIGURATION_JWT (3)** — token-leak detection and
   wiring the existing `ForgeAlgConfusion`/`kid` to a row (0vzb.7).
4. **File upload (7 FN)**, **SSRF metadata (4)**, **cache poisoning (4)**, **IDOR (4)** — the `0vzb`
   active-check rows.

## Reproducing

```bash
docker run --rm -p 9090:9090 sasanlabs/owasp-vulnerableapp:latest
/tmp/burpsy -db /tmp/bsy.db -proxy 127.0.0.1:18080 -web 127.0.0.1:18081 -scope-include 127.0.0.1
python3 scripts/bench/run_vulnapp.py --full-profile --out /tmp/bench
python3 scripts/bench/explain_case.py --full-profile PathTraversal/LEVEL_8   # one case, in detail
```

