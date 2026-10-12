# VulnerableApp category status — 2026-10-11

Per-category detection status against OWASP VulnerableApp, measured with `scripts/bench/run_vulnapp.py
--full-profile` (every check family on except DOM/corpus) on the live target.

## Score

| Run | TP | FN | TN | FP | strict |
|---|---|---|---|---|---|
| original hand-run baseline (master) | 19 | 128 | 21 | 0 | 12.9% |
| harness, default profile (a harness bug) | 7 | 134 | 21 | 0 | 4.3% |
| harness, true full profile | 26 | 115 | 21 | 0 | 16.0% |
| + path traversal fix (`j1mk.35`) | — | — | — | — | path traversal 12/15 |
| + JWT carrier fix (`j1mk.7`) | 32 | 109 | 21 | 0 | 19.8% |
| + blanket-row scoring by CWE | 37 | 104 | 21 | 0 | 22.8% |
| + coarse-CWE credit by name, `fetch` seed | 44 | 97 | 21 | 0 | 27.2% |
| + XXE sound differential, LDAP password seed | 49 | 92 | 21 | 0 | 30.2% |
| + in-band SSRF (0vzb.6) | 50 | 96 | 21 | 0 | 29.9% |
| review corrections, 2026-10-12 (not re-measured) | see below | | | | expected ≈ 22–25% |

`0 FP` is still an artefact of CWE matching hiding off-target findings; precision is not yet measured.
The last measured row's TP+FN is 146 where the rows above it have 141: that run's case list differed
(five more cases were testable), so the two percentages are not strictly comparable.

### 2026-10-12 review corrections — what the numbers above overstated

Every row above counted credit the 2026-10-12 review removed, so none of them is a detection-only
score. The corrections, and the expected loss per category (estimated from the per-case reports, NOT
re-measured):

| Correction | Category | Expected detection TP lost |
|---|---|---|
| CWE-522 is no longer credited by name to the cookie-flag rows; those cases are reported as **posture credit**, outside the score | CLIENT_SIDE_VULNERABLE_JWT | 8 (to 0/10) |
| Traversal payloads/signatures keyed to the app's own files removed (`secret.json`, `OwaspAppInfo.json`, `…%00UserInfo.json`, their content strings). The NUL-with-allowed-suffix form is now derived from the point's own value, and the harness now seeds `fileName=UserInfo.json` (the app's own request), so the `application.properties%00UserInfo.json` levels are still tested — by technique | PATH_TRAVERSAL | up to about 4 of 12: the levels whose only evidence was a planted JSON file's content (`secret.json`, `OwaspAppInfo.json`) |
| The reflected-XSS browser route for this app moved out of the scanner; `/api/scanner/config` cannot carry a route, so the harness cannot hand it over and every XSS point is declined | REFLECTED_XSS | every level the browser confirmation had confirmed (0 in the last full run, which did not reproduce it; up to 5 when the family ran alone) |
| In-band SSRF evidence no longer accepts a string that is in the payload (`computeMetadata`) or in the baseline | SIMPLE_SSRF | 0 expected: the measured TP is the `file:///etc/passwd` read, whose evidence is file content |
| XXE fallback requires the control's exact shape with a value and a non-error status | XXE | 0 expected: the measured TPs return the file content where the control returned its marker |

The detection-only headline is therefore expected near 50 − 8 − (0…4) ≈ 38–42 TP of 146, i.e. about
22–25%, with CLIENT_SIDE_VULNERABLE_JWT's 8 cases moving to the separate posture-credit line.

## Categories that detect

| Category | TP/FN | Note |
|---|---|---|
| BLIND_SQL_INJECTION | 2/0 | complete |
| UNION_BASED_SQL_INJECTION | 2/0 | complete |
| ERROR_BASED_SQL_INJECTION | 2/3 | levels 3–4 missed (j1mk.36) |
| OPEN_REDIRECT_3XX_STATUS_CODE | 7/1 | one level missed (j1mk.36) |
| PATH_TRAVERSAL | 12/3 | was 0/15; fixed (j1mk.35) |
| SERVER_SIDE_VULNERABLE_JWT | 5/1 | was 0/6; forgery rows now fire (j1mk.7) |
| CLICKJACKING | 3/2 | "Frameable response" (CWE-1021, its own CWE) answers a clickjacking case; scored once the blanket list stopped dropping it |
| INSECURE_CRYPTOGRAPHIC_STORAGE | 2/0 | recovered by the same scoring fix |
| PASSWORD_RESET_TOKEN_EXPOSED_VIA_REFERRER | 1/0 | |

## Categories that do not detect, and why

Three distinct causes. Only the first is a scanner defect.

### 1. Reachable, not yet detected — scanner work

| Category | FN | Cause |
|---|---|---|
| REFLECTED_XSS / PERSISTENT_XSS | 18 / 13 | the endpoints answer `text/plain` and the page's own JS writes the body with `innerHTML`, so the reflected markup never appears in the HTTP response. The browser confirmation (j1mk.38) can confirm them, but only through a caller-supplied route (this app's is in `scripts/bench/run_vulnapp.py`), and `/api/scanner/config` has no key to supply one, so in this harness it declines every point. |
| CLIENT_SIDE_VULNERABLE_JWT | 10 | token leak to the client (CWE-522) — a different class from the forgery checks, which cover SERVER_SIDE. No check exists. The cookie-flag rows fire on 8 of these levels; that is reported as posture credit, not detection, because those rows fire on any cookie missing a flag. |
| INSECURE_CONFIGURATION_JWT | 3 | alg confusion / expired / `kid` handling (CWE-1188); `ForgeAlgConfusion` exists but is not wired to a row (0vzb.7). |
| UNRESTRICTED_FILE_UPLOAD | 7 | active upload checks absent (0vzb.15) |
| LDAP_INJECTION | 3/1 | levels 1–3 detect; 5 needs its own probe shape |
| XXE | 2/1, TN 4/4 | differential: the external answer must be the internal-entity control's answer with the marker replaced by a non-empty value, under the same non-error status class |
| INSECURE_DIRECT_OBJECT_REFERENCE | 4 | no IDOR check (0vzb.12) |
| SIMPLE_SSRF | 3 | in-band SSRF exists (0vzb.6) and finds the `file://` read; its canary listener is loopback-only, so its HTTP canary proves a fetch only when target and scanner share a host |
| WEB_CACHE_POISONING | 4 | shallow unkeyed-input set (0vzb.2) |
| HEADER_INJECTION | 1 | depth unverified (0vzb.16) |
| REMOTE_CODE_EXECUTION | 1 | — |
| DENIAL_OF_SERVICE / UNCONTROLLED_RESOURCE_CONSUMPTION | 1 / 1 | passive only (0vzb.20) |

### 2. Logic classes with no active check — scanner work, larger

`CLICKJACKING` (the 2 levels "Frameable response" misses), `NO_LOGIN_RATE_LIMITING` (6), the password-reset token family (7),
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
3. **CLIENT_SIDE_JWT (10, detection 0; posture credit separately)** and **INSECURE_CONFIGURATION_JWT (3)** — token-leak detection and
   wiring the existing `ForgeAlgConfusion`/`kid` to a row (0vzb.7).
4. **File upload (7 FN)**, **SSRF metadata (4)**, **cache poisoning (4)**, **IDOR (4)** — the `0vzb`
   active-check rows.

## Reproducing

```bash
docker run --rm -p 9090:9090 sasanlabs/owasp-vulnerableapp:latest
/tmp/burpsy -db /tmp/bsy.db -proxy 127.0.0.1:18080 -web 127.0.0.1:8081 -scope-include 127.0.0.1
python3 scripts/bench/run_vulnapp.py --full-profile --out /tmp/bench
python3 scripts/bench/explain_case.py --full-profile PathTraversal/LEVEL_8   # one case, in detail
```

## A pre-existing test flake, recorded honestly

`TestTheScannerStaysQuietOnTheSafeCounterparts` fails on this machine under load, across unrelated
families (DOM, referer-dependent, backup-file, XML), always with the message *"did not fire against
its vulnerable twin in this run"* — i.e. the check is presumed dead rather than the safe twin being
wrong. The specific subtests **pass in isolation** (`-run '.../Referer'`) and the same failures
reproduce at the commit before the JWT work, so this is not that change.

The likely cause is contention, not logic: the test runs its subtests in parallel (`t.Parallel()`)
while the package's other tests stand up the shared vulnerable-app target and Chrome tabs, and the
runner here has 4 CPUs and ~16 GB shared with a Docker daemon and a live benchmark. The safe-twin
guard is *correct* — it refuses to accept silence as evidence when the positive control did not
fire — so the honest reading is "the harness was starved in this run", not "the check is broken".
Worth confirming against CI (which shards the package and has a cleaner machine before treating it
as a defect; if it reproduces there, the fix is to bound the subtests' parallelism rather than to
weaken the guard.


