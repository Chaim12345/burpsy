# VulnerableApp baseline — 2026-10-10

First scored run of burpsy's active scanner against a benchmark with ground truth. Part of epic
`j1mk` (reference parity); this is the burpsy side of `j1mk.1` for one target.

**Target:** [OWASP VulnerableApp](https://owasp.org/www-project-vulnerableapp/) (SasanLabs), built
from master `36d1090`, 168 cases (147 vulnerable, 21 secure variants) from its own `/scanner`
ground-truth endpoint, each mapped to a CWE through the app's `VulnerabilityType`.
**Scanner:** burpsy-go at `dc04060a`.

OWASP Benchmark v1.1 (2016, 21k cases) was dropped as outdated. Benchmark v1.2 (2,740 cases) is
built and its request list generated, but cannot be scanned yet: its certificate expired in 2015
and burpsy's active-scan sender ignores `tls.verify=false` (j1mk.33).

## Method

Per case: the seed request (example values from the app's metadata) goes through burpsy's proxy,
becoming a captured exchange; `POST /api/audit/{id}` audits it (120 s budget); findings are tied to
the case by `exchange_id`. A finding counts only if one of its issue type's catalog CWEs matches a
CWE of the case. TP/FN on vulnerable variants, FP/TN on secure ones. "Strict" drops issue types
raised on ≥90% of cases (Frameable response, Unencrypted communications). No crawl, no login.

## Result (full profile: every check family on except DOM, OOB, corpus)

| Vulnerability | TP | FN | TN | FP |
|---|---|---|---|---|
| Command injection | 5 | 0 | 0 | 0 |
| Blind SQLi | 2 | 0 | 0 | 0 |
| UNION SQLi | 2 | 0 | 1 | 0 |
| Error-based SQLi | 2 | 2 | 0 | 0 |
| Open redirect (3xx) | 7 | 2 | 2 | 0 |
| Password reset | 1 | 8 | 0 | 0 |
| Path traversal | 0 | 12 | 0 | 0 |
| XSS (reflected, stored) | 0 | 14 | 3 | 0 |
| LDAP / XXE / SSRF | 0 | 11 | 7 | 0 |
| File upload | 0 | 10 | 3 | 0 |
| Cache poisoning | 0 | 7 | 1 | 0 |
| JWT | 0 | 20 | 0 | 0 |
| IDOR, OTP, session, auth, crypto, deserialization, clickjacking | 0 | 42 | 4 | 0 |
| **Total** | **19** | **128** | **21** | **0** |

Score (TPR − FPR): **12.9%** strict, 16.3% lenient. Default server config: 4.8% / 8.2%.

The 0 FP is misleading: CWE matching hides off-target findings. "OS command injection" fired on
35 cases, 30 of them not command injection; code-injection and SSTI checks did the same.

## Findings and beads

| Bead | |
|---|---|
| j1mk.32 (P1) | Query/form encoder sends `"` `<` `>` raw; Tomcat returns 400, so every XSS probe dies. Reproduced. |
| j1mk.33 (P1) | Active-scan sender ignores `tls.verify=false`; blocks Benchmark v1.2. |
| j1mk.34 (P1) | Command/code-injection checks fire on unrelated endpoints (30 FPs). |
| j1mk.35 (P2) | Path traversal 0/12: only the plain `../etc/passwd` probe. |
| j1mk.36 (P2) | Error SQLi L3–4, open redirect L6–7 missed. |
| j1mk.37 (P2) | Default config leaves command, LDAP, XPath, path, XXE and redirect checks off. |
| j1mk.38 (P2) | Move the harness into `scripts/bench/` and run VulnerableApp nightly as a tracked baseline. |

No check exists for IDOR, rate limiting/OTP, session fixation/logout, password-reset logic, weak
crypto/storage, deserialization, cache poisoning or JWT signature flaws (CWEs 347/522/1188); those
are already tracked under `0vzb` and `j1mk.12/.17/.19`.

## Reproducing

The harness is in the session scratchpad until j1mk.38 lands: start VulnerableApp
(`java -jar VulnerableApp-1.0.0.jar --server.port=9090`, built from source with the toolchain set to
the installed JDK), generate requests from `/VulnerableApp/scanner`, then run the seed/audit/score
loop under `scripts/capped-run.sh` (about 35 s per case, full profile, 2 CPUs).
