# Detection-gaps program plan — 2026-10-10

> Working plan for closing every scanner detection gap tracked under the three open epics
> `v0ei` (SQL injection), `0vzb` (modern classes beyond Burp's catalogue) and `j1mk`
> (reference-tool parity, including the seven VulnerableApp bugs `j1mk.32`–`.38`).
> Source research: `docs/DETECTION-GAPS-2026-10-10.md`,
> `docs/REFERENCE-PARITY-2026-10-10.md`, `docs/VULNERABLEAPP-BASELINE-2026-10-10.md`.
> Process rules: `docs/DEVELOPMENT-PROCESS.md` (this plan is subordinate to it).
>
> Created 2026-10-10. Update the status column as beads land; do not re-derive the baseline.

## 1. Where we are (honest baseline)

| Metric | Value | Source |
|---|---|---|
| Catalog rows registered | 183 / 183 (0 declined) | `SCANNER-COVERAGE.md` |
| Rows demonstrated end-to-end | 160 (pinned `wantDemonstrated`) | `runtime_coverage_test.go` |
| BCheck corpus parse conformance | 264 / 264 | `BCHECK-COVERAGE.md` |
| **VulnerableApp score (full profile)** | **19 TP / 128 FN / 21 TN / 0 FP → 12.9% strict, 16.3% lenient** | `VULNERABLEAPP-BASELINE-2026-10-10.md` |
| VulnerableApp score (default config) | 4.8% / 8.2% | same |
| Open detection beads | 8 (`v0ei`) + 21 (`0vzb`) + 38 (`j1mk`) ≈ **67** | `.beads/issues.jsonl` |

The 0 FP is misleading: CWE matching hides off-target hits — "OS command injection" fired on 35
cases of which 30 were not command injection (`j1mk.34`). **FN count is the target; FP count is
currently unmeasurable** and measuring it is itself a deliverable (§4, W0).

Master is currently **red**: `TestRawApplyLeavesTheVariantBytesUntouched` fails because the
`j1mk.32` encoder fix (`c465f213`, direct to master) escapes `" < > \ ^ ` { | } [ ]` in the `Raw`
policy too, which the test forbids. Fixing forward or reverting the raw-branch change is W0.

## 2. Guardrails (non-negotiable, from the repo's own rules)

1. **Honest counting.** A check that cannot run reports a named refusal; a failed probe is never
   labelled "Audited" (bead `8dnu`). No headline parity % until CS-11 re-verifies.
2. **One egress path.** Every new probe goes through `sender.AuthorisedSender` bound to the target
   authority. No raw dials; external reference tools (sqlmap, dalfox, commix…) are gated by the
   `-tools` allowlist and pre-flight `extscan.Authorise`.
3. **Non-destructive by default.** Anything that writes, sends mail, or changes server state
   (race conditions, password-reset poisoning, file upload, SSPP revert, mass assignment) ships
   **off by default** and behind a gated route with an explicit confirmation.
4. **Licences.** burpsy is GPL-3.0-or-later; sqlmap/ffuf/nuclei data reuse is allowed with notices.
   Reference tools run as subprocesses, never linked. Do not vendor a tool's binary without a pin
   and hash.
5. **Beads are edited by the lead only.** Agents report new work; the lead files it. Bead closures
   cite a merged sha (`scripts/beads-close-merged.py`).
6. **Rounds.** ≤6 items, ≤~800 lines per item, ≤1 Chrome/corpus item per round, two items may not
   share a file except the named exceptions. CI credits are exhausted, so land via rounds and
   verify locally with `scripts/capped-run.sh` until Actions billing returns.

## 3. Dependency graph

```
W0  master-green fix · bench harness (j1mk.1/.38) · TLS verify (j1mk.33) · FP tightening (j1mk.34)
     │
     ├─► W1  SQLi core (v0ei.1 timing · v0ei.2 error bank · v0ei.4 boolean · v0ei.5 UNION)
     │        └─► v0ei.3 OOB · v0ei.6 NoSQL · v0ei.8 WAF-evasion · v0ei.7 sqlmap hand-off
     │
     ├─► W2  modern classes, P1 set (0vzb.1/.2/.3/.4/.5/.6/.7)
     │
     ├─► W3  parity tools for the P1 classes (j1mk.2/.3/.5/.6/.9/.10/.11/.12/.17)
     │
     └─► W4+ P2/P3 classes and their parity rows (0vzb.8–.21 · j1mk.4/.7/.8/.13–.31)
```

Everything scoring-related depends on **W0's harness**: until `scripts/bench/` exists, a class bead
can only be checked by hand, and hand-scored runs are the thing this repo forbids.

## 4. Waves

### W0 — Foundation (unblocks everything) — round 1–2

| Item | Bead(s) | Files (predicted) | Acceptance |
|---|---|---|---|
| A. Master green: reconcile the Raw-escape contract | `j1mk.32` | `internal/bcheck/insertion.go`, `internal/scanner/xss_decoding_variants_test.go` | `ci-shard.sh scanner-rest` green locally; Raw still passes `%`/high bytes, escapes the RFC-3986 illegal set only in default mode |
| B. TLS-verify unified (proxy + scanner sender) | `j1mk.33` | `internal/sender/network.go`, `internal/web/api_network.go`, `internal/proxy/*` | audit of an https exchange to an expired-cert target runs when `verify=false`, refuses when true |
| C. FP tightening: command/code-injection confirmations | `j1mk.34` | `internal/scanner/checks_injection.go`, `infra_injection_evidence.go` | VulnerableApp FP set (30 off-target) drops; the 5 true cmd-injection cases stay |
| D. **Bench harness → `scripts/bench/`** | `j1mk.1`, `j1mk.38` | `scripts/bench/*` (new), `scripts/ci-install-tools.sh`, `.github/workflows/nightly.yml` | VulnerableApp scored nightly under `capped-run.sh`; per-type table stored; regression fails |
| D2. **Bench target is OWASP VulnerableApp** | `j1mk.1`, `j1mk.38` | `scripts/bench/*` | The suite's ground truth is VulnerableApp's own `/scanner` endpoint (168 cases, 147 vulnerable / 21 secure) mapped to CWE via `VulnerabilityType`. Generalise the harness to the other suites only after it is green here |
| E. Default-config decision | `j1mk.37` | `internal/scanner/scan_config*.go`, UI | **decision-needed** — see §7. No code until answered |
| F. Path traversal depth | `j1mk.35`, `0vzb.4` | `infra_injection_payloads.go`, `checks_injection.go` | ≥8/12 VulnerableApp levels; SECURE level clean |

### W1 — SQL injection (epic `v0ei`) — rounds 3–5

Order matters: the error bank (`.2`) and timing (`.1`) make the boolean (`.4`) and UNION (`.5`)
findings confident, and OOB (`.3`) reuses the OOB channel that already exists.

| Item | Bead | Notes |
|---|---|---|
| Timing probes, all DBMS + statistical confirmation | `v0ei.1` | MySQL `SLEEP`/`BENCHMARK`, Oracle `DBMS_PIPE.RECEIVE_MESSAGE`, SQLite heavy query, DB2; three delays + repeat; negative control (a target that sleeps on every request must not fire) |
| DBMS error bank (sqlmap `errors.xml` base + driver/ORM) | `v0ei.2` | GPL-3 allows the reuse; keep notice + record sqlmap version; baseline-differs rule preserved |
| OOB SQLi (DNS canary per probe) | `v0ei.3` | `internal/oob`; xp_dirtree, UTL_INADDR/UTL_HTTP, LOAD_FILE UNC, COPY/dblink; gated on the OOB setting |
| Robust boolean detection | `v0ei.4` | similarity with dynamic-content removal; AND/OR, arithmetic, ORDER BY, LIKE, IN, JSON body |
| UNION column-count + stacked | `v0ei.5` | evidence only, no data extraction |
| NoSQL injection | `v0ei.6` | new catalog row(s); Mongo operators, `$where`, error signatures; pairs with `j1mk.7` |
| sqlmap hand-off adapter | `v0ei.7` | `extscan` shape like ffuf/nuclei; `-r` request file, `--batch`, scope-gated, routed through the proxy |
| WAF-evasion variants | `v0ei.8` | opt-in, only after a plain probe is blocked |

### W2 — Modern classes, P1 (`0vzb`) — rounds 6–9

| Item | Bead | Gated? |
|---|---|---|
| Request smuggling variants (CL.0, TE.0, 0.CL/Expect, client-side desync, H2) | `0vzb.1` | no (read-only probes) |
| Cache poisoning/deception (unkeyed params, 2024 delimiters) | `0vzb.2` | no (cache-buster required on every probe) |
| Server-side prototype pollution | `0vzb.3` | revert afterwards |
| Host-header attacks | `0vzb.5` | password-reset poisoning sub-case opt-in |
| Cloud-metadata SSRF (in-band) | `0vzb.6` | no |
| JWT `kid` injection + alg-confusion wiring | `0vzb.7` | no |

### W3 — Reference parity for P1 classes (`j1mk`) — rounds 10–12

Harness (W0-D) drives these. Each bead is "run tool vs run burpsy, diff, file the misses".

`j1mk.2` SQLi↔sqlmap · `j1mk.3` XSS↔dalfox · `j1mk.5` cmdi↔commix · `j1mk.6` SSTI↔SSTImap ·
`j1mk.9` SSRF↔SSRFmap · `j1mk.10` traversal↔dotdotpwn · `j1mk.11` smuggling↔smuggler ·
`j1mk.12` cache↔WCVS · `j1mk.17` JWT↔jwt_tool.

Tool pinning + hash-check goes in `scripts/ci-install-tools.sh` (same pattern as ffuf/nuclei).

### W4+ — P2/P3 long tail — rounds 13+

Grouped by shared surface so items do not collide:

- **Crawler/API surface:** `0vzb.12` (BOLA/BFLA/mass assignment from OpenAPI), `0vzb.13` (GraphQL
  batching/aliases + GET/CSRF), `j1mk.13` (hidden params), `j1mk.18` (graphql-cop), `j1mk.27`
  (crawler vs ZAP/katana).
- **Protocol/transport:** `0vzb.8` (race conditions, opt-in), `0vzb.11` (CSWSH), `0vzb.14`
  (spoofable client IP), `0vzb.16` (CRLF depth).
- **Content/upload/crypto:** `0vzb.15` (file upload, cleanup), `0vzb.19` (cookie prefixes),
  `0vzb.20` (passive ReDoS/enumeration), `j1mk.14` (CORS/Corsy), `j1mk.15` (CRLF/crlfuzz),
  `j1mk.16` (open redirect), `j1mk.24` (TLS/testssl.sh), `j1mk.25` (secrets/gitleaks).
- **Infra/ecosystem:** `0vzb.17` (subdomain takeover), `0vzb.21` (bundle BCheck corpus — licence
  check), `0vzb.18` (LLM), `j1mk.19` (deserialization), `j1mk.20` (SSPP ref), `j1mk.21`
  (client-side PP), `j1mk.22` (race ref), `j1mk.23` (nuclei/nikto), `j1mk.26` (content discovery),
  `j1mk.29`–`.31` (takeover/LLM/OAuth refs).
- **DOM:** `j1mk.4` (DOM XSS vs DOM Invader) — needs Chrome; schedule alone in a round.
- **Scoring gaps from the VulnerableApp baseline:** `j1mk.36` (error-SQLi L3–4, redirect L6–7).

## 5. Per-item deliverables (the checklist every bead carries)

1. The probe/check in `internal/scanner` or `internal/bcheck`, via `AuthorisedSender`.
2. A **catalog row** (or an explicit `declinedDescriptor`) — every native descriptor must name a
   real catalog issue (`ByName` panics otherwise).
3. A composed-finding contract: severity, confidence, `Param`, `Evidence`, `AdvisoryNote`.
4. A test named as a full-sentence claim, with a **negative control** that fails on the revert.
5. `vulnapp` manifest row + route (both lists) where the class is plantable, so runtime coverage
   is pinned, not asserted.
6. A bench entry so the class is scored, not just unit-tested.
7. `gaps.md` row if the change diverges from the Rust reference (append only).
8. T1 local run (`gofmt`/`vet`/affected tests; `bun run check` if UI changed) and a report saying
   what ran and what was skipped.

## 6. Metrics to track (add to the nightly bench output)

| Metric | Now | Goal |
|---|---|---|
| VulnerableApp strict score | 12.9% | ≥60% before declaring the program done |
| VulnerableApp FN | 128 | ≤40 |
| Measured FP (needs a ground-truth-aware FP pass, W0-D) | unmeasured | measured and reported per class |
| Distinct catalog rows demonstrated | 160 | rises with each new row |
| Reference-parity classes with a diff report | 0 | 25+ |
| Checks whose probes fail and are labelled clean | present (`8dnu`) | 0 |

## 7. Decisions needed from the owner (stop and ask; do not build both)

1. **Default scan config (`j1mk.37`).** Burp's default audit runs cmd/LDAP/XPath/XXE/redirect; burpsy
   defaults them off (4.8% vs 12.9%). Turn them on by default (changes what a default scan does, and
   its noise), or keep off and make the UI choice explicit? Recommend: enable the read-only
   injection checks, keep state-changing ones off, and make the preset visible in the New Scan dialog.
2. **Bundled BCheck corpus (`0vzb.21`).** Ship a vetted PortSwigger corpus by default (licence and
   maintenance burden) or a fetch-and-pin step? Recommend fetch-and-pin, default-on with a recorded
   version.
3. **State-changing classes scope.** Confirm race conditions, password-reset poisoning, file upload
   and mass assignment all stay opt-in behind gated routes with confirmation.
4. **Reference-tool binaries in CI.** Adding sqlmap/dalfox/commix/etc. to the nightly image grows it
   substantially. Confirm they belong on nightly (not per-PR) and are pinned+hashed.

## 8. Definition of done

- Every `v0ei`, `0vzb` and `j1mk` child bead closed against a merged sha.
- VulnerableApp nightly score meets the §6 goal, with per-type regressions failing the job.
- Every new class has a catalog row, a negative-controlled test, a `vulnapp` manifest entry and a
  bench entry.
- No probe failure can render as "Audited"; the FP pass measures precision per class.
- `gaps.md` records every deliberate Rust↔Go divergence introduced.

## 9. Immediate next actions

1. Decide §7 items 1–4 (owner).
2. W0 item A — fix master's red test (the only thing blocking a clean base).
3. W0 items B–D as round 1; W0 items E–F as round 2.
4. File the W0 bench harness bead (`j1mk.1`/`.38` already cover it) and give it the round.
