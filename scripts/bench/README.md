# scripts/bench — the scanner's scored benchmarks

A benchmark with ground truth: burpsy's active scanner is run against a deliberately vulnerable
application that declares, per endpoint, exactly which vulnerability it plants, and the score is
how many of those it finds. This is the burpsy side of reference-parity bead `j1mk.1`, and the
harness `j1mk.38` asks to live in the repo.

Two things it is not:

- **Not a parity count.** It scores detection against the target's own labels; the reference-tool
  diff ("did sqlmap find what we did not") is a separate step per class.
- **Not an FP-free number.** A case that plants an IDOR is scored against findings whose CWE set
  intersects the case's, so an off-target finding with no CWE match is invisible — the `0 FP` the
  earlier hand-run baseline reported is that artefact. `j1mk.34` (command-injection checks firing
  on unrelated endpoints) is the measured counter-example.

## Targets

| Target | File | Status |
|---|---|---|
| OWASP VulnerableApp | `run_vulnapp.py` | the scored baseline today |
| OWASP Benchmark v1.1 | — | dropped: 2016, outdated |
| OWASP Benchmark v1.2 | — | blocked on `j1mk.33` (fixed) then harness reuse |

## Running VulnerableApp

```bash
# 1. the target (Docker or the released jar; the app serves http on 9090)
docker run --rm -p 9090:9090 sasanlabs/owasp-vulnerableapp:latest

# 2. burpsy, scoped to the target, on a known proxy/web pair
go build -o /tmp/burpsy ./cmd/burpsy
/tmp/burpsy -db /tmp/bsy.db -proxy 127.0.0.1:18080 -web 127.0.0.1:18081 -scope-include 127.0.0.1

# 3. score it (writes vulnapp-<date>.json and .md under --out)
python3 scripts/bench/run_vulnapp.py --out /tmp/bench
```

`--limit N` scores the first N cases (a quick smoke run). `--fail-under PCT` turns the run into a
gate, exiting non-zero under the given strict score; nightly CI uses the recorded baseline minus a
regression margin, not an absolute floor, so an honest improvement is never a failure.

No third-party Python is needed — the harness is standard library only, so it runs anywhere the
Go toolchain and the target do.

## What a case is, and where the facts come from

`vulnapp_cases.py` holds the two tables the app's `/scanner` endpoint does not carry:

- **`FAMILY_PARAMS`** — every VulnerableApp handler binds `@RequestParam Map<String,String>`, so
  the request parameter's *name* exists only in the page's own JavaScript (`?id=`, `?fileName=`,
  `?value=` …). The table maps each family directory to the name its UI sends.
- **`TYPE_CWES`** — `VulnerabilityType`'s constructor is `(cweID, wascID)`, so the enum is the
  app's own ground-truth CWE mapping, not a judgement of ours.

A finding counts when one of the CWE numbers in its advisory's `classifications` matches one of the
case's. "Strict" additionally drops the named blanket posture checks (`BLANKET_CHECK_NAMES`),
which fire on every response and would otherwise inflate a scanner that reports nothing but header
posture. The lenient number is kept beside it.

A case the harness cannot exercise (no parameter known, the proxy refused it, the audit failed) is
listed under **Untestable** and is never scored as a pass — the honest-counting rule the rest of
the tree follows, applied to the benchmark itself.

## The full benchmark: one command, every prerequisite in place

`run_vulnapp.py` scores whatever app and burpsy you already started, and seeds nothing, so the
JWT, IDOR, session, auth, OTP, upload and password-reset cases score as misses for the harness's
reason rather than the scanner's. `full_benchmark.py` owns the whole environment instead:

```bash
sudo python3 scripts/bench/full_benchmark.py \
  --jar /path/to/VulnerableApp-1.0.0.jar --out /tmp/bench-full \
  [--dom-remote @/path/shared-chrome.ws] [--baseline /tmp/bench-prev/report.json] \
  [--only JWTVulnerability,IDORVulnerability] [--burpsy /path/to/burpsy] [--workers 8] [--app-port 9190]
```

What it does, in order:

1. **Mail sink, then VulnerableApp as uid 65534.** `mailsink.py` on `--smtp-port`/`--inbox-port`,
   then the jar under `setpriv --reuid=65534 --regid=65534 --clear-groups`, bound to 127.0.0.1 on
   `--app-port`, mailing to the sink (`--spring.mail.host/port`, and
   `--vulnerableapp.email.base-url` so reset links name this instance). It waits for
   `/VulnerableApp/scanner`, checks the process really runs as uid 65534, and checks the committed
   case list against that live `/scanner` (a list from another app version is refused).
2. **One seeded request list** (`seeded-requests.json` in `--out`):

   | Category | Seeder | What it supplies |
   |---|---|---|
   | SessionManagement | `vulnapp_session_seed.py` | the app's seeded `session_user` login |
   | PasswordReset | `vulnapp_pwreset_seed.py` | each level's reset body + a confirm companion; its accounts become `reset_test_identities` |
   | Authentication | `vulnapp_auth_seed.py` | each level's own account name (enumeration needs a username that exists) |
   | JWT | `vulnapp_jwt_seed.py` | each level's own issued token, where that level reads it (query, `Authorization`, or cookie), without `fetch` |
   | IDOR | `vulnapp_idor_seed.py` | a real login's cookies (tokens expire after an hour) |
   | OTP | `vulnapp_otp_seed.py` | each level's account, plus its `/validate` step as an AUDITED companion |
   | UnrestrictedFileUpload | `vulnapp_upload_seed.py` | an inert 1x1 PNG the levels accept, instead of a refused `test.txt` |
   | PathTraversal, PersistentXSS, CachePoisoning, the rest | (generated) | the request each level's page sends; the checks plant their own markers and discover unkeyed headers |

   Token-bearing cases (IDOR, JWT) are re-seeded at send time once older than `--reseed-minutes`
   (default 50).
3. **burpsy with every switch on**, one instance per worker slot (`--burpsy-base-port` + 2N), all
   sharing one CA that is created once before the parallel start (N servers generating it at once
   write a mismatched certificate and key). The profile goes through the confirmed
   `PUT /api/scanner/config`: EVERY `check_*` boolean the running binary reports (read at run time,
   so a new switch cannot be missed), `xss_browser_targets` for this app's origin,
   `reset_test_identities`, `reset_mailbox_url` (`http://127.0.0.1:<inbox>/inbox?to={identity}`).
   The config is read back; a key that did not take makes that chunk's cases untestable, with the
   reason. `-dom` is the shared Chrome (`--dom-remote ws://…` or `@file`, else `$BURPSY_DOM_REMOTE`)
   when it answers `/json/version`, else a local Chrome (`--chrome`, `$BURPSY_CHROME`, or
   `chromium`/`google-chrome` on PATH). The bundled PortSwigger BCheck corpus is what `check_corpus`
   runs unless `--bchecks DIR` is given.
4. **Every case in the list** — all 168, upload and traversal included; `--only` narrows it to
   categories. Seeding is serial and finishes first; the cases then run concurrently in chunks of
   `--chunk-size` (4), each chunk on a fresh burpsy server with its own port pair. Two lanes:
   the **main lane** at `--workers` servers (8; cases are I/O-bound — timing probes, browser waits —
   so more than the CPU count is fine), and a **timing lane** at `--timing-workers` (2) for cases
   whose verdict is a latency or a uniform burst: blind (time-based) SQL injection, and the
   login-shaped Authentication, OTP and SessionManagement categories the rate-limit check bursts.
   The timing lane runs after the main lane by default (`--timing-lane after`), so parallel load
   cannot skew it; `alongside` overlaps them. Request smuggling is timing-based too, but it is a
   check that runs on every case, not a case, so it runs in whichever lane its case is in. The
   report gives the wall time per lane. Hazardous families (command injection, RCE, deserialization, DoS) run last. A case the
   harness could not exercise (target stopped answering, audit timed out, seed not captured) is
   **untestable**, listed with its reason, never scored as a pass or a miss.
5. **Scoring**, `run_vulnapp.py`'s rules: strict is detection only; posture rows are reported as
   posture credit beside it, never in it; lenient adds posture and blanket rows. A finding's CWEs come
   from its own advisory plus the RUNNING burpsy's advisory catalogue: Burp's rows from
   `/api/advisories`, burpsy-only rows (`BurpsyNativeRows`, type index `0xb5……`, defined in
   `internal/advisory/native`) from `/api/advisories/{index}`, which serves them though the listing
   omits them. So every native row is scored by the CWE the binary itself declares, and a new row needs
   no table edit here. A finding on an audited companion (OTP validate) counts for its case.
   `report.json` + `report.md`: headline, an **Abilities** table (each RUN or SKIPPED, with why), a
   per-category and a per-type table, untestable cases, seed failures, and with `--baseline` (a
   previous `report.json`, or `score_va.py`'s `-raw.jsonl`) a per-category comparison and every case
   whose verdict changed.
6. **Cleanup by PID.** Every process it started is stopped by its own PID, with descendants (a local
   Chrome) found through `/proc` and matched on start time so a recycled PID is never signalled. It
   never `pkill`s a pattern, and it refuses to start when any of its ports is already taken, so it
   cannot collide with, reuse or stop a shared instance. The app's run directory (uploaded files
   included) and a burpsy it built itself are removed at the end.

### Why VulnerableApp must run as an unprivileged uid

Its upload and path-traversal levels write wherever a filename points — that is the vulnerability.
Run as root, the benchmark's own traversal probes overwrote `/etc/passwd`. As uid 65534 (nobody)
such a write fails with EACCES and the case still answers, so the cases stay scorable and the host
stays intact. The script therefore needs root only to drop to 65534; it never runs the app as root,
and as a non-root user it refuses unless `--run-as-current-user` accepts that the app may write to
that user's files.

Two consequences of the drop that the script handles, and that a hand-started instance gets wrong:

- **The run directory's whole path must be traversable by uid 65534.** Spring Boot's launcher reopens
  the jar by its absolute path, so a jar under a 0700 directory (such as a per-user `/tmp/claude-0`)
  fails with `ClassNotFoundException: JarLauncher`, and uploads under one fail with a 500. The script
  runs the app from a fresh `mkdtemp` under `/tmp` (`--va-parent`), with the jar hard-linked in
  (copied when on another filesystem).
- **`--logging.file.name=` does not stop the file log.** The jar's own `log4j2.xml` writes DEBUG to a
  rolling `./logs/server.log` whatever Spring's `logging.file.*` says. The script passes its own
  console-only WARN `log4j2.xml` (`-Dlog4j2.configurationFile` and `--logging.config`) and discards
  the console unless `--app-console-log FILE` asks to keep it.

### Abilities that may be SKIPPED, and a known defect

- **Out-of-band collaborator.** burpsy's only collaborator is the external `interactsh-client`
  binary (`-collaborator-server`, `-collaborator-client`); the binary has no local or in-process
  endpoint, and the tests' fake provider is test-only. `check_out_of_band` is switched on regardless,
  and without a client its rows refuse ("no collaborator channel is configured"), which the report
  lists as SKIPPED. Measured here: the public pool (oast.*) answers through the proxy and DNS
  resolves, so `--collaborator-client /path/interactsh-client --collaborator-server public` enables it
  where that binary is installed and approved.
- **DOM engine.** SKIPPED only when neither a shared nor a local Chrome is available.
- **Known scanner defect: DOM engine vs. session and rate-limit checks.** With `-dom` attached, every
  audit of a non-browser POST (a JSON login, an OTP validate step) reported 2 checks "send failed" and
  50-53 "unit abandoned", and the session-management and login-rate-limit rows never reported:
  SessionManagement 0/5 with `-dom` vs 5/5 without; OTP 0/4 vs 4/4 (all four by "Authentication
  attempts not rate limited" on the validate step). Same binary, same `--parallel 1`. Authentication
  scored the same either way. The default runs every ability everywhere and so shows the defect;
  `--dom-off-categories SessionManagementVulnerability,OTPVulnerability` audits those categories
  without the browser, and the report's Notes say so. Other POST-shaped categories may be depressed
  the same way; a `--no-dom` run beside a default one measures it.

### The case list

`vulnapp_requests.json` is the generated 168-case list for SasanLabs/VulnerableApp master `36d1090`
(`vulnapp_build_requests.py` regenerates it from the app's source and its `/scanner` and
`/allEndPoint` answers). Its cookies, tokens and accounts are placeholders; the seeders replace them
at run time, and nothing seeded is ever written back to it.
