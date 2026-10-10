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
