# UAT results

## The problem this fixes

The four matrices next door hold **1,300 test cases** in tables shaped
`| ID | Route | Precondition | Steps | Expected result | Type |`.

There is no result column. So the cases were unrun **by construction, not by neglect** — there was
nowhere to record a run, and `README.md` in the parent directory nonetheless asks for UAT coverage
before a release. Nobody could comply with that even in principle, and "1,300 UAT cases" read in a
status report as coverage that had never existed.

## Why results live here and not in the matrix

Two candidates were considered: add `Status` and `Evidence` columns to the four markdown tables, or
keep results in sidecar files. Sidecar won, for three reasons:

1. **The matrix is a spec; results are observations.** The spec is human-authored and reviewed in
   diffs. Results are rewritten wholesale on every run. Inlining them makes every run a 1,300-line
   diff and buries the one changed expectation in the noise.
2. **A harness can write TSV.** It cannot reliably rewrite a markdown table cell without risking the
   spec text in the same row.
3. **Two runs are comparable.** A per-run file can be kept, diffed, or attached to a release. A
   column can only hold the latest, and the previous answer is gone.

## Format

One TSV per run, `results/<iso-date>-<runner>.tsv`, tab-separated, with this header:

```
id	status	evidence	at	note
```

- **id** — the case id exactly as it appears in the matrix (`SITEMAP-001`). An id not in the matrix
  is an error, not a warning: see below.
- **status** — one of `pass`, `fail`, `blocked`, `skip`. There is deliberately no `partial`.
  - `blocked` means the precondition could not be established (no target application, no TLS CA
    installed). It is not a failure of the thing under test, and it is not a pass.
  - `skip` means deliberately not run, and the `note` must say why. A `skip` with no note is
    reported as unrun.
- **evidence** — a path, a URL, or a test name. **Required for `pass`.** A pass with no evidence is
  someone's recollection, and this whole directory exists because recollection was being counted as
  coverage.
- **at** — ISO 8601 timestamp of the run.
- **note** — free text. Required for `skip` and `blocked`; optional otherwise.

## The rule that makes this worth having

**A case with no row is `unrun`, and `unrun` is never reported as `pass`.** The report tool counts
the four statuses and the unrun remainder separately, and prints the unrun count even when it is
large — because the alternative is a coverage figure computed over only the cases somebody
remembered to run, which is how 1,300 unrun cases came to be described as a test matrix.

This mirrors `verify.sh`'s discipline exactly: a check that did not run is not a check that passed.

## Tools

```sh
node ../tools/uat-index.mjs      # rebuild index.tsv from the four matrices
node ../tools/uat-report.mjs     # join index + results, print coverage
```

`uat-report.mjs` exits non-zero when a results file names an id the matrices do not contain. That is
an error rather than a warning because a result for a case that does not exist is worse than no
result: it inflates the coverage denominator's numerator with a row nobody can go back and read.
