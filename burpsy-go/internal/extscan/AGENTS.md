<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# extscan

## Purpose

Delegates a whole scan phase to an external security tool and turns what comes back into the same
`report.Row`s burpsy's own checks produce. Two tools are wired: `ffuf` for content and parameter
discovery — a capability burpsy has nowhere else in the tree — and `nuclei` for its community
template corpus, which is far broader than the bundled 183-row catalog. Both are run as subprocesses
for now; reimplementing either natively in Go is a later question this package does not prejudge.

This is a different shape from `scanner`'s `run tool`: that runs a named tool per insertion point on
behalf of a BCheck, this runs one tool once against a target and owns the whole phase. They share
the operator's `-tools` allowlist deliberately, so there is one place to switch external tooling on.
There is no Rust crate counterpart.

## Key Files

| File | Description |
|------|-------------|
| `extscan.go` | The gates and the exec: `Config` (allowlist + bounds), `Authorise`/`Target` (the scope gate), the `Outcome` enum, the typed refusals `ErrNotAllowed`/`ErrUnavailable`/`ErrUnauthorised`, `run` (no shell, bounded; cut-short runs wrap `ErrTimedOut`/`ErrStopped`/`ErrOutputIncomplete`), `cappedBuffer` |
| `ffuf.go` | `RunFFUF`, `FFUFOptions`, `FFUFResult`, the `Discovery` record, `parseFFUF`, and `FFUFResult.Rows` |
| `nuclei.go` | `RunNuclei`, `NucleiOptions`, `NucleiResult`, the `TemplateHit` record, `parseNuclei`, `MapSeverity`, and `NucleiResult.Rows` |
| `util.go` | Small shared helpers: `pathOf`, `statusText`, stable sorting, `dedupe` |
| `extscan_test.go` | The gates: scope authorisation and its refusals, allowlist refusals, severity mapping, the output cap |
| `parse_test.go` | Parsing and row conversion against captured real tool output |
| `live_test.go` | Actually launches `ffuf` and `nuclei` against a local `httptest` server; carries the counted-skip enforcement |
| `testdata/` | Real captured output from ffuf 2.1.0-dev and nuclei v3.8.0. Fixtures for the parsers — not evidence of any finding |

## For AI Agents

- **A delegated tool cannot be put behind `sender.AuthorisedSender`, so the scope gate moved
  earlier.** An external process dials the target itself; the per-request byte gate that authorises
  everything burpsy constructs does not reach it. `Authorise` is the substitute and it runs before
  exec. Nothing else in this package will launch a binary: `RunFFUF`/`RunNuclei` refuse a `Target`
  that did not come from `Authorise`, which is what the unexported `scoped` field on `Target` is for.
  Do not add a constructor that sets it.
- **A partially-in-scope host is a refusal, not a smaller scan.** `Authorise` asks scope twice: about
  the base path, and about an invented path beneath it (`unauthorisedProbe`). `ffuf` picks paths from
  a wordlist and `nuclei` templates pick their own, so a path-scoped `exclude` cannot be honoured
  inside either — the request is on the wire before this process could object. Refusing is the only
  answer that is true. Widening the scope is the operator's decision to make, not this package's.
- **Results are re-checked against scope after the run too** (`filterInScope`, `filterHitsInScope`).
  The requests are already sent by then; the point is that an out-of-engagement result must not enter
  a report as though burpsy meant to fetch it. Both filters return nil for a nil scope rather than
  passing everything through.
- **`Outcome` is the honest-counting type, and `len(Discoveries) == 0` is not a verdict.** Seven states
  keep "not allowlisted", "binary missing", "scope refused", "nothing asked", "ran and failed",
  "ran but was cut short" (`OutcomePartial`) and "ran" apart. `Outcome.Looked()` is the only thing a
  caller may gate a "clean" claim on; `Outcome.Reported()` is what gates showing results. A nuclei
  run killed at its timeout, stopped, whose output was not fully captured, or that stopped parsing
  keeps the hits it streamed but is `OutcomePartial` with `NucleiResult.Incomplete` naming why —
  classified from `run`'s wrapped `ErrTimedOut`/`ErrStopped`/`ErrOutputIncomplete`, never from the
  message text (burpsy-react-ui-b2wh).
- **`ffuf` has no stdout-JSON mode.** `-of` selects the format of the `-o` file, so `RunFFUF` manages
  a temp file and removes it. `nuclei` does stream JSONL to stdout under `-jsonl`. Do not "simplify"
  ffuf to a stdout parse — it does not exist.
- **Severity goes through `core.ParseSeverity`, never a private table.** That is what stops one merged
  report carrying two severity scales that only look alike; a nuclei `high` and a burpsy `high` sort
  together because they are the same value. nuclei's `info` and `unknown` both land on
  `Informational`. ffuf rows are `Informational` unconditionally — a path existing is an observation,
  and letting a wordlist drive burpsy's severity vocabulary would be nonsense.
- **Rows are grouped, and the grouping key differs by tool on purpose.** ffuf groups by status code
  (a wordlist sweep would otherwise bury every other finding under hundreds of one-path rows); nuclei
  groups by template (one issue observed *n* times, which is how burpsy's own findings already
  count). The individual paths survive as `Row.Evidence` either way.
- **Both row builders set `AdvisoryNote` rather than leaving the catalogue silently empty.** The
  bundled catalogue is keyed by Burp issue type and has no entry for "a path exists" or for a nuclei
  template id. Saying so is the difference between a deliberate absence and a hole.

## Testing Requirements

```bash
go test ./internal/extscan/...
```

The live tests need `ffuf` and `nuclei` (with a template corpus under `~/.local/nuclei-templates`) on
PATH. **Their absence fails the package rather than skipping quietly** — a skipped test and a passing
test are both silent, so a machine without the binaries would report green having verified nothing
about the tools this package claims to integrate. `BURPSY_ALLOW_UNVERIFIED_EXTSCAN=1` accepts a
deliberately reduced environment and logs what it cost. This mirrors the Chrome rule in
`scanner/runtime_coverage_test.go` and exists for the same reason.

## Dependencies

### Internal

- `core` — `Severity`/`ParseSeverity` for the one severity vocabulary, and `*core.Scope` satisfies
  `ScopeAuthoriser` at the call site.
- `report` — `Row`/`Evidence`, the output of both `Rows` methods.
- Notably **not** `sender`: this package opens no socket of its own. The external binary does, which
  is exactly why the scope gate here is a pre-flight decision rather than a per-request one.

### External

- The external `ffuf` and `nuclei` binaries at run time — invoked via `os/exec`, not linked, and only
  when the operator's `-tools` allowlist names them.
- stdlib only otherwise (`encoding/json`, `bufio`, `bytes`, `context`, `net/url`, `os/exec`, `sort`).

<!-- MANUAL: -->
