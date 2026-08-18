<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# sequencer

## Purpose

Statistical randomness analysis of captured session tokens — the Go port of
`../../crates/sequencer`. It answers one question two ways: a character-level view (alphabet,
per-position variation, Shannon entropy) and the bit-level FIPS 140-2 battery, assembled into one
`SequencerReport` with a `Grade`.

## Two APIs in this package (a Go-specific split)

- **The faithful report** (`report.go` + `fips.go`): `AnalyseReport(tokens)` / `AnalyseAs(tokens, *Encoding)`
  build a `SequencerReport` (`Grade`, `CharacterAnalysis`, `FipsReport`). This is the port that
  mirrors the Rust crate's `lib.rs`/`chars.rs`/`fips.rs` to the letter and is the authority.
- **A simpler descriptive surface** (`sequencer.go`): `TokenList`, `AnalyseCharacters`,
  `ShannonEntropy`, `ChiSquare`, `SerialCorrelation`, `MonteCarloPi`, `RateEntropy`/`Rating`,
  `DetectPatterns`, `Analyse`. These are extra descriptive statistics with no Rust counterpart in
  the crate's structure; they do not feed the FIPS verdict.

## Key Files

| File | Description |
|------|-------------|
| `fips.go` | The four FIPS 140-2 tests (monobit, poker, runs, long-runs), `Encoding` (raw/hex/base64) with `DetectEncoding`, `BitsOf`, `BitStats`, `FipsReport`, `AnalyseFips`/`AnalyseFipsBits`. `BlockBits = 20000`; every threshold is quoted with its spec section |
| `report.go` | `Grade`, `CharCount`, `PositionStats`, `CharacterAnalysis`, `SequencerReport`; `AnalyseReport`/`AnalyseAs`, `verdictFor`, `TokensFromText`. Assembles the verdict and names its assumptions |
| `sequencer.go` | `TokenList` (mutex-guarded collector) and the descriptive statistics surface listed above |

## For AI Agents

### The refusals this port is built on — do not "fix" them

1. **A verdict is only printed where the test applies.** Every FIPS threshold is a function of a
   20,000-bit sample (`BlockBits`); the stream is cut into **whole** 20,000-bit blocks, each tested
   as specified, and the remainder reported as untested. Fewer than one whole block yields a nil
   `Tests` and `GradeInsufficient`. Rescaling the constants for a shorter sample is the tempting and
   wrong "improvement".
2. **The bit stream is decoded before it is tested.** `DetectEncoding` picks the narrowest alphabet
   that fits (raw/hex/base64) and the report names it, because a hex id read as ASCII fails monobit
   for reasons about hex, not about the generator. `AnalyseAs` lets the operator force an encoding,
   and the report then says it was supplied rather than detected.

The 140-2 (not 140-1) constants are hard-coded: monobit `9725 < ones < 10275`, poker
`2.16 < X < 46.17`, long run fails at length `>= 26`, and the twelve runs intervals for lengths
1..6. The poker interval is two-sided, so a perfectly even nibble spread *fails* it — that is
correct, not a bug.

### Also deliberately absent

- **No Burp-comparable "effective entropy".** What is reported is raw per-position Shannon entropy,
  the sample ceiling that bounds it, and an explicit "assumes positional independence" flag —
  `CharacterAnalysis` names the assumption so a sum is not mistaken for a measurement.
- **No token store beyond the caller's list**, and per-position reporting is capped
  (`MaxPositionsReported = 256`) so a pathological huge "token" cannot turn a report into a memory
  problem; the truncation is stated.

### Divergence from Rust: no live capture, no network, no dependencies

The Rust crate has a `capture.rs` (an `Extractor`, `CaptureProgress`, and a live loop that sends
through `AuthorisedSender`) and depends on `core` and `sender`. **This Go package has none of
that** — it imports no other `internal/` package and no external module; it is pure standard
library. Tokens arrive as `[]string`, are analysed, and are dropped. Any live-capture loop lives
elsewhere in the Go tree, so the Rust "the network is not this crate's to touch" rule is moot here —
there is simply no egress path in this package to grow one on. `MinTokensForConfidence` is 100.

## Testing Requirements

```bash
go test ./internal/sequencer/...
```

Tests are inline (`fips_test.go`, `report_test.go`) and use known-answer vectors; they touch no
network.

## Dependencies

### Internal

None. This package imports no other `internal/` package.

### External

None beyond the Go standard library (`math`, `sort`, `strings`, `sync`, `encoding/json`).

<!-- MANUAL: -->
