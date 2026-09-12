<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# sequencer

## Purpose

Statistical randomness analysis of captured session tokens — the Go port of
`../../crates/sequencer`, plus four more tests Burp's Sequencer runs that the Rust crate does not.
It answers one question three ways: a character-level view (alphabet, per-position variation,
Shannon entropy), the bit-level FIPS 140-2 battery, and the extended battery (transition, spectral,
correlation, compression), assembled into one `SequencerReport` with a `Grade`.

## Three APIs in this package (a Go-specific split)

- **The faithful report** (`report.go` + `fips.go`): `AnalyseReport(tokens)` / `AnalyseAs(tokens, *Encoding)`
  build a `SequencerReport` (`Grade`, `CharacterAnalysis`, `FipsReport`). This is the port that
  mirrors the Rust crate's `lib.rs`/`chars.rs`/`fips.rs` to the letter and is the authority.
- **The extended battery** (`advanced.go` + `chi.go`): `SequencerReport.Advanced`, four further
  tests that exist in Burp and not in the Rust crate, plus the chi-square upper tail they read
  their verdicts against. **Go-only: there is no Rust counterpart to port**, so this is Burp parity
  and it never touches `Grade` (`advanced.affects_grade` is always false and says so on the wire).
- **A simpler descriptive surface** (`sequencer.go`): `TokenList`, `AnalyseCharacters`,
  `ShannonEntropy`, `ChiSquare`, `SerialCorrelation`, `MonteCarloPi`, `RateEntropy`/`Rating`,
  `DetectPatterns`, `Analyse`. These are extra descriptive statistics with no Rust counterpart in
  the crate's structure; they do not feed the FIPS verdict.

## Key Files

| File | Description |
|------|-------------|
| `fips.go` | The four FIPS 140-2 tests (monobit, poker, runs, long-runs), `Encoding` (raw/hex/base64) with `DetectEncoding`, `BitsOf`, `BitStats`, `FipsReport`, `AnalyseFips`/`AnalyseFipsBits`. `BlockBits = 20000`; every threshold is quoted with its spec section |
| `report.go` | `Grade`, `CharCount`, `PositionStats`, `CharacterAnalysis`, `SequencerReport`; `AnalyseReport`/`AnalyseAs`, `verdictFor`, `TokensFromText`. Assembles the verdict and names its assumptions |
| `advanced.go` | The extended battery: `AdvancedTest`/`AdvancedReport`, `advancedFor`, and the four tests (`transitionTest`, `spectralTest`, `correlationTest`, `compressionTest`) with every constant and refusal documented |
| `chi.go` | `chiSquareUpperTail(x, df)` — `Q(df/2, x/2)` by the standard series / continued-fraction split. The distribution written out rather than assumed; `chi_test.go` pins it against closed forms and published critical values |
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
3. **The extended battery never moves the grade.** `Grade` and `Verdict` stay byte-for-byte the
   Rust ones, so a compression finding shows up in `advanced.tests[]` and nowhere else — folding it
   in would break parity in a way no Rust test could see. Every verdict in the battery is held to a
   Bonferroni-corrected 0.05 over that test's own comparison count, because the spectral and
   correlation tables span hundreds of comparisons and an uncorrected threshold manufactures flags
   on honest generators. The correction is deliberately conservative: it over-corrects, and
   under-correcting is the failure mode this package exists to refuse.
4. **A test that cannot run says so, with the count it needed.** Each member reports either its
   statistic or `tested: false` with a concrete reason — the spectral test's tuplets above the
   stream's reach, the correlation test's asymptotic score statistic below 30 tokens, the
   compression test's DEFLATE framing below 512 tokens, and the transition test's Cochran
   conditions (no expected cell under 1, no more than 20% under 5), each with the sample size that
   would make it runnable. Do not relax those floors to make a row render a verdict: a chi-square
   p-value from a sparse table is wrong, not conservative, and wrong in the direction of flagging.

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

None beyond the Go standard library (`math`, `sort`, `strings`, `sync`, `encoding/json`, and — for
the extended battery — `math/bits`, `bytes`, `compress/zlib`, `crypto/sha256`, `fmt`).

<!-- MANUAL: -->
