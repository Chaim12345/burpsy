//! The four FIPS 140-2 statistical RNG tests, implemented to the letter of the spec.
//!
//! # Reference
//!
//! FIPS PUB 140-2, **§4.9.1 "Power-Up Tests"**, subsection *Statistical random number generator
//! tests*. It defines exactly four tests — Monobit, Poker, Runs and Long Runs — and every one of
//! them is specified **on a single 20,000-bit sample**. The pass intervals below are quoted from
//! that section; the same tests appear in FIPS 140-1 §4.11.1 with looser intervals, and mixing the
//! two sets of constants is the classic way to get this wrong, so both are recorded here and only
//! the 140-2 numbers are used:
//!
//! | Test | FIPS 140-2 | FIPS 140-1 (**not used**) |
//! |------|-----------|---------------------------|
//! | Monobit | `9_725 < ones < 10_275` | `9_654 < ones < 10_346` |
//! | Poker | `2.16 < X < 46.17` | `1.03 < X < 57.4` |
//! | Long runs | no run of length ≥ 26 | no run of length ≥ 34 |
//!
//! Stated honestly, because this crate is about not overclaiming a statistical result: FIPS 140-2
//! **Change Notice 2** (3 December 2002) struck the statistical tests from the mandatory power-up
//! self-test list. They are not a current compliance requirement. What they remain is the standard,
//! cheap, widely-understood battery for "is this token generator obviously broken", which is the
//! use Burp's Sequencer puts them to and the use they are put to here. A pass is not a proof of
//! randomness; a failure is strong evidence of the absence of it.
//!
//! # Why the 20,000-bit block size is enforced rather than scaled
//!
//! Every interval above is a function of that sample size — the Monobit bounds are roughly
//! `10_000 ± 2.58σ` for `σ = sqrt(20_000)/2 ≈ 70.7`, and the Runs intervals are centred on
//! `20_000 / 2^(k+1)`. Rescaling them for a shorter sample is a different test with different
//! constants, and quietly running the 20,000-bit thresholds against 6,000 bits would produce a
//! confident verdict that means nothing. So the stream is cut into whole 20,000-bit blocks, each
//! block is tested exactly as specified, and the leftover bits are reported as untested rather
//! than folded in. Fewer than one whole block yields no verdict at all — see
//! [`FipsReport::tests`].

use serde::Serialize;

/// The sample size every FIPS 140-2 statistical test is defined on. Not a tunable.
pub const BLOCK_BITS: usize = 20_000;

/// Monobit: `9_725 < ones < 10_275` (FIPS 140-2 §4.9.1).
const MONOBIT_LOW: usize = 9_725;
const MONOBIT_HIGH: usize = 10_275;

/// Poker: `2.16 < X < 46.17` (FIPS 140-2 §4.9.1).
const POKER_LOW: f64 = 2.16;
const POKER_HIGH: f64 = 46.17;

/// The poker test's 4-bit segments: 20,000 / 4.
const POKER_SEGMENTS: usize = BLOCK_BITS / 4;

/// Long runs: a run of 26 or more bits of the same value fails (FIPS 140-2 §4.9.1).
const LONG_RUN_BITS: usize = 26;

/// Runs test intervals for run lengths 1..=6, where 6 means "6 or more" (FIPS 140-2 §4.9.1).
/// All twelve counts — six lengths for zeros and six for ones — must fall inside their interval.
const RUN_INTERVALS: [(usize, usize); 6] = [
    (2_315, 2_685),
    (1_114, 1_386),
    (527, 723),
    (240, 384),
    (103, 209),
    (103, 209),
];

/// How a bit stream was derived from the captured token bytes.
///
/// This matters more than it looks. A 32-character hex session id carries at most 128 bits, but its
/// *ASCII* form is 256 bits in which bit 7 of every byte is always 0 and bit 6 is fixed across the
/// digit range — so running FIPS over the characters guarantees a spectacular failure that says
/// nothing whatever about the generator, only about hex. Reporting that as a randomness verdict
/// would be precisely the kind of confidently-wrong number this project refuses to print, so the
/// encoding is detected, decoded, and named in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// The token bytes as they stand, 8 bits per byte. Right for a genuinely binary token.
    Raw,
    /// Hex digits, 4 bits per character. Case-insensitive.
    Hex,
    /// Base64 (standard or URL alphabet), 6 bits per character. `=` padding is dropped.
    Base64,
}

impl Encoding {
    /// Pick the narrowest encoding every token fits, so the bit stream carries signal rather than
    /// the alphabet's padding. Falls back to [`Encoding::Raw`], which always applies.
    pub fn detect(tokens: &[impl AsRef<[u8]>]) -> Encoding {
        if tokens.is_empty() {
            return Encoding::Raw;
        }
        let all = |f: fn(u8) -> bool| {
            tokens
                .iter()
                .all(|t| !t.as_ref().is_empty() && t.as_ref().iter().all(|&b| f(b)))
        };
        if all(|b| b.is_ascii_hexdigit()) {
            Encoding::Hex
        } else if all(is_base64_byte) {
            Encoding::Base64
        } else {
            Encoding::Raw
        }
    }
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=')
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn base64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Concatenate every token into one bit stream under `encoding`.
///
/// Bit order for [`Encoding::Raw`] is most-significant-first within each byte, which is the
/// conventional textbook and network order and is stated here so the numbers in a report can be
/// reproduced by hand. Characters that do not belong to the chosen alphabet are skipped rather than
/// mapped to zero: inventing bits would move the statistic.
pub fn bits_of(tokens: &[impl AsRef<[u8]>], encoding: Encoding) -> Vec<u8> {
    let per = match encoding {
        Encoding::Raw => 8,
        Encoding::Hex => 4,
        Encoding::Base64 => 6,
    };
    let total: usize = tokens.iter().map(|t| t.as_ref().len()).sum();
    let mut out = Vec::with_capacity(total * per);
    for token in tokens {
        for &byte in token.as_ref() {
            let (value, width) = match encoding {
                Encoding::Raw => (byte, 8u32),
                Encoding::Hex => match hex_value(byte) {
                    Some(v) => (v, 4),
                    None => continue,
                },
                Encoding::Base64 => match base64_value(byte) {
                    Some(v) => (v, 6),
                    None => continue,
                },
            };
            for i in (0..width).rev() {
                out.push((value >> i) & 1);
            }
        }
    }
    out
}

/// Statistics over the whole supplied stream, whatever its length.
///
/// Reported unconditionally and deliberately kept apart from [`FipsReport`]: these are descriptive
/// and always meaningful, whereas a FIPS *verdict* is only meaningful on a whole 20,000-bit block.
/// Mixing the two would let a 300-bit sample look like it had been tested.
#[derive(Debug, Clone, Serialize)]
pub struct BitStats {
    pub bits: usize,
    pub ones: usize,
    pub zeros: usize,
    /// Shannon entropy of the bit stream in bits per bit; 1.0 is an even split.
    pub bit_entropy: f64,
    pub longest_run: usize,
    /// Runs of length 1..=6, index 5 meaning "6 or more" — zeros then ones, as the runs test counts
    /// them.
    pub runs_zeros: [usize; 6],
    pub runs_ones: [usize; 6],
}

impl BitStats {
    pub fn of(bits: &[u8]) -> Self {
        let ones = bits.iter().filter(|&&b| b == 1).count();
        let (runs_zeros, runs_ones, longest_run) = run_histogram(bits);
        Self {
            bits: bits.len(),
            ones,
            zeros: bits.len() - ones,
            bit_entropy: binary_entropy(ones, bits.len()),
            longest_run,
            runs_zeros,
            runs_ones,
        }
    }
}

fn binary_entropy(ones: usize, total: usize) -> f64 {
    if total == 0 || ones == 0 || ones == total {
        return 0.0;
    }
    let p = ones as f64 / total as f64;
    let q = 1.0 - p;
    -(p * p.log2() + q * q.log2())
}

/// Runs of each length for zeros and ones, plus the longest run seen.
///
/// A run is a maximal sequence of equal bits (FIPS 140-2 §4.9.1). Lengths above 6 are counted in
/// the length-6 bucket, as the spec directs — the *longest* run is returned separately because the
/// long-runs test needs the true length, and clamping it into the bucket would lose exactly the
/// information that test asks for.
fn run_histogram(bits: &[u8]) -> ([usize; 6], [usize; 6], usize) {
    let mut zeros = [0usize; 6];
    let mut ones = [0usize; 6];
    let mut longest = 0usize;
    let mut i = 0usize;
    while i < bits.len() {
        let value = bits[i];
        let start = i;
        while i < bits.len() && bits[i] == value {
            i += 1;
        }
        let len = i - start;
        longest = longest.max(len);
        let bucket = len.min(6) - 1;
        if value == 1 {
            ones[bucket] += 1;
        } else {
            zeros[bucket] += 1;
        }
    }
    (zeros, ones, longest)
}

/// One of the four tests, aggregated over every block that was run.
#[derive(Debug, Clone, Serialize)]
pub struct FipsTest {
    /// `monobit` | `poker` | `runs` | `long_runs`.
    pub id: &'static str,
    pub name: &'static str,
    /// The spec section this comes from, so a reader can check the constants against the source.
    pub spec: &'static str,
    /// The pass condition, spelled out with its constants.
    pub requirement: &'static str,
    /// True only when every block passed. A suite that passed 9 blocks and failed 1 has not passed.
    pub passed: bool,
    pub blocks_passed: usize,
    pub blocks_failed: usize,
    /// What was actually measured: the first failing block's statistic, or the first block's when
    /// none failed. A bare pass/fail with no number is not something an operator can check.
    pub observed: String,
}

/// The suite's outcome over the supplied stream.
#[derive(Debug, Clone, Serialize)]
pub struct FipsReport {
    pub bits_supplied: usize,
    /// `blocks_tested * 20_000`.
    pub bits_tested: usize,
    /// The tail that did not fill a block. Reported, never folded into a block.
    pub bits_untested: usize,
    pub blocks_tested: usize,
    /// The block size the tests are defined on, echoed so the report is self-describing.
    pub block_bits: usize,
    /// `None` when not one whole block was supplied — the honest answer in that case is "not
    /// tested", not a verdict computed from thresholds that do not apply.
    pub tests: Option<[FipsTest; 4]>,
}

impl FipsReport {
    /// True when every test in an applicable suite passed. `None` when the suite did not run.
    pub fn passed(&self) -> Option<bool> {
        self.tests.as_ref().map(|t| t.iter().all(|x| x.passed))
    }

    /// Human names of the tests that failed. Empty when the suite passed or did not run.
    pub fn failures(&self) -> Vec<&'static str> {
        self.tests
            .as_ref()
            .map(|t| t.iter().filter(|x| !x.passed).map(|x| x.name).collect())
            .unwrap_or_default()
    }
}

/// One block's four results, as raw numbers.
struct BlockResult {
    monobit_ones: usize,
    poker_x: f64,
    runs_zeros: [usize; 6],
    runs_ones: [usize; 6],
    longest_run: usize,
}

impl BlockResult {
    fn monobit_ok(&self) -> bool {
        self.monobit_ones > MONOBIT_LOW && self.monobit_ones < MONOBIT_HIGH
    }
    fn poker_ok(&self) -> bool {
        self.poker_x > POKER_LOW && self.poker_x < POKER_HIGH
    }
    fn runs_ok(&self) -> bool {
        self.failing_run().is_none()
    }
    /// The first run bucket outside its interval: `(value, length, count, interval)`.
    fn failing_run(&self) -> Option<(u8, usize, usize, (usize, usize))> {
        for (i, interval) in RUN_INTERVALS.iter().enumerate() {
            for (value, counts) in [(0u8, &self.runs_zeros), (1u8, &self.runs_ones)] {
                let count = counts[i];
                if count < interval.0 || count > interval.1 {
                    return Some((value, i + 1, count, *interval));
                }
            }
        }
        None
    }
    fn long_runs_ok(&self) -> bool {
        self.longest_run < LONG_RUN_BITS
    }
}

/// Monobit test (FIPS 140-2 §4.9.1): count the ones in the 20,000-bit block.
fn monobit(block: &[u8]) -> usize {
    block.iter().filter(|&&b| b == 1).count()
}

/// Poker test (FIPS 140-2 §4.9.1).
///
/// Divide the 20,000 bits into 5,000 contiguous 4-bit segments, count the occurrences `f(i)` of
/// each of the 16 possible values, and evaluate
///
/// ```text
/// X = (16 / 5000) * Σ f(i)² - 5000
/// ```
///
/// Note that the interval is two-sided: a stream whose sixteen nibble values are *too* evenly
/// spread fails the lower bound, because a real random source does not distribute that neatly.
/// There is a known-answer test for exactly that below.
fn poker(block: &[u8]) -> f64 {
    let mut f = [0usize; 16];
    for segment in block.chunks_exact(4) {
        let v = (segment[0] << 3) | (segment[1] << 2) | (segment[2] << 1) | segment[3];
        f[v as usize] += 1;
    }
    let sum_squares: usize = f.iter().map(|&c| c * c).sum();
    (16.0 / POKER_SEGMENTS as f64) * sum_squares as f64 - POKER_SEGMENTS as f64
}

fn test_block(block: &[u8]) -> BlockResult {
    let (runs_zeros, runs_ones, longest_run) = run_histogram(block);
    BlockResult {
        monobit_ones: monobit(block),
        poker_x: poker(block),
        runs_zeros,
        runs_ones,
        longest_run,
    }
}

/// Run the suite over `bits`, in whole 20,000-bit blocks.
pub fn analyse_bits(bits: &[u8]) -> FipsReport {
    let blocks: Vec<BlockResult> = bits.chunks_exact(BLOCK_BITS).map(test_block).collect();
    let blocks_tested = blocks.len();
    let report = FipsReport {
        bits_supplied: bits.len(),
        bits_tested: blocks_tested * BLOCK_BITS,
        bits_untested: bits.len() - blocks_tested * BLOCK_BITS,
        blocks_tested,
        block_bits: BLOCK_BITS,
        tests: None,
    };
    if blocks.is_empty() {
        return report;
    }

    let monobit_test = aggregate(
        "monobit",
        "Monobit Test",
        "FIPS 140-2 §4.9.1",
        "9725 < ones < 10275 per 20000-bit block",
        &blocks,
        BlockResult::monobit_ok,
        |b| format!("{} ones in 20000 bits", b.monobit_ones),
    );
    let poker_test = aggregate(
        "poker",
        "Poker Test",
        "FIPS 140-2 §4.9.1",
        "2.16 < X < 46.17, X = (16/5000)·Σf(i)² - 5000",
        &blocks,
        BlockResult::poker_ok,
        |b| format!("X = {:.4}", b.poker_x),
    );
    let runs_test = aggregate(
        "runs",
        "Runs Test",
        "FIPS 140-2 §4.9.1",
        "runs of length 1..6 within 2315-2685, 1114-1386, 527-723, 240-384, 103-209, 103-209 \
         for both zeros and ones",
        &blocks,
        BlockResult::runs_ok,
        |b| match b.failing_run() {
            Some((value, len, count, (lo, hi))) => format!(
                "{count} runs of {len} {}(s) — outside {lo}-{hi}",
                if value == 1 { "one" } else { "zero" }
            ),
            None => format!(
                "zeros {:?}, ones {:?} for lengths 1..6",
                b.runs_zeros, b.runs_ones
            ),
        },
    );
    let long_runs_test = aggregate(
        "long_runs",
        "Long Runs Test",
        "FIPS 140-2 §4.9.1",
        "no run of length 26 or more",
        &blocks,
        BlockResult::long_runs_ok,
        |b| format!("longest run {} bits", b.longest_run),
    );

    FipsReport {
        tests: Some([monobit_test, poker_test, runs_test, long_runs_test]),
        ..report
    }
}

/// Collapse one test across blocks. Reports the first *failing* block's numbers where there is one,
/// because "which block broke and by how much" is the only useful thing to show next to a failure.
fn aggregate(
    id: &'static str,
    name: &'static str,
    spec: &'static str,
    requirement: &'static str,
    blocks: &[BlockResult],
    ok: fn(&BlockResult) -> bool,
    describe: impl Fn(&BlockResult) -> String,
) -> FipsTest {
    let blocks_passed = blocks.iter().filter(|b| ok(b)).count();
    let blocks_failed = blocks.len() - blocks_passed;
    let shown = match blocks.iter().find(|b| !ok(b)) {
        Some(failing) => failing,
        None => &blocks[0],
    };
    FipsTest {
        id,
        name,
        spec,
        requirement,
        passed: blocks_failed == 0,
        blocks_passed,
        blocks_failed,
        observed: describe(shown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 20,000 bits, `0101…`. Chosen because it is the textbook demonstration that the monobit test
    /// alone is worthless: the ones count is *exactly* 10,000, and the stream is as far from random
    /// as a stream can be.
    fn alternating() -> Vec<u8> {
        (0..BLOCK_BITS).map(|i| (i % 2) as u8).collect()
    }

    /// 5,000 nibbles cycling `0,1,…,15`. Every 4-bit value appears 312 or 313 times — a *perfectly*
    /// even spread, which is why it fails the poker test's lower bound.
    fn uniform_nibbles() -> Vec<u8> {
        let mut bits = Vec::with_capacity(BLOCK_BITS);
        for k in 0..POKER_SEGMENTS {
            let v = (k % 16) as u8;
            for i in (0..4).rev() {
                bits.push((v >> i) & 1);
            }
        }
        bits
    }

    /// xorshift64* — a small, well-specified PRNG, reimplemented here so the reference values below
    /// can be recomputed from scratch in any language. Big-endian bytes of each 64-bit output.
    fn xorshift64star(seed: u64, nbytes: usize) -> Vec<u8> {
        let mut x = seed;
        let mut out = Vec::with_capacity(nbytes + 8);
        while out.len() < nbytes {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            out.extend_from_slice(&x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes());
        }
        out.truncate(nbytes);
        out
    }

    /// The known-answer test. Every number here was computed independently (in Python) from the
    /// same xorshift64* definition above before this implementation existed, so agreement is
    /// evidence the Rust is right rather than evidence it is self-consistent.
    ///
    /// Reference for seed 1, 2,500 bytes = 20,000 bits:
    ///   first bytes 71,228,206,75,137,108,221,29 · ones 9,956 · Σf(i)² 1,566,958 · X 14.2656
    ///   run lengths 1..6, zeros [2491,1281,598,297,166,167] ones [2517,1282,587,302,151,161]
    ///   longest run 18 · 10,000 runs in total
    #[test]
    fn the_suite_reproduces_an_independently_computed_reference_stream() {
        let stream = xorshift64star(1, 2_500);
        assert_eq!(
            &stream[..8],
            &[71u8, 228, 206, 75, 137, 108, 221, 29],
            "the PRNG itself drifted, so nothing below would mean anything"
        );
        let bits = bits_of(&[stream], Encoding::Raw);
        assert_eq!(bits.len(), BLOCK_BITS);

        let block = test_block(&bits);
        assert_eq!(
            block.monobit_ones, 9_956,
            "monobit count must match the reference"
        );
        // X = (16·1_566_958 - 25_000_000)/5_000 = 71_328/5_000 = 14.2656, exactly representable.
        assert!(
            (block.poker_x - 14.2656).abs() < 1e-9,
            "poker X must match the reference: got {}",
            block.poker_x
        );
        assert_eq!(block.runs_zeros, [2_491, 1_281, 598, 297, 166, 167]);
        assert_eq!(block.runs_ones, [2_517, 1_282, 587, 302, 151, 161]);
        assert_eq!(block.longest_run, 18);
        assert_eq!(
            block
                .runs_zeros
                .iter()
                .chain(block.runs_ones.iter())
                .sum::<usize>(),
            10_000,
            "every run must be counted exactly once"
        );

        let report = analyse_bits(&bits);
        assert_eq!(report.blocks_tested, 1);
        assert_eq!(report.bits_untested, 0);
        assert_eq!(
            report.passed(),
            Some(true),
            "a decent PRNG must pass all four: {:?}",
            report.failures()
        );
    }

    /// The pair of vectors that prove the tests are independent rather than four names for one
    /// check: an alternating stream has a perfect ones count and fails everything else.
    #[test]
    fn an_alternating_stream_passes_monobit_and_fails_the_rest() {
        let bits = alternating();
        let block = test_block(&bits);
        assert_eq!(block.monobit_ones, 10_000);
        assert!(block.monobit_ok(), "10000 ones is dead centre");
        // 5,000 segments all equal to 0b0101, so Σf(i)² = 5000² and X = 16·5000 - 5000 = 75_000.
        assert!(
            (block.poker_x - 75_000.0).abs() < 1e-6,
            "got {}",
            block.poker_x
        );
        assert!(!block.poker_ok());
        assert_eq!(block.runs_zeros, [10_000, 0, 0, 0, 0, 0]);
        assert_eq!(block.runs_ones, [10_000, 0, 0, 0, 0, 0]);
        assert!(!block.runs_ok());
        assert_eq!(block.longest_run, 1);
        assert!(
            block.long_runs_ok(),
            "no run reaches 26, so long-runs genuinely passes here"
        );

        let report = analyse_bits(&bits);
        assert_eq!(report.passed(), Some(false));
        assert_eq!(report.failures(), vec!["Poker Test", "Runs Test"]);
    }

    /// The poker interval is two-sided and the lower bound does real work. This vector's sixteen
    /// nibble counts are 313×8 and 312×8, which gives Σf(i)² = 1,562,504 and therefore
    /// `X = (16·1_562_504 - 25_000_000)/5_000 = 64/5_000 = 0.0128` — exact rational arithmetic, so
    /// this is a true known answer rather than a tolerance check.
    #[test]
    fn a_too_even_nibble_spread_fails_the_poker_lower_bound() {
        let bits = uniform_nibbles();
        let block = test_block(&bits);
        assert!(
            (block.poker_x - 0.0128).abs() < 1e-9,
            "expected exactly 64/5000: got {}",
            block.poker_x
        );
        assert!(
            !block.poker_ok(),
            "0.0128 is below the 2.16 floor: too uniform to be random"
        );
        assert_eq!(
            block.monobit_ones, 9_996,
            "popcount 0..15 is 32 per cycle, so this passes monobit"
        );
        assert!(block.monobit_ok());
    }

    #[test]
    fn a_constant_stream_fails_every_test_including_long_runs() {
        let bits = vec![0u8; BLOCK_BITS];
        let block = test_block(&bits);
        assert_eq!(block.monobit_ones, 0);
        assert_eq!(block.longest_run, BLOCK_BITS);
        assert!(!block.long_runs_ok());
        let report = analyse_bits(&bits);
        assert_eq!(report.failures().len(), 4, "all four must bite");
    }

    /// The long-runs boundary is "26 or more", so 25 passes and 26 fails. Off-by-one here would be
    /// invisible on real data and wrong on the one case the test exists for.
    #[test]
    fn the_long_run_boundary_is_twenty_six_not_twenty_five() {
        let with_run = |len: usize| {
            let mut bits = Vec::with_capacity(BLOCK_BITS);
            bits.extend(std::iter::repeat_n(1u8, len));
            // Fill the rest with an alternating tail so nothing else produces a long run.
            while bits.len() < BLOCK_BITS {
                bits.push(0);
                if bits.len() < BLOCK_BITS {
                    bits.push(1);
                }
            }
            test_block(&bits)
        };
        assert!(with_run(25).long_runs_ok(), "25 is not yet a long run");
        assert!(!with_run(26).long_runs_ok(), "26 is the failure threshold");
    }

    /// The whole point of the block rule: a short sample gets no verdict, and says how short it was.
    #[test]
    fn a_sample_shorter_than_one_block_is_reported_untested_rather_than_judged() {
        let bits = vec![1u8; BLOCK_BITS - 1];
        let report = analyse_bits(&bits);
        assert!(
            report.tests.is_none(),
            "19999 bits must not be judged against 20000-bit thresholds"
        );
        assert_eq!(report.passed(), None);
        assert_eq!(report.blocks_tested, 0);
        assert_eq!(report.bits_untested, BLOCK_BITS - 1);
        assert!(report.failures().is_empty());
    }

    /// A leftover tail must be counted as untested, not quietly dropped and not padded.
    #[test]
    fn leftover_bits_beyond_the_last_whole_block_are_reported_not_absorbed() {
        let stream = xorshift64star(7, 2_500 + 13);
        let bits = bits_of(&[stream], Encoding::Raw);
        let report = analyse_bits(&bits);
        assert_eq!(report.blocks_tested, 1);
        assert_eq!(report.bits_tested, BLOCK_BITS);
        assert_eq!(report.bits_untested, 13 * 8);
        assert_eq!(report.bits_supplied, BLOCK_BITS + 13 * 8);
    }

    /// One failing block among many fails the suite. "Mostly passed" is not a pass.
    #[test]
    fn one_bad_block_among_good_ones_fails_the_suite_and_names_the_count() {
        let mut bits = bits_of(&[xorshift64star(1, 2_500)], Encoding::Raw);
        bits.extend(std::iter::repeat_n(0u8, BLOCK_BITS));
        let report = analyse_bits(&bits);
        assert_eq!(report.blocks_tested, 2);
        assert_eq!(report.passed(), Some(false));
        let tests = report.tests.as_ref().unwrap();
        let monobit = &tests[0];
        assert_eq!(monobit.blocks_passed, 1);
        assert_eq!(monobit.blocks_failed, 1);
        assert!(
            monobit.observed.contains("0 ones"),
            "the failing block's numbers are what should be shown: {}",
            monobit.observed
        );
    }

    // ---- encodings --------------------------------------------------------------------------

    #[test]
    fn hex_tokens_are_decoded_to_four_bits_a_character_rather_than_eight() {
        let tokens = [b"00ff".to_vec(), b"a5A5".to_vec()];
        assert_eq!(Encoding::detect(&tokens), Encoding::Hex);
        let bits = bits_of(&tokens, Encoding::Hex);
        assert_eq!(
            bits.len(),
            2 * 4 * 4,
            "two 4-character tokens at 4 bits per hex digit, not 8"
        );
        assert_eq!(&bits[..8], &[0, 0, 0, 0, 0, 0, 0, 0], "\"00\"");
        assert_eq!(&bits[8..16], &[1, 1, 1, 1, 1, 1, 1, 1], "\"ff\"");
        // 0xa5A5 -> 1010 0101 1010 0101, and the case of the digits must not matter.
        assert_eq!(
            &bits[16..],
            &[1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1]
        );
    }

    /// The reason the encoding step exists at all, made checkable — and the single most important
    /// test in this file, because it is the difference between a report that means something and a
    /// report that libels a perfectly good generator.
    ///
    /// The tokens are the *same* 2,500 reference bytes as the known-answer test above, hex-encoded
    /// into 250 tokens of 20 characters. Read as hex they are that reference stream exactly, and pass
    /// all four tests. Read as ASCII they are 40,000 bits in which the top bit of every byte is
    /// structurally zero, and both blocks fail monobit by more than a thousand — an artefact of hex,
    /// not of the generator. Independently computed reference: hex view 9,956 ones; ASCII view 8,698
    /// and 8,750 ones.
    #[test]
    fn the_same_tokens_pass_decoded_and_fail_as_ascii_which_is_why_encoding_is_detected() {
        let stream = xorshift64star(1, 2_500);
        let tokens: Vec<Vec<u8>> = stream
            .chunks(10)
            .map(|c| {
                c.iter()
                    .flat_map(|b| format!("{b:02x}").into_bytes())
                    .collect()
            })
            .collect();
        assert_eq!(tokens.len(), 250);
        assert_eq!(tokens[0].len(), 20);
        assert_eq!(Encoding::detect(&tokens), Encoding::Hex);

        let hex_bits = bits_of(&tokens, Encoding::Hex);
        assert_eq!(hex_bits.len(), BLOCK_BITS);
        assert_eq!(
            hex_bits,
            bits_of(&[stream], Encoding::Raw),
            "hex-encoding bytes and decoding them again must be the identity on the bit stream"
        );
        let decoded = analyse_bits(&hex_bits);
        assert_eq!(
            decoded.passed(),
            Some(true),
            "decoded, this is the reference stream and must pass: {:?}",
            decoded.failures()
        );

        let ascii_bits = bits_of(&tokens, Encoding::Raw);
        assert_eq!(ascii_bits.len(), BLOCK_BITS * 2);
        assert!(
            ascii_bits.iter().step_by(8).all(|&b| b == 0),
            "the top bit of every ASCII byte is structurally zero — that is the whole problem"
        );
        let as_ascii = analyse_bits(&ascii_bits);
        assert_eq!(as_ascii.blocks_tested, 2);
        let monobit_row = &as_ascii.tests.as_ref().unwrap()[0];
        assert!(!monobit_row.passed);
        assert_eq!(
            monobit_row.blocks_failed, 2,
            "both ASCII blocks must fail, and for a reason that is about hex rather than randomness"
        );
        assert!(
            monobit_row.observed.contains("8698"),
            "the first failing block's real count belongs in the report: {}",
            monobit_row.observed
        );
    }

    #[test]
    fn base64_is_detected_and_decoded_at_six_bits_a_character() {
        let tokens = [b"AAAA".to_vec(), b"////".to_vec(), b"a-_z".to_vec()];
        assert_eq!(Encoding::detect(&tokens), Encoding::Base64);
        let bits = bits_of(&tokens[..1], Encoding::Base64);
        assert_eq!(bits.len(), 24);
        assert!(bits.iter().all(|&b| b == 0), "'A' is value 0");
        let ones = bits_of(&tokens[1..2], Encoding::Base64);
        assert!(ones.iter().all(|&b| b == 1), "'/' is value 63");
    }

    #[test]
    fn a_non_alphabet_token_falls_back_to_raw_bytes() {
        let tokens = [b"tok=en!".to_vec()];
        assert_eq!(Encoding::detect(&tokens), Encoding::Raw);
        assert_eq!(bits_of(&tokens, Encoding::Raw).len(), 7 * 8);
    }

    /// Hex digits are also base64 characters, so detection order decides. Narrowest wins, because a
    /// hex string read as base64 would carry two dead bits in every character.
    #[test]
    fn detection_prefers_hex_over_base64_when_both_would_fit() {
        let tokens = [b"deadbeef".to_vec()];
        assert_eq!(Encoding::detect(&tokens), Encoding::Hex);
    }

    #[test]
    fn an_empty_token_set_does_not_claim_an_encoding_it_cannot_know() {
        let empty: [Vec<u8>; 0] = [];
        assert_eq!(Encoding::detect(&empty), Encoding::Raw);
        assert_eq!(bits_of(&empty, Encoding::Raw).len(), 0);
        let report = analyse_bits(&[]);
        assert_eq!(report.blocks_tested, 0);
        assert!(report.tests.is_none());
    }

    #[test]
    fn bit_stats_describe_a_stream_of_any_length_without_pretending_it_was_tested() {
        let stats = BitStats::of(&[1, 1, 1, 0, 0, 1]);
        assert_eq!((stats.bits, stats.ones, stats.zeros), (6, 4, 2));
        assert_eq!(stats.longest_run, 3);
        assert_eq!(stats.runs_ones[0], 1, "the trailing single 1");
        assert_eq!(stats.runs_ones[2], 1, "the leading run of 3");
        assert_eq!(stats.runs_zeros[1], 1, "one run of two zeros");
        assert!((stats.bit_entropy - 0.9182958).abs() < 1e-6, "H(4/6)");
    }
}
