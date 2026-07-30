//! burpsy-sequencer — statistical randomness analysis of captured session tokens.
//!
//! # Why the crate is shaped this way
//!
//! Burp's Sequencer answers one question: is the thing this application uses as a session id or a
//! CSRF token actually unpredictable? It answers it two ways at once — a character-level view (what
//! alphabet, how much does each position vary) and a bit-level view (the FIPS 140-2 battery) — and
//! it feeds them from either a live capture loop or a block of pasted text.
//!
//! Three shaping decisions here, and each of them is a refusal:
//!
//! **1. A verdict is only printed where the test it comes from applies.** Every FIPS 140-2 threshold
//! is a function of a 20,000-bit sample. Running those constants against 4,000 bits produces a
//! confident answer to a question nobody asked, so [`fips`] cuts the stream into whole blocks, tests
//! each one, and reports the remainder as untested. A sample too short for one block gets no verdict
//! at all — `tests: None`, `verdict: insufficient` — rather than a scaled guess. That is the root
//! `AGENTS.md` rule about honest counting applied to statistics: a partial result must not be able
//! to look complete.
//!
//! **2. The bit stream is decoded before it is tested.** A 32-character hex session id read as ASCII
//! is 256 bits of which a quarter are structurally fixed by the hex alphabet, and it fails every
//! FIPS test spectacularly for reasons that have nothing to do with the generator. So the token
//! encoding is detected and decoded first, and named in the report. See
//! [`fips::Encoding`] — there is a test that the same tokens pass decoded and fail as ASCII, which
//! is the whole argument in one assertion.
//!
//! **3. The network is not this crate's to touch.** Live capture goes through
//! [`burpsy_sender::AuthorisedSender`], the workspace's one authorising path to a socket, so a
//! capture aimed outside the engagement is refused against its actual outbound bytes rather than
//! against the host somebody typed. This crate names no transport and its `tokio` features are
//! narrowed to `time`; the only reason it wants the runtime at all is to wait between requests.
//!
//! # Deliberately absent
//!
//! * **No significance levels or effective-entropy estimate.** Burp reports entropy at a chosen
//!   significance level from a set of per-position hypothesis tests. That is a bigger statistical
//!   claim than four counted thresholds, and half-implementing it would produce a number that looks
//!   like Burp's and is not comparable to it. What is here instead is the raw per-position entropy,
//!   the sample ceiling that bounds it, and an explicit note that summing positions assumes
//!   independence.
//! * **No token store.** Tokens arrive as [`bytes::Bytes`], are analysed, and are dropped. Nothing
//!   here is persisted, so a capture cannot quietly become the largest thing in the process.
//! * **No scope of its own.** Like `intruder`'s engine, this crate has no concept of engagement
//!   scope and should not grow one. The decision belongs to the sender it is handed.
//!
//! # Layout
//!
//! * [`chars`] — alphabet, per-position distribution, Shannon entropy;
//! * [`fips`] — the four FIPS 140-2 statistical tests and the bit-stream encodings;
//! * [`capture`] — the live capture loop and response-side token extraction.

pub mod capture;
pub mod chars;
pub mod fips;

pub use capture::{
    CaptureConfig, CaptureEnd, CaptureOutcome, CaptureProgress, DEFAULT_TOKENS, Extractor,
    MAX_TOKENS, ResponsePart, capture,
};
pub use chars::{CharCount, CharacterAnalysis, PositionStats};
pub use fips::{BLOCK_BITS, BitStats, Encoding, FipsReport, FipsTest};

use serde::Serialize;

/// Tokens below which no part of this analysis is worth acting on.
///
/// The character-level tests are still computed and reported — they are descriptive and a small
/// sample is still a fact about the tokens — but the report carries a warning, because with fewer
/// samples than the alphabet is wide every position is capped at `log2(tokens)` bits however good
/// the generator is. 100 is the conventional floor and matches [`DEFAULT_TOKENS`].
pub const MIN_TOKENS_FOR_CONFIDENCE: usize = 100;

/// How much of an answer the sample supports.
///
/// Three states rather than a bare boolean because "we did not have enough data" is a different
/// thing from "it failed", and collapsing them is exactly how a tool ends up reporting a weak
/// generator that was never tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    /// Not one whole FIPS block. No bit-level verdict was reached.
    Insufficient,
    /// Every applicable test passed.
    Pass,
    /// At least one applicable test failed.
    Fail,
}

/// The whole analysis of one token sample.
#[derive(Debug, Clone, Serialize)]
pub struct SequencerReport {
    pub tokens: usize,
    /// Which bit view the FIPS tests were run over, and why the numbers are what they are.
    pub encoding: Encoding,
    /// True when the encoding was chosen by [`Encoding::detect`] rather than supplied.
    pub encoding_detected: bool,
    pub characters: CharacterAnalysis,
    pub bits: BitStats,
    pub fips: FipsReport,
    pub grade: Grade,
    /// One sentence an operator can act on, with the numbers in it.
    pub verdict: String,
    /// Everything that limits how far the verdict can be trusted. Never empty when it should not be.
    pub warnings: Vec<String>,
}

/// Analyse a token sample, detecting the encoding.
pub fn analyse(tokens: &[impl AsRef<[u8]>]) -> SequencerReport {
    analyse_as(tokens, None)
}

/// Analyse a token sample, optionally forcing the bit-level encoding.
///
/// Forcing it is the operator's escape hatch for the case detection cannot see: tokens that happen
/// to be all hex characters but are really opaque bytes carried in hex, or the reverse. Detection is
/// a heuristic over the alphabet and says so in the report.
pub fn analyse_as(tokens: &[impl AsRef<[u8]>], encoding: Option<Encoding>) -> SequencerReport {
    let detected = encoding.is_none();
    let encoding = encoding.unwrap_or_else(|| Encoding::detect(tokens));
    let characters = chars::analyse(tokens);
    let bit_stream = fips::bits_of(tokens, encoding);
    let bits = BitStats::of(&bit_stream);
    let fips = fips::analyse_bits(&bit_stream);

    let mut warnings = Vec::new();
    if tokens.is_empty() {
        warnings.push("no tokens were supplied, so there is nothing to analyse".to_string());
    } else if tokens.len() < MIN_TOKENS_FOR_CONFIDENCE {
        warnings.push(format!(
            "only {} token(s): fewer than {MIN_TOKENS_FOR_CONFIDENCE} caps every character position \
             at log2({}) = {:.1} bits however good the generator is, so a low per-position entropy \
             here is a fact about the sample and not about the application",
            tokens.len(),
            tokens.len(),
            characters.entropy_ceiling_bits,
        ));
    }
    if characters.min_len != characters.max_len {
        warnings.push(format!(
            "token lengths vary ({} to {}): positions past {} have fewer samples than the rest, and \
             a variable-length token is itself worth explaining",
            characters.min_len, characters.max_len, characters.min_len,
        ));
    }
    if characters.positions_truncated {
        warnings.push(format!(
            "only the first {} character positions are reported, of {}",
            characters.positions.len(),
            characters.max_len,
        ));
    }
    if fips.bits_untested > 0 && fips.blocks_tested > 0 {
        warnings.push(format!(
            "{} bit(s) past the last whole {BLOCK_BITS}-bit block were not tested",
            fips.bits_untested,
        ));
    }
    if detected && encoding == Encoding::Raw && characters.alphabet_size <= 64 {
        warnings.push(format!(
            "the tokens use {} distinct byte values but did not fit the hex or base64 alphabets, so \
             the bit view is the raw characters — if these are text-encoded bytes in some other \
             alphabet, the bit-level results describe the encoding as much as the generator",
            characters.alphabet_size,
        ));
    }

    let (grade, verdict) = verdict_for(tokens.len(), &characters, &fips);
    SequencerReport {
        tokens: tokens.len(),
        encoding,
        encoding_detected: detected,
        characters,
        bits,
        fips,
        grade,
        verdict,
        warnings,
    }
}

fn verdict_for(
    tokens: usize,
    characters: &CharacterAnalysis,
    fips: &FipsReport,
) -> (Grade, String) {
    match fips.passed() {
        None => (
            Grade::Insufficient,
            format!(
                "No bit-level verdict: {} bit(s) supplied and the FIPS 140-2 suite is defined on a \
                 {BLOCK_BITS}-bit sample, so not one whole block could be tested. \
                 {tokens} token(s) at this length would need about {} in total. The character-level \
                 analysis below stands on its own — it measures {:.1} bit(s) of entropy across {} \
                 position(s).",
                fips.bits_supplied,
                tokens_needed(tokens, fips.bits_supplied),
                characters.total_entropy_bits,
                characters.positions.len(),
            ),
        ),
        Some(true) => (
            Grade::Pass,
            format!(
                "All four FIPS 140-2 tests passed over {} whole {BLOCK_BITS}-bit block(s) from {} \
                 token(s). Character-level entropy is {:.1} bit(s) per token across {} position(s), \
                 against a {:.1}-bit ceiling for this alphabet and length. A pass is evidence \
                 against an obviously broken generator, not proof of unpredictability.",
                fips.blocks_tested,
                tokens,
                characters.total_entropy_bits,
                characters.positions.len(),
                characters.max_possible_bits,
            ),
        ),
        Some(false) => {
            let failed = fips.failures();
            (
                Grade::Fail,
                format!(
                    "{} of 4 FIPS 140-2 tests failed over {} whole {BLOCK_BITS}-bit block(s) from {} \
                     token(s): {}. Character-level entropy is {:.1} bit(s) per token across {} \
                     position(s), against a {:.1}-bit ceiling. Check the per-position distribution \
                     for a fixed or slow-moving position before concluding the source is weak.",
                    failed.len(),
                    fips.blocks_tested,
                    tokens,
                    failed.join(", "),
                    characters.total_entropy_bits,
                    characters.positions.len(),
                    characters.max_possible_bits,
                ),
            )
        }
    }
}

/// Roughly how many tokens of the observed size would fill one FIPS block.
///
/// Deliberately approximate and phrased that way in the verdict: it is there so an operator knows
/// whether they are short by a hundred tokens or by a hundred thousand.
fn tokens_needed(tokens: usize, bits_supplied: usize) -> String {
    if tokens == 0 || bits_supplied == 0 {
        return format!("{BLOCK_BITS} bits' worth");
    }
    let per_token = bits_supplied as f64 / tokens as f64;
    let needed = (BLOCK_BITS as f64 / per_token).ceil() as usize;
    format!("{needed} token(s)")
}

/// Split a pasted block of text into one token per line.
///
/// The manual path, and the reason it is a function rather than an inline `lines()` call at the HTTP
/// boundary: an operator pastes from a spreadsheet or a log, so blank lines and trailing whitespace
/// are the normal case rather than an error, and dropping them here means every caller drops them
/// the same way. Interior whitespace is left alone — a token containing a space is unusual but it is
/// not this function's place to decide it is a mistake.
pub fn tokens_from_text(text: &str) -> Vec<bytes::Bytes> {
    text.lines()
        .map(|line| line.trim_matches(|c: char| c.is_whitespace()))
        .filter(|line| !line.is_empty())
        .map(|line| bytes::Bytes::copy_from_slice(line.as_bytes()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_tokens(seed: u64, count: usize, bytes_each: usize) -> Vec<bytes::Bytes> {
        // xorshift64*, the same generator the fips known-answer tests use.
        let mut x = seed;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut token = String::with_capacity(bytes_each * 2);
            for _ in 0..bytes_each {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                let byte = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
                token.push_str(&format!("{byte:02x}"));
            }
            out.push(bytes::Bytes::from(token.into_bytes()));
        }
        out
    }

    #[test]
    fn a_pasted_block_becomes_one_token_per_line_ignoring_blanks_and_padding() {
        let tokens = tokens_from_text("  abc123 \n\n\tdef456\r\n\n   \nghi789\n");
        let seen: Vec<&[u8]> = tokens.iter().map(|t| &t[..]).collect();
        assert_eq!(seen, vec![&b"abc123"[..], &b"def456"[..], &b"ghi789"[..]]);
    }

    #[test]
    fn an_empty_paste_yields_no_tokens_and_a_report_that_says_so() {
        assert!(tokens_from_text("   \n\n").is_empty());
        let report = analyse(&tokens_from_text(""));
        assert_eq!(report.tokens, 0);
        assert_eq!(report.grade, Grade::Insufficient);
        assert!(report.fips.tests.is_none());
        assert!(
            report.warnings.iter().any(|w| w.contains("no tokens")),
            "{:?}",
            report.warnings
        );
    }

    /// The end-to-end happy path: enough good tokens to fill a block, and everything passes.
    /// 1,250 tokens of 8 hex characters is 1,250 × 32 = 40,000 bits — two whole blocks.
    #[test]
    fn a_healthy_sample_passes_and_reports_which_encoding_it_used() {
        let tokens = hex_tokens(1, 1_250, 4);
        let report = analyse(&tokens);
        assert_eq!(report.tokens, 1_250);
        assert_eq!(report.encoding, Encoding::Hex);
        assert!(report.encoding_detected);
        assert_eq!(report.bits.bits, 40_000);
        assert_eq!(report.fips.blocks_tested, 2);
        assert_eq!(report.fips.bits_untested, 0);
        assert_eq!(
            report.grade,
            Grade::Pass,
            "verdict was: {} / failures {:?}",
            report.verdict,
            report.fips.failures()
        );
        assert!(report.verdict.contains("All four FIPS 140-2 tests passed"));
        assert_eq!(report.characters.alphabet_size, 16);
        assert_eq!(
            (report.characters.min_len, report.characters.max_len),
            (8, 8)
        );
        // 8 hex positions at ~4 bits each.
        assert!(
            report.characters.total_entropy_bits > 31.0,
            "got {}",
            report.characters.total_entropy_bits
        );
        assert!((report.characters.max_possible_bits - 32.0).abs() < 1e-9);
    }

    /// The failure this tool is for: a token with a fixed prefix and a counter in the tail. It looks
    /// like a 16-character hex id and carries almost nothing.
    #[test]
    fn a_counter_dressed_up_as_a_session_id_is_caught_at_both_levels() {
        let tokens: Vec<bytes::Bytes> = (0..2_000u32)
            .map(|i| bytes::Bytes::from(format!("deadbeef{i:08x}").into_bytes()))
            .collect();
        let report = analyse(&tokens);
        assert_eq!(report.encoding, Encoding::Hex);
        assert_eq!(report.grade, Grade::Fail);
        assert!(
            !report.fips.failures().is_empty(),
            "a counter must not pass the bit-level suite"
        );
        // The first eight positions are constant, so they contribute exactly nothing.
        assert!(
            report.characters.positions[..8]
                .iter()
                .all(|p| p.entropy_bits == 0.0),
            "the fixed prefix must read as zero bits"
        );
        assert!(
            report.characters.total_entropy_bits < 20.0,
            "16 hex characters could carry 64 bits; this carries {}",
            report.characters.total_entropy_bits
        );
    }

    /// A short sample is graded `insufficient`, not `fail`. This is the distinction the `Grade` enum
    /// exists for, and getting it wrong would mean reporting untested tokens as bad ones.
    #[test]
    fn a_short_sample_is_insufficient_rather_than_failed_and_says_how_short() {
        let tokens = hex_tokens(9, 20, 8);
        let report = analyse(&tokens);
        assert_eq!(report.bits.bits, 20 * 64);
        assert_eq!(report.grade, Grade::Insufficient);
        assert!(report.fips.tests.is_none());
        assert_eq!(report.fips.blocks_tested, 0);
        assert_eq!(report.fips.bits_untested, 20 * 64);
        assert!(
            report.verdict.contains("No bit-level verdict"),
            "{}",
            report.verdict
        );
        // 64 bits per token, so 20000/64 = 313 tokens.
        assert!(
            report.verdict.contains("313 token(s)"),
            "the verdict must say how many more are needed: {}",
            report.verdict
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("only 20 token(s)")),
            "{:?}",
            report.warnings
        );
        // The character-level half is still reported and still useful.
        assert_eq!(report.characters.alphabet_size, 16);
        assert!(report.characters.total_entropy_bits > 0.0);
    }

    #[test]
    fn varying_token_lengths_are_reported_as_a_caveat_rather_than_normalised_away() {
        let mut tokens = hex_tokens(3, 200, 4);
        tokens.push(bytes::Bytes::from_static(b"abcdef"));
        let report = analyse(&tokens);
        assert_eq!(
            (report.characters.min_len, report.characters.max_len),
            (6, 8)
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("token lengths vary")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn an_encoding_can_be_forced_and_the_report_stops_claiming_it_was_detected() {
        let tokens = hex_tokens(5, 400, 4);
        let detected = analyse(&tokens);
        let forced = analyse_as(&tokens, Some(Encoding::Raw));
        assert_eq!(detected.encoding, Encoding::Hex);
        assert!(detected.encoding_detected);
        assert_eq!(forced.encoding, Encoding::Raw);
        assert!(!forced.encoding_detected);
        assert_eq!(
            forced.bits.bits,
            detected.bits.bits * 2,
            "the raw view is twice the bits, and worse ones"
        );
        assert_eq!(
            forced.characters.total_entropy_bits, detected.characters.total_entropy_bits,
            "the character-level analysis does not depend on the bit view at all"
        );
    }
}
