//! Character-level analysis: what alphabet the tokens draw on, and how much each position varies.
//!
//! # Why per-position, and what the sum of positional entropies is and is not
//!
//! A token generator can look fine in aggregate and be broken at one position — a counter in the
//! last two characters, a fixed machine id in the first four, a timestamp prefix that only changes
//! once a second. Pooling every character of every token hides exactly that, so the per-position
//! distribution is the primary output here and the pooled figure is secondary.
//!
//! [`CharacterAnalysis::total_entropy_bits`] is the sum of the positional entropies. That sum is an
//! **upper** estimate of the token's real entropy, because it assumes the positions are
//! independent: a token that is `abc` or `xyz` and nothing else carries 1 bit, but this sum reports
//! 3 × 1 = 3. The assumption is inherent to character-level analysis rather than a shortcut taken
//! here — Burp's Sequencer character-level tests have the same shape — and it is named in the
//! report as `assumes_positional_independence` so a reader is not invited to treat it as a
//! measurement.
//!
//! The second caveat is sample size, and it cuts the other way. Shannon entropy computed from
//! counts is *downward* biased: with fewer tokens than the alphabet is wide, no position can show
//! more than `log2(tokens)` bits however good the generator is, so a 16-token sample caps every
//! position at 4 bits. [`CharacterAnalysis::entropy_ceiling_bits`] reports that ceiling next to the
//! measurement so a small sample cannot be mistaken for a weak generator.

use serde::Serialize;

/// Positions past this are counted but not individually reported, so one pathological 10 MB "token"
/// cannot turn a report into a memory problem. The truncation is stated in the report.
pub const MAX_POSITIONS_REPORTED: usize = 256;

/// One observed character at one position.
#[derive(Debug, Clone, Serialize)]
pub struct CharCount {
    /// Printable form for display: the character itself, or `\xNN` when it is not printable ASCII.
    pub label: String,
    pub byte: u8,
    pub count: usize,
    /// Share of the samples at this position, 0.0..=1.0. Precomputed because the bar display needs
    /// it and the divisor is not otherwise on the row.
    pub fraction: f64,
}

/// One character position across every token long enough to have it.
#[derive(Debug, Clone, Serialize)]
pub struct PositionStats {
    pub index: usize,
    /// Tokens that actually had a character here. Shorter tokens are excluded rather than padded —
    /// padding would invent a character and shift the distribution towards it.
    pub samples: usize,
    pub distinct: usize,
    /// Shannon entropy of this position's distribution, in bits.
    pub entropy_bits: f64,
    /// Every observed character, most frequent first, ties broken by byte value so the order is
    /// stable across runs.
    pub counts: Vec<CharCount>,
}

/// The character-level view of a token sample.
#[derive(Debug, Clone, Serialize)]
pub struct CharacterAnalysis {
    pub tokens: usize,
    pub min_len: usize,
    pub max_len: usize,
    /// Distinct byte values over every character of every token.
    pub alphabet_size: usize,
    /// The alphabet itself, in byte order, rendered for display.
    pub alphabet: Vec<String>,
    /// One entry per position, up to [`MAX_POSITIONS_REPORTED`].
    pub positions: Vec<PositionStats>,
    /// True when `max_len` exceeded [`MAX_POSITIONS_REPORTED`] and later positions are absent.
    pub positions_truncated: bool,
    /// Shannon entropy over every character of every token pooled together, bits per character.
    pub entropy_bits_per_char: f64,
    /// Sum of the reported positions' entropies. An upper estimate — see the module header.
    pub total_entropy_bits: f64,
    /// Always true, and serialised so the number above is never read without its caveat.
    pub assumes_positional_independence: bool,
    /// `log2(tokens)`: the most any single position can show from this many samples, regardless of
    /// the generator. A `total_entropy_bits` at or near `positions × this` means the sample ran out
    /// before the generator did.
    pub entropy_ceiling_bits: f64,
    /// `positions × log2(alphabet_size)`: the most this alphabet and length could ever carry.
    pub max_possible_bits: f64,
}

/// Shannon entropy of a count distribution, in bits: `H = -Σ pᵢ log2 pᵢ`.
///
/// A single observed value gives 0.0 rather than a NaN, which is the mathematically right answer
/// (`p = 1`, `log2 1 = 0`) and also the one a caller can display.
pub fn entropy_bits(counts: impl IntoIterator<Item = usize>) -> f64 {
    let counts: Vec<usize> = counts.into_iter().filter(|&c| c > 0).collect();
    let total: usize = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    -counts
        .iter()
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Render a byte for a human: itself when printable ASCII, `\xNN` otherwise.
fn label(byte: u8) -> String {
    match byte {
        b' '..=b'~' => (byte as char).to_string(),
        b'\n' => "\\n".to_string(),
        b'\r' => "\\r".to_string(),
        b'\t' => "\\t".to_string(),
        _ => format!("\\x{byte:02x}"),
    }
}

/// Analyse the character-level structure of a token sample.
pub fn analyse(tokens: &[impl AsRef<[u8]>]) -> CharacterAnalysis {
    let lens: Vec<usize> = tokens.iter().map(|t| t.as_ref().len()).collect();
    let max_len = lens.iter().copied().max().unwrap_or(0);
    let min_len = lens.iter().copied().min().unwrap_or(0);

    // One pass over every character fills both the pooled histogram and the per-position ones.
    let mut pooled = [0usize; 256];
    let reported = max_len.min(MAX_POSITIONS_REPORTED);
    let mut per_position: Vec<[usize; 256]> = vec![[0usize; 256]; reported];
    for token in tokens {
        for (i, &byte) in token.as_ref().iter().enumerate() {
            pooled[byte as usize] += 1;
            if let Some(slot) = per_position.get_mut(i) {
                slot[byte as usize] += 1;
            }
        }
    }

    let alphabet: Vec<String> = (0..256)
        .filter(|&b| pooled[b] > 0)
        .map(|b| label(b as u8))
        .collect();
    let alphabet_size = alphabet.len();

    let positions: Vec<PositionStats> = per_position
        .iter()
        .enumerate()
        .map(|(index, hist)| {
            let samples: usize = hist.iter().sum();
            let mut counts: Vec<CharCount> = (0..256)
                .filter(|&b| hist[b] > 0)
                .map(|b| CharCount {
                    label: label(b as u8),
                    byte: b as u8,
                    count: hist[b],
                    fraction: if samples == 0 {
                        0.0
                    } else {
                        hist[b] as f64 / samples as f64
                    },
                })
                .collect();
            // Most frequent first; byte order breaks ties so two runs over the same data agree.
            counts.sort_by(|a, b| b.count.cmp(&a.count).then(a.byte.cmp(&b.byte)));
            PositionStats {
                index,
                samples,
                distinct: counts.len(),
                entropy_bits: entropy_bits(hist.iter().copied()),
                counts,
            }
        })
        .collect();

    let total_entropy_bits = positions.iter().map(|p| p.entropy_bits).sum();
    CharacterAnalysis {
        tokens: tokens.len(),
        min_len,
        max_len,
        alphabet_size,
        alphabet,
        positions_truncated: max_len > reported,
        positions,
        entropy_bits_per_char: entropy_bits(pooled),
        total_entropy_bits,
        assumes_positional_independence: true,
        entropy_ceiling_bits: if tokens.is_empty() {
            0.0
        } else {
            (tokens.len() as f64).log2()
        },
        max_possible_bits: if alphabet_size == 0 {
            0.0
        } else {
            reported as f64 * (alphabet_size as f64).log2()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(list: &[&str]) -> Vec<Vec<u8>> {
        list.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    /// Hand-checkable arithmetic: two equally likely characters at each of two positions.
    #[test]
    fn two_even_choices_at_each_position_is_one_bit_each() {
        let a = analyse(&toks(&["ab", "ab", "cd", "cd"]));
        assert_eq!(a.tokens, 4);
        assert_eq!(a.alphabet_size, 4);
        assert_eq!((a.min_len, a.max_len), (2, 2));
        assert!((a.positions[0].entropy_bits - 1.0).abs() < 1e-12);
        assert!((a.positions[1].entropy_bits - 1.0).abs() < 1e-12);
        assert!((a.total_entropy_bits - 2.0).abs() < 1e-12);
        // Pooled: a,b,c,d one each in 8 characters -> 4 values at 1/4 -> 2 bits per character.
        assert!((a.entropy_bits_per_char - 2.0).abs() < 1e-12);
    }

    /// The failure this analysis exists to catch: a token that looks varied but has a dead position.
    #[test]
    fn a_constant_position_reports_zero_bits_while_its_neighbours_do_not() {
        let a = analyse(&toks(&["Xa1", "Xb2", "Xc3", "Xd4"]));
        assert_eq!(a.positions[0].distinct, 1);
        assert_eq!(a.positions[0].entropy_bits, 0.0);
        assert!((a.positions[1].entropy_bits - 2.0).abs() < 1e-12);
        assert!((a.positions[2].entropy_bits - 2.0).abs() < 1e-12);
        assert!(
            (a.total_entropy_bits - 4.0).abs() < 1e-12,
            "3 characters, 4 bits: the fixed prefix contributes nothing"
        );
    }

    /// Sixteen distinct hex digits, each once: exactly 4 bits. Also the ceiling for 16 samples, so
    /// the report must say the sample is the binding constraint rather than the generator.
    #[test]
    fn sixteen_distinct_values_in_sixteen_samples_is_four_bits_and_also_the_ceiling() {
        let tokens: Vec<Vec<u8>> = (0..16u8)
            .map(|i| vec![b"0123456789abcdef"[i as usize]])
            .collect();
        let a = analyse(&tokens);
        assert!((a.positions[0].entropy_bits - 4.0).abs() < 1e-12);
        assert!((a.entropy_ceiling_bits - 4.0).abs() < 1e-12);
        assert!((a.max_possible_bits - 4.0).abs() < 1e-12);
    }

    /// Shorter tokens are excluded from the positions they do not reach. Padding them would invent
    /// a character and pull that position's entropy towards it.
    #[test]
    fn a_short_token_is_excluded_from_positions_it_does_not_reach_not_padded() {
        let a = analyse(&toks(&["ab", "cd", "e"]));
        assert_eq!((a.min_len, a.max_len), (1, 2));
        assert_eq!(a.positions[0].samples, 3);
        assert_eq!(
            a.positions[1].samples, 2,
            "the one-character token has no position 1"
        );
        assert_eq!(a.positions[1].distinct, 2);
        assert!((a.positions[1].entropy_bits - 1.0).abs() < 1e-12);
    }

    #[test]
    fn counts_are_ordered_most_frequent_first_with_a_stable_tie_break() {
        let a = analyse(&toks(&["a", "a", "a", "b", "b", "c"]));
        let labels: Vec<&str> = a.positions[0]
            .counts
            .iter()
            .map(|c| c.label.as_str())
            .collect();
        assert_eq!(labels, vec!["a", "b", "c"]);
        assert_eq!(a.positions[0].counts[0].count, 3);
        assert!((a.positions[0].counts[0].fraction - 0.5).abs() < 1e-12);
    }

    #[test]
    fn a_non_printable_byte_gets_an_escaped_label_rather_than_mangling_the_json() {
        let a = analyse(&[vec![0x00u8, 0x1f, b'A', 0xff]]);
        let labels: Vec<String> = a
            .positions
            .iter()
            .map(|p| p.counts[0].label.clone())
            .collect();
        assert_eq!(labels, vec!["\\x00", "\\x1f", "A", "\\xff"]);
    }

    #[test]
    fn an_over_long_token_is_truncated_for_reporting_and_says_so() {
        let long = vec![b'z'; MAX_POSITIONS_REPORTED + 10];
        let a = analyse(&[long]);
        assert_eq!(a.max_len, MAX_POSITIONS_REPORTED + 10);
        assert_eq!(a.positions.len(), MAX_POSITIONS_REPORTED);
        assert!(
            a.positions_truncated,
            "a truncated report that does not admit it is worse than no report"
        );
    }

    #[test]
    fn an_empty_sample_produces_zeroes_rather_than_nan() {
        let empty: [Vec<u8>; 0] = [];
        let a = analyse(&empty);
        assert_eq!(a.tokens, 0);
        assert_eq!(a.alphabet_size, 0);
        assert!(a.positions.is_empty());
        assert_eq!(a.entropy_bits_per_char, 0.0);
        assert_eq!(a.total_entropy_bits, 0.0);
        assert!(a.entropy_bits_per_char.is_finite() && a.total_entropy_bits.is_finite());
    }

    #[test]
    fn identical_tokens_carry_no_entropy_at_all() {
        let a = analyse(&toks(&["same", "same", "same"]));
        assert_eq!(a.total_entropy_bits, 0.0);
        assert_eq!(
            a.entropy_bits_per_char, 2.0,
            "pooled over s,a,m,e — four even values"
        );
        assert!(a.positions.iter().all(|p| p.entropy_bits == 0.0));
    }

    #[test]
    fn entropy_of_a_single_value_is_zero_not_nan() {
        assert_eq!(entropy_bits([7usize]), 0.0);
        assert_eq!(entropy_bits(std::iter::empty()), 0.0);
        assert!((entropy_bits([1usize, 1]) - 1.0).abs() < 1e-12);
        assert!((entropy_bits([3usize, 1]) - 0.8112781).abs() < 1e-6);
    }
}
