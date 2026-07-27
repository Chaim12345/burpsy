//! Comparer — a diff between two messages, at word or byte granularity.
//!
//! # The cost problem, and why the trim is the whole trick
//!
//! The job this tool actually gets is "two 200 KB responses that differ in one character" — a
//! reflected-payload check, a blind-injection oracle, a session token that changed. A textbook
//! dynamic-programming diff is O(n·m): on 200 KB that is 4×10^10 cell updates, which is not a slow
//! tool, it is a hung one.
//!
//! Myers' algorithm is O((n+m)·D) where D is the size of the edit script, so its cost is driven by
//! *how different* the inputs are rather than how big they are. Two responses differing in one byte
//! have D = 2. Stripping the common prefix and suffix first — one linear scan each — reduces that
//! case to a handful of tokens before the real algorithm sees anything at all.
//!
//! # The bail-out, stated honestly
//!
//! Two genuinely unrelated 200 KB bodies have a large D, and O((n+m)·D) is then no better than
//! quadratic. So D is capped by a budget scaled to the input size, and exceeding it produces a
//! coarse "this whole region was replaced" diff with [`Diff::truncated`] set. That is a real answer
//! — the bodies share nothing worth aligning — delivered in bounded time instead of a hang.
//!
//! # No bytes are copied
//!
//! Every op carries [`Span`]s into the two original buffers, never their contents. Diffing two
//! 200 KB bodies allocates an op list proportional to the number of *changes*, in keeping with the
//! rest of the codebase: hold offsets, not payloads.

use burpsy_core::Span;
use serde::{Deserialize, Serialize};

/// What counts as one unit of change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Granularity {
    /// Every byte is a token. The finest view, and the one that localises a single-character edit.
    Byte,
    /// A token is a maximal run of non-whitespace or a maximal run of whitespace. Reads the way a
    /// human compares two responses, and cuts the token count by roughly 6× on text.
    Word,
}

/// One aligned region. Spans point into the inputs given to [`diff`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Op {
    Equal {
        a: Span,
        b: Span,
    },
    /// Present in `a`, absent from `b`.
    Delete {
        a: Span,
    },
    /// Absent from `a`, present in `b`.
    Insert {
        b: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diff {
    pub granularity: Granularity,
    pub ops: Vec<Op>,
    pub equal_tokens: usize,
    pub deleted_tokens: usize,
    pub inserted_tokens: usize,
    /// The edit script exceeded the budget; the differing region is reported as one wholesale
    /// replacement rather than aligned. The diff is still correct, just coarse.
    pub truncated: bool,
}

impl Diff {
    pub fn is_identical(&self) -> bool {
        self.deleted_tokens == 0 && self.inserted_tokens == 0
    }

    /// Total tokens that differ, the number to show as "N changes".
    pub fn changes(&self) -> usize {
        self.deleted_tokens + self.inserted_tokens
    }
}

/// Diff two buffers with a budget derived from their size.
pub fn diff(a: &[u8], b: &[u8], granularity: Granularity) -> Diff {
    let ta = Tokens::new(a, granularity);
    let tb = Tokens::new(b, granularity);
    let budget = budget_for(ta.len() + tb.len());
    run(&ta, &tb, granularity, budget)
}

/// Diff with an explicit cap on the edit-script size. Useful to assert that a change really is
/// small: a one-byte difference in a megabyte still resolves with `max_d = 4`.
pub fn diff_with_budget(a: &[u8], b: &[u8], granularity: Granularity, max_d: usize) -> Diff {
    let ta = Tokens::new(a, granularity);
    let tb = Tokens::new(b, granularity);
    run(&ta, &tb, granularity, max_d)
}

/// Work is O((n+m)·D), so the cap has to shrink as the inputs grow or the bail-out costs more than
/// the diff. ~2×10^7 token comparisons is a few tens of milliseconds; the floor keeps small inputs
/// aligning properly and the ceiling bounds the O(D²) trace to about 16 MB.
fn budget_for(total_tokens: usize) -> usize {
    (20_000_000 / (total_tokens + 1)).clamp(64, 2048)
}

fn run(ta: &Tokens<'_>, tb: &Tokens<'_>, granularity: Granularity, max_d: usize) -> Diff {
    let (na, nb) = (ta.len(), tb.len());

    // Linear prefix/suffix trim. This is what makes the headline case cheap.
    let mut lo = 0;
    while lo < na && lo < nb && ta.eq(lo, tb, lo) {
        lo += 1;
    }
    let mut tail = 0;
    while tail < na - lo && tail < nb - lo && ta.eq(na - 1 - tail, tb, nb - 1 - tail) {
        tail += 1;
    }
    let (mid_a, mid_b) = (na - tail - lo, nb - tail - lo);

    let mut ops = Vec::new();
    let mut equal = 0usize;
    let mut deleted = 0usize;
    let mut inserted = 0usize;

    if lo > 0 {
        ops.push(Op::Equal {
            a: ta.range(0, lo),
            b: tb.range(0, lo),
        });
        equal += lo;
    }

    let script = myers(mid_a, mid_b, |x, y| ta.eq(lo + x, tb, lo + y), max_d);
    let truncated = script.is_none();
    match script {
        Some(edits) => {
            let mut i = 0;
            while i < edits.len() {
                let mut j = i;
                while j < edits.len() && edits[j].kind() == edits[i].kind() {
                    j += 1;
                }
                let n = j - i;
                match edits[i] {
                    Edit::Equal(ax, bx) => {
                        ops.push(Op::Equal {
                            a: ta.range(lo + ax, n),
                            b: tb.range(lo + bx, n),
                        });
                        equal += n;
                    }
                    Edit::Delete(ax) => {
                        ops.push(Op::Delete {
                            a: ta.range(lo + ax, n),
                        });
                        deleted += n;
                    }
                    Edit::Insert(bx) => {
                        ops.push(Op::Insert {
                            b: tb.range(lo + bx, n),
                        });
                        inserted += n;
                    }
                }
                i = j;
            }
        }
        None => {
            if mid_a > 0 {
                ops.push(Op::Delete {
                    a: ta.range(lo, mid_a),
                });
                deleted += mid_a;
            }
            if mid_b > 0 {
                ops.push(Op::Insert {
                    b: tb.range(lo, mid_b),
                });
                inserted += mid_b;
            }
        }
    }

    if tail > 0 {
        ops.push(Op::Equal {
            a: ta.range(na - tail, tail),
            b: tb.range(nb - tail, tail),
        });
        equal += tail;
    }

    Diff {
        granularity,
        ops,
        equal_tokens: equal,
        deleted_tokens: deleted,
        inserted_tokens: inserted,
        truncated,
    }
}

// ---- tokens -----------------------------------------------------------------------------------

/// A buffer viewed as a token sequence. Byte granularity stores no span table: token `i` *is*
/// byte `i`, and materialising 200 000 `Span`s to say so would cost more than the diff.
struct Tokens<'a> {
    buf: &'a [u8],
    spans: Option<Vec<Span>>,
    hashes: Vec<u64>,
    /// True when a hash match implies a byte match, so equality needs no second compare.
    hash_is_exact: bool,
}

impl<'a> Tokens<'a> {
    fn new(buf: &'a [u8], g: Granularity) -> Self {
        match g {
            Granularity::Byte => Self {
                hashes: buf.iter().map(|&b| b as u64).collect(),
                spans: None,
                hash_is_exact: true,
                buf,
            },
            Granularity::Word => {
                let spans = word_spans(buf);
                let hashes = spans
                    .iter()
                    .map(|s| fnv1a(&buf[s.offset..s.end()]))
                    .collect();
                Self {
                    buf,
                    spans: Some(spans),
                    hashes,
                    hash_is_exact: false,
                }
            }
        }
    }

    fn len(&self) -> usize {
        self.spans.as_ref().map_or(self.buf.len(), Vec::len)
    }

    fn span(&self, i: usize) -> Span {
        self.spans
            .as_ref()
            .map_or_else(|| Span::new(i, 1), |v| v[i])
    }

    /// One span covering `count` consecutive tokens from `start`.
    fn range(&self, start: usize, count: usize) -> Span {
        if count == 0 {
            return Span::new(self.span(start.min(self.len())).offset, 0);
        }
        let first = self.span(start);
        let last = self.span(start + count - 1);
        Span::new(first.offset, last.end() - first.offset)
    }

    fn eq(&self, i: usize, other: &Tokens<'_>, j: usize) -> bool {
        if self.hashes[i] != other.hashes[j] {
            return false;
        }
        if self.hash_is_exact && other.hash_is_exact {
            return true;
        }
        let (a, b) = (self.span(i), other.span(j));
        self.buf[a.offset..a.end()] == other.buf[b.offset..b.end()]
    }
}

fn word_spans(buf: &[u8]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let ws = buf[i].is_ascii_whitespace();
        let start = i;
        while i < buf.len() && buf[i].is_ascii_whitespace() == ws {
            i += 1;
        }
        out.push(Span::new(start, i - start));
    }
    out
}

fn fnv1a(b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

// ---- Myers ------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edit {
    Equal(usize, usize),
    Delete(usize),
    Insert(usize),
}

impl Edit {
    fn kind(self) -> u8 {
        match self {
            Edit::Equal(..) => 0,
            Edit::Delete(_) => 1,
            Edit::Insert(_) => 2,
        }
    }
}

/// Greedy forward Myers with a per-round trace, capped at `max_d`. `None` means the cap was hit.
///
/// The trace keeps only the diagonals each round can actually read back — 2d+3 entries for round
/// d — so its memory is O(D²) rather than O(D·(n+m)). At the 2048 ceiling that is ~16 MB; storing
/// the full diagonal array each round would be ~13 GB on a 200 KB input.
fn myers(n: usize, m: usize, eq: impl Fn(usize, usize) -> bool, max_d: usize) -> Option<Vec<Edit>> {
    let max_d = max_d.min(n + m);
    let off = (max_d + 1) as isize;
    let mut v = vec![0i32; 2 * max_d + 3];
    let mut trace: Vec<Vec<i32>> = Vec::new();
    let (n_i, m_i) = (n as i32, m as i32);

    for d in 0..=max_d {
        let di = d as isize;
        trace.push(v[(off - di - 1) as usize..=(off + di + 1) as usize].to_vec());
        let mut k = -di;
        while k <= di {
            let idx = (k + off) as usize;
            // Extend the furthest-reaching path on diagonal k: down (insert) or right (delete).
            let mut x = if k == -di || (k != di && v[idx - 1] < v[idx + 1]) {
                v[idx + 1]
            } else {
                v[idx - 1] + 1
            };
            let mut y = x - k as i32;
            while x < n_i && y < m_i && eq(x as usize, y as usize) {
                x += 1;
                y += 1;
            }
            v[idx] = x;
            if x >= n_i && y >= m_i {
                return Some(backtrack(&trace, n, m));
            }
            k += 2;
        }
    }
    None
}

fn backtrack(trace: &[Vec<i32>], n: usize, m: usize) -> Vec<Edit> {
    let mut edits = Vec::new();
    let (mut x, mut y) = (n as i32, m as i32);
    for d in (0..trace.len()).rev() {
        let v = &trace[d];
        let di = d as i32;
        let k = x - y;
        let at = |kk: i32| v[(kk + di + 1) as usize];
        let prev_k = if k == -di || (k != di && at(k - 1) < at(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = at(prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            edits.push(Edit::Equal((x - 1) as usize, (y - 1) as usize));
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if x == prev_x {
                edits.push(Edit::Insert(prev_y as usize));
            } else {
                edits.push(Edit::Delete(prev_x as usize));
            }
        }
        x = prev_x;
        y = prev_y;
    }
    edits.reverse();
    edits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replaying the ops against `a` must reproduce `b`. Any span error shows up here.
    fn rebuild(a: &[u8], b: &[u8], d: &Diff) -> Vec<u8> {
        let mut out = Vec::new();
        for op in &d.ops {
            match *op {
                Op::Equal { b: s, .. } | Op::Insert { b: s } => {
                    out.extend_from_slice(&b[s.offset..s.end()])
                }
                Op::Delete { a: s } => {
                    // Deleted spans must be real regions of `a`, so touch them to prove it.
                    assert!(s.end() <= a.len(), "delete span past the end of a");
                }
            }
        }
        out
    }

    fn check(a: &[u8], b: &[u8], g: Granularity) -> Diff {
        let d = diff(a, b, g);
        assert_eq!(rebuild(a, b, &d), b, "ops must reconstruct b");
        d
    }

    #[test]
    fn one_byte_differing_in_a_200kb_response_is_found_with_a_tiny_edit_script() {
        // The headline case. Budget of 4 proves the prefix/suffix trim did the work: without it
        // Myers would need D in the hundreds of thousands and this would truncate.
        let mut a = vec![b'x'; 200_000];
        for (i, c) in a.iter_mut().enumerate() {
            *c = b"abcdefghij"[i % 10];
        }
        let mut b = a.clone();
        b[123_456] = b'Z';

        let d = diff_with_budget(&a, &b, Granularity::Byte, 4);
        assert!(
            !d.truncated,
            "a one-byte change must not exhaust a budget of 4"
        );
        assert_eq!(d.deleted_tokens, 1);
        assert_eq!(d.inserted_tokens, 1);
        assert_eq!(d.equal_tokens, 199_999);
        let changed: Vec<&Op> = d
            .ops
            .iter()
            .filter(|o| !matches!(o, Op::Equal { .. }))
            .collect();
        assert_eq!(changed.len(), 2, "one delete and one insert, nothing else");
        assert!(
            matches!(changed[0], Op::Delete { a } if a.offset == 123_456 && a.len == 1),
            "{:?}",
            changed[0]
        );
        assert_eq!(rebuild(&a, &b, &d), b);
    }

    #[test]
    fn identical_inputs_produce_a_single_equal_op() {
        let a = b"HTTP/1.1 200 OK\r\nX: 1\r\n\r\nbody";
        let d = check(a, a, Granularity::Byte);
        assert!(d.is_identical());
        assert_eq!(d.ops.len(), 1);
        assert_eq!(d.changes(), 0);
    }

    #[test]
    fn word_granularity_reports_one_changed_word_where_bytes_report_a_character() {
        let a = b"the quick brown fox";
        let b = b"the quick brawn fox";
        let w = check(a, b, Granularity::Word);
        assert_eq!(
            (w.deleted_tokens, w.inserted_tokens),
            (1, 1),
            "one word replaced"
        );
        let by = check(a, b, Granularity::Byte);
        assert_eq!(
            (by.deleted_tokens, by.inserted_tokens),
            (1, 1),
            "one byte replaced"
        );
        // The word diff points at the whole word; the byte diff at the single character.
        let w_del = w.ops.iter().find_map(|o| match o {
            Op::Delete { a } => Some(*a),
            _ => None,
        });
        assert_eq!(w_del, Some(Span::new(10, 5)), "the span covers \"brown\"");
    }

    #[test]
    fn a_pure_insertion_is_reported_as_an_insert_with_no_deletes() {
        let a = b"Host: x\r\n";
        let b = b"Host: x\r\nCookie: s=1\r\n";
        let d = check(a, b, Granularity::Byte);
        assert_eq!(d.deleted_tokens, 0);
        assert_eq!(d.inserted_tokens, 13, "Cookie: s=1 plus CRLF");
        assert_eq!(d.ops.len(), 2, "one equal prefix then one insert");
    }

    #[test]
    fn a_pure_deletion_is_reported_as_a_delete_with_no_inserts() {
        let d = check(b"abcdefXYZghij", b"abcdefghij", Granularity::Byte);
        assert_eq!(d.inserted_tokens, 0);
        assert_eq!(d.deleted_tokens, 3);
    }

    #[test]
    fn an_empty_side_is_all_insert_or_all_delete() {
        let d = check(b"", b"hello", Granularity::Byte);
        assert_eq!(d.inserted_tokens, 5);
        assert_eq!(d.deleted_tokens, 0);
        let d = check(b"hello", b"", Granularity::Byte);
        assert_eq!(d.deleted_tokens, 5);
        assert_eq!(d.inserted_tokens, 0);
        let d = check(b"", b"", Granularity::Byte);
        assert!(d.ops.is_empty());
    }

    #[test]
    fn interleaved_edits_are_aligned_rather_than_lumped_together() {
        let d = check(b"aXbXcXd", b"aYbYcYd", Granularity::Byte);
        assert!(!d.truncated);
        assert_eq!(d.deleted_tokens, 3);
        assert_eq!(d.inserted_tokens, 3);
        // Three separate substitutions, each keeping the surrounding letters aligned.
        assert_eq!(d.equal_tokens, 4);
    }

    #[test]
    fn exhausting_the_budget_falls_back_to_a_whole_region_replacement_and_says_so() {
        let a: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let b: Vec<u8> = (0..2000u32).map(|i| (i % 241 + 3) as u8).collect();
        let d = diff_with_budget(&a, &b, Granularity::Byte, 2);
        assert!(d.truncated, "two unrelated buffers cannot align within D=2");
        assert_eq!(
            rebuild(&a, &b, &d),
            b,
            "a truncated diff is still a correct one"
        );
        assert_eq!(
            d.ops
                .iter()
                .filter(|o| matches!(o, Op::Delete { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn the_default_budget_shrinks_as_the_inputs_grow() {
        // Small inputs get the ceiling; a pair of 200 KB bodies gets the floor, which is what keeps
        // the bail-out cheap instead of burning 10^8 comparisons before giving up.
        assert_eq!(budget_for(100), 2048);
        assert_eq!(budget_for(400_000), 64);
    }

    #[test]
    fn spans_index_the_original_buffers_so_nothing_is_copied() {
        let a = b"GET /a HTTP/1.1";
        let b = b"GET /b HTTP/1.1";
        let d = check(a, b, Granularity::Word);
        for op in &d.ops {
            match *op {
                Op::Equal { a: sa, b: sb } => {
                    assert_eq!(&a[sa.offset..sa.end()], &b[sb.offset..sb.end()]);
                }
                Op::Delete { a: s } => assert_eq!(&a[s.offset..s.end()], b"/a"),
                Op::Insert { b: s } => assert_eq!(&b[s.offset..s.end()], b"/b"),
            }
        }
    }

    #[test]
    fn two_realistic_responses_differing_in_one_header_align_on_that_header() {
        let a =
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: id=aaa\r\nX-Frame: DENY\r\n\r\n{}";
        let b =
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: id=bbb\r\nX-Frame: DENY\r\n\r\n{}";
        let d = check(a, b, Granularity::Word);
        assert_eq!(d.changes(), 2, "one token out, one token in");
        let del = d.ops.iter().find_map(|o| match o {
            Op::Delete { a } => Some(*a),
            _ => None,
        });
        let s = del.unwrap();
        assert_eq!(&a[s.offset..s.end()], b"id=aaa");
    }
}
