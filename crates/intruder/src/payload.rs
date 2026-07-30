//! Payload *generators*: another way to produce a payload set, not another kind of payload set.
//!
//! # Why this resolves to a `Vec<Bytes>` and stops there
//!
//! Burp models a payload type as a live object the attack pulls from
//! (`IPayloadGeneratorFactory` / `IIntruderPayloadGenerator.getNextPayload`), so the generator is a
//! participant in the send loop and every attack mode has to know how to drive one. Here the engine
//! already consumes `&[Vec<Bytes>]` and [`crate::AttackPlan`] derives request `i` from `i` alone —
//! two properties that are worth more than laziness in the generator:
//!
//! * a result row can hold an ordinal and nothing else, because the payload behind an ordinal is
//!   still there to be looked up after the attack;
//! * the engine has exactly one payload representation to handle, so adding a generator cannot
//!   change how a request gets sent.
//!
//! So a generator is a *resolve-time* function: it runs once, before the attack, and hands back the
//! same `Vec<Bytes>` a literal list would have been. [`Attack::new`](crate::Attack::new) does not
//! change shape and does not learn what a generator is.
//!
//! # What that costs, stated plainly
//!
//! A generator whose next payload depends on the previous *response* cannot be expressed this way at
//! all. Burp's **Recursive grep** is exactly that: it feeds each response's extracted value into the
//! next request. It is deliberately absent here rather than bolted on — see the module note at the
//! bottom of this file.
//!
//! # Bounding
//!
//! Every generator is bounded twice, and reports both facts the way [`crate::AttackPlan`] does:
//!
//! * **the list** is capped at `max_count` (itself capped at [`MAX_PAYLOADS`]) and
//!   [`PayloadSet::truncated`] says when the cap bit, next to [`PayloadSet::total`] — what the
//!   operator actually asked for. A cap the operator cannot see turns "I tried every value" into a
//!   lie, which is the same reason `AttackPlan` carries `combinations` alongside `len`.
//! * **each item** is capped at [`MAX_ITEM_LEN`], and that one is *refused* rather than truncated. A
//!   shortened list is an honest subset of the attack; a shortened payload is a different payload,
//!   and silently sending it would be mangling input to avoid an error.
//!
//! A brute-forcer over 62 characters at length 1..=8 describes 2.2×10^14 payloads. The count is
//! computed arithmetically and saturates; the `Vec` never exceeds the cap.

use crate::process::DropReason;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Hard ceiling on a resolved payload set, whatever `max_count` a caller passes.
///
/// Matched deliberately to the web edge's own ceiling on `max_requests`: you cannot generate more
/// payloads than the largest attack the edge will ever agree to send. 200 000 `Bytes` handles is
/// ~6 MB of handles plus the payload bytes themselves — bounded, and small next to the response
/// traffic an attack that size produces.
pub const MAX_PAYLOADS: usize = 200_000;

/// Refuse to build a single payload longer than this.
///
/// 64 KiB is far past any payload an operator types and far short of a generator config that turns
/// into gigabytes: `CharBlocks { max: 1_000_000_000 }` is a typo, not a request.
pub const MAX_ITEM_LEN: usize = 64 * 1024;

/// A generator config that cannot produce anything meaningful.
///
/// [`crate::AttackPlan`] is deliberately *total* — it plans zero requests for input it cannot
/// express, and rejecting nonsense is the edge's job. Generators are the other case: they run at the
/// edge, once, before anything is sent, and a `step` of zero silently yielding an empty set would
/// hand the operator an attack that sent nothing and looked like it worked. So this one refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    /// A step of zero never advances.
    ZeroStep,
    /// A range whose sign disagrees with its step: it would run away from `to`, not towards it.
    BackwardsRange { from: String, to: String, step: i64 },
    /// A character set or position slot with nothing in it.
    Empty(&'static str),
    /// `min_len > max_len`, or a maximum of zero.
    BadLengthRange { min: usize, max: usize },
    /// Burp requires two or more slots for a custom iterator; one slot is a plain list.
    TooFewSlots(usize),
    /// One payload would exceed [`MAX_ITEM_LEN`]. See the module note on why this refuses.
    ItemTooLong { len: usize, max: usize },
    /// A date that is not `YYYY-MM-DD`.
    BadDate(String),
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadError::ZeroStep => f.write_str("step must not be zero: it would never advance"),
            PayloadError::BackwardsRange { from, to, step } => write!(
                f,
                "step {step} runs away from the end of the range {from}..{to}"
            ),
            PayloadError::Empty(what) => write!(f, "{what} is empty"),
            PayloadError::BadLengthRange { min, max } => {
                write!(f, "length range {min}..={max} produces nothing")
            }
            PayloadError::TooFewSlots(n) => write!(
                f,
                "a custom iterator needs at least 2 position slots, got {n}"
            ),
            PayloadError::ItemTooLong { len, max } => write!(
                f,
                "one payload would be {len} bytes, over the {max}-byte limit; \
                 refused rather than shortened"
            ),
            PayloadError::BadDate(s) => write!(f, "not a YYYY-MM-DD date: {s:?}"),
        }
    }
}

impl std::error::Error for PayloadError {}

/// A resolved payload set, carrying the same pair of facts [`crate::AttackPlan`] does: what was
/// asked for, and what the bound left.
#[derive(Debug, Clone)]
pub struct PayloadSet {
    /// What the attack will actually use. This is the `Vec<Bytes>` the engine already consumes.
    pub items: Vec<Bytes>,
    /// Payloads the source describes with no bound applied, saturating at `u64::MAX`.
    pub total: u64,
    /// False when [`PayloadSet::total`] saturated and is therefore a floor, not a count.
    pub total_exact: bool,
    /// True when `max_count` cut the set short.
    pub truncated: bool,
    /// The bound that was in force.
    pub max_count: usize,
    /// Payloads a processing rule dropped before sending. See [`crate::process::Chain::run`].
    pub skipped: usize,
    /// Why they were dropped, grouped: distinct reasons with counts, never one row per payload.
    pub dropped: Vec<DropReason>,
}

impl PayloadSet {
    /// A set that is exactly the literal list it was given.
    pub fn literal(items: Vec<Bytes>) -> Self {
        let n = items.len();
        Self {
            items,
            total: n as u64,
            total_exact: true,
            truncated: false,
            max_count: n,
            skipped: 0,
            dropped: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Sequential or drawn at random.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumberOrder {
    #[default]
    Sequential,
    /// Random draws. Reproducible only when [`Numbers::seed`] is set — see its doc comment.
    Random,
}

/// How a number is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumberBase {
    #[default]
    Decimal,
    /// Lowercase hex. A negative value is written `-` then the magnitude, because two's-complement
    /// hex of a negative `i64` is sixteen digits of `f` and nobody means that.
    Hex,
}

/// Burp's **Numbers** payload type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Numbers {
    pub from: i64,
    /// Inclusive.
    pub to: i64,
    /// Distance between successive values. Its sign must point from `from` towards `to`.
    pub step: i64,
    #[serde(default)]
    pub order: NumberOrder,
    /// How many to draw. [`NumberOrder::Random`] only; sequential takes its count from the range.
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub base: NumberBase,
    /// Zero-pad the digits to this width. 0 leaves them unpadded. Applied after any sign, so
    /// `-7` at width 4 is `-0007`.
    #[serde(default)]
    pub pad_to: usize,
    /// Seed for [`NumberOrder::Random`].
    ///
    /// Set it and the same attack regenerates the same payloads, which is what makes a result's
    /// ordinal replayable across runs and not just within one. Unset draws from the clock, and the
    /// set is then reproducible only for the lifetime of the resolved `Vec`.
    #[serde(default)]
    pub seed: Option<u64>,
}

/// Burp's **Dates** payload type: a range walked in whole days, written through a format string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dates {
    /// `YYYY-MM-DD`, inclusive.
    pub from: String,
    /// `YYYY-MM-DD`, inclusive.
    pub to: String,
    /// Days between successive dates. Its sign must point from `from` towards `to`.
    pub step: i64,
    /// `yyyy`, `yy`, `MM`, `MMM`, `dd` are substituted; every other character is copied through.
    /// Longest token first, so `yyyy` never parses as two `yy`.
    pub format: String,
}

/// Burp's **Brute forcer**: every string over an alphabet, across a length range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForce {
    /// The alphabet, as characters. Taken as characters rather than bytes so a non-ASCII set does
    /// not get split into invalid UTF-8 fragments.
    pub charset: String,
    pub min_len: usize,
    /// Inclusive.
    pub max_len: usize,
}

/// Burp's **Custom iterator**: independent lists per position slot, permuted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomIterator {
    /// One list per slot. Two or more, else it is a plain list wearing a hat.
    pub positions: Vec<Vec<String>>,
    /// Placed between slots. Burp allows one separator per position; a single shared one covers what
    /// an operator actually types, and a per-slot separator can be folded into the slot's own items.
    #[serde(default)]
    pub separator: String,
}

/// How to produce a payload set.
///
/// [`PayloadSource::List`] is a variant rather than a special case so a caller has one type to
/// handle instead of "a list, or else a generator".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PayloadSource {
    /// A literal list, exactly as before.
    List { items: Vec<String> },
    Numbers(Numbers),
    Dates(Dates),
    BruteForce(BruteForce),
    CustomIterator(CustomIterator),
    /// Burp's **Null payloads**: `count` copies of the empty payload, i.e. send the base request
    /// `count` times unchanged. The one payload type with nothing to configure and real uses —
    /// session-handling checks, and measuring a target's variance before reading anything into it.
    Null { count: usize },
}

impl PayloadSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadSource::List { .. } => "list",
            PayloadSource::Numbers(_) => "numbers",
            PayloadSource::Dates(_) => "dates",
            PayloadSource::BruteForce(_) => "brute_force",
            PayloadSource::CustomIterator(_) => "custom_iterator",
            PayloadSource::Null { .. } => "null",
        }
    }

    /// Produce the set, capped at `min(max_count, MAX_PAYLOADS)`.
    ///
    /// The cap is applied to the *allocation*, not to a generated list that is then trimmed: a
    /// config describing 10^14 payloads must not allocate 10^14 anything on its way to being cut
    /// down to 5 000.
    pub fn resolve(&self, max_count: usize) -> Result<PayloadSet, PayloadError> {
        let cap = max_count.min(MAX_PAYLOADS);
        let (items, total, total_exact) = match self {
            PayloadSource::List { items } => {
                let total = items.len() as u64;
                let out: Vec<Bytes> = items
                    .iter()
                    .take(cap)
                    .map(|s| Bytes::from(s.clone().into_bytes()))
                    .collect();
                for i in &out {
                    check_len(i.len())?;
                }
                (out, u128::from(total), true)
            }
            PayloadSource::Null { count } => {
                let n = (*count).min(cap);
                (vec![Bytes::new(); n], *count as u128, true)
            }
            PayloadSource::Numbers(n) => numbers(n, cap)?,
            PayloadSource::Dates(d) => dates(d, cap)?,
            PayloadSource::BruteForce(b) => brute_force(b, cap)?,
            PayloadSource::CustomIterator(c) => custom_iterator(c, cap)?,
        };
        let saturated = total > u128::from(u64::MAX);
        Ok(PayloadSet {
            truncated: total > items.len() as u128,
            items,
            total: total.min(u128::from(u64::MAX)) as u64,
            total_exact: total_exact && !saturated,
            max_count: cap,
            skipped: 0,
            dropped: Vec::new(),
        })
    }
}

fn check_len(len: usize) -> Result<(), PayloadError> {
    if len > MAX_ITEM_LEN {
        return Err(PayloadError::ItemTooLong {
            len,
            max: MAX_ITEM_LEN,
        });
    }
    Ok(())
}

/// How many values `from`, `to`, `step` describe, or an error if the three disagree.
fn range_count(from: i64, to: i64, step: i64) -> Result<u128, PayloadError> {
    if step == 0 {
        return Err(PayloadError::ZeroStep);
    }
    let (from, to, step) = (i128::from(from), i128::from(to), i128::from(step));
    let span = to - from;
    if (span > 0 && step < 0) || (span < 0 && step > 0) {
        return Err(PayloadError::BackwardsRange {
            from: from.to_string(),
            to: to.to_string(),
            step: step as i64,
        });
    }
    // `span == 0` is a single value, whatever the step's sign.
    Ok((span / step).unsigned_abs() + 1)
}

fn numbers(n: &Numbers, cap: usize) -> Result<(Vec<Bytes>, u128, bool), PayloadError> {
    match n.order {
        NumberOrder::Sequential => {
            let total = range_count(n.from, n.to, n.step)?;
            let take = (total.min(cap as u128)) as usize;
            let mut out = Vec::with_capacity(take);
            let mut v = i128::from(n.from);
            for _ in 0..take {
                let s = write_number(v, n.base, n.pad_to);
                check_len(s.len())?;
                out.push(Bytes::from(s.into_bytes()));
                v += i128::from(n.step);
            }
            Ok((out, total, true))
        }
        NumberOrder::Random => {
            // The range still has to make sense — a draw needs a low and a high, even though the
            // step does not participate.
            let (lo, hi) = (n.from.min(n.to), n.from.max(n.to));
            let total = n.count as u128;
            let take = n.count.min(cap);
            let mut rng = Rng::new(n.seed);
            let mut out = Vec::with_capacity(take);
            let width = (i128::from(hi) - i128::from(lo) + 1) as u128;
            for _ in 0..take {
                let v = i128::from(lo) + (rng.next() as u128 % width) as i128;
                let s = write_number(v, n.base, n.pad_to);
                check_len(s.len())?;
                out.push(Bytes::from(s.into_bytes()));
            }
            Ok((out, total, true))
        }
    }
}

fn write_number(v: i128, base: NumberBase, pad_to: usize) -> String {
    let neg = v < 0;
    let mag = v.unsigned_abs();
    let digits = match base {
        NumberBase::Decimal => mag.to_string(),
        NumberBase::Hex => format!("{mag:x}"),
    };
    let pad = pad_to.saturating_sub(digits.len()).min(MAX_ITEM_LEN);
    let mut s = String::with_capacity(digits.len() + pad + usize::from(neg));
    if neg {
        s.push('-');
    }
    for _ in 0..pad {
        s.push('0');
    }
    s.push_str(&digits);
    s
}

fn dates(d: &Dates, cap: usize) -> Result<(Vec<Bytes>, u128, bool), PayloadError> {
    let from = parse_date(&d.from)?;
    let to = parse_date(&d.to)?;
    let total = range_count(from, to, d.step)?;
    let take = (total.min(cap as u128)) as usize;
    let mut out = Vec::with_capacity(take);
    let mut day = from;
    for _ in 0..take {
        let s = format_date(day, &d.format);
        check_len(s.len())?;
        out.push(Bytes::from(s.into_bytes()));
        day = day.saturating_add(d.step);
    }
    Ok((out, total, true))
}

/// `YYYY-MM-DD` to a day number. Strict on purpose: a date the operator mistyped must not silently
/// become a different one.
fn parse_date(s: &str) -> Result<i64, PayloadError> {
    let bad = || PayloadError::BadDate(s.to_string());
    let mut parts = s.trim().split('-');
    // A leading `-` would be a negative year, which is not a date anyone types here.
    let y: i64 = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let m: u32 = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let d: u32 = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    if d > days_in_month(y, m) {
        return Err(bad());
    }
    Ok(days_from_civil(y, m, d))
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn format_date(day: i64, fmt: &str) -> String {
    let (y, m, d) = civil_from_days(day);
    let mut out = String::with_capacity(fmt.len() + 8);
    let b = fmt.as_bytes();
    let mut i = 0;
    while i < b.len() {
        // Longest token first: `yyyy` must not be read as two `yy`.
        if b[i..].starts_with(b"yyyy") {
            out.push_str(&format!("{y:04}"));
            i += 4;
        } else if b[i..].starts_with(b"yy") {
            out.push_str(&format!("{:02}", y.rem_euclid(100)));
            i += 2;
        } else if b[i..].starts_with(b"MMM") {
            // `civil_from_days` only ever returns 1..=12, but indexing is the wrong place to rely on
            // that: a clamp costs nothing and cannot panic if the arithmetic above ever changes.
            out.push_str(MONTHS[(m as usize).saturating_sub(1).min(11)]);
            i += 3;
        } else if b[i..].starts_with(b"MM") {
            out.push_str(&format!("{m:02}"));
            i += 2;
        } else if b[i..].starts_with(b"dd") {
            out.push_str(&format!("{d:02}"));
            i += 2;
        } else {
            // Byte-wise copy of everything else. `fmt` is `&str`, so pushing one byte at a time
            // would risk splitting a multi-byte character; copy the whole character instead.
            let ch = fmt[i..].chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01. Howard Hinnant's `days_from_civil`, which is exact for the whole `i64`
/// range and needs no table — cheaper to carry than a date library for one payload type.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn brute_force(b: &BruteForce, cap: usize) -> Result<(Vec<Bytes>, u128, bool), PayloadError> {
    let alphabet: Vec<Vec<u8>> = b
        .charset
        .chars()
        .map(|c| c.to_string().into_bytes())
        .collect();
    if alphabet.is_empty() {
        return Err(PayloadError::Empty("charset"));
    }
    let min = b.min_len.max(1);
    if b.max_len < min {
        return Err(PayloadError::BadLengthRange {
            min: b.min_len,
            max: b.max_len,
        });
    }
    // The longest possible item, checked before generating rather than on the way out: the answer
    // is the same for every item of that length, so one check settles it.
    let widest = alphabet.iter().map(|c| c.len()).max().unwrap_or(1);
    check_len(widest.saturating_mul(b.max_len))?;

    let n = alphabet.len() as u128;
    let mut total: u128 = 0;
    let mut saturated = false;
    for len in min..=b.max_len {
        match n.checked_pow(u32::try_from(len).unwrap_or(u32::MAX)) {
            Some(p) => match total.checked_add(p) {
                Some(t) => total = t,
                None => {
                    total = u128::MAX;
                    saturated = true;
                    break;
                }
            },
            None => {
                total = u128::MAX;
                saturated = true;
                break;
            }
        }
    }

    let take = total.min(cap as u128) as usize;
    let mut out = Vec::with_capacity(take);
    // Odometer, shortest string first and the last position varying fastest — counting order, which
    // is what an operator reading the results expects.
    let mut idx: Vec<usize> = vec![0; min];
    'outer: while out.len() < take {
        let mut item = Vec::with_capacity(idx.len() * widest);
        for i in &idx {
            item.extend_from_slice(&alphabet[*i]);
        }
        out.push(Bytes::from(item));
        // Increment.
        let mut p = idx.len();
        loop {
            if p == 0 {
                // Every position wrapped: move to the next length.
                if idx.len() >= b.max_len {
                    break 'outer;
                }
                idx = vec![0; idx.len() + 1];
                break;
            }
            p -= 1;
            idx[p] += 1;
            if idx[p] < alphabet.len() {
                break;
            }
            idx[p] = 0;
        }
    }
    Ok((out, total, !saturated))
}

fn custom_iterator(
    c: &CustomIterator,
    cap: usize,
) -> Result<(Vec<Bytes>, u128, bool), PayloadError> {
    if c.positions.len() < 2 {
        return Err(PayloadError::TooFewSlots(c.positions.len()));
    }
    for slot in &c.positions {
        if slot.is_empty() {
            return Err(PayloadError::Empty("custom iterator position slot"));
        }
    }
    let mut total: u128 = 1;
    let mut saturated = false;
    for slot in &c.positions {
        match total.checked_mul(slot.len() as u128) {
            Some(t) => total = t,
            None => {
                total = u128::MAX;
                saturated = true;
                break;
            }
        }
    }
    // Longest item is the longest choice in each slot, plus the separators. Settled once.
    let widest: usize = c
        .positions
        .iter()
        .map(|s| s.iter().map(|i| i.len()).max().unwrap_or(0))
        .sum::<usize>()
        + c.separator.len() * (c.positions.len() - 1);
    check_len(widest)?;

    let take = total.min(cap as u128) as usize;
    let mut out = Vec::with_capacity(take);
    let mut idx: Vec<usize> = vec![0; c.positions.len()];
    while out.len() < take {
        let mut item = Vec::with_capacity(widest);
        for (j, slot) in c.positions.iter().enumerate() {
            if j > 0 {
                item.extend_from_slice(c.separator.as_bytes());
            }
            item.extend_from_slice(slot[idx[j]].as_bytes());
        }
        out.push(Bytes::from(item));
        // Last slot fastest, as Burp's own iterator does.
        let mut p = c.positions.len();
        loop {
            if p == 0 {
                return Ok((out, total, !saturated));
            }
            p -= 1;
            idx[p] += 1;
            if idx[p] < c.positions[p].len() {
                break;
            }
            idx[p] = 0;
        }
    }
    Ok((out, total, !saturated))
}

/// SplitMix64. Sixteen lines and a well-known constant, against a `rand` dependency in a crate whose
/// manifest is narrowed on purpose. Payload selection is not a security decision — this picks which
/// of the operator's own numbers to try, and it is not used for anything a target could predict to
/// its advantage.
struct Rng(u64);

impl Rng {
    fn new(seed: Option<u64>) -> Self {
        Self(seed.unwrap_or_else(|| {
            // Unseeded means "any values will do"; the clock is enough entropy for that, and the
            // counter keeps two sets resolved in the same nanosecond from matching.
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x2545_F491_4F6C_DD1D);
            nanos ^ N.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
        }))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ---- deliberately absent -------------------------------------------------------------------
//
// **Recursive grep** is Burp's payload type that takes each response's grep-extract result and uses
// it as the next request's payload. It is not implemented as a `PayloadSource` and should not be: a
// source resolves to a `Vec<Bytes>` *before* the attack runs, and a recursive-grep payload does not
// exist until the previous response has come back. Faking it here would mean either resolving to an
// empty set (an attack that silently sends nothing) or teaching the engine to pull payloads from a
// generator mid-flight — which would take away the property that makes a result row 40 bytes: that
// `AttackPlan` derives request `i` from `i` alone.
//
// If it is wanted, it is a *different shape of attack* (a serial chain of length 1, with the next
// payload read off the previous response) and belongs next to `AttackKind`, not here.
//
// Also absent, and merely not yet done rather than refused: Character substitution, Bit flipper,
// Illegal Unicode, Character blocks, Username generator, ECB block shuffler, Copy other payload.
// Each is a pure function of a base value or of a length range and fits this module unchanged.

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(set: &PayloadSet) -> Vec<String> {
        set.items
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect()
    }

    #[test]
    fn a_generator_produces_the_same_shape_a_literal_list_does() {
        // The whole premise: nothing downstream can tell a generated set from a typed one.
        let list = PayloadSource::List {
            items: vec!["1".into(), "2".into(), "3".into()],
        }
        .resolve(100)
        .unwrap();
        let generated = PayloadSource::Numbers(Numbers {
            from: 1,
            to: 3,
            step: 1,
            order: NumberOrder::Sequential,
            count: 0,
            base: NumberBase::Decimal,
            pad_to: 0,
            seed: None,
        })
        .resolve(100)
        .unwrap();
        assert_eq!(generated.items, list.items);
    }

    #[test]
    fn sequential_numbers_walk_the_range_inclusively() {
        let s = PayloadSource::Numbers(Numbers {
            from: 10,
            to: 20,
            step: 5,
            order: NumberOrder::Sequential,
            count: 0,
            base: NumberBase::Decimal,
            pad_to: 0,
            seed: None,
        })
        .resolve(100)
        .unwrap();
        assert_eq!(strs(&s), vec!["10", "15", "20"]);
        assert_eq!(s.total, 3);
        assert!(!s.truncated);
    }

    #[test]
    fn numbers_count_down_when_the_step_is_negative() {
        let s = PayloadSource::Numbers(Numbers {
            from: 3,
            to: 1,
            step: -1,
            order: NumberOrder::Sequential,
            count: 0,
            base: NumberBase::Decimal,
            pad_to: 0,
            seed: None,
        })
        .resolve(100)
        .unwrap();
        assert_eq!(strs(&s), vec!["3", "2", "1"]);
    }

    #[test]
    fn hex_and_zero_padding_are_applied_to_the_digits_not_the_sign() {
        let s = PayloadSource::Numbers(Numbers {
            from: 254,
            to: 256,
            step: 1,
            order: NumberOrder::Sequential,
            count: 0,
            base: NumberBase::Hex,
            pad_to: 4,
            seed: None,
        })
        .resolve(100)
        .unwrap();
        assert_eq!(strs(&s), vec!["00fe", "00ff", "0100"]);

        let neg = PayloadSource::Numbers(Numbers {
            from: -7,
            to: -7,
            step: 1,
            order: NumberOrder::Sequential,
            count: 0,
            base: NumberBase::Decimal,
            pad_to: 4,
            seed: None,
        })
        .resolve(10)
        .unwrap();
        assert_eq!(strs(&neg), vec!["-0007"]);
    }

    /// A step of zero would loop forever if it were generated and produce an empty set if it were
    /// merely counted. Neither is an answer, so it is refused.
    #[test]
    fn a_zero_step_is_refused_rather_than_producing_an_empty_set() {
        let e = PayloadSource::Numbers(Numbers {
            from: 1,
            to: 9,
            step: 0,
            order: NumberOrder::Sequential,
            count: 0,
            base: NumberBase::Decimal,
            pad_to: 0,
            seed: None,
        })
        .resolve(100)
        .unwrap_err();
        assert_eq!(e, PayloadError::ZeroStep);
    }

    #[test]
    fn a_step_pointing_away_from_the_end_of_the_range_is_refused() {
        let e = PayloadSource::Numbers(Numbers {
            from: 1,
            to: 100,
            step: -1,
            order: NumberOrder::Sequential,
            count: 0,
            base: NumberBase::Decimal,
            pad_to: 0,
            seed: None,
        })
        .resolve(100)
        .unwrap_err();
        assert!(matches!(e, PayloadError::BackwardsRange { .. }), "{e}");
    }

    #[test]
    fn a_seeded_random_draw_is_reproducible_and_stays_inside_the_range() {
        let cfg = Numbers {
            from: 100,
            to: 199,
            step: 1,
            order: NumberOrder::Random,
            count: 50,
            base: NumberBase::Decimal,
            pad_to: 0,
            seed: Some(42),
        };
        let a = PayloadSource::Numbers(cfg.clone()).resolve(1_000).unwrap();
        let b = PayloadSource::Numbers(cfg).resolve(1_000).unwrap();
        assert_eq!(a.items, b.items, "a seeded draw must replay identically");
        assert_eq!(a.len(), 50);
        for v in strs(&a) {
            let n: i64 = v.parse().unwrap();
            assert!((100..=199).contains(&n), "{n} escaped the range");
        }
        // And it is actually varying, not fifty copies of one number.
        let mut uniq = strs(&a);
        uniq.sort();
        uniq.dedup();
        assert!(uniq.len() > 10, "only {} distinct draws", uniq.len());
    }

    #[test]
    fn dates_walk_a_range_through_the_format_string() {
        let s = PayloadSource::Dates(Dates {
            from: "2026-02-27".into(),
            to: "2026-03-02".into(),
            step: 1,
            format: "dd/MM/yyyy".into(),
        })
        .resolve(100)
        .unwrap();
        // 2026 is not a leap year, so February ends on the 28th.
        assert_eq!(
            strs(&s),
            vec!["27/02/2026", "28/02/2026", "01/03/2026", "02/03/2026"]
        );
    }

    #[test]
    fn a_leap_day_is_produced_and_a_non_leap_29th_of_february_is_refused() {
        let s = PayloadSource::Dates(Dates {
            from: "2024-02-28".into(),
            to: "2024-03-01".into(),
            step: 1,
            format: "yyyy-MM-dd".into(),
        })
        .resolve(100)
        .unwrap();
        assert_eq!(strs(&s), vec!["2024-02-28", "2024-02-29", "2024-03-01"]);

        let e = PayloadSource::Dates(Dates {
            from: "2026-02-29".into(),
            to: "2026-03-01".into(),
            step: 1,
            format: "yyyy-MM-dd".into(),
        })
        .resolve(100)
        .unwrap_err();
        assert!(matches!(e, PayloadError::BadDate(_)), "{e}");
    }

    #[test]
    fn the_longest_format_token_wins_so_yyyy_is_not_two_yy() {
        let s = PayloadSource::Dates(Dates {
            from: "2026-07-04".into(),
            to: "2026-07-04".into(),
            step: 1,
            format: "yyyy yy MMM MM dd!".into(),
        })
        .resolve(10)
        .unwrap();
        assert_eq!(strs(&s), vec!["2026 26 Jul 07 04!"]);
    }

    #[test]
    fn brute_force_covers_every_string_shortest_first() {
        let s = PayloadSource::BruteForce(BruteForce {
            charset: "ab".into(),
            min_len: 1,
            max_len: 2,
        })
        .resolve(100)
        .unwrap();
        assert_eq!(strs(&s), vec!["a", "b", "aa", "ab", "ba", "bb"]);
        assert_eq!(s.total, 6, "2 + 4");
    }

    /// The point of the bound: a config that describes 2.2×10^14 payloads must cost the cap, not
    /// the count — and the operator must be told what they asked for.
    #[test]
    fn an_enormous_brute_force_is_capped_and_says_what_it_would_have_been() {
        let s = PayloadSource::BruteForce(BruteForce {
            charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".into(),
            min_len: 1,
            max_len: 8,
        })
        .resolve(1_000)
        .unwrap();
        assert_eq!(s.len(), 1_000, "the cap, not the count, is what got built");
        assert!(s.truncated);
        assert!(s.total_exact);
        assert_eq!(s.total, 221_919_451_578_090, "sum of 62^1..62^8");
        assert_eq!(s.max_count, 1_000);
    }

    #[test]
    fn no_caller_can_ask_for_an_unbounded_set() {
        let s = PayloadSource::BruteForce(BruteForce {
            charset: "abcdefghij".into(),
            min_len: 1,
            max_len: 12,
        })
        .resolve(usize::MAX)
        .unwrap();
        assert_eq!(
            s.len(),
            MAX_PAYLOADS,
            "usize::MAX must still land on the hard ceiling"
        );
        assert!(s.truncated);
    }

    #[test]
    fn a_payload_too_long_to_be_itself_is_refused_not_shortened() {
        let e = PayloadSource::BruteForce(BruteForce {
            charset: "ab".into(),
            min_len: 1,
            max_len: MAX_ITEM_LEN + 1,
        })
        .resolve(10)
        .unwrap_err();
        assert!(matches!(e, PayloadError::ItemTooLong { .. }), "{e}");
    }

    #[test]
    fn a_multibyte_charset_is_split_by_character_not_by_byte() {
        let s = PayloadSource::BruteForce(BruteForce {
            charset: "aé".into(),
            min_len: 1,
            max_len: 1,
        })
        .resolve(10)
        .unwrap();
        assert_eq!(strs(&s), vec!["a", "é"]);
    }

    #[test]
    fn a_custom_iterator_permutes_its_slots_with_the_last_varying_fastest() {
        let s = PayloadSource::CustomIterator(CustomIterator {
            positions: vec![
                vec!["adm".into(), "usr".into()],
                vec!["1".into(), "2".into(), "3".into()],
            ],
            separator: "-".into(),
        })
        .resolve(100)
        .unwrap();
        assert_eq!(
            strs(&s),
            vec!["adm-1", "adm-2", "adm-3", "usr-1", "usr-2", "usr-3"]
        );
        assert_eq!(s.total, 6);
    }

    #[test]
    fn a_custom_iterator_with_one_slot_is_a_list_and_is_refused_as_one() {
        let e = PayloadSource::CustomIterator(CustomIterator {
            positions: vec![vec!["only".into()]],
            separator: String::new(),
        })
        .resolve(10)
        .unwrap_err();
        assert_eq!(e, PayloadError::TooFewSlots(1));
    }

    #[test]
    fn an_empty_slot_is_refused_rather_than_silently_erasing_the_product() {
        let e = PayloadSource::CustomIterator(CustomIterator {
            positions: vec![vec!["a".into()], vec![]],
            separator: String::new(),
        })
        .resolve(10)
        .unwrap_err();
        assert!(matches!(e, PayloadError::Empty(_)), "{e}");
    }

    #[test]
    fn null_payloads_are_n_unchanged_requests() {
        let s = PayloadSource::Null { count: 4 }.resolve(100).unwrap();
        assert_eq!(s.len(), 4);
        assert!(s.items.iter().all(|b| b.is_empty()));
        assert_eq!(s.total, 4);
    }

    #[test]
    fn civil_date_arithmetic_round_trips_across_a_century() {
        for y in [1970i64, 1999, 2000, 2024, 2026, 2100] {
            for m in 1..=12u32 {
                let d = days_in_month(y, m);
                let n = days_from_civil(y, m, d);
                assert_eq!(civil_from_days(n), (y, m, d), "{y}-{m}-{d} did not survive");
            }
        }
    }
}
