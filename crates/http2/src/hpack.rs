//! HPACK (RFC 7541): the primitive integer and string encodings, the static and dynamic tables,
//! and a decoder for all five header field representations.
//!
//! # Why a decoder belongs in a crate that emits, not just parses
//!
//! [`crate::frame`]'s doc comment already makes the case for hand-writing the frame layer: a
//! compliant HPACK implementation refuses to *show you* a header block it judges malformed, and
//! burpsy's whole reason to exist is showing a tester exactly what a peer sent. The same argument
//! applies here at one level down — see the crate root for the fuller version.
//!
//! # Huffman is slice 2b, not here
//!
//! [`decode_string`] bounds-checks and slices every string literal regardless of its Huffman flag,
//! but a set flag returns [`HpackError::HuffmanNotImplemented`] rather than decoding it. That is
//! the seam slice 2b replaces: exactly that one `if huffman` arm, nothing else. Passing the raw
//! Huffman-coded octets through as though they were the literal value would be worse than
//! refusing them — it would silently hand a caller bytes that are not the header value they claim
//! to be.
//!
//! # One decoder per (connection, direction)
//!
//! A dynamic table is connection state accumulated across every header block sent in one
//! direction (RFC 7541 §2.3.2): each call to [`Decoder::decode`] both reads and mutates it. A
//! [`Decoder`] must therefore live exactly as long as one direction of one connection, and a
//! fresh request/response pair must **not** get a fresh `Decoder` — the encoder on the other end
//! is still referencing index 62 as whatever it inserted last, and a decoder that forgot that
//! disagrees with the peer about what index 62 means. Two directions must not share one
//! `Decoder` either: a request's insertions and a response's insertions are two independent
//! tables in the real protocol, and merging them produces indices that resolve to whichever
//! direction happened to insert more recently. Both mistakes are worse than a crash, because
//! they do not look wrong — they produce a fully-formed, plausible, wrong header list.
//!
//! # The encoder's representation strategy is a choice, not a fact
//!
//! RFC 7541 lets an encoder pick, for each field, among an indexed reference (§6.1), a literal
//! with an indexed name (§6.2.1), or a literal with everything spelled out (§6.2.1 again, index
//! 0). [`Encoder`] resolves that choice deterministically: exact name+value match anywhere in the
//! combined static/dynamic address space wins (cheapest on the wire, no insertion); otherwise a
//! name-only match reuses the name and inserts the pair; otherwise both strings are literal and
//! the pair is inserted. It never emits "without indexing" (§6.2.2) or "never indexed" (§6.2.3) —
//! those exist for a sender who wants a field to skip the table, which is not a distinction this
//! encoder's callers currently need to express — and it never emits Huffman-coded strings, for the
//! same reason [`decode_string`] never decodes them: see "Huffman is slice 2b" above. Every string
//! this encoder writes sets H=0, which is spec-legal (Huffman is always optional) and costs bytes
//! on the wire versus a real encoder, not a bug.

use bytes::Bytes;
use std::collections::VecDeque;

/// The RFC 7541 Appendix A static table. Index `i` (1-based) is `STATIC_TABLE[i - 1]`.
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// A fault found while decoding a header block, always carrying the byte offset (into the block
/// passed to [`Decoder::decode`]) it was found at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpackError {
    /// Fewer bytes remain than a representation needs to start or continue.
    Truncated { at: usize, need: usize, have: usize },
    /// A prefix integer (§5.1) did not terminate within the continuation-octet bound this decoder
    /// enforces.
    IntegerTooLong { at: usize },
    /// A string literal's declared length (§5.2) reaches past the end of the block.
    StringLengthOverrun {
        at: usize,
        declared: usize,
        remaining: usize,
    },
    /// A string literal's Huffman flag is set. Slice 2b's seam — see the module doc.
    HuffmanNotImplemented { at: usize },
    /// Index 0 in an indexed header field representation (§6.1) — reserved, never valid.
    ZeroIndex { at: usize },
    /// An index names neither a static nor a dynamic table entry.
    IndexOutOfRange {
        at: usize,
        index: u64,
        table_size: usize,
    },
    /// A §6.3 dynamic table size update exceeded the maximum this connection negotiated.
    TableSizeTooLarge {
        at: usize,
        requested: u64,
        max: usize,
    },
}

impl HpackError {
    /// The byte offset the fault was found at, so callers can report position uniformly without
    /// matching on the variant.
    pub fn at(&self) -> usize {
        match self {
            HpackError::Truncated { at, .. }
            | HpackError::IntegerTooLong { at }
            | HpackError::StringLengthOverrun { at, .. }
            | HpackError::HuffmanNotImplemented { at }
            | HpackError::ZeroIndex { at }
            | HpackError::IndexOutOfRange { at, .. }
            | HpackError::TableSizeTooLarge { at, .. } => *at,
        }
    }
}

impl std::fmt::Display for HpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Each arm says what the failure means for an operator, not which field disagreed.
        match self {
            HpackError::Truncated { at, need, have } => write!(
                f,
                "header block at byte {at} needs at least {need} more byte(s) but only {have} \
                 remain — the block ends mid-representation, whether by truncation or by design"
            ),
            HpackError::IntegerTooLong { at } => write!(
                f,
                "the integer at byte {at} did not terminate within the continuation-octet bound \
                 this decoder enforces — a peer that never clears the continuation bit is trying \
                 to make the decoder loop or overflow, not encoding a legitimately large value"
            ),
            HpackError::StringLengthOverrun {
                at,
                declared,
                remaining,
            } => write!(
                f,
                "the string literal at byte {at} declares {declared} byte(s) but only {remaining} \
                 remain in the block — the length is corrupt or the block was truncated"
            ),
            HpackError::HuffmanNotImplemented { at } => write!(
                f,
                "the string literal at byte {at} sets the Huffman flag, which this decoder does \
                 not yet implement — refusing to hand back its raw octets as though they were the \
                 literal value"
            ),
            HpackError::ZeroIndex { at } => write!(
                f,
                "the indexed header field at byte {at} names index 0, which RFC 7541 §6.1 \
                 reserves — no table entry ever occupies it"
            ),
            HpackError::IndexOutOfRange {
                at,
                index,
                table_size,
            } => write!(
                f,
                "the header field at byte {at} names index {index}, but the static and dynamic \
                 tables together currently hold only {table_size} entries"
            ),
            HpackError::TableSizeTooLarge { at, requested, max } => write!(
                f,
                "the dynamic table size update at byte {at} requests {requested} byte(s), which \
                 exceeds the {max}-byte maximum this connection negotiated"
            ),
        }
    }
}

impl std::error::Error for HpackError {}

/// The cost §4.1 assigns an entry: both strings' lengths plus a fixed 32-octet estimate of
/// per-entry bookkeeping overhead. Not the encoder's Huffman-compressed size — the size on the
/// wire is deliberately irrelevant to how much table space an entry costs.
fn entry_cost(name: &Bytes, value: &Bytes) -> usize {
    name.len() + value.len() + 32
}

/// How many continuation octets (§5.1) a prefix integer may use before this decoder gives up on
/// it. Five octets carries a prefix integer past 2^35, which is already far beyond any index,
/// length, or table size this crate will ever need to represent; a peer sending more than that is
/// not encoding a legitimate value; it is trying to make the decode loop or wrap. This is a cap
/// this implementation chooses, not a number the RFC states.
const MAX_INTEGER_CONTINUATION_OCTETS: usize = 5;

/// Decode a prefix integer (§5.1): `block[at]`'s low `prefix_bits` bits are the prefix, followed
/// by zero or more continuation octets. Returns the value and the total octets consumed.
///
/// Bounded, not looping: the continuation loop runs at most
/// [`MAX_INTEGER_CONTINUATION_OCTETS`] times and every accumulation is a checked add, so a peer
/// that never clears the continuation bit gets [`HpackError::IntegerTooLong`] instead of an
/// unbounded loop or a silently wrapped value.
fn decode_int(block: &[u8], at: usize, prefix_bits: u32) -> Result<(u64, usize), HpackError> {
    debug_assert!((1..=8).contains(&prefix_bits));
    let prefix_max: u64 = (1u64 << prefix_bits) - 1;
    let first = *block.get(at).ok_or(HpackError::Truncated {
        at,
        need: 1,
        have: 0,
    })?;
    let prefix_val = (first as u64) & prefix_max;
    if prefix_val < prefix_max {
        return Ok((prefix_val, 1));
    }

    let mut value = prefix_max;
    let mut shift: u32 = 0;
    for i in 0..MAX_INTEGER_CONTINUATION_OCTETS {
        let byte_at = at + 1 + i;
        let byte = *block.get(byte_at).ok_or(HpackError::Truncated {
            at: byte_at,
            need: 1,
            have: 0,
        })?;
        value = value
            .checked_add(((byte & 0x7F) as u64) << shift)
            .ok_or(HpackError::IntegerTooLong { at })?;
        if byte & 0x80 == 0 {
            return Ok((value, 1 + i + 1));
        }
        shift += 7;
    }
    Err(HpackError::IntegerTooLong { at })
}

/// Decode a length-prefixed string (§5.2): a Huffman flag in the length octet's top bit, a 7-bit
/// length prefix, then that many raw octets. Bounds-checks the declared length against what
/// remains in `block` **before** slicing — a declared length is attacker-influenced and must
/// never reach a slice operation unchecked.
///
/// A set Huffman flag is [`HpackError::HuffmanNotImplemented`] — slice 2b's seam, see the module
/// doc. Bounds-checking happens first regardless of the flag, so a too-long Huffman string is
/// still reported as a length overrun rather than masked by the not-implemented error.
fn decode_string(block: &[u8], at: usize) -> Result<(Bytes, usize), HpackError> {
    let (len, int_len) = decode_int(block, at, 7)?;
    // `decode_int` already proved `block[at]` exists.
    let huffman = block[at] & 0x80 != 0;
    let data_at = at + int_len;
    let remaining = block.len().saturating_sub(data_at);
    // `usize::MAX` is never a real length; a `len` too large for this platform's `usize` folds
    // into it, which is guaranteed to compare greater than `remaining` below rather than wrap.
    let declared = usize::try_from(len).unwrap_or(usize::MAX);
    if declared > remaining {
        return Err(HpackError::StringLengthOverrun {
            at: data_at,
            declared,
            remaining,
        });
    }
    if huffman {
        // SEAM(slice 2b): replace this arm with the Huffman decode of
        // `block[data_at..data_at + declared]`. Everything above it — the length prefix, the
        // bounds check against `remaining` — is unchanged by that replacement.
        return Err(HpackError::HuffmanNotImplemented { at });
    }
    let bytes = Bytes::copy_from_slice(&block[data_at..data_at + declared]);
    Ok((bytes, int_len + declared))
}

/// Encode a prefix integer (§5.1), the exact inverse of [`decode_int`]: `pattern` already carries
/// the representation's high bits shifted into position (e.g. `0x80` for an indexed field's
/// leading `1`), and `value`'s low `prefix_bits` bits share that same first octet, spilling into
/// as many continuation octets as `value` needs once it does not fit.
fn encode_int(out: &mut Vec<u8>, value: u64, prefix_bits: u32, pattern: u8) {
    debug_assert!((1..=8).contains(&prefix_bits));
    let prefix_max: u64 = (1u64 << prefix_bits) - 1;
    if value < prefix_max {
        out.push(pattern | value as u8);
        return;
    }
    out.push(pattern | prefix_max as u8);
    let mut remaining = value - prefix_max;
    while remaining >= 0x80 {
        out.push(((remaining & 0x7f) as u8) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

/// Encode a length-prefixed string (§5.2). Always `H=0` — see the module doc's note on why this
/// encoder never Huffman-codes — so the length prefix's top bit, which [`decode_string`] reads as
/// the Huffman flag, is always clear.
fn encode_string(out: &mut Vec<u8>, data: &Bytes) {
    encode_int(out, data.len() as u64, 7, 0x00);
    out.extend_from_slice(data);
}

/// A stateful HPACK decoder: the dynamic table for one direction of one connection, plus the size
/// limits that bound it. See the module doc for why one instance must not span two directions or
/// be dropped between header blocks on the same one.
#[derive(Debug)]
pub struct Decoder {
    /// Newest entry at the front (index 62), oldest at the back — matching §2.3.2's index order
    /// directly, so lookup needs no reversal.
    dynamic: VecDeque<(Bytes, Bytes)>,
    /// Sum of `entry_cost` over `dynamic`. Maintained incrementally rather than recomputed, since
    /// every insert and evict already touches the entries that would need re-summing.
    dynamic_size: usize,
    /// The ceiling a §6.3 size update may not exceed — the peer's `SETTINGS_HEADER_TABLE_SIZE`,
    /// fixed for the life of this decoder.
    max_table_size: usize,
    /// The currently active limit eviction enforces. Starts equal to `max_table_size` and can
    /// only move within `[0, max_table_size]` via §6.3 updates.
    table_size_limit: usize,
}

impl Decoder {
    /// A fresh decoder with an empty dynamic table, bounded by `max_table_size` — the value this
    /// connection's peer advertised as `SETTINGS_HEADER_TABLE_SIZE`.
    pub fn new(max_table_size: usize) -> Self {
        Self {
            dynamic: VecDeque::new(),
            dynamic_size: 0,
            max_table_size,
            table_size_limit: max_table_size,
        }
    }

    /// Decode one header block, applying its representations in order against this decoder's
    /// dynamic table and returning the decoded header list.
    ///
    /// The returned list preserves order and duplicates exactly as the block encodes them: no
    /// lowercasing, deduplication, reordering, or merging. An uppercase field name is invalid
    /// HTTP/2 (RFC 9113 §8.2.1), but this layer's job is to report what a peer sent, not to
    /// correct it — see [`crate::frame`]'s doc comment for the same argument made about frames.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(Bytes, Bytes)>, HpackError> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < block.len() {
            let first = block[at];
            if first & 0x80 != 0 {
                // §6.1 Indexed Header Field.
                let (index, len) = decode_int(block, at, 7)?;
                let (name, value) = self.lookup(index, at)?;
                out.push((name, value));
                at += len;
            } else if first & 0x40 != 0 {
                // §6.2.1 Literal Header Field with Incremental Indexing.
                let (name, value, len) = self.decode_literal(block, at, 6)?;
                self.insert(name.clone(), value.clone());
                out.push((name, value));
                at += len;
            } else if first & 0x20 != 0 {
                // §6.3 Dynamic Table Size Update.
                let (new_max, len) = decode_int(block, at, 5)?;
                self.apply_size_update(new_max, at)?;
                at += len;
            } else {
                // §6.2.2 (0000) and §6.2.3 (0001) share the same wire shape and the same
                // "do not touch the dynamic table" behaviour; only re-encoding rules distinguish
                // them (§6.2.3), which is not this decoder's concern.
                let (name, value, len) = self.decode_literal(block, at, 4)?;
                out.push((name, value));
                at += len;
            }
        }
        Ok(out)
    }

    /// The shared shape of §6.2.1/§6.2.2/§6.2.3: an optionally-indexed name (`prefix_bits` wide,
    /// 0 meaning "literal name follows") followed by a literal value. Returns the decoded
    /// `(name, value)` and the total octets the whole representation consumed, but never touches
    /// the dynamic table — inserting on incremental indexing is the caller's job, since only one
    /// of the three representations does it.
    fn decode_literal(
        &self,
        block: &[u8],
        at: usize,
        prefix_bits: u32,
    ) -> Result<(Bytes, Bytes, usize), HpackError> {
        let (name_index, idx_len) = decode_int(block, at, prefix_bits)?;
        let mut pos = at + idx_len;
        let name = if name_index == 0 {
            let (name, consumed) = decode_string(block, pos)?;
            pos += consumed;
            name
        } else {
            // Index 0 already handled above, so a genuine zero-index error here can only mean
            // §6.1's reserved index — see `lookup`.
            let (name, _value) = self.lookup(name_index, at)?;
            name
        };
        let (value, consumed) = decode_string(block, pos)?;
        pos += consumed;
        Ok((name, value, pos - at))
    }

    /// Resolve an index (§2.3.3) to its `(name, value)`. Index 0 and an index past the combined
    /// address space are both errors; nothing else in this decoder produces index 0 as an
    /// argument here, since [`Self::decode_literal`] intercepts it before calling in.
    fn lookup(&self, index: u64, at: usize) -> Result<(Bytes, Bytes), HpackError> {
        if index == 0 {
            return Err(HpackError::ZeroIndex { at });
        }
        // `index` is bounded to roughly 2^35 by `decode_int`'s continuation-octet cap, so this
        // narrowing cannot silently wrap even on a 32-bit `usize`: a value too large to fit folds
        // to `usize::MAX`, which fails both range checks below exactly like a genuinely
        // out-of-range index would.
        let idx = usize::try_from(index).unwrap_or(usize::MAX);
        if idx <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[idx - 1];
            return Ok((
                Bytes::from_static(name.as_bytes()),
                Bytes::from_static(value.as_bytes()),
            ));
        }
        let dyn_idx = idx - STATIC_TABLE.len() - 1;
        self.dynamic
            .get(dyn_idx)
            .cloned()
            .ok_or(HpackError::IndexOutOfRange {
                at,
                index,
                table_size: STATIC_TABLE.len() + self.dynamic.len(),
            })
    }

    /// Insert a new entry at the front, evicting from the back (§4.4) until it fits. An entry
    /// larger than the whole table's current limit empties the table rather than being rejected
    /// or truncated — that emptying already happened by the time the eviction loop below exits,
    /// so the entry is simply never pushed.
    fn insert(&mut self, name: Bytes, value: Bytes) {
        let cost = entry_cost(&name, &value);
        while self.dynamic_size + cost > self.table_size_limit && !self.dynamic.is_empty() {
            let (n, v) = self
                .dynamic
                .pop_back()
                .expect("checked non-empty in the loop condition");
            self.dynamic_size -= entry_cost(&n, &v);
        }
        if cost <= self.table_size_limit {
            self.dynamic.push_front((name, value));
            self.dynamic_size += cost;
        }
        // Else: eviction above already emptied the table (or left it as small as it can get)
        // and this entry is still too big — §4.4 says do not insert it.
    }

    /// Apply a §6.3 dynamic table size update: `new_max` above `max_table_size` is an error (the
    /// peer would be raising the bound past what it itself negotiated), otherwise entries are
    /// evicted from the back (§4.3) until the table fits the new limit.
    fn apply_size_update(&mut self, new_max: u64, at: usize) -> Result<(), HpackError> {
        if new_max > self.max_table_size as u64 {
            return Err(HpackError::TableSizeTooLarge {
                at,
                requested: new_max,
                max: self.max_table_size,
            });
        }
        // The check above proves `new_max <= self.max_table_size`, which is a `usize`, so this
        // narrowing is exact.
        self.table_size_limit = new_max as usize;
        while self.dynamic_size > self.table_size_limit {
            let (n, v) = self
                .dynamic
                .pop_back()
                .expect("dynamic_size > limit implies at least one entry remains");
            self.dynamic_size -= entry_cost(&n, &v);
        }
        Ok(())
    }

    /// Number of entries currently in the dynamic table.
    pub fn dynamic_table_len(&self) -> usize {
        self.dynamic.len()
    }

    /// Sum of `entry_cost` over the dynamic table — what RFC 7541 calls the table's size.
    pub fn dynamic_table_bytes(&self) -> usize {
        self.dynamic_size
    }

    /// A snapshot of the dynamic table's entries, newest first — the same order §2.3.2 indexes
    /// them in. Beyond the two summary accessors above, tests need this to assert against the
    /// RFC's own "Dynamic Table (after decoding)" listings, which name entries, not just counts.
    pub fn dynamic_table_entries(&self) -> Vec<(Bytes, Bytes)> {
        self.dynamic.iter().cloned().collect()
    }
}

/// Where a field's name and/or value already live in the combined static+dynamic address space
/// (RFC 7541 §2.3.3), found by [`Encoder::find`]. Drives the §6.1 vs §6.2.1 choice documented in
/// the module doc.
enum TableMatch {
    /// Both name and value match this 1-based combined index — cheapest: an indexed field, no
    /// insertion.
    NameAndValue(usize),
    /// Only the name matches this 1-based combined index — the value is still literal, but the
    /// name need not be spelled out.
    NameOnly(usize),
    /// Neither matches: both strings must be literal.
    Neither,
}

/// A stateful HPACK encoder: the mirror image of [`Decoder`], carrying the dynamic table for one
/// direction of one connection. The same one-decoder-per-direction argument in the module doc
/// applies here identically — an encoder inserts into its table exactly when the peer's decoder
/// would insert into its own from the octets produced, so the two must evolve in lockstep, which
/// means one long-lived `Encoder` per direction, never a fresh one per header block.
#[derive(Debug)]
pub struct Encoder {
    /// Newest entry at the front (index 62), oldest at the back — same layout and index order as
    /// [`Decoder::dynamic`], so the two stay directly comparable.
    dynamic: VecDeque<(Bytes, Bytes)>,
    /// Sum of `entry_cost` over `dynamic`, maintained incrementally like the decoder's.
    dynamic_size: usize,
    /// The table-size budget this encoder respects (RFC 7541 §4.2) — the peer's advertised
    /// `SETTINGS_HEADER_TABLE_SIZE`. Unlike [`Decoder`], there is no separate "currently active"
    /// limit: this encoder never receives a §6.3 size-update instruction from anyone (it is the
    /// one who would *emit* one, which no caller currently asks for), so `max_table_size` is the
    /// limit, full stop.
    max_table_size: usize,
}

impl Encoder {
    /// A fresh encoder with an empty dynamic table, bounded by `max_table_size` — the peer's
    /// advertised `SETTINGS_HEADER_TABLE_SIZE` for this direction.
    pub fn new(max_table_size: usize) -> Self {
        Self {
            dynamic: VecDeque::new(),
            dynamic_size: 0,
            max_table_size,
        }
    }

    /// Encode one header block: every field in `fields`, in order, against this encoder's
    /// dynamic table — mutating it exactly as a peer decoding the output would mutate its own.
    ///
    /// `fields` is encoded verbatim: duplicate names, unusual casing, and pseudo-headers
    /// (`:`-prefixed names) are ordinary fields here, never reordered or treated specially — the
    /// crate's header-list-exactness guarantee (see the crate root) starts with this function not
    /// disturbing what it was given.
    pub fn encode(&mut self, fields: &[(Bytes, Bytes)]) -> Bytes {
        let mut out = Vec::new();
        for (name, value) in fields {
            self.encode_field(&mut out, name, value);
        }
        Bytes::from(out)
    }

    /// Choose and emit one field's representation, per the strategy in the module doc.
    fn encode_field(&mut self, out: &mut Vec<u8>, name: &Bytes, value: &Bytes) {
        match self.find(name, value) {
            TableMatch::NameAndValue(index) => {
                // §6.1 Indexed Header Field: the whole field is one integer, no insertion.
                encode_int(out, index as u64, 7, 0x80);
            }
            TableMatch::NameOnly(index) => {
                // §6.2.1 Literal Header Field with Incremental Indexing, indexed name.
                encode_int(out, index as u64, 6, 0x40);
                encode_string(out, value);
                self.insert(name.clone(), value.clone());
            }
            TableMatch::Neither => {
                // §6.2.1 Literal Header Field with Incremental Indexing, new name (index 0 in a
                // 6-bit prefix is always a single `0x40` octet — it never needs continuation).
                out.push(0x40);
                encode_string(out, name);
                encode_string(out, value);
                self.insert(name.clone(), value.clone());
            }
        }
    }

    /// Search the static table, then the dynamic table (newest first), for `name`/`value`. An
    /// exact match anywhere returns immediately; a name-only match is remembered but the search
    /// continues, since an exact match found later is strictly better and must win.
    fn find(&self, name: &Bytes, value: &Bytes) -> TableMatch {
        let mut name_only: Option<usize> = None;
        for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
            if n.as_bytes() == name.as_ref() {
                if v.as_bytes() == value.as_ref() {
                    return TableMatch::NameAndValue(i + 1);
                }
                name_only.get_or_insert(i + 1);
            }
        }
        for (i, (n, v)) in self.dynamic.iter().enumerate() {
            if n == name {
                if v == value {
                    return TableMatch::NameAndValue(STATIC_TABLE.len() + i + 1);
                }
                name_only.get_or_insert(STATIC_TABLE.len() + i + 1);
            }
        }
        match name_only {
            Some(index) => TableMatch::NameOnly(index),
            None => TableMatch::Neither,
        }
    }

    /// Insert a new entry at the front, evicting from the back (§4.4) until it fits — identical
    /// accounting to [`Decoder::insert`], including the same "too big to ever fit" outcome: the
    /// eviction loop can empty the table and the entry still does not get pushed.
    fn insert(&mut self, name: Bytes, value: Bytes) {
        let cost = entry_cost(&name, &value);
        while self.dynamic_size + cost > self.max_table_size && !self.dynamic.is_empty() {
            let (n, v) = self
                .dynamic
                .pop_back()
                .expect("checked non-empty in the loop condition");
            self.dynamic_size -= entry_cost(&n, &v);
        }
        if cost <= self.max_table_size {
            self.dynamic.push_front((name, value));
            self.dynamic_size += cost;
        }
    }

    /// Number of entries currently in the dynamic table.
    pub fn dynamic_table_len(&self) -> usize {
        self.dynamic.len()
    }

    /// Sum of `entry_cost` over the dynamic table — what RFC 7541 calls the table's size.
    pub fn dynamic_table_bytes(&self) -> usize {
        self.dynamic_size
    }

    /// A snapshot of the dynamic table's entries, newest first, matching
    /// [`Decoder::dynamic_table_entries`]'s order exactly.
    pub fn dynamic_table_entries(&self) -> Vec<(Bytes, Bytes)> {
        self.dynamic.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, value: &str) -> (Bytes, Bytes) {
        (
            Bytes::copy_from_slice(name.as_bytes()),
            Bytes::copy_from_slice(value.as_bytes()),
        )
    }

    // ---- RFC 7541 Appendix C.2: independent representation examples ----

    #[test]
    fn c_2_1_a_literal_with_indexing_is_decoded_and_added_to_the_dynamic_table() {
        const BLOCK: [u8; 26] = [
            0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0d, 0x63,
            0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
        ];
        let mut d = Decoder::new(4096);
        let out = d.decode(&BLOCK).expect("C.2.1 must decode");
        assert_eq!(out, vec![h("custom-key", "custom-header")]);
        assert_eq!(d.dynamic_table_len(), 1, "the literal must be indexed");
        assert_eq!(
            d.dynamic_table_bytes(),
            55,
            "10 + 13 + 32, per RFC 7541 §4.1"
        );
        assert_eq!(
            d.dynamic_table_entries(),
            vec![h("custom-key", "custom-header")]
        );
    }

    #[test]
    fn c_2_2_a_literal_without_indexing_leaves_the_dynamic_table_empty() {
        const BLOCK: [u8; 14] = [
            0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68,
        ];
        let mut d = Decoder::new(4096);
        let out = d.decode(&BLOCK).expect("C.2.2 must decode");
        assert_eq!(out, vec![h(":path", "/sample/path")]);
        assert_eq!(
            d.dynamic_table_len(),
            0,
            "without-indexing must not touch the table"
        );
    }

    #[test]
    fn c_2_3_a_never_indexed_literal_leaves_the_dynamic_table_empty() {
        const BLOCK: [u8; 17] = [
            0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06, 0x73, 0x65, 0x63,
            0x72, 0x65, 0x74,
        ];
        let mut d = Decoder::new(4096);
        let out = d.decode(&BLOCK).expect("C.2.3 must decode");
        assert_eq!(out, vec![h("password", "secret")]);
        assert_eq!(
            d.dynamic_table_len(),
            0,
            "never-indexed must not touch the table"
        );
    }

    #[test]
    fn c_2_4_an_indexed_header_field_decodes_from_the_static_table_alone() {
        const BLOCK: [u8; 1] = [0x82];
        let mut d = Decoder::new(4096);
        let out = d.decode(&BLOCK).expect("C.2.4 must decode");
        assert_eq!(out, vec![h(":method", "GET")]);
        assert_eq!(d.dynamic_table_len(), 0);
    }

    // ---- RFC 7541 Appendix C.3: a request sequence, one decoder throughout ----

    #[test]
    fn c_3_the_request_sequence_indexes_and_evicts_exactly_as_the_rfc_states() {
        let mut d = Decoder::new(4096);

        // C.3.1
        const REQ1: [u8; 20] = [
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        let out1 = d.decode(&REQ1).expect("C.3.1 must decode");
        assert_eq!(
            out1,
            vec![
                h(":method", "GET"),
                h(":scheme", "http"),
                h(":path", "/"),
                h(":authority", "www.example.com"),
            ]
        );
        assert_eq!(d.dynamic_table_bytes(), 57, "table size after C.3.1");
        assert_eq!(
            d.dynamic_table_entries(),
            vec![h(":authority", "www.example.com")],
            "dynamic table contents after C.3.1"
        );

        // C.3.2 — references dynamic index 62 (:authority) via 0xbe.
        const REQ2: [u8; 14] = [
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
        ];
        let out2 = d.decode(&REQ2).expect("C.3.2 must decode");
        assert_eq!(
            out2,
            vec![
                h(":method", "GET"),
                h(":scheme", "http"),
                h(":path", "/"),
                h(":authority", "www.example.com"),
                h("cache-control", "no-cache"),
            ]
        );
        assert_eq!(d.dynamic_table_bytes(), 110, "table size after C.3.2");
        assert_eq!(
            d.dynamic_table_entries(),
            vec![
                h("cache-control", "no-cache"),
                h(":authority", "www.example.com"),
            ],
            "dynamic table contents after C.3.2 — newest entry first"
        );

        // C.3.3 — references dynamic index 63 (:authority, now shifted back one) via 0xbf.
        const REQ3: [u8; 29] = [
            0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b,
            0x65, 0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75,
            0x65,
        ];
        let out3 = d.decode(&REQ3).expect("C.3.3 must decode");
        assert_eq!(
            out3,
            vec![
                h(":method", "GET"),
                h(":scheme", "https"),
                h(":path", "/index.html"),
                h(":authority", "www.example.com"),
                h("custom-key", "custom-value"),
            ]
        );
        assert_eq!(d.dynamic_table_bytes(), 164, "table size after C.3.3");
        assert_eq!(
            d.dynamic_table_entries(),
            vec![
                h("custom-key", "custom-value"),
                h("cache-control", "no-cache"),
                h(":authority", "www.example.com"),
            ],
            "dynamic table contents after C.3.3"
        );
    }

    // ---- RFC 7541 Appendix C.5: a response sequence with a 256-byte table, forcing eviction ----

    #[test]
    fn c_5_the_response_sequence_evicts_under_a_256_byte_table_exactly_as_the_rfc_states() {
        let mut d = Decoder::new(256);

        // C.5.1
        const RESP1: [u8; 70] = [
            0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
            0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20,
            0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x31, 0x20,
            0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77,
            0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        let out1 = d.decode(&RESP1).expect("C.5.1 must decode");
        assert_eq!(
            out1,
            vec![
                h(":status", "302"),
                h("cache-control", "private"),
                h("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                h("location", "https://www.example.com"),
            ]
        );
        assert_eq!(d.dynamic_table_bytes(), 222, "table size after C.5.1");
        assert_eq!(
            d.dynamic_table_entries(),
            vec![
                h("location", "https://www.example.com"),
                h("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                h("cache-control", "private"),
                h(":status", "302"),
            ],
            "dynamic table contents after C.5.1"
        );

        // C.5.2 — inserting ":status: 307" evicts ":status: 302" to stay under 256.
        const RESP2: [u8; 8] = [0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf];
        let out2 = d.decode(&RESP2).expect("C.5.2 must decode");
        assert_eq!(
            out2,
            vec![
                h(":status", "307"),
                h("cache-control", "private"),
                h("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                h("location", "https://www.example.com"),
            ]
        );
        assert_eq!(d.dynamic_table_bytes(), 222, "table size after C.5.2");
        assert_eq!(
            d.dynamic_table_entries(),
            vec![
                h(":status", "307"),
                h("location", "https://www.example.com"),
                h("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                h("cache-control", "private"),
            ],
            "dynamic table contents after C.5.2 — :status: 302 evicted"
        );

        // C.5.3 — evicts cache-control:private, date(...21...), and :status:307 in turn.
        const RESP3: [u8; 98] = [
            0x88, 0xc1, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63,
            0x74, 0x20, 0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32,
            0x32, 0x20, 0x47, 0x4d, 0x54, 0xc0, 0x5a, 0x04, 0x67, 0x7a, 0x69, 0x70, 0x77, 0x38,
            0x66, 0x6f, 0x6f, 0x3d, 0x41, 0x53, 0x44, 0x4a, 0x4b, 0x48, 0x51, 0x4b, 0x42, 0x5a,
            0x58, 0x4f, 0x51, 0x57, 0x45, 0x4f, 0x50, 0x49, 0x55, 0x41, 0x58, 0x51, 0x57, 0x45,
            0x4f, 0x49, 0x55, 0x3b, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, 0x3d, 0x33,
            0x36, 0x30, 0x30, 0x3b, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x31,
        ];
        let out3 = d.decode(&RESP3).expect("C.5.3 must decode");
        assert_eq!(
            out3,
            vec![
                h(":status", "200"),
                h("cache-control", "private"),
                h("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                h("location", "https://www.example.com"),
                h("content-encoding", "gzip"),
                h(
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
                ),
            ]
        );
        assert_eq!(d.dynamic_table_bytes(), 215, "table size after C.5.3");
        assert_eq!(
            d.dynamic_table_entries(),
            vec![
                h(
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
                ),
                h("content-encoding", "gzip"),
                h("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ],
            "dynamic table contents after C.5.3"
        );
    }

    // ---- negative tests: every one active, none ignored ----

    #[test]
    fn index_zero_in_an_indexed_header_field_is_an_error() {
        let mut d = Decoder::new(4096);
        let err = d.decode(&[0x80]).expect_err("index 0 must be refused");
        assert_eq!(err, HpackError::ZeroIndex { at: 0 });
        assert_eq!(err.at(), 0);
    }

    #[test]
    fn an_index_past_the_combined_tables_is_an_error_naming_the_index() {
        let mut d = Decoder::new(4096);
        // 0xbe = indexed field, index 62 — the first dynamic-table slot, empty on a fresh decoder.
        let err = d
            .decode(&[0xbe])
            .expect_err("index 62 must be refused when the dynamic table is empty");
        assert_eq!(
            err,
            HpackError::IndexOutOfRange {
                at: 0,
                index: 62,
                table_size: 61,
            }
        );
    }

    #[test]
    fn a_declared_string_length_overrunning_the_block_is_an_error_with_the_offset() {
        // 0x04 = literal without indexing, indexed name (:path, static index 4).
        // 0x05 = value length 5, but only 2 octets follow.
        let mut d = Decoder::new(4096);
        let err = d
            .decode(&[0x04, 0x05, b'a', b'b'])
            .expect_err("a length past the block must be refused");
        assert_eq!(
            err,
            HpackError::StringLengthOverrun {
                at: 2,
                declared: 5,
                remaining: 2,
            }
        );
    }

    #[test]
    fn a_non_terminating_multi_byte_integer_errors_rather_than_looping() {
        // 0xff = indexed field, 7-bit prefix maxed (127). Six continuation octets follow, all
        // with the continuation bit set — one more than this decoder's bound, and it never
        // supplies a terminator.
        let mut d = Decoder::new(4096);
        let block = [0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80];
        let err = d
            .decode(&block)
            .expect_err("an integer that never terminates must be refused, not looped on");
        assert_eq!(err, HpackError::IntegerTooLong { at: 0 });
    }

    #[test]
    fn a_size_update_above_the_negotiated_maximum_is_an_error() {
        // 0x3f 0x46 = dynamic table size update requesting 101 (31 + 70), against a 100-byte max.
        let mut d = Decoder::new(100);
        let err = d
            .decode(&[0x3f, 0x46])
            .expect_err("a size update above the negotiated maximum must be refused");
        assert_eq!(
            err,
            HpackError::TableSizeTooLarge {
                at: 0,
                requested: 101,
                max: 100,
            }
        );
    }

    #[test]
    fn an_entry_larger_than_the_whole_dynamic_table_empties_it_and_is_not_inserted() {
        let mut d = Decoder::new(50);

        // Literal with incremental indexing, new name: "a" -> "b" costs 1 + 1 + 32 = 34, fits.
        let small = [0x40, 0x01, b'a', 0x01, b'b'];
        d.decode(&small)
            .expect("a 34-byte entry must fit in a 50-byte table");
        assert_eq!(d.dynamic_table_len(), 1);
        assert_eq!(d.dynamic_table_bytes(), 34);

        // Literal with incremental indexing, new name: a 10-byte name and a 10-byte value cost
        // 10 + 10 + 32 = 52, which exceeds the 50-byte table outright.
        let big = [
            0x40, 0x0a, b'n', b'n', b'n', b'n', b'n', b'n', b'n', b'n', b'n', b'n', 0x0a, b'v',
            b'v', b'v', b'v', b'v', b'v', b'v', b'v', b'v', b'v',
        ];
        let out = d
            .decode(&big)
            .expect("decoding still succeeds — the header is emitted, just not indexed");
        assert_eq!(
            out,
            vec![h("nnnnnnnnnn", "vvvvvvvvvv")],
            "an oversized entry is still part of the decoded header list"
        );
        assert_eq!(
            d.dynamic_table_len(),
            0,
            "an entry larger than the whole table empties it"
        );
        assert_eq!(d.dynamic_table_bytes(), 0);
    }

    #[test]
    fn a_huffman_flagged_string_returns_huffman_not_implemented() {
        // 0x14 = literal never indexed, indexed name (:path, static index 4).
        // 0x85 = H=1, length 5, at byte 1.
        let mut d = Decoder::new(4096);
        let block = [0x14, 0x85, 0, 0, 0, 0, 0];
        let err = d
            .decode(&block)
            .expect_err("a Huffman-flagged string must not be treated as raw octets");
        assert_eq!(
            err,
            HpackError::HuffmanNotImplemented { at: 1 },
            "the offset must name the string's own length octet, not the representation's start"
        );
    }

    // ---- order and duplicates are the caller's concern, not this decoder's to fix ----

    #[test]
    fn duplicate_field_names_both_survive_in_order() {
        // Two "literal without indexing, new name" representations, both named "foo".
        let block = [
            0x00, 0x03, b'f', b'o', b'o', 0x04, b'b', b'a', b'r', b'1', //
            0x00, 0x03, b'f', b'o', b'o', 0x04, b'b', b'a', b'r', b'2',
        ];
        let mut d = Decoder::new(4096);
        let out = d.decode(&block).expect("duplicate names are not an error");
        assert_eq!(
            out,
            vec![h("foo", "bar1"), h("foo", "bar2")],
            "a decoder must not deduplicate or merge repeated header names"
        );
    }

    #[test]
    fn an_uppercase_field_name_decodes_unchanged_rather_than_being_lowercased() {
        // Literal without indexing, new name: "X-Test" -> "foo".
        let block = [
            0x00, 0x06, b'X', b'-', b'T', b'e', b's', b't', 0x03, b'f', b'o', b'o',
        ];
        let mut d = Decoder::new(4096);
        let out = d
            .decode(&block)
            .expect("an uppercase name is not this layer's error to raise");
        assert_eq!(
            out,
            vec![(Bytes::from_static(b"X-Test"), Bytes::from_static(b"foo"))],
            "the caller, not the decoder, decides what to do with an invalid-for-HTTP/2 uppercase \
             name — silently lowercasing it would hide the very thing a smuggling probe needs to see"
        );
    }

    // ---- table mechanics not already covered by the RFC sequences ----

    #[test]
    fn a_size_update_at_or_below_the_maximum_is_accepted_and_lowers_the_limit() {
        let mut d = Decoder::new(4096);
        // Fill the table past what a lowered limit of 50 could hold.
        let entry = [0x40, 0x01, b'a', 0x01, b'b']; // cost 34
        d.decode(&entry).expect("insert");
        d.decode(&entry).expect("insert");
        assert_eq!(d.dynamic_table_bytes(), 68);

        // 0x3f 0x13 = size update requesting 50 (31 + 19).
        d.decode(&[0x3f, 0x13])
            .expect("a size update at or below the max must be accepted");
        assert_eq!(
            d.dynamic_table_bytes(),
            34,
            "lowering the limit must evict from the back until the table fits"
        );
        assert_eq!(d.dynamic_table_len(), 1);
    }

    #[test]
    fn a_size_update_to_zero_empties_the_table_without_erroring() {
        let mut d = Decoder::new(4096);
        d.decode(&[0x40, 0x01, b'a', 0x01, b'b']).expect("insert");
        assert_eq!(d.dynamic_table_len(), 1);
        // 0x20 = size update requesting 0.
        d.decode(&[0x20])
            .expect("a size update to zero must be accepted");
        assert_eq!(d.dynamic_table_len(), 0);
        assert_eq!(d.dynamic_table_bytes(), 0);
    }

    // ---- Encoder: RFC 7541 Appendix C round trips ----

    /// Defends: RFC 7541 Appendix C.2.1 — a novel field, encoded then decoded, is the same field
    /// and lands in the dynamic table exactly as a literal-with-incremental-indexing would.
    #[test]
    fn c_2_1_round_trip_a_novel_field_survives_encode_then_decode_and_is_indexed() {
        let fields = vec![h("custom-key", "custom-header")];
        let mut enc = Encoder::new(4096);
        let block = enc.encode(&fields);
        let mut dec = Decoder::new(4096);
        let out = dec.decode(&block).expect("encoder output must decode");
        assert_eq!(out, fields, "round trip must reproduce the original field");
        assert_eq!(
            enc.dynamic_table_len(),
            1,
            "a field with no existing table match must be inserted, mirroring the decoder"
        );
        assert_eq!(
            enc.dynamic_table_bytes(),
            55,
            "10 + 13 + 32, per RFC 7541 §4.1"
        );
        assert_eq!(enc.dynamic_table_entries(), dec.dynamic_table_entries());
    }

    /// Defends: RFC 7541 Appendix C.2.4 — a field with both name and value in the static table
    /// must round-trip AND take the one-byte indexed representation (§6.1), not a literal one;
    /// the byte length pins that the "prefer an exact match" rule in the module doc actually
    /// fires rather than merely happening to decode correctly.
    #[test]
    fn c_2_4_round_trip_a_static_table_exact_match_encodes_as_one_indexed_byte() {
        let fields = vec![h(":method", "GET")];
        let mut enc = Encoder::new(4096);
        let block = enc.encode(&fields);
        assert_eq!(
            block.as_ref(),
            &[0x82],
            "an exact static-table match must be a single indexed-field octet, not a literal"
        );
        let mut dec = Decoder::new(4096);
        let out = dec.decode(&block).expect("encoder output must decode");
        assert_eq!(out, fields);
        assert_eq!(
            enc.dynamic_table_len(),
            0,
            "an indexed field must never be inserted into the dynamic table"
        );
    }

    /// Defends: RFC 7541 Appendix C.3 — three requests on ONE encoder/decoder pair must round
    /// trip every field list, and the dynamic table must evolve on both sides exactly as the RFC
    /// states after each call: this is the "one instance per direction, not one per header
    /// block" invariant from the module doc, exercised across calls rather than within one.
    #[test]
    fn c_3_round_trip_three_requests_on_one_encoder_decoder_pair_evolve_the_table_together() {
        let mut enc = Encoder::new(4096);
        let mut dec = Decoder::new(4096);

        let req1 = vec![
            h(":method", "GET"),
            h(":scheme", "http"),
            h(":path", "/"),
            h(":authority", "www.example.com"),
        ];
        let block1 = enc.encode(&req1);
        let out1 = dec.decode(&block1).expect("req1 must decode");
        assert_eq!(out1, req1);
        assert_eq!(enc.dynamic_table_bytes(), 57, "table size after req1");
        assert_eq!(enc.dynamic_table_entries(), dec.dynamic_table_entries());

        let req2 = vec![
            h(":method", "GET"),
            h(":scheme", "http"),
            h(":path", "/"),
            h(":authority", "www.example.com"),
            h("cache-control", "no-cache"),
        ];
        let block2 = enc.encode(&req2);
        let out2 = dec.decode(&block2).expect("req2 must decode");
        assert_eq!(out2, req2);
        assert_eq!(enc.dynamic_table_bytes(), 110, "table size after req2");
        assert_eq!(enc.dynamic_table_entries(), dec.dynamic_table_entries());

        let req3 = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/index.html"),
            h(":authority", "www.example.com"),
            h("custom-key", "custom-value"),
        ];
        let block3 = enc.encode(&req3);
        let out3 = dec.decode(&block3).expect("req3 must decode");
        assert_eq!(out3, req3);
        assert_eq!(enc.dynamic_table_bytes(), 164, "table size after req3");
        assert_eq!(
            enc.dynamic_table_entries(),
            dec.dynamic_table_entries(),
            "encoder and decoder must agree on dynamic table contents after every call"
        );
    }

    // ---- Encoder: properties beyond the RFC vectors ----

    /// Defends: the crate's stated header-list-exactness guarantee (crate root doc) — duplicate
    /// names and unusual casing are not something an encoder is allowed to normalise away, so
    /// they must survive encode → decode as the same ordered list.
    #[test]
    fn duplicate_names_and_unusual_casing_survive_encode_then_decode_in_order() {
        let fields = vec![
            h("foo", "bar1"),
            h("foo", "bar2"),
            h("X-Test", "value"),
            (Bytes::from_static(b"foo"), Bytes::from_static(b"bar1")),
        ];
        let mut enc = Encoder::new(4096);
        let block = enc.encode(&fields);
        let mut dec = Decoder::new(4096);
        let out = dec
            .decode(&block)
            .expect("duplicate names and mixed casing must still decode");
        assert_eq!(
            out, fields,
            "an encoder must not deduplicate, merge, or lowercase fields"
        );
    }

    /// Defends: RFC 7541 §4.4 — an entry whose cost exceeds the table's entire budget must clear
    /// the table rather than being rejected or truncated, and must still be part of the emitted
    /// header list (only the *indexing* is refused, not the field itself). Mirrors the decoder's
    /// `an_entry_larger_than_the_whole_dynamic_table_empties_it_and_is_not_inserted` test, but
    /// pins the same property from the encoder's side of the wire, and confirms a decoder fed the
    /// same two blocks agrees the table ends up empty too.
    #[test]
    fn an_oversized_entry_clears_the_encoders_dynamic_table_but_still_reaches_the_decoded_output() {
        let mut enc = Encoder::new(50);
        let mut dec = Decoder::new(50);

        // "a" -> "b" costs 1 + 1 + 32 = 34, fits in a 50-byte table.
        let small = vec![h("a", "b")];
        let block1 = enc.encode(&small);
        dec.decode(&block1).expect("the small entry must decode");
        assert_eq!(enc.dynamic_table_len(), 1);
        assert_eq!(enc.dynamic_table_bytes(), 34);

        // A 10-byte name and a 10-byte value cost 10 + 10 + 32 = 52, over the 50-byte budget.
        let big = vec![h("nnnnnnnnnn", "vvvvvvvvvv")];
        let block2 = enc.encode(&big);
        assert_eq!(
            enc.dynamic_table_len(),
            0,
            "an entry larger than the whole table must empty the encoder's table"
        );
        assert_eq!(enc.dynamic_table_bytes(), 0);

        let out2 = dec
            .decode(&block2)
            .expect("the oversized field must still decode");
        assert_eq!(
            out2, big,
            "an oversized entry is still part of the decoded header list, only unindexed"
        );
        assert_eq!(
            dec.dynamic_table_len(),
            0,
            "the decoder's table must end up empty too, in lockstep with the encoder's"
        );
    }

    /// Defends: encoding must be deterministic — the representation strategy in the module doc
    /// has no hidden randomness or ordering dependency, so a fresh encoder given the same field
    /// list twice must produce byte-identical output both times.
    #[test]
    fn encoding_the_same_list_twice_on_a_fresh_encoder_is_deterministic() {
        let fields = vec![
            h(":method", "GET"),
            h(":path", "/"),
            h("x-custom", "value"),
        ];
        let block_a = Encoder::new(4096).encode(&fields);
        let block_b = Encoder::new(4096).encode(&fields);
        assert_eq!(
            block_a, block_b,
            "the same input on a fresh encoder must produce identical bytes every time"
        );
    }
}
