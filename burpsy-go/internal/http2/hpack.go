package http2

import (
	"bytes"
	"fmt"
	"math"
)

// HPACK (RFC 7541): the primitive integer and string encodings, the static and dynamic tables, and a
// decoder for all five header field representations.
//
// # Why a decoder belongs in a layer that emits, not just parses
//
// frame.go's header already makes the case for hand-writing the frame layer: a compliant HPACK
// implementation refuses to *show you* a header block it judges malformed, and burpsy's whole reason
// to exist includes showing a tester exactly what a peer sent. The same argument applies here at one
// level down. golang.org/x/net/http2/hpack does export a Decoder, but it is a conformant one — it
// rejects rather than reports, and it is the same library the transport path already uses, so
// leaning on it would put the malformed-input path back behind the wall this layer exists to get
// around.
//
// # Huffman is a named seam, in both languages
//
// decodeHpackString bounds-checks and slices every string literal regardless of its Huffman flag,
// but a set flag reports HpackHuffmanNotImplemented rather than decoding it. crates/http2/src/hpack.rs
// does exactly the same and calls that arm "slice 2b's seam"; this port carries the seam across
// rather than closing it, so the two implementations decode the same inputs and refuse the same
// ones. Passing the raw Huffman-coded octets through as though they were the literal value would be
// worse than refusing them — it would silently hand a caller bytes that are not the header value
// they claim to be.
//
// The practical consequence is worth stating plainly, because it bounds what this decoder is useful
// for today: real peers Huffman-code most header strings, so decoding a *captured* block off the
// wire will frequently stop at this error. Blocks this package's Encoder produced always decode,
// because that encoder never sets H=1.
//
// # One codec per (connection, direction)
//
// A dynamic table is connection state accumulated across every header block sent in one direction
// (RFC 7541 §2.3.2): each call to Decoder.Decode both reads and mutates it. A Decoder must therefore
// live exactly as long as one direction of one connection, and a fresh request/response pair must
// **not** get a fresh Decoder — the encoder on the other end is still referencing index 62 as
// whatever it inserted last, and a decoder that forgot that disagrees with the peer about what index
// 62 means. Two directions must not share one Decoder either: a request's insertions and a
// response's insertions are two independent tables in the real protocol, and merging them produces
// indices that resolve to whichever direction happened to insert more recently. Both mistakes are
// worse than a crash, because they do not look wrong — they produce a fully-formed, plausible, wrong
// header list.
//
// # The encoder's representation strategy is a choice, not a fact
//
// RFC 7541 lets an encoder pick, for each field, among an indexed reference (§6.1), a literal with
// an indexed name (§6.2.1), or a literal with everything spelled out (§6.2.1 again, index 0).
// Encoder resolves that choice deterministically: exact name+value match anywhere in the combined
// static/dynamic address space wins (cheapest on the wire, no insertion); otherwise a name-only
// match reuses the name and inserts the pair; otherwise both strings are literal and the pair is
// inserted. It never emits "without indexing" (§6.2.2) or "never indexed" (§6.2.3) — those exist for
// a sender who wants a field to skip the table, which is not a distinction this encoder's callers
// currently need to express — and it never emits Huffman-coded strings, for the same reason
// decodeHpackString never decodes them. Every string this encoder writes sets H=0, which is
// spec-legal (Huffman is always optional) and costs bytes on the wire versus a real encoder, not a
// bug.
//
// # Divergences from crates/http2/src/hpack.rs, which is this codec's spec
//
//   - Rust's `HpackError` is an enum with per-variant fields; Go has no such thing, so HpackError is
//     one struct with a Kind and the union of the fields, and only the fields its Kind names are
//     populated — the shape core.CorruptRecord established. Rust's `HpackError::at()` accessor
//     exists because an enum's payload is not reachable without matching; the Go field At is, so
//     there is no accessor.
//   - A header field is `(Bytes, Bytes)` in Rust and HeaderField here, because Go tuples do not
//     exist and a `[2][]byte` would not say which element is the name. Distinct from this package's
//     existing Header (string-typed, for HTTP/1-shaped rendering): HPACK is byte-exact, and a header
//     name that is not valid UTF-8 is a thing a peer can send.
//   - Rust's `Bytes` clones by reference count, so handing a caller a table entry is free and safe.
//     Go slices alias, so every lookup copies: a returned header list must not be a window onto the
//     table that a caller can rewrite.
//   - Rust holds the dynamic table in a `VecDeque` and pushes to the front; Go uses a slice with the
//     same newest-first order (so index 62 is dynamic[0], matching §2.3.2 directly) and prepends. A
//     4096-byte table holds at most 128 entries, so the copy a prepend costs is smaller than the
//     indirection a ring buffer would add.
//   - Decoder.Decode returns the error interface rather than *HpackError, unlike the unexported
//     helpers below it. A nil *HpackError assigned into an error interface is not nil, so a caller
//     forwarding a decode failure upward would turn "decoded cleanly" into "failed for no stated
//     reason" — the exact class of silent lie this package is built to refuse. errors.As recovers the
//     Kind.
//
// hpackStaticTableLen, below, is how many entries RFC 7541 Appendix A defines; it is also the offset
// the dynamic table's indices start after, which is why it appears in every index calculation here.
const hpackStaticTableLen = 61

// hpackStaticTable is the RFC 7541 Appendix A static table. Index i (1-based) is
// hpackStaticTable[i-1]. Held as strings and copied to bytes on lookup — see the divergence note.
var hpackStaticTable = [hpackStaticTableLen]struct{ name, value string }{
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

// HeaderField is one header field as HPACK carries it: bytes, not strings, because a name or value a
// peer sent need not be valid UTF-8 and must survive being shown to an operator regardless.
type HeaderField struct {
	Name  []byte
	Value []byte
}

// NewHeaderField copies name and value into a field, for callers building a list to encode.
func NewHeaderField(name, value string) HeaderField {
	return HeaderField{Name: []byte(name), Value: []byte(value)}
}

// Equal compares two fields byte for byte. Named because Go's == does not work on a struct holding
// slices, and reflect.DeepEqual treats a nil slice and an empty one as different where HPACK does
// not.
func (f HeaderField) Equal(other HeaderField) bool {
	return bytes.Equal(f.Name, other.Name) && bytes.Equal(f.Value, other.Value)
}

// clone copies both slices, so a returned header list is never a window onto a table.
func (f HeaderField) clone() HeaderField {
	return HeaderField{
		Name:  append([]byte(nil), f.Name...),
		Value: append([]byte(nil), f.Value...),
	}
}

// HeaderFieldsEqual compares two header lists in order, including duplicates.
func HeaderFieldsEqual(a, b []HeaderField) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// HpackErrorKind names what is wrong with a header block, so a caller can branch on the fault rather
// than matching on message text.
type HpackErrorKind int

const (
	// HpackTruncated means fewer bytes remain than a representation needs to start or continue.
	HpackTruncated HpackErrorKind = iota
	// HpackIntegerTooLong means a prefix integer (§5.1) did not terminate within the
	// continuation-octet bound this decoder enforces.
	HpackIntegerTooLong
	// HpackStringLengthOverrun means a string literal's declared length (§5.2) reaches past the end
	// of the block.
	HpackStringLengthOverrun
	// HpackHuffmanNotImplemented means a string literal's Huffman flag is set. The named seam — see
	// the module docs.
	HpackHuffmanNotImplemented
	// HpackZeroIndex means index 0 in an indexed header field representation (§6.1) — reserved,
	// never valid.
	HpackZeroIndex
	// HpackIndexOutOfRange means an index names neither a static nor a dynamic table entry.
	HpackIndexOutOfRange
	// HpackTableSizeTooLarge means a §6.3 dynamic table size update exceeded the maximum this
	// connection negotiated.
	HpackTableSizeTooLarge
)

// HpackError is a fault found while decoding a header block, always carrying the byte offset (into
// the block passed to Decoder.Decode) it was found at.
//
// Only the fields its Kind names are populated; the rest are zero. This is the Go shape of Rust's
// HpackError enum — see the divergence note in the module docs.
type HpackError struct {
	Kind HpackErrorKind
	// At is the offset the fault was found at, populated for every Kind.
	At int

	// Need, Have are set for HpackTruncated.
	Need, Have int
	// Declared, Remaining are set for HpackStringLengthOverrun.
	Declared, Remaining int
	// Index, TableSize are set for HpackIndexOutOfRange.
	Index     uint64
	TableSize int
	// Requested, Max are set for HpackTableSizeTooLarge.
	Requested uint64
	Max       int
}

// Error says what the failure means for an operator, not which field disagreed.
func (e *HpackError) Error() string {
	switch e.Kind {
	case HpackTruncated:
		return fmt.Sprintf("header block at byte %d needs at least %d more byte(s) but only %d "+
			"remain — the block ends mid-representation, whether by truncation or by design",
			e.At, e.Need, e.Have)
	case HpackIntegerTooLong:
		return fmt.Sprintf("the integer at byte %d did not terminate within the continuation-octet "+
			"bound this decoder enforces — a peer that never clears the continuation bit is trying "+
			"to make the decoder loop or overflow, not encoding a legitimately large value", e.At)
	case HpackStringLengthOverrun:
		return fmt.Sprintf("the string literal at byte %d declares %d byte(s) but only %d remain "+
			"in the block — the length is corrupt or the block was truncated",
			e.At, e.Declared, e.Remaining)
	case HpackHuffmanNotImplemented:
		return fmt.Sprintf("the string literal at byte %d sets the Huffman flag, which this decoder "+
			"does not yet implement — refusing to hand back its raw octets as though they were the "+
			"literal value", e.At)
	case HpackZeroIndex:
		return fmt.Sprintf("the indexed header field at byte %d names index 0, which RFC 7541 §6.1 "+
			"reserves — no table entry ever occupies it", e.At)
	case HpackIndexOutOfRange:
		return fmt.Sprintf("the header field at byte %d names index %d, but the static and dynamic "+
			"tables together currently hold only %d entries", e.At, e.Index, e.TableSize)
	case HpackTableSizeTooLarge:
		return fmt.Sprintf("the dynamic table size update at byte %d requests %d byte(s), which "+
			"exceeds the %d-byte maximum this connection negotiated", e.At, e.Requested, e.Max)
	default:
		return fmt.Sprintf("the header block at byte %d is malformed in an unrecognised way (kind %d)",
			e.At, e.Kind)
	}
}

// hpackEntryCost is the cost §4.1 assigns an entry: both strings' lengths plus a fixed 32-octet
// estimate of per-entry bookkeeping overhead. Not the encoder's compressed size — the size on the
// wire is deliberately irrelevant to how much table space an entry costs.
func hpackEntryCost(f HeaderField) int {
	return len(f.Name) + len(f.Value) + 32
}

// maxIntegerContinuationOctets is how many continuation octets (§5.1) a prefix integer may use
// before this decoder gives up on it. Five octets carries a prefix integer past 2^35, which is
// already far beyond any index, length, or table size this package will ever need to represent; a
// peer sending more than that is not encoding a legitimate value, it is trying to make the decode
// loop or wrap. This is a cap this implementation chooses, not a number the RFC states.
const maxIntegerContinuationOctets = 5

// decodeHpackInt decodes a prefix integer (§5.1): block[at]'s low prefixBits bits are the prefix,
// followed by zero or more continuation octets. Returns the value and the total octets consumed.
//
// Bounded, not looping: the continuation loop runs at most maxIntegerContinuationOctets times and
// every accumulation is checked for overflow, so a peer that never clears the continuation bit gets
// HpackIntegerTooLong instead of an unbounded loop or a silently wrapped value.
func decodeHpackInt(block []byte, at int, prefixBits uint) (uint64, int, *HpackError) {
	prefixMax := uint64(1)<<prefixBits - 1
	if at < 0 || at >= len(block) {
		return 0, 0, &HpackError{Kind: HpackTruncated, At: at, Need: 1, Have: 0}
	}
	prefixVal := uint64(block[at]) & prefixMax
	if prefixVal < prefixMax {
		return prefixVal, 1, nil
	}

	value := prefixMax
	shift := uint(0)
	for i := 0; i < maxIntegerContinuationOctets; i++ {
		byteAt := at + 1 + i
		if byteAt >= len(block) {
			return 0, 0, &HpackError{Kind: HpackTruncated, At: byteAt, Need: 1, Have: 0}
		}
		b := block[byteAt]
		// The octet cap above bounds `value` well below 2^36, so this addition cannot in fact wrap;
		// the check is kept because it is what makes that bound a local property of this loop rather
		// than something a reader has to re-derive from the cap.
		add := uint64(b&0x7F) << shift
		if value+add < value {
			return 0, 0, &HpackError{Kind: HpackIntegerTooLong, At: at}
		}
		value += add
		if b&0x80 == 0 {
			return value, 1 + i + 1, nil
		}
		shift += 7
	}
	return 0, 0, &HpackError{Kind: HpackIntegerTooLong, At: at}
}

// decodeHpackString decodes a length-prefixed string (§5.2): a Huffman flag in the length octet's
// top bit, a 7-bit length prefix, then that many raw octets. Bounds-checks the declared length
// against what remains in block **before** slicing — a declared length is attacker-influenced and
// must never reach a slice operation unchecked.
//
// A set Huffman flag is HpackHuffmanNotImplemented — the named seam, see the module docs.
// Bounds-checking happens first regardless of the flag, so a too-long Huffman string is still
// reported as a length overrun rather than masked by the not-implemented error.
func decodeHpackString(block []byte, at int) ([]byte, int, *HpackError) {
	length, intLen, err := decodeHpackInt(block, at, 7)
	if err != nil {
		return nil, 0, err
	}
	// decodeHpackInt already proved block[at] exists.
	huffman := block[at]&0x80 != 0
	dataAt := at + intLen
	remaining := len(block) - dataAt
	if remaining < 0 {
		remaining = 0
	}
	// math.MaxInt is never a real length; a length too large for int folds into it, which is
	// guaranteed to compare greater than remaining below rather than wrap.
	declared := math.MaxInt
	if length <= uint64(math.MaxInt) {
		declared = int(length)
	}
	if declared > remaining {
		return nil, 0, &HpackError{
			Kind: HpackStringLengthOverrun, At: dataAt, Declared: declared, Remaining: remaining,
		}
	}
	if huffman {
		// SEAM: replace this arm with the Huffman decode of block[dataAt : dataAt+declared].
		// Everything above it — the length prefix, the bounds check against remaining — is unchanged
		// by that replacement. Mirrors the same seam in crates/http2/src/hpack.rs.
		return nil, 0, &HpackError{Kind: HpackHuffmanNotImplemented, At: at}
	}
	out := make([]byte, declared)
	copy(out, block[dataAt:dataAt+declared])
	return out, intLen + declared, nil
}

// encodeHpackInt encodes a prefix integer (§5.1), the exact inverse of decodeHpackInt: pattern
// already carries the representation's high bits shifted into position (e.g. 0x80 for an indexed
// field's leading 1), and value's low prefixBits bits share that same first octet, spilling into as
// many continuation octets as value needs once it does not fit.
func encodeHpackInt(out []byte, value uint64, prefixBits uint, pattern byte) []byte {
	prefixMax := uint64(1)<<prefixBits - 1
	if value < prefixMax {
		return append(out, pattern|byte(value))
	}
	out = append(out, pattern|byte(prefixMax))
	remaining := value - prefixMax
	for remaining >= 0x80 {
		out = append(out, byte(remaining&0x7F)|0x80)
		remaining >>= 7
	}
	return append(out, byte(remaining))
}

// encodeHpackString encodes a length-prefixed string (§5.2). Always H=0 — see the module docs on why
// this encoder never Huffman-codes — so the length prefix's top bit, which decodeHpackString reads
// as the Huffman flag, is always clear.
func encodeHpackString(out []byte, data []byte) []byte {
	out = encodeHpackInt(out, uint64(len(data)), 7, 0x00)
	return append(out, data...)
}

// Decoder is a stateful HPACK decoder: the dynamic table for one direction of one connection, plus
// the size limits that bound it. See the module docs for why one instance must not span two
// directions or be dropped between header blocks on the same one.
type Decoder struct {
	// dynamic holds the newest entry at index 0 (table index 62), oldest last — matching §2.3.2's
	// index order directly, so lookup needs no reversal.
	dynamic []HeaderField
	// dynamicSize is the sum of hpackEntryCost over dynamic. Maintained incrementally rather than
	// recomputed, since every insert and evict already touches the entries that would need
	// re-summing.
	dynamicSize int
	// maxTableSize is the ceiling a §6.3 size update may not exceed — the peer's
	// SETTINGS_HEADER_TABLE_SIZE, fixed for the life of this decoder.
	maxTableSize int
	// tableSizeLimit is the currently active limit eviction enforces. Starts equal to maxTableSize
	// and can only move within [0, maxTableSize] via §6.3 updates.
	tableSizeLimit int
}

// NewDecoder builds a fresh decoder with an empty dynamic table, bounded by maxTableSize — the value
// this connection's peer advertised as SETTINGS_HEADER_TABLE_SIZE.
func NewDecoder(maxTableSize int) *Decoder {
	return &Decoder{maxTableSize: maxTableSize, tableSizeLimit: maxTableSize}
}

// Decode reads one header block, applying its representations in order against this decoder's
// dynamic table, and returns the decoded header list.
//
// The returned list preserves order and duplicates exactly as the block encodes them: no
// lowercasing, deduplication, reordering, or merging. An uppercase field name is invalid HTTP/2 (RFC
// 9113 §8.2.1), but this layer's job is to report what a peer sent, not to correct it — see frame.go
// for the same argument made about frames.
//
// A fault stops the decode and returns what went wrong, not a partial list: a header list missing
// the fields after byte N is a plausible-looking wrong answer, where the error names the byte. The
// return type is the error interface rather than *HpackError so that a caller forwarding it upward
// cannot turn a nil *HpackError into a non-nil error; recover the Kind with errors.As.
func (d *Decoder) Decode(block []byte) ([]HeaderField, error) {
	var out []HeaderField
	at := 0
	for at < len(block) {
		first := block[at]
		switch {
		case first&0x80 != 0:
			// §6.1 Indexed Header Field.
			index, n, err := decodeHpackInt(block, at, 7)
			if err != nil {
				return nil, err
			}
			field, err := d.lookup(index, at)
			if err != nil {
				return nil, err
			}
			out = append(out, field)
			at += n
		case first&0x40 != 0:
			// §6.2.1 Literal Header Field with Incremental Indexing.
			field, n, err := d.decodeLiteral(block, at, 6)
			if err != nil {
				return nil, err
			}
			// insert copies what it stores, so the field handed to the caller and the table entry
			// are separate from here on.
			d.insert(field)
			out = append(out, field)
			at += n
		case first&0x20 != 0:
			// §6.3 Dynamic Table Size Update.
			newMax, n, err := decodeHpackInt(block, at, 5)
			if err != nil {
				return nil, err
			}
			if err := d.applySizeUpdate(newMax, at); err != nil {
				return nil, err
			}
			at += n
		default:
			// §6.2.2 (0000) and §6.2.3 (0001) share the same wire shape and the same "do not touch
			// the dynamic table" behaviour; only re-encoding rules distinguish them (§6.2.3), which
			// is not this decoder's concern.
			field, n, err := d.decodeLiteral(block, at, 4)
			if err != nil {
				return nil, err
			}
			out = append(out, field)
			at += n
		}
	}
	return out, nil
}

// decodeLiteral reads the shared shape of §6.2.1/§6.2.2/§6.2.3: an optionally-indexed name
// (prefixBits wide, 0 meaning "literal name follows") followed by a literal value. Returns the
// decoded field and the total octets the whole representation consumed, but never touches the
// dynamic table — inserting on incremental indexing is the caller's job, since only one of the three
// representations does it.
func (d *Decoder) decodeLiteral(block []byte, at int, prefixBits uint) (HeaderField, int, *HpackError) {
	nameIndex, idxLen, err := decodeHpackInt(block, at, prefixBits)
	if err != nil {
		return HeaderField{}, 0, err
	}
	pos := at + idxLen
	var name []byte
	if nameIndex == 0 {
		decoded, consumed, err := decodeHpackString(block, pos)
		if err != nil {
			return HeaderField{}, 0, err
		}
		name = decoded
		pos += consumed
	} else {
		// Index 0 is intercepted above, so a genuine zero-index error here can only mean §6.1's
		// reserved index — see lookup.
		field, err := d.lookup(nameIndex, at)
		if err != nil {
			return HeaderField{}, 0, err
		}
		name = field.Name
	}
	value, consumed, err := decodeHpackString(block, pos)
	if err != nil {
		return HeaderField{}, 0, err
	}
	pos += consumed
	return HeaderField{Name: name, Value: value}, pos - at, nil
}

// lookup resolves an index (§2.3.3) to its field. Index 0 and an index past the combined address
// space are both errors; nothing else in this decoder produces index 0 as an argument here, since
// decodeLiteral intercepts it before calling in.
func (d *Decoder) lookup(index uint64, at int) (HeaderField, *HpackError) {
	if index == 0 {
		return HeaderField{}, &HpackError{Kind: HpackZeroIndex, At: at}
	}
	// index is bounded to roughly 2^35 by decodeHpackInt's continuation-octet cap, so this narrowing
	// cannot silently wrap: a value too large to fit folds to math.MaxInt, which fails both range
	// checks below exactly like a genuinely out-of-range index would.
	idx := math.MaxInt
	if index <= uint64(math.MaxInt) {
		idx = int(index)
	}
	if idx <= hpackStaticTableLen {
		entry := hpackStaticTable[idx-1]
		return HeaderField{Name: []byte(entry.name), Value: []byte(entry.value)}, nil
	}
	dynIdx := idx - hpackStaticTableLen - 1
	if dynIdx >= len(d.dynamic) {
		return HeaderField{}, &HpackError{
			Kind:      HpackIndexOutOfRange,
			At:        at,
			Index:     index,
			TableSize: hpackStaticTableLen + len(d.dynamic),
		}
	}
	return d.dynamic[dynIdx].clone(), nil
}

// insert adds a new entry at the front, evicting from the back (§4.4) until it fits. An entry larger
// than the whole table's current limit empties the table rather than being rejected or truncated —
// that emptying has already happened by the time the eviction loop below exits, so the entry is
// simply never pushed.
func (d *Decoder) insert(f HeaderField) {
	d.dynamic, d.dynamicSize = hpackInsert(d.dynamic, d.dynamicSize, d.tableSizeLimit, f)
}

// applySizeUpdate applies a §6.3 dynamic table size update: a newMax above maxTableSize is an error
// (the peer would be raising the bound past what it itself negotiated), otherwise entries are
// evicted from the back (§4.3) until the table fits the new limit.
func (d *Decoder) applySizeUpdate(newMax uint64, at int) *HpackError {
	if newMax > uint64(d.maxTableSize) {
		return &HpackError{
			Kind: HpackTableSizeTooLarge, At: at, Requested: newMax, Max: d.maxTableSize,
		}
	}
	// The check above proves newMax <= d.maxTableSize, which is an int, so this narrowing is exact.
	d.tableSizeLimit = int(newMax)
	for d.dynamicSize > d.tableSizeLimit {
		last := len(d.dynamic) - 1
		d.dynamicSize -= hpackEntryCost(d.dynamic[last])
		d.dynamic = d.dynamic[:last]
	}
	return nil
}

// DynamicTableLen is the number of entries currently in the dynamic table.
func (d *Decoder) DynamicTableLen() int { return len(d.dynamic) }

// DynamicTableBytes is the sum of per-entry costs over the dynamic table — what RFC 7541 calls the
// table's size.
func (d *Decoder) DynamicTableBytes() int { return d.dynamicSize }

// DynamicTableEntries is a snapshot of the dynamic table's entries, newest first — the same order
// §2.3.2 indexes them in. Beyond the two summary accessors above, tests need this to assert against
// the RFC's own "Dynamic Table (after decoding)" listings, which name entries, not just counts.
func (d *Decoder) DynamicTableEntries() []HeaderField { return cloneHeaderFields(d.dynamic) }

// Encoder is a stateful HPACK encoder: the mirror image of Decoder, carrying the dynamic table for
// one direction of one connection. The same one-codec-per-direction argument in the module docs
// applies here identically — an encoder inserts into its table exactly when the peer's decoder would
// insert into its own from the octets produced, so the two must evolve in lockstep, which means one
// long-lived Encoder per direction, never a fresh one per header block.
type Encoder struct {
	// dynamic holds the newest entry at index 0 (table index 62) — same layout and index order as
	// Decoder.dynamic, so the two stay directly comparable.
	dynamic []HeaderField
	// dynamicSize is the sum of per-entry costs over dynamic, maintained incrementally like the
	// decoder's.
	dynamicSize int
	// maxTableSize is the table-size budget this encoder respects (RFC 7541 §4.2) — the peer's
	// advertised SETTINGS_HEADER_TABLE_SIZE. Unlike Decoder, there is no separate "currently active"
	// limit: this encoder never receives a §6.3 size-update instruction from anyone (it is the one
	// who would *emit* one, which no caller currently asks for), so maxTableSize is the limit, full
	// stop.
	maxTableSize int
}

// NewEncoder builds a fresh encoder with an empty dynamic table, bounded by maxTableSize — the
// peer's advertised SETTINGS_HEADER_TABLE_SIZE for this direction.
func NewEncoder(maxTableSize int) *Encoder {
	return &Encoder{maxTableSize: maxTableSize}
}

// Encode writes one header block: every field in fields, in order, against this encoder's dynamic
// table — mutating it exactly as a peer decoding the output would mutate its own.
//
// fields is encoded verbatim: duplicate names, unusual casing, and pseudo-headers (`:`-prefixed
// names) are ordinary fields here, never reordered or treated specially. The header-list-exactness
// guarantee starts with this function not disturbing what it was given.
func (e *Encoder) Encode(fields []HeaderField) []byte {
	out := []byte{}
	for _, f := range fields {
		out = e.encodeField(out, f)
	}
	return out
}

// hpackMatchKind names where a field's name and/or value already live in the combined
// static+dynamic address space (RFC 7541 §2.3.3). Drives the §6.1 vs §6.2.1 choice documented in the
// module docs.
type hpackMatchKind int

const (
	// matchNeither means neither name nor value matches: both strings must be literal.
	matchNeither hpackMatchKind = iota
	// matchNameOnly means only the name matches — the value is still literal, but the name need not
	// be spelled out.
	matchNameOnly
	// matchNameAndValue means both match — cheapest: an indexed field, no insertion.
	matchNameAndValue
)

// encodeField chooses and emits one field's representation, per the strategy in the module docs.
func (e *Encoder) encodeField(out []byte, f HeaderField) []byte {
	kind, index := e.find(f)
	switch kind {
	case matchNameAndValue:
		// §6.1 Indexed Header Field: the whole field is one integer, no insertion.
		return encodeHpackInt(out, uint64(index), 7, 0x80)
	case matchNameOnly:
		// §6.2.1 Literal Header Field with Incremental Indexing, indexed name.
		out = encodeHpackInt(out, uint64(index), 6, 0x40)
		out = encodeHpackString(out, f.Value)
		e.insert(f)
		return out
	default:
		// §6.2.1 Literal Header Field with Incremental Indexing, new name (index 0 in a 6-bit prefix
		// is always a single 0x40 octet — it never needs continuation).
		out = append(out, 0x40)
		out = encodeHpackString(out, f.Name)
		out = encodeHpackString(out, f.Value)
		e.insert(f)
		return out
	}
}

// find searches the static table, then the dynamic table (newest first), for the field's name and
// value. An exact match anywhere returns immediately; a name-only match is remembered but the search
// continues, since an exact match found later is strictly better and must win.
func (e *Encoder) find(f HeaderField) (hpackMatchKind, int) {
	nameOnly := 0
	for i := range hpackStaticTable {
		entry := hpackStaticTable[i]
		if string(f.Name) != entry.name {
			continue
		}
		if string(f.Value) == entry.value {
			return matchNameAndValue, i + 1
		}
		if nameOnly == 0 {
			nameOnly = i + 1
		}
	}
	for i := range e.dynamic {
		if !bytes.Equal(e.dynamic[i].Name, f.Name) {
			continue
		}
		if bytes.Equal(e.dynamic[i].Value, f.Value) {
			return matchNameAndValue, hpackStaticTableLen + i + 1
		}
		if nameOnly == 0 {
			nameOnly = hpackStaticTableLen + i + 1
		}
	}
	if nameOnly != 0 {
		return matchNameOnly, nameOnly
	}
	return matchNeither, 0
}

// insert adds a new entry at the front, evicting from the back (§4.4) until it fits — identical
// accounting to Decoder.insert, including the same "too big to ever fit" outcome: the eviction loop
// can empty the table and the entry still does not get pushed.
func (e *Encoder) insert(f HeaderField) {
	e.dynamic, e.dynamicSize = hpackInsert(e.dynamic, e.dynamicSize, e.maxTableSize, f)
}

// DynamicTableLen is the number of entries currently in the dynamic table.
func (e *Encoder) DynamicTableLen() int { return len(e.dynamic) }

// DynamicTableBytes is the sum of per-entry costs over the dynamic table — what RFC 7541 calls the
// table's size.
func (e *Encoder) DynamicTableBytes() int { return e.dynamicSize }

// DynamicTableEntries is a snapshot of the dynamic table's entries, newest first, matching
// Decoder.DynamicTableEntries's order exactly.
func (e *Encoder) DynamicTableEntries() []HeaderField { return cloneHeaderFields(e.dynamic) }

// hpackInsert is §4.4's insert-and-evict, shared by both tables so the two cannot drift apart: an
// encoder whose eviction rule differed from its peer's decoder would produce indices that resolve to
// the wrong entry, which is a wrong header list rather than an error.
//
// The entry is copied in, because a caller's slices must not become table state that later mutations
// through their own reference could rewrite.
func hpackInsert(table []HeaderField, size, limit int, f HeaderField) ([]HeaderField, int) {
	cost := hpackEntryCost(f)
	for size+cost > limit && len(table) > 0 {
		last := len(table) - 1
		size -= hpackEntryCost(table[last])
		table = table[:last]
	}
	if cost <= limit {
		table = append([]HeaderField{f.clone()}, table...)
		size += cost
	}
	// Else: eviction above already emptied the table (or left it as small as it can get) and this
	// entry is still too big — §4.4 says do not insert it.
	return table, size
}

// cloneHeaderFields deep-copies a header list, so a snapshot cannot be used to rewrite the table it
// came from.
func cloneHeaderFields(in []HeaderField) []HeaderField {
	out := make([]HeaderField, len(in))
	for i := range in {
		out[i] = in[i].clone()
	}
	return out
}
