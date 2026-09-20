package intruder

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Hard ceiling on a resolved payload set, whatever maxCount a caller passes.
//
// Matched deliberately to the web edge's own ceiling on max_requests: you cannot generate more
// payloads than the largest attack the edge will ever agree to send. 200 000 handles is bounded,
// and small next to the response traffic an attack that size produces.
const MaxPayloads = 200_000

// Refuse to build a single payload longer than this.
//
// 64 KiB is far past any payload an operator types and far short of a generator config that turns
// into gigabytes: CharBlocks{max: 1e9} is a typo, not a request.
const MaxItemLen = 64 * 1024

// PayloadErrorKind distinguishes the ways a generator config can refuse to produce anything.
type PayloadErrorKind int

const (
	// PayloadErrZeroStep: a step of zero never advances.
	PayloadErrZeroStep PayloadErrorKind = iota
	// PayloadErrBackwardsRange: a range whose sign disagrees with its step; it would run away
	// from `to`, not towards it.
	PayloadErrBackwardsRange
	// PayloadErrEmpty: a character set or position slot with nothing in it.
	PayloadErrEmpty
	// PayloadErrBadLengthRange: min_len > max_len, or a maximum of zero.
	PayloadErrBadLengthRange
	// PayloadErrTooFewSlots: a custom iterator needs two or more slots; one slot is a plain list.
	PayloadErrTooFewSlots
	// PayloadErrItemTooLong: one payload would exceed MaxItemLen. Refused, never shortened.
	PayloadErrItemTooLong
	// PayloadErrBadDate: a date that is not YYYY-MM-DD.
	PayloadErrBadDate
)

// PayloadError carries the kind plus the fields needed to render a specific refusal.
type PayloadError struct {
	Kind  PayloadErrorKind
	From  string
	To    string
	Step  int64
	What  string
	Min   int
	Max   int
	Len   int
	Limit int
	Slots int
	Date  string
}

func (e *PayloadError) Error() string {
	switch e.Kind {
	case PayloadErrZeroStep:
		return "step must not be zero: it would never advance"
	case PayloadErrBackwardsRange:
		return fmt.Sprintf("step %d runs away from the end of the range %s..%s", e.Step, e.From, e.To)
	case PayloadErrEmpty:
		return fmt.Sprintf("%s is empty", e.What)
	case PayloadErrBadLengthRange:
		return fmt.Sprintf("length range %d..=%d produces nothing", e.Min, e.Max)
	case PayloadErrTooFewSlots:
		return fmt.Sprintf("a custom iterator needs at least 2 position slots, got %d", e.Slots)
	case PayloadErrItemTooLong:
		return fmt.Sprintf("one payload would be %d bytes, over the %d-byte limit; refused rather than shortened", e.Len, e.Limit)
	case PayloadErrBadDate:
		return fmt.Sprintf("not a YYYY-MM-DD date: %q", e.Date)
	default:
		return "unknown payload error"
	}
}

// DropReason names a processing rule's reason for dropping a payload and how many it dropped.
// Carried on PayloadSet so a cap never looks like checks that stopped firing.
type DropReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// PayloadSet is a resolved payload set, carrying the same pair of facts AttackPlan does: what
// was asked for, and what the bound left.
type PayloadSet struct {
	// Kind names the generator that produced this set ("list", "numbers", ...).
	Kind string `json:"kind"`
	// Items is what the attack will actually use.
	Items []string `json:"-"`
	// Count is the number of items actually produced.
	Count int `json:"count"`
	// Total is payloads the source describes with no bound applied, saturating at MaxUint64.
	Total uint64 `json:"total"`
	// TotalExact is false when Total saturated and is therefore a floor, not a count.
	TotalExact bool `json:"total_exact"`
	// Truncated is true when maxCount cut the set short.
	Truncated bool `json:"truncated"`
	// MaxCount is the bound that was in force.
	MaxCount int `json:"max_count"`
	// Skipped is payloads a processing rule dropped before sending.
	Skipped int `json:"skipped"`
	// Dropped names the drop reasons, grouped: distinct reasons with counts.
	Dropped []DropReason `json:"dropped"`
}

// NumberOrder is sequential or drawn at random.
type NumberOrder string

const (
	NumberOrderSequential NumberOrder = "sequential"
	NumberOrderRandom     NumberOrder = "random"
)

// NumberBase is how a number is written.
type NumberBase string

const (
	NumberBaseDecimal NumberBase = "decimal"
	// NumberBaseHex is lowercase hex. A negative value is written "-" then the magnitude.
	NumberBaseHex NumberBase = "hex"
)

// Numbers is Burp's Numbers payload type.
type Numbers struct {
	From int64 `json:"from"`
	// Inclusive.
	To int64 `json:"to"`
	// Step is the distance between successive values. Its sign must point from From towards To.
	Step int64 `json:"step"`
	// Order is sequential (default) or random.
	Order NumberOrder `json:"order,omitempty"`
	// Count is how many to draw; NumberOrderRandom only. Sequential takes its count from the range.
	Count int `json:"count,omitempty"`
	// Base is decimal (default) or hex.
	Base NumberBase `json:"base,omitempty"`
	// PadTo zero-pads the digits to this width. 0 leaves them unpadded. Applied after any sign,
	// so -7 at width 4 is -0007.
	PadTo int `json:"pad_to,omitempty"`
	// Seed makes a random draw reproducible: the same seed regenerates the same payloads.
	Seed *uint64 `json:"seed,omitempty"`
}

// Dates is Burp's Dates payload type: a range walked in whole days, written through a format.
type Dates struct {
	// From is YYYY-MM-DD, inclusive.
	From string `json:"from"`
	// To is YYYY-MM-DD, inclusive.
	To string `json:"to"`
	// Step is days between successive dates. Its sign must point from From towards To.
	Step int64 `json:"step"`
	// Format substitutes yyyy, yy, MM, MMM, dd; every other character is copied through.
	// Longest token first, so yyyy never parses as two yy.
	Format string `json:"format"`
}

// BruteForce is Burp's Brute forcer: every string over an alphabet, across a length range.
type BruteForce struct {
	// Charset is the alphabet, as characters. Taken as characters rather than bytes so a
	// non-ASCII set does not get split into invalid UTF-8 fragments.
	Charset string `json:"charset"`
	MinLen  int    `json:"min_len"`
	// MaxLen is inclusive.
	MaxLen int `json:"max_len"`
}

// CustomIterator is Burp's Custom iterator: independent lists per position slot, permuted.
type CustomIterator struct {
	// Positions is one list per slot. Two or more, else it is a plain list wearing a hat.
	Positions [][]string `json:"positions"`
	// Separator is placed between slots. A per-slot separator can be folded into the slot's items.
	Separator string `json:"separator"`
}

// PayloadSource is how to produce a payload set. It serialises as the tagged shape the UI
// sends, e.g. {"type":"numbers","from":1,...}. A List is a variant rather than a special case
// so a caller has one type to handle instead of "a list, or else a generator".
type PayloadSource struct {
	Type string `json:"type"`

	List             *ListSource
	Numbers          *Numbers
	Dates            *Dates
	BruteForce       *BruteForce
	CustomIterator   *CustomIterator
	Null             *NullSource
	File             *FileSource
	CharSubstitution *CharSubstitution
	CaseModification *CaseModification
	IllegalUnicode   *IllegalUnicode
	CharacterBlocks  *CharacterBlocks
	BitFlipper       *BitFlipper
	Username         *UsernameGenerator
	ECBShuffler      *ECBShuffler
	// CopyOther has no fields of its own to resolve: it names another selected position by
	// index and is handled before Resolve is ever called (see intruderSources in
	// internal/web/api_tools.go), by copying that position's already-resolved PayloadSet
	// verbatim. It is a PayloadSource variant, not a payload_rules step, because Burp offers
	// it as a payload *type* an operator picks per position, the same menu Numbers and
	// Custom iterator live in — not a transform applied after some other type generated
	// something.
	CopyOther *CopyOtherSource
	// Collaborator (hi8) is Burp's Intruder Collaborator payload type (Zg3a.COLLABORATOR_
	// INTERACTION_IDS): each payload is a fresh out-of-band address, so an OOB probe can be
	// swept across a parameter list. Like copy_other it has no generator of its own — the web
	// layer mints the addresses at launch (it holds the interaction channel) and hands Resolve
	// an ordinary list — because minting needs the channel and the engine package must not hold
	// one. Burp mints per request at generation time (Zcc_.buildNextPayload); minting at launch
	// differs only in when the address exists, and it moves the no-channel refusal BEFORE any
	// request goes out, which is strictly more honest than Burp's set-ends-early-on-null.
	Collaborator *CollaboratorSource
	// RecursiveGrep (ztuu) is Burp's Recursive grep: the payload for request N+1 is extracted
	// from the response to request N, so a chain follows dependent values (CSRF tokens,
	// sequential DB enumeration) without a pre-resolved list. It is a PayloadSource variant
	// because Burp offers it in the same per-position payload-type menu — but unlike every
	// other variant, Resolve cannot produce the set: the payloads do not exist until the
	// responses do. Resolve returns the one-payload set holding Initial, and the engine's
	// recursive driver (Run's recursive branch, engine.go) owns the chain from there. The
	// obvious alternative — resolving at launch by pre-sending the whole chain — is refused
	// because it would replay the target out of order and record nothing the operator could
	// pause or stop mid-chain.
	RecursiveGrep *RecursiveGrepSource
}

// CollaboratorSource is the configuration for {"type":"collaborator"}.
//
// Count is Burp's "Number of payloads to generate" (Zrvn's payloadCollaboratorNumberOfPayloads,
// persisted via ZNP). IncludeLocation is Burp's "Include Collaborator server location" checkbox:
// off yields the bare interaction id without the server domain (Zcc_ passes the flag straight
// through to the address builder).
type CollaboratorSource struct {
	// Count is how many distinct payloads to mint. 1..maxCollaboratorMint; the web layer
	// validates against the same ceiling the Collaborator page's batch mint uses.
	Count int `json:"count"`
	// IncludeLocation controls whether the server domain follows the id: true produces
	// `<marker>.<domain>`, false the bare `<marker>`. A POINTER with nil = true, because
	// Burp's checkbox is CHECKED by default (Zrvn's constructor: ZE.setSelected(true)) and a
	// plain bool would make the wire's absent field mean "off" — the opposite of the default
	// an operator who never touched the box gets in Burp. An id without a domain cannot
	// receive a callback by itself, so the address form is what an operator almost always
	// wants spliced into a request.
	IncludeLocation *bool `json:"include_location"`
}

// RecursiveGrepSource is the configuration for {"type":"recursive_grep"}.
//
// Field names follow Burp's own three settings (payload-types.html): Initial payload for first
// request, Extract grep item, Stop if duplicate payload found. The extract item here is a single
// regex with the same convention Grep.extract already holds — first capture group, or the whole
// match when the pattern has no group — capped at MAX_EXTRACT, which is Burp's own default
// maximum capture length (100) made one byte-budget across both features.
type RecursiveGrepSource struct {
	// Initial is the payload for the first request. The chain starts here because the first
	// extraction needs a response to read.
	Initial string `json:"initial"`
	// ExtractRe is the regex whose match in the previous response becomes the next payload.
	ExtractRe string `json:"extract_re"`
	// StopDuplicate is Burp's "Stop if duplicate payload found": stop when the extracted payload
	// equals the one just sent — "the same payload is derived twice in succession. This
	// normally indicates that the exercise is complete."
	StopDuplicate bool `json:"stop_duplicate"`
}

// ListSource is the items for {"type":"list"}.
type ListSource struct {
	Items []string `json:"items"`
}

// NullSource is the count for {"type":"null"}: N copies of the empty payload.
type NullSource struct {
	Count int `json:"count"`
}

// FileSource is the filename for {"type":"file"} — payloads from server file, one per line.
type FileSource struct {
	Filename string `json:"filename"`
}

// CharSubstitution is Burp's Character substitution: a base word list, with configured
// single-character substitutions (e.g. "e"->"3", "a"->"4") applied in every combination, not
// just all-or-nothing. "password" with e->3 and a->4 produces password, p4ssword, passw0rd
// (if o->0 were configured), p4ssw0rd, and so on — one payload per subset of the word's
// substitutable positions.
type CharSubstitution struct {
	// Words is the base word list, one payload family per word.
	Words []string `json:"words"`
	// Subs maps a single character (as it appears in a word) to its replacement. Keyed by
	// exact character, case-sensitive — an operator wanting "E" and "e" both substituted
	// lists both.
	Subs map[string]string `json:"subs"`
	// MaxPerWord bounds combinations generated per word, so one word with many
	// substitutable positions cannot alone exhaust the payload cap before later words are
	// ever reached. 0 means unbounded (subject to the overall Resolve cap).
	MaxPerWord int `json:"max_per_word"`
}

// CaseModification is Burp's Case modification: case variants of a base word list.
type CaseModification struct {
	Words []string `json:"words"`
	// Lower, Upper and Capitalize select which variants to generate; at least one must be
	// set, or nothing would be produced from a configured generator, which is a
	// configuration error rather than a silent empty set.
	Lower      bool `json:"lower"`
	Upper      bool `json:"upper"`
	Capitalize bool `json:"capitalize"`
}

// IllegalUnicode is Burp's Illegal Unicode: overlong UTF-8 encodings of ASCII characters, used
// to probe whether an application canonicalises or validates its input before a security
// check runs on it — the class of bug behind the historic overlong-encoded "%c0%af" (an
// overlong '/') IIS directory-traversal bypass.
type IllegalUnicode struct {
	// Chars are the base characters to re-encode illegally; each must be ASCII (0x00-0x7F),
	// since only a 7-bit value fits the bit budget these forms leave for it.
	Chars string `json:"chars"`
	// Forms selects which overlong widths to emit: "overlong2", "overlong3", "overlong4"
	// (a legal UTF-8 encoder would use one byte for any of these characters).
	Forms []string `json:"forms"`
	// PercentEncode renders each illegal byte as %XX, for splicing into a URL or query
	// value; false emits the raw bytes, for a context (a body, say) that can carry them
	// unencoded.
	PercentEncode bool `json:"percent_encode"`
}

// CharacterBlocks is Burp's Character blocks (also shipped under the name Character
// frobber in older Burp releases — the same generator, renamed): one payload per length in a
// range, each consisting of Chars repeated (cycled) to fill exactly that length. Used to find
// the block size that trips a buffer limit or a fixed-size field, by walking the length
// upward until something breaks.
type CharacterBlocks struct {
	// Chars is the block alphabet, cycled to fill each block. A single character ("A") is
	// Burp's ordinary use; a short repeating sequence is accepted too.
	Chars string `json:"chars"`
	// MinLen and MaxLen bound the lengths generated, inclusive.
	MinLen int `json:"min_len"`
	MaxLen int `json:"max_len"`
	// Step is the length increment between successive blocks.
	Step int `json:"step"`
}

// BitFlipper is Burp's Bit flipper: one payload per bit of Base, with exactly that bit
// inverted — a coverage sweep for a parser that only misbehaves on one specific corrupted
// bit (a checksum routine, a length field, a sign bit).
//
// Base is taken as its raw UTF-8 bytes; a flipped bit can and often does produce a byte
// sequence that is not valid UTF-8. That is not an error here — ApplyAll splices raw bytes,
// never re-validating them as text — but it does mean a payload from this generator can
// render lossily (as U+FFFD) if it is ever round-tripped through JSON, which is why
// PayloadSet.Items is tagged `json:"-"`: these strings are engine-internal byte carriers,
// never sent to the browser directly.
type BitFlipper struct {
	Base string `json:"base"`
}

// UsernameGenerator is Burp's Username generator: candidate usernames derived from a list of
// full names, in the formats real-world account-naming conventions actually use.
type UsernameGenerator struct {
	// Names is "First Last" per line (a middle name, if present, is ignored: only the first
	// and last whitespace-separated tokens are used).
	Names []string `json:"names"`
	// Formats selects which shapes to generate: "first", "last", "first.last", "firstlast",
	// "flast" (first initial + last), "firstl" (first + last initial). Empty means all six —
	// an operator who configured a name list almost always wants the full sweep, and an
	// empty list reading as "generate nothing" would be a silently useless attack.
	Formats []string `json:"formats"`
}

// usernameFormats is the full set, and CaseModification-style default when none is named.
var usernameFormats = []string{"first", "last", "first.last", "firstlast", "flast", "firstl"}

// ECBShuffler is Burp's ECB block shuffler: reorders the cipher blocks of a sample value to
// test whether an application is using unauthenticated ECB-mode encryption, where each block
// decrypts independently of its position — swapping two blocks in an ECB ciphertext produces
// a ciphertext that still decrypts block-by-block, just with those two blocks' plaintext
// transposed, which is the tell.
type ECBShuffler struct {
	// Sample is the value to permute, as it appears in the request (already encoded).
	Sample string `json:"sample"`
	// Encoding is how Sample is decoded before splitting into blocks, and how each
	// permutation is re-encoded afterwards: "base64" or "hex".
	Encoding string `json:"encoding"`
	// BlockSize is the cipher's block size in bytes (16 for AES, 8 for DES/3DES/Blowfish).
	BlockSize int `json:"block_size"`
}

// CopyOtherSource is Burp's Copy other payload: this position's payload, for every request,
// is whichever payload the named other position received for that same request. Useful for a
// password-confirmation field, a duplicated CSRF token position, or any pair of positions
// that must carry matching values for the request to be worth sending at all.
//
// It carries no generator of its own — see PayloadSource.CopyOther's doc for where it is
// actually resolved (before Resolve is called, by aliasing the referenced position's already-
// resolved set), and why that placement is the only one Burp's own semantics for it permit:
// it only means the same thing as another position's payload when the two are stepped
// together, which pitchfork and cluster bomb do (one set per position) and sniper/battering
// ram do not (one set shared or replayed across all positions, not one per position).
type CopyOtherSource struct {
	// Position is the OTHER selected position index (0-based, in request order) to mirror.
	// It must name a position earlier in the same request's position list — see
	// intruderSources for why a forward or self reference is refused rather than guessed at.
	Position int `json:"position"`
}

// UnmarshalJSON decodes the tagged shape, dispatching on "type".
func (s *PayloadSource) UnmarshalJSON(b []byte) error {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	s.Type = probe.Type
	switch probe.Type {
	case "list":
		var l ListSource
		if err := json.Unmarshal(b, &l); err != nil {
			return err
		}
		s.List = &l
	case "numbers":
		var n Numbers
		if err := json.Unmarshal(b, &n); err != nil {
			return err
		}
		s.Numbers = &n
	case "dates":
		var d Dates
		if err := json.Unmarshal(b, &d); err != nil {
			return err
		}
		s.Dates = &d
	case "brute_force":
		var bf BruteForce
		if err := json.Unmarshal(b, &bf); err != nil {
			return err
		}
		s.BruteForce = &bf
	case "custom_iterator":
		var ci CustomIterator
		if err := json.Unmarshal(b, &ci); err != nil {
			return err
		}
		s.CustomIterator = &ci
	case "null":
		var n NullSource
		if err := json.Unmarshal(b, &n); err != nil {
			return err
		}
		s.Null = &n
	case "file":
		var f FileSource
		if err := json.Unmarshal(b, &f); err != nil {
			return err
		}
		s.File = &f
	case "char_substitution":
		var c CharSubstitution
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		s.CharSubstitution = &c
	case "case_modification":
		var c CaseModification
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		s.CaseModification = &c
	case "illegal_unicode":
		var iu IllegalUnicode
		if err := json.Unmarshal(b, &iu); err != nil {
			return err
		}
		s.IllegalUnicode = &iu
	case "character_blocks":
		var cb CharacterBlocks
		if err := json.Unmarshal(b, &cb); err != nil {
			return err
		}
		s.CharacterBlocks = &cb
	case "bit_flipper":
		var bf BitFlipper
		if err := json.Unmarshal(b, &bf); err != nil {
			return err
		}
		s.BitFlipper = &bf
	case "username":
		var u UsernameGenerator
		if err := json.Unmarshal(b, &u); err != nil {
			return err
		}
		s.Username = &u
	case "ecb_shuffler":
		var e ECBShuffler
		if err := json.Unmarshal(b, &e); err != nil {
			return err
		}
		s.ECBShuffler = &e
	case "copy_other":
		var c CopyOtherSource
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		s.CopyOther = &c
	case "recursive_grep":
		var rg RecursiveGrepSource
		if err := json.Unmarshal(b, &rg); err != nil {
			return err
		}
		s.RecursiveGrep = &rg
	case "collaborator":
		var c CollaboratorSource
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		s.Collaborator = &c
	default:
		return fmt.Errorf("unknown payload source type %q", probe.Type)
	}
	return nil
}

// AsStr returns the generator kind as a string.
func (s *PayloadSource) AsStr() string {
	return s.Type
}

// Resolve produces the set, capped at min(maxCount, MaxPayloads).
//
// The cap is applied to the allocation, not to a generated list that is then trimmed: a config
// describing 10^14 payloads must not allocate 10^14 anything on its way to being cut down.
func (s *PayloadSource) Resolve(maxCount int) (*PayloadSet, error) {
	cap := maxCount
	if cap > MaxPayloads {
		cap = MaxPayloads
	}
	if cap < 0 {
		cap = 0
	}
	var (
		items []string
		total uint64
		exact bool
		trunc bool
	)
	switch s.Type {
	case "list":
		if s.List == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "list"}
		}
		total = uint64(len(s.List.Items))
		items = make([]string, 0, minI(cap, len(s.List.Items)))
		for _, item := range s.List.Items {
			if len(items) >= cap {
				break
			}
			if err := checkLen(len(item)); err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		exact = true
		trunc = uint64(len(items)) < total
	case "null":
		if s.Null == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "null"}
		}
		n := s.Null.Count
		if n > cap {
			n = cap
		}
		if n < 0 {
			n = 0
		}
		items = make([]string, n)
		total = uint64(s.Null.Count)
		exact = true
		trunc = uint64(len(items)) < total
	case "numbers":
		if s.Numbers == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "numbers"}
		}
		var err error
		items, total, exact, trunc, err = resolveNumbers(s.Numbers, cap)
		if err != nil {
			return nil, err
		}
	case "dates":
		if s.Dates == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "dates"}
		}
		var err error
		items, total, exact, trunc, err = resolveDates(s.Dates, cap)
		if err != nil {
			return nil, err
		}
	case "brute_force":
		if s.BruteForce == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "brute_force"}
		}
		var err error
		items, total, exact, trunc, err = resolveBruteForce(s.BruteForce, cap)
		if err != nil {
			return nil, err
		}
	case "custom_iterator":
		if s.CustomIterator == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "custom_iterator"}
		}
		var err error
		items, total, exact, trunc, err = resolveCustomIterator(s.CustomIterator, cap)
		if err != nil {
			return nil, err
		}
	case "file":
		if s.File == nil || strings.TrimSpace(s.File.Filename) == "" {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "file"}
		}
		// The bundled-corpus shorthand (kal): "builtin:<name>" resolves from the embedded
		// wordlists rather than the server's filesystem — the same reader contract, one
		// extra address space. Checked BEFORE the os.ReadFile so a builtin name never
		// becomes a filesystem probe.
		if IsBuiltinWordlist(s.File.Filename) {
			lines, err := resolveBuiltinWordlist(s.File.Filename, checkLen)
			if err != nil {
				return nil, err
			}
			total = uint64(len(lines))
			exact = true
			if uint64(len(lines)) > uint64(cap) {
				lines = lines[:cap]
				trunc = true
			}
			items = lines
			break
		}
		data, err := os.ReadFile(s.File.Filename)
		if err != nil {
			return nil, err
		}
		var payloads []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				if err := checkLen(len(line)); err != nil {
					return nil, err
				}
				payloads = append(payloads, line)
			}
		}
		total = uint64(len(payloads))
		exact = true
		if uint64(len(payloads)) > uint64(cap) {
			payloads = payloads[:cap]
			trunc = true
		}
		items = payloads
	case "char_substitution":
		if s.CharSubstitution == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "char_substitution"}
		}
		var err error
		items, total, exact, trunc, err = resolveCharSubstitution(s.CharSubstitution, cap)
		if err != nil {
			return nil, err
		}
	case "case_modification":
		if s.CaseModification == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "case_modification"}
		}
		var err error
		items, total, exact, trunc, err = resolveCaseModification(s.CaseModification, cap)
		if err != nil {
			return nil, err
		}
	case "illegal_unicode":
		if s.IllegalUnicode == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "illegal_unicode"}
		}
		var err error
		items, total, exact, trunc, err = resolveIllegalUnicode(s.IllegalUnicode, cap)
		if err != nil {
			return nil, err
		}
	case "character_blocks":
		if s.CharacterBlocks == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "character_blocks"}
		}
		var err error
		items, total, exact, trunc, err = resolveCharacterBlocks(s.CharacterBlocks, cap)
		if err != nil {
			return nil, err
		}
	case "bit_flipper":
		if s.BitFlipper == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "bit_flipper"}
		}
		var err error
		items, total, exact, trunc, err = resolveBitFlipper(s.BitFlipper, cap)
		if err != nil {
			return nil, err
		}
	case "username":
		if s.Username == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "username"}
		}
		var err error
		items, total, exact, trunc, err = resolveUsername(s.Username, cap)
		if err != nil {
			return nil, err
		}
	case "ecb_shuffler":
		if s.ECBShuffler == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "ecb_shuffler"}
		}
		var err error
		items, total, exact, trunc, err = resolveECBShuffler(s.ECBShuffler, cap)
		if err != nil {
			return nil, err
		}
	case "copy_other":
		// Never reached through the ordinary edge: intruderSources (internal/web/api_tools.go)
		// resolves copy_other by aliasing another position's already-resolved PayloadSet before
		// Resolve is ever called on this one — see CopyOtherSource's own doc for why. A caller
		// that reaches here anyway gets a named refusal, not a payload set that pretends to mean
		// something on its own.
		return nil, fmt.Errorf("copy_other has no generator of its own; it must be resolved by the caller against the position it names")
	case "collaborator":
		// Same shape as copy_other's refusal: the web layer resolves this one, because minting
		// needs the interaction channel the engine package must not hold. A caller that reaches
		// here anyway gets a named refusal, not a payload set that pretends to mean something.
		return nil, fmt.Errorf("collaborator has no generator of its own; the web layer mints the addresses at launch and hands over an ordinary list")
	case "recursive_grep":
		if s.RecursiveGrep == nil {
			return nil, &PayloadError{Kind: PayloadErrEmpty, What: "recursive_grep"}
		}
		if s.RecursiveGrep.ExtractRe == "" {
			return nil, fmt.Errorf("recursive_grep: extract_re is empty — there is no way to derive the second payload, so the chain would stop after the first request")
		}
		if _, err := regexp.Compile(s.RecursiveGrep.ExtractRe); err != nil {
			return nil, fmt.Errorf("recursive_grep: extract pattern does not compile: %w", err)
		}
		// The set holds the initial payload only; the chain is the engine's. Total is inexact
		// because the chain length is unknown until the responses arrive — an exact-looking 1
		// would make the report claim the attack had one payload when the plan's bound (the
		// operator's max_requests) is the real ceiling.
		items = []string{s.RecursiveGrep.Initial}
		total, exact = 0, false
	default:
		return nil, fmt.Errorf("unknown payload source type %q", s.Type)
	}
	return &PayloadSet{
		Kind:       s.Type,
		Items:      items,
		Count:      len(items),
		Total:      total,
		TotalExact: exact,
		Truncated:  trunc,
		MaxCount:   cap,
		Skipped:    0,
		// Empty, not nil. types.tools.ts declares PayloadSetReport.dropped as `DropReason[]`, and a
		// nil slice marshals to JSON `null` — which is what made the payload-sets table read
		// `null.length` and take the whole Results tab down with the ErrorBoundary
		// (burpsy-react-ui-9pxd). This is the one place a PayloadSet is constructed, so it is the
		// one place the wire form can be guaranteed.
		Dropped: []DropReason{},
	}, nil
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// takeOf converts an unbounded uint64 total into a safe allocation size. cap is always small
// (it is clamped to MaxPayloads before Resolve dispatches), so int(total) is only safe when it
// is below that cap; anything larger just yields the cap.
func takeOf(total uint64, cap int) int {
	if uint64(cap) >= total {
		return int(total)
	}
	return cap
}

func checkLen(length int) error {
	if length > MaxItemLen {
		return &PayloadError{Kind: PayloadErrItemTooLong, Len: length, Limit: MaxItemLen}
	}
	return nil
}

// rangeCount returns how many values from..to by step describe, or an error if they disagree.
// The distance is computed in unsigned space so a full int64 range cannot overflow.
func rangeCount(from, to, step int64) (uint64, error) {
	if step == 0 {
		return 0, &PayloadError{Kind: PayloadErrZeroStep}
	}
	// Rust promotes to i128; the unsigned difference of the larger encoding minus the smaller
	// is the exact |to-from| for any int64 pair.
	var span uint64
	if to > from {
		span = uint64(to) - uint64(from)
	} else {
		span = uint64(from) - uint64(to)
	}
	if (to > from && step < 0) || (to < from && step > 0) {
		return 0, &PayloadError{
			Kind: PayloadErrBackwardsRange,
			From: strconv.FormatInt(from, 10),
			To:   strconv.FormatInt(to, 10),
			Step: step,
		}
	}
	stepAbs := step
	if stepAbs < 0 {
		// |MinInt| does not fit in int64; halve-and-shift gives the exact magnitude.
		stepAbs = -(stepAbs + 1) + 1
	}
	return span/uint64(stepAbs) + 1, nil
}

func resolveNumbers(n *Numbers, cap int) ([]string, uint64, bool, bool, error) {
	switch n.Order {
	case NumberOrderSequential, "":
		total, err := rangeCount(n.From, n.To, n.Step)
		if err != nil {
			return nil, 0, false, false, err
		}
		take := takeOf(total, cap)
		out := make([]string, 0, take)
		v := n.From
		for i := 0; i < take; i++ {
			s := writeNumber(v, n.Base, n.PadTo)
			if err := checkLen(len(s)); err != nil {
				return nil, 0, false, false, err
			}
			out = append(out, s)
			v += n.Step
		}
		trunc := uint64(len(out)) < total
		return out, total, true, trunc, nil
	case NumberOrderRandom:
		lo, hi := n.From, n.To
		if lo > hi {
			lo, hi = hi, lo
		}
		count := n.Count
		if count < 0 {
			// A negative count asks for nothing; refuse is friendlier than a silent empty set.
			count = 0
		}
		total := uint64(count)
		take := takeOf(total, cap)
		rng := newSplitMix64(n.Seed)
		out := make([]string, 0, take)
		// The inclusive span as a width. uint64 subtraction is exact for any int64 pair; when
		// lo and hi are the full two's-complement range the +1 wraps to 0, which means "draw
		// the whole width", so fall back to the raw uint64 draw.
		width := uint64(hi) - uint64(lo) + 1
		whole := width == 0
		for i := 0; i < take; i++ {
			var v int64
			if whole {
				v = lo + int64(rng.next())
			} else {
				v = lo + int64(rng.next()%width)
			}
			s := writeNumber(v, n.Base, n.PadTo)
			if err := checkLen(len(s)); err != nil {
				return nil, 0, false, false, err
			}
			out = append(out, s)
		}
		trunc := uint64(len(out)) < total
		return out, total, true, trunc, nil
	default:
		return nil, 0, false, false, fmt.Errorf("unknown number order %q", n.Order)
	}
}

func writeNumber(v int64, base NumberBase, padTo int) string {
	neg := v < 0
	mag := v
	if neg {
		mag = -mag
	}
	digits := strconv.FormatInt(mag, 10)
	if base == NumberBaseHex {
		digits = strconv.FormatUint(uint64(mag), 16)
	}
	pad := padTo - len(digits)
	if pad < 0 {
		pad = 0
	}
	if pad > MaxItemLen {
		pad = MaxItemLen
	}
	var b strings.Builder
	b.Grow(len(digits) + pad + 1)
	if neg {
		b.WriteByte('-')
	}
	for i := 0; i < pad; i++ {
		b.WriteByte('0')
	}
	b.WriteString(digits)
	return b.String()
}

func resolveDates(d *Dates, cap int) ([]string, uint64, bool, bool, error) {
	from, err := parseDate(d.From)
	if err != nil {
		return nil, 0, false, false, err
	}
	to, err := parseDate(d.To)
	if err != nil {
		return nil, 0, false, false, err
	}
	total, err := rangeCount(from, to, d.Step)
	if err != nil {
		return nil, 0, false, false, err
	}
	take := takeOf(total, cap)
	out := make([]string, 0, take)
	day := from
	for i := 0; i < take; i++ {
		s := formatDate(day, d.Format)
		if err := checkLen(len(s)); err != nil {
			return nil, 0, false, false, err
		}
		out = append(out, s)
		day += d.Step
	}
	trunc := uint64(len(out)) < total
	return out, total, true, trunc, nil
}

// parseDate converts YYYY-MM-DD to a day number. Strict on purpose: a date the operator
// mistyped must not silently become a different one.
func parseDate(s string) (int64, error) {
	bad := func() error { return &PayloadError{Kind: PayloadErrBadDate, Date: s} }
	parts := strings.Split(s, "-")
	// A leading "-" would be a negative year, which is not a date anyone types here.
	if len(parts) != 3 {
		return 0, bad()
	}
	y, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, bad()
	}
	m, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || m < 1 || m > 12 {
		return 0, bad()
	}
	dd, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || dd < 1 || dd > 31 {
		return 0, bad()
	}
	if dd > int64(daysInMonth(y, m)) {
		return 0, bad()
	}
	return daysFromCivil(y, m, dd), nil
}

var months = [12]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

func formatDate(day int64, format string) string {
	y, m, d := civilFromDays(day)
	var b strings.Builder
	b.Grow(len(format) + 8)
	for i := 0; i < len(format); {
		// Longest token first: yyyy must not be read as two yy.
		switch {
		case strings.HasPrefix(format[i:], "yyyy"):
			b.WriteString(fmt.Sprintf("%04d", y))
			i += 4
		case strings.HasPrefix(format[i:], "yy"):
			b.WriteString(fmt.Sprintf("%02d", y%100))
			i += 2
		case strings.HasPrefix(format[i:], "MMM"):
			// civilFromDays only ever returns 1..=12, but a clamp costs nothing.
			idx := m - 1
			if idx < 0 {
				idx = 0
			}
			if idx > 11 {
				idx = 11
			}
			b.WriteString(months[idx])
			i += 3
		case strings.HasPrefix(format[i:], "MM"):
			b.WriteString(fmt.Sprintf("%02d", m))
			i += 2
		case strings.HasPrefix(format[i:], "dd"):
			b.WriteString(fmt.Sprintf("%02d", d))
			i += 2
		default:
			// Copy the whole character, never a byte that would split a multi-byte rune.
			r, size := utf8.DecodeRuneInString(format[i:])
			b.WriteRune(r)
			i += size
		}
	}
	return b.String()
}

func isLeap(y int64) bool {
	return (y%4 == 0 && y%100 != 0) || y%400 == 0
}

func daysInMonth(y, m int64) int64 {
	switch m {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeap(y) {
			return 29
		}
		return 28
	}
	return 0
}

// daysFromCivil is Howard Hinnant's days_from_civil, exact for the whole int64 range.
func daysFromCivil(y, m, d int64) int64 {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 && y%400 != 0 {
		era--
	}
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}

// civilFromDays is the inverse of daysFromCivil.
func civilFromDays(z int64) (int64, int64, int64) {
	z += 719468
	// Rust's `if z >= 0 { z } else { z - 146_096 } / 146_097` is floor division; the
	// subtract-then-truncate and the decrement-if-not-exact forms agree on every input.
	era := z / 146097
	if z < 0 && z%146097 != 0 {
		era--
	}
	doe := z - era*146097
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d := doy - (153*mp+2)/5 + 1
	m := mp + 3
	if mp >= 10 {
		m = mp - 9
	}
	if m <= 2 {
		y++
	}
	return y, m, d
}

func resolveBruteForce(b *BruteForce, cap int) ([]string, uint64, bool, bool, error) {
	alphabet := runesOf(b.Charset)
	if len(alphabet) == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "charset"}
	}
	min := b.MinLen
	if min < 1 {
		min = 1
	}
	if b.MaxLen < min {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadLengthRange, Min: b.MinLen, Max: b.MaxLen}
	}
	// The longest possible item, checked before generating: the answer is the same for every
	// item of that length, so one check settles it.
	widest := 0
	for _, c := range alphabet {
		if len(c) > widest {
			widest = len(c)
		}
	}
	if widest == 0 {
		widest = 1
	}
	if b.MaxLen > MaxItemLen/widest {
		// The true length is at least MaxItemLen+1; report a saturated value rather than an
		// overflowed product.
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrItemTooLong, Len: MaxItemLen + 1, Limit: MaxItemLen}
	}
	if err := checkLen(widest * b.MaxLen); err != nil {
		return nil, 0, false, false, err
	}

	n := uint64(len(alphabet))
	var total uint64
	saturated := false
	for length := min; length <= b.MaxLen; length++ {
		p := powU64(n, length)
		if total > math.MaxUint64-p {
			total = math.MaxUint64
			saturated = true
			break
		}
		total += p
	}
	exact := !saturated

	take := takeOf(total, cap)
	out := make([]string, 0, take)
	// Odometer, shortest string first and the last position varying fastest — counting order.
	idx := make([]int, min)
	for len(out) < take {
		var item strings.Builder
		item.Grow(len(idx) * widest)
		for _, i := range idx {
			item.WriteString(alphabet[i])
		}
		out = append(out, item.String())
		// Increment.
		p := len(idx)
		for {
			if p == 0 {
				// Every position wrapped: move to the next length.
				if len(idx) >= b.MaxLen {
					return out, total, exact, uint64(len(out)) < total, nil
				}
				idx = make([]int, len(idx)+1)
				break
			}
			p--
			idx[p]++
			if idx[p] < len(alphabet) {
				break
			}
			idx[p] = 0
		}
	}
	trunc := uint64(len(out)) < total
	return out, total, exact, trunc, nil
}

func runesOf(s string) []string {
	runes := make([]string, 0, utf8.RuneCountInString(s))
	for _, r := range s {
		runes = append(runes, string(r))
	}
	return runes
}

func powU64(base uint64, exp int) uint64 {
	result := uint64(1)
	for i := 0; i < exp; i++ {
		next := result * base
		if base != 0 && next/base != result {
			return math.MaxUint64
		}
		result = next
	}
	return result
}

func resolveCustomIterator(c *CustomIterator, cap int) ([]string, uint64, bool, bool, error) {
	if len(c.Positions) < 2 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrTooFewSlots, Slots: len(c.Positions)}
	}
	for _, slot := range c.Positions {
		if len(slot) == 0 {
			return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "custom iterator position slot"}
		}
	}
	var total uint64 = 1
	saturated := false
	for _, slot := range c.Positions {
		slotLen := uint64(len(slot))
		if total > math.MaxUint64/slotLen {
			total = math.MaxUint64
			saturated = true
			break
		}
		total *= slotLen
	}
	exact := !saturated
	// Longest item is the longest choice in each slot, plus the separators. Settled once.
	// The widest possible item length is bounded by slots*MaxItemLen+separators; cap the sum so
	// a pathological config (a separator near MaxItemLen across many slots) cannot overflow int.
	widest := len(c.Separator) * (len(c.Positions) - 1)
	for _, slot := range c.Positions {
		for _, item := range slot {
			if len(item) > widest {
				widest = len(item)
			}
		}
	}
	if widest < 0 || widest > MaxItemLen {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrItemTooLong, Len: MaxItemLen + 1, Limit: MaxItemLen}
	}

	take := takeOf(total, cap)
	out := make([]string, 0, take)
	idx := make([]int, len(c.Positions))
	for len(out) < take {
		var item strings.Builder
		for j, slot := range c.Positions {
			if j > 0 {
				item.WriteString(c.Separator)
			}
			item.WriteString(slot[idx[j]])
		}
		out = append(out, item.String())
		// Last slot fastest, as Burp's own iterator does.
		p := len(c.Positions)
		for {
			if p == 0 {
				trunc := uint64(len(out)) < total
				return out, total, exact, trunc, nil
			}
			p--
			idx[p]++
			if idx[p] < len(c.Positions[p]) {
				break
			}
			idx[p] = 0
		}
	}
	trunc := uint64(len(out)) < total
	return out, total, exact, trunc, nil
}

// resolveCharSubstitution enumerates, for each word, every subset of its substitutable
// character positions (2^k combinations for k substitutable positions), the all-original
// combination included — that is the base word itself, so a word with no configured
// substitution in it still contributes one payload rather than none.
func resolveCharSubstitution(c *CharSubstitution, cap int) ([]string, uint64, bool, bool, error) {
	if len(c.Words) == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "words"}
	}
	if len(c.Subs) == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "subs"}
	}
	perWord := c.MaxPerWord
	if perWord <= 0 {
		perWord = math.MaxInt
	}

	var total uint64
	saturated := false
	// wordPositions names, per word, which rune indices have a configured substitute — computed
	// once so the generation pass below does not re-scan the word for every combination.
	wordPositions := make([][]int, len(c.Words))
	wordRunes := make([][]rune, len(c.Words))
	for wi, word := range c.Words {
		runes := []rune(word)
		wordRunes[wi] = runes
		var positions []int
		for ri, r := range runes {
			if _, ok := c.Subs[string(r)]; ok {
				positions = append(positions, ri)
			}
		}
		wordPositions[wi] = positions
		k := len(positions)
		// Capped well short of any real word length so 1<<k never approaches overflow; a word
		// with more than 32 substitutable characters is not a config anyone typed by hand.
		if k > 32 {
			k = 32
		}
		combos := uint64(1) << uint(k)
		if total > math.MaxUint64-combos {
			total = math.MaxUint64
			saturated = true
		} else {
			total += combos
		}
	}
	exact := !saturated

	take := takeOf(total, cap)
	out := make([]string, 0, take)
	for wi := range c.Words {
		if len(out) >= take {
			break
		}
		positions := wordPositions[wi]
		k := len(positions)
		if k > 32 {
			k = 32
		}
		combos := uint64(1) << uint(k)
		limit := combos
		if uint64(perWord) < limit {
			limit = uint64(perWord)
		}
		for mask := uint64(0); mask < limit && len(out) < take; mask++ {
			runes := append([]rune(nil), wordRunes[wi]...)
			for bit := 0; bit < k; bit++ {
				if mask&(1<<uint(bit)) != 0 {
					pos := positions[bit]
					sub := c.Subs[string(runes[pos])]
					if sub != "" {
						runes[pos] = []rune(sub)[0]
					}
				}
			}
			item := string(runes)
			if err := checkLen(len(item)); err != nil {
				return nil, 0, false, false, err
			}
			out = append(out, item)
		}
	}
	trunc := uint64(len(out)) < total
	return out, total, exact, trunc, nil
}

// resolveCaseModification generates the selected case variants of each word, in the fixed
// order lower, upper, capitalize — an operator who enabled all three always gets them in the
// same order, which is what makes a truncated (capped) result predictable rather than
// depending on map iteration or similar.
func resolveCaseModification(c *CaseModification, cap int) ([]string, uint64, bool, bool, error) {
	if len(c.Words) == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "words"}
	}
	if !c.Lower && !c.Upper && !c.Capitalize {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "at least one case mode"}
	}
	perWord := 0
	if c.Lower {
		perWord++
	}
	if c.Upper {
		perWord++
	}
	if c.Capitalize {
		perWord++
	}
	total := uint64(len(c.Words)) * uint64(perWord)
	take := takeOf(total, cap)
	out := make([]string, 0, take)
	for _, word := range c.Words {
		if len(out) >= take {
			break
		}
		if c.Lower {
			out = append(out, strings.ToLower(word))
		}
		if len(out) < take && c.Upper {
			out = append(out, strings.ToUpper(word))
		}
		if len(out) < take && c.Capitalize {
			out = append(out, capitalizeFirst(word))
		}
	}
	trunc := uint64(len(out)) < total
	return out, total, true, trunc, nil
}

// capitalizeFirst upper-cases the first rune and lower-cases the rest — Burp's "Capitalize"
// mode, so "jSMITH" becomes "Jsmith" rather than "JSMITH" with one letter changed.
func capitalizeFirst(s string) string {
	runes := []rune(strings.ToLower(s))
	if len(runes) == 0 {
		return s
	}
	runes[0] = []rune(strings.ToUpper(string(runes[0])))[0]
	return string(runes)
}

// illegalOverlong2/3/4 render c (which must be ASCII, 0x00-0x7F) as a 2/3/4-byte overlong
// UTF-8 sequence: a legal encoder would use one byte for any of these values, so any of these
// forms is malformed by construction and exists only to probe an input path that decodes
// UTF-8 without rejecting non-shortest-form sequences — the class of bug behind the historic
// overlong-encoded "%c0%af" IIS directory-traversal bypass.
func illegalOverlong2(c byte) []byte { return []byte{0xC0 | (c >> 6), 0x80 | (c & 0x3F)} }
func illegalOverlong3(c byte) []byte { return []byte{0xE0, 0x80 | (c >> 6), 0x80 | (c & 0x3F)} }
func illegalOverlong4(c byte) []byte { return []byte{0xF0, 0x80, 0x80 | (c >> 6), 0x80 | (c & 0x3F)} }

// resolveIllegalUnicode generates one payload per (character, form) pair.
func resolveIllegalUnicode(iu *IllegalUnicode, cap int) ([]string, uint64, bool, bool, error) {
	if iu.Chars == "" {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "chars"}
	}
	if len(iu.Forms) == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "forms"}
	}
	for _, r := range iu.Chars {
		if r > 0x7F {
			return nil, 0, false, false, fmt.Errorf(
				"illegal_unicode: %q is not ASCII; only a 7-bit value fits an overlong encoding's spare bits", r)
		}
	}
	for _, f := range iu.Forms {
		switch f {
		case "overlong2", "overlong3", "overlong4":
		default:
			return nil, 0, false, false, fmt.Errorf(
				"illegal_unicode: unknown form %q (want overlong2, overlong3 or overlong4)", f)
		}
	}
	chars := []rune(iu.Chars)
	total := uint64(len(chars)) * uint64(len(iu.Forms))
	take := takeOf(total, cap)
	out := make([]string, 0, take)
	for _, r := range chars {
		if len(out) >= take {
			break
		}
		for _, f := range iu.Forms {
			if len(out) >= take {
				break
			}
			var raw []byte
			switch f {
			case "overlong2":
				raw = illegalOverlong2(byte(r))
			case "overlong3":
				raw = illegalOverlong3(byte(r))
			case "overlong4":
				raw = illegalOverlong4(byte(r))
			}
			if iu.PercentEncode {
				var b strings.Builder
				for _, by := range raw {
					fmt.Fprintf(&b, "%%%02X", by)
				}
				out = append(out, b.String())
			} else {
				out = append(out, string(raw))
			}
		}
	}
	trunc := uint64(len(out)) < total
	return out, total, true, trunc, nil
}

// resolveCharacterBlocks generates one payload per length in [MinLen, MaxLen] stepping by
// Step, each Chars cycled to fill exactly that length.
func resolveCharacterBlocks(cbk *CharacterBlocks, cap int) ([]string, uint64, bool, bool, error) {
	alphabet := runesOf(cbk.Chars)
	if len(alphabet) == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "chars"}
	}
	if cbk.Step == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrZeroStep}
	}
	if cbk.Step < 0 || cbk.MaxLen < cbk.MinLen {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadLengthRange, Min: cbk.MinLen, Max: cbk.MaxLen}
	}
	if cbk.MinLen < 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadLengthRange, Min: cbk.MinLen, Max: cbk.MaxLen}
	}
	if err := checkLen(cbk.MaxLen); err != nil {
		return nil, 0, false, false, err
	}
	total := uint64((cbk.MaxLen-cbk.MinLen)/cbk.Step) + 1
	take := takeOf(total, cap)
	out := make([]string, 0, take)
	for length := cbk.MinLen; len(out) < take && length <= cbk.MaxLen; length += cbk.Step {
		var b strings.Builder
		b.Grow(length * 4)
		for i := 0; i < length; i++ {
			b.WriteString(alphabet[i%len(alphabet)])
		}
		out = append(out, b.String())
	}
	trunc := uint64(len(out)) < total
	return out, total, true, trunc, nil
}

// resolveBitFlipper generates len(Base)*8 payloads, each Base's bytes with exactly one bit
// inverted. Bit 0 of a byte is its most significant bit, walked byte 0 first — an arbitrary
// but fixed and documented order, since nothing downstream depends on which bit is "first".
func resolveBitFlipper(bf *BitFlipper, cap int) ([]string, uint64, bool, bool, error) {
	base := []byte(bf.Base)
	if len(base) == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "base"}
	}
	total := uint64(len(base)) * 8
	take := takeOf(total, cap)
	out := make([]string, 0, take)
	for i := 0; i < take; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		flipped := append([]byte(nil), base...)
		flipped[byteIdx] ^= 0x80 >> uint(bitIdx)
		out = append(out, string(flipped))
	}
	trunc := uint64(len(out)) < total
	return out, total, true, trunc, nil
}

// resolveUsername generates, for each name, one username per requested format. A name with
// no second (surname) token skips any format that needs one, rather than fabricating a
// surname from nothing.
func resolveUsername(u *UsernameGenerator, cap int) ([]string, uint64, bool, bool, error) {
	if len(u.Names) == 0 {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "names"}
	}
	formats := u.Formats
	if len(formats) == 0 {
		formats = usernameFormats
	}
	for _, f := range formats {
		switch f {
		case "first", "last", "first.last", "firstlast", "flast", "firstl":
		default:
			return nil, 0, false, false, fmt.Errorf(
				"username: unknown format %q (want first, last, first.last, firstlast, flast or firstl)", f)
		}
	}
	// usernamesFor is computed once per name up front so the total can be counted exactly
	// before generating anything, the same shape every other generator here uses.
	perName := make([][]string, len(u.Names))
	var total uint64
	for ni, name := range u.Names {
		parts := strings.Fields(name)
		first := ""
		last := ""
		if len(parts) > 0 {
			first = strings.ToLower(parts[0])
		}
		if len(parts) > 1 {
			last = strings.ToLower(parts[len(parts)-1])
		}
		var names []string
		for _, f := range formats {
			switch f {
			case "first":
				if first != "" {
					names = append(names, first)
				}
			case "last":
				if last != "" {
					names = append(names, last)
				}
			case "first.last":
				if first != "" && last != "" {
					names = append(names, first+"."+last)
				}
			case "firstlast":
				if first != "" && last != "" {
					names = append(names, first+last)
				}
			case "flast":
				if first != "" && last != "" {
					names = append(names, first[:1]+last)
				}
			case "firstl":
				if first != "" && last != "" {
					names = append(names, first+last[:1])
				}
			}
		}
		perName[ni] = names
		total += uint64(len(names))
	}
	take := takeOf(total, cap)
	out := make([]string, 0, take)
	for _, names := range perName {
		if len(out) >= take {
			break
		}
		for _, n := range names {
			if len(out) >= take {
				break
			}
			out = append(out, n)
		}
	}
	trunc := uint64(len(out)) < total
	return out, total, true, trunc, nil
}

// factorialSaturating returns n!, saturating at MaxUint64 — ECBShuffler's unbounded total,
// the same saturating-arithmetic contract every combinatorial generator in this file honours
// (rangeCount, powU64, resolveCustomIterator's product).
func factorialSaturating(n int) (uint64, bool) {
	result := uint64(1)
	for i := 2; i <= n; i++ {
		next := result * uint64(i)
		if next/uint64(i) != result {
			return math.MaxUint64, true
		}
		result = next
	}
	return result, false
}

// resolveECBShuffler decodes Sample, splits it into BlockSize-byte blocks and generates
// permutations of the block order, re-encoding each. Permutations are enumerated in
// lexicographic order over the block indices (the standard next-permutation algorithm)
// starting from the identity order, which both bounds memory (no permutation list is ever
// materialised) and makes a capped result deterministic rather than however a map or a
// recursive generator happened to visit them.
func resolveECBShuffler(e *ECBShuffler, cap int) ([]string, uint64, bool, bool, error) {
	if strings.TrimSpace(e.Sample) == "" {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "sample"}
	}
	if e.BlockSize <= 0 {
		return nil, 0, false, false, fmt.Errorf("ecb_shuffler: block_size must be positive, got %d", e.BlockSize)
	}
	var decoded []byte
	var err error
	switch e.Encoding {
	case "base64":
		decoded, err = base64.StdEncoding.DecodeString(e.Sample)
	case "hex":
		decoded, err = hex.DecodeString(e.Sample)
	default:
		return nil, 0, false, false, fmt.Errorf("ecb_shuffler: unknown encoding %q (want base64 or hex)", e.Encoding)
	}
	if err != nil {
		return nil, 0, false, false, fmt.Errorf("ecb_shuffler: sample does not decode as %s: %w", e.Encoding, err)
	}
	if len(decoded)%e.BlockSize != 0 {
		return nil, 0, false, false, fmt.Errorf(
			"ecb_shuffler: sample is %d bytes, not a whole number of %d-byte blocks", len(decoded), e.BlockSize)
	}
	blockCount := len(decoded) / e.BlockSize
	if blockCount < 2 {
		return nil, 0, false, false, fmt.Errorf(
			"ecb_shuffler: sample decodes to %d block(s); at least 2 are needed for a reordering to mean anything", blockCount)
	}
	blocks := make([][]byte, blockCount)
	for i := range blocks {
		blocks[i] = decoded[i*e.BlockSize : (i+1)*e.BlockSize]
	}

	total, saturated := factorialSaturating(blockCount)
	exact := !saturated
	take := takeOf(total, cap)

	order := make([]int, blockCount)
	for i := range order {
		order[i] = i
	}
	out := make([]string, 0, take)
	for len(out) < take {
		buf := make([]byte, 0, len(decoded))
		for _, idx := range order {
			buf = append(buf, blocks[idx]...)
		}
		var item string
		if e.Encoding == "hex" {
			item = hex.EncodeToString(buf)
		} else {
			item = base64.StdEncoding.EncodeToString(buf)
		}
		if err := checkLen(len(item)); err != nil {
			return nil, 0, false, false, err
		}
		out = append(out, item)
		if !nextPermutation(order) {
			break
		}
	}
	trunc := uint64(len(out)) < total
	return out, total, exact, trunc, nil
}

// nextPermutation rearranges order into the next lexicographically greater permutation,
// in place, and reports whether one existed (false when order was already the last, i.e.
// strictly descending).
func nextPermutation(order []int) bool {
	n := len(order)
	i := n - 2
	for i >= 0 && order[i] >= order[i+1] {
		i--
	}
	if i < 0 {
		return false
	}
	j := n - 1
	for order[j] <= order[i] {
		j--
	}
	order[i], order[j] = order[j], order[i]
	for l, r := i+1, n-1; l < r; l, r = l+1, r-1 {
		order[l], order[r] = order[r], order[l]
	}
	return true
}

// SplitMix64 is a well-known constant PRNG; payload selection is not a security decision.
type splitMix64 struct {
	state uint64
}

func newSplitMix64(seed *uint64) *splitMix64 {
	var s uint64
	if seed != nil {
		s = *seed
	} else {
		nanos := uint64(time.Now().UnixNano())
		s = nanos ^ atomic.AddUint64(&rngCounter, 0x9E3779B97F4A7C15)
	}
	return &splitMix64{state: s}
}

var rngCounter uint64

func (r *splitMix64) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}
