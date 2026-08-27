package intruder

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
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

	List           *ListSource
	Numbers        *Numbers
	Dates          *Dates
	BruteForce     *BruteForce
	CustomIterator *CustomIterator
	Null           *NullSource
	File           *FileSource
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
		Dropped:    nil,
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
