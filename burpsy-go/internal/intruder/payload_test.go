package intruder

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// strs returns the items as plain strings for assertion.
func strs(set *PayloadSet) []string {
	return set.Items
}

// mustResolve unmarshals a tagged wire config and resolves it, failing the test on error.
func mustResolve(t *testing.T, wire string, maxCount int) *PayloadSet {
	t.Helper()
	var src PayloadSource
	if err := json.Unmarshal([]byte(wire), &src); err != nil {
		t.Fatalf("unmarshal %s: %v", wire, err)
	}
	set, err := src.Resolve(maxCount)
	if err != nil {
		t.Fatalf("resolve %s: %v", wire, err)
	}
	return set
}

// TestGeneratorProducesTheSameShapeALiteralListDoes pins the whole premise: nothing downstream
// can tell a generated set from a typed one.
func TestGeneratorProducesTheSameShapeALiteralListDoes(t *testing.T) {
	list := mustResolve(t, `{"type":"list","items":["1","2","3"]}`, 100)
	generated := mustResolve(t,
		`{"type":"numbers","from":1,"to":3,"step":1,"order":"sequential","count":0,"base":"decimal","pad_to":0}`,
		100)
	if len(list.Items) != len(generated.Items) {
		t.Fatalf("lengths differ: list=%d generated=%d", len(list.Items), len(generated.Items))
	}
	for i := range list.Items {
		if list.Items[i] != generated.Items[i] {
			t.Errorf("item %d differs: list=%q generated=%q", i, list.Items[i], generated.Items[i])
		}
	}
}

// TestSequentialNumbersWalkTheRangeInclusively pins inclusive from/to and honest total.
func TestSequentialNumbersWalkTheRangeInclusively(t *testing.T) {
	s := mustResolve(t,
		`{"type":"numbers","from":10,"to":20,"step":5,"order":"sequential","count":0,"base":"decimal","pad_to":0}`,
		100)
	got := strs(s)
	want := []string{"10", "15", "20"}
	if len(got) != len(want) {
		t.Fatalf("got %d items, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %q, want %q", i, got[i], want[i])
		}
	}
	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.Truncated {
		t.Error("Truncated should be false: the cap did not bite")
	}
	if s.Count != 3 {
		t.Errorf("Count = %d, want 3", s.Count)
	}
}

// TestNumbersCountDownWhenTheStepIsNegative pins a negative step walking from high to low.
func TestNumbersCountDownWhenTheStepIsNegative(t *testing.T) {
	s := mustResolve(t,
		`{"type":"numbers","from":3,"to":1,"step":-1,"order":"sequential","count":0,"base":"decimal","pad_to":0}`,
		100)
	got := strs(s)
	want := []string{"3", "2", "1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestHexAndZeroPaddingAreAppliedToTheDigitsNotTheSign pins base hex and that padding pads the
// magnitude after any sign, so -7 at width 4 is -0007, not --007.
func TestHexAndZeroPaddingAreAppliedToTheDigitsNotTheSign(t *testing.T) {
	s := mustResolve(t,
		`{"type":"numbers","from":254,"to":256,"step":1,"order":"sequential","count":0,"base":"hex","pad_to":4}`,
		100)
	got := strs(s)
	want := []string{"00fe", "00ff", "0100"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("hex item %d = %q, want %q", i, got[i], want[i])
		}
	}

	neg := mustResolve(t,
		`{"type":"numbers","from":-7,"to":-7,"step":1,"order":"sequential","count":0,"base":"decimal","pad_to":4}`,
		10)
	if len(neg.Items) != 1 || neg.Items[0] != "-0007" {
		t.Errorf("negative padded = %v, want [\"-0007\"]", neg.Items)
	}
}

// TestAZeroStepIsRefusedRatherThanProducingAnEmptySet pins that a step of zero is refused,
// because generating it would loop forever and counting it would look like an empty set.
func TestAZeroStepIsRefusedRatherThanProducingAnEmptySet(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(
		`{"type":"numbers","from":1,"to":9,"step":0,"order":"sequential","count":0,"base":"decimal","pad_to":0}`,
	), &src); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := src.Resolve(100)
	if err == nil {
		t.Fatal("expected error for zero step, got nil")
	}
	pe, ok := err.(*PayloadError)
	if !ok {
		t.Fatalf("error type = %T, want *PayloadError", err)
	}
	if pe.Kind != PayloadErrZeroStep {
		t.Errorf("Kind = %v, want PayloadErrZeroStep", pe.Kind)
	}
}

// TestAStepPointingAwayFromTheEndOfTheRangeIsRefused pins the backwards-range refusal: a step
// whose sign disagrees with the span direction would run away from `to`.
func TestAStepPointingAwayFromTheEndOfTheRangeIsRefused(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(
		`{"type":"numbers","from":1,"to":100,"step":-1,"order":"sequential","count":0,"base":"decimal","pad_to":0}`,
	), &src); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := src.Resolve(100)
	if err == nil {
		t.Fatal("expected error for backwards range, got nil")
	}
	pe, ok := err.(*PayloadError)
	if !ok {
		t.Fatalf("error type = %T, want *PayloadError", err)
	}
	if pe.Kind != PayloadErrBackwardsRange {
		t.Errorf("Kind = %v, want PayloadErrBackwardsRange", pe.Kind)
	}
}

// TestASeededRandomDrawIsReproducibleAndStaysInsideTheRange pins that a seeded draw replays
// identically, stays inside the requested range, and actually varies.
func TestASeededRandomDrawIsReproducibleAndStaysInsideTheRange(t *testing.T) {
	wire := `{"type":"numbers","from":100,"to":199,"step":1,"order":"random","count":50,"base":"decimal","pad_to":0,"seed":42}`
	a := mustResolve(t, wire, 1000)
	b := mustResolve(t, wire, 1000)
	if len(a.Items) != len(b.Items) {
		t.Fatalf("reproducible draw lengths differ: %d vs %d", len(a.Items), len(b.Items))
	}
	for i := range a.Items {
		if a.Items[i] != b.Items[i] {
			t.Errorf("seeded draw item %d differs between runs: %q vs %q", i, a.Items[i], b.Items[i])
		}
	}
	if len(a.Items) != 50 {
		t.Errorf("Count = %d, want 50", len(a.Items))
	}
	for _, v := range a.Items {
		n, err := parseInt64(v)
		if err != nil {
			t.Fatalf("draw %q not a number: %v", v, err)
		}
		if n < 100 || n > 199 {
			t.Errorf("draw %d escaped the range 100..199", n)
		}
	}
	uniq := map[string]bool{}
	for _, v := range a.Items {
		uniq[v] = true
	}
	if len(uniq) <= 10 {
		t.Errorf("only %d distinct draws — the rng is not varying", len(uniq))
	}
}

func parseInt64(s string) (int64, error) {
	var n int64
	neg := false
	rest := s
	if strings.HasPrefix(rest, "-") {
		neg = true
		rest = rest[1:]
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return 0, &badNumber{s}
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

type badNumber struct{ s string }

func (e *badNumber) Error() string { return "bad number: " + e.s }

// TestDatesWalkARangeThroughTheFormatString pins day stepping through the format tokens,
// including the 2026 non-leap February turn.
func TestDatesWalkARangeThroughTheFormatString(t *testing.T) {
	s := mustResolve(t,
		`{"type":"dates","from":"2026-02-27","to":"2026-03-02","step":1,"format":"dd/MM/yyyy"}`,
		100)
	got := strs(s)
	want := []string{"27/02/2026", "28/02/2026", "01/03/2026", "02/03/2026"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("date %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestALeapDayIsProducedAndANonLeap29thOfFebruaryIsRefused pins leap handling in both
// directions: 2024-02-29 exists, 2026-02-29 is refused as a mistyped date.
func TestALeapDayIsProducedAndANonLeap29thOfFebruaryIsRefused(t *testing.T) {
	s := mustResolve(t,
		`{"type":"dates","from":"2024-02-28","to":"2024-03-01","step":1,"format":"yyyy-MM-dd"}`,
		100)
	got := strs(s)
	want := []string{"2024-02-28", "2024-02-29", "2024-03-01"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("leap date %d = %q, want %q", i, got[i], want[i])
		}
	}

	var src PayloadSource
	if err := json.Unmarshal([]byte(
		`{"type":"dates","from":"2026-02-29","to":"2026-03-01","step":1,"format":"yyyy-MM-dd"}`,
	), &src); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := src.Resolve(100)
	if err == nil {
		t.Fatal("expected BadDate for 2026-02-29, got nil")
	}
	pe, ok := err.(*PayloadError)
	if !ok {
		t.Fatalf("error type = %T, want *PayloadError", err)
	}
	if pe.Kind != PayloadErrBadDate {
		t.Errorf("Kind = %v, want PayloadErrBadDate", pe.Kind)
	}
}

// TestTheLongestFormatTokenWinsSoYyyyIsNotTwoYy pins longest-token-first substitution.
func TestTheLongestFormatTokenWinsSoYyyyIsNotTwoYy(t *testing.T) {
	s := mustResolve(t,
		`{"type":"dates","from":"2026-07-04","to":"2026-07-04","step":1,"format":"yyyy yy MMM MM dd!"}`,
		10)
	got := strs(s)
	want := []string{"2026 26 Jul 07 04!"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("format output = %v, want %v", got, want)
	}
}

// TestBruteForceCoversEveryStringShortestFirst pins the odometer order and the exact total.
func TestBruteForceCoversEveryStringShortestFirst(t *testing.T) {
	s := mustResolve(t,
		`{"type":"brute_force","charset":"ab","min_len":1,"max_len":2}`,
		100)
	got := strs(s)
	want := []string{"a", "b", "aa", "ab", "ba", "bb"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %q, want %q", i, got[i], want[i])
		}
	}
	if s.Total != 6 {
		t.Errorf("Total = %d, want 6 (2 + 4)", s.Total)
	}
}

// TestAnEnormousBruteForceIsCappedAndSaysWhatItWouldHaveBeen pins the whole bounding argument:
// a config describing 2.2e14 payloads must cost the cap, not the count — and the operator must
// be told exactly what they asked for.
func TestAnEnormousBruteForceIsCappedAndSaysWhatItWouldHaveBeen(t *testing.T) {
	s := mustResolve(t,
		`{"type":"brute_force","charset":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789","min_len":1,"max_len":8}`,
		1000)
	if len(s.Items) != 1000 {
		t.Errorf("len = %d, want 1000 (the cap, not the count)", len(s.Items))
	}
	if !s.Truncated {
		t.Error("Truncated should be true: the cap cut the set short")
	}
	if !s.TotalExact {
		t.Error("TotalExact should be true: the 2.2e14 total is exactly representable")
	}
	if s.Total != 221_919_451_578_090 {
		t.Errorf("Total = %d, want 221919451578090 (sum of 62^1..62^8)", s.Total)
	}
	if s.MaxCount != 1000 {
		t.Errorf("MaxCount = %d, want 1000", s.MaxCount)
	}
}

// TestNoCallerCanAskForAnUnboundedSet pins the hard ceiling: MaxInt must still land on MAX_PAYLOADS.
func TestNoCallerCanAskForAnUnboundedSet(t *testing.T) {
	s := mustResolve(t,
		`{"type":"brute_force","charset":"abcdefghij","min_len":1,"max_len":12}`,
		math.MaxInt)
	if len(s.Items) != MaxPayloads {
		t.Errorf("len = %d, want MAX_PAYLOADS (%d)", len(s.Items), MaxPayloads)
	}
	if !s.Truncated {
		t.Error("Truncated should be true")
	}
}

// TestAPayloadTooLongToBeItselfIsRefusedNotShortened pins the refusal semantics: a shortened
// list is an honest subset of the attack; a shortened payload is a different payload.
func TestAPayloadTooLongToBeItselfIsRefusedNotShortened(t *testing.T) {
	// Two characters, min length 1, max length one over the cap: the widest item alone exceeds
	// MAX_ITEM_LEN, so the generator refuses rather than emitting a truncated payload.
	wire := `{"type":"brute_force","charset":"ab","min_len":1,"max_len":65537}`
	var src PayloadSource
	if err := json.Unmarshal([]byte(wire), &src); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := src.Resolve(10)
	if err == nil {
		t.Fatal("expected ItemTooLong, got nil")
	}
	pe, ok := err.(*PayloadError)
	if !ok {
		t.Fatalf("error type = %T, want *PayloadError", err)
	}
	if pe.Kind != PayloadErrItemTooLong {
		t.Errorf("Kind = %v, want PayloadErrItemTooLong", pe.Kind)
	}
}

// TestAMultibyteCharsetIsSplitByCharacterNotByByte pins that a non-ASCII charset is taken as
// characters, so a multibyte char is never split into invalid UTF-8 fragments.
func TestAMultibyteCharsetIsSplitByCharacterNotByByte(t *testing.T) {
	s := mustResolve(t,
		`{"type":"brute_force","charset":"aé","min_len":1,"max_len":1}`,
		10)
	got := strs(s)
	want := []string{"a", "é"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestACustomIteratorPermutesItsSlotsWithTheLastVaryingFastest pins the iteration order Burp's
// own iterator uses, plus the separator and exact total.
func TestACustomIteratorPermutesItsSlotsWithTheLastVaryingFastest(t *testing.T) {
	s := mustResolve(t,
		`{"type":"custom_iterator","positions":[["adm","usr"],["1","2","3"]],"separator":"-"}`,
		100)
	got := strs(s)
	want := []string{"adm-1", "adm-2", "adm-3", "usr-1", "usr-2", "usr-3"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %q, want %q", i, got[i], want[i])
		}
	}
	if s.Total != 6 {
		t.Errorf("Total = %d, want 6", s.Total)
	}
}

// TestACustomIteratorWithOneSlotIsARefusedPlainList pins Burp's two-or-more-slot requirement.
func TestACustomIteratorWithOneSlotIsARefusedPlainList(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(
		`{"type":"custom_iterator","positions":[["only"]],"separator":""}`,
	), &src); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := src.Resolve(10)
	if err == nil {
		t.Fatal("expected TooFewSlots, got nil")
	}
	pe, ok := err.(*PayloadError)
	if !ok {
		t.Fatalf("error type = %T, want *PayloadError", err)
	}
	if pe.Kind != PayloadErrTooFewSlots {
		t.Errorf("Kind = %v, want PayloadErrTooFewSlots", pe.Kind)
	}
}

// TestAnEmptySlotIsRefusedRatherThanSilentlyErasingTheProduct pins the empty-slot refusal.
func TestAnEmptySlotIsRefusedRatherThanSilentlyErasingTheProduct(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(
		`{"type":"custom_iterator","positions":[["a"],[]],"separator":""}`,
	), &src); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := src.Resolve(10)
	if err == nil {
		t.Fatal("expected Empty, got nil")
	}
	pe, ok := err.(*PayloadError)
	if !ok {
		t.Fatalf("error type = %T, want *PayloadError", err)
	}
	if pe.Kind != PayloadErrEmpty {
		t.Errorf("Kind = %v, want PayloadErrEmpty", pe.Kind)
	}
}

// TestNullPayloadsAreNUnchangedRequests pins the null payload type: N copies of the empty
// payload, i.e. the base request sent unchanged N times.
func TestNullPayloadsAreNUnchangedRequests(t *testing.T) {
	s := mustResolve(t, `{"type":"null","count":4}`, 100)
	if len(s.Items) != 4 {
		t.Errorf("len = %d, want 4", len(s.Items))
	}
	for i, item := range s.Items {
		if item != "" {
			t.Errorf("item %d = %q, want empty", i, item)
		}
	}
	if s.Total != 4 {
		t.Errorf("Total = %d, want 4", s.Total)
	}
}

// TestCivilDateArithmeticRoundTripsAcrossACentury pins the days_from_civil/civil_from_days
// pair on real month boundaries including leap years and century non-leaps.
func TestCivilDateArithmeticRoundTripsAcrossACentury(t *testing.T) {
	for _, y := range []int64{1970, 1999, 2000, 2024, 2026, 2100} {
		for m := int64(1); m <= 12; m++ {
			d := daysInMonth(y, m)
			day := daysFromCivil(y, m, d)
			yy, mm, dd := civilFromDays(day)
			if yy != y || mm != m || dd != d {
				t.Errorf("%d-%02d-%02d did not survive: got %d-%02d-%02d", y, m, d, yy, mm, dd)
			}
		}
	}
}

// TestTheWireShapeListDecodesAndResolves pins the exact tagged shape the UI sends for lists,
// including that `items` is split on commas by the UI and arrives as a real array here.
func TestTheWireShapeListDecodesAndResolves(t *testing.T) {
	s := mustResolve(t, `{"type":"list","items":["admin","test","payload1","0000"]}`, 100)
	got := strs(s)
	want := []string{"admin", "test", "payload1", "0000"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %q, want %q", i, got[i], want[i])
		}
	}
	if !s.TotalExact {
		t.Error("a literal list is exactly counted")
	}
	if s.Truncated {
		t.Error("a list under the cap is not truncated")
	}
}

// TestResolveCapsALiteralList pins the cap cutting a long list and reporting truncation.
func TestResolveCapsALiteralList(t *testing.T) {
	s := mustResolve(t, `{"type":"list","items":["1","2","3","4","5"]}`, 3)
	if len(s.Items) != 3 {
		t.Errorf("len = %d, want 3", len(s.Items))
	}
	if !s.Truncated {
		t.Error("Truncated should be true: the cap cut a 5-item list to 3")
	}
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5 (what was asked for)", s.Total)
	}
	if s.MaxCount != 3 {
		t.Errorf("MaxCount = %d, want 3", s.MaxCount)
	}
}

// TestAnEmptyBruteForceCharsetIsRefused pins the Empty refusal for a charset with nothing in it.
func TestAnEmptyBruteForceCharsetIsRefused(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(
		`{"type":"brute_force","charset":"","min_len":1,"max_len":2}`,
	), &src); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := src.Resolve(10)
	if err == nil {
		t.Fatal("expected Empty for empty charset, got nil")
	}
	pe, ok := err.(*PayloadError)
	if !ok {
		t.Fatalf("error type = %T, want *PayloadError", err)
	}
	if pe.Kind != PayloadErrEmpty {
		t.Errorf("Kind = %v, want PayloadErrEmpty", pe.Kind)
	}
}

// TestABadLengthRangeIsRefused pins min_len > max_len being refused rather than yielding nothing.
func TestABadLengthRangeIsRefused(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(
		`{"type":"brute_force","charset":"ab","min_len":3,"max_len":2}`,
	), &src); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := src.Resolve(10)
	if err == nil {
		t.Fatal("expected BadLengthRange, got nil")
	}
	pe, ok := err.(*PayloadError)
	if !ok {
		t.Fatalf("error type = %T, want *PayloadError", err)
	}
	if pe.Kind != PayloadErrBadLengthRange {
		t.Errorf("Kind = %v, want PayloadErrBadLengthRange", pe.Kind)
	}
}

// TestUnknownSourceTypeIsRefusedAtDecodeTime pins that a typo'd type tag fails loud, not silently.
func TestUnknownSourceTypeIsRefusedAtDecodeTime(t *testing.T) {
	var src PayloadSource
	err := json.Unmarshal([]byte(`{"type":"not_a_source","from":1}`), &src)
	if err == nil {
		t.Fatal("expected decode error for unknown type, got nil")
	}
}
