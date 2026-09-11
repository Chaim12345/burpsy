package intruder

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// 2g13: the 9 Burp payload types burpsy did not have. Copy other payload is exercised in
// api_tools_copy_other_test.go (internal/web) instead, since it is resolved at the caller —
// see CopyOtherSource's doc comment for why.

func TestCharSubstitutionEnumeratesEverySubsetOfSubstitutablePositions(t *testing.T) {
	s := mustResolve(t, `{"type":"char_substitution","words":["cat"],"subs":{"a":"4","c":"C"}}`, 100)
	got := strs(s)
	want := map[string]bool{"cat": true, "Cat": true, "c4t": true, "C4t": true}
	if len(got) != 4 {
		t.Fatalf("got %d items, want 4 (2 substitutable positions -> 2^2 combos): %v", len(got), got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected combination %q, want one of %v", g, want)
		}
	}
	if s.Total != 4 || !s.TotalExact {
		t.Fatalf("total=%d exact=%v, want 4/true", s.Total, s.TotalExact)
	}
}

func TestCharSubstitutionWordWithNothingSubstitutableStillYieldsTheBaseWord(t *testing.T) {
	s := mustResolve(t, `{"type":"char_substitution","words":["xyz"],"subs":{"a":"4"}}`, 100)
	if got := strs(s); len(got) != 1 || got[0] != "xyz" {
		t.Fatalf("got %v, want exactly [\"xyz\"]", got)
	}
}

func TestCharSubstitutionMaxPerWordBoundsOneWordWithoutStarvingTheNext(t *testing.T) {
	s := mustResolve(t,
		`{"type":"char_substitution","words":["aaaa","b"],"subs":{"a":"4","b":"8"},"max_per_word":2}`, 100)
	// "aaaa" has 4 substitutable positions (16 combinations), capped at 2; "b" has 1 (2
	// combinations), under the cap, so both contribute — the second word must not starve.
	got := strs(s)
	if len(got) != 4 {
		t.Fatalf("got %d items (2 from \"aaaa\", 2 from \"b\"), want 4: %v", len(got), got)
	}
	foundB := false
	for _, g := range got[2:] {
		if g == "b" || g == "8" {
			foundB = true
		}
	}
	if !foundB {
		t.Fatalf("the second word's combinations never appeared: %v", got)
	}
}

func TestCharSubstitutionRefusesEmptyWordsOrSubs(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"char_substitution","words":[],"subs":{"a":"4"}}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("empty words must be refused")
	}
	if err := json.Unmarshal([]byte(`{"type":"char_substitution","words":["a"],"subs":{}}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("empty subs must be refused")
	}
}

func TestCaseModificationGeneratesTheSelectedVariantsInAFixedOrder(t *testing.T) {
	s := mustResolve(t, `{"type":"case_modification","words":["AdMin"],"lower":true,"upper":true,"capitalize":true}`, 100)
	want := []string{"admin", "ADMIN", "Admin"}
	got := strs(s)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCaseModificationRefusesWhenNoModeIsSelected(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"case_modification","words":["a"]}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("no case mode selected must be refused, not silently produce nothing")
	}
}

func TestIllegalUnicodeProducesTheOverlongIISTraversalByte(t *testing.T) {
	// The historically famous case: '/' (0x2F) overlong-2-byte-encoded is 0xC0 0xAF —
	// %c0%af, the IIS Unicode directory-traversal bypass.
	s := mustResolve(t, `{"type":"illegal_unicode","chars":"/","forms":["overlong2"],"percent_encode":true}`, 10)
	got := strs(s)
	if len(got) != 1 || got[0] != "%C0%AF" {
		t.Fatalf("got %v, want [\"%%C0%%AF\"]", got)
	}
}

func TestIllegalUnicodeRawBytesDecodeBackToTheOriginalCharacterAsOverlongUTF8(t *testing.T) {
	s := mustResolve(t, `{"type":"illegal_unicode","chars":"A","forms":["overlong2","overlong3","overlong4"],"percent_encode":false}`, 10)
	got := strs(s)
	if len(got) != 3 {
		t.Fatalf("got %d items, want 3 (one per form): %v", len(got), got)
	}
	wantLens := []int{2, 3, 4}
	for i, g := range got {
		if len(g) != wantLens[i] {
			t.Errorf("form %d: byte length = %d, want %d", i, len(g), wantLens[i])
		}
	}
}

func TestIllegalUnicodeRefusesANonASCIICharacter(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"illegal_unicode","chars":"é","forms":["overlong2"]}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("a non-ASCII character has no 7-bit value to overlong-encode and must be refused")
	}
}

func TestCharacterBlocksWalksTheLengthRange(t *testing.T) {
	s := mustResolve(t, `{"type":"character_blocks","chars":"A","min_len":1,"max_len":5,"step":2}`, 100)
	got := strs(s)
	want := []string{"A", "AAA", "AAAAA"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCharacterBlocksCyclesAMultiCharAlphabet(t *testing.T) {
	s := mustResolve(t, `{"type":"character_blocks","chars":"AB","min_len":5,"max_len":5,"step":1}`, 100)
	got := strs(s)
	if len(got) != 1 || got[0] != "ABABA" {
		t.Fatalf("got %v, want [\"ABABA\"]", got)
	}
}

func TestCharacterBlocksRefusesAZeroStepTheSameWayNumbersDoes(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"character_blocks","chars":"A","min_len":1,"max_len":5,"step":0}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("a zero step never advances and must be refused")
	}
}

func TestBitFlipperFlipsExactlyOneBitPerPayload(t *testing.T) {
	s := mustResolve(t, `{"type":"bit_flipper","base":"A"}`, 100)
	got := strs(s)
	if len(got) != 8 {
		t.Fatalf("got %d items, want 8 (one 'A' byte * 8 bits): %v", len(got), got)
	}
	base := byte('A')
	seen := map[byte]bool{}
	for _, g := range got {
		if len(g) != 1 {
			t.Fatalf("payload %q is not one byte", g)
		}
		flipped := g[0]
		diff := base ^ flipped
		// Exactly one bit differs: diff is a power of two (and non-zero).
		if diff == 0 || diff&(diff-1) != 0 {
			t.Errorf("payload byte 0x%02x differs from base 0x%02x by more than one bit (diff 0x%02x)", flipped, base, diff)
		}
		seen[flipped] = true
	}
	if len(seen) != 8 {
		t.Fatalf("only %d distinct flips produced, want 8 (one per bit)", len(seen))
	}
}

func TestBitFlipperRefusesAnEmptyBase(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"bit_flipper","base":""}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("an empty base has no bits to flip and must be refused")
	}
}

func TestUsernameGeneratorDerivesTheDefaultFormatsFromAFullName(t *testing.T) {
	s := mustResolve(t, `{"type":"username","names":["John Smith"]}`, 100)
	got := strs(s)
	want := map[string]bool{"john": true, "smith": true, "john.smith": true, "johnsmith": true, "jsmith": true, "johns": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want the 6 default formats", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected username %q", g)
		}
	}
}

func TestUsernameGeneratorHonoursAnExplicitFormatList(t *testing.T) {
	s := mustResolve(t, `{"type":"username","names":["Ada Lovelace"],"formats":["first.last"]}`, 100)
	if got := strs(s); len(got) != 1 || got[0] != "ada.lovelace" {
		t.Fatalf("got %v, want [\"ada.lovelace\"]", got)
	}
}

func TestUsernameGeneratorSkipsSurnameFormatsForAOneWordName(t *testing.T) {
	s := mustResolve(t, `{"type":"username","names":["Cher"],"formats":["first","last","first.last"]}`, 100)
	got := strs(s)
	if len(got) != 1 || got[0] != "cher" {
		t.Fatalf("got %v, want just [\"cher\"] — no surname to build the other formats from", got)
	}
}

func TestECBShufflerPermutesBlocksAndReencodesToTheSameLength(t *testing.T) {
	sample := base64.StdEncoding.EncodeToString([]byte("AAAABBBBCCCC")) // 3 blocks of 4 bytes
	s := mustResolve(t, `{"type":"ecb_shuffler","sample":"`+sample+`","encoding":"base64","block_size":4}`, 100)
	got := strs(s)
	if len(got) != 6 { // 3! = 6
		t.Fatalf("got %d items, want 6 (3! permutations of 3 blocks): %v", len(got), got)
	}
	seen := map[string]bool{}
	for _, g := range got {
		decoded, err := base64.StdEncoding.DecodeString(g)
		if err != nil {
			t.Fatalf("permutation %q does not decode: %v", g, err)
		}
		if len(decoded) != 12 {
			t.Fatalf("permutation decodes to %d bytes, want 12", len(decoded))
		}
		seen[g] = true
	}
	if len(seen) != 6 {
		t.Fatalf("only %d distinct permutations, want 6", len(seen))
	}
	if !seen[sample] {
		t.Fatalf("the identity order must be one of the 6 permutations")
	}
}

func TestECBShufflerRefusesASampleThatIsNotAWholeNumberOfBlocks(t *testing.T) {
	sample := base64.StdEncoding.EncodeToString([]byte("AAAABBBBC")) // 9 bytes, not a multiple of 4
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"ecb_shuffler","sample":"`+sample+`","encoding":"base64","block_size":4}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("a sample that is not a whole number of blocks must be refused")
	}
}

func TestECBShufflerCapsAtTheOverallPayloadLimitForManyBlocks(t *testing.T) {
	// 6 blocks = 720 permutations; capped at 5 must produce exactly 5, deterministically, and
	// report the true (uncapped) total honestly.
	raw := make([]byte, 6*4)
	for i := range raw {
		raw[i] = byte('A' + i/4)
	}
	sample := base64.StdEncoding.EncodeToString(raw)
	s := mustResolve(t, `{"type":"ecb_shuffler","sample":"`+sample+`","encoding":"base64","block_size":4}`, 5)
	if len(s.Items) != 5 {
		t.Fatalf("got %d items, want the cap of 5", len(s.Items))
	}
	if s.Total != 720 || !s.TotalExact {
		t.Fatalf("total=%d exact=%v, want 720/true (6! is not a saturating case)", s.Total, s.TotalExact)
	}
	if !s.Truncated {
		t.Fatal("truncated must be true: 720 possible, only 5 taken")
	}
}

func TestECBShufflerRefusesFewerThanTwoBlocks(t *testing.T) {
	sample := base64.StdEncoding.EncodeToString([]byte("AAAA"))
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"ecb_shuffler","sample":"`+sample+`","encoding":"base64","block_size":4}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("a single block has nothing to reorder against and must be refused")
	}
}

func TestFactorialSaturatingMatchesSmallValuesAndSaturatesLargeOnes(t *testing.T) {
	if got, sat := factorialSaturating(5); got != 120 || sat {
		t.Fatalf("5! = %d (saturated=%v), want 120/false", got, sat)
	}
	if _, sat := factorialSaturating(25); !sat {
		t.Fatal("25! overflows uint64 and must report saturated")
	}
}

func TestCopyOtherResolvedDirectlyRefusesRatherThanGeneratingSomething(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"copy_other","position":0}`), &src); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve(10); err == nil {
		t.Fatal("copy_other has no generator of its own; Resolve must refuse rather than invent a payload set")
	}
}
