package intruder

import (
	"encoding/json"
	"strings"
	"testing"
)

// Burp's Character frobber "modifies the value of each character position of an input" and increments
// one character at a time (tools/intruder/configure-attack/payload-types.html:590-595). burpsy shipped
// CharacterBlocks under the name "character blocks/frobber", and those are different generators: the
// blocks one has an alphabet and a length range and no input value to vary, so it cannot express the
// technique this one exists for (burpsy-react-ui-cd00).
//
// The technique: take a token the target issued, and walk one character at a time to find which
// position an authorization check, a signature or a parser actually depends on.

// The core property: every payload is the base with EXACTLY ONE character changed, and every
// (position, character) pair appears. A generator that changed two at once, or skipped a pair, would
// satisfy a weaker test and answer a different question.
func TestTheFrobberChangesExactlyOneCharacterPerPayload(t *testing.T) {
	base := "abc"
	src := PayloadSource{Type: "character_frobber", CharacterFrobber: &CharacterFrobber{Base: base, Chars: "xy"}}
	set, err := src.Resolve(1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if set.Total != 6 {
		t.Errorf("total = %d, want 3 positions x 2 characters = 6", set.Total)
	}
	if len(set.Items) != 6 {
		t.Fatalf("produced %d payloads, want 6", len(set.Items))
	}
	for _, item := range set.Items {
		if len(item) != len(base) {
			t.Fatalf("payload %q is not the base's length; the frobber replaces one character and "+
				"never adds or removes one", item)
		}
		diffs := 0
		for i := range base {
			if item[i] != base[i] {
				diffs++
			}
		}
		if diffs != 1 {
			t.Errorf("payload %q differs from the base in %d position(s); a frobber changes exactly one",
				item, diffs)
		}
	}
	// And every pair is covered: position-major, so position 0's two characters come first.
	want := []string{"xbc", "ybc", "axc", "ayc", "abx", "aby"}
	for i, w := range want {
		if set.Items[i] != w {
			t.Errorf("payload %d = %q, want %q (position-major order: one position across the whole "+
				"alphabet before moving on, so the first divergence from the valid token surfaces early)",
				i, set.Items[i], w)
		}
	}
}

// The DEFAULT alphabet, which is the case that matters: a token's characters are printable ASCII, and
// an operator who has not typed an alphabet should still get a sweep rather than a refusal.
func TestTheFrobberDefaultsToThePrintableRange(t *testing.T) {
	src := PayloadSource{Type: "character_frobber", CharacterFrobber: &CharacterFrobber{Base: "a"}}
	set, err := src.Resolve(1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// 0x20..0x7e is 95 characters.
	if set.Total != 95 {
		t.Errorf("total = %d, want 95 (the printable ASCII range 0x20..0x7e)", set.Total)
	}
	joined := strings.Join(set.Items, "")
	if !strings.Contains(joined, string(rune(' '))) {
		t.Error("the space character is missing from the default alphabet; 0x20 is in the printable range")
	}
	if strings.Contains(joined, string(rune(0x7f))) {
		t.Error("DEL is in the default alphabet; 0x7e is the last printable character")
	}
}

// A multi-byte character is ONE position, not several. Counting bytes would make "position 3" mean
// something different here than it does in the target's own parameter, and the operator mapping
// payloads back onto a token could not line them up.
func TestTheFrobberCountsCharactersNotBytes(t *testing.T) {
	base := "é☃" // 2 characters, 5 UTF-8 bytes
	src := PayloadSource{Type: "character_frobber", CharacterFrobber: &CharacterFrobber{Base: base, Chars: "x"}}
	set, err := src.Resolve(1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if set.Total != 2 {
		t.Errorf("total = %d, want 2 (one per CHARACTER); a byte count would say 5 and produce payloads "+
			"that split a character in half", set.Total)
	}
	want := []string{"x☃", "éx"}
	for i, w := range want {
		if set.Items[i] != w {
			t.Errorf("payload %d = %q, want %q", i, set.Items[i], w)
		}
	}
}

// The cap truncates, and says so. A twenty-character token over the printable range is 1,900
// payloads, which is inside the bound; a long one is not, and an operator must be able to see that
// before launching rather than discover it from a short run.
func TestTheFrobberHonoursTheCapAndReportsTruncation(t *testing.T) {
	src := PayloadSource{Type: "character_frobber", CharacterFrobber: &CharacterFrobber{Base: "abcdefgh", Chars: "xyz"}}
	set, err := src.Resolve(5)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(set.Items) != 5 {
		t.Errorf("produced %d payloads under a cap of 5", len(set.Items))
	}
	if set.Total != 24 {
		t.Errorf("total = %d, want 24 (8 positions x 3 characters); the cap must not change the count the "+
			"operator is shown", set.Total)
	}
	if !set.Truncated {
		t.Error("Truncated is false under a cap of 5 with 24 available: an operator would read a short run as " +
			"a complete one")
	}
}

// An empty base is refused, because there is nothing to vary. It is a different refusal from an
// empty alphabet — the alphabet has a sensible default, the base does not — and the message says which.
func TestTheFrobberRefusesAnEmptyBaseAndSaysSo(t *testing.T) {
	src := PayloadSource{Type: "character_frobber", CharacterFrobber: &CharacterFrobber{Base: ""}}
	_, err := src.Resolve(100)
	if err == nil {
		t.Fatal("an empty base was accepted; there is no value to increment")
	}
	if !strings.Contains(err.Error(), "base") {
		t.Errorf("error = %q, want it to name the base — an empty alphabet is fine here (it defaults), "+
			"so naming that instead would send the operator looking in the wrong field", err)
	}
}

// The wire shape, because the console posts it: a character_frobber document must decode into the
// frobber and NOT into the blocks generator. Two generators sharing a name on screen is what made this
// bead necessary, so the decoder is where that separation has to hold.
func TestTheFrobberDecodesFromItsOwnWireName(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"character_frobber","base":"secret","chars":"az"}`), &src); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if src.CharacterFrobber == nil {
		t.Fatal("a character_frobber document decoded without a frobber")
	}
	if src.CharacterBlocks != nil {
		t.Error("a character_frobber document decoded into CharacterBlocks; the two generators are " +
			"different and sharing a decoder arm is what made this look delivered (burpsy-react-ui-cd00)")
	}
	if src.CharacterFrobber.Base != "secret" || src.CharacterFrobber.Chars != "az" {
		t.Errorf("decoded %+v, want base=secret chars=az", *src.CharacterFrobber)
	}
}

// And the blocks generator keeps its own name, so the two stop sharing one in the close reasons as
// well as on screen.
func TestCharacterBlocksStillDecodesFromItsOwnWireName(t *testing.T) {
	var src PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"character_blocks","chars":"A","min_len":1,"max_len":4,"step":1}`), &src); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if src.CharacterBlocks == nil {
		t.Fatal("a character_blocks document stopped decoding into CharacterBlocks")
	}
	if src.CharacterFrobber != nil {
		t.Error("a character_blocks document decoded into the frobber; the two must not share a name on " +
			"the wire either")
	}
}

// The base's own character is emitted where the alphabet CONTAINS it, so an operator can tell
// whether a position matters by whether the request that changes nothing else still fails. Where the
// alphabet does not contain the base's character for that position, no payload is the base — and
// reporting one anyway would tell the operator a position was unperturbed when it never was.
func TestTheFrobberEmitsTheBaseItselfAtEveryPosition(t *testing.T) {
	base := "ab"
	src := PayloadSource{Type: "character_frobber", CharacterFrobber: &CharacterFrobber{Base: base, Chars: "az"}}
	set, err := src.Resolve(100)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Alphabet order is 'a' then 'z'. At position 0 the base's own character is 'a', so payload 0
	// is the base itself. At position 1 it is 'b' — which is NOT in the alphabet — so no payload at
	// that position is the base, and that is the point: a position whose character the alphabet does
	// not contain cannot be returned to the valid value, and pretending otherwise would report a
	// position as unperturbed when it never was.
	want := []string{"ab", "zb", "aa", "az"}
	for i, w := range want {
		if set.Items[i] != w {
			t.Errorf("payload %d = %q, want %q", i, set.Items[i], w)
		}
	}
}
