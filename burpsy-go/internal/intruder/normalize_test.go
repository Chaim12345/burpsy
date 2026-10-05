package intruder

import "testing"

func apply1(t *testing.T, spec RuleSpec, in string) Processed {
	t.Helper()
	c, err := NewChain([]RuleSpec{spec})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	return c.Apply([]byte(in))
}

// The attack: a fullwidth payload validates clean but NFKC-collapses to the raw characters, so the
// processor emits the fullwidth form and the loop below proves a server NFKC pass recovers "<script>".
func TestNormalizeFullwidthCollapsesUnderNFKC(t *testing.T) {
	got := apply1(t, RuleSpec{Rule: "normalize", Form: "fullwidth"}, "<script>")
	if got.Dropped {
		t.Fatalf("dropped: %s", got.Reason)
	}
	if string(got.Keep) == "<script>" {
		t.Fatal("fullwidth variant equals the ASCII input; nothing was transformed")
	}
	// A target that NFKC-normalises after validating sees the original.
	back := apply1(t, RuleSpec{Rule: "normalize", Form: "nfkc"}, string(got.Keep))
	if string(back.Keep) != "<script>" {
		t.Errorf("NFKC of the fullwidth variant = %q, want <script>", back.Keep)
	}
}

// NFKD decomposes a compatibility character (the ligature) to its ASCII letters.
func TestNormalizeNFKDDecomposesLigature(t *testing.T) {
	got := apply1(t, RuleSpec{Rule: "normalize", Form: "nfkd"}, "ﬃ") // U+FB03 LATIN SMALL LIGATURE FFI
	if string(got.Keep) != "ffi" {
		t.Errorf("NFKD(ﬃ) = %q, want ffi", got.Keep)
	}
}

// Homoglyph swaps Latin letters for confusables, and the bytes differ from the input.
func TestNormalizeHomoglyphSubstitutes(t *testing.T) {
	got := apply1(t, RuleSpec{Rule: "normalize", Form: "homoglyph"}, "admin")
	if string(got.Keep) == "admin" {
		t.Fatal("homoglyph variant equals the ASCII input")
	}
	// 'd', 'm', 'n' have no confusable here; 'a', 'i' do — so the result is a mix, still 5 runes.
	if n := len([]rune(string(got.Keep))); n != 5 {
		t.Errorf("homoglyph changed the rune count to %d", n)
	}
}

func TestNormalizeRefusesAnUnknownForm(t *testing.T) {
	if _, err := NewChain([]RuleSpec{{Rule: "normalize", Form: "nfz"}}); err == nil {
		t.Error("an unknown form was accepted")
	}
}
