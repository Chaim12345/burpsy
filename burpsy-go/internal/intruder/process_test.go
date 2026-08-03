package intruder

import (
	"reflect"
	"strings"
	"testing"
)

// Ports burpsy-intruder::process's test suite (process.rs:300-596). The chain runs at resolve
// time, so a dropped payload is a shorter set, not a hole in the plan.

func chain(t *testing.T, specs ...RuleSpec) *Chain {
	t.Helper()
	c, err := NewChain(specs)
	if err != nil {
		t.Fatalf("chain must compile: %v", err)
	}
	return c
}

func one(specs []RuleSpec, payload string) Processed {
	c, err := NewChain(specs)
	if err != nil {
		panic(err)
	}
	return c.Apply([]byte(payload))
}

func kept(t *testing.T, p Processed) string {
	t.Helper()
	if p.Dropped {
		t.Fatalf("dropped: %s", p.Reason)
	}
	return string(p.Keep)
}

func setOf(t *testing.T, items ...string) *PayloadSet {
	t.Helper()
	set, err := (&PayloadSource{Type: "list", List: &ListSource{Items: items}}).Resolve(1000)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return set
}

func TestRulesApplyInTheOrderTheyWereGiven(t *testing.T) {
	// prefix-then-uppercase and uppercase-then-prefix are different attacks.
	a := kept(t, one([]RuleSpec{
		{Rule: "add_prefix", Text: "abc"},
		{Rule: "uppercase"},
	}, "xy"))
	b := kept(t, one([]RuleSpec{
		{Rule: "uppercase"},
		{Rule: "add_prefix", Text: "abc"},
	}, "xy"))
	if a != "ABCXY" {
		t.Errorf("prefix then uppercase = %q, want %q", a, "ABCXY")
	}
	if b != "abcXY" {
		t.Errorf("uppercase then prefix = %q, want %q", b, "abcXY")
	}
}

func TestPrefixAndSuffixWrapThePayload(t *testing.T) {
	s := kept(t, one([]RuleSpec{
		{Rule: "add_prefix", Text: "'or "},
		{Rule: "add_suffix", Text: "--"},
	}, "1=1"))
	if s != "'or 1=1--" {
		t.Errorf("wrapped = %q, want %q", s, "'or 1=1--")
	}
}

func TestRegexReplaceUsesCaptureGroupsAndHonoursTheAllFlag(t *testing.T) {
	first := kept(t, one([]RuleSpec{{
		Rule:    "replace",
		Pattern: `(\d+)`,
		Replace: "[$1]",
		All:     false,
	}}, "a1b2"))
	if first != "a[1]b2" {
		t.Errorf("first only = %q, want %q", first, "a[1]b2")
	}
	all := kept(t, one([]RuleSpec{{
		Rule:    "replace",
		Pattern: `(\d+)`,
		Replace: "[$1]",
		All:     true,
	}}, "a1b2"))
	if all != "a[1]b[2]" {
		t.Errorf("all = %q, want %q", all, "a[1]b[2]")
	}
}

// The point of depending on the tools codecs rather than writing these again: the codecs are
// the same ones the Decoder tool uses, so a payload encoded here round-trips there.
func TestEncodeAndDecodeReuseTheDecoderCodecs(t *testing.T) {
	if s := kept(t, one([]RuleSpec{{Rule: "encode", Layer: "url"}}, "a b&c=d")); s != "a%20b%26c%3Dd" {
		t.Errorf("url encode = %q, want %q", s, "a%20b%26c%3Dd")
	}
	if s := kept(t, one([]RuleSpec{{Rule: "encode", Layer: "base64"}}, "admin")); s != "YWRtaW4=" {
		t.Errorf("base64 encode = %q, want %q", s, "YWRtaW4=")
	}
	if s := kept(t, one([]RuleSpec{{Rule: "decode", Layer: "base64"}}, "YWRtaW4=")); s != "admin" {
		t.Errorf("base64 decode = %q, want %q", s, "admin")
	}
	if s := kept(t, one([]RuleSpec{{Rule: "encode", Layer: "html"}}, "<script>")); s != "&lt;script&gt;" {
		t.Errorf("html encode = %q, want %q", s, "&lt;script&gt;")
	}
	// Chained, which is how an operator actually uses these.
	if s := kept(t, one([]RuleSpec{
		{Rule: "encode", Layer: "base64"},
		{Rule: "encode", Layer: "url"},
	}, "a?")); s != "YT8%3D" {
		t.Errorf("chained = %q, want %q", s, "YT8%3D")
	}
}

func TestAHashStepProducesLowercaseHex(t *testing.T) {
	if s := kept(t, one([]RuleSpec{{Rule: "hash", Algorithm: "md5"}}, "abc")); s != "900150983cd24fb0d6963f7d28e17f72" {
		t.Errorf("md5 = %q, want %q", s, "900150983cd24fb0d6963f7d28e17f72")
	}
	// Hash then encode is the combination that makes hex the right default: the operator can
	// get to base64 in one more step, but cannot get back from raw bytes spliced into a URL.
	if s := kept(t, one([]RuleSpec{
		{Rule: "hash", Algorithm: "sha256"},
		{Rule: "uppercase"},
	}, "abc")); s != "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" {
		t.Errorf("sha256 uppercase = %q, want %q", s, "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
	}
}

func TestSkipIfMatchesDropsThePayloadWithItsReason(t *testing.T) {
	p := one([]RuleSpec{{Rule: "skip_if_matches", Pattern: `^\d+$`}}, "12345")
	if !p.Dropped {
		t.Fatal("a numeric payload must be skipped")
	}
	if !strings.Contains(p.Reason, "skipped") {
		t.Errorf("reason %q must say it skipped", p.Reason)
	}
	if s := kept(t, one([]RuleSpec{{Rule: "skip_if_matches", Pattern: `^\d+$`}}, "12a45")); s != "12a45" {
		t.Errorf("non-numeric payload = %q, want %q", s, "12a45")
	}
}

// Where in the chain the skip sits decides what it tests. This is why it is a rule rather
// than a separate filter applied first.
func TestASkipAfterADecodeTestsTheDecodedForm(t *testing.T) {
	specs := []RuleSpec{
		{Rule: "decode", Layer: "base64"},
		{Rule: "skip_if_matches", Pattern: "admin"},
	}
	if p := one(specs, "YWRtaW4="); !p.Dropped {
		t.Fatal("decoded 'admin' must be skipped")
	}
	if p := one(specs, "Z3Vlc3Q="); p.Dropped {
		t.Fatalf("decoded 'guest' must be kept: %s", p.Reason)
	}
}

func TestAPayloadARuleCannotProcessIsDroppedNotPassedThrough(t *testing.T) {
	// `zz` is not hex. Passing it through unchanged while the report claims a hex decode ran
	// would send a payload the operator did not ask for.
	p := one([]RuleSpec{{Rule: "decode", Layer: "hex"}}, "zz")
	if !p.Dropped {
		t.Fatalf("passed through: %q", p.Keep)
	}
	if !strings.Contains(p.Reason, "hex digit") {
		t.Errorf("reason %q must name the hex digit", p.Reason)
	}
}

func TestRunShortensTheSetAndAccountsForEveryPayloadItDropped(t *testing.T) {
	set := setOf(t, "1", "2", "admin", "3", "root")
	chain(t, RuleSpec{Rule: "skip_if_matches", Pattern: `^\d+$`}).Run(set)
	if len(set.Items) != 2 {
		t.Errorf("items = %v, want only the non-numeric payloads", set.Items)
	}
	if set.Count != 2 {
		t.Errorf("count = %d, want 2", set.Count)
	}
	if set.Skipped != 3 {
		t.Errorf("skipped = %d, want 3", set.Skipped)
	}
	if len(set.Dropped) != 1 {
		t.Fatalf("dropped reasons = %v, want one reason for three payloads", set.Dropped)
	}
	if set.Dropped[0].Count != 3 {
		t.Errorf("reason count = %d, want 3", set.Dropped[0].Count)
	}
}

func TestAnEmptyChainLeavesTheSetExactlyAsItWas(t *testing.T) {
	set := setOf(t, "a", "b", "c")
	before := append([]string(nil), set.Items...)
	c, err := NewChain(nil)
	if err != nil {
		t.Fatalf("empty chain: %v", err)
	}
	c.Run(set)
	if !reflect.DeepEqual(set.Items, before) {
		t.Errorf("items changed: %v", set.Items)
	}
	if set.Skipped != 0 {
		t.Errorf("skipped = %d, want 0", set.Skipped)
	}
	if len(set.Dropped) != 0 {
		t.Errorf("dropped = %v, want none", set.Dropped)
	}
}

func TestABadPatternIsOneErrorAtConstructionNotNDropsAtRunTime(t *testing.T) {
	_, err := NewChain([]RuleSpec{{Rule: "skip_if_matches", Pattern: "([unclosed"}})
	if err == nil {
		t.Fatal("an unclosed group must be refused at construction")
	}
	re, ok := err.(*RuleError)
	if !ok || re.Kind != RuleErrBadRegex {
		t.Errorf("error = %v, want a BadRegex refusal", err)
	}
}

func TestAnUnknownLayerOrHashIsRefusedAtConstruction(t *testing.T) {
	_, err := NewChain([]RuleSpec{{Rule: "encode", Layer: "rot13"}})
	re, ok := err.(*RuleError)
	if !ok || re.Kind != RuleErrUnknownLayer || re.Layer != "rot13" {
		t.Errorf("error = %v, want unknown layer rot13", err)
	}
	_, err = NewChain([]RuleSpec{{Rule: "hash", Algorithm: "sha3"}})
	re, ok = err.(*RuleError)
	if !ok || re.Kind != RuleErrUnknownHash || re.Algorithm != "sha3" {
		t.Errorf("error = %v, want unknown hash sha3", err)
	}
}

func TestARuleThatWouldGrowAPayloadPastTheLimitDropsIt(t *testing.T) {
	// Twelve hex layers of a kilobyte is not a payload anyone means, but a chain that ran
	// away must not be able to put 64 MiB into one spliced request.
	big := strings.Repeat("A", 4_000)
	specs := make([]RuleSpec, 0, 12)
	for range 12 {
		specs = append(specs, RuleSpec{Rule: "encode", Layer: "hex"})
	}
	p := chain(t, specs...).Apply([]byte(big))
	if !p.Dropped {
		t.Fatalf("built a %d-byte payload", len(p.Keep))
	}
	if !strings.Contains(p.Reason, "over the") {
		t.Errorf("reason %q must name the size limit", p.Reason)
	}
}

func TestJWTIsALayerThatCannotBeEncodedAndSaysSoAtRunTime(t *testing.T) {
	// It parses as a layer, so this is not a construction error; it is a per-payload refusal
	// carrying the decoder's own message.
	p := one([]RuleSpec{{Rule: "encode", Layer: "jwt"}}, "anything")
	if !p.Dropped {
		t.Fatal("jwt has no inverse")
	}
	if !strings.Contains(p.Reason, "cannot be encoded") {
		t.Errorf("reason %q must carry the decoder's refusal", p.Reason)
	}
}
