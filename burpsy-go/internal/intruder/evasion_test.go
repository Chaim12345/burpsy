package intruder

import (
	"bytes"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/tools"
)

// ---------------------------------------------------------------------------
// User-Agent rotation
// ---------------------------------------------------------------------------

func TestUserAgentPoolRotatesInOrderAndWraps(t *testing.T) {
	pool, err := NewUserAgentPool([]string{"A", "B", "C"})
	if err != nil {
		t.Fatalf("NewUserAgentPool: %v", err)
	}
	got := []string{pool.Next(), pool.Next(), pool.Next(), pool.Next(), pool.Next()}
	want := []string{"A", "B", "C", "A", "B"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("agent %d: got %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestNewUserAgentPoolRefusesEmptyOrAllBlank(t *testing.T) {
	if _, err := NewUserAgentPool(nil); err == nil {
		t.Fatal("expected error for nil pool")
	}
	if _, err := NewUserAgentPool([]string{"", "  "}); err == nil {
		t.Fatal("expected error for all-blank pool")
	}
	if _, err := NewUserAgentPool([]string{"", "real-agent", ""}); err != nil {
		t.Fatalf("expected blanks to be dropped, not refused: %v", err)
	}
}

func TestDefaultUserAgentsIsNonEmptyAndBuildsAPool(t *testing.T) {
	agents := DefaultUserAgents()
	if len(agents) == 0 {
		t.Fatal("DefaultUserAgents returned no agents")
	}
	pool, err := NewUserAgentPool(agents)
	if err != nil {
		t.Fatalf("NewUserAgentPool(DefaultUserAgents()): %v", err)
	}
	if pool.Len() != len(agents) {
		t.Fatalf("pool.Len() = %d, want %d", pool.Len(), len(agents))
	}
}

// ---------------------------------------------------------------------------
// ApplyUserAgent
// ---------------------------------------------------------------------------

func TestApplyUserAgentReplacesExistingHeader(t *testing.T) {
	raw := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: OldAgent/1.0\r\nAccept: */*\r\n\r\n")
	out := ApplyUserAgent(raw, "NewAgent/2.0")
	if !bytes.Contains(out, []byte("User-Agent: NewAgent/2.0")) {
		t.Fatalf("new agent not present: %s", out)
	}
	if bytes.Contains(out, []byte("OldAgent/1.0")) {
		t.Fatalf("old agent still present: %s", out)
	}
	if strings.Count(string(out), "User-Agent:") != 1 {
		t.Fatalf("expected exactly one User-Agent header, got: %s", out)
	}
}

func TestApplyUserAgentInsertsWhenMissing(t *testing.T) {
	raw := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")
	out := ApplyUserAgent(raw, "Agent/1.0")
	if !bytes.Contains(out, []byte("User-Agent: Agent/1.0")) {
		t.Fatalf("agent header not inserted: %s", out)
	}
	if !bytes.HasPrefix(out, []byte("GET /path HTTP/1.1\r\n")) {
		t.Fatalf("request line changed: %s", out)
	}
}

func TestApplyUserAgentIsCaseInsensitiveAndLeavesBodyAlone(t *testing.T) {
	// Deliberately construct a body that contains the literal text of a header line, to prove
	// only the header block is touched.
	raw := []byte("POST /x HTTP/1.1\r\nHost: h\r\nuser-agent: lower/1.0\r\n\r\nfield=User-Agent: fake")
	out := ApplyUserAgent(raw, "Real/1.0")
	if bytes.Contains(out, []byte("lower/1.0")) {
		t.Fatalf("case-insensitive header not replaced: %s", out)
	}
	if !bytes.Contains(out, []byte("field=User-Agent: fake")) {
		t.Fatalf("body was mangled: %s", out)
	}
	if strings.Count(string(out), "User-Agent:") != 2 { // one real header, one in the body text
		t.Fatalf("expected one header + one body occurrence, got: %s", out)
	}
}

func TestApplyUserAgentOnMalformedRequestIsANoOp(t *testing.T) {
	raw := []byte("")
	if out := ApplyUserAgent(raw, "X"); !bytes.Equal(out, raw) {
		t.Fatalf("expected unchanged output for empty input, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// ShuffleHeaders
// ---------------------------------------------------------------------------

func headerSet(raw []byte) []string {
	requestLine, headers, _, _, ok := splitRequest(raw)
	if !ok {
		return nil
	}
	_ = requestLine
	out := make([]string, len(headers))
	for i, h := range headers {
		out[i] = string(h)
	}
	sort.Strings(out)
	return out
}

func TestShuffleHeadersPreservesRequestLineAndBodyAndHeaderSet(t *testing.T) {
	raw := []byte("GET /p HTTP/1.1\r\nHost: h\r\nAccept: */*\r\nX-Custom: 1\r\nCookie: a=b\r\n\r\nbody-bytes")
	rnd := rand.New(rand.NewPCG(1, 1))
	out := ShuffleHeaders(raw, rnd)

	if !bytes.HasPrefix(out, []byte("GET /p HTTP/1.1\r\n")) {
		t.Fatalf("request line changed: %s", out)
	}
	if !bytes.HasSuffix(out, []byte("body-bytes")) {
		t.Fatalf("body changed: %s", out)
	}
	before := headerSet(raw)
	after := headerSet(out)
	if len(before) != len(after) {
		t.Fatalf("header count changed: before=%d after=%d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("header set changed:\nbefore=%v\nafter=%v", before, after)
		}
	}
}

func TestShuffleHeadersIsDeterministicForTheSameSeed(t *testing.T) {
	raw := []byte("GET /p HTTP/1.1\r\nHost: h\r\nAccept: */*\r\nX-Custom: 1\r\nCookie: a=b\r\n\r\n")
	out1 := ShuffleHeaders(raw, rand.New(rand.NewPCG(42, 42)))
	out2 := ShuffleHeaders(raw, rand.New(rand.NewPCG(42, 42)))
	if !bytes.Equal(out1, out2) {
		t.Fatalf("same seed produced different orders:\n%s\n---\n%s", out1, out2)
	}
}

func TestShuffleHeadersActuallyChangesOrderEventually(t *testing.T) {
	raw := []byte("GET /p HTTP/1.1\r\nHost: h\r\nAccept: */*\r\nX-Custom: 1\r\nCookie: a=b\r\nX-Two: 2\r\nX-Three: 3\r\n\r\n")
	changed := false
	for seed := uint64(0); seed < 20; seed++ {
		out := ShuffleHeaders(raw, rand.New(rand.NewPCG(seed, seed)))
		if !bytes.Equal(out, raw) {
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("no seed in range produced a different header order")
	}
}

func TestShuffleHeadersNoOpWithFewerThanTwoHeaders(t *testing.T) {
	raw := []byte("GET /p HTTP/1.1\r\nHost: h\r\n\r\n")
	out := ShuffleHeaders(raw, rand.New(rand.NewPCG(1, 1)))
	if !bytes.Equal(out, raw) {
		t.Fatalf("expected no-op with a single header, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Jitter
// ---------------------------------------------------------------------------

func TestJitterDelayStaysWithinBounds(t *testing.T) {
	j, err := NewJitter(10*time.Millisecond, 50*time.Millisecond, 7)
	if err != nil {
		t.Fatalf("NewJitter: %v", err)
	}
	for i := 0; i < 200; i++ {
		d := j.Delay()
		if d < 10*time.Millisecond || d > 50*time.Millisecond {
			t.Fatalf("delay %s out of bounds [10ms, 50ms]", d)
		}
	}
}

func TestJitterEqualBoundsIsFixedDelay(t *testing.T) {
	j, err := NewJitter(25*time.Millisecond, 25*time.Millisecond, 1)
	if err != nil {
		t.Fatalf("NewJitter: %v", err)
	}
	for i := 0; i < 10; i++ {
		if d := j.Delay(); d != 25*time.Millisecond {
			t.Fatalf("delay = %s, want exactly 25ms", d)
		}
	}
}

func TestJitterRefusesInvalidBounds(t *testing.T) {
	if _, err := NewJitter(-1, 10, 0); err == nil {
		t.Fatal("expected error for negative min")
	}
	if _, err := NewJitter(0, -1, 0); err == nil {
		t.Fatal("expected error for negative max")
	}
	if _, err := NewJitter(50*time.Millisecond, 10*time.Millisecond, 0); err == nil {
		t.Fatal("expected error for min > max")
	}
}

func TestJitterIsDeterministicForTheSameSeed(t *testing.T) {
	j1, _ := NewJitter(0, 100*time.Millisecond, 99)
	j2, _ := NewJitter(0, 100*time.Millisecond, 99)
	for i := 0; i < 20; i++ {
		d1, d2 := j1.Delay(), j2.Delay()
		if d1 != d2 {
			t.Fatalf("draw %d diverged: %s vs %s", i, d1, d2)
		}
	}
}

// ---------------------------------------------------------------------------
// EncodeVariant
// ---------------------------------------------------------------------------

func TestEncodeVariantMatchesToolsLayersDirectly(t *testing.T) {
	payload := []byte("<script>alert(1)</script>&x=1")

	url, err := EncodeVariant(payload, "url")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	wantURL, err := tools.Encode(tools.LayerURL, payload)
	if err != nil {
		t.Fatalf("tools.Encode url: %v", err)
	}
	if !bytes.Equal(url, wantURL) {
		t.Fatalf("url variant = %q, want %q", url, wantURL)
	}

	b64, err := EncodeVariant(payload, "base64")
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	wantB64, _ := tools.Encode(tools.LayerBase64, payload)
	if !bytes.Equal(b64, wantB64) {
		t.Fatalf("base64 variant = %q, want %q", b64, wantB64)
	}

	hexOut, err := EncodeVariant(payload, "hex")
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	wantHex, _ := tools.Encode(tools.LayerHex, payload)
	if !bytes.Equal(hexOut, wantHex) {
		t.Fatalf("hex variant = %q, want %q", hexOut, wantHex)
	}
}

func TestEncodeVariantDoubleURLMatchesTwoChainedEncodeRules(t *testing.T) {
	payload := []byte("a b&c=<d>")

	got, err := EncodeVariant(payload, "double_url")
	if err != nil {
		t.Fatalf("double_url: %v", err)
	}

	// Equivalent to building a processing Chain with two "encode" rules, layer "url" — the
	// mechanism this convenience is documented to be identical to.
	chain, err := NewChain([]RuleSpec{
		{Rule: "encode", Layer: "url"},
		{Rule: "encode", Layer: "url"},
	})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	res := chain.Apply(payload)
	if res.Dropped {
		t.Fatalf("chain dropped payload: %s", res.Reason)
	}
	if !bytes.Equal(got, res.Keep) {
		t.Fatalf("EncodeVariant(double_url) = %q, chain-equivalent = %q", got, res.Keep)
	}

	// And it really is double-encoded: decoding once must still leave a percent-escape behind.
	once, err := tools.Encode(tools.LayerURL, payload)
	if err != nil {
		t.Fatalf("tools.Encode: %v", err)
	}
	if !bytes.Equal(got, mustEncodeURL(t, once)) {
		t.Fatalf("double_url is not two url-encodes back to back")
	}
}

func mustEncodeURL(t *testing.T, in []byte) []byte {
	t.Helper()
	out, err := tools.Encode(tools.LayerURL, in)
	if err != nil {
		t.Fatalf("tools.Encode: %v", err)
	}
	return out
}

func TestEncodeVariantRefusesUnknownVariant(t *testing.T) {
	if _, err := EncodeVariant([]byte("x"), "rot13"); err == nil {
		t.Fatal("expected error for unknown variant")
	}
}

func TestEncodingVariantsListsEveryVariantEncodeVariantAccepts(t *testing.T) {
	for _, v := range EncodingVariants() {
		if _, err := EncodeVariant([]byte("probe"), v); err != nil {
			t.Fatalf("variant %q from EncodingVariants() is rejected by EncodeVariant: %v", v, err)
		}
	}
}

// ---------------------------------------------------------------------------
// WAFEvasion.Wrap
// ---------------------------------------------------------------------------

func TestWAFEvasionWrapAppliesUserAgentAndShufflesHeaders(t *testing.T) {
	pool, err := NewUserAgentPool([]string{"UA-One", "UA-Two"})
	if err != nil {
		t.Fatalf("NewUserAgentPool: %v", err)
	}
	w := NewWAFEvasion(3)
	w.UserAgents = pool
	w.ShuffleHeaderOrder = true

	raw := []byte("GET /p HTTP/1.1\r\nHost: h\r\nAccept: */*\r\nX-A: 1\r\nX-B: 2\r\n\r\n")

	var seen [][]byte
	send := func(r []byte) (Sent, error) {
		cp := append([]byte(nil), r...)
		seen = append(seen, cp)
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\n\r\n")}, nil
	}
	wrapped := w.Wrap(send)

	for i := 0; i < 2; i++ {
		if _, err := wrapped(raw); err != nil {
			t.Fatalf("wrapped send: %v", err)
		}
	}

	if len(seen) != 2 {
		t.Fatalf("expected 2 sends, got %d", len(seen))
	}
	if !bytes.Contains(seen[0], []byte("User-Agent: UA-One")) {
		t.Fatalf("first send missing rotated agent: %s", seen[0])
	}
	if !bytes.Contains(seen[1], []byte("User-Agent: UA-Two")) {
		t.Fatalf("second send missing rotated agent: %s", seen[1])
	}
	// Original bytes must never be mutated by the wrapper.
	if bytes.Contains(raw, []byte("User-Agent:")) {
		t.Fatalf("original raw bytes were mutated: %s", raw)
	}
}

func TestWAFEvasionWrapWithNoTechniquesConfiguredIsAPassthrough(t *testing.T) {
	w := NewWAFEvasion(1)
	raw := []byte("GET /p HTTP/1.1\r\nHost: h\r\n\r\n")
	var gotRaw []byte
	send := func(r []byte) (Sent, error) {
		gotRaw = r
		return Sent{}, nil
	}
	if _, err := w.Wrap(send)(raw); err != nil {
		t.Fatalf("wrapped send: %v", err)
	}
	if !bytes.Equal(gotRaw, raw) {
		t.Fatalf("expected passthrough, got: %s", gotRaw)
	}
}

func TestWAFEvasionWrapAppliesJitterDelay(t *testing.T) {
	jitter, err := NewJitter(20*time.Millisecond, 20*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewJitter: %v", err)
	}
	w := NewWAFEvasion(0)
	w.Jitter = jitter
	send := func(r []byte) (Sent, error) { return Sent{}, nil }
	start := time.Now()
	if _, err := w.Wrap(send)([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")); err != nil {
		t.Fatalf("wrapped send: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("wrapped send returned after %s, want at least the 20ms jitter delay", elapsed)
	}
}
