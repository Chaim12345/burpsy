package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What word granularity actually changes, stated as the thing it is: hunk boundaries fall on word
// boundaries, so the console's highlight reads as "this word changed" rather than "these bytes did".
//
// It is NOT "fewer changed bytes". Byte-level Myers already aligns and already trims the shared
// prefix and suffix, so on a one-word change it is nearly as compact — and on this fixture it is
// more compact, because it finds the shared `a` inside `alpha`/`bravo` and reports four bytes. The
// honest difference is where the boundary lands: `lpha` is not a word, and an operator reading the
// A column of a word-level diff should never be shown half of one.
func TestWordOpsStartOnWordBoundariesWhereByteOpsNeedNot(t *testing.T) {
	a := []byte(`x="alpha"`)
	b := []byte(`x="bravo"`)

	boundaries := map[int]bool{0: true, len(a): true}
	for _, w := range tokeniseWords(a) {
		boundaries[w.start] = true
		boundaries[w.end] = true
	}

	byteDiff := diffBytes(a, b)
	byteSplitAWord := false
	for _, op := range byteDiff.Ops {
		if op.Kind == "equal" {
			continue
		}
		if !boundaries[op.AOffset] || !boundaries[op.AOffset+op.ALen] {
			byteSplitAWord = true
		}
	}
	if !byteSplitAWord {
		t.Fatalf("byte diff of %q against %q cut on word boundaries (%s), so this fixture cannot show the difference between the modes",
			a, b, describeOps(byteDiff.Ops))
	}

	wordDiff := diffWords(a, b)
	for _, op := range wordDiff.Ops {
		if op.Kind == "equal" {
			continue
		}
		if !boundaries[op.AOffset] || !boundaries[op.AOffset+op.ALen] {
			t.Errorf("word-mode op %s starts or ends inside a word; the whole point of the mode is that it does not", describeOp(op))
		}
		if got := string(a[op.AOffset : op.AOffset+op.ALen]); got != "alpha" {
			t.Errorf("A side of the difference is %q, want the whole word %q", got, "alpha")
		}
		if got := string(b[op.BOffset : op.BOffset+op.BLen]); got != "bravo" {
			t.Errorf("B side of the difference is %q, want the whole word %q", got, "bravo")
		}
	}
}

// describeOp renders one op for a failure message.
func describeOp(op compareOp) string {
	return fmt.Sprintf("%s(a=%d+%d b=%d+%d)", op.Kind, op.AOffset, op.ALen, op.BOffset, op.BLen)
}

// Token offsets must tile the input: every byte belongs to exactly one token, in order. The console
// highlights byte ranges built from these offsets, so a gap or an overlap would highlight the wrong
// text — and it would do it only for inputs whose shape the fixtures happen not to cover.
func TestTokensTileTheirInput(t *testing.T) {
	for _, in := range []string{
		"", "a", "hello world", "  \r\n\t ", `{"a":1,"b":[2,3]}`,
		"line\r\nline2", "héllo wörld", strings.Repeat("x", 40) + "." + strings.Repeat("y", 40),
	} {
		words := tokeniseWords([]byte(in))
		var rebuilt strings.Builder
		prevEnd := 0
		for _, w := range words {
			if w.start != prevEnd {
				t.Errorf("input %q: token at %d..%d leaves a gap or overlap after %d", in, w.start, w.end, prevEnd)
			}
			if w.text != in[w.start:w.end] {
				t.Errorf("input %q: token text %q does not match its own range %d..%d", in, w.text, w.start, w.end)
			}
			prevEnd = w.end
			rebuilt.WriteString(w.text)
		}
		if rebuilt.String() != in {
			t.Errorf("input %q: tokens rebuilt %q", in, rebuilt.String())
		}
	}
}

// Identical inputs are one equal op in both modes: the console's "identical" check looks for exactly
// that, so a mode that reported several equal ops would make two equal files look different.
func TestWordDiffOfIdenticalInputsIsOneEqualOp(t *testing.T) {
	for _, in := range []string{"", "x", "hello world", "<a href=\"/x\">text</a>", strings.Repeat("word ", 200)} {
		got := diffWords([]byte(in), []byte(in))
		if len(got.Ops) != 1 || got.Ops[0].Kind != "equal" {
			t.Errorf("input len %d: ops = %s, want exactly one equal", len(in), describeOps(got.Ops))
		}
	}
}

// A word that is inserted whole is an insert of that word, not a replace of the tail — the case
// operators hit constantly when a response grows.
func TestAWordInsertedMidLineIsAnInsert(t *testing.T) {
	a := []byte("one two three")
	b := []byte("one two NEW three")
	got := diffWords(a, b)
	var kinds []string
	for _, op := range got.Ops {
		kinds = append(kinds, op.Kind)
	}
	if strings.Join(kinds, ",") == strings.Repeat("replace", len(kinds)) {
		t.Fatalf("every op is a replace: %s", describeOps(got.Ops))
	}
	inserted := ""
	for _, op := range got.Ops {
		if op.Kind == "insert" {
			inserted += string(b[op.BOffset : op.BOffset+op.BLen])
		}
	}
	if inserted != "NEW " {
		t.Errorf("inserted %q, want %q (the word and its trailing space, as the tokens fall)", inserted, "NEW ")
	}
}

// Punctuation aligns one character at a time, which is what keeps `a` against `b` a one-character
// difference instead of a rewritten attribute.
func TestPunctuationIsNotSwallowedIntoAWord(t *testing.T) {
	words := tokeniseWords([]byte(`x="a"`))
	var texts []string
	for _, w := range words {
		texts = append(texts, w.text)
	}
	want := []string{"x", "=", `"`, "a", `"`}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("tokens = %v, want %v", texts, want)
	}
}

// Word mode through the endpoint, and the unit its counters are in. Burp's Comparer counts *tokens*;
// a word-level run that reported byte lengths under that name would tell an operator "5 tokens" for
// one deleted word, which is the kind of number nobody can check.
//
// Note what a *replacement* is worth here: nothing, in either counter. The endpoint's counters are
// deletes and inserts only — a replace is reported as its own op and the console counts it separately
// — so a one-word substitution legitimately reads deleted=0 inserted=0. That is pre-existing
// semantics, checked here so the word mode cannot quietly change what the numbers mean.
func TestTheEndpointReportsWordCountsForAWordComparison(t *testing.T) {
	ts := newTestServer()

	post := func(payload map[string]any) (struct {
		Granularity    string        `json:"granularity"`
		DeletedTokens  int           `json:"deleted_tokens"`
		InsertedTokens int           `json:"inserted_tokens"`
		Ops            []compareOpJS `json:"ops"`
	}, int) {
		var out struct {
			Granularity    string        `json:"granularity"`
			DeletedTokens  int           `json:"deleted_tokens"`
			InsertedTokens int           `json:"inserted_tokens"`
			Ops            []compareOpJS `json:"ops"`
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/tools/compare", strings.NewReader(string(body)))
		rec := httptest.NewRecorder()
		ts.mux.ServeHTTP(rec, req)
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
		}
		return out, rec.Code
	}

	// A deleted word: one token, five bytes.
	out, code := post(map[string]any{"a": `{"user":"alpha"}`, "b": `{"user":""}`, "granularity": "words"})
	if code != http.StatusOK {
		t.Fatalf("POST = %d", code)
	}
	if out.Granularity != "words" {
		t.Errorf("granularity echoed as %q; the console cannot label a result whose mode it is not told", out.Granularity)
	}
	if out.DeletedTokens != 1 {
		t.Errorf("deleted_tokens = %d for one deleted word, want 1 — in word mode the counters are tokens, not bytes",
			out.DeletedTokens)
	}

	// A substituted word: a replace, so the byte-length and token-count readings would be 5 either
	// way; the point is that the op covers the whole word rather than the four bytes a byte-level
	// alignment picks out of `alpha` against `bravo`.
	out, _ = post(map[string]any{"a": `{"user":"alpha"}`, "b": `{"user":"bravo"}`, "granularity": "words"})
	var replaced bool
	for _, op := range out.Ops {
		if op.Kind == "replace" {
			replaced = true
			if op.ALen != len("alpha") || op.BLen != len("bravo") {
				t.Errorf("replace covers a=%d b=%d bytes, want %d and %d: the op should be the whole word",
					op.ALen, op.BLen, len("alpha"), len("bravo"))
			}
		}
	}
	if !replaced {
		t.Errorf("no replace op for a substituted word; ops were %v", out.Ops)
	}
	if out.DeletedTokens != 0 || out.InsertedTokens != 0 {
		t.Errorf("a substitution reported deleted=%d inserted=%d; those counters are deletes and inserts only, and a replace is neither",
			out.DeletedTokens, out.InsertedTokens)
	}
}

// The byte mode is unchanged for a client that says nothing — including its counters, which stay
// byte lengths. Named because the two modes share this field and the meaning depends on the mode.
func TestTheEndpointStaysByteLevelWhenNoGranularityIsSent(t *testing.T) {
	ts := newTestServer()
	body, _ := json.Marshal(map[string]any{"a": `x="alpha"`, "b": `x="bravo"`})
	req := httptest.NewRequest(http.MethodPost, "/api/tools/compare", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	var out struct {
		Granularity   string `json:"granularity"`
		DeletedTokens int    `json:"deleted_tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Granularity != "bytes" {
		t.Errorf("granularity = %q, want bytes for a client that sent none", out.Granularity)
	}
	if out.DeletedTokens == 1 {
		t.Error("deleted_tokens = 1 for a byte-level comparison; the counters must stay in the unit of the mode that ran")
	}
}

// An unknown granularity is refused rather than quietly served as bytes: an operator who asked for
// words must not be handed a byte diff that claims to be one.
func TestAnUnknownGranularityIsRefused(t *testing.T) {
	ts := newTestServer()
	body, _ := json.Marshal(map[string]any{"a": "x", "b": "y", "granularity": "paragraphs"})
	req := httptest.NewRequest(http.MethodPost, "/api/tools/compare", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST with granularity=paragraphs = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "paragraphs") {
		t.Errorf("refusal does not quote the value it refused: %s", rec.Body.String())
	}
}
