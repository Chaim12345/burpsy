package graphqlmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubTransport records what was sent and replies from a handler, so wire shape is testable
// without a network.
type stubTransport struct {
	sent    []Request
	handler func(Request) *Response
}

func (s *stubTransport) Do(_ context.Context, req Request) (*Response, error) {
	s.sent = append(s.sent, req)
	if s.handler == nil {
		return &Response{Status: 200, Body: []byte(`{"data":{}}`)}, nil
	}
	return s.handler(req), nil
}

func envelope(data string) *Response {
	return &Response{Status: 200, Body: []byte(`{"data":` + data + `}`)}
}

// ---------- wire shape ----------

func TestJSONEncodingPostsAQueryObject(t *testing.T) {
	st := &stubTransport{}
	c := New("https://api.test/graphql", st)
	if _, err := c.Execute(context.Background(), "{__typename}"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := st.sent[0]
	if got.Method != "POST" || got.Headers["Content-Type"] != "application/json" {
		t.Fatalf("request = %+v, want a JSON POST", got)
	}
	var body map[string]string
	if err := json.Unmarshal(got.Body, &body); err != nil {
		t.Fatalf("body is not a query object: %q", got.Body)
	}
	if body["query"] != "{__typename}" {
		t.Errorf("query = %q", body["query"])
	}
}

// The Python tool stores introspection documents with '+' for spaces and substitutes them
// back before sending. A document sent with literal '+' would be a syntax error.
func TestPlusIsRestoredToSpaceBeforeSending(t *testing.T) {
	st := &stubTransport{}
	c := New("https://api.test/graphql", st)
	if _, err := c.Execute(context.Background(), "query+IntrospectionQuery+{x}"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var body map[string]string
	_ = json.Unmarshal(st.sent[0].Body, &body)
	if strings.Contains(body["query"], "+") {
		t.Fatalf("query still carries '+': %q", body["query"])
	}
	if body["query"] != "query IntrospectionQuery {x}" {
		t.Errorf("query = %q", body["query"])
	}
}

func TestGetEncodingPutsTheQueryInTheURL(t *testing.T) {
	st := &stubTransport{}
	c := New("https://api.test/graphql", st, WithMethod("GET"))
	if _, err := c.Execute(context.Background(), "{a}"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(st.sent[0].URL, "query=") || st.sent[0].Method != "GET" {
		t.Fatalf("request = %+v, want the query in a GET parameter", st.sent[0])
	}
}

func TestFormEncodingUsesUrlencodedBody(t *testing.T) {
	st := &stubTransport{}
	c := New("https://api.test/graphql", st, WithEncoding(EncodingForm))
	if _, err := c.Execute(context.Background(), "{a}"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if ct := st.sent[0].Headers["Content-Type"]; ct != "application/x-www-form-urlencoded" {
		t.Fatalf("content type = %q", ct)
	}
}

// Batching must be a JSON array of query objects. Joining queries with newlines — which the
// Go port does — produces one invalid document, so the attack silently never fires.
func TestBatchingSendsAJSONArrayNotAJoinedDocument(t *testing.T) {
	st := &stubTransport{handler: func(Request) *Response {
		return &Response{Status: 200, Body: []byte(`[{"data":{}},{"data":{}},{"data":{}}]`)}
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.Batch(context.Background(), "{__typename}", 3)
	if err != nil {
		t.Fatalf("Batch: %v", err)
	}
	var arr []map[string]string
	if err := json.Unmarshal(st.sent[0].Body, &arr); err != nil {
		t.Fatalf("batch body is not a JSON array: %q", st.sent[0].Body)
	}
	if len(arr) != 3 {
		t.Fatalf("array has %d entries, want 3", len(arr))
	}
	if !rep.Accepted || rep.Returned != 3 {
		t.Errorf("report = %+v, want 3 accepted", rep)
	}
}

func TestBatchTokenOverridesTheRequestedSize(t *testing.T) {
	st := &stubTransport{handler: func(Request) *Response {
		return &Response{Status: 200, Body: []byte(`[{"data":{}},{"data":{}}]`)}
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.Batch(context.Background(), "BATCHING_2 {__typename}", 5)
	if err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if rep.Requested != 2 {
		t.Fatalf("Requested = %d, want the token's 2", rep.Requested)
	}
	var arr []map[string]string
	_ = json.Unmarshal(st.sent[0].Body, &arr)
	if len(arr) != 2 || strings.Contains(arr[0]["query"], TokenBatching) {
		t.Errorf("token leaked into the sent query: %+v", arr)
	}
}

// A backend that ignores batching returns one envelope, which must not read as accepted.
func TestBatchingNotAcceptedWhenFewerEnvelopesComeBack(t *testing.T) {
	st := &stubTransport{handler: func(Request) *Response {
		return &Response{Status: 200, Body: []byte(`{"data":{}}`)}
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.Batch(context.Background(), "{__typename}", 4)
	if err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if rep.Accepted {
		t.Fatalf("report = %+v, want not accepted", rep)
	}
}

// ---------- fuzzing baseline ----------

// The baseline must be the untouched query. The Go port compares every payload against the
// *first payload's* response, so a uniformly odd first payload skews everything after it.
func TestFuzzCaptureesACleanBaselineBeforeAnyPayload(t *testing.T) {
	var seen []string
	st := &stubTransport{handler: func(r Request) *Response {
		var b map[string]string
		_ = json.Unmarshal(r.Body, &b)
		seen = append(seen, b["query"])
		return envelope(`{"n":1}`)
	}}
	c := New("https://api.test/graphql", st)
	if _, err := c.FuzzCharset(context.Background(), `{u(x:"aGRAPHQL_CHARSET")}`, "ab"); err != nil {
		t.Fatalf("FuzzCharset: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("sent %d queries, want 1 baseline + 2 payloads: %v", len(seen), seen)
	}
	if strings.Contains(seen[0], TokenCharset) || seen[0] != `{u(x:"a")}` {
		t.Errorf("first request %q is not the placeholder-free baseline", seen[0])
	}
}

func TestFuzzCharsetMarksOnlyResponsesThatMoveFromBaseline(t *testing.T) {
	st := &stubTransport{handler: func(r Request) *Response {
		var b map[string]string
		_ = json.Unmarshal(r.Body, &b)
		if strings.Contains(b["query"], `"a*"`) {
			return envelope(`{"hit":"` + strings.Repeat("x", 200) + `"}`)
		}
		return envelope(`{}`)
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.FuzzCharset(context.Background(), `{u(x:"aGRAPHQL_CHARSET")}`, "*b")
	if err != nil {
		t.Fatalf("FuzzCharset: %v", err)
	}
	if len(rep.Interesting) != 1 || rep.Interesting[0].Input != "*" {
		t.Fatalf("interesting = %+v, want only the '*' result", rep.Interesting)
	}
}

func TestFuzzIncrementReadsTheBoundFromTheToken(t *testing.T) {
	st := &stubTransport{handler: func(Request) *Response { return envelope(`{}`) }}
	c := New("https://api.test/graphql", st)
	rep, err := c.FuzzIncrement(context.Background(), `{p(id:"GRAPHQL_INCREMENT_4")}`, 0)
	if err != nil {
		t.Fatalf("FuzzIncrement: %v", err)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("got %d results, want 4 from the token bound", len(rep.Results))
	}
	if rep.Results[0].Input != "0" || rep.Results[3].Input != "3" {
		t.Errorf("inputs = %q..%q, want 0..3", rep.Results[0].Input, rep.Results[3].Input)
	}
}

func TestFuzzRequiresItsPlaceholder(t *testing.T) {
	c := New("https://api.test/graphql", &stubTransport{})
	if _, err := c.FuzzCharset(context.Background(), "{a}", "ab"); err == nil {
		t.Error("FuzzCharset accepted a query with no placeholder")
	}
	if _, err := c.FuzzIncrement(context.Background(), "{a}", 3); err == nil {
		t.Error("FuzzIncrement accepted a query with no placeholder")
	}
}

// A failed send is neither clean nor interesting; it must be counted.
func TestFuzzCountsUnsentProbesSeparately(t *testing.T) {
	calls := 0
	st := &stubTransport{handler: func(Request) *Response {
		calls++
		if calls == 1 {
			return envelope(`{}`) // baseline succeeds
		}
		return nil
	}}
	c := New("https://api.test/graphql", TransportFunc(func(ctx context.Context, r Request) (*Response, error) {
		res, _ := st.Do(ctx, r)
		if res == nil {
			return nil, fmt.Errorf("connection refused")
		}
		return res, nil
	}))
	rep, err := c.FuzzCharset(context.Background(), `{u(x:"GRAPHQL_CHARSET")}`, "ab")
	if err != nil {
		t.Fatalf("FuzzCharset: %v", err)
	}
	if rep.Unsent != 2 {
		t.Fatalf("Unsent = %d, want 2", rep.Unsent)
	}
	if len(rep.Interesting) != 0 {
		t.Errorf("unsent probes were reported as interesting: %+v", rep.Interesting)
	}
}

// Every verdict FuzzCharset reaches is "this response differs from the baseline". With no
// baseline there is nothing to differ from, so a substituted empty one would make the first
// probe the reference and silently reclassify everything after it. The failure must surface
// as an error rather than as a report full of confident comparisons against nothing.
func TestFuzzRefusesToRunWithoutABaseline(t *testing.T) {
	calls := 0
	c := New("https://api.test/graphql", TransportFunc(func(context.Context, Request) (*Response, error) {
		calls++
		return nil, fmt.Errorf("connection refused")
	}))

	rep, err := c.FuzzCharset(context.Background(), `{u(x:"GRAPHQL_CHARSET")}`, "ab")
	if err == nil {
		t.Fatalf("FuzzCharset returned a report with no baseline to compare against: %+v", rep)
	}
	if rep != nil {
		t.Errorf("a failed baseline still produced a report: %+v", rep)
	}
	// It must give up on the baseline, not carry on probing the charset regardless.
	if calls != 1 {
		t.Errorf("sent %d requests after the baseline failed, want 1", calls)
	}
}

// ---------- blind extraction ----------

// The Python original has no break in its charset loop, so every matching character is
// appended in one pass. Extracting "ba" from a charset of "ab" would yield "ab".
func TestBlindExtractStopsAtTheFirstMatchPerPosition(t *testing.T) {
	const secret = "ba"
	var tried []string
	st := &stubTransport{handler: func(r Request) *Response {
		var b map[string]string
		_ = json.Unmarshal(r.Body, &b)
		// Recover the tried prefix: it sits between `^` and the escaped closing quote.
		// Cutting at a bare `"` would keep the escape backslash and never match.
		start := strings.Index(b["query"], "^")
		if start < 0 {
			return envelope(`{}`)
		}
		rest := b["query"][start+1:]
		end := strings.Index(rest, `\"`)
		if end < 0 {
			return envelope(`{}`)
		}
		tried = append(tried, rest[:end])
		if strings.HasPrefix(secret, rest[:end]) {
			return &Response{Status: 200, Body: []byte(`{"data":{"id":"MATCHED"}}`)}
		}
		return envelope(`{}`)
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.BlindExtract(context.Background(), ExtractSpec{
		Query:   `{d(search:"{\"n\":{\"$regex\":\"^BLIND_PLACEHOLDER\"}}"){id}}`,
		Check:   "MATCHED",
		Charset: "ab",
	})
	if err != nil {
		t.Fatalf("BlindExtract: %v", err)
	}
	if rep.Value != secret {
		t.Fatalf("extracted %q, want %q; appending every charset match per pass is the bug this fixes", rep.Value, secret)
	}
	if !rep.Complete {
		t.Error("extraction did not report completion")
	}
	// A prefix oracle converges on the same string either way, so the value alone does not
	// prove the walk stopped at the first match — the *sequence* does. Once a position has
	// matched, the remaining charset characters for that position must not be probed.
	want := []string{"a", "b", "ba", "baa", "bab"}
	if len(tried) != len(want) {
		t.Fatalf("probed %v (%d requests), want %v (%d); a missing break keeps scanning a position that already matched", tried, len(tried), want, len(want))
	}
	for i := range want {
		if tried[i] != want[i] {
			t.Fatalf("probe %d was %q, want %q (full sequence %v)", i, tried[i], want[i], tried)
		}
	}
	if rep.Requests != len(want) {
		t.Errorf("Requests = %d, want %d; the counter must agree with the probes actually sent", rep.Requests, len(want))
	}
}

func TestBlindExtractRequiresACheckString(t *testing.T) {
	c := New("https://api.test/graphql", &stubTransport{})
	_, err := c.BlindExtract(context.Background(), ExtractSpec{Query: "{a(b:\"BLIND_PLACEHOLDER\")}"})
	if err == nil {
		t.Fatal("BlindExtract accepted an empty check string; every response would look like a match")
	}
}

// A value longer than the budget must be reported as a prefix, not as the whole secret.
func TestBlindExtractReportsTruncation(t *testing.T) {
	st := &stubTransport{handler: func(Request) *Response {
		return &Response{Status: 200, Body: []byte(`{"data":{"id":"MATCHED"}}`)}
	}}
	c := New("https://api.test/graphql", st, WithMaxExtract(4))
	rep, err := c.BlindExtract(context.Background(), ExtractSpec{
		Query: "{a(b:\"BLIND_PLACEHOLDER\")}", Check: "MATCHED", Charset: "a"})
	if err != nil {
		t.Fatalf("BlindExtract: %v", err)
	}
	if !rep.Truncated || len(rep.Value) != 4 {
		t.Fatalf("report = %+v, want a truncated 4-character prefix", rep)
	}
	if rep.Complete {
		t.Error("a truncated extraction reported completion")
	}
}

// ---------- timing ----------

func TestTimingPayloadsMatchTheOriginalShapes(t *testing.T) {
	for _, tc := range []struct {
		d    Dialect
		want string
	}{
		{PostgreSQL, "1 AND pg_sleep(5) --"},
		{MySQL, "'-SLEEP(5); #"},
		{MSSQL, "'; WAITFOR DELAY '00:00:05';"},
	} {
		got, err := TimingPayload(tc.d, 5*time.Second)
		if err != nil {
			t.Fatalf("%s: %v", tc.d, err)
		}
		if got != tc.want {
			t.Errorf("%s payload = %q, want %q", tc.d, got, tc.want)
		}
	}
	if _, err := TimingPayload("oracle", time.Second); err == nil {
		t.Error("an unknown dialect was accepted")
	}
}

func TestTimingProbeObservesADelayAgainstBaseline(t *testing.T) {
	st := &stubTransport{handler: func(r Request) *Response {
		var b map[string]string
		_ = json.Unmarshal(r.Body, &b)
		if strings.Contains(b["query"], "pg_sleep") {
			return &Response{Status: 200, Body: []byte(`{"data":{}}`), Duration: 5 * time.Second}
		}
		return &Response{Status: 200, Body: []byte(`{"data":{}}`), Duration: 20 * time.Millisecond}
	}}
	c := New("https://api.test/graphql", st, WithTimingDelay(5*time.Second))
	rep, err := c.TimingProbe(context.Background(), `{u(id:"BLIND_PLACEHOLDER")}`, PostgreSQL)
	if err != nil {
		t.Fatalf("TimingProbe: %v", err)
	}
	if rep.Verdict != TimingDelayObserved {
		t.Fatalf("verdict = %v, want a delay", rep.Verdict)
	}
}

// A uniformly slow endpoint must be inconclusive, never a finding. The Python original prints
// two timestamps and leaves this judgement to the reader.
func TestTimingProbeIsInconclusiveOnASlowEndpoint(t *testing.T) {
	st := &stubTransport{handler: func(Request) *Response {
		return &Response{Status: 200, Body: []byte(`{"data":{}}`), Duration: 4 * time.Second}
	}}
	c := New("https://api.test/graphql", st, WithTimingDelay(5*time.Second))
	rep, err := c.TimingProbe(context.Background(), `{u(id:"BLIND_PLACEHOLDER")}`, PostgreSQL)
	if err != nil {
		t.Fatalf("TimingProbe: %v", err)
	}
	if rep.Verdict != TimingInconclusive {
		t.Fatalf("verdict = %v, want inconclusive", rep.Verdict)
	}
}

func TestTimingProbeReportsNoDelayOnAPromptEndpoint(t *testing.T) {
	st := &stubTransport{handler: func(Request) *Response {
		return &Response{Status: 200, Body: []byte(`{"data":{}}`), Duration: 5 * time.Millisecond}
	}}
	c := New("https://api.test/graphql", st, WithTimingDelay(5*time.Second))
	rep, _ := c.TimingProbe(context.Background(), `{u(id:"BLIND_PLACEHOLDER")}`, MySQL)
	if rep.Verdict != TimingNoDelay {
		t.Fatalf("verdict = %v, want no delay", rep.Verdict)
	}
}

// ---------- error sweep ----------

func TestSweepErrorsReportsIntroducedSignaturesOnly(t *testing.T) {
	st := &stubTransport{handler: func(r Request) *Response {
		var b map[string]string
		_ = json.Unmarshal(r.Body, &b)
		if strings.Contains(b["query"], `'`) {
			return &Response{Status: 200, Body: []byte(`{"errors":[{"message":"You have an error in your SQL syntax"}]}`)}
		}
		return envelope(`{}`)
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.SweepErrors(context.Background(), `{u(id:"BLIND_PLACEHOLDER")}`, nil)
	if err != nil {
		t.Fatalf("SweepErrors: %v", err)
	}
	if len(rep.Confirmed()) == 0 {
		t.Fatal("an introduced SQL error was not reported")
	}
}

// An endpoint that always emits the signature proves nothing.
func TestSweepErrorsIsInconclusiveWhenTheBaselineAlreadyErrors(t *testing.T) {
	st := &stubTransport{handler: func(Request) *Response {
		return &Response{Status: 200, Body: []byte(`{"errors":[{"message":"You have an error in your SQL syntax"}]}`)}
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.SweepErrors(context.Background(), `{u(id:"BLIND_PLACEHOLDER")}`, nil)
	if err != nil {
		t.Fatalf("SweepErrors: %v", err)
	}
	if len(rep.Confirmed()) != 0 {
		t.Fatalf("an always-erroring endpoint produced %d confirmations", len(rep.Confirmed()))
	}
	if rep.Inconclusive == 0 {
		t.Error("the pre-existing signature was dropped instead of reported as inconclusive")
	}
}

// ---------- boolean sweep ----------

func TestSweepBooleanNeedsBothHalves(t *testing.T) {
	st := &stubTransport{handler: func(r Request) *Response {
		var b map[string]string
		_ = json.Unmarshal(r.Body, &b)
		if strings.Contains(b["query"], "1=2") || strings.Contains(b["query"], `'1'='2`) {
			return envelope(`{}`)
		}
		return envelope(`{"u":{"name":"admin-and-plenty-more-content"}}`)
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.SweepBoolean(context.Background(), `{u(id:"BLIND_PLACEHOLDER")}`, PostgreSQL)
	if err != nil {
		t.Fatalf("SweepBoolean: %v", err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Kind == FindingBooleanDifferential {
			found = true
		}
	}
	if !found {
		t.Fatalf("no boolean differential reported: %+v", rep.Findings)
	}
}

func TestSweepBooleanIsInconclusiveWhenBothConditionsChange(t *testing.T) {
	calls := 0
	st := &stubTransport{handler: func(Request) *Response {
		calls++
		if calls == 1 {
			return envelope(`{"baseline":"x"}`)
		}
		return envelope(`{"rejected":"` + strings.Repeat("y", 100) + `"}`)
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.SweepBoolean(context.Background(), `{u(id:"BLIND_PLACEHOLDER")}`, MySQL)
	if err != nil {
		t.Fatalf("SweepBoolean: %v", err)
	}
	if len(rep.Confirmed()) != 0 {
		t.Errorf("both-changed was reported as a finding: %+v", rep.Confirmed())
	}
	if rep.Inconclusive == 0 {
		t.Error("both-changed was not counted as inconclusive")
	}
}

// ---------- schema ----------

const introspectionPayload = `{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutations"},
 "types":[
  {"kind":"OBJECT","name":"Query","fields":[
     {"name":"doctor","args":[{"name":"email","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"String"}}}],"type":{"kind":"OBJECT","name":"Doctor"}}]},
  {"kind":"OBJECT","name":"Mutations","fields":[
     {"name":"importPaste","args":[
        {"name":"host","type":{"kind":"SCALAR","name":"String"}},
        {"name":"port","type":{"kind":"SCALAR","name":"Int"}}],"type":{"kind":"OBJECT","name":"Result"}}]},
  {"kind":"OBJECT","name":"__Type","fields":[{"name":"hidden","args":[],"type":{"kind":"SCALAR","name":"String"}}]}
 ]}}`

func TestParseSchemaReadsTypesAndUnwrapsNonNull(t *testing.T) {
	s, err := ParseSchema(json.RawMessage(introspectionPayload))
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}
	if s.QueryType != "Query" || s.MutationType != "Mutations" {
		t.Errorf("root types = %q/%q", s.QueryType, s.MutationType)
	}
	args := s.StringArguments()
	if len(args) == 0 {
		t.Fatal("no String arguments found; NON_NULL wrapping was not unwrapped")
	}
	var sawEmail bool
	for _, a := range args {
		if a.Argument == "email" && a.TypeName == "String" {
			sawEmail = true
		}
	}
	if !sawEmail {
		t.Errorf("the NON_NULL(String) email argument was not recognised: %+v", args)
	}
}

// Introspection's own __-prefixed types are not application surface.
func TestObjectTypesExcludeIntrospectionMeta(t *testing.T) {
	s, _ := ParseSchema(json.RawMessage(introspectionPayload))
	for _, tp := range s.ObjectTypes() {
		if strings.HasPrefix(tp.Name, "__") {
			t.Errorf("meta type %q leaked into the application surface", tp.Name)
		}
	}
}

func TestMutationTemplatesSubstituteScalarLiterals(t *testing.T) {
	s, _ := ParseSchema(json.RawMessage(introspectionPayload))
	tmpl := s.MutationTemplates()
	if len(tmpl) != 1 {
		t.Fatalf("got %d templates, want 1: %v", len(tmpl), tmpl)
	}
	if !strings.Contains(tmpl[0], `host:"string"`) || !strings.Contains(tmpl[0], "port:1") {
		t.Errorf("template did not substitute scalar literals: %q", tmpl[0])
	}
}

func TestParseSchemaRejectsAnEmptyOrTypelessDocument(t *testing.T) {
	if _, err := ParseSchema(nil); err == nil {
		t.Error("nil data parsed as a schema")
	}
	if _, err := ParseSchema(json.RawMessage(`{"__schema":{"types":[]}}`)); err == nil {
		t.Error("a schema with no types parsed cleanly")
	}
}

// A server that rejects the modern document but answers the legacy one has introspection on;
// giving up after the first would report it as off.
func TestIntrospectFallsBackToTheLegacyDocument(t *testing.T) {
	var docs []string
	st := &stubTransport{handler: func(r Request) *Response {
		var b map[string]string
		_ = json.Unmarshal(r.Body, &b)
		docs = append(docs, b["query"])
		if strings.HasPrefix(b["query"], "query IntrospectionQuery") {
			return &Response{Status: 200, Body: []byte(`{"errors":[{"message":"unknown"}]}`)}
		}
		return &Response{Status: 200, Body: []byte(`{"data":` + introspectionPayload + `}`)}
	}}
	c := New("https://api.test/graphql", st)
	s, err := c.Introspect(context.Background())
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if s.Document != "legacy" {
		t.Errorf("Document = %q, want legacy", s.Document)
	}
	if len(docs) != 2 {
		t.Errorf("tried %d documents, want both", len(docs))
	}
}

func TestFieldSuggestionsAreExtractedFromErrorProse(t *testing.T) {
	got := FieldSuggestions([]string{
		`Cannot query field "pastes" on type "Query". Did you mean "paste" or "pasteCount"?`,
	})
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "paste") || !strings.Contains(joined, "pasteCount") {
		t.Fatalf("suggestions = %v, want the two field names", got)
	}
}

func TestFieldSuggestionsIgnoresUnrelatedErrors(t *testing.T) {
	if got := FieldSuggestions([]string{"Syntax Error: Unexpected <EOF>"}); len(got) != 0 {
		t.Fatalf("suggestions = %v, want none", got)
	}
}

func TestIsGraphQLEnvelopeDistinguishesAnEndpointFromA404(t *testing.T) {
	if !IsGraphQLEnvelope([]byte(`{"data":{"a":1}}`)) {
		t.Error("a data envelope was not recognised")
	}
	if !IsGraphQLEnvelope([]byte(`{"errors":[{"message":"x"}]}`)) {
		t.Error("an errors envelope was not recognised")
	}
	if IsGraphQLEnvelope([]byte(`<html>404</html>`)) {
		t.Error("an HTML page was treated as a GraphQL envelope")
	}
	if IsGraphQLEnvelope([]byte(`{"ok":true}`)) {
		t.Error("an unrelated JSON object was treated as a GraphQL envelope")
	}
}

// ---------- transport and audit ----------

func TestHTTPTransportRoundTripsAgainstARealServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()

	tr, err := NewHTTPTransport(HTTPTransportOptions{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPTransport: %v", err)
	}
	c := New(srv.URL, tr)
	res, err := c.Execute(context.Background(), "{__typename}")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Status != 200 || !strings.Contains(string(res.Data), "Query") {
		t.Fatalf("response = %+v", res)
	}
	if res.Duration <= 0 {
		t.Error("no duration was measured; timing probes depend on it")
	}
}

func TestAuditReportsIntrospectionSuggestionsAndBatching(t *testing.T) {
	st := &stubTransport{handler: func(r Request) *Response {
		var single map[string]string
		if err := json.Unmarshal(r.Body, &single); err == nil {
			switch {
			case strings.Contains(single["query"], "IntrospectionQuery"):
				return &Response{Status: 200, Body: []byte(`{"data":` + introspectionPayload + `}`)}
			case strings.Contains(single["query"], "bsyNoSuchField"):
				return &Response{Status: 200, Body: []byte(
					`{"errors":[{"message":"Cannot query field \"bsyNoSuchField\" on type \"Query\". Did you mean \"doctor\"?"}]}`)}
			}
			return envelope(`{}`)
		}
		return &Response{Status: 200, Body: []byte(`[{"data":{}},{"data":{}}]`)}
	}}
	c := New("https://api.test/graphql", st)
	rep, err := c.Audit(context.Background(), 2)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !rep.IntrospectionEnabled || rep.Schema == nil {
		t.Error("introspection was not reported")
	}
	if len(rep.Suggestions) == 0 {
		t.Error("field suggestions were not reported")
	}
	if rep.Batching == nil || !rep.Batching.Accepted {
		t.Errorf("batching was not reported: %+v", rep.Batching)
	}
	if len(rep.Findings) < 3 {
		t.Errorf("findings = %d, want introspection + suggestions + batching", len(rep.Findings))
	}
}

func TestNoTransportIsAnErrorNotAPanic(t *testing.T) {
	c := New("https://api.test/graphql", nil)
	if _, err := c.Execute(context.Background(), "{a}"); err == nil {
		t.Fatal("Execute with no transport returned no error")
	}
}
