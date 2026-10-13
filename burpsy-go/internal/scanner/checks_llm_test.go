package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// The LLM prompt injection check (burpsy-react-ui-0vzb.18) against vulnapp's LLM family, whose
// "models" are deterministic stand-ins. Each safe twin is kept quiet by a named guard, and the trace
// shows that guard decided it (not a parameter that was never probed):
//
//   - /llm/safe/summary, /llm/safe/echo, /llm/safe/fixed, /helpdesk/safe/reply and the echoing
//     stream: probed, and no answer carries the transformed canary (an echo carries only its operands);
//   - /llm/safe/textutil: every probe answer carries the evidence, and so does its instruction-free
//     control;
//   - /llm/safe/support/contact: a POST that messages staff gets no request at all.

func llmAudit(t *testing.T, path string) ([]*Finding, uint32) {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckLLMPromptInjection: true}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	return findings, outcome.RequestsSent
}

func llmFindingIn(fs []*Finding) *Finding {
	for _, f := range fs {
		if f != nil && f.Name == IssueLLMPromptInjection {
			return f
		}
	}
	return nil
}

// llmTraced audits path with the trace hook on and returns every probed parameter's attempts.
func llmTraced(t *testing.T, path string) ([]*Finding, uint32, map[string][]llmAttempt) {
	t.Helper()
	var mu sync.Mutex
	got := map[string][]llmAttempt{}
	route, _, _ := strings.Cut(path, "?")
	llmTrace = func(target, param string, attempts []llmAttempt) {
		if !strings.Contains(target, route) {
			return
		}
		mu.Lock()
		got[param] = attempts
		mu.Unlock()
	}
	defer func() { llmTrace = nil }()
	fs, sent := llmAudit(t, path)
	mu.Lock()
	defer mu.Unlock()
	return fs, sent, got
}

func TestLLMPromptInjectionFindsEachModel(t *testing.T) {
	cases := []struct {
		path, param string
		mustSay     []string
	}{
		{"/llm/chat?prompt=What+are+your+opening+hours", "prompt", []string{
			"says it carries a prompt", "2 of 2 attempts held", "reverse a random word"}},
		// The streamed model cannot reverse: sum, reverse (not followed), sum.
		{"/llm/v1/chat/completions", "", []string{
			"answers with a stream", "2 of 3 attempts held", "Found in the stream of the answer",
			"not followed"}},
		{"/helpdesk/reply?text=How+do+I+return+a+damaged+item", "text", []string{
			"natural language and the answer is prose", "2 of 2 attempts held"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, sent := llmAudit(t, c.path)
			f := llmFindingIn(fs)
			if f == nil {
				t.Fatalf("no LLM prompt injection finding (%d requests sent)", sent)
			}
			if c.param != "" && f.Param != c.param || f.Confidence != "firm" {
				t.Fatalf("got %s on %q, want firm on %q\n%s", f.Confidence, f.Param, c.param, f.Evidence)
			}
			t.Logf("%d requests, param %q\n%s\n%s", sent, f.Param, f.Description, f.Evidence)
			for _, s := range c.mustSay {
				if !strings.Contains(f.Evidence, s) {
					t.Errorf("evidence lacks %q:\n%s", s, f.Evidence)
				}
			}
			if !strings.Contains(f.Param, "content") && c.param == "" {
				t.Errorf("the chat body's user message was not the parameter probed: %q", f.Param)
			}
			if max := uint32(llmMaxPoints*2*llmAttempts + 4); sent > max {
				t.Errorf("sent %d requests, over the check's budget %d", sent, max)
			}
		})
	}
}

func TestLLMPromptInjectionStaysQuietOnTheSafeTwins(t *testing.T) {
	noEvidence := func(t *testing.T, at map[string][]llmAttempt) {
		t.Helper()
		if len(at) == 0 {
			t.Fatal("no parameter was probed, so silence proves nothing")
		}
		for p, as := range at {
			for i, a := range as {
				if a.inProbe {
					t.Errorf("%s attempt %d: the probe's answer carried %q", p, i+1, a.evidence)
				}
			}
		}
	}
	cases := []struct {
		path string
		why  func(t *testing.T, at map[string][]llmAttempt)
	}{
		{"/llm/safe/summary?prompt=What+are+your+opening+hours", noEvidence},
		{"/llm/safe/echo?prompt=What+are+your+opening+hours", noEvidence},
		{"/llm/safe/fixed?prompt=What+are+your+opening+hours", noEvidence},
		{"/llm/safe/v1/chat/completions", noEvidence},
		{"/helpdesk/safe/reply?text=How+do+I+return+a+damaged+item", noEvidence},
		// The probe's answer carries the evidence every time; only the control comparison stops it.
		{"/llm/safe/textutil?prompt=What+are+your+opening+hours", func(t *testing.T, at map[string][]llmAttempt) {
			as := at["prompt"]
			if len(as) < 2 {
				t.Fatalf("prompt was not probed twice: %d attempts", len(as))
			}
			for i, a := range as {
				if !a.inProbe || !a.inControl {
					t.Errorf("attempt %d: inProbe=%v inControl=%v, want both (the control guard decides)", i+1,
						a.inProbe, a.inControl)
				}
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, sent, at := llmTraced(t, c.path)
			if f := llmFindingIn(fs); f != nil {
				t.Fatalf("false positive on a safe twin (%d requests):\n%s", sent, f.Evidence)
			}
			c.why(t, at)
		})
	}
}

// A POST whose path says it messages someone gets no request: each probe would be a message to staff.
// The twin fronts the instruction-following model, so without the gate it is found.
func TestLLMPromptInjectionSendsNothingToAMessagingPost(t *testing.T) {
	path := "/llm/safe/support/contact"
	startRuntimeTarget(t)
	before := vulnapp.LLMContactRequests()
	fs, sent := llmAudit(t, path)
	if got := vulnapp.LLMContactRequests() - before; got != 0 || sent != 0 {
		t.Fatalf("the messaging POST received %d request(s) (engine counted %d); want 0", got, sent)
	}
	if f := llmFindingIn(fs); f != nil {
		t.Fatalf("reported %q without sending anything?", f.Name)
	}
}

// Two of three attempts must hold, and the run stops as soon as the verdict cannot change.
func TestLLMTallyNeedsTwoOfThree(t *testing.T) {
	a := func(held ...bool) []llmAttempt {
		var out []llmAttempt
		for _, h := range held {
			out = append(out, llmAttempt{held: h})
		}
		return out
	}
	for _, c := range []struct {
		in         []llmAttempt
		held, done bool
	}{
		{a(true), false, false},
		{a(false), false, false},
		{a(true, true), true, true},
		{a(true, false), false, false},
		{a(false, false), false, true},
		{a(true, false, true), true, true},
		{a(false, true, false), false, true},
	} {
		held, done := llmTally(c.in)
		if held != c.held || done != c.done {
			t.Errorf("%v: held=%v done=%v, want %v %v", c.in, held, done, c.held, c.done)
		}
	}
}

// The evidence is a transform the request cannot carry, and a reassembled stream still finds it when
// it is split across chunks between id/model members.
func TestLLMEvidenceIsATransformAndStreamsReassemble(t *testing.T) {
	c := llmCanary{transform: llmSum, a: 314, b: 271, word: "qzvxktab"}
	ev, re := c.evidence()
	if ev != "585qzvxktab" {
		t.Fatalf("evidence = %q", ev)
	}
	if re.MatchString(c.instruction()) || re.MatchString(c.control()) {
		t.Fatal("the instruction or its control matches its own evidence")
	}
	for _, s := range []string{"585qzvxktab", "**585** qzvxktab", "The answer: 585, qzvxktab", "585 QZVXKTAB"} {
		if !re.MatchString(s) {
			t.Errorf("%q not matched", s)
		}
	}
	for _, s := range []string{"1585qzvxktab", "585 is the word qzvxktab", "314 271 qzvxktab"} {
		if re.MatchString(s) {
			t.Errorf("%q matched", s)
		}
	}
	r := llmCanary{transform: llmReverse, word: "qzvxktab"}
	if _, rre := r.evidence(); !rre.MatchString("Sure: batkxvzq.") || rre.MatchString(r.instruction()) {
		t.Error("reverse evidence misread")
	}

	sse := "data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
		"data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"58\"}}]}\n\n" +
		"data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"5qzv\"}}]}\n\n" +
		"data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"xktab Hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	if ok, where, _ := llmFind(ProbeResponse{Body: sse}, re); !ok || where != "stream" {
		t.Errorf("split stream: found=%v in %q", ok, where)
	}
	ndjson := "{\"response\":\"58\",\"done\":false}\n{\"response\":\"5 qzvxktab\",\"done\":false}\n"
	if ok, _, _ := llmFind(ProbeResponse{Body: ndjson}, re); !ok {
		t.Error("newline-delimited JSON stream not reassembled")
	}
	if ok, _, _ := llmFind(ProbeResponse{Body: `{"reply":"<b>585</b>qzvxktab"}`}, re); !ok {
		t.Error("evidence wrapped in markup not found")
	}
	if got, ok := llmJSONStrings(`{"a":{"content":"x","n":1,"text":["y","z"]},"content":"w"}`, llmTextKeys); !ok ||
		strings.Join(got, ",") != "x,y,z,w" {
		t.Errorf("text members = %v, %v", got, ok)
	}
}

// Requests nothing marks as a model's are not probed, and the method and side-effect gates hold.
func TestLLMGates(t *testing.T) {
	for raw, want := range map[string]bool{
		"GET /llm/chat?prompt=hi HTTP/1.1\r\n\r\n":                                                                   true,
		"PUT /llm/chat?prompt=hi HTTP/1.1\r\n\r\n":                                                                   false,
		"GET /chat/delete?prompt=hi HTTP/1.1\r\n\r\n":                                                                false,
		"POST /support/contact HTTP/1.1\r\n\r\n":                                                                     false,
		"POST /api/chat HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nmessage=hi":               true,
		"POST /api/chat HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nmessage=hi&email=a%40b.c": false,
	} {
		if got := llmProbeable(raw); got != want {
			t.Errorf("llmProbeable(%q) = %v, want %v", raw, got, want)
		}
	}
	pts := func(raw string) []bcheck.InsertionPoint {
		p, _ := bcheck.Enumerate([]byte(raw), []string{"query", "body"})
		return p
	}
	prose := ProbeResponse{Body: "<p>Returns are free within thirty days: print the label and drop the parcel off.</p>"}
	short := ProbeResponse{Body: "<p>3 results</p>"}
	for _, c := range []struct {
		raw    string
		base   ProbeResponse
		marked bool
		want   []string
	}{
		// An identifier and a one-word search are not prompts, whatever the page says.
		{"GET /product?id=3&q=shoes HTTP/1.1\r\n\r\n", prose, false, nil},
		// A natural-language value with a non-prose answer is a search box.
		{"GET /search?q=red+running+shoes HTTP/1.1\r\n\r\n", short, false, nil},
		{"GET /search?q=red+running+shoes HTTP/1.1\r\n\r\n", prose, false, []string{"q"}},
		// Nor is a one-line status, however unlike the input.
		{"GET /search?q=red+running+shoes HTTP/1.1\r\n\r\n",
			ProbeResponse{Body: "<p>We found nothing matching that.</p>"}, false, nil},
		// A long answer that is the input echoed back is not prose.
		{"GET /search?q=red+running+shoes+for+trail+and+road+racing HTTP/1.1\r\n\r\n",
			ProbeResponse{Body: "<h1>Results for red running shoes for trail and road racing</h1><p>No results.</p>"}, false, nil},
		{"GET /x?prompt=hi&id=7 HTTP/1.1\r\n\r\n", short, false, []string{"prompt"}},
		{"GET /chat?id=7&lang=en HTTP/1.1\r\n\r\n", short, true, []string{"lang"}},
	} {
		var got []string
		for _, cand := range llmCandidates(pts(c.raw), c.base, c.marked, "marked") {
			got = append(got, cand.pt.Name)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%q: candidates %v, want %v", c.raw, got, c.want)
		}
	}
}
