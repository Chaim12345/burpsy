package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// hiddenTarget is vulnapp behind a hit counter, with an exchange store to seed captures into.
type hiddenTarget struct {
	srv   *httptest.Server
	host  string
	port  uint16
	hits  atomic.Int64
	store *core.TrafficStore
}

func startHiddenTarget(t *testing.T) *hiddenTarget {
	t.Helper()
	ht := &hiddenTarget{store: core.NewTrafficStore()}
	inner := vulnapp.Handler()
	ht.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ht.hits.Add(1)
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(ht.srv.Close)
	h, p, _ := strings.Cut(strings.TrimPrefix(ht.srv.URL, "http://"), ":")
	n, _ := strconv.Atoi(p)
	ht.host, ht.port = h, uint16(n)
	return ht
}

// seed records a capture of path without contacting the target, so the hit counter only ever
// counts what the guesser sent.
func (ht *hiddenTarget) seed(t *testing.T, path string, extra map[string]string) core.ExchangeID {
	t.Helper()
	reqID, _ := ht.store.Put([]byte(buildRawRequest("GET", path, ht.host, ht.port, "", "", extra)), core.DirectionRequest)
	respID, _ := ht.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), core.DirectionResponse)
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: ht.host, Port: ht.port, Method: "GET", Path: path}
	ht.store.AddExchange(ex)
	return ex.ID
}

func (ht *hiddenTarget) scanner(include string) *ActiveScanner {
	scope := core.NewScope()
	scope.AddInclude(include)
	return NewActiveScanner(ht.store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(scope)
}

// assertPartition checks the per-kind accounting adds up: no name leaves a run uncounted.
func assertPartition(t *testing.T, res HiddenInputResult) {
	t.Helper()
	for _, k := range res.Kinds {
		if got := k.Present + k.Settled + k.Unresolved + k.Untested; got != k.Candidates {
			t.Errorf("%s: present %d + settled %d + unresolved %d + untested %d = %d, want candidates %d",
				k.Kind, k.Present, k.Settled, k.Unresolved, k.Untested, got, k.Candidates)
		}
		if k.Untested < 0 || k.Settled < 0 {
			t.Errorf("%s: negative count in %+v", k.Kind, k)
		}
	}
}

func inputKeys(in []HiddenInput) []string {
	out := []string{}
	for _, i := range in {
		key := string(i.Kind) + ":" + i.Name
		if i.Reflected {
			key += " (reflected)"
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func TestHiddenInputWordlistsAreClean(t *testing.T) {
	token := regexp.MustCompile(`^[A-Za-z0-9_\-]+$`)
	total := 0
	for _, k := range HiddenInputKinds {
		words := HiddenInputWordlist(k)
		total += len(words)
		seen := map[string]bool{}
		for _, w := range words {
			key := w
			if k == HiddenInputHeader {
				key = strings.ToLower(w)
				if hiddenHeaderDenylist[key] {
					t.Errorf("header wordlist carries the denylisted framing header %q", w)
				}
			}
			if seen[key] {
				t.Errorf("%s wordlist repeats %q", k, w)
			}
			seen[key] = true
			if !token.MatchString(w) {
				t.Errorf("%s wordlist name %q is not a plain token", k, w)
			}
		}
	}
	if total < 200 || total > 600 {
		t.Errorf("the built-in wordlists hold %d names; the design is a few hundred", total)
	}
	// The fixture names must be on the list and outside the first batch, so finding them proves
	// bisection ran rather than a one-name batch getting lucky.
	for k, name := range map[HiddenInputKind]string{
		HiddenInputQuery: vulnapp.HiddenQueryParam, HiddenInputCookie: vulnapp.HiddenCookie,
		HiddenInputHeader: vulnapp.HiddenHeader,
	} {
		idx := -1
		for i, w := range HiddenInputWordlist(k) {
			if w == name {
				idx = i
			}
		}
		if idx < hiddenInputBatch[k] {
			t.Errorf("fixture %s %q is at index %d; it must be on the list and past the first batch of %d",
				k, name, idx, hiddenInputBatch[k])
		}
	}
}

func TestHiddenInputRequestRewrites(t *testing.T) {
	base := []byte("GET /a?x=1 HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\n\r\n")
	if got := string(addQueryPairs(base, [][2]string{{"debug", "v"}, {"a b", "c&d"}})); !strings.HasPrefix(got, "GET /a?x=1&debug=v&a+b=c%26d HTTP/1.1\r\n") {
		t.Errorf("query rewrite = %q", got)
	}
	if got := string(addQueryPairs([]byte("GET /a HTTP/1.1\r\nHost: h\r\n\r\n"), [][2]string{{"q", "1"}})); !strings.HasPrefix(got, "GET /a?q=1 HTTP/1.1") {
		t.Errorf("query rewrite without a query = %q", got)
	}
	if got := string(addCookiePairs(base, [][2]string{{"beta", "1"}, {"x", "2"}})); !strings.Contains(got, "\r\nCookie: s=1; beta=1; x=2\r\n\r\n") {
		t.Errorf("cookie rewrite must extend the one Cookie header: %q", got)
	}
	if got := string(addCookiePairs([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), [][2]string{{"b", "1"}})); !strings.HasSuffix(got, "\r\nCookie: b=1\r\n\r\n") {
		t.Errorf("cookie rewrite without a Cookie header = %q", got)
	}
	got := string(addHeaderLines(base, [][2]string{{"X-Debug", "1"}, {"Transfer-Encoding", "chunked"}, {"host", "evil"}}))
	if !strings.HasSuffix(got, "\r\nX-Debug: 1\r\n\r\n") || strings.Contains(got, "Transfer-Encoding") || strings.Contains(got, "evil") {
		t.Errorf("header rewrite must add X-Debug and drop denylisted names: %q", got)
	}
	withBody := []byte("POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na=b")
	if got := string(addHeaderLines(withBody, [][2]string{{"X-A", "1"}})); !strings.HasSuffix(got, "X-A: 1\r\n\r\na=b") {
		t.Errorf("header rewrite must keep the body: %q", got)
	}
	if p := presentInputs(base, HiddenInputQuery); !p["x"] || len(p) != 1 {
		t.Errorf("present query = %v", p)
	}
	if p := presentInputs(base, HiddenInputCookie); !p["s"] || len(p) != 1 {
		t.Errorf("present cookies = %v", p)
	}
	if p := presentInputs(base, HiddenInputHeader); !p["host"] || !p["cookie"] {
		t.Errorf("present headers = %v", p)
	}
}

func TestGuessHiddenInputsFindsExactlyTheFixtureInputs(t *testing.T) {
	ht := startHiddenTarget(t)
	id := ht.seed(t, "/hidden/account", nil)
	res := ht.scanner(ht.host).GuessHiddenInputs(context.Background(), id,
		HiddenInputOptions{Kinds: HiddenInputKinds})
	t.Log(res.Summary)
	if res.State != "done" {
		t.Fatalf("state = %q (%s)", res.State, res.Summary)
	}
	want := []string{
		"cookie:" + vulnapp.HiddenCookie,
		"header:" + vulnapp.HiddenHeader,
		"query:" + vulnapp.HiddenQueryParam,
		"query:" + vulnapp.HiddenReflectedParam + " (reflected)",
	}
	if got := inputKeys(res.Inputs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("inputs = %v, want %v\nsummary: %s", got, want, res.Summary)
	}
	for _, in := range res.Inputs {
		if in.Confidence != "firm" || in.Issue != in.Kind.IssueName() || in.Evidence == "" {
			t.Errorf("input %+v: want firm confidence, its kind's issue name and an evidence line", in)
		}
	}
	assertPartition(t, res)
	if res.Sent != int(ht.hits.Load()) || res.Sent > res.Budget {
		t.Errorf("sent %d, origin saw %d, budget %d", res.Sent, ht.hits.Load(), res.Budget)
	}
	for _, k := range res.Kinds {
		if k.Untested != 0 || k.State != "done" {
			t.Errorf("%s: state %q with %d untested; a completed run tests every name", k.Kind, k.State, k.Untested)
		}
	}
}

// The random page must yield nothing, and say why: the two-baseline stability check.
func TestGuessHiddenInputsStopsOnAResponseThatVariesOnItsOwn(t *testing.T) {
	ht := startHiddenTarget(t)
	id := ht.seed(t, "/hidden/random", nil)
	res := ht.scanner(ht.host).GuessHiddenInputs(context.Background(), id, HiddenInputOptions{Kinds: HiddenInputKinds})
	if res.State != "unstable" || !strings.Contains(res.Reason, "varies on its own") {
		t.Fatalf("state %q reason %q; want unstable / varies on its own", res.State, res.Reason)
	}
	if res.Sent != 2 || len(res.Inputs) != 0 {
		t.Fatalf("an unstable page must cost exactly the two baselines and report nothing: sent %d, inputs %v", res.Sent, res.Inputs)
	}
	body, _ := json.Marshal(res)
	if !strings.Contains(string(body), `"inputs":[]`) {
		t.Errorf("inputs must marshal as [], got %s", body)
	}
	assertPartition(t, res)
}

// A page that echoes everything reads no input. Every kind must stop at its control.
func TestGuessHiddenInputsReportsNothingOnAPageThatEchoesItsRequest(t *testing.T) {
	ht := startHiddenTarget(t)
	id := ht.seed(t, "/hidden/echo", nil)
	res := ht.scanner(ht.host).GuessHiddenInputs(context.Background(), id, HiddenInputOptions{Kinds: HiddenInputKinds})
	t.Log(res.Summary)
	if len(res.Inputs) != 0 {
		t.Fatalf("an echo page has no hidden inputs, got %v (%s)", inputKeys(res.Inputs), res.Summary)
	}
	for _, k := range res.Kinds {
		if k.State != "stopped" || !strings.Contains(k.Reason, "any "+kindNoun(k.Kind)) {
			t.Errorf("%s: state %q reason %q; want stopped at the control", k.Kind, k.State, k.Reason)
		}
	}
	assertPartition(t, res)
}

func TestGuessHiddenInputsHonoursTheRequestBudget(t *testing.T) {
	ht := startHiddenTarget(t)
	id := ht.seed(t, "/hidden/account", nil)
	res := ht.scanner(ht.host).GuessHiddenInputs(context.Background(), id,
		HiddenInputOptions{Kinds: HiddenInputKinds, MaxRequests: 6})
	if res.State != "budget" || !strings.Contains(res.Reason, "budget (6)") {
		t.Fatalf("state %q reason %q", res.State, res.Reason)
	}
	if res.Sent != 6 || ht.hits.Load() != 6 {
		t.Fatalf("sent %d, origin saw %d; the budget is a hard bound", res.Sent, ht.hits.Load())
	}
	if res.Untested() == 0 {
		t.Fatalf("a budget-bound run must count names never sent")
	}
	assertPartition(t, res)
}

// Names the request already carries are not guessed.
func TestGuessHiddenInputsSkipsNamesTheRequestAlreadyCarries(t *testing.T) {
	ht := startHiddenTarget(t)
	id := ht.seed(t, "/hidden/account?"+vulnapp.HiddenQueryParam+"=1", nil)
	res := ht.scanner(ht.host).GuessHiddenInputs(context.Background(), id,
		HiddenInputOptions{Kinds: []HiddenInputKind{HiddenInputQuery}})
	for _, in := range res.Inputs {
		if in.Name == vulnapp.HiddenQueryParam {
			t.Fatalf("a name already in the request was reported as hidden")
		}
	}
	if res.Kinds[0].Present != 1 {
		t.Fatalf("present = %d, want 1", res.Kinds[0].Present)
	}
	assertPartition(t, res)
}

// Out of scope: the gate refuses the first baseline and nothing reaches the origin.
func TestGuessHiddenInputsSendsNothingOutOfScope(t *testing.T) {
	ht := startHiddenTarget(t)
	id := ht.seed(t, "/hidden/account", nil)
	res := ht.scanner("other.invalid").GuessHiddenInputs(context.Background(), id, HiddenInputOptions{Kinds: HiddenInputKinds})
	if res.State != "failed" || !strings.Contains(res.Reason, "outside the engagement scope") {
		t.Fatalf("state %q reason %q", res.State, res.Reason)
	}
	if ht.hits.Load() != 0 || len(res.Inputs) != 0 {
		t.Fatalf("origin saw %d requests; an out-of-scope run must send none", ht.hits.Load())
	}
}

// A name that changes the response during the batch and bisection but stops doing so before the
// second confirming send is not reported: confirmation is a repeat, not a formality. The target
// changes its page for the first three requests carrying "debug" — the batch, the bisected half
// and the first confirming send — and never again.
func TestGuessHiddenInputsDoesNotReportAChangeThatDoesNotRepeat(t *testing.T) {
	var seen, hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		extra := ""
		if r.URL.Query().Has("debug") && seen.Add(1) <= 3 {
			extra = "<p>debug</p>"
		}
		_, _ = w.Write([]byte("<html><body>page" + extra + "</body></html>"))
	}))
	t.Cleanup(srv.Close)
	h, p, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	n, _ := strconv.Atoi(p)
	ht := &hiddenTarget{srv: srv, host: h, port: uint16(n), store: core.NewTrafficStore()}
	id := ht.seed(t, "/", nil)
	res := ht.scanner(h).GuessHiddenInputs(context.Background(), id, HiddenInputOptions{
		Kinds:     []HiddenInputKind{HiddenInputQuery},
		Wordlists: map[HiddenInputKind][]string{HiddenInputQuery: {"alpha", "debug"}},
	})
	t.Log(res.Summary)
	if len(res.Inputs) != 0 {
		t.Fatalf("a change that did not repeat was reported: %v", inputKeys(res.Inputs))
	}
	if got := res.Kinds[0].Unconfirmed; len(got) != 1 || got[0] != "debug" {
		t.Fatalf("unconfirmed = %v, want [debug]", got)
	}
	if seen.Load() != 4 {
		t.Fatalf("debug was sent %d times; the test's arithmetic assumes batch, half, and two confirming sends", seen.Load())
	}
	assertPartition(t, res)
}

// Stoppable: a cancelled context ends the run at the next send, says so, and still accounts for
// every name — the dashboard's Stop button reaches this through the task's context.
func TestGuessHiddenInputsStopsWhenItsContextIsCancelled(t *testing.T) {
	ht := startHiddenTarget(t)
	id := ht.seed(t, "/hidden/account", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const stopAt = 5
	res := ht.scanner(ht.host).GuessHiddenInputs(ctx, id, HiddenInputOptions{
		Kinds: HiddenInputKinds,
		Progress: func(sent int) {
			if sent == stopAt {
				cancel()
			}
		},
	})
	if res.State != "stopped" || !strings.Contains(res.Reason, "stopped by the operator") {
		t.Fatalf("state %q reason %q", res.State, res.Reason)
	}
	if res.Sent != stopAt || ht.hits.Load() > stopAt {
		t.Fatalf("sent %d, origin saw %d; the run must stop at the cancelled send", res.Sent, ht.hits.Load())
	}
	if res.Untested() == 0 {
		t.Fatalf("a stopped run must count the names it never sent")
	}
	assertPartition(t, res)
}
