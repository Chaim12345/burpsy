package intruder

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// The capture filter (burpsy-react-ui-ip2b): Burp's Zbjk/Zpoo/Zht8/Zs3t predicates, and what a discarded
// item still counts toward.

func mustCapture(t *testing.T, spec CaptureFilterSpec) *CaptureFilter {
	t.Helper()
	f, err := NewCaptureFilter(spec)
	if err != nil {
		t.Fatalf("NewCaptureFilter(%+v): %v", spec, err)
	}
	return f
}

func resp(status int, body string) []byte {
	return []byte("HTTP/1.1 " + itoaStr(status) + " X\r\nContent-Length: " + itoaStr(len(body)) + "\r\n\r\n" + body)
}

func TestCaptureFilterPredicates(t *testing.T) {
	s := func(n int) *int { return &n }
	cases := []struct {
		name   string
		spec   CaptureFilterSpec
		resp   []byte
		status *int
		want   bool
	}{
		{"nil filter spec captures a failure", CaptureFilterSpec{}, nil, nil, true},
		{"discard no response drops a failure", CaptureFilterSpec{DiscardNoResponse: true}, nil, nil, false},
		{"discard no response drops an empty response", CaptureFilterSpec{DiscardNoResponse: true}, []byte{}, nil, false},
		{"discard no response keeps a response", CaptureFilterSpec{DiscardNoResponse: true}, resp(200, "x"), s(200), true},
		{"an unticked class drops", CaptureFilterSpec{Statuses: []StatusClass{Status2xx}}, resp(404, "x"), s(404), false},
		{"a ticked class keeps", CaptureFilterSpec{Statuses: []StatusClass{Status2xx}}, resp(204, ""), s(204), true},
		{"a status outside 2xx-5xx always passes", CaptureFilterSpec{Statuses: []StatusClass{}}, resp(101, ""), s(101), true},
		{"no response passes the status filter", CaptureFilterSpec{Statuses: []StatusClass{}}, nil, nil, true},
		{"a literal term is found case-insensitively", CaptureFilterSpec{Term: "WELCOME"}, resp(200, "welcome back"), s(200), true},
		{"a case-sensitive term is not", CaptureFilterSpec{Term: "WELCOME", CaseSensitive: true}, resp(200, "welcome back"), s(200), false},
		{"a literal term is not a regex", CaptureFilterSpec{Term: "a.c"}, resp(200, "abc"), s(200), false},
		{"a regex term", CaptureFilterSpec{Term: "a.c", Regex: true}, resp(200, "abc"), s(200), true},
		{"negative search drops a match", CaptureFilterSpec{Term: "error", Negate: true}, resp(500, "an error"), s(500), false},
		{"negative search keeps a non-match", CaptureFilterSpec{Term: "error", Negate: true}, resp(200, "fine"), s(200), true},
		{"a positive term drops an item with no response", CaptureFilterSpec{Term: "x"}, nil, nil, false},
		{"a negative term keeps an item with no response", CaptureFilterSpec{Term: "x", Negate: true}, nil, nil, true},
		{"predicates combine with AND", CaptureFilterSpec{Term: "ok", Statuses: []StatusClass{Status3xx}}, resp(200, "ok"), s(200), false},
	}
	for _, c := range cases {
		if got := mustCapture(t, c.spec).captures(c.resp, c.status); got != c.want {
			t.Errorf("%s: captures = %v, want %v", c.name, got, c.want)
		}
	}
	var none *CaptureFilter
	if !none.captures(nil, nil) {
		t.Error("no filter must capture everything")
	}
	if _, err := NewCaptureFilter(CaptureFilterSpec{Statuses: []StatusClass{"6xx"}}); err == nil || !strings.Contains(err.Error(), "6xx") {
		t.Errorf("an unknown status class must be refused by name, got %v", err)
	}
	if _, err := NewCaptureFilter(CaptureFilterSpec{Term: "(", Regex: true}); err == nil {
		t.Error("a term that does not compile must be refused")
	}
}

// statusSender answers payload p with the status and body statusFor(p) gives; payload "fail" errors.
func statusSender(statusFor func(payload string) (int, string)) SendFn {
	return func(raw []byte) (Sent, error) {
		line := strings.SplitN(string(raw), " ", 3)[1]
		p := strings.TrimPrefix(line, "/s?q=")
		if p == "fail" {
			return Sent{}, errors.New("connection refused")
		}
		st, body := statusFor(p)
		return Sent{Raw: resp(st, body), Duration: time.Millisecond, Status: ptr(st)}, nil
	}
}

func filteredAttack(t *testing.T, items []string, f *CaptureFilter) (*Attack, *[]string, *[]string) {
	t.Helper()
	raw, pts := basePoints(t, "GET /s?q=v HTTP/1.1\r\nHost: t.test\r\n\r\n")
	a := NewAttack(raw, pts[:1], []PayloadSet{itemSet(items)}, NewAttackPlan(AttackKindSniper, 1, []int{len(items)}, 1000))
	a.Limits.MaxInFlight = 1
	a.WithCapture(f)
	var mu sync.Mutex
	var stored, observed []string
	a.RecordRequest = true
	a.RequestFn = func(b []byte) uint64 {
		mu.Lock()
		defer mu.Unlock()
		stored = append(stored, "req:"+strings.SplitN(string(b), "\r\n", 2)[0])
		return uint64(len(stored))
	}
	a.Observe = func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		observed = append(observed, string(b))
	}
	return a, &stored, &observed
}

func recordingTo(stored *[]string) RecordFn {
	return func(b []byte) uint64 {
		*stored = append(*stored, "resp:"+strings.SplitN(string(b), "\r\n", 2)[0])
		return uint64(len(*stored))
	}
}

// Discarded items are counted everywhere a count lives and stored nowhere.
func TestCaptureFilterDiscardsRowsAndStorageButNotCounts(t *testing.T) {
	items := []string{"a", "bb", "fail", "ccc", "dd"}
	statusFor := func(p string) (int, string) {
		if len(p) == 2 {
			return 404, "missing"
		}
		return 200, "found " + p
	}
	f := mustCapture(t, CaptureFilterSpec{Statuses: []StatusClass{Status2xx}, DiscardNoResponse: true})
	a, stored, observed := filteredAttack(t, items, f)
	r := Run(a, statusSender(statusFor), recordingTo(stored))

	if r.Sent != 4 || r.Failed != 1 {
		t.Fatalf("sent=%d failed=%d, want 4 and 1: discarding never shrinks what was sent", r.Sent, r.Failed)
	}
	if r.Discarded != 3 { // bb, dd (404) and fail (no response)
		t.Fatalf("discarded = %d, want 3", r.Discarded)
	}
	if got := len(r.Attempts) + r.Discarded; got != r.Sent+r.Failed {
		t.Fatalf("rows %d + discarded %d != sent %d + failed %d", len(r.Attempts), r.Discarded, r.Sent, r.Failed)
	}
	for _, at := range r.Attempts {
		if at.Status == nil || *at.Status != 200 {
			t.Fatalf("a discarded item left a row: %+v", at)
		}
	}
	total := 0
	for _, b := range r.Buckets {
		total += b.Count
		if b.Status != nil && *b.Status == 404 {
			if b.Count != 2 {
				t.Fatalf("the 404 bucket counts %d, want both discarded 404s", b.Count)
			}
			if b.ExampleRequestID != nil || b.ExampleResponseID != nil || b.ExampleOrdinal != nil {
				t.Fatalf("a bucket of discarded items stored an exemplar: %+v", b)
			}
		}
	}
	if total != r.Sent {
		t.Fatalf("bucket counts sum to %d, want every sent item (%d)", total, r.Sent)
	}
	if len(r.Errors) != 1 || r.Errors[0].Count != 1 {
		t.Fatalf("errors = %+v, want the discarded failure still grouped", r.Errors)
	}
	for _, s := range *stored {
		if strings.Contains(s, "q=bb") || strings.Contains(s, "q=dd") || strings.Contains(s, "404") {
			t.Fatalf("a discarded item was stored: %q (all: %q)", s, *stored)
		}
	}
	// The jar's hook still saw the opening response of every bucket, discarded or not.
	if len(*observed) != len(r.Buckets) {
		t.Fatalf("observe saw %d responses for %d buckets", len(*observed), len(r.Buckets))
	}
	if r.CaptureFilter == nil || !r.CaptureFilter.DiscardNoResponse {
		t.Fatalf("report.capture_filter = %+v, want the filter echoed", r.CaptureFilter)
	}
}

// A bucket whose opening response was discarded takes its exemplar from the first captured response in
// it, and says which ordinal that is.
func TestCaptureFilterExemplarComesFromTheFirstCapturedResponse(t *testing.T) {
	// Same status, same length, different content: one bucket, and only the second contains "yes".
	statusFor := func(p string) (int, string) { return 200, p + "-reply" }
	f := mustCapture(t, CaptureFilterSpec{Term: "yes"})
	a, stored, _ := filteredAttack(t, []string{"nah", "yes", "zzz"}, f)
	a.WithGrepPayloads(GrepPayloads{}) // keep the reflected flag out of the bucket key
	r := Run(a, statusSender(statusFor), recordingTo(stored))
	if len(r.Buckets) != 1 {
		t.Fatalf("buckets = %+v, want one", r.Buckets)
	}
	b := r.Buckets[0]
	if b.Count != 3 || b.FirstOrdinal != 0 {
		t.Fatalf("bucket = %+v, want all three counted from ordinal 0", b)
	}
	if b.ExampleOrdinal == nil || *b.ExampleOrdinal != 1 || b.ExampleResponseID == nil || b.ExampleRequestID == nil {
		t.Fatalf("bucket exemplar = ordinal %v ids %v/%v, want ordinal 1's stored exchange", b.ExampleOrdinal, b.ExampleRequestID, b.ExampleResponseID)
	}
	if len(r.Attempts) != 1 || r.Attempts[0].Ordinal != 1 || r.Attempts[0].ResponseID == nil {
		t.Fatalf("attempts = %+v, want ordinal 1's row carrying the exemplar response", r.Attempts)
	}

	// Without a filter the exemplar is the opening response, as it always was.
	a2, stored2, _ := filteredAttack(t, []string{"nah", "yes"}, nil)
	a2.WithGrepPayloads(GrepPayloads{})
	r2 := Run(a2, statusSender(statusFor), recordingTo(stored2))
	if eo := r2.Buckets[0].ExampleOrdinal; eo == nil || *eo != 0 || r2.Discarded != 0 || r2.CaptureFilter != nil {
		t.Fatalf("unfiltered: example_ordinal %v discarded %d filter %+v", eo, r2.Discarded, r2.CaptureFilter)
	}
}

// With a filter, the row budget is spent on captured items, not on the first ordinals.
func TestCaptureFilterSpendsTheRowBudgetOnCapturedItems(t *testing.T) {
	items := make([]string, 20)
	for i := range items {
		items[i] = "p" + itoaStr(i)
	}
	// Only ordinals 10 and up answer 200.
	statusFor := func(p string) (int, string) {
		if len(p) == 3 {
			return 200, "hit"
		}
		return 403, "no"
	}
	a, stored, _ := filteredAttack(t, items, mustCapture(t, CaptureFilterSpec{Statuses: []StatusClass{Status2xx}}))
	a.DetailLimit = 4
	r := Run(a, statusSender(statusFor), recordingTo(stored))
	if len(r.Attempts) != 4 {
		t.Fatalf("rows = %d, want the 4-row budget filled with captured items", len(r.Attempts))
	}
	for i, at := range r.Attempts {
		if at.Ordinal != 10+i {
			t.Fatalf("row %d is ordinal %d, want %d: the budget went to discarded ordinals", i, at.Ordinal, 10+i)
		}
	}
}
