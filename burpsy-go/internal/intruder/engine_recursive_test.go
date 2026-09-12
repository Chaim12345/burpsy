package intruder

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The recursive grep chain (ztuu) is Burp's answer to dependent values: the payload for
// request N+1 is extracted from the response to request N. The stop conditions are ported
// from the decompiled original (Zccc.Zt): the extraction matching nothing ends the chain as
// complete, and stop-if-duplicate ends it when the extracted payload equals the one just sent.
//
// The origin below is a sequential database in miniature: each response names the next row's
// key, and the last row says "end". An attack that walks the whole table is the whole point
// of the payload type — the operator could not have listed the payloads up front, because
// they only exist once each response arrives.
func Test_the_recursive_grep_chain_walks_a_response_derived_sequence(t *testing.T) {
	// next is the extraction contract the chain reads: a token hidden in prose, exactly the
	// shape Burp's own documented example produces (an error message disclosing the next name).
	table := []string{"accounts", "backups", "cards"}
	var served int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0, 64)
		body = append(body, r.URL.Query().Get("q")...)
		body = append(body, " => next: "...)
		n := atomic.AddInt32(&served, 1)
		if int(n) <= len(table) {
			body = append(body, table[n-1]...)
		} else {
			body = append(body, "end"...)
		}
		w.Write(body)
	}))
	defer srv.Close()

	base := fmt.Sprintf("GET /?q=%%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		strings.TrimPrefix(srv.URL, "http://"))

	// The set holds only the initial payload; the chain derives the rest. The regex mirrors
	// Grep.extract's convention: with a group, the group is the payload.
	src := PayloadSource{Type: "recursive_grep", RecursiveGrep: &RecursiveGrepSource{
		Initial:   "a",
		ExtractRe: `next: ([a-z]+)`,
	}}
	set, err := src.Resolve(1000)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(set.Items) != 1 || set.Items[0] != "a" {
		t.Fatalf("the resolved set should hold exactly the initial payload, got %v", set.Items)
	}

	points := []InsertionPoint{{
		Kind:  PointURLParamValue,
		Span:  core.Span{Offset: strings.Index(base, "?q=") + 3, Len: 1},
		Label: "q",
	}}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 100)
	atk := NewAttack([]byte(base), points, []PayloadSet{*set}, plan).
		WithLimits(Unthrottled(1))
	re, err := regexp.Compile(src.RecursiveGrep.ExtractRe)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	atk.WithRecursive(&RecursiveGrep{Re: re})

	report := Run(atk, sendToURL(srv), nil)

	// The chain: initial "a" pulls "accounts", "accounts" pulls "backups", "backups" pulls
	// "cards", "cards" pulls "end", and "end" extracts as... it DOES match [a-z]+ — so the
	// walk continues until the table stops naming new tokens? No: the response after the
	// table's last row says "end", whose extraction is "end" again only if asked. The origin
	// above answers "end" for every request past the table, so the chain would send "end",
	// extract "end" — and stop only via the duplicate rule. This test does not set it, so the
	// honest expectation is the bound: 100 requests max, all completing. That is why the
	// sibling test below pins the duplicate stop; this one pins the walk and the bound.
	if report.Sent < 4 {
		t.Fatalf("the chain should have walked at least the four real tokens (a, accounts, backups, cards), sent %d: %v",
			report.Sent, report.ChainPayloads)
	}
	want := []string{"a", "accounts", "backups", "cards"}
	for i, p := range want {
		if i >= len(report.ChainPayloads) || report.ChainPayloads[i] != p {
			t.Fatalf("chain payload %d = %q, want %q (full chain: %v)",
				i, chainAt(report.ChainPayloads, i), p, report.ChainPayloads)
		}
	}
	if report.Status != StatusCompleted {
		t.Fatalf("an extraction that keeps matching runs to the bound and completes, got %q", report.Status)
	}
}

// Burp's "Stop if duplicate payload found" is the chain's natural ending for a table that
// stops producing new values: the same payload derived twice in succession means "the
// exercise is complete" (payload-types.html). Zccc compares the newly-derived payload with
// the one before it — not with any payload ever seen.
func Test_the_recursive_grep_chain_stops_when_the_same_payload_returns_twice_in_succession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every response names the same token, so the second derivation repeats the first.
		fmt.Fprintf(w, "%s -> next: fixed", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	base := fmt.Sprintf("GET /?q=%%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		strings.TrimPrefix(srv.URL, "http://"))
	src := PayloadSource{Type: "recursive_grep", RecursiveGrep: &RecursiveGrepSource{
		Initial:       "start",
		ExtractRe:     `next: ([a-z]+)`,
		StopDuplicate: true,
	}}
	set, err := src.Resolve(1000)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	points := []InsertionPoint{{
		Kind:  PointURLParamValue,
		Span:  core.Span{Offset: strings.Index(base, "?q=") + 3, Len: 5},
		Label: "q",
	}}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 100)
	atk := NewAttack([]byte(base), points, []PayloadSet{*set}, plan).
		WithLimits(Unthrottled(1))
	re, _ := regexp.Compile(src.RecursiveGrep.ExtractRe)
	atk.WithRecursive(&RecursiveGrep{Re: re, StopDuplicate: true})

	report := Run(atk, sendToURL(srv), nil)

	// "start" derives "fixed"; "fixed" derives "fixed" again — the duplicate stop fires on
	// the second derivation, after two sends. Without the rule the first test showed the
	// chain running to its bound; with it, two.
	if report.Sent != 2 {
		t.Fatalf("stop-if-duplicate should end the chain after 'fixed' repeats, sent %d: %v",
			report.Sent, report.ChainPayloads)
	}
	if got := report.ChainPayloads; len(got) != 2 || got[0] != "start" || got[1] != "fixed" {
		t.Fatalf("chain should record [start fixed], got %v", got)
	}
}

// A response with no match is the chain's other end: nothing was extracted, so there is no
// next payload. The attack completes — "no more data" is an answer, not an error.
func Test_the_recursive_grep_chain_ends_cleanly_when_extraction_matches_nothing(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			fmt.Fprintf(w, "token for you: %s", r.URL.Query().Get("q"))
			return
		}
		w.Write([]byte("login required"))
	}))
	defer srv.Close()

	base := fmt.Sprintf("GET /?q=%%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		strings.TrimPrefix(srv.URL, "http://"))
	src := PayloadSource{Type: "recursive_grep", RecursiveGrep: &RecursiveGrepSource{
		Initial:   "first",
		ExtractRe: `token for you: (\w+)`,
	}}
	set, err := src.Resolve(1000)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	points := []InsertionPoint{{
		Kind:  PointURLParamValue,
		Span:  core.Span{Offset: strings.Index(base, "?q=") + 3, Len: 5},
		Label: "q",
	}}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 100)
	atk := NewAttack([]byte(base), points, []PayloadSet{*set}, plan).
		WithLimits(Unthrottled(1))
	re, _ := regexp.Compile(src.RecursiveGrep.ExtractRe)
	atk.WithRecursive(&RecursiveGrep{Re: re})

	report := Run(atk, sendToURL(srv), nil)

	// "first" is echoed as the token; the echo's response carries no token, so the chain
	// stops after two sends with a completed status and zero errors.
	if report.Sent != 2 {
		t.Fatalf("the chain should stop when nothing extracts, sent %d: %v", report.Sent, report.ChainPayloads)
	}
	if len(report.Errors) != 0 || report.Failed != 0 {
		t.Fatalf("a no-match extraction is a clean end, not a failure: errors=%v failed=%d",
			report.Errors, report.Failed)
	}
	if report.Status != StatusCompleted {
		t.Fatalf("chain should complete, got %q", report.Status)
	}
}

func sendToURL(srv *httptest.Server) SendFn {
	return func(raw []byte) (Sent, error) {
		// Minimal HTTP/1.1 client for the test origin: the request line is already absolute-path,
		// so cutting the headers' end and forwarding verbatim is enough for httptest.
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/?q="+queryOf(raw), strings.NewReader(""))
		if err != nil {
			return Sent{}, err
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			return Sent{}, err
		}
		defer resp.Body.Close()
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		status := resp.StatusCode
		body := append([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", status, http.StatusText(status))), buf[:n]...)
		return Sent{Raw: body, Status: &status}, nil
	}
}

func chainAt(chain []string, i int) string {
	if i < len(chain) {
		return chain[i]
	}
	return ""
}

// queryOf digs the q= value out of the spliced request — the payload the chain sent.
func queryOf(raw []byte) string {
	s := string(raw)
	i := strings.Index(s, "?q=")
	if i < 0 {
		return ""
	}
	rest := s[i+3:]
	if j := strings.IndexAny(rest, " \r\n"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// A chain that dies is a settled failure, and the live progress view has to say so: control.go's
// contract is that its counters are "the same totals the eventual report carries, so a live view
// cannot disagree with it". runRecursive called note(true) on the success path only, so a chain
// ending on a send error or a guard refusal reported failed=1 in the report while a poll of the
// control route still said 0 — the view under-reporting the one thing an operator watching a
// stalled attack is looking at.
func Test_a_chain_that_dies_counts_its_failure_in_the_live_progress(t *testing.T) {
	rg := &RecursiveGrep{Re: regexp.MustCompile(`next: ([a-z]+)`)}

	run := func(t *testing.T, guard bool) {
		t.Helper()
		base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
		plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 10)
		ctrl := NewControl()
		atk := NewAttack(base, pts[:1], sets([]string{"a"}), plan).
			WithLimits(Unthrottled(1)).
			WithControl(ctrl).
			WithRecursive(rg)
		if guard {
			atk.Guard = func(raw []byte) error { return errors.New("refused by the test guard") }
		}
		send := func(raw []byte) (Sent, error) { return Sent{}, errors.New("connection reset") }

		report := Run(atk, send, nil)
		if report.Failed != 1 {
			t.Fatalf("report.Failed = %d, want 1 — the chain's single attempt failed", report.Failed)
		}
		sent, failed := ctrl.Progress()
		if failed != 1 {
			t.Errorf("live progress = sent %d / failed %d, want failed 1: a poll of the control route must not disagree with the report it will be compared against", sent, failed)
		}
	}

	t.Run("a send that fails", func(t *testing.T) { run(t, false) })
	t.Run("a request the guard refuses", func(t *testing.T) { run(t, true) })
}
