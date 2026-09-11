package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// tokenServer answers every request with a Set-Cookie carrying a distinct token, and counts how many
// requests it received. The count is what proves a capture actually sent traffic rather than
// reporting a number it invented — the whole defect being fixed here was a capture surface that
// answered without a loop behind it.
//
// setCookie chooses what the token header looks like, so one helper covers both the happy path and
// the response-with-no-token case.
func tokenServer(t *testing.T, setCookie func(n int) string) (host string, port uint16, hits *int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var count int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				n := int(atomic.AddInt64(&count, 1))
				extra := setCookie(n)
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\n%sContent-Length: 2\r\nConnection: close\r\n\r\nok", extra)
			}(conn)
		}
	}()
	h, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(portStr)
	return h, uint16(p), &count
}

// The capture bound is Burp's own FIPS 140-2 sample maximum (burpsy-react-ui-vhs0): 20000
// is the size a formally compliant live capture must be able to reach, so it is accepted;
// past it is a typo's commitment to a million requests and is refused. Pinning both sides
// keeps the ceiling from drifting back down — the page presents FIPS results, and a capture
// that could not reach the compliant size would make that presentation unreachable.
func TestTheCaptureCountBoundIsBurpsFIPSMaximum(t *testing.T) {
	s := newTestServer()
	target := "http://127.0.0.1:1" // never dialed: the bound is checked before any send
	request := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"

	rec := postJSON(t, s, "/api/sequencer/capture", map[string]any{
		"target":   target,
		"request":  request,
		"count":    20000,
		"location": map[string]string{"kind": "header", "name": "X-Token"},
	})
	if rec.Code != http.StatusAccepted {
		t.Errorf("count 20000 (FIPS-compliant maximum) = %d (%s), want accepted", rec.Code, rec.Body.String())
	}

	rec = postJSON(t, s, "/api/sequencer/capture", map[string]any{
		"target":   target,
		"request":  request,
		"count":    20001,
		"location": map[string]string{"kind": "header", "name": "X-Token"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("count 20001 = %d, want 400 — past the maximum is a typo, not an ambition", rec.Code)
	}
}

// captureServer builds a Server wired for capture: in-scope, with a real sender and a task registry.
func captureServer(t *testing.T, host string, port uint16) *Server {
	t.Helper()
	scope := core.NewScope()
	scope.AddInclude(host)
	s := NewServer(core.NewTrafficStore(), scope).
		WithSender(sender.NewSender(sender.DefaultSenderConfig()))
	if s.tasks == nil {
		t.Fatal("NewServer left the task registry nil; capture progress and cancellation both need it")
	}
	return s
}

func startCapture(t *testing.T, s *Server, body map[string]any) captureView {
	t.Helper()
	rec := postJSON(t, s, "/api/sequencer/capture", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/sequencer/capture answered %d: %s", rec.Code, rec.Body.String())
	}
	var view captureView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode capture %q: %v", rec.Body.String(), err)
	}
	return view
}

// awaitCapture polls the capture until it stops running, and returns its final view.
func awaitCapture(t *testing.T, s *Server, id uint64) captureView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rec := get(t, s, fmt.Sprintf("/api/sequencer/capture/%d", id))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET capture %d answered %d: %s", id, rec.Code, rec.Body.String())
		}
		var view captureView
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			t.Fatalf("decode capture %q: %v", rec.Body.String(), err)
		}
		if !view.Capturing {
			return view
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("capture %d never finished", id)
	return captureView{}
}

// HONEST-02.
//
// The capture surface used to answer `{"total": 0, "tokens": []}` from a helper whose whole body was
// `return nil`, so "the application's tokens could not be read" and "nothing ever asked for one"
// rendered identically. This asserts the loop exists by counting the requests the target received:
// a stub cannot make a server register hits.
func Test_a_sequencer_capture_actually_sends_requests_and_collects_the_tokens_HONEST_02(t *testing.T) {
	host, port, hits := tokenServer(t, func(n int) string {
		return fmt.Sprintf("Set-Cookie: SESSIONID=tok-%03d; Path=/; HttpOnly\r\n", n)
	})
	s := captureServer(t, host, port)

	view := startCapture(t, s, map[string]any{
		"target":   fmt.Sprintf("http://%s:%d", host, port),
		"request":  fmt.Sprintf("GET /login HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port),
		"count":    8,
		"location": map[string]any{"kind": "cookie", "name": "SESSIONID"},
	})
	if view.Requested != 8 {
		t.Fatalf("capture reported requested = %d, want 8", view.Requested)
	}
	final := awaitCapture(t, s, view.ID)

	if got := atomic.LoadInt64(hits); got != 8 {
		t.Errorf("the target received %d requests, want 8 — a capture that reports tokens must have sent for them", got)
	}
	if final.Total != 8 || len(final.Tokens) != 8 {
		t.Fatalf("captured %d tokens (%v), want 8", final.Total, final.Tokens)
	}
	// Distinct values, in order: a loop that collected the same response eight times would satisfy a
	// count assertion while proving nothing about the sample an entropy verdict is computed over.
	for i, token := range final.Tokens {
		want := fmt.Sprintf("tok-%03d", i+1)
		if token != want {
			t.Errorf("token %d = %q, want %q", i, token, want)
		}
	}
	if final.Misses != 0 {
		t.Errorf("misses = %d on a target that set the cookie every time", final.Misses)
	}
	// The token list is what /api/sequencer/analyse reads when no explicit list is posted, so the two
	// halves of the tool are actually connected rather than each working alone.
	if got := s.captureTokens(); len(got) != 8 {
		t.Errorf("captureTokens() returned %d tokens, want the capture's 8", len(got))
	}
	// And the run appears on the dashboard: a capture visible only in the tab that started it is the
	// pre-DASH-01 failure mode.
	var seen bool
	for _, task := range s.tasks.Snapshot() {
		if task.Kind == dash.KindSequencerCapture {
			seen = true
			if task.Done != 8 || task.Total != 8 {
				t.Errorf("capture task progress = %d/%d, want 8/8", task.Done, task.Total)
			}
		}
	}
	if !seen {
		t.Error("no sequencer-capture task was registered, so the run was invisible on the dashboard")
	}
}

// A response that carries no token is a miss with a reason, not a token and not a silent skip. The
// difference matters because an entropy verdict over 4 tokens from 8 requests is a weaker claim than
// one over 8, and the old shape had no way to say which it was.
func Test_responses_with_no_token_are_counted_as_misses_with_reasons_HONEST_02(t *testing.T) {
	host, port, hits := tokenServer(t, func(n int) string {
		if n%2 == 0 {
			return "" // every other response sets no cookie at all
		}
		return fmt.Sprintf("Set-Cookie: SESSIONID=tok-%d\r\n", n)
	})
	s := captureServer(t, host, port)

	view := startCapture(t, s, map[string]any{
		"target":   fmt.Sprintf("http://%s:%d", host, port),
		"request":  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port),
		"count":    6,
		"location": map[string]any{"kind": "cookie", "name": "SESSIONID"},
	})
	final := awaitCapture(t, s, view.ID)

	if got := atomic.LoadInt64(hits); got != 6 {
		t.Errorf("the target received %d requests, want 6", got)
	}
	if final.Total != 3 {
		t.Errorf("collected %d tokens, want 3 (every other response carried one)", final.Total)
	}
	if final.Misses != 3 {
		t.Errorf("misses = %d, want 3", final.Misses)
	}
	if final.Attempts != 6 {
		t.Errorf("attempts = %d, want 6 — the count sent, as distinct from the count collected", final.Attempts)
	}
	if len(final.MissExamples) == 0 || final.MissExamples[0].Reason == "" {
		t.Errorf("miss examples = %+v; a miss must carry why, or a misspelled cookie name looks like a sparse token",
			final.MissExamples)
	}
}

// The headline defect. /stop answered `{"stopped": true}` unconditionally — for a loop that did not
// exist, on any verb. Both halves are pinned: nothing running answers stopped=false and says so, and
// a real capture is genuinely interrupted, mid-run, keeping the tokens it had.
func Test_stopping_a_sequencer_capture_reports_whether_one_was_running_HONEST_02(t *testing.T) {
	t.Run("nothing running", func(t *testing.T) {
		s := newTestServer()
		rec := postJSON(t, s, "/api/sequencer/capture/stop", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST stop answered %d", rec.Code)
		}
		var resp stopCaptureResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		if resp.Stopped || resp.Signalled != 0 {
			t.Errorf("stop claimed stopped=%v signalled=%d with no capture running", resp.Stopped, resp.Signalled)
		}
		if resp.Note == "" {
			t.Error("stop must say why nothing was stopped, or false is indistinguishable from a failure")
		}
	})

	t.Run("a real capture is interrupted", func(t *testing.T) {
		host, port, hits := tokenServer(t, func(n int) string {
			return fmt.Sprintf("Set-Cookie: SESSIONID=tok-%d\r\n", n)
		})
		s := captureServer(t, host, port)
		// Paced, so the capture is guaranteed to still be running when the stop arrives. Without a
		// delay a 400-request capture against a loopback server can finish before the stop is sent,
		// and the test would pass for the wrong reason.
		view := startCapture(t, s, map[string]any{
			"target":   fmt.Sprintf("http://%s:%d", host, port),
			"request":  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port),
			"count":    400,
			"delay_ms": 20,
			"location": map[string]any{"kind": "cookie", "name": "SESSIONID"},
		})
		// Wait for the first token so the stop lands on a capture that has actually begun.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && atomic.LoadInt64(hits) == 0 {
			time.Sleep(5 * time.Millisecond)
		}

		rec := postJSON(t, s, "/api/sequencer/capture/stop", nil)
		var resp stopCaptureResp
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		if !resp.Stopped || resp.Signalled != 1 {
			t.Errorf("stop reported stopped=%v signalled=%d for one running capture", resp.Stopped, resp.Signalled)
		}

		final := awaitCapture(t, s, view.ID)
		if final.Attempts >= 400 {
			t.Errorf("the capture ran to completion (%d attempts) despite being stopped", final.Attempts)
		}
		if final.StopReason == "" {
			t.Error("a short capture must say why it is short, or the sample size looks like the target's answer")
		}
		// The partial sample is kept: tokens collected before a stop are real tokens.
		if final.Total == 0 {
			t.Error("a stopped capture discarded the tokens it had already collected")
		}
		// And the task ends stopped rather than done, so the dashboard does not read a cancelled run
		// as a completed one.
		for _, task := range s.tasks.Snapshot() {
			if task.Kind == dash.KindSequencerCapture && task.State != dash.TaskStopped {
				t.Errorf("capture task state = %v, want stopped", task.State)
			}
		}
	})
}

// A capture whose token location cannot be parsed is refused, rather than run against a guess. A
// heuristic that picked the wrong cookie would produce a confident entropy verdict about the wrong
// string, which is worse than no verdict at all.
func Test_a_capture_refuses_an_unusable_token_location(t *testing.T) {
	host, port, _ := tokenServer(t, func(int) string { return "" })
	s := captureServer(t, host, port)
	base := func(loc any) map[string]any {
		return map[string]any{
			"target":   fmt.Sprintf("http://%s:%d", host, port),
			"request":  "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			"count":    1,
			"location": loc,
		}
	}
	for name, loc := range map[string]any{
		"no location at all":            map[string]any{},
		"an unknown kind":               map[string]any{"kind": "telepathy"},
		"a cookie with no name":         map[string]any{"kind": "cookie"},
		"a regex that does not compile": map[string]any{"kind": "body_regex", "pattern": "([unclosed"},
	} {
		rec := postJSON(t, s, "/api/sequencer/capture", base(loc))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", name, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s was refused with no reason", name)
		}
	}
}

// A capture id that was never issued is a 404 naming why, not an empty capture. `{"total": 0,
// "tokens": []}` for an unknown id was the original defect in its purest form: it reads as a capture
// that ran and found nothing.
func Test_an_unknown_capture_id_is_a_404_rather_than_an_empty_capture_HONEST_02(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/sequencer/capture/999")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET an unknown capture answered %d (%s), want 404", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		t.Error("the 404 carries no reason")
	}
}

// Scope is enforced on capture for the reason it is enforced on Repeater and Intruder, and more so:
// a capture is the most request-hungry thing in the tool — hundreds of unattended sends at one
// endpoint — so a scope an operator set to bound outbound traffic must not be bypassable by starting
// one.
//
// An *excluded* host, specifically. Scope.MayContainHost is documented as a deliberately permissive
// pre-filter: a whole-host exclude is what puts a host beyond its reach — the layer this test
// exercises — while the per-send AuthoriseRaw gate on the bytes is the other one, and it is the reason
// the capture binds an AuthorisedSender rather than sending through s.sender directly.
func Test_a_capture_against_an_excluded_host_is_refused(t *testing.T) {
	host, port, hits := tokenServer(t, func(int) string { return "Set-Cookie: SESSIONID=x\r\n" })
	scope := core.NewScope()
	scope.AddExclude(host)
	s := NewServer(core.NewTrafficStore(), scope).
		WithSender(sender.NewSender(sender.DefaultSenderConfig()))

	rec := postJSON(t, s, "/api/sequencer/capture", map[string]any{
		"target":   fmt.Sprintf("http://%s:%d", host, port),
		"request":  "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"count":    5,
		"location": map[string]any{"kind": "cookie", "name": "SESSIONID"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a capture against an excluded host answered %d (%s), want 403", rec.Code, rec.Body.String())
	}
	// Asserted by request count, not by the status code alone: a 403 that had already sent traffic
	// would be a scope check in name only.
	time.Sleep(100 * time.Millisecond)
	if got := atomic.LoadInt64(hits); got != 0 {
		t.Errorf("the excluded target received %d requests", got)
	}
}
