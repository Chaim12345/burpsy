package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// Pause/resume on the live capture (burpsy-react-ui-5kx): a running capture can be held
// between sends without losing the tokens collected, and resumed. The gate sits between
// sends, never inside one, so the sample is never half-recorded; a stop issued while paused
// is honoured promptly, which the loop's select covers.

// pauseOrigin answers each request after a short delay, with a distinct token in the body,
// so the capture is provably still running when the pause lands.
func pauseOrigin(t *testing.T) (string, uint16) {
	t.Helper()
	// 15ms per response keeps the capture provably running when the pause lands, and each
	// response carries a distinct regex-extractable body token.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		n := 0
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n++
			go func(c net.Conn, i int) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				time.Sleep(15 * time.Millisecond)
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nTOK%08dEND", i)
			}(conn, n)
		}
	}()
	h, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(portStr)
	return h, uint16(p)
}

// pauseTestServer is captureServer scoped to the pause origin's host: in-scope, real sender,
// wired task registry — everything the capture loop needs to actually run.
func pauseTestServer(t *testing.T, host string, port uint16) *Server {
	t.Helper()
	return captureServer(t, host, port)
}

func waitForTokens(t *testing.T, s *Server, id uint64, atLeast int) captureView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		v := getCapture(t, s, id)
		if v.Total >= atLeast {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("capture %d never reached %d tokens", id, atLeast)
	return captureView{}
}

func waitForPaused(t *testing.T, s *Server, id uint64, paused bool) captureView {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		v := getCapture(t, s, id)
		if v.Paused == paused {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("capture %d never reported paused=%v", id, paused)
	return captureView{}
}

func getCapture(t *testing.T, s *Server, id uint64) captureView {
	t.Helper()
	rec := get(t, s, fmt.Sprintf("/api/sequencer/capture/%d", id))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET capture %d answered %d", id, rec.Code)
	}
	var v captureView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func startPauseCapture(t *testing.T, s *Server, host string, port uint16) captureView {
	t.Helper()
	rec := postJSON(t, s, "/api/sequencer/capture", map[string]any{
		"target":  fmt.Sprintf("http://%s:%d", host, port),
		"request": "GET / HTTP/1.1\r\nHost: pause.test\r\n\r\n",
		"count":   500,
		"location": map[string]any{
			"kind":    "body_regex",
			"pattern": `TOK(\d{8})END`,
		},
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start answered %d: %s", rec.Code, rec.Body.String())
	}
	var view captureView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

// The full loop: pause a running capture, watch the sample stop growing while the tokens
// already collected stay intact, resume, watch it grow again.
func TestACaptureCanBePausedAndResumedWithoutLosingTokens(t *testing.T) {
	host, port := pauseOrigin(t)
	s := pauseTestServer(t, host, port)
	started := startPauseCapture(t, s, host, port)

	waitForTokens(t, s, started.ID, 3)

	if rec := postJSON(t, s, "/api/sequencer/capture/pause", nil); rec.Code != http.StatusOK {
		t.Fatalf("pause answered %d: %s", rec.Code, rec.Body.String())
	}
	paused := waitForPaused(t, s, started.ID, true)
	if !paused.Capturing {
		t.Fatal("a paused capture must still be capturing — pause is not stop")
	}
	// The baseline is read AFTER the view confirms paused AND one in-flight send has drained:
	// a pause lands between sends, so the one send already on the wire when the request
	// arrived still records — stopping the NEXT send is the contract, not aborting the one in
	// flight. waitForPaused polls on 20ms ticks but the view is written before the loop re-
	// checks the gate, so give the in-flight response 120ms (origin answers in 15ms plus
	// transport slack) to land before taking the baseline.
	time.Sleep(120 * time.Millisecond)
	baseline := getCapture(t, s, started.ID)
	if baseline.Total < paused.Total {
		t.Fatalf("tokens lost on pause: %d -> %d", paused.Total, baseline.Total)
	}

	// While paused the sample must not move. 400ms is many sends' worth for this origin.
	time.Sleep(400 * time.Millisecond)
	after := getCapture(t, s, started.ID)
	if after.Total != baseline.Total {
		t.Fatalf("sample grew while paused: %d -> %d (attempts %d -> %d)", baseline.Total, after.Total, baseline.Attempts, after.Attempts)
	}
	if after.Total < baseline.Total {
		t.Fatalf("tokens lost on pause: %d -> %d", baseline.Total, after.Total)
	}

	if rec := postJSON(t, s, "/api/sequencer/capture/resume", nil); rec.Code != http.StatusOK {
		t.Fatalf("resume answered %d: %s", rec.Code, rec.Body.String())
	}
	resumed := waitForPaused(t, s, started.ID, false)
	if resumed.Total < after.Total {
		t.Fatalf("tokens lost on resume: %d -> %d", after.Total, resumed.Total)
	}
	waitForTokens(t, s, started.ID, after.Total+3)
	if getCapture(t, s, started.ID).Paused {
		t.Error("the capture still reports paused after resume and more tokens")
	}

	postJSON(t, s, "/api/sequencer/capture/stop", nil)
}

// A pause aimed at nothing is a 409, not a success: a UI that believes a capture is live
// must be told it is not.
func TestPausingWithNoLiveCaptureIsRefused(t *testing.T) {
	s := newTestServer() // no sender wired, and no capture started
	if rec := postJSON(t, s, "/api/sequencer/capture/pause", nil); rec.Code != http.StatusConflict {
		t.Errorf("pause with no capture answered %d, want 409", rec.Code)
	}
	if rec := postJSON(t, s, "/api/sequencer/capture/resume", nil); rec.Code != http.StatusConflict {
		t.Errorf("resume with no capture answered %d, want 409", rec.Code)
	}
}

// The captured token list is on the view the UI already polls, so Copy tokens / Save tokens
// need no new route — the acceptance criterion is that the list can be exported, which the
// UI does from these tokens. The pin here is that the list is non-empty, non-blank and
// complete against the count.
func TestCaptureViewCarriesTheTokensForExport(t *testing.T) {
	host, port := pauseOrigin(t)
	s := pauseTestServer(t, host, port)
	started := startPauseCapture(t, s, host, port)
	view := waitForTokens(t, s, started.ID, 5)
	if len(view.Tokens) < 5 {
		t.Fatalf("view carries %d tokens, want at least 5 for export", len(view.Tokens))
	}
	for i, tok := range view.Tokens {
		if tok == "" {
			t.Errorf("token %d is empty; a blank line in a saved wordlist silently shifts every payload", i)
		}
	}
	postJSON(t, s, "/api/sequencer/capture/stop", nil)
}
