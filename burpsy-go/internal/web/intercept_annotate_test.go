package web

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// Annotate a held message (burpsy-react-ui-5q8u): the operator's comment and highlight ride
// the hold — and, when the hold forwards into a recorded exchange, into HTTP history, which is
// exactly Burp's "annotations that you make also appear against the item in the HTTP history".

// holdOne wires a server with intercept on for requests and holds one request through the
// engine, returning the held id.
func holdOne(t *testing.T, s *Server) uint64 {
	t.Helper()
	s.intercept.SetEnabled(true)
	// SetRules with an empty rule list turns the request list "unconditional" — on with
	// nothing to match, so everything holds. Enable alone does not hold: with no list
	// active there is nothing deciding to hold, which is the engine's own contract.
	if err := s.intercept.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	held := s.intercept.Hold(&intercept.Message{
		Direction: intercept.DirectionRequest,
		Host:      "annot.test",
		Port:      80,
		Method:    "GET",
		Path:      "/held",
		Raw:       []byte("GET /held HTTP/1.1\r\nHost: annot.test\r\n\r\n"),
	})
	if held == nil {
		t.Fatal("the hold did not happen; intercept is not holding requests")
	}
	return held.ID
}

// The annotation lands on the hold and reads back through the queue view.
func TestAHeldMessageCanBeAnnotated(t *testing.T) {
	s := newTestServer()
	id := holdOne(t, s)

	rec := postJSON(t, s, "/api/intercept/annotate/"+itoa64(id), map[string]any{
		"comment":   "check the auth header",
		"highlight": "red",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("annotate answered %d (%s)", rec.Code, rec.Body.String())
	}

	rec = get(t, s, "/api/intercept")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/intercept answered %d", rec.Code)
	}
	var body struct {
		Held []struct {
			ID        uint64 `json:"id"`
			Comment   string `json:"comment"`
			Highlight string `json:"highlight"`
		} `json:"held"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, h := range body.Held {
		if h.ID == id {
			found = true
			if h.Comment != "check the auth header" {
				t.Errorf("comment = %q", h.Comment)
			}
			if h.Highlight != "red" {
				t.Errorf("highlight = %q", h.Highlight)
			}
		}
	}
	if !found {
		t.Fatal("the held message disappeared from the queue after annotation")
	}
}

// Clearing: empty comment and "" highlight clear both — "" is the picker's no-colour value.
func TestAHeldMessageAnnotationCanBeCleared(t *testing.T) {
	s := newTestServer()
	id := holdOne(t, s)

	postJSON(t, s, "/api/intercept/annotate/"+itoa64(id), map[string]any{"comment": "x", "highlight": "red"})
	rec := postJSON(t, s, "/api/intercept/annotate/"+itoa64(id), map[string]any{"comment": "", "highlight": ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("clear answered %d", rec.Code)
	}
	h := s.intercept.Get(id)
	if h.Comment != "" || h.Highlight != "" {
		t.Errorf("annotation did not clear: comment=%q highlight=%q", h.Comment, h.Highlight)
	}
}

// An unknown id is 404: a stale queue render must be told the message resolved, not told done.
func TestAnnotatingAResolvedHoldIsRefused(t *testing.T) {
	s := newTestServer()
	id := holdOne(t, s)
	s.intercept.Drop(id, "gone")

	rec := postJSON(t, s, "/api/intercept/annotate/"+itoa64(id), map[string]any{"comment": "late"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("annotate on resolved hold answered %d, want 404", rec.Code)
	}
}

// The carry-forward: an annotated hold that forwards records its annotation on the exchange in
// HTTP history — the whole point of the feature.
func TestAHeldAnnotationsRideForwardIntoHistory(t *testing.T) {
	s := newTestServer()
	id := holdOne(t, s)
	postJSON(t, s, "/api/intercept/annotate/"+itoa64(id), map[string]any{
		"comment":   "forwarded with a note",
		"highlight": "orange",
	})

	h := s.intercept.Get(id)
	capture := scanner.Capture{Store: s.store, Source: core.SourceProxy}
	ex, err := capture.Record(scanner.CapturedExchange{
		Host:      h.Host,
		Port:      h.Port,
		TLS:       h.TLS,
		Method:    h.Method,
		Path:      h.Path,
		Request:   h.Raw,
		Response:  []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		Started:   time.Now(),
		Notes:     &h.Comment,
		Highlight: h.Highlight,
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if ex.Notes == nil || *ex.Notes != "forwarded with a note" {
		t.Errorf("notes = %v, want the held comment", ex.Notes)
	}
	if ex.Highlight != "orange" {
		t.Errorf("highlight = %q, want the held colour", ex.Highlight)
	}
}

func itoa64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
