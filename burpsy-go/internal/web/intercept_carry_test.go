package web

import (
	"net/http"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// The carry-forward at the API level: after annotating a hold, the exchange that the proxy
// records from that hold's bytes carries the comment and the colour into HTTP history. This is
// the half the issue names explicitly — "nothing carried into HTTP history".

func TestAnnotatedHoldForwardThroughRecordCarriesBothAnnotations(t *testing.T) {
	s := newTestServer()
	id := holdOne(t, s)

	if rec := postJSON(t, s, "/api/intercept/annotate/"+itoa64(id), map[string]any{
		"comment":   "carried note",
		"highlight": "blue",
	}); rec.Code != http.StatusOK {
		t.Fatalf("annotate: %d (%s)", rec.Code, rec.Body.String())
	}

	h := s.intercept.Get(id)
	cap := scanner.Capture{Store: s.store, Source: core.SourceProxy}
	ex, err := cap.Record(scanner.CapturedExchange{
		Host:      h.Host,
		Port:      h.Port,
		TLS:       h.TLS,
		Method:    h.Method,
		Path:      h.Path,
		Request:   h.Raw,
		Response:  []byte("HTTP/1.1 204 No Content\r\n\r\n"),
		Started:   time.Now(),
		Notes:     &h.Comment,
		Highlight: h.Highlight,
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	// Read it back the way history does: through the exchange index.
	got, err := s.store.GetExchange(ex.ID)
	if err != nil {
		t.Fatalf("get exchange: %v", err)
	}
	if got.Notes == nil || *got.Notes != "carried note" {
		t.Errorf("history notes = %v, want the held comment", got.Notes)
	}
	if got.Highlight != "blue" {
		t.Errorf("history highlight = %q, want blue", got.Highlight)
	}
}
