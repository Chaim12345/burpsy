package web

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/filelog"
)

// Burp's Project settings → Logging (burpsy-react-ui-nvfl) through its route, with the writer
// observing the server's own store the way main wires it: a Repeater send through the real send
// route lands in the repeater requests file, and the setting is persisted.
func TestFileLoggingRouteAndARepeaterSendReachingTheFile(t *testing.T) {
	s := newTestServerWithPersist(t)
	l := filelog.New(s.store)
	defer l.Close()
	s.store.ObserveExchanges(l.Observe)
	s.WithFileLog(l)

	body := get(t, s, "/api/project/logging").Body.String()
	if !strings.Contains(body, `"repeater":""`) || !strings.Contains(body, `"tools":["all_tools","proxy","scanner","repeater","intruder","sequencer","extender"]`) {
		t.Fatalf("GET = %s", body)
	}
	if rec := putJSON(t, s, "/api/project/logging", map[string]any{"requests": map[string]string{"repeater": "rel.log"}}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "absolute") {
		t.Errorf("a relative path = %d %q", rec.Code, rec.Body.String())
	}
	if rec := putJSON(t, s, "/api/project/logging", map[string]any{"request": map[string]string{}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown key = %d", rec.Code)
	}
	logPath := filepath.Join(t.TempDir(), "repeater-requests.log")
	if rec := putJSON(t, s, "/api/project/logging", map[string]any{"requests": map[string]string{"repeater": logPath}}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	if saved, err := s.persist.LoadFileLogging(); err != nil || saved == nil || saved.Requests["repeater"] != logPath {
		t.Errorf("not persisted: %+v %v", saved, err)
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	host := strings.TrimPrefix(origin.URL, "http://")
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{"target": origin.URL,
		"request": fmt.Sprintf("GET /logged-path HTTP/1.1\r\nHost: %s\r\n\r\n", host)})
	if rec.Code != http.StatusOK {
		t.Fatalf("repeater send = %d %s", rec.Code, rec.Body.String())
	}
	l.Flush()
	got, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(got), "GET /logged-path HTTP/1.1") {
		t.Errorf("the repeater request is not in the log: %q %v", got, err)
	}
}
