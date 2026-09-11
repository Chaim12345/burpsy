package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The payload upload (016): an operator's wordlist arrives as the request body and the response
// names the stored path, which the ordinary {"type":"file"} payload source resolves. The whole
// point is that an operator's own wordlist is not second-class: the engine cannot tell an
// uploaded list from a server-side one, and that is the property these tests pin.

// Upload, then run an attack against the stored path: the payloads that hit the target are the
// uploaded ones, proving the loop an operator actually drives (choose file -> upload -> attack).
func Test_an_uploaded_wordlist_feeds_the_file_payload_source(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "got %s", r.URL.RawQuery)
	}))
	defer origin.Close()
	host, port := hostPort(t, origin)

	s := newTestServer()
	s.scope.AddInclude(host)
	raw := fmt.Sprintf("GET /?q=x HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	id := putMessage(t, s, []byte(raw), core.DirectionRequest)

	// The upload: three payloads plus the blank line Resolve skips.
	wordlist := "admin\npassword\n\nroot\n"
	rec := postUpload(t, s, wordlist, "my-list.txt")
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var up struct {
		Filename     string `json:"filename"`
		Lines        int    `json:"lines"`
		OriginalName string `json:"original_name"`
	}
	if err := decodeInto(rec, &up); err != nil {
		t.Fatalf("decode upload: %v", err)
	}
	if up.Lines != 3 {
		t.Fatalf("the response should count the payloads the attack will see (blank line skipped), got %d", up.Lines)
	}
	if up.OriginalName != "my-list.txt" {
		t.Fatalf("the operator's name rides along for display, got %q", up.OriginalName)
	}
	// The stored name is chosen by the server, never the client: a client-supplied filename is
	// a path-traversal primitive and a collision vector.
	if strings.Contains(up.Filename, "my-list") || !strings.HasPrefix(up.Filename, "/") {
		t.Fatalf("the stored path should be server-chosen and absolute, got %q", up.Filename)
	}
	if _, err := os.Stat(up.Filename); err != nil {
		t.Fatalf("stored file missing: %v", err)
	}

	// The attack consumes it through the ordinary file source.
	run := postJSONRaw(t, s, "/api/intruder/run", fmt.Sprintf(`{
		"msg_id": %d, "target": "%s:%d", "mode": "sniper", "points": [0],
		"payload_sources": [{"type": "file", "filename": %q}]
	}`, id, host, port, up.Filename))
	if run.Code != http.StatusOK {
		t.Fatalf("run = %d: %s", run.Code, strings.TrimSpace(run.Body.String()))
	}
	var view struct {
		Report struct {
			Sent    int `json:"sent"`
			Failed  int `json:"failed"`
			Planned int `json:"planned"`
		} `json:"report"`
		Examples []struct {
			Payloads []string `json:"payloads"`
		} `json:"examples"`
	}
	if err := decodeInto(run, &view); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if view.Report.Sent != 3 || view.Report.Failed != 0 {
		t.Fatalf("three uploaded payloads should be three sends, got sent=%d failed=%d",
			view.Report.Sent, view.Report.Failed)
	}
	seen := map[string]bool{}
	for _, ex := range view.Examples {
		for _, p := range ex.Payloads {
			seen[p] = true
		}
	}
	for _, want := range []string{"admin", "password", "root"} {
		if !seen[want] {
			t.Fatalf("uploaded payload %q never reached the target; examples: %+v", want, view.Examples)
		}
	}
}

// An empty upload is refused with the remedy named, not stored to be discovered at run time.
func Test_an_empty_upload_is_refused(t *testing.T) {
	s := newTestServer()
	rec := postUpload(t, s, "   \n\n", "blank.txt")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an empty upload should be refused, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "one payload per line") {
		t.Fatalf("the refusal should say what the body should be, got: %s", strings.TrimSpace(rec.Body.String()))
	}
}

// GET is refused: the route stores state.
func Test_the_upload_route_rejects_non_post(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/intruder/payload-files", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", rec.Code)
	}
}

func postUpload(t *testing.T, s *Server, body, name string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/intruder/payload-files", strings.NewReader(body))
	req.Header.Set("X-Payload-Filename", name)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}
