package web

import (
	"strings"
	"testing"
)

// burpsy's Clickbandit (burpsy-react-ui-g67w): the script is served as JavaScript text with the
// controls the documented workflow names, and the engagement search route still answers beside it.
func TestTheClickbanditScriptIsServed(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/engagement/clickbandit.js")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("GET = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	for _, want := range []string{"Start", "Finish", "Disable click actions", "Sandbox iframe", "Toggle transparency", "Reset", "Save", "ArrowLeft", "clickjacking-poc.html"} {
		if !strings.Contains(body, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	if rec := get(t, s, "/api/engagement/comments"); rec.Code != 200 {
		t.Errorf("the engagement search beside it = %d", rec.Code)
	}
}
