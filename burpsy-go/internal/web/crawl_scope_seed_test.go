package web

// A crawl whose seeds the engagement scope refuses (burpsy-react-ui-us6r.3): all refused is a 403
// naming the scope's reason and registers no task; some refused starts from the rest and names them.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestACrawlOfOnlyOutOfScopeSeedsIsRefusedWithTheReason(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{"http://localhost:18473/"}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "outside the engagement scope") {
		t.Fatalf("all out of scope = %d %q, want 403 naming the scope", rec.Code, rec.Body.String())
	}
	if n := len(s.tasks.Snapshot()); n != 0 {
		t.Errorf("a refused crawl registered %d task(s); it must not appear as a finished run", n)
	}

	rec = postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{"http://127.0.0.1:1/", "http://localhost:18473/"}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("partly in scope = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		OutOfScope []struct {
			URL    string `json:"url"`
			Reason string `json:"reason"`
		} `json:"out_of_scope_seeds"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.OutOfScope) != 1 || out.OutOfScope[0].URL != "http://localhost:18473/" || out.OutOfScope[0].Reason == "" {
		t.Errorf("out_of_scope_seeds = %+v, want the localhost seed with a reason", out.OutOfScope)
	}
	if !strings.Contains(rec.Body.String(), `"out_of_scope_seeds":[`) {
		t.Errorf("the list must be an array on the wire: %s", rec.Body.String())
	}
}
