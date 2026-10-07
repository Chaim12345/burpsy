package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// liveAuditResp mirrors the /api/scanner/live GET response shape.
type liveAuditResp struct {
	Wired    bool   `json:"wired"`
	Enabled  bool   `json:"enabled"`
	Hint     string `json:"hint"`
	Swept    uint64 `json:"swept"`
	Findings uint64 `json:"findings"`
	// Behind, BehindForMs and BatchLimit are the backlog's three numbers (burpsy-react-ui-iosv):
	// how much is left, how long it has been left, and the admission bound the last tick ran with.
	Behind      uint64 `json:"behind"`
	BehindForMs int64  `json:"behind_for_ms"`
	BatchLimit  uint64 `json:"batch_limit"`
}

func liveAuditGet(t *testing.T, s *Server) liveAuditResp {
	t.Helper()
	var v liveAuditResp
	rec := get(t, s, "/api/scanner/live")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scanner/live: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode live audit response %q: %v", rec.Body.String(), err)
	}
	return v
}

// A wired server reports the recorded sweep/finding totals and is disabled by
// default; POSTing {"enabled":true} flips it and the next GET shows it.
func TestLiveAuditWiredStateReportsAndFlips(t *testing.T) {
	s := newTestServer().WithLiveAudit(NewLiveAuditState())

	s.liveAudit.Record(5, 2)
	s.liveAudit.Record(3, 1)

	v := liveAuditGet(t, s)
	if !v.Wired {
		t.Errorf("wired = false, want true")
	}
	if v.Enabled {
		t.Errorf("enabled = true, want false by default")
	}
	if v.Swept != 8 {
		t.Errorf("swept = %d, want 8 after two records (5+3)", v.Swept)
	}
	if v.Findings != 3 {
		t.Errorf("findings = %d, want 3 after two records (2+1)", v.Findings)
	}

	rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/scanner/live: status = %d, want 200", rec.Code)
	}
	var flipped liveAuditResp
	if err := json.Unmarshal(rec.Body.Bytes(), &flipped); err != nil {
		t.Fatalf("decode POST response %q: %v", rec.Body.String(), err)
	}
	if !flipped.Enabled {
		t.Errorf("POST response enabled = false, want true")
	}

	if v = liveAuditGet(t, s); !v.Enabled {
		t.Errorf("enabled after POST = false, want true")
	}
}

// A server built without WithLiveAudit reports wired:false with a hint, so the
// UI does not mistake an unwired process for a broken route.
func TestLiveAuditUnwiredServerReportsWiredFalse(t *testing.T) {
	s := newTestServer()

	v := liveAuditGet(t, s)
	if v.Wired {
		t.Errorf("wired = true, want false without WithLiveAudit")
	}
	if v.Enabled {
		t.Errorf("enabled = true, want false when unwired")
	}
	if v.Swept != 0 || v.Findings != 0 {
		t.Errorf("unwired counts = swept %d findings %d, want 0", v.Swept, v.Findings)
	}
	if !strings.Contains(v.Hint, "--bchecks") {
		t.Errorf("hint = %q, want it to mention --bchecks", v.Hint)
	}
}

// POST on an unwired server is a no-op: it reports wired:false, never a 500.
func TestLiveAuditPostOnUnwiredServerIsANoOp(t *testing.T) {
	s := newTestServer()

	rec := postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/scanner/live on unwired server: status = %d, want 200", rec.Code)
	}
	var v liveAuditResp
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode POST response %q: %v", rec.Body.String(), err)
	}
	if v.Wired || v.Enabled {
		t.Errorf("unwired POST response = wired %v enabled %v, want false/false", v.Wired, v.Enabled)
	}
}
