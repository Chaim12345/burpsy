package scanner

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// burpsy-react-ui-806w end to end at the audit layer: a request with operator-marked spans, carried
// on the CheckContext's EnumerateOptions (where cfg.enumerateOptions() puts cfg.ManualSpans), makes
// the probe harness enumerate exactly the marked point and none of the heuristic ones.
func TestAuditHarnessProbesOnlyTheMarkedSpan(t *testing.T) {
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}, "/search?q=hello&sort=asc")

	// Without marks, the harness finds the heuristic points (q, sort, ...).
	heur, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatal(err)
	}
	if len(heur.Points()) < 2 {
		t.Fatalf("control: expected several heuristic points, got %d", len(heur.Points()))
	}

	// Mark the "hello" value on the raw request, the way cfg.ManualSpans would arrive.
	raw := heur.reqBytes
	start := strings.Index(string(raw), "hello")
	if start < 0 {
		t.Fatal("fixture request did not carry the marked value")
	}
	cc.EnumerateOptions = bcheck.EnumerateOptions{ManualSpans: [][2]int{{start, start + len("hello")}}}

	marked, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatal(err)
	}
	pts := marked.Points()
	if len(pts) != 1 {
		t.Fatalf("a marked request must probe exactly the marked span, got %d points: %+v", len(pts), pts)
	}
	if pts[0].Kind != bcheck.IpManual {
		t.Errorf("point kind = %q, want manual", pts[0].Kind)
	}
}
