package bcheck

import (
	"strings"
	"testing"
)

// burpsy-react-ui-806w: a request with operator-marked spans enumerates exactly those spans and
// nothing else — the heuristic query/body/cookie points are not built — and Apply splices the payload
// into the marked byte range of the raw request.
func TestManualInsertionPointsShortCircuitAndSpliceRaw(t *testing.T) {
	req := []byte("GET /search?q=hello&sort=asc HTTP/1.1\r\nHost: t.test\r\nCookie: sid=abc\r\n\r\n")
	// Mark the value of q (the bytes "hello").
	start := strings.Index(string(req), "hello")
	end := start + len("hello")

	pts, declined := EnumerateWith(req, []string{"any"}, EnumerateOptions{ManualSpans: [][2]int{{start, end}}})
	if len(declined) != 0 {
		t.Fatalf("unexpected declines: %v", declined)
	}
	if len(pts) != 1 {
		t.Fatalf("manual spans must yield exactly the marked points, got %d: %+v", len(pts), pts)
	}
	if pts[0].Kind != IpManual || pts[0].BaseValue != "hello" {
		t.Errorf("point = kind %q base %q", pts[0].Kind, pts[0].BaseValue)
	}

	out, err := pts[0].Apply(req, "INJECTED", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "q=INJECTED&sort=asc") {
		t.Errorf("payload not spliced into the marked span: %s", out)
	}
	// The non-manual positions (sort, the cookie) were NOT enumerated: the same request without a
	// manual span yields several heuristic points, proving the short-circuit.
	heur, _ := EnumerateWith(req, []string{"any"}, EnumerateOptions{})
	if len(heur) <= 1 {
		t.Fatalf("control: heuristic enumeration should find several points, got %d", len(heur))
	}
}

// An out-of-range span is declined, not applied.
func TestManualInsertionPointRejectsABadSpan(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: t\r\n\r\n")
	pts, declined := EnumerateWith(req, []string{"any"}, EnumerateOptions{ManualSpans: [][2]int{{5, 9999}}})
	if len(pts) != 0 || len(declined) != 1 {
		t.Errorf("bad span should be declined: points %d declined %d", len(pts), len(declined))
	}
}
