package intruder

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// Manual points are Burp's Add §: an arbitrary byte range of the base request
// marked by hand, spliced wire-faithfully (escapeNone) — the payload crosses
// exactly as typed, and fixContentLength runs after the splice like it does for
// every other point family (burpsy-react-ui-mun).

func TestManualPointsSpliceAnArbitraryByteRange(t *testing.T) {
	// Marking a slice of a value the discoverer cannot model: half of "12" in
	// id=1234, which is one body_param_value point to the discoverer and two
	// possible manual marks to an operator.
	raw := "POST / HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nid=1234&x=1"
	base := []byte(raw)
	offset := strings.Index(raw, "34")
	pts, err := ManualPoints(base, []ManualSpan{{Start: offset, End: offset + 2}})
	if err != nil {
		t.Fatalf("ManualPoints: %v", err)
	}
	if len(pts) != 1 {
		t.Fatalf("points = %+v, want one", pts)
	}
	if pts[0].Kind != PointManual || pts[0].Label != "manual 1" {
		t.Fatalf("point = %+v, want a manual 1", pts[0])
	}
	out := Apply(base, &pts[0], []byte("AB"))
	if !bytes.Contains(out, []byte("id=12AB&x=1")) {
		t.Errorf("spliced: %s", out)
	}
	// "AB" replaces the 2-byte "34", so the body length is unchanged at 11 —
	// fixContentLength must still have run and re-stated it honestly.
	if !bytes.Contains(out, []byte("Content-Length: 11")) {
		t.Errorf("content-length not fixed: %s", out)
	}
}

func TestManualPointsRefuseBadSpans(t *testing.T) {
	base := []byte("GET / HTTP/1.1\r\nHost: t.test\r\n\r\n")
	for _, span := range []ManualSpan{
		{Start: -1, End: 4},
		{Start: 4, End: 4},
		{Start: 10, End: 4},
		{Start: 10, End: len(base) + 5},
	} {
		if _, err := ManualPoints(base, []ManualSpan{span}); err == nil {
			t.Errorf("span %+v accepted", span)
		}
	}
}

func TestManualPointsRefuseOverlaps(t *testing.T) {
	base := []byte("GET /search?q=alpha HTTP/1.1\r\nHost: t.test\r\n\r\n")
	if _, err := ManualPoints(base, []ManualSpan{{Start: 5, End: 15}, {Start: 10, End: 20}}); err == nil {
		t.Fatal("overlapping spans accepted")
	}
	// Adjacent is not overlapping: byte 15 belongs to the second mark only.
	if _, err := ManualPoints(base, []ManualSpan{{Start: 5, End: 15}, {Start: 15, End: 20}}); err != nil {
		t.Fatalf("adjacent spans refused: %v", err)
	}
}

func TestManualPointSurvivesAFullAttack(t *testing.T) {
	// End-to-end through Run: the plan counts the manual mark as a position and
	// each payload lands in its own bucket.
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	base := []byte(raw)
	offset := strings.Index(raw, "alpha")
	pts, err := ManualPoints(base, []ManualSpan{{Start: offset, End: offset + 5}})
	if err != nil {
		t.Fatalf("ManualPoints: %v", err)
	}
	sets := []PayloadSet{{Kind: "list", Items: []string{"bravo", "charlie", "delta"}}}
	plan := NewAttackPlan(AttackKindSniper, len(pts), []int{len(sets[0].Items)}, 100)
	// Locked, and the bytes copied: Run's default limits allow several requests in flight, so it
	// calls this from a worker pool. The unsynchronised append here was a real data race that
	// `go test -race` reports every run — engine_test.go's recordingSender already takes a mutex
	// for exactly this reason, and this test simply did not (burpsy-react-ui-1817).
	var mu sync.Mutex
	sent := make([][]byte, 0, 3)
	attack := NewAttack(base, pts, sets, plan)
	report := Run(attack, func(req []byte) (Sent, error) {
		mu.Lock()
		sent = append(sent, append([]byte(nil), req...))
		mu.Unlock()
		status := 200
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: " + string(rune('0'+len(req))) + "\r\n\r\n"), Status: &status, Duration: 1}, nil
	}, func([]byte) uint64 { return 0 })
	if report.Planned != 3 || report.Sent != 3 {
		t.Fatalf("planned/sent = %d/%d, want 3/3", report.Planned, report.Sent)
	}
	if len(sent) != 3 {
		t.Fatalf("sent %d requests, want 3", len(sent))
	}
	// Asserted as a set, not by index. Arrival order is not plan order under concurrency and the
	// engine never promised it was — indexing sent[i] was asserting a property this test happened
	// to observe rather than one the engine has. What the test is actually about is that every
	// payload reached the wire spliced into the MANUAL point.
	for _, want := range []string{"bravo", "charlie", "delta"} {
		found := false
		for _, req := range sent {
			if bytes.Contains(req, []byte("q="+want)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no request carried payload %q spliced into the manual point; sent %s", want, sent)
		}
	}
}
