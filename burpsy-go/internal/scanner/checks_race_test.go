package scanner

// Race-condition (single-packet) check tests (burpsy-react-ui-0vzb.8).

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// raceAudit audits one race fixture path with the check's own switch on (and whatever the
// caller's mod adds).
func raceAudit(t *testing.T, path string, mod func(*ScanConfig)) []*Finding {
	t.Helper()
	rt := startRuntimeTarget(t)
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckRaceConditions: true}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	exchange, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("no captured exchange for %s", path)
	}
	outcome, findings := scan.AuditWithin(ctx, exchange, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	return findings
}

func TestRaceConditionFindsADoubleRedeem(t *testing.T) {
	fs := raceAudit(t, "/race/redeem?coupon=welcome", nil)
	var f *Finding
	for _, x := range fs {
		if x.Name == IssueRaceConditionSinglePacket {
			f = x
		}
	}
	if f == nil {
		var got []string
		for _, x := range fs {
			got = append(got, x.Name)
		}
		t.Fatalf("no race-condition finding (got %v)", got)
	}
	if f.Confidence != "firm" || f.Severity != "high" {
		t.Fatalf("finding confidence/severity = %s/%s, want firm/high", f.Confidence, f.Severity)
	}
}

func TestRaceConditionStaysQuietOnTheSafeTwin(t *testing.T) {
	fs := raceAudit(t, "/race/safe/redeem?coupon=welcome", nil)
	for _, x := range fs {
		if x.Name == IssueRaceConditionSinglePacket {
			t.Fatalf("safe twin reported: %+v", x)
		}
	}
}

func TestRaceConditionIsOffByDefault(t *testing.T) {
	rt := startRuntimeTarget(t)
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	exchange, ok := rt.exchanges["/race/redeem?coupon=welcome"]
	if !ok {
		t.Fatalf("no captured exchange for /race/redeem")
	}
	outcome, findings := scan.AuditWithin(ctx, exchange, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit failed: %s", outcome.Error)
	}
	for _, x := range findings {
		if x.Name == IssueRaceConditionSinglePacket {
			t.Fatalf("switch off, still reported: %+v", x)
		}
	}
}

// RaceConditionCandidateAndCopy unit-cover the candidate gate and the per-phase token mint.
func TestRaceConditionCandidateGate(t *testing.T) {
	redeem := "POST /race/redeem?coupon=welcome HTTP/1.1\r\nHost: x\r\n\r\n"
	if !raceCandidate(redeem) {
		t.Fatal("a POST to a redeem path is a candidate")
	}
	getRedeem := "GET /race/redeem?coupon=welcome HTTP/1.1\r\nHost: x\r\n\r\n"
	if raceCandidate(getRedeem) {
		t.Fatal("a GET is never a candidate")
	}
	bland := "POST /account/profile HTTP/1.1\r\nHost: x\r\n\r\nname=carlos"
	if raceCandidate(bland) {
		t.Fatal("a bland profile POST is not a candidate")
	}
}

func TestRaceFreshCopyMintsQueryAndJSON(t *testing.T) {
	query := "POST /race/redeem?coupon=welcome HTTP/1.1\r\nHost: x\r\n\r\n"
	out, ok := raceFreshCopy(query, "race-c1-abc")
	if !ok {
		t.Fatal("query coupon not minted")
	}
	if want := "coupon=race-c1-abc"; !strings.Contains(out, want) {
		t.Fatalf("minted query missing %q: %s", want, out)
	}
	body := "POST /api/claim HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"claim\":\"abc\",\"n\":1}"
	out, ok = raceFreshCopy(body, "race-g1-def")
	if !ok {
		t.Fatal("JSON claim not minted")
	}
	if want := `"claim":"race-g1-def"`; !strings.Contains(out, want) {
		t.Fatalf("minted body missing %q: %s", want, out)
	}
	if _, ok := raceFreshCopy("POST /race/redeem HTTP/1.1\r\nHost: x\r\n\r\n", "race-x"); ok {
		t.Fatal("no single-use parameter: mint must decline")
	}
}
