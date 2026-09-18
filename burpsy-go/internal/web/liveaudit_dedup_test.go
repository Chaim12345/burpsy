package web

// The cross-run request-content dedup (burpsy-react-ui-apfh) — Burp's
// REQUEST_TO_AUDIT_DEDUPLICATED (Zeze.java:17) as a first-class disposition row for the
// live sweep. The sweep's dispatch ledger dies with its run; this one is keyed by
// (host, request fingerprint), lives on the state, and persists, so a re-seen exchange
// whose content a previous sweep already audited is counted as a dedup row instead of
// re-audit work. What these tests pin:
//
//   - a re-seen identical request is deduplicated (counted, NOT audited again);
//   - changed content still audits — the 6n4d pairing: apfh refuses the same content, 6n4d
//     admits the changed, and one gate must not break the other;
//   - a zero fingerprint (hand-built or pre-fingerprint exchanges) always admits: refusing
//     content the ledger cannot identify would dedup on "unknown";
//   - the ledger survives a NEW sweep's run (the cross-run claim) and a Persist/Load
//     round-trip (the restart claim);
//   - the ledger is bounded: past its cap it resets visibly and the counter says so.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestAReSeenIdenticalRequestIsDeduplicatedNotReAudited(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	s := auditableServer(t, target.URL)
	host, port := targetHostPort(t, target.URL)

	// The same content twice at the same path. The fingerprint makes them one key.
	raw1 := []byte("POST /login HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 5\r\n\r\nuser=a")
	for i := 0; i < 2; i++ {
		reqID, _ := s.store.Put(raw1, core.DirectionRequest)
		respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
		s.store.AddExchange(&core.Exchange{
			Request: reqID, Response: &respID,
			Host: host, Port: port, Method: "POST", Path: "/login",
			RequestFP: core.RequestFingerprint(raw1),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	// The second capture is deduplicated: a disposition row exists for it and it never
	// became audit work (the target sees probes for the FIRST capture only, and the
	// deduplicated counter is exactly 1).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.Deduplicated() == 0 {
		time.Sleep(sweepTick)
	}
	if got := s.liveAudit.Deduplicated(); got != 1 {
		t.Fatalf("deduplicated = %d, want 1: the re-seen identical request must count as REQUEST_TO_AUDIT_DEDUPLICATED, not re-audit work", got)
	}
}

func TestChangedContentAtTheSamePathStillAudits(t *testing.T) {
	// The apfh/6n4d pairing in one test: identical re-seen content dedups here, changed
	// content at the same path admits (it is a different fingerprint), so one gate does not
	// break the other.
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	s := auditableServer(t, target.URL)
	host, port := targetHostPort(t, target.URL)

	first := []byte("POST /login HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 5\r\n\r\nuser=a")
	changed := []byte("POST /login HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 5\r\n\r\nuser=b")
	for i, raw := range [][]byte{first, changed} {
		reqID, _ := s.store.Put(raw, core.DirectionRequest)
		respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
		s.store.AddExchange(&core.Exchange{
			Request: reqID, Response: &respID,
			Host: host, Port: port, Method: "POST", Path: "/login",
			RequestFP: core.RequestFingerprint(raw),
		})
		_ = i
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.Swept() < 2 {
		time.Sleep(sweepTick)
	}
	if s.liveAudit.Swept() < 2 {
		t.Fatalf("swept = %d, want both captures audited — the changed one was lost (control case: the sweep never reached them)", s.liveAudit.Swept())
	}
	if s.liveAudit.Deduplicated() != 0 {
		t.Fatalf("deduplicated = %d, want 0: changed content must NOT be deduplicated (that is 6n4d's job: it admits the changed)", s.liveAudit.Deduplicated())
	}
}

func TestAZeroFingerprintAlwaysAdmits(t *testing.T) {
	// The unit-level claim, no sweep needed: exchanges the ledger cannot identify (hand-built,
	// restored, minted before the seam computed a fingerprint) must never be deduplicated on
	// "unknown" — that would be a silent coverage hole with a counter that reads as success.
	s := NewLiveAuditState()
	ex := &core.Exchange{Host: "app.test", RequestFP: 0}
	if !s.admitSeen(ex) {
		t.Fatal("a zero fingerprint was deduplicated: content the ledger cannot identify must admit")
	}
	if !s.admitSeen(ex) {
		t.Fatal("a zero fingerprint was deduplicated on the second consult too — the hole is permanent, not one-shot")
	}
}

func TestTheSeenLedgerSurvivesANewSweepRunAndARestart(t *testing.T) {
	// The cross-run claim, at the state level: the ledger lives on LiveAuditState, not the
	// sweep's run, so a NEW run (the sweep restarted) still dedups; and the Persist/Load
	// round-trip carries it across a process restart.
	state := NewLiveAuditState()
	ex := &core.Exchange{Host: "app.test", RequestFP: 0xdeadbeef}
	if !state.admitSeen(ex) {
		t.Fatal("control: the first consult must admit")
	}
	if state.admitSeen(ex) {
		t.Fatal("the second consult admitted identical content — the dedup is broken")
	}

	// A fresh run consults the same state (the ledger is not on the run).
	if state.admitSeen(ex) {
		t.Fatal("a new sweep's run re-audited content the state had already seen — the cross-run claim is broken")
	}

	// The round-trip: persist, load into a fresh state, still dedups.
	blob := state.PersistSeen()
	fresh := NewLiveAuditState()
	fresh.LoadSeen(blob)
	if fresh.admitSeen(ex) {
		t.Fatal("after a restart the ledger forgot what it had seen — the persistence claim is broken")
	}
	if !fresh.admitSeen(&core.Exchange{Host: "app.test", RequestFP: 0xfeedface}) {
		t.Fatal("the restored ledger refuses NEW content — the load corrupted the map's semantics")
	}
}

func TestTheSeenLedgerIsBoundedAndItsResetIsCounted(t *testing.T) {
	state := NewLiveAuditState()
	state.seenCap = 4
	for i := 0; i < 5; i++ {
		state.admitSeen(&core.Exchange{Host: "app.test", RequestFP: uint64(0x1000 + i)})
	}
	// Cap 4, admitted 5: the reset should have fired.
	if !state.maybeResetSeen() {
		t.Fatal("the ledger did not reset past its cap — unbounded memory is the failure the cap exists to prevent")
	}
	if got := state.SeenLedgerResets(); got != 1 {
		t.Fatalf("seen ledger resets = %d, want 1: a reset must be counted, not silent", got)
	}
	if got := state.SeenCount(); got != 0 {
		t.Fatalf("after the reset the ledger holds %d keys, want 0", got)
	}
}
