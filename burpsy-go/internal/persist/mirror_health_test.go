package persist

// Regression tests for weakness 9: a failed durable-mirror write used to be one Warn line
// and then silence. These pin the new contract — the failure is counted, first-reported
// through the installed hook the moment it happens, marked in the database, and reported
// again by the next Open, so the divergence is announced on both sides of the restart.

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// injectFindingFailure installs a trigger that fails every findings write while leaving
// the rest of the database — including the settings table the failure marker lives in —
// writable, so the test drives the real Save -> log -> noteWriteFailure path end to end
// rather than simulating it.
func injectFindingFailure(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`CREATE TRIGGER fail_finding_writes BEFORE INSERT ON findings
		BEGIN SELECT RAISE(FAIL, 'injected mirror failure'); END;`); err != nil {
		t.Fatalf("install failing trigger: %v", err)
	}
}

func TestMirrorWriteFailureIsCountedHookedAndMarked(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "w9.db")
	s, err := Open(dbPath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var mu sync.Mutex
	var hookCalls []string
	s.SetWriteFailureHook(func(op string, err error) {
		mu.Lock()
		hookCalls = append(hookCalls, op+": "+err.Error())
		mu.Unlock()
	})

	injectFindingFailure(t, s)
	f := &core.Finding{ID: 1, Name: "test finding"}
	s.SaveFinding(f)
	s.SaveFinding(f)

	h := s.MirrorHealth()
	if h.Failures != 2 {
		t.Fatalf("MirrorHealth().Failures = %d, want 2", h.Failures)
	}
	if h.FirstOp != "finding" {
		t.Errorf("MirrorHealth().FirstOp = %q, want %q", h.FirstOp, "finding")
	}
	if !strings.Contains(h.FirstErr, "injected mirror failure") {
		t.Errorf("MirrorHealth().FirstErr = %q, want the injected failure", h.FirstErr)
	}
	if h.FirstAt.IsZero() || h.LastAt.Before(h.FirstAt) {
		t.Errorf("MirrorHealth() timestamps incoherent: first %v last %v", h.FirstAt, h.LastAt)
	}
	mu.Lock()
	if len(hookCalls) != 2 || !strings.Contains(hookCalls[0], "finding") {
		t.Errorf("hook calls = %v, want one per failure naming the op", hookCalls)
	}
	mu.Unlock()

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The marker is how the NEXT run learns this one diverged. It is rewritten on the
	// first failure and then only every 64th, so a small failure count reads as at least
	// one — the divergence report must never read as a false all-clear.
	s2, err := Open(dbPath, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := s2.PriorSessionMirrorFailures(); got < 1 {
		t.Errorf("PriorSessionMirrorFailures() after a failing run = %d, want >= 1", got)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("Close s2: %v", err)
	}

	// Open clears the marker: a clean run after the failing one reports no prior failures.
	s3, err := Open(dbPath, nil)
	if err != nil {
		t.Fatalf("reopen 2: %v", err)
	}
	if got := s3.PriorSessionMirrorFailures(); got != 0 {
		t.Errorf("PriorSessionMirrorFailures() on a clean reopen = %d, want 0 (marker should be cleared)", got)
	}
	s3.Close()
}

func TestMirrorHealthyRunReportsNoFailures(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "w9-healthy.db"), nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if got := s.MirrorHealth().Failures; got != 0 {
		t.Errorf("MirrorHealth().Failures on a fresh store = %d, want 0", got)
	}
	if got := s.PriorSessionMirrorFailures(); got != 0 {
		t.Errorf("PriorSessionMirrorFailures() on a fresh database = %d, want 0", got)
	}
}
