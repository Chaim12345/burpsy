package web

// The web-server half of the weakness-9 fix: WithPersist wires the store's failure hook to
// the dashboard event log — the surface an operator actually watches — so a failed mirror
// write shows up there the moment it happens, and a previous session's recorded failures
// are announced on startup, on the side of the restart where the divergence surfaces.

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

func persistEvents(s *Server) []dash.Event {
	var out []dash.Event
	for _, e := range s.events.Recent(50) {
		if e.Kind == "persist" && e.Severity == dash.SeverityError {
			out = append(out, e)
		}
	}
	return out
}

func TestWithPersistReportsMirrorFailuresOnTheDashboard(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "w9.db")

	// Seed a database whose previous run recorded mirror failures, the way a run that
	// lost writes leaves its marker behind for the next Open.
	p0, err := persist.Open(dbPath, zap.NewNop())
	if err != nil {
		t.Fatalf("Open seed store: %v", err)
	}
	p0.Close()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO settings (key, value) VALUES ('mirror_write_failures', '7')`); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	raw.Close()

	p, err := persist.Open(dbPath, zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := NewServer(core.NewTrafficStore(), core.NewScope())
	s.WithPersist(p)

	has := func(evs []dash.Event, subs ...string) bool {
		for _, e := range evs {
			all := true
			for _, sub := range subs {
				if !strings.Contains(e.Detail, sub) {
					all = false
					break
				}
			}
			if all {
				return true
			}
		}
		return false
	}

	// Startup leg: the previous session's divergence is announced before state restores.
	evs := persistEvents(s)
	if len(evs) != 1 || !has(evs, "previous session", "7") {
		t.Fatalf("startup persist events = %v, want one naming the previous session's 7 failures", evs)
	}

	// Live leg: a write failure right now lands on the same surface the moment it happens.
	// Closing the handle makes the next write fail; the hook must fire regardless.
	p.Close()
	p.SaveFinding(&core.Finding{ID: 1, Name: "test finding"})
	evs = persistEvents(s)
	if len(evs) != 2 || !has(evs, "Durable mirror write failed", "finding") || !has(evs, "previous session", "7") {
		t.Fatalf("persist events after a failed write = %v, want the startup report plus the live failure", evs)
	}
}
