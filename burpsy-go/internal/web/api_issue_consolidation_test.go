package web

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

func dupFinding(task uint64) core.NewFinding {
	return core.NewFinding{
		Name: "Reflected XSS", Severity: core.SeverityHigh, TaskID: task,
		Target: core.FindingTarget{Host: "t.test", Port: 80, Path: "/s"},
	}
}

// burpsy-react-ui-oorl: the default merges and says so — per run — and an unset policy marshals its
// override map as {} rather than null (a nil map reaches the console as null and breaks .length-style
// reads there; Go tests cannot see that from the struct).
func TestIssueConsolidationReportsWhatEachRunMerged(t *testing.T) {
	s := newTestServer()
	s.findings.Add(dupFinding(7))
	s.findings.Add(dupFinding(7))
	s.findings.Add(dupFinding(7))

	rec := get(t, s, "/api/issues/consolidation")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"default":"keep_existing"`, `"per_row":{}`, `"never_merge":[`} {
		if !strings.Contains(body, want) {
			t.Errorf("GET consolidation lacks %s: %s", want, body)
		}
	}
	var v consolidationView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Tally.Merged != 2 || len(v.ByTask) != 1 || v.ByTask[0].TaskID != 7 || v.ByTask[0].Merged != 2 {
		t.Errorf("tallies = %+v by task %+v; want 2 merges under run 7", v.Tally, v.ByTask)
	}

	issues := get(t, s, "/api/issues")
	if !strings.Contains(issues.Body.String(), `"merged_count":2`) {
		t.Errorf("/api/issues does not carry the merge count: %s", issues.Body.String())
	}
}

// A PUT validates every action, applies to findings filed after it, and survives a restart with the
// project.
func TestIssueConsolidationIsValidatedAppliedAndSavedWithTheProject(t *testing.T) {
	s := newTestServer()
	if rec := putJSON(t, s, "/api/issues/consolidation", map[string]any{"default": "keep_maybe"}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown default = %d, want 400", rec.Code)
	}
	if rec := putJSON(t, s, "/api/issues/consolidation", map[string]any{"default": "keep_existing", "per_row": map[string]string{"X": "nope"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown override = %d, want 400", rec.Code)
	}

	dir := t.TempDir()
	store, err := persist.Open(filepath.Join(dir, "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s2 := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(store)
	rec := putJSON(t, s2, "/api/issues/consolidation", map[string]any{
		"default": "keep_existing", "per_row": map[string]string{"Reflected XSS": "keep_both"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	s2.findings.Add(dupFinding(1))
	s2.findings.Add(dupFinding(1))
	if n := s2.findings.Count(); n != 2 {
		t.Errorf("keep_both override filed %d findings, want 2", n)
	}
	store.Close()

	reopened, err := persist.Open(filepath.Join(dir, "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s3 := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(reopened)
	if got := s3.findings.Consolidation().PerRow["Reflected XSS"]; got != core.ConsolidateKeepBoth {
		t.Errorf("the override did not survive the restart: %q", got)
	}
	// And a finding store swapped in later inherits it.
	s3.WithFindings(core.NewFindingStore())
	if got := s3.findings.Consolidation().PerRow["Reflected XSS"]; got != core.ConsolidateKeepBoth {
		t.Errorf("a swapped-in finding store lost the policy: %q", got)
	}
}
