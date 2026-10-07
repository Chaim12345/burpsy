package web

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// exiu item 2: the Issues view carried task_id but not the finding's timestamp, and had no source at
// all. Both were knowable — FindingStore.Add has stamped Timestamp since the beginning, and TaskID
// distinguishes a run from a person — so the wire shape was the only thing missing. Without them the
// issue list is an unordered set of rows from every producer in the project: an operator cannot tell
// which of three tasks raised an issue, cannot separate a manual finding from a scan's, and cannot
// order by when something was found.

type provenanceWire struct {
	Findings []struct {
		ID              uint64 `json:"id"`
		CheckName       string `json:"check_name"`
		TaskID          uint64 `json:"task_id"`
		TimestampUnixMs int64  `json:"timestamp_unix_ms"`
		Source          string `json:"source"`
	} `json:"findings"`
}

func issuesWith(t *testing.T, fs *core.FindingStore) provenanceWire {
	t.Helper()
	s := newTestServer().WithFindings(fs)
	rec := get(t, s, "/api/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/issues: %d", rec.Code)
	}
	var out provenanceWire
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// A finding raised by a run carries that run's id, says so in Source, and reports when it was first
// raised. All three were absent from the wire.
func TestAFindingARunRaisedCarriesWhenAndByWhat(t *testing.T) {
	fs := core.NewFindingStore()
	before := time.Now().UnixMilli()
	fs.Add(core.NewFinding{
		Name:   "Raised by a run",
		TaskID: 7,
		Target: core.FindingTarget{Host: "app.test"},
	})

	var found bool
	for _, f := range issuesWith(t, fs).Findings {
		if f.CheckName != "Raised by a run" {
			continue
		}
		found = true
		if f.TaskID != 7 {
			t.Errorf("task_id = %d, want 7", f.TaskID)
		}
		if f.Source != "scan" {
			t.Errorf("source = %q, want \"scan\": task 7 raised this, and \"the scanner found this\" is the "+
				"claim the operator needs to be able to make", f.Source)
		}
		if f.TimestampUnixMs == 0 {
			t.Fatal("no timestamp on the wire; FindingStore.Add has stamped one since the beginning and the " +
				"view dropped it, so the list is an unordered set of rows from every producer")
		}
		if f.TimestampUnixMs < before-1000 {
			t.Errorf("timestamp = %d, before the Add that raised it at %d", f.TimestampUnixMs, before)
		}
	}
	if !found {
		t.Fatal("the finding is not in the list at all")
	}
}

// A finding no run raised is not a scan's, and the column has to say so — otherwise a recording a
// person added reads identically to something the scanner found, and the two carry different
// follow-ups.
func TestAFindingNoRunRaisedIsReportedAsManual(t *testing.T) {
	fs := core.NewFindingStore()
	fs.Add(core.NewFinding{Name: "Recorded by hand", Target: core.FindingTarget{Host: "app.test"}})

	for _, f := range issuesWith(t, fs).Findings {
		if f.CheckName != "Recorded by hand" {
			continue
		}
		if f.TaskID != 0 {
			t.Errorf("a finding added with no TaskID reports task_id = %d", f.TaskID)
		}
		if f.Source != "manual" {
			t.Errorf("source = %q, want \"manual\": nothing tracked this finding", f.Source)
		}
		if f.TimestampUnixMs == 0 {
			t.Error("a manually added finding carries no timestamp; an operator cannot order the list " +
				"without one")
		}
		return
	}
	t.Fatal("the manually added finding is not in the list")
}

// The two states are actually distinguishable, and a list holding both says so per row. Without this
// the manual test above would pass against a source field hardwired to "manual".
func TestTheTwoProvenancesAreDistinguishableInOneList(t *testing.T) {
	fs := core.NewFindingStore()
	fs.Add(core.NewFinding{Name: "From a run", TaskID: 3, Target: core.FindingTarget{Host: "a.test"}})
	fs.Add(core.NewFinding{Name: "From a person", Target: core.FindingTarget{Host: "b.test"}})

	byName := map[string]string{}
	for _, f := range issuesWith(t, fs).Findings {
		byName[f.CheckName] = f.Source
	}
	if byName["From a run"] != "scan" || byName["From a person"] != "manual" {
		t.Errorf("sources = %v, want From-a-run=scan and From-a-person=manual in the same list", byName)
	}
}

// The projection is the contract, so it is asserted directly too: and the JSON tags are what the
// console reads, so a rename here would silently drop the column rather than fail a build.
func TestTheProvenanceFieldsAreOnTheWireUnderTheNamesTheConsoleReads(t *testing.T) {
	if got := issueSource(&core.Finding{TaskID: 3}); got != "scan" {
		t.Errorf("issueSource with TaskID 3 = %q, want \"scan\"", got)
	}
	if got := issueSource(&core.Finding{}); got != "manual" {
		t.Errorf("issueSource with no TaskID = %q, want \"manual\"", got)
	}
	// A finding whose timestamp is zero reports zero rather than being given a time it never had.
	// Inventing one — "now", or the process start — would put a plausible-looking value in a column
	// an operator orders by.
	if got := int64((&core.Finding{}).Timestamp); got != 0 {
		t.Errorf("a finding with no timestamp reports %d; the projection must not invent one", got)
	}

	b, err := json.Marshal(issueFindingView{TimestampUnixMs: 1234, Source: "scan"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded["timestamp_unix_ms"]; !ok {
		t.Error("timestamp_unix_ms is not on the wire; the console orders the list by it")
	}
	if _, ok := decoded["source"]; !ok {
		t.Error("source is not on the wire; the console filters the list by it")
	}
}
