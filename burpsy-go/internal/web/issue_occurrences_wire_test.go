package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// A finding with no resolvable occurrence must still reach the browser as an array
// (burpsy-react-ui-qmlk).
//
// Asserted on the marshalled JSON rather than on the struct, for the reason the intruder report's
// equivalent test gives: Go cannot tell a nil slice from an empty one — same len, same range — so
// the defect exists only on the wire. internal/web/ui/src/lib/types.attack.ts declares
// `occurrences: Occurrence[]` and pages/scanner.tsx:150 reads `.length` on it with no guard,
// inside groupFindings, which runs over every finding on every render. So one `null` here did not
// break one row; it replaced the whole Issues tab with the ErrorBoundary.
func TestAFindingWithNoOccurrencesMarshalsAnArrayNotNull(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())

	// No occurrences at all — the state activeFinding produces when the exchange it would have
	// pointed at is gone, which history's Delete items and Clear made reachable.
	f := &core.Finding{
		ID:       1,
		Name:     "orphaned finding",
		Severity: core.SeverityLow,
	}
	view := srv.findingToIssueView(f)

	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), `"occurrences":null`) {
		t.Fatalf("occurrences went out as null; the page declares it an array and reads .length on it:\n%s", encoded)
	}
	if !strings.Contains(string(encoded), `"occurrences":[]`) {
		t.Fatalf("occurrences is not an empty array:\n%s", encoded)
	}
}
