// GET /api/scanner/issue-types: the issue catalogue as the per-issue selection sees it
// (burpsy-react-ui-saq3.3.1).
//
// A scan configuration's selection is a list of catalogue type indexes and (type, method) pairs, and
// an operator choosing them needs the other side of that join: every type by NAME, the detection
// methods Burp defines for it, and which of those burpsy actually runs. /api/advisories is not that
// source. It serves the advisory catalogue, which may not be loaded at all, spells indexes as hex
// strings and carries no methods; this one is scanner.All() — the table the write side validates
// against — so the console cannot offer a type or method the save would refuse.
package web

import (
	"net/http"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

// issueTypeView is one catalogue row as the selection editor reads it.
type issueTypeView struct {
	// TypeIndex is a number, the spelling issue_types and disabled_issue_types use, so the console
	// joins on it without converting.
	TypeIndex       uint32 `json:"type_index"`
	Name            string `json:"name"`
	TypicalSeverity string `json:"typical_severity"`
	// DetectionMethods are Burp's methods for the type, in Burp's order; [] for a type Burp selects
	// by type alone, which a deny entry naming a method for it would be refused for.
	DetectionMethods []string `json:"detection_methods"`
	// ImplementedMethods is the subset burpsy runs. A method in the first list and not this one can
	// be switched off (Burp's file means something by it) and never runs here when switched on.
	ImplementedMethods []string `json:"implemented_methods"`
}

// handleScannerIssueTypes serves the catalogue rows, in type-index order.
func (s *Server) handleScannerIssueTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	all := scanner.All()
	rows := make([]issueTypeView, 0, len(all))
	for _, d := range all {
		methods := scanner.BurpDetectionMethods(d.TypeIndex)
		if methods == nil {
			methods = []string{}
		}
		rows = append(rows, issueTypeView{
			TypeIndex:          d.TypeIndex,
			Name:               d.Name,
			TypicalSeverity:    d.TypicalSeverity,
			DetectionMethods:   methods,
			ImplementedMethods: scanner.ImplementedDetectionMethods(d.TypeIndex),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issue_types": rows,
		"count":       len(rows),
	})
}
