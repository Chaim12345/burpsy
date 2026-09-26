package scanner

import "sort"

// CheckCoverageRow is the operator-facing status of one registered check. It
// intentionally reports implementation status separately from execution.
type CheckCoverageRow struct {
	TypeIndex      uint32
	Name           string
	Implementation CheckImplementation
	Phase          CheckPhase
	Scope          DispatchScope
	Runnable       bool
	DeclineReason  string
	// Suppressed reports that this row is runnable but a live per-issue selection would exclude it.
	//
	// It is a third state and the coverage number needs all three: a row that is runnable and
	// selected, a row that is runnable and SUPPRESSED, and a row that is declined outright. A
	// coverage report that cannot say "suppressed" counts the suppressed row as covered, so the
	// number overstates what a run under this configuration would do -- which is the one thing a
	// coverage number is for (burpsy-react-ui-kvmx).
	//
	// Populated only when a selection is in force. With no selection every runnable row is selected,
	// and a report that claimed otherwise would be describing a configuration nobody asked for.
	Suppressed bool
}

// NativeCheckCoverage returns stable rows for the current registry. It is a
// registry report, not a claim that any row ran during a scan.
// NativeCheckCoverageUnder is the coverage report for a run under a specific configuration, so a
// suppressed row can be reported as suppressed.
//
// The selection-aware sibling of NativeCheckCoverage, and the reason the selection is worth having
// at all: a coverage number an operator reads has to be the number for the configuration they are
// about to run, or it is a number about somebody else's run.
func NativeCheckCoverageUnder(cfg ScanConfig) []CheckCoverageRow {
	rows := NativeCheckCoverage()
	if len(cfg.IssueTypes) == 0 {
		return rows
	}
	for i := range rows {
		// A declined row is not "suppressed" — it was never going to run either way, and reporting a
		// second reason for the same absence would be two explanations for one fact.
		rows[i].Suppressed = rows[i].Runnable && !cfg.IsIssueTypeSelected(rows[i].TypeIndex)
	}
	return rows
}

func NativeCheckCoverage() []CheckCoverageRow {
	registry, err := RegistryByTypeIndex(NativeCheckRegistry())
	if err != nil {
		return nil
	}
	rows := make([]CheckCoverageRow, 0, len(registry))
	for _, descriptor := range registry {
		rows = append(rows, CheckCoverageRow{
			TypeIndex:      descriptor.TypeIndex,
			Name:           descriptor.Name,
			Implementation: descriptor.Implementation,
			Phase:          descriptor.Phase,
			Scope:          descriptor.Scope,
			Runnable:       descriptor.Runnable(),
			DeclineReason:  descriptor.DeclineReason,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TypeIndex < rows[j].TypeIndex })
	return rows
}
