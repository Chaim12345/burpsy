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
}

// NativeCheckCoverage returns stable rows for the current registry. It is a
// registry report, not a claim that any row ran during a scan.
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
