package scanner

// EnrichFinding fills remediation from Burp's shipped catalog when the check
// supplied none and the issue name is an exact match. Severity is never
// overwritten: the catalog's typical severity describes an issue class, while a
// finding's severity is a judgement about the evidence in hand.
func EnrichFinding(f *Finding) {
	if f == nil || f.Solution != "" {
		return
	}
	if d, ok := ByName(f.Name); ok && d.HasRemediation() {
		f.Solution = d.Remediation
	}
}

// DefinitionFor returns the catalog entry for a finding name, if any.
func DefinitionFor(name string) (IssueDefinition, bool) {
	return ByName(name)
}
