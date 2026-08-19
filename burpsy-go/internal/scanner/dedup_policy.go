package scanner

import "github.com/burpsy-go/burpsy/internal/core"

// DedupPolicy derives core's per-catalog-row deduplication tuning from the check registry.
//
// core.FindingStore merges a new finding into an existing one when both are the same catalog row at
// the same target, and it needs to know, per row, what "the same target" means. That knowledge
// already exists here: a descriptor's DispatchScope says how often the check is meant to run.
//
//   - DispatchScopePerHost -> the row is a property of the host. "Strict transport security not
//     enforced" is true of an origin, not of a URL, and the passive path re-derives it from every
//     response, so at path granularity one host would accumulate one identical finding per captured
//     URL. These merge on the origin alone.
//   - every other scope -> the row is a property of an endpoint. Reflected XSS on /search and on
//     /login are different issues and must stay different findings, so the path is in the key.
//
// core cannot import scanner (scanner imports core), so this is handed in via
// core.FindingStore.SetDedupPolicy at each composition root rather than looked up. A build that
// forgets to wire it still dedups, just at path granularity for every row — the direction that only
// ever under-merges.
//
// The Exempt set adds the four provenance rows to core's built-in exemptions. Those two lists are
// split deliberately: core's are a correctness floor a missing policy cannot switch off, and these
// are a fact about this port's catalog that only this package knows.
func DedupPolicy() *core.DedupPolicy {
	// The provenance rows are not issue classes, they are labels for who filed the finding (see
	// provenanceRows). Their name carries none of what the finding is about, so two unrelated BChecks
	// firing at one target would merge into a single "BCheck generated issue" and the second one's
	// substance would be gone. Every other row's name identifies the issue; these four identify the
	// author, and deduplicating by author is not deduplication.
	//
	// Burp's own exemption gate has a third clause beyond the two issue types core carries — a
	// fingerprint compared against a string constant (Zbvp.java:62) that the obfuscator stripped. What
	// it named is unrecoverable, so this is not a claim to have matched it; it is this port's own
	// reading of which rows cannot survive a merge.
	exempt := make(map[string]bool, len(provenanceRows))
	for _, name := range provenanceRows {
		exempt[name] = true
	}
	// Built after the exemptions so an exempt row cannot also appear here. core checks Exempt first,
	// so listing a row in both would be harmless but would state two different things about it.
	hostScoped := make(map[string]bool)
	for _, d := range NativeCheckRegistry() {
		if d.Scope == DispatchScopePerHost && !exempt[d.Name] {
			hostScoped[d.Name] = true
		}
	}
	return &core.DedupPolicy{HostScoped: hostScoped, Exempt: exempt}
}
