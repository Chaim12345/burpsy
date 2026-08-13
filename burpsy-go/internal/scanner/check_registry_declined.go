// check_registry_declined.go is where a catalog issue goes when burpsy cannot evaluate it
// honestly. Each row named the missing capability so a clean scan result was never mistaken for
// "we looked and found nothing", while keeping its TypeIndex reserved and its catalog metadata
// intact.
//
// The list is currently empty: all 183 catalog rows have evaluators. The file stays because it
// is the mechanism, not a backlog — the moment a row cannot be answered honestly it belongs
// here rather than quietly absent, and `TestNoDeclineReasonCitesAnAvailablePrimitive` keeps any
// future entry from citing a capability the tree already has.
package scanner

// extendedCoverageEnabled gates every row in this file (and the DOM/stored declines in
// checks_declined_dom.go) behind ScanConfig.CheckExtendedCoverage. A declined issue has no
// individual ScanConfig switch of its own — Java gives most of them none either — so admitting
// them unconditionally would silently change what every existing caller's narrower ScanConfig
// means. With both lists empty the gate currently admits nothing; it remains the correct gate
// for whatever is added next.
func extendedCoverageEnabled(c *ScanConfig) bool { return c != nil && c.CheckExtendedCoverage }

// DeclinedCatalogDescriptors returns the declined rows. Empty today; see the file comment for
// why it is kept.
//
// Scope for a future entry is DispatchScopePerUrl (once per URL) for request/response-driven
// issues, and DispatchScopePerHost for transport, cross-domain policy, and endpoint-discovery
// issues. The honest signal a caller reads for why a row did not run is DeclineReason.
func DeclinedCatalogDescriptors() []CheckDescriptor {
	return []CheckDescriptor{}
}
