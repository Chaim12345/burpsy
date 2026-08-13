package scanner

import "testing"

// TestDeclinedCatalogDescriptors asserts the contract for every declined catalog descriptor:
//   - each is a valid (ImplementationDeclined) row;
//   - no TypeIndex collides with the already-claimed native, HeaderChecks, or CacheChecks types;
//   - the partition of the 183-entry catalog is exhaustive (7 native + 6 HeaderChecks + 4
//     CacheChecks + 9 Main + bcheck-matched + this function) and sums to exactly 183.
func TestDeclinedCatalogDescriptors(t *testing.T) {
	// TypeIndex values claimed by other parts of the batch. If any of these change, the
	// coordinating session's aggregate registry would collide; surface it loudly here.
	claimedNative := map[uint32]string{
		1049088: "SQL injection",
		1049344: "File path traversal",
		2097920: "Cross-site scripting (reflected)",
		2099459: "JWT weak HMAC secret",
		5243008: "Vulnerable JavaScript dependency",
	}
	claimedHeader := map[uint32]string{
		2098439: "Content security policy: allows clickjacking",
		2098441: "Content security policy: not enforced",
		2098689: "Cross-origin resource sharing: arbitrary origin trusted",
		2098690: "Cross-origin resource sharing: unencrypted origin trusted",
		2098691: "Cross-origin resource sharing: all subdomains trusted",
		4196864: "Duplicate cookies set",
	}
	// claimedCache lost HTTP request smuggling and Client-side desync to the final bucket,
	// which owns them now that they run on SendPipelined.
	claimedCache := map[uint32]string{
		2097536: "Web cache poisoning",
		2098768: "Web cache deception",
	}
	// claimedMain shrank when the DOM tranche landed: the six DOM/JS-injection spellings it
	// used to own are now claimed by claimedDOM, derived from DOMCheckDescriptors.
	// claimedMain is now empty: its three remaining rows moved to the stored bucket
	// (SQL injection (second order), Cross-site scripting (stored)) and the DOM-extra bucket
	// (Client-side template injection) when those tranches were wired.
	claimedMain := map[uint32]string{}
	claimedReflection := map[uint32]string{
		4197376: "Input returned in response (reflected)",
		5243136: "Open redirection (reflected)",
		5246979: "Link manipulation (reflected)",
		2097664: "HTTP response header injection",
		1052672: "Unidentified code injection",
		1052928: "SSI injection",
	}
	claimedDiscovery := map[uint32]string{
		1049216: "ASP.NET tracing enabled",
		1050624: "ASP.NET debugging enabled",
		2098449: "GraphQL endpoint discovered",
		4194560: "Referer-dependent response",
		4194592: "User agent-dependent response",
		6291672: "Backup file",
		6292992: "Robots.txt file",
		6293760: "OpenAPI definition found (active scan check)",
		1050880: "HTTP PUT method is enabled",
		5245440: "HTTP TRACE method is enabled",
	}

	// bcheck-matched catalog names (corpus BCheck issue name == catalog Name, exact or
	// normalized). Verified by the registry sweep: the corpus contains no BCheck whose
	// metadata.name matches any catalog Name, so this set is empty.
	bcheckMatchedCount := 0
	nativeCount := len(claimedNative)
	headerCount := len(claimedHeader)
	cacheCount := len(claimedCache)
	mainCount := len(claimedMain)
	reflectionCount := len(claimedReflection)
	discoveryCount := len(claimedDiscovery)
	// The passive-posture set is derived from its own descriptor list rather than
	// hand-listed: it is the newest slice and a hand-copied TypeIndex table would drift
	// the moment a row is added there.
	claimedPassive := make(map[uint32]string)
	for _, d := range PassivePostureCheckDescriptors() {
		claimedPassive[d.TypeIndex] = d.Name
	}
	passiveCount := len(claimedPassive)
	claimedAnalysis := make(map[uint32]string)
	for _, d := range PassiveAnalysisCheckDescriptors() {
		claimedAnalysis[d.TypeIndex] = d.Name
	}
	analysisCount := len(claimedAnalysis)
	claimedInjection := make(map[uint32]string)
	for _, d := range InjectionCheckDescriptors() {
		claimedInjection[d.TypeIndex] = d.Name
	}
	injectionCount := len(claimedInjection)
	claimedDOM := make(map[uint32]string)
	for _, d := range DOMCheckDescriptors() {
		claimedDOM[d.TypeIndex] = d.Name
	}
	domCount := len(claimedDOM)
	claimedRemaining := make(map[uint32]string)
	for _, d := range RemainingCheckDescriptors() {
		claimedRemaining[d.TypeIndex] = d.Name
	}
	remainingCount := len(claimedRemaining)
	claimedDOMExtra := make(map[uint32]string)
	for _, d := range DOMExtraCheckDescriptors() {
		claimedDOMExtra[d.TypeIndex] = d.Name
	}
	domExtraCount := len(claimedDOMExtra)
	claimedStored := make(map[uint32]string)
	for _, d := range StoredCheckDescriptors() {
		claimedStored[d.TypeIndex] = d.Name
	}
	storedCount := len(claimedStored)
	claimedFinal := make(map[uint32]string)
	for _, d := range FinalCheckDescriptors() {
		claimedFinal[d.TypeIndex] = d.Name
	}
	finalCount := len(claimedFinal)

	excluded := make(map[uint32]struct{})
	for ti := range claimedNative {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedHeader {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedCache {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedMain {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedReflection {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedDiscovery {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedPassive {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedAnalysis {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedInjection {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedDOM {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedRemaining {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedDOMExtra {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedStored {
		excluded[ti] = struct{}{}
	}
	for ti := range claimedFinal {
		excluded[ti] = struct{}{}
	}

	descs := DeclinedCatalogDescriptors()

	seen := make(map[uint32]struct{})
	for _, d := range descs {
		if !d.Valid() {
			t.Errorf("declined descriptor %q (TypeIndex %d) is not Valid()", d.Name, d.TypeIndex)
		}
		if d.Implementation != ImplementationDeclined {
			t.Errorf("declined descriptor %q has Implementation %q, want ImplementationDeclined", d.Name, d.Implementation)
		}
		if d.DeclineReason == "" {
			t.Errorf("declined descriptor %q has empty DeclineReason", d.Name)
		}
		if _, dup := seen[d.TypeIndex]; dup {
			t.Errorf("duplicate TypeIndex %d in DeclinedCatalogDescriptors", d.TypeIndex)
		}
		seen[d.TypeIndex] = struct{}{}
		if _, clash := excluded[d.TypeIndex]; clash {
			t.Errorf("declined descriptor %q collides with a claimed TypeIndex %d", d.Name, d.TypeIndex)
		}
	}

	total := nativeCount + headerCount + cacheCount + mainCount + reflectionCount + discoveryCount + passiveCount + analysisCount + injectionCount + domCount + remainingCount + domExtraCount + storedCount + finalCount + bcheckMatchedCount + len(descs)
	if total != 183 {
		t.Fatalf("catalog partition does not sum to 183: native=%d header=%d cache=%d main=%d reflection=%d discovery=%d passive=%d analysis=%d injection=%d dom=%d remaining=%d domextra=%d stored=%d final=%d bcheck=%d declined=%d => %d (delta %d from 183)",
			nativeCount, headerCount, cacheCount, mainCount, reflectionCount, discoveryCount, passiveCount, analysisCount, injectionCount, domCount, remainingCount, domExtraCount, storedCount, finalCount, bcheckMatchedCount, len(descs), total, 183-total)
	}

	// Globally: no TypeIndex in the catalog may be claimed twice across the partition.
	all := make(map[uint32]struct{})
	for ti := range excluded {
		all[ti] = struct{}{}
	}
	for ti := range seen {
		if _, dup := all[ti]; dup {
			t.Errorf("TypeIndex %d appears in both claimed and declined sets", ti)
		}
		all[ti] = struct{}{}
	}
}
