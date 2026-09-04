package scanner

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/advisory"
	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// ---- one condition, one finding, one severity -------------------------------------------
//
// BURP_PARITY_GAP_ANALYSIS.md §3.0.3b: grouping /api/issues by (url, advisory.type_index)
// showed `005009a0` arriving twice on the same URL — once as `Low | Missing X-Frame-Options
// Header` and once as `Informational | Frameable response (potential Clickjacking)`.
//
// Two producers of the same condition:
//
//   - PassiveScanner.checkSecurityHeaders emitted "Missing X-Frame-Options Header" whenever
//     the header was absent, at severity low.
//   - checkFrameableResponse emits "Frameable response (potential Clickjacking)" at info,
//     using IsFrameable, which also honours a CSP frame-ancestors directive.
//
// advisory/aliases.go maps the first name onto the second's catalogue entry (0x005009a0), so
// both land on one type_index at two severities. Counts inflate and one condition splits
// across two severity buckets, which corrupts any triage that sorts or totals by severity.
//
// The legacy check was not merely redundant. It was also *wrong* in a case the native one
// gets right, which is what settled which of the two to remove rather than which to keep.

func frameableExchange(t *testing.T, store *core.TrafficStore, respHeaders string) *core.Exchange {
	t.Helper()
	reqID, err := store.Put([]byte("GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + respHeaders + "\r\n<html><body>hi</body></html>"
	respID, err := store.Put([]byte(resp), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{
		Request:  reqID,
		Response: &respID,
		Host:     "example.test",
		Port:     80,
		Method:   "GET",
		Path:     "/page",
	}
	store.AddExchange(ex)
	return ex
}

// The false positive that decided the fix.
//
// A response protected by `Content-Security-Policy: frame-ancestors 'none'` and no
// X-Frame-Options is NOT frameable — CSP frame-ancestors supersedes the older header, which
// is why IsFrameable consults both. The legacy check only asked whether the header string was
// present, so it reported a clickjacking exposure on a site that had correctly defended
// against clickjacking by the modern mechanism.
func TestCSPFrameAncestorsIsNotReportedAsAMissingHeader(t *testing.T) {
	store := core.NewTrafficStore()
	ex := frameableExchange(t, store, "Content-Security-Policy: frame-ancestors 'none'\r\n")

	findings := NewPassiveScanner(store, zap.NewNop()).Scan(ex)

	for _, f := range findings {
		if strings.Contains(f.Name, "X-Frame-Options") {
			t.Fatalf("reported %q at severity %q on a response defended by CSP frame-ancestors. "+
				"IsFrameable treats frame-ancestors as protection; a check that only looks for the "+
				"header contradicts it and reports an exposure that does not exist.", f.Name, f.Severity)
		}
	}
	// Sanity: the fixture is a real response and the scanner did look at it, so an empty
	// result here would mean the test proves nothing.
	if len(findings) == 0 {
		t.Log("no passive findings at all for this fixture; the assertion above is vacuous if " +
			"checkSecurityHeaders stopped running entirely — verify against the sibling test")
	}
}

// The duplicate itself: a genuinely frameable response must not produce two findings that
// resolve to the same catalogue entry.
//
// Resolution goes through the real alias table rather than a hard-coded index, because the
// aliasing is the mechanism that created the collision — asserting against a literal
// 0x005009a0 would pass even if the alias were repointed.
//
// # It must aggregate both scan paths, or it proves nothing
//
// The first version of this test scanned only through `PassiveScanner.Scan` and passed
// against the unfixed code, because the two producers live on *different* paths:
// `checkSecurityHeaders` is reached by the passive scanner, and `checkFrameableResponse` is a
// native registry descriptor reached by the audit engine. Neither path alone shows the
// duplicate; `/api/issues` shows it because it aggregates what both produced for one URL.
//
// So this collects from both and groups the union, which is the thing the operator actually
// sees. A test that reproduced only half of a two-path defect and passed would have been a
// worked example of this report's own thesis.
func TestOneFrameableConditionResolvesToOneAdvisoryOnce(t *testing.T) {
	cat, err := advisory.Load()
	if err != nil {
		t.Fatalf("advisory.Load: %v", err)
	}

	store := core.NewTrafficStore()
	// No X-Frame-Options and no CSP: genuinely frameable, so both producers have grounds.
	ex := frameableExchange(t, store, "")

	all := NewPassiveScanner(store, zap.NewNop()).Scan(ex)

	native, err := checkFrameableResponse(t.Context(), NewCheckContext(NewActiveScanner(store, zap.NewNop()), ex, ex))
	if err != nil {
		t.Fatalf("checkFrameableResponse: %v", err)
	}
	if len(native) == 0 {
		t.Fatal("checkFrameableResponse found nothing on a response with no X-Frame-Options and " +
			"no CSP; the fixture is not frameable and this test cannot see the duplicate")
	}
	all = append(all, native...)

	// Every finding that resolves to the frameable advisory, counted by the index it resolves
	// to rather than by its name — two different names on one index is exactly the defect.
	byIndex := map[int][]string{}
	for _, f := range all {
		// Resolve, not ByName: Resolve is what api_capture.go:502 calls when building the
		// issues view, and it consults the alias table. ByName only sees the catalogue's own
		// definition names, so it never resolves "Missing X-Frame-Options Header" at all — which
		// is why the first draft of this test could not see the collision it was written for.
		if def, _ := cat.Resolve(f.Name); def != nil {
			byIndex[def.TypeIndex] = append(byIndex[def.TypeIndex], f.Name+"("+f.Severity+")")
		}
	}
	frameable, _ := cat.Resolve("Frameable response (potential Clickjacking)")
	if frameable == nil {
		t.Fatal("the catalogue has no Frameable response entry; the alias table cannot be checked")
	}
	if got := byIndex[frameable.TypeIndex]; len(got) > 1 {
		t.Fatalf("advisory %d reported %d times from one passive scan: %v. One condition must "+
			"produce one finding at one severity, or issue counts inflate and triage that sorts "+
			"by severity sees the same problem in two buckets.", frameable.TypeIndex, len(got), got)
	}
}

// The other two headers in checkSecurityHeaders have no native equivalent, so removing the
// X-Frame-Options branch must not take them with it. Without this, "delete the function"
// would satisfy both tests above while silently dropping two real checks.
func TestTheOtherSecurityHeaderChecksSurvive(t *testing.T) {
	store := core.NewTrafficStore()
	ex := frameableExchange(t, store, "")

	findings := NewPassiveScanner(store, zap.NewNop()).Scan(ex)

	var sawContentType, sawCSP bool
	for _, f := range findings {
		if strings.Contains(f.Name, "X-Content-Type-Options") {
			sawContentType = true
		}
		if strings.Contains(f.Name, "Content-Security-Policy") {
			sawCSP = true
		}
	}
	if !sawContentType {
		t.Error("Missing X-Content-Type-Options Header is gone; it has no native replacement " +
			"and removing the X-Frame-Options branch must not remove its siblings")
	}
	if !sawCSP {
		t.Error("the Content-Security-Policy finding is gone; same reasoning")
	}
}
