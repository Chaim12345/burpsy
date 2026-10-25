package scanner

// The three DOM-family rows that are not a source-to-sink flow, and therefore cannot be
// expressed through domFamilies:
//
//   - Client-side prototype pollution: the finding is a write to Object.prototype, which has
//     no per-variant spelling in the catalog and is confirmed in two tiers (goja and a real
//     browser) rather than one.
//   - Client-side template injection: proved by a computed value being *rendered*, not by a
//     value reaching a named sink. Its runner lives in checks_csti.go.
//   - Path-relative style sheet import: a page-structure condition, not a runtime flow.

import (
	"context"
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// checkClientSidePrototypePollution confirms a write to Object.prototype driven by a
// URL-borne source.
func checkClientSidePrototypePollution(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Exchange == nil {
		return nil, nil
	}
	obs, err := observeDOM(ctx, cc, []domexec.SourceKind{
		domexec.SourceLocationHash, domexec.SourceLocationSearch,
	})
	if err != nil {
		return nil, err
	}
	hits := domexec.ObservationsForSink(obs, domexec.SinkPrototypePollution)
	if len(hits) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Client-side prototype pollution", "medium", "firm",
		fmt.Sprintf("%s -> Object.prototype[%s]", hits[0].Source, hits[0].Argument),
		"a URL-controlled value names a property written onto Object.prototype, which every object in the page "+
			"then inherits. Exploitation additionally requires a gadget - code that reads the polluted property "+
			"and acts on it. This check looks for the source only and did not search for one, which is the same "+
			"scope Burp reports here before deferring gadget discovery to DOM Invader")}, nil
}

// checkPathRelativeStyleSheetImport reports the PRSSI precondition: a stylesheet referenced by
// a path-relative URL.
//
// The row is a page-structure condition, so it is judged on the served markup. A relative
// stylesheet href means the browser resolves it against whatever path the page was reached at,
// which is what lets an attacker who can add path segments point it at content they control.
// Confirming exploitability additionally needs the server to tolerate appended segments and to
// serve the page with content sniffing available, so the finding is tentative and says so.
func checkPathRelativeStyleSheetImport(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	body := responseBody(responseRaw(cc.Scanner, cc.Exchange))
	if body == "" {
		return nil, nil
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil, nil
	}
	var relative []string
	doc.Find(`link[rel="stylesheet"][href]`).Each(func(_ int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		href = strings.TrimSpace(href)
		// Absolute URLs, protocol-relative URLs and root-relative paths all resolve
		// independently of the page's own path, so none of them carry this defect.
		if href == "" || strings.HasPrefix(href, "/") || strings.HasPrefix(href, "//") ||
			strings.Contains(href, "://") || strings.HasPrefix(href, "data:") {
			return
		}
		relative = append(relative, href)
	})
	if len(relative) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Path-relative style sheet import", "info", "tentative",
		strings.Join(relative, ", "),
		"the page imports a stylesheet by a path-relative URL, so the browser resolves it against the request path. "+
			"Exploitability additionally requires the server to accept appended path segments and the response to be sniffable, neither of which this check probes")}, nil
}

// DOMExtraCheckDescriptors returns the three rows above.
func DOMExtraCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		// The server-side prototype-pollution check (checks_sppj.go, 0vzb.3) rides this row behind
		// its own switch: its finding is burpsy's own row (CWE-1321), and the registry admits one
		// descriptor per Burp catalogue type.
		nativeDescriptor("Client-side prototype pollution", DispatchScopePerUrl,
			func(c *ScanConfig) bool { return domChecksEnabled(c) || sppjEnabled(c) },
			withServerSidePrototypePollution(checkClientSidePrototypePollution)),
		nativeDescriptor("Client-side template injection", DispatchScopePerUrl, domChecksEnabled, checkClientSideTemplateInjection),
		nativeDescriptor("Path-relative style sheet import", DispatchScopePerUrl, passiveAnalysisEnabled, checkPathRelativeStyleSheetImport),
	}
}
