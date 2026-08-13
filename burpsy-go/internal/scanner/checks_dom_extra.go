package scanner

// The three DOM-family rows that are not a source-to-sink flow, and therefore cannot be
// expressed through domFamilies:
//
//   - Client-side prototype pollution: the finding is a write to Object.prototype, which has
//     no per-variant spelling in the catalog and is confirmed in two tiers (goja and a real
//     browser) rather than one.
//   - Client-side template injection: proved by an arithmetic expression being *rendered*, not
//     by a value reaching a named sink.
//   - Path-relative style sheet import: a page-structure condition, not a runtime flow.

import (
	"context"
	"fmt"
	"net/url"
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
		"a URL-controlled value names a property written onto Object.prototype, which every object in the page then inherits")}, nil
}

// templateInjectionMarkers are the delimiter families a client-side template engine evaluates.
// The product, not the expression, is what proves evaluation.
func templateInjectionMarkers() []string {
	arith := fmt.Sprintf("%d*%d", ArithmeticProofLeft, ArithmeticProofRight)
	return []string{
		"{{" + arith + "}}",
		"${" + arith + "}",
		"{{" + arith + "}}{{",
		"[[" + arith + "]]",
	}
}

// checkClientSideTemplateInjection plants a template expression in a URL source and looks for
// its product in the rendered DOM.
//
// The check is on the *rendered* markup because a client-side template engine evaluates after
// script runs; the served HTML never contains the product, which is exactly why an HTTP-only
// scanner cannot see this row at all.
func checkClientSideTemplateInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Exchange == nil {
		return nil, nil
	}
	browser, err := cc.Browser(ctx)
	if err != nil {
		return nil, err
	}
	base := exchangeURL(cc.Exchange)
	product := ArithmeticProofProduct()

	// The baseline rendering decides whether the product was already on the page. Without
	// it a page that legitimately displays "42" would report every payload as evaluated.
	baseline, err := browser.RenderedDOM(ctx, base)
	if err != nil {
		return nil, err
	}
	if strings.Contains(baseline, product) {
		return nil, nil
	}

	for _, marker := range templateInjectionMarkers() {
		target := base + "#" + url.QueryEscape(marker)
		rendered, err := browser.RenderedDOM(ctx, target)
		if err != nil {
			continue
		}
		// The marker itself must not be what matched: a page echoing the expression
		// verbatim has not evaluated it.
		if !strings.Contains(rendered, product) || strings.Contains(rendered, marker) {
			continue
		}
		return []*Finding{buildHeaderFinding(cc, "Client-side template injection", "high", "firm",
			marker,
			fmt.Sprintf("the expression %q was evaluated by a client-side template engine and rendered as %s", marker, product))}, nil
	}
	return nil, nil
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
		nativeDescriptor("Client-side prototype pollution", DispatchScopePerUrl, domChecksEnabled, checkClientSidePrototypePollution),
		nativeDescriptor("Client-side template injection", DispatchScopePerUrl, domChecksEnabled, checkClientSideTemplateInjection),
		nativeDescriptor("Path-relative style sheet import", DispatchScopePerUrl, passiveAnalysisEnabled, checkPathRelativeStyleSheetImport),
	}
}
