package crawler

import (
	"net/url"
	"testing"
)

// Burp's distinct crawl events (burpsy-react-ui-ai64, burp/Zwkv.java) that were folded into one skip.

func TestAnOutOfScopeAPILocationAndASeedRedirectAreTheirOwnEvents(t *testing.T) {
	h := newHarness()
	h.scope.AddInclude("in.test")
	c, err := New(h.config("http://in.test/"))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("http://in.test/openapi.json")
	rep, lim := &Report{}, &LimitReport{}
	c.admit(discoveredLink{raw: "http://out.test/users", tag: "api:openapi"}, base, 1, rep, lim)
	c.admit(discoveredLink{raw: "http://out.test/login", tag: "redirect"}, base, 1, rep, lim) // from a seed
	c.admit(discoveredLink{raw: "http://out.test/later", tag: "redirect"}, base, 3, rep, lim) // from a deep page
	c.admit(discoveredLink{raw: "http://out.test/page", tag: "a"}, base, 2, rep, lim)

	snap := c.skips.Snapshot()
	for reason, want := range map[Skip]uint64{
		SkipAPILocationOutOfScope:    1,
		SkipSeedRedirectedOutOfScope: 1,
		SkipOutOfScope:               2, // the deep redirect and the anchor
	} {
		if got := snap.Count(reason); got != want {
			t.Errorf("%s = %d, want %d", reason.String(), got, want)
		}
	}
}

func TestWSDLFailuresAreNamedApartFromAPIDefinitionFailures(t *testing.T) {
	const truncated = `<?xml version="1.0"?><definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
	<binding name="B"><operation name="GetUser"><soap:operation soapAction="urn:GetUser"/></operation><operation name="Broken`
	const empty = `<?xml version="1.0"?><definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><types/></definitions>`
	for _, c := range []struct {
		name, body string
		want       Skip
	}{{"truncated", truncated, SkipWSDLInvalid}, {"empty", empty, SkipWSDLNoOperations}} {
		srv := sitemapTarget(t, map[string]servedPage{
			"/":             {`<html><body><a href="/service.wsdl">wsdl</a></body></html>`, "text/html"},
			"/service.wsdl": {c.body, "text/xml"},
		})
		h := newHarness()
		cfg := h.config(srv.URL + "/")
		cfg.ParseSOAPWSDLs = true
		cfg.ParseAPIDefinitions = true
		rep := run(t, cfg)
		if !skippedWith(rep, c.want) || skippedWith(rep, SkipAPIUnparsed) {
			var nz []string
			for _, sc := range rep.Skips.Counts {
				if sc.Count > 0 {
					nz = append(nz, sc.Name)
				}
			}
			t.Errorf("%s WSDL: want %s and not api-unparsed; non-zero %v; fetched %v; api docs %d", c.name, c.want.String(), nz, fetchedPaths(rep), rep.APIDocumentsRead)
		}
	}
}

// An HTML page that links to a WSDL and mentions OpenAPI is still an HTML page: its links are walked.
// Before ai64 it was consumed as an API definition and its links were never followed.
func TestAnHTMLPageThatMentionsWSDLOrOpenAPIIsStillWalked(t *testing.T) {
	srv := sitemapTarget(t, map[string]servedPage{
		"/":      {`<html><body><p>Our openapi docs and WSDL.</p><a href="/service.wsdl">wsdl</a><a href="/about">about</a></body></html>`, "text/html"},
		"/about": {`<html><body>about</body></html>`, "text/html"},
	})
	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.ParseSOAPWSDLs, cfg.ParseAPIDefinitions = true, true
	rep := run(t, cfg)
	if fetchedPaths(rep)["/about"] == 0 {
		t.Errorf("the HTML page's links were not walked: %v", fetchedPaths(rep))
	}
	if rep.APIDocumentsRead != 0 {
		t.Errorf("an HTML page was read as an API definition (%d)", rep.APIDocumentsRead)
	}
}
