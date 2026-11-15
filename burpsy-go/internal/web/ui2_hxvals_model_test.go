package web

import (
	"encoding/json"
	"html"
	"regexp"
	"testing"
)

var hxValsRe = regexp.MustCompile(`hx-vals='([^']*)'`)

// hxValsAttr extracts the sentinel hx-vals attribute and JSON-decodes it after HTML attribute
// unescaping, which is what the browser hands to htmx.
func hxValsAttr(t *testing.T, rendered string) map[string]any {
	t.Helper()
	m := hxValsRe.FindStringSubmatch(rendered)
	if m == nil {
		t.Fatalf("no hx-vals attribute in: %s", rendered)
	}
	var vals map[string]any
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &vals); err != nil {
		t.Fatalf("hx-vals is not valid JSON after attribute decoding (%q): %v", m[1], err)
	}
	return vals
}

// The sentinel row's hx-vals must stay valid JSON after HTML attribute decoding, whatever the
// operator typed into filter/search (the quoted-filter breakage).
func TestUI2HistoryHxValsQuotedFilter(t *testing.T) {
	rows := ui2HistoryRows{NextOffset: 50, Limit: 25, HasMore: true, HxVals: ui2HistoryHxVals(50, ui2HistoryParams{Q: `host:"admin" path:'/x'`, Search: `a "quoted" term`, Limit: 25})}
	for _, name := range []string{"history_rows.html", "history_rows_append.html"} {
		vals := hxValsAttr(t, string(ui2Exec(name, rows)))
		if vals["q"] != `host:"admin" path:'/x'` || vals["search"] != `a "quoted" term` || vals["offset"] != 50.0 {
			t.Fatalf("%s round-trip lost the operator text: %v", name, vals)
		}
	}
}

func TestUI2LoggerHxValsQuotedSearch(t *testing.T) {
	model := ui2LoggerModel{NextOffset: 10, Limit: 5, HasMore: true, HxVals: ui2LoggerHxVals(10, 5, `GET "admin"`)}
	for _, name := range []string{"logger.html", "logger_rows_append.html"} {
		vals := hxValsAttr(t, string(ui2Exec(name, model)))
		if vals["search"] != `GET "admin"` || vals["offset"] != 10.0 {
			t.Fatalf("%s round-trip lost the search text: %v", name, vals)
		}
	}
}

func TestUI2HostFromRequestKeepsScheme(t *testing.T) {
	if got := ui2HostFromRequest("GET https://example.com/login?a=1 HTTP/1.1\r\nHost: ignored.example\r\n\r\n"); got != "https://example.com" {
		t.Fatalf("absolute-form scheme dropped: %q", got)
	}
	if got := ui2HostFromRequest("GET http://example.com:8080/x HTTP/1.1\n\n"); got != "example.com:8080" {
		t.Fatalf("http absolute-form wrong: %q", got)
	}
	// Host-header fallback keeps returning a bare authority.
	if got := ui2HostFromRequest("GET /x HTTP/1.1\r\nHost: plain.example:8443\r\n\r\n"); got != "plain.example:8443" {
		t.Fatalf("host header fallback changed: %q", got)
	}
	// The derived target parses to TLS:443, the behavior the ui2 Repeater/Intruder send needs.
	host, port, tls, err := targetParts(ui2HostFromRequest("GET https://example.com/x HTTP/1.1"))
	if err != nil || host != "example.com" || port != 443 || !tls {
		t.Fatalf("scheme-qualified target not honoured: %q %d %v %v", host, port, tls, err)
	}
}
