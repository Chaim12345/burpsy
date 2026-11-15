package web

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The search page runs /api/search with the form's options and links each hit to a preview
// that marks the matched bytes; the tool list is served even before a search.
func TestUI2SearchFindsAndPreviewsMatch(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nhello NEEDLE!")
	seedUI2Exchange(t, s, "GET /b HTTP/1.1\r\nHost: b.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")

	empty := getUI2(t, s, "/ui2/search").Body.String()
	if !strings.Contains(empty, `name="tool" value="repeater"`) || !strings.Contains(empty, "No search yet") {
		t.Fatalf("blank search lacks the served tool list or empty state")
	}

	body := getUI2(t, s, "/ui2/search?q=needle&location=response&within=body&tool=proxy").Body.String()
	if !strings.Contains(body, "a.test") || strings.Contains(body, "b.test") {
		t.Fatalf("results should list only the matching exchange")
	}
	if !strings.Contains(body, `value="response" selected`) || !strings.Contains(body, `value="proxy" checked`) {
		t.Errorf("form did not round-trip its options")
	}
	m := regexp.MustCompile(`hx-get="(/ui2/search/message/[^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no preview link in results")
	}
	prev := getUI2(t, s, html.UnescapeString(m[1]))
	if prev.Code != http.StatusOK || !strings.Contains(prev.Body.String(), "<mark>NEEDLE</mark>") {
		t.Fatalf("preview = %d, want the match marked: %s", prev.Code, prev.Body.String())
	}

	// Offsets index the raw bytes: invalid UTF-8 before the match must not shift the mark.
	seedUI2Exchange(t, s, "GET /c HTTP/1.1\r\nHost: c.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n\xff\xffTARGETX!")
	bin := getUI2(t, s, "/ui2/search?q=targetx").Body.String()
	if m := regexp.MustCompile(`hx-get="(/ui2/search/message/[^"]+)"`).FindStringSubmatch(bin); m == nil ||
		!strings.Contains(getUI2(t, s, html.UnescapeString(m[1])).Body.String(), "<mark>TARGETX</mark>") {
		t.Errorf("match after invalid UTF-8 bytes was not marked exactly")
	}

	bad := getUI2(t, s, "/ui2/search?q=x&tool=nosuchtool").Body.String()
	if !strings.Contains(bad, "The search did not run") || !strings.Contains(bad, `value="proxy"`) {
		t.Errorf("a refused search must say so and still offer the tool list")
	}
}

func TestUI2DiscoverFiltersAndMapsHotkeys(t *testing.T) {
	s := newTestServer()
	all := html.UnescapeString(getUI2(t, s, "/ui2/discover").Body.String())
	for _, want := range []string{`id="reference-limits"`, `id="reference-query"`, `id="reference-bcheck"`, `id="reference-tool-intercept"`, `id="reference-docs"`, "<kbd>mod+K</kbd>", "Open settings"} {
		if !strings.Contains(all, want) {
			t.Errorf("discover page missing %q", want)
		}
	}
	got := getUI2(t, s, "/ui2/discover?q=append-only").Body.String()
	if !strings.Contains(got, "Deleting captured traffic") || strings.Contains(got, `id="reference-bcheck"`) {
		t.Errorf("q did not filter the reference to the matching rows")
	}
}

// Every example the query panel documents must parse, and every refusal must not.
func TestUI2DiscoverQueryExamplesParse(t *testing.T) {
	s := newTestServer()
	for _, p := range ui2DiscoverPanels {
		for _, b := range p.Blocks {
			if p.ID != "query" || (b.Label != "Examples" && b.Label != "Refused at parse time") {
				continue
			}
			for _, q := range strings.Split(b.Body, "\n") {
				_, err := compileQuery(q, s.store)
				if (err == nil) != (b.Label == "Examples") {
					t.Errorf("%s: %q parse err=%v", b.Label, q, err)
				}
			}
		}
	}
}
