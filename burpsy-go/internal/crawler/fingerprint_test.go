package crawler

import (
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// TestRequestFingerprintTreatsEquivalentURLsAsOne pins the normalisations the frontier depends on. A
// crawler that queued each of the left-hand pairs twice would double its request count on any page
// that builds links in a non-deterministic order.
func TestRequestFingerprintTreatsEquivalentURLsAsOne(t *testing.T) {
	same := [][2]string{
		{"http://h/a", "http://H/a"},                           // host case
		{"http://h/a", "http://h:80/a"},                        // default port made explicit
		{"https://h/a", "https://h:443/a"},                     // ditto for https
		{"http://h/a?x=1&y=2", "http://h/a?y=2&x=1"},           // query order
		{"http://h/a?csrf=abc", "http://h/a?csrf=def"},         // volatile value
		{"http://h/a?_=111", "http://h/a?_=222"},               // cache buster
		{"http://h/a?sid=1&page=2", "http://h/a?sid=9&page=2"}, // volatile alongside a real parameter
	}
	for _, pair := range same {
		a := requestFingerprint("GET", mustURL(t, pair[0]), nil, "")
		b := requestFingerprint("GET", mustURL(t, pair[1]), nil, "")
		if a != b {
			t.Errorf("%q and %q are the same request but fingerprint differently:\n %s\n %s", pair[0], pair[1], a, b)
		}
	}
}

// TestRequestFingerprintKeepsGenuineDifferences is the other half: a normalisation that merged these
// would silently skip pages, which is worse than crawling one twice.
func TestRequestFingerprintKeepsGenuineDifferences(t *testing.T) {
	different := [][2]string{
		{"http://h/a", "http://h/b"},               // path
		{"http://h/a", "http://h/A"},               // path case is significant on most servers
		{"http://h/a", "https://h/a"},              // scheme
		{"http://h/a", "http://h:8080/a"},          // non-default port
		{"http://h/a?page=1", "http://h/a?page=2"}, // a real parameter's value
		{"http://h/a", "http://h/a?csrf=x"},        // a volatile parameter's *presence*
		{"http://h/a", "http://other/a"},           // host
	}
	for _, pair := range different {
		a := requestFingerprint("GET", mustURL(t, pair[0]), nil, "")
		b := requestFingerprint("GET", mustURL(t, pair[1]), nil, "")
		if a == b {
			t.Errorf("%q and %q are different requests but share fingerprint %s", pair[0], pair[1], a)
		}
	}
	// Method and body are part of the request's identity too.
	u := mustURL(t, "http://h/submit")
	if requestFingerprint("GET", u, nil, "") == requestFingerprint("POST", u, nil, "") {
		t.Error("method must be part of the fingerprint")
	}
	if requestFingerprint("POST", u, []byte("a=1"), "") == requestFingerprint("POST", u, []byte("a=2"), "") {
		t.Error("two submissions with different bodies are different requests")
	}
	if requestFingerprint("POST", u, nil, "") == requestFingerprint("POST", u, []byte("a=1"), "") {
		t.Error("a body's presence must change the fingerprint")
	}
	// The fragment never reaches the server, so it must not be part of the identity. Both sides of
	// this comparison used to be the same fragment-free URL, so it asserted only that the function is
	// deterministic and the property it names went untested.
	if requestFingerprint("GET", mustURL(t, "http://h/a#top"), nil, "") !=
		requestFingerprint("GET", mustURL(t, "http://h/a"), nil, "") {
		t.Error("a fragment never reaches the server and must not change the fingerprint")
	}
}

// TestLocationFingerprintIgnoresEphemeralContent is the reason locations are keyed by contents rather
// than by URL: the two documents below are the same page rendered twice, and every difference between
// them is data.
func TestLocationFingerprintIgnoresEphemeralContent(t *testing.T) {
	base := mustURL(t, "http://h/page")
	// Everything that differs between these two renders is data: the user's name, a timestamp, a CSRF
	// token in a hidden field, and a form input's value. The structure, the form signature and the
	// outgoing link are identical, so they are one location.
	first := []byte(`<html><body>
		<h1>Welcome back, Alice</h1>
		<p>Last seen 2026-08-04 09:11:02</p>
		<form action="/save" method="post">
			<input type="hidden" name="csrf" value="aaa">
			<input name="note" value="hello">
		</form>
		<a href="/next">Next</a>
		</body></html>`)
	second := []byte(`<html><body>
		<h1>Welcome back, Bobby</h1>
		<p>Last seen 2026-08-04 17:44:51</p>
		<form action="/save" method="post">
			<input type="hidden" name="csrf" value="zzz">
			<input name="note" value="something else">
		</form>
		<a href="/next">Next</a>
		</body></html>`)

	a := parsePage(first, base, DefaultLimits(), false)
	b := parsePage(second, base, DefaultLimits(), false)
	if a.fingerprint != b.fingerprint {
		t.Fatalf("the same page rendered twice must be one location:\n %s\n %s", a.fingerprint, b.fingerprint)
	}

	// A genuinely different structure must not collapse into it.
	third := []byte(`<html><body><h1>Welcome back, Alice</h1><table><tr><td>x</td></tr></table></body></html>`)
	if c := parsePage(third, base, DefaultLimits(), false); c.fingerprint == a.fingerprint {
		t.Error("a different page structure must fingerprint differently")
	}
	// A different set of links is a different location, even with identical markup around it.
	fourth := []byte(`<html><body>
		<h1>Welcome back, Alice</h1>
		<p>Last seen 2026-08-04 09:11:02</p>
		<form action="/save" method="post">
			<input type="hidden" name="csrf" value="aaa">
			<input name="note" value="hello">
		</form>
		<a href="/somewhere-else">Next</a>
		</body></html>`)
	if d := parsePage(fourth, base, DefaultLimits(), false); d.fingerprint == a.fingerprint {
		t.Error("a page linking somewhere else is a different location")
	}
}

// TestLocationFingerprintKeepsDetailPagesApart is the load-bearing assertion behind keeping outgoing
// link targets raw. `/users/1` and `/users/2` have the same tag skeleton, the same form signature and
// text of the same order of magnitude. If they merged, a crawl of a fifty-thousand-row table would
// fetch one row, never scan the rest, and report a completed crawl — a silent hole across a whole
// application. Merging is the failure this test exists to prevent.
func TestLocationFingerprintKeepsDetailPagesApart(t *testing.T) {
	page := func(id string) pageStructure {
		return parsePage([]byte(`<html><body>
			<h1>User `+id+`</h1>
			<a href="/users/`+id+`/edit">Edit</a>
			</body></html>`), mustURL(t, "http://h/users/"+id), DefaultLimits(), false)
	}
	one, two := page("1"), page("2")
	if one.fingerprint == two.fingerprint {
		t.Fatal("two detail pages linking to their own edit URLs must not merge into one location")
	}
	// And the same page fetched twice is still one location.
	if page("1").fingerprint != one.fingerprint {
		t.Fatal("fingerprinting must be deterministic for the same document")
	}
}

// TestLocationFingerprintSplitsOnAnEphemeralLinkTarget documents the accepted cost of the rule above.
// A cache-buster inside a *link* splits the page per render. That is the deliberate direction of the
// trade — a false split is a bounded re-fetch that shows up in the counters, a false merge is coverage
// lost invisibly — and the per-template visit quota is what stops the split from running away.
func TestLocationFingerprintSplitsOnAnEphemeralLinkTarget(t *testing.T) {
	base := mustURL(t, "http://h/page")
	a := parsePage([]byte(`<html><body><a href="/next?_=111">Next</a></body></html>`), base, DefaultLimits(), false)
	b := parsePage([]byte(`<html><body><a href="/next?_=222">Next</a></body></html>`), base, DefaultLimits(), false)
	if a.fingerprint == b.fingerprint {
		t.Fatal("this is documented as a false split; if it now merges, the raw-link-target rule was weakened")
	}
	// The frontier's own key does merge them, which is the layer that contains the split.
	if requestFingerprint("GET", mustURL(t, "http://h/next?_=111"), nil, "") !=
		requestFingerprint("GET", mustURL(t, "http://h/next?_=222"), nil, "") {
		t.Fatal("the request fingerprint should normalise a cache-buster away")
	}
}

// TestURLTemplateCollapsesIDSpaces pins the cutoff that actually stops an infinite application: the
// template, which is what the per-template quota counts against.
func TestURLTemplateCollapsesIDSpaces(t *testing.T) {
	same := [][2]string{
		{"http://h/orders/1", "http://h/orders/2"},
		{"http://h/orders/1", "http://h/orders/90000"},
		{"http://h/u/550e8400-e29b-41d4-a716-446655440000", "http://h/u/6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		{"http://h/f/deadbeefcafe1234", "http://h/f/0123456789abcdef"},
		{"http://h/cal?month=1", "http://h/cal?month=2"},
		{"http://h/cal?month=1&year=2026", "http://h/cal?year=2027&month=3"},
	}
	for _, pair := range same {
		a := urlTemplate("GET", mustURL(t, pair[0]), nil, "")
		b := urlTemplate("GET", mustURL(t, pair[1]), nil, "")
		if a != b {
			t.Errorf("%q and %q are one template but differ:\n %s\n %s", pair[0], pair[1], a, b)
		}
	}
	different := [][2]string{
		{"http://h/orders/1", "http://h/invoices/1"},
		{"http://h/orders/1", "http://h/orders/1/items"},
		{"http://h/cal?month=1", "http://h/cal?week=1"},
		{"http://h/a", "http://other/a"},
	}
	for _, pair := range different {
		if urlTemplate("GET", mustURL(t, pair[0]), nil, "") == urlTemplate("GET", mustURL(t, pair[1]), nil, "") {
			t.Errorf("%q and %q are different templates but collapsed together", pair[0], pair[1])
		}
	}
	// A named segment must not be mistaken for an id — merging two sections of an application under
	// one template would apply one quota to both and cut the crawl short invisibly.
	for _, word := range []string{"orders", "administration", "search", "checkout"} {
		if looksLikeID(word) {
			t.Errorf("looksLikeID(%q) = true; a named path segment is not an id", word)
		}
	}
	for _, id := range []string{"1", "0", "99999", "550e8400-e29b-41d4-a716-446655440000", "deadbeefcafe1234"} {
		if !looksLikeID(id) {
			t.Errorf("looksLikeID(%q) = false, want true", id)
		}
	}
	// A form's field names are part of its template: two forms posting different field sets to one
	// action are different shapes.
	u := mustURL(t, "http://h/submit")
	if urlTemplate("POST", u, []string{"a", "b"}, "") == urlTemplate("POST", u, []string{"c"}, "") {
		t.Error("field names must be part of a form submission's template")
	}
	if urlTemplate("POST", u, []string{"a", "b"}, "") != urlTemplate("POST", u, []string{"b", "a"}, "") {
		t.Error("field-name order must not change a template")
	}
}

func TestPortOfFillsInSchemeDefaults(t *testing.T) {
	cases := map[string]uint16{
		"http://h/":         80,
		"https://h/":        443,
		"http://h:8080/":    8080,
		"https://h:8443/":   8443,
		"http://h:notaport": 80,
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			// An unparseable authority is url.Parse's business, not portOf's.
			continue
		}
		if got := portOf(u); got != want {
			t.Errorf("portOf(%q) = %d, want %d", raw, got, want)
		}
	}
}

// TestParsePageHonoursTheBaseElement pins that `<base href>` retargets relative links, since a
// crawler that ignored it would resolve every link on such a page against the wrong origin.
func TestParsePageHonoursTheBaseElement(t *testing.T) {
	page := parsePage(
		[]byte(`<html><head><base href="http://other.example/app/"></head><body><a href="x">x</a></body></html>`),
		mustURL(t, "http://h/page"),
		DefaultLimits(),
		false)
	if len(page.links) != 1 {
		t.Fatalf("expected one link, got %d", len(page.links))
	}
	// The link is stored as written; resolution happens in admit against the same effective base, so
	// what this asserts is that the base element was seen at all — its effect is visible in the
	// fingerprint's targets.
	if page.fingerprint == "" {
		t.Fatal("a parsed page must have a fingerprint")
	}
	without := parsePage(
		[]byte(`<html><head></head><body><a href="x">x</a></body></html>`),
		mustURL(t, "http://h/page"),
		DefaultLimits(),
		false)
	if without.fingerprint == page.fingerprint {
		t.Error("a base element that retargets every link must change the location's skeleton")
	}
}

// TestParsePageBoundsAreCountedNotSilent pins the per-page link bound and the parse-byte bound: both
// drop work, and both must say so.
func TestParsePageBoundsAreCountedNotSilent(t *testing.T) {
	var body []byte
	body = append(body, []byte("<html><body>")...)
	for i := 0; i < 20; i++ {
		body = append(body, []byte(`<a href="/p">x</a>`)...)
	}
	body = append(body, []byte("</body></html>")...)

	page := parsePage(body, mustURL(t, "http://h/"), Limits{MaxLinksPerPage: 5}.normalise(), false)
	if len(page.links) != 5 {
		t.Fatalf("expected the bound of 5 links to be honoured, got %d", len(page.links))
	}
	if page.dropped != 15 {
		t.Fatalf("expected 15 dropped links to be counted, got %d", page.dropped)
	}

	truncated := parsePage(body, mustURL(t, "http://h/"), Limits{MaxParseBytes: 20}.normalise(), false)
	if !truncated.truncated {
		t.Fatal("a body longer than the parse bound must report that it was truncated")
	}
}

// TestFormFieldDefaultsMatchWhatABrowserWouldSend pins the submission-shape decisions, which are the
// difference between a submission the application processes and one it rejects before any of its
// logic runs.
func TestFormFieldDefaultsMatchWhatABrowserWouldSend(t *testing.T) {
	page := parsePage([]byte(`<html><body><form action="/go" method="POST" enctype="application/x-www-form-urlencoded">
		<input type="hidden" name="csrf" value="keep-me">
		<input type="text" name="empty">
		<input type="text" name="prefilled" value="theirs">
		<input type="email" name="mail">
		<input type="number" name="qty">
		<input type="checkbox" name="on" value="1" checked>
		<input type="checkbox" name="off" value="1">
		<input type="radio" name="pick" value="a">
		<select name="choice"><option value="first">First</option><option value="second">Second</option></select>
		<textarea name="note"></textarea>
		<input type="file" name="upload">
		<input type="submit" name="do" value="Send">
		</form></body></html>`), mustURL(t, "http://h/"), DefaultLimits(), false)

	if len(page.forms) != 1 {
		t.Fatalf("expected one form, got %d", len(page.forms))
	}
	f := page.forms[0]
	if f.method != "POST" {
		t.Errorf("method %q, want POST", f.method)
	}
	if !f.hasFileInput {
		t.Error("a file input must be recorded, since a urlencoded submission cannot carry one")
	}
	got := map[string]string{}
	for _, fl := range f.fields {
		got[fl.name] = fl.value
	}
	want := map[string]string{
		"csrf":      "keep-me",
		"empty":     fillerText,
		"prefilled": "theirs",
		"mail":      "burpsy@example.invalid",
		"qty":       "1",
		"on":        "1",
		"choice":    "first",
		"note":      fillerText,
		"do":        "Send",
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("field %q = %q, want %q", name, got[name], value)
		}
	}
	for _, absent := range []string{"off", "pick", "upload"} {
		if _, present := got[absent]; present {
			t.Errorf("field %q must not be submitted: a browser would not send it", absent)
		}
	}
	if f.label != "Send" {
		t.Errorf("form label %q, want the submit control's caption", f.label)
	}
}

func TestIsHTMLTreatsAnAbsentContentTypeAsMarkup(t *testing.T) {
	yes := []string{"", "text/html", "text/html; charset=utf-8", "TEXT/HTML", "application/xhtml+xml"}
	no := []string{"application/json", "image/png", "text/plain", "application/pdf", "text/css"}
	for _, ct := range yes {
		if !isHTML(ct) {
			t.Errorf("isHTML(%q) = false, want true", ct)
		}
	}
	for _, ct := range no {
		if isHTML(ct) {
			t.Errorf("isHTML(%q) = true, want false", ct)
		}
	}
}
