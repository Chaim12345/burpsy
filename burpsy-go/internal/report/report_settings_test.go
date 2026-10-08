package report

import (
	"strings"
	"testing"
)

// The Settings renderer (burpsy-react-ui-a9qy) is Burp's report-settings.html
// wizard made honest: title, organisation, TOC depth, issue-detail sections
// and message inclusion. Zero Settings must mean the report the settings-free
// HTML() has always produced — the parameters widen the report, they do not
// replace it — and every explicit choice must be visible in the document these
// tests assert on.

// settingsRows is three findings chosen so the three organisations disagree:
// two SQL-injection rows (same type) on different URLs and severities, and one
// CSP row on the lower-severity end. A set where every axis sorts the same way
// would pass every ordering test without proving any of them.
func settingsRows() []Row {
	return []Row{
		{
			ID: 1, Name: "SQL injection", Severity: "High", Confidence: "Firm",
			Description: "The q parameter is injectable.", Remediation: "Use parameterised queries.",
			Evidence: []Evidence{{Method: "POST", Host: "shop.test", Path: "/login", Status: 200}},
		},
		{
			ID: 2, Name: "SQL injection", Severity: "Critical", Confidence: "Certain",
			Description: "The sort parameter is injectable.", Remediation: "Use parameterised queries.",
			Evidence: []Evidence{{Method: "POST", Host: "shop.test", Path: "/search", Status: 500}},
		},
		{
			ID: 3, Name: "Missing CSP header", Severity: "Low", Confidence: "Tentative",
			Description: "Response carries no Content-Security-Policy.", Remediation: "Set a CSP header.",
			Evidence: []Evidence{{Method: "GET", Host: "api.test", Path: "/v1", Status: 200}},
		},
	}
}

// By type: one <h2 class="group"> per issue name, in name order, and inside a
// group the worst severity still leads — the reader's eye lands on the
// critical thing first even when the operator asked for a type-grouped report.
func TestTheSettingsReportGroupsByTypeAndKeepsWorstSeverityFirstInsideAGroup(t *testing.T) {
	doc := string(HTMLWithSettings(settingsRows(), Settings{OrganiseBy: "type"}))

	csp := strings.Index(doc, `<h2 class="group">Missing CSP header</h2>`)
	sql := strings.Index(doc, `<h2 class="group">SQL injection</h2>`)
	if csp == -1 || sql == -1 {
		t.Fatalf("a by-type group heading is missing: CSP@%d SQL@%d", csp, sql)
	}
	if sql < csp {
		t.Error("group headings are not in name order: SQL injection must come after Missing CSP header")
	}
	// The Critical SQL injection is the same type as the High one, so it must
	// still lead inside the group.
	crit := strings.Index(doc, `<h3>SQL injection</h3><span class="pill sev-critical">`)
	high := strings.Index(doc, `<h3>SQL injection</h3><span class="pill sev-high">`)
	if crit == -1 || high == -1 || crit > high {
		t.Errorf("inside the SQL injection group the Critical row must precede the High one: crit@%d high@%d", crit, high)
	}
}

// By URL: groups ordered by host then path — never by the two fields read as
// one concatenated string, which would interleave hosts and paths — and two
// findings on one host sit together.
func TestTheSettingsReportGroupsByURLHostThenPathAscending(t *testing.T) {
	// shop.test.evil sorts after shop.test as a host, but its full string
	// "shop.test.evil/a" sorts BEFORE "shop.test/login" ('.' < '/'), so this
	// row is the one that catches a grouping that compares the two fields as
	// one concatenated string instead of host-then-path.
	rows := append(settingsRows(), Row{
		ID: 4, Name: "Odd host header", Severity: "Low",
		Evidence: []Evidence{{Method: "GET", Host: "shop.test.evil", Path: "/a", Status: 200}},
	})
	doc := string(HTMLWithSettings(rows, Settings{OrganiseBy: "url"}))

	api := strings.Index(doc, `<h2 class="group">api.test/v1</h2>`)
	login := strings.Index(doc, `<h2 class="group">shop.test/login</h2>`)
	search := strings.Index(doc, `<h2 class="group">shop.test/search</h2>`)
	evil := strings.Index(doc, `<h2 class="group">shop.test.evil/a</h2>`)
	if api == -1 || login == -1 || search == -1 || evil == -1 {
		t.Fatalf("a by-URL group heading is missing: api@%d login@%d search@%d evil@%d", api, login, search, evil)
	}
	if !(api < login && login < search && search < evil) {
		t.Errorf("groups are not host-then-path ascending: api@%d login@%d search@%d evil@%d", api, login, search, evil)
	}
}

// Zero Settings is the report HTML() always produced: severity bands,
// worst-first — the parameters cannot have quietly reorganised the default.
func TestZeroSettingsStillOrganisesBySeverityWorstFirst(t *testing.T) {
	doc := string(HTMLWithSettings(settingsRows(), Settings{}))
	crit := strings.Index(doc, `<h2 class="sev sev-critical">CRITICAL</h2>`)
	high := strings.Index(doc, `<h2 class="sev sev-high">HIGH</h2>`)
	low := strings.Index(doc, `<h2 class="sev sev-low">LOW</h2>`)
	if crit == -1 || high == -1 || low == -1 {
		t.Fatalf("a severity band is missing: crit@%d high@%d low@%d", crit, high, low)
	}
	if !(crit < high && high < low) {
		t.Errorf("the default settings report is not worst-first: crit@%d high@%d low@%d", crit, high, low)
	}
	if !strings.Contains(doc, "Missing CSP header") {
		t.Error("a finding is missing from the zero-settings report")
	}
}

// The TOC depth is the wizard's "levels of detail": 0 is no TOC, 1 lists the
// groups without the findings, 2 lists each finding beneath its group.
func TestTheTOCFollowsTheRequestedDepth(t *testing.T) {
	noTOC := string(HTMLWithSettings(settingsRows(), Settings{OrganiseBy: "type"}))
	if strings.Contains(noTOC, `class="toc"`) {
		t.Error("TOCDepth 0 must not render a TOC")
	}

	depth1 := string(HTMLWithSettings(settingsRows(), Settings{OrganiseBy: "type", TOCDepth: 1}))
	tocAt := strings.Index(depth1, `<nav class="toc">`)
	if tocAt == -1 {
		t.Fatal("TOCDepth 1 must render a TOC")
	}
	end := strings.Index(depth1[tocAt:], `</nav>`)
	if end == -1 {
		t.Fatal("the TOC never closes")
	}
	if strings.Contains(depth1[tocAt:tocAt+end], `#finding-`) {
		t.Error("a depth-1 TOC listed the findings — depth 1 is groups only")
	}

	depth2 := string(HTMLWithSettings(settingsRows(), Settings{OrganiseBy: "type", TOCDepth: 2}))
	tocAt = strings.Index(depth2, `<nav class="toc">`)
	if tocAt == -1 {
		t.Fatal("TOCDepth 2 must render a TOC")
	}
	end = strings.Index(depth2[tocAt:], `</nav>`)
	if end == -1 {
		t.Fatal("the depth-2 TOC never closes")
	}
	for _, want := range []string{`href="#finding-1"`, `href="#finding-2"`, `href="#finding-3"`} {
		if !strings.Contains(depth2[tocAt:tocAt+end], want) {
			t.Errorf("the depth-2 TOC is missing %s", want)
		}
	}
}

// The issue-detail sections are a keep-if-match list. An explicit list drops
// everything not on it; the zero value prints everything, because the
// settings-free report always did.
func TestSectionsTakeDetailOutNotLeaveHiddenDefaultsIn(t *testing.T) {
	rows := settingsRows()
	all := string(HTMLWithSettings(rows, Settings{}))
	if !strings.Contains(all, "Detail</div>") || !strings.Contains(all, "Remediation</div>") {
		t.Error("the zero-value settings report dropped a section — nothing selected must mean everything printed")
	}

	backgroundOnly := string(HTMLWithSettings(rows, Settings{Sections: []string{"background"}}))
	if strings.Contains(backgroundOnly, "Detail</div>") {
		t.Error(`sections=["background"] still printed the finding's own detail`)
	}
	if strings.Contains(backgroundOnly, "Remediation</div>") {
		t.Error(`sections=["background"] still printed the finding's own remediation`)
	}
}

// The advisory with everything attached: background and classifications are
// independently selectable, and selecting both prints each list once — not
// once inside the advisory block and once more under the section.
func TestBackgroundAndClassificationsAreSelectedIndependentlyAndPrintOnce(t *testing.T) {
	rows := []Row{{
		ID: 1, Name: "SQL injection", Severity: "High",
		Advisory: &Advisory{
			Name:            "SQL injection",
			TypeIndex:       "00100200",
			DescriptionHTML: "<p>Injected SQL is executed by the database.</p>",
			Classifications: []Link{{Title: "CWE-89", URL: "https://cwe.mitre.org/data/definitions/89.html"}},
			References:      []Link{{Title: "Reading", URL: "https://portswigger.net/x"}},
		},
	}}

	classOnly := string(HTMLWithSettings(rows, Settings{Sections: []string{"classifications"}}))
	if !strings.Contains(classOnly, "CWE-89") {
		t.Error(`sections=["classifications"] did not print the CWE mapping`)
	}
	if strings.Contains(classOnly, "Issue definition") {
		t.Error(`sections=["classifications"] printed the catalogue block it was not asked for`)
	}

	both := string(HTMLWithSettings(rows, Settings{Sections: []string{"background", "classifications"}}))
	if n := strings.Count(both, "CWE-89"); n != 1 {
		t.Errorf("the classification printed %d times under sections=[background,classifications], want exactly 1", n)
	}
}

// "sections=" with nothing on it is Burp's untick-everything report — a bare
// list of names and evidence — and must not be coerced back to "everything".
// The nil/empty slice split is what carries the two states apart.
func TestAnEmptySectionsListPrintsNoDetailAtAll(t *testing.T) {
	// A row carrying everything the sections gate: its own detail and
	// remediation, the params list, and a catalogue entry behind it.
	rows := []Row{{
		ID: 1, Name: "SQL injection", Severity: "High",
		Description: "The q parameter is injectable.", Remediation: "Use parameterised queries.",
		Params:   []string{"q"},
		Hosts:    []string{"shop.test"},
		Evidence: []Evidence{{Method: "POST", Host: "shop.test", Path: "/login"}},
		Advisory: &Advisory{Name: "SQL injection", TypeIndex: "00100200", DescriptionHTML: "<p>Injected SQL is executed.</p>", RemediationHTML: "<p>Use parameterised queries.</p>"},
	}}
	all := string(HTMLWithSettings(rows, Settings{}))
	none := string(HTMLWithSettings(rows, Settings{Sections: []string{}}))
	for _, gone := range []string{"Detail</div>", "Remediation</div>", "Issue definition"} {
		if strings.Contains(none, gone) {
			t.Errorf("the all-off report still prints %q", gone)
		}
		if !strings.Contains(all, gone) {
			t.Errorf("the nil-list report lost %q — nil must mean every section", gone)
		}
	}
	// The always-printed core survives: the finding is still named, graded and
	// located. The params list is location metadata — Burp prints it beside
	// the issue header, not under a detail section — so it stays too.
	for _, kept := range []string{"SQL injection", "sev-high", "shop.test", "Affected parameters"} {
		if !strings.Contains(none, kept) {
			t.Errorf("the all-off report lost the core %q", kept)
		}
	}
}

// The title replaces "burpsy scan report" in both the h1 and the <title>, so a
// client-facing copy carries the engagement's own name.
func TestTheSettingsTitleReplacesTheDefaultHeading(t *testing.T) {
	doc := string(HTMLWithSettings(settingsRows(), Settings{Title: "Acme re-test, October 2026"}))
	for _, want := range []string{
		`<title>Acme re-test, October 2026</title>`,
		`<h1>Acme re-test, October 2026</h1>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the settings title is missing from %q", want)
		}
	}
	if strings.Contains(doc, "burpsy scan report") {
		t.Error("the default title survived a settings title that should have replaced it")
	}
	// The title is operator text and must not become markup in the file.
	evil := string(HTMLWithSettings(settingsRows(), Settings{Title: `<script>alert(1)</script>`}))
	if strings.Contains(evil, "<script>alert(1)</script>") {
		t.Error("an operator title carrying markup was embedded unescaped")
	}
}

// A message the caller attached prints its bytes and, when MaxMessageLen cut
// it, the explicit marker — a truncated message that reads as complete is the
// "we did not look" reported as "we looked".
func TestAttachedMessagesPrintTheirBytesAndTheTruncationMarker(t *testing.T) {
	rows := []Row{{
		ID: 1, Name: "SQL injection", Severity: "High",
		Evidence: []Evidence{{Method: "POST", Host: "shop.test", Path: "/login"}},
		Messages: []AttachedMessage{
			{Evidence: 0, IsRequest: true, Raw: []byte("POST /login HTTP/1.1\r\nHost: shop.test"), Truncated: true},
		},
	}}
	doc := string(HTMLWithSettings(rows, Settings{MaxMessageLen: 20}))
	for _, want := range []string{
		"POST /login HTTP/1.1",             // the bytes survived
		"[truncated at 20 bytes]",          // the marker names the bound
		`<div class="label">Request</div>`, // and which half it is
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the message block is missing %q", want)
		}
	}
}

// A relevant extract is the header block, not the whole message, and the
// report says so — an extract that reads as the full message is a false claim
// about what was captured.
func TestARelevantExtractIsLabelledAsHeadersOnly(t *testing.T) {
	rows := []Row{{
		ID: 1, Name: "SQL injection", Severity: "High",
		Evidence: []Evidence{{Method: "POST", Host: "shop.test", Path: "/login"}},
		Messages: []AttachedMessage{
			{Evidence: 0, IsRequest: false, Raw: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html"), HeadersOnly: true},
		},
	}}
	doc := string(HTMLWithSettings(rows, Settings{}))
	if !strings.Contains(doc, "[relevant extract &mdash; body omitted]") {
		t.Error("a headers-only extract was not labelled as an extract")
	}
	if !strings.Contains(doc, `<div class="label">Response</div>`) {
		t.Error("the extract is not labelled with which half it is")
	}
}

// The message bytes are attacker-influenced — a scanned response can carry
// markup — and must not become live markup in the exported file.
func TestAttachedMessageBytesAreEscaped(t *testing.T) {
	rows := []Row{{
		ID: 1, Name: "Thing", Severity: "Low",
		Evidence: []Evidence{{Method: "GET", Host: "shop.test", Path: "/x"}},
		Messages: []AttachedMessage{
			{Evidence: 0, IsRequest: false, Raw: []byte("<script>alert(1)</script>")},
		},
	}}
	doc := string(HTMLWithSettings(rows, Settings{}))
	if strings.Contains(doc, "<script>alert(1)</script>") {
		t.Error("message bytes carrying markup were embedded unescaped")
	}
	// The escaped form, not the raw markup: "survived" means a reader can
	// still see what the bytes said, not that a browser can run them.
	if !strings.Contains(doc, "&lt;script&gt;alert(1)") {
		t.Error("the message bytes did not survive escaping")
	}
}
