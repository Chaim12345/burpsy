package web

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// The report-settings route parameters (burpsy-react-ui-a9qy) are Burp's
// reporting wizard made a query string: title, organisation, TOC depth, the
// issue-detail sections, and the HTTP-messages mode and length. These tests
// drive the real /api/report route and assert on the rendered artefact, not
// on the parsed struct — a settings parameter that parsed but never reached
// the document is exactly the silent no-op this bead exists to remove.

// everySetting asks for one of everything: a title, the by-type organisation,
// a depth-2 TOC, only the catalogue block from the sections, and full
// messages capped at 50 bytes.
const everySetting = "title=Acme+re-test&organise_by=type&toc_depth=2&sections=background&message_mode=full&max_message_len=50"

func TestTheHTMLReportHonoursEverySettingsParameter(t *testing.T) {
	s := newTestServer()
	reqBytes, _ := xmlSeedFindings(t, s)

	rec := get(t, s, "/api/report/html?"+everySetting)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/report/html?%s answered %d (%s)", everySetting, rec.Code, rec.Body.String())
	}
	doc := rec.Body.String()

	for _, want := range []struct {
		fragment string
		why      string
	}{
		{`<h1>Acme re-test</h1>`, "the title must replace the default heading"},
		{`<h2 class="group">SQL injection</h2>`, "organise_by=type must group by issue name"},
		{`class="toc"`, "toc_depth=2 must render a table of contents"},
		{`href="#finding-0"`, "a depth-2 TOC must list the findings"},
		{`<div class="label">Request</div>`, "message_mode=full must attach the request"},
		{string(reqBytes[:50]), "the first 50 bytes of the request must be in the document"},
		{"[truncated at 50 bytes]", "a message cut by max_message_len must carry the truncation marker"},
	} {
		if !strings.Contains(doc, want.fragment) {
			t.Errorf("the settings report is missing %s — wanted %q", want.why, want.fragment)
		}
	}
	// sections=background drops the finding's own detail but keeps the
	// catalogue block, and the body bytes past the bound must not leak.
	if strings.Contains(doc, "<div class=\"label\">Detail</div>") {
		t.Error(`sections=["background"] still printed the finding's own detail`)
	}
	if !strings.Contains(doc, "Issue definition") {
		t.Error(`sections=["background"] did not print the catalogue block`)
	}
	if strings.Contains(doc, string(reqBytes[50:])) {
		t.Error("message bytes past max_message_len leaked into the report")
	}
}

// message_mode=relevant attaches the header block — the honest substitute for
// Burp's highlight window (see gaps.md) — and labels it as an extract so it
// cannot read as the whole message.
func TestMessageModeRelevantAttachesTheHeaderExtract(t *testing.T) {
	s := newTestServer()
	xmlSeedFindings(t, s)

	rec := get(t, s, "/api/report/html?message_mode=relevant")
	if rec.Code != http.StatusOK {
		t.Fatalf("message_mode=relevant answered %d", rec.Code)
	}
	doc := rec.Body.String()
	if !strings.Contains(doc, "[relevant extract &mdash; body omitted]") {
		t.Error("a relevant extract must be labelled as an extract")
	}
	if !strings.Contains(doc, "Content-Type: text/html") {
		t.Error("the extract must carry the response's headers")
	}
	// The NUL, the high byte and the CDATA terminator are distinctive to the
	// body — the document's own frame contains "</html>" too, so a bare tail
	// comparison would match the report's closing tag, not a leak.
	if strings.Contains(doc, "\x00\x01") || strings.Contains(doc, "]]>") {
		t.Error("the body bytes leaked into a headers-only extract")
	}
}

// The default bulk export stays message-free: "Do not include" is Burp's
// default, and a scan-wide report that inlined every request body would be
// unusable as a document.
func TestTheDefaultHTMLReportCarriesNoMessages(t *testing.T) {
	s := newTestServer()
	xmlSeedFindings(t, s)

	rec := get(t, s, "/api/report/html")
	if rec.Code != http.StatusOK {
		t.Fatalf("the default html report answered %d", rec.Code)
	}
	if doc := rec.Body.String(); strings.Contains(doc, `class="msg"`) {
		t.Error("the default report attached messages nobody asked for")
	}
}

// A bad settings value is refused with the parameter and its accepted values
// named, whichever format the URL ends in — a typo must not silently become a
// default.
func TestBadSettingsAreRefusedWithTheParameterNamed(t *testing.T) {
	s := newTestServer()
	xmlSeedFindings(t, s)

	for _, tc := range []struct {
		param, value, wantInMessage string
	}{
		{"organise_by", "bogus", `unknown organise_by "bogus"; the accepted values are severity, type, url`},
		{"sections", "background,detail,nonsense", `unknown section "nonsense"`},
		{"message_mode", "fuller", `unknown message_mode "fuller"; the accepted values are none, relevant, full`},
		{"max_message_len", "-5", `max_message_len "-5" is not a non-negative number of bytes`},
		{"toc_depth", "x", `toc_depth "x" is not a non-negative number`},
	} {
		for _, format := range []string{"html", "json", "xml"} {
			rec := get(t, s, "/api/report/"+format+"?"+tc.param+"="+tc.value)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s=%s on /api/report/%s answered %d, want 400", tc.param, tc.value, format, rec.Code)
				continue
			}
			if !strings.Contains(rec.Body.String(), tc.wantInMessage) {
				t.Errorf("%s=%s on %s answered %q, which does not name the parameter and its accepted values",
					tc.param, tc.value, format, rec.Body.String())
			}
		}
	}
}

// sections= — present but empty — turns every detail section off, distinct
// from the parameter being absent, which prints everything.
func TestAnEmptySectionsParameterTurnsEveryDetailSectionOff(t *testing.T) {
	s := newTestServer()
	xmlSeedFindings(t, s)

	rec := get(t, s, "/api/report/html?sections=")
	if rec.Code != http.StatusOK {
		t.Fatalf("sections= answered %d (%s)", rec.Code, rec.Body.String())
	}
	doc := rec.Body.String()
	for _, gone := range []string{"Detail</div>", "Remediation</div>", "Issue definition"} {
		if strings.Contains(doc, gone) {
			t.Errorf("the all-off report still prints %q", gone)
		}
	}
	// The params list is location metadata, not a detail section, so it
	// survives an all-off report the way the finding's name does.
	for _, kept := range []string{"SQL injection", "Affected parameters"} {
		if !strings.Contains(doc, kept) {
			t.Errorf("the all-off report lost the core %q", kept)
		}
	}
}

// toc_depth beyond 2 is clamped to 2 rather than refused — there is no third
// level to invent — and it still renders, not errors.
func TestTOCDepthIsClampedToTheMeaningfulLevels(t *testing.T) {
	s := newTestServer()
	xmlSeedFindings(t, s)

	rec := get(t, s, "/api/report/html?toc_depth=99")
	if rec.Code != http.StatusOK {
		t.Fatalf("toc_depth=99 answered %d, want a clamped 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `href="#finding-0"`) {
		t.Error("toc_depth=99 should clamp to depth 2 and still list the findings")
	}
}

// The XML export honours the settings too: an explicit message_mode=none
// leaves the requestresponse elements out, and max_message_len bounds the
// bytes that ride the base64 — the bound must bite on the wire, not only in
// the HTML rendering.
func TestTheXMLExportRespectsTheMessageSettings(t *testing.T) {
	s := newTestServer()
	reqBytes, _ := xmlSeedFindings(t, s)

	none := get(t, s, "/api/report/xml?message_mode=none")
	if none.Code != http.StatusOK {
		t.Fatalf("message_mode=none on xml answered %d", none.Code)
	}
	if strings.Contains(none.Body.String(), "<requestresponse>") {
		t.Error("message_mode=none must leave the XML export with no requestresponse elements")
	}
	if strings.Contains(none.Body.String(), "no readable request/response bytes") {
		t.Error("an explicit opt-out must not be peppered with unreadable-evidence comments")
	}

	bounded := get(t, s, "/api/report/xml?max_message_len=10")
	if bounded.Code != http.StatusOK {
		t.Fatalf("max_message_len=10 on xml answered %d", bounded.Code)
	}
	doc := bounded.Body.String()
	start := strings.Index(doc, `base64="true">`)
	if start == -1 {
		t.Fatal("the bounded export carries no message at all")
	}
	start += len(`base64="true">`)
	end := strings.Index(doc[start:], "</request>")
	if end == -1 {
		t.Fatal("the request element never closes")
	}
	got, err := base64.StdEncoding.DecodeString(doc[start : start+end])
	if err != nil {
		t.Fatalf("the bounded body is not valid base64: %v", err)
	}
	if string(got) != string(reqBytes[:10]) {
		t.Errorf("the bounded message is not the first 10 bytes of the capture:\n got %q\nwant %q", got, reqBytes[:10])
	}

	// sections=detail drops the catalogue text from the XML the way the
	// wizard's issue-details toggles gate Burp's own XML writer.
	detailOnly := get(t, s, "/api/report/xml?sections=detail")
	if detailOnly.Code != http.StatusOK {
		t.Fatalf("sections=detail on xml answered %d", detailOnly.Code)
	}
	if strings.Contains(detailOnly.Body.String(), "<issueBackground>") {
		t.Error("sections=detail must drop issueBackground from the XML export")
	}
	if !strings.Contains(detailOnly.Body.String(), "<issueDetail>The q parameter is injectable.</issueDetail>") {
		t.Error("sections=detail must keep the finding's own detail")
	}
}
