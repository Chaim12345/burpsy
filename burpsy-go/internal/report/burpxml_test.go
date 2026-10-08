package report

import (
	"encoding/base64"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Burp-XML export (burpsy-react-ui-m7dk) is judged by the same standard
// as any interchange format: a consumer that knows Burp's export must accept
// what burpsy writes, and must get back byte-identical messages when it
// decodes them. The tests here validate against the DTD itself (xmllint,
// the same way the extscan suite shells out to real binaries and skips with
// a reason when one is missing), and against Go's own parser for everything
// that must survive a round-trip.

// exportTime is a fixed clock so element positions and lengths are stable;
// the DTD's exportTime attribute is CDATA, so any shape parses.
func xmlTestTime() time.Time {
	return time.Date(2026, 10, 8, 11, 4, 5, 0, time.UTC)
}

// xmlSettings asks for full messages, the mode the structural tests exercise.
func xmlSettings() Settings { return Settings{MessageMode: "full"} }

// xmlRow is a catalogue-backed finding with one evidence pair and no
// surprises, the row every structural assertion starts from.
func xmlRow() Row {
	return Row{
		ID: 7, Name: "SQL injection", Severity: "High", Confidence: "Firm",
		Description: "The q parameter is injectable.", Remediation: "Use parameterised queries.",
		Params:   []string{"q"},
		Hosts:    []string{"shop.test"},
		Evidence: []Evidence{{Method: "POST", Host: "shop.test", Path: "/login", Status: 200, HasRequest: true, HasResponse: true}},
		Advisory: &Advisory{
			Name:            "SQL injection",
			TypeIndex:       "00100200",
			TypicalSeverity: "HIGH",
			DescriptionHTML: "<p>SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner.</p>",
			RemediationHTML: "<p>Use parameterised queries.</p>",
			References:      []Link{{Title: "Web Security Academy: SQL injection", URL: "https://portswigger.net/web-security/sql-injection"}},
			Classifications: []Link{{Title: "CWE-89", URL: "https://cwe.mitre.org/data/definitions/89.html"}},
		},
	}
}

// validateWithXmllint runs xmllint --valid against the document's own
// embedded DTD — a real validating parser, not a hand-rolled structural walk.
// Skips with a reason when xmllint is not installed, the same honest-skip
// convention the extscan live tests use for tlsx and interactsh-client; CI
// installs libxml2-utils so the skip never happens there.
func validateWithXmllint(t *testing.T, doc []byte) {
	t.Helper()
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skipf("xmllint is not installed, so DTD validation is undemonstrated here: %v", err)
	}
	path := filepath.Join(t.TempDir(), "export.xml")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatalf("write temp xml: %v", err)
	}
	out, err := exec.Command("xmllint", "--valid", "--noout", path).CombinedOutput()
	if err != nil {
		t.Fatalf("xmllint rejected the export against Burp's own DTD — a Burp-ingesting consumer would too:\n%s", out)
	}
}

// The document burpsy writes must carry Burp's DTD, not an approximation of
// it, and must validate against it. A validating consumer is the acceptance
// test for this bead.
func TestTheXMLExportValidatesAgainstBurpsOwnDTD(t *testing.T) {
	doc := BurpXML([]Row{xmlRow()}, xmlSettings(), xmlTestTime())
	validateWithXmllint(t, doc)

	s := string(doc)
	// Spot-checks that the embedded DTD is Burp's full grammar, not a
	// trimmed subset: the elements burpsy never writes are the ones whose
	// absence would prove the DTD had been "simplified".
	for _, declaration := range []string{
		"<!ELEMENT issue (serialNumber, type, name, host, path, location, severity, confidence, issueBackground?, remediationBackground?, references?, vulnerabilityClassifications?, issueDetail?, issueDetailItems?, remediationDetail?, requestresponse*, collaboratorEvent*, infiltratorEvent*, staticAnalysis*, dynamicAnalysis*, prototypePollution*)>",
		"<!ELEMENT collaboratorEvent (interactionType, originIp, time, lookupType?, lookupHost?, requestresponse?, smtp?)>",
		"<!ELEMENT prototypePollution (poc, pollutionTechnique, pollutionType)>",
		"<!ATTLIST request base64 (true|false) \"false\">",
	} {
		if !strings.Contains(s, declaration) {
			t.Errorf("the embedded DTD is missing Burp's declaration %q — the format was trimmed, not reproduced", declaration)
		}
	}
	// Every line of the document is CRLF, the byte shape Burp's writer
	// produces (Zxke appends "\r\n" to every line).
	if n := strings.Count(s, "\n"); n != strings.Count(s, "\r\n") {
		t.Errorf("%d of %d newlines are not CRLF — Burp's export is uniformly CRLF", n-strings.Count(s, "\r\n"), n)
	}
}

// A finding with a catalogue entry exports the catalogue's numeric type, the
// element consumers key on ("This value is constant across different
// instances of Burp" — report-settings.html).
func TestTheTypeElementCarriesTheCatalogueIndexAsADecimal(t *testing.T) {
	doc := string(BurpXML([]Row{xmlRow()}, xmlSettings(), xmlTestTime()))
	// 00100200 hex is 1049088 decimal: the element carries the number, not
	// the hex form the console displays.
	for _, want := range []string{
		"<type>1049088</type>",
		"<serialNumber>7</serialNumber>",
		"<name>SQL injection</name>",
		`<host ip="">shop.test</host>`,
		"<path>/login</path>",
		"<location>shop.test/login [q]</location>",
		"<severity>High</severity>",
		"<confidence>Firm</confidence>",
		"<issueDetail>The q parameter is injectable.</issueDetail>",
		"<remediationDetail>Use parameterised queries.</remediationDetail>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the issue element is missing %q", want)
		}
	}
}

// A finding with no catalogue entry gets Burp's extension-generated type and
// a comment saying so — the number is reported as a substitution, never
// invented and never silently passed off as a real index.
func TestAFindingWithNoCatalogueEntryGetsTheExtensionGeneratedTypeAndSaysSo(t *testing.T) {
	row := Row{ID: 3, Name: "Odd check nobody catalogued", Severity: "Low", Confidence: "Tentative",
		Evidence: []Evidence{{Method: "GET", Host: "shop.test", Path: "/x"}}}
	doc := string(BurpXML([]Row{row}, xmlSettings(), xmlTestTime()))
	if !strings.Contains(doc, "<type>134217728</type>") {
		t.Error("a catalogue-less finding must export type 134217728 (0x08000000, Extension generated issue)")
	}
	if !strings.Contains(doc, "no issue-definition catalogue entry") {
		t.Error("the substitution must be flagged in a comment — a consumer tallying types must be able to tell it apart from a real index")
	}
	if !strings.Contains(doc, "<name>Odd check nobody catalogued</name>") {
		t.Error("the finding's own name must still be exported")
	}
}

// Base64 is the whole point of the format's message carriage: a strict XML
// parser cannot carry NULL bytes and arbitrary binary otherwise ("HTTP
// messages may contain nonprinting characters that are not permitted in XML
// documents" — report-settings.html). Decoding must give back the exact
// bytes, not an approximation of them.
func TestBase64MessagesDecodeBackByteIdenticalIncludingBinary(t *testing.T) {
	// A response body with NUL, high bytes and a CDATA terminator: the
	// three things a text node cannot carry honestly.
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01\xff]]>\x7f")
	row := xmlRow()
	row.Messages = []AttachedMessage{
		{Evidence: 0, IsRequest: true, Raw: []byte("POST /login HTTP/1.1\r\nHost: shop.test\r\n\r\nq=1")},
		{Evidence: 0, IsRequest: false, Raw: response},
	}
	doc := string(BurpXML([]Row{row}, xmlSettings(), xmlTestTime()))
	validateWithXmllint(t, []byte(doc))

	// Pull the two base64 bodies out of the document and decode them.
	for _, tc := range []struct {
		open, closeTag string
		want           []byte
	}{
		{`<request method="POST" base64="true">`, "</request>", row.Messages[0].Raw},
		{`<response base64="true">`, "</response>", response},
	} {
		start := strings.Index(doc, tc.open)
		if start == -1 {
			t.Fatalf("%s was not written", tc.open)
		}
		start += len(tc.open)
		end := strings.Index(doc[start:], tc.closeTag)
		if end == -1 {
			t.Fatalf("the %s element never closes", tc.closeTag)
		}
		got, err := base64.StdEncoding.DecodeString(doc[start : start+end])
		if err != nil {
			t.Fatalf("the message body is not valid base64: %v", err)
		}
		if string(got) != string(tc.want) {
			t.Errorf("decoded message is not byte-identical to the stored bytes:\n got %q\nwant %q", got, tc.want)
		}
	}
}

// Text elements carrying & and the CDATA terminator must survive a parse
// round-trip — "]]>" is the one sequence XML forbids in content, and it is
// also exactly what a scanned response is likely to contain.
func TestTextElementsSurviveAmpersandsAndCdataTerminators(t *testing.T) {
	row := Row{ID: 1, Name: "Response <![CDATA[ leaks ]] & reflects", Severity: "Low",
		Description: "Found ]]> and & in the body.",
		Evidence:    []Evidence{{Method: "GET", Host: "shop.test", Path: "/x"}}}
	doc := BurpXML([]Row{row}, xmlSettings(), xmlTestTime())
	validateWithXmllint(t, doc)

	// Parse with Go's XML decoder and take the name element's text back.
	dec := xmlNameText(t, string(doc), "name")
	if dec != row.Name {
		t.Errorf("the name element did not survive the round-trip: got %q, want %q", dec, row.Name)
	}
	detail := xmlNameText(t, string(doc), "issueDetail")
	if detail != row.Description {
		t.Errorf("the issueDetail element did not survive the round-trip: got %q, want %q", detail, row.Description)
	}
	if strings.Contains(string(doc), "]]>") {
		t.Error("a literal CDATA terminator is in the document — it must always be escaped")
	}
}

// The path element excludes the query string (report-settings.html), but
// burpsy's capture store keeps the query in the exchange path, so the export
// must cut it here.
func TestThePathElementExcludesTheQueryString(t *testing.T) {
	row := xmlRow()
	row.Evidence[0].Path = "/search?q=payload&x=1"
	doc := string(BurpXML([]Row{row}, xmlSettings(), xmlTestTime()))
	if !strings.Contains(doc, "<path>/search</path>") {
		t.Errorf("the path element carries the query string: %s", doc)
	}
	if strings.Contains(doc, "<path>/search?q=payload") {
		t.Error("the query string leaked into the path element")
	}
}

// Evidence with no readable bytes is commented, not silent: an export that
// drops the pair entirely reads as "there was no request", a claim about the
// target rather than about the capture.
func TestEvidenceWithoutBytesIsCommentedNotSilent(t *testing.T) {
	row := xmlRow()
	row.Evidence = append(row.Evidence, Evidence{Method: "GET", Host: "shop.test", Path: "/gone", HasRequest: true})
	// Only evidence 0 has messages attached; evidence 1 expects bytes and
	// has none.
	doc := string(BurpXML([]Row{row}, xmlSettings(), xmlTestTime()))
	if !strings.Contains(doc, "no readable request/response bytes") {
		t.Error("an evidence entry with no readable bytes vanished without a comment")
	}
	if n := strings.Count(doc, "<requestresponse>"); n != 0 {
		t.Errorf("evidence without bytes still wrote %d requestresponse elements", n)
	}
}

// The advisory's background text arrives as plain text, the way Burp's
// export carries it (Burp strips the HTML before writing) — a <p> tag inside
// a PCDATA element would be markup smuggled into a text field.
func TestTheAdvisoryBackgroundArrivesAsPlainText(t *testing.T) {
	doc := string(BurpXML([]Row{xmlRow()}, xmlSettings(), xmlTestTime()))
	background := xmlNameText(t, doc, "issueBackground")
	if strings.Contains(background, "<p>") || strings.Contains(background, "</p>") {
		t.Errorf("the issueBackground element carries markup: %q", background)
	}
	if !strings.Contains(background, "user-controllable data") {
		t.Errorf("the issueBackground text lost the advisory's words: %q", background)
	}
	if !strings.Contains(doc, "<references>Web Security Academy: SQL injection: https://portswigger.net/web-security/sql-injection</references>") {
		t.Error("the references element does not carry the advisory's further-reading list")
	}
	if !strings.Contains(doc, "<vulnerabilityClassifications>CWE-89: https://cwe.mitre.org/data/definitions/89.html</vulnerabilityClassifications>") {
		t.Error("the vulnerabilityClassifications element does not carry the CWE mapping")
	}
}

// An empty export is a valid document with no issues, not a truncated one.
func TestAnEmptyExportIsStillAValidDocument(t *testing.T) {
	doc := BurpXML(nil, xmlSettings(), xmlTestTime())
	validateWithXmllint(t, doc)
	s := string(doc)
	if !strings.Contains(s, `<issues burpVersion="burpsy" exportTime="Thu Oct 08 11:04:05 UTC 2026">`) {
		t.Errorf("the empty export does not carry the issues root with burpsy's version and the export time:\n%s", s)
	}
	if strings.Contains(s, "<issue>") {
		t.Error("the empty export carries an issue element — an empty store must export an empty document")
	}
}

// xmlNameText pulls one element's text back out through Go's XML parser, so
// a round-trip assertion says the parser read the same string, not that the
// bytes happen to be there.
func xmlNameText(t *testing.T, doc, element string) string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(doc))
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("parsing the export: %v", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != element {
			continue
		}
		var s struct {
			Text string `xml:",chardata"`
		}
		if err := dec.DecodeElement(&s, &start); err != nil {
			t.Fatalf("decoding <%s>: %v", element, err)
		}
		return s.Text
	}
}
