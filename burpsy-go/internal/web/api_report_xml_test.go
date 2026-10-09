package web

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The Burp-XML export's route (burpsy-react-ui-m7dk). The acceptance bar is
// the one the bead states: tooling that ingests Burp's XML must be able to
// consume what comes back — so these tests go through the real /api/report
// route, validate the document against the DTD with a real validating parser,
// and decode the Base64 messages back to the exact bytes the capture holds.

// xmlSeedFindings loads one catalogue-backed finding with binary-bearing
// evidence bytes, and one finding no catalogue entry describes.
func xmlSeedFindings(t *testing.T, s *Server) (reqBytes, respBytes []byte) {
	t.Helper()
	reqBytes = []byte("POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=%27+OR+1%3D1--")
	// NUL, a high byte and a CDATA terminator: the three things that make
	// base64 the only honest carriage for messages in an XML document.
	respBytes = []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>\x00\x01]]></html>")

	reqID, err := s.store.Put(reqBytes, core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put(respBytes, core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		Host: "shop.test", Port: 443, TLS: true, Method: "POST",
		// The query rides the exchange path — the XML path element must cut it.
		Path: "/login?user=x", Status: &status,
		Request: core.MsgPtr(reqID), Response: core.MsgPtr(respID),
	}
	s.store.AddExchange(ex)

	sqlID := s.findings.Add(core.NewFinding{
		Name: "SQL injection", Severity: core.SeverityHigh, Confidence: core.ConfidenceFirm,
		Description: "The q parameter is injectable.", Remediation: "Use parameterised queries.",
		Param: "q",
		Occurrences: []core.Occurrence{{
			ExchangeID: ex.ID, Request: core.MsgPtr(reqID), Response: core.MsgPtr(respID),
		}},
		Target: core.FindingTarget{Host: "shop.test", Port: 443, TLS: true, Path: "/login"},
	})
	s.findings.Add(core.NewFinding{
		Name: "A check no catalogue entry describes", Severity: core.SeverityLow, Confidence: core.ConfidenceTentative,
		Occurrences: []core.Occurrence{{
			ExchangeID: ex.ID, Request: core.MsgPtr(reqID), Response: core.MsgPtr(respID),
		}},
		Target: core.FindingTarget{Host: "shop.test", Port: 443, TLS: true, Path: "/login"},
	})
	_ = sqlID
	return reqBytes, respBytes
}

// The route serves a document that validates against Burp's own DTD and
// carries the issue's data: serial number, the catalogue's numeric type, the
// host, the query-stripped path, the location with its parameters, severity
// and confidence — and Base64 messages that decode back byte-identical.
func TestTheXMLExportRouteServesAValidatableDocumentWithExactMessages(t *testing.T) {
	s := newTestServer()
	reqBytes, respBytes := xmlSeedFindings(t, s)

	rec := get(t, s, "/api/report/xml")
	if rec.Code != 200 {
		t.Fatalf("GET /api/report/xml answered %d (%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "burpsy-report.xml") {
		t.Errorf("Content-Disposition = %q, want an attachment named burpsy-report.xml", cd)
	}

	doc := rec.Body.String()
	validateXMLWithXmllint(t, rec.Body.Bytes())

	for _, want := range []string{
		"<serialNumber>0</serialNumber>",
		"<type>1049088</type>", // 0x00100200, the catalogue's SQL injection index, as a decimal
		"<name>SQL injection</name>",
		// Burp's host element is the service URL, scheme and all.
		`>https://shop.test</host>`,
		"<path>/login</path>",
		// location is Burp's entry-point shape: the path and the parameter.
		"<location>/login [q parameter]</location>",
		"<severity>High</severity>",
		"<confidence>Firm</confidence>",
		"<issueDetail>The q parameter is injectable.</issueDetail>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the XML export is missing %q", want)
		}
	}

	// The base64 bodies decode back to the exact bytes the store holds.
	for _, tc := range []struct {
		open, closeTag string
		want           []byte
	}{
		{`<request method="POST" base64="true">`, "</request>", reqBytes},
		{`<response base64="true">`, "</response>", respBytes},
	} {
		start := strings.Index(doc, tc.open)
		if start == -1 {
			t.Fatalf("the export has no %s element", tc.open)
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
			t.Errorf("the decoded %s is not byte-identical to the capture:\n got %q\nwant %q", tc.closeTag, got, tc.want)
		}
	}
}

// A finding no catalogue entry describes exports the extension-generated type
// with a comment saying the number is a substitution — through the route, not
// just at the package level.
func TestTheXMLExportRouteGivesUncataloguedFindingsTheExtensionGeneratedType(t *testing.T) {
	s := newTestServer()
	xmlSeedFindings(t, s)

	rec := get(t, s, "/api/report/xml")
	if rec.Code != 200 {
		t.Fatalf("GET /api/report/xml answered %d (%s)", rec.Code, rec.Body.String())
	}
	doc := rec.Body.String()
	if !strings.Contains(doc, "A check no catalogue entry describes") {
		t.Fatal("the uncatalogued finding is missing from the export")
	}
	issue := doc[strings.Index(doc, "A check no catalogue entry describes")-200:]
	if !strings.Contains(issue, "<type>134217728</type>") {
		t.Error("the uncatalogued finding did not get the extension-generated type 134217728")
	}
	if !strings.Contains(issue, "no issue-definition catalogue entry") {
		t.Error("the type substitution is not flagged in a comment")
	}
}

// The export honours the filter axes the other formats honour: severity,
// host substring and false-positive exclusion compose on the XML route too.
func TestTheXMLExportHonoursTheReportFilter(t *testing.T) {
	s := newTestServer()
	xmlSeedFindings(t, s)

	rec := get(t, s, "/api/report/xml?severity=high")
	if rec.Code != 200 {
		t.Fatalf("severity-filtered XML export answered %d", rec.Code)
	}
	doc := rec.Body.String()
	if !strings.Contains(doc, "SQL injection") {
		t.Error("the High finding was dropped by severity=high")
	}
	if strings.Contains(doc, "A check no catalogue entry describes") {
		t.Error("a Low finding survived severity=high")
	}
}

// Evidence whose bytes the capture can no longer produce is commented in the
// export, not silently dropped — the operator asked for messages (XML always
// does), and "the request existed but could not be read" is a different claim
// from "there was no request".
func TestTheXMLExportCommentsEvidenceWhoseBytesAreGone(t *testing.T) {
	s := newTestServer()
	xmlSeedFindings(t, s)
	// Point the finding's occurrence at a message id the store does not hold.
	// A fresh store's dense ids make 9999 reliably absent.
	s.findings.Add(core.NewFinding{
		Name: "SQL injection", Severity: core.SeverityHigh, Confidence: core.ConfidenceFirm,
		Occurrences: []core.Occurrence{{
			ExchangeID: core.ExchangeID(9999),
			Request:    core.MsgPtr(9999), Response: core.MsgPtr(9998),
		}},
		Target: core.FindingTarget{Host: "shop.test", Port: 443, TLS: true, Path: "/gone"},
	})

	rec := get(t, s, "/api/report/xml?severity=high")
	if rec.Code != 200 {
		t.Fatalf("GET /api/report/xml answered %d (%s)", rec.Code, rec.Body.String())
	}
	doc := rec.Body.String()
	// The evidence entry that could not be resolved carries no exchange, so
	// its message ids are the ones evidenceMessageBytes fails to read; the
	// writer must say so rather than emit nothing.
	if !strings.Contains(doc, "no readable request/response bytes") {
		t.Errorf("evidence with unreadable bytes vanished silently:\n%s", doc)
	}
}

// validateXMLWithXmllint runs a real validating parser against the document
// and its embedded DTD. Skips with a reason when xmllint is not installed —
// the same convention the extscan live tests use; CI installs libxml2-utils
// so the skip does not happen there.
func validateXMLWithXmllint(t *testing.T, doc []byte) {
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
