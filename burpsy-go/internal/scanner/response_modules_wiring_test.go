package scanner

// Tests for the response-module WIRING — the part that makes the module framework reachable at all
// (burpsy-react-ui-8j0d's seam).
//
// # Why this file exists separately from the module tests
//
// response_modules_test.go proves the modules work. It cannot prove they RUN: every one of those
// tests constructs a module and calls Analyze directly, so the whole framework could sit in the
// package, perfectly green, and never once look at a captured response in production. That is the
// decorative-control failure this project's conventions forbid — a control that changes no
// behaviour is worse than no control, because it reads as coverage. These tests drive the real
// seam (Capture.Record → ScanExchange) instead, so a regression that drops the wiring fails here
// rather than being invisible.

import (
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// A leaked credential in a real captured response must produce a stored finding that carries the
// exchange — i.e. it is reachable from history, not merely produced. The ExchangeID assertion is the
// load-bearing half: a finding with no exchange is a row no view can join to the traffic that
// produced it.
func TestACapturedResponseWithALeakedKeyProducesAStoredFindingCarryingTheExchange(t *testing.T) {
	cap, _, findings := newTestCapture()
	cap.ResponseModules = DefaultResponseModules()

	body := `{"debug_config":{"aws_secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}`
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		itoaForCaptureTest(len(body)) + "\r\n\r\n" + body

	_, err := cap.Record(CapturedExchange{
		Host: "h", Port: 80, Method: "GET", Path: "/config",
		Request: []byte("GET /config HTTP/1.1\r\nHost: h\r\n\r\n"), Response: []byte(resp),
		Started: time.Now(), Duration: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	got := findings.All()
	var secret *core.Finding
	for _, f := range got {
		if strings.Contains(f.Name, "AWS secret access key") {
			secret = f
			break
		}
	}
	if secret == nil {
		t.Fatalf("no AWS secret finding reached the store; the response modules are not wired into "+
			"the capture path, or the wiring dropped this module. Findings: %d", len(got))
	}
	if secret.Description == "" {
		t.Error("finding carries no description")
	}
	// The excerpt rides its OWN field now (burpsy-react-ui-cx31). It used to arrive glued into
	// Description as a workaround for core having nowhere to put it, so the description must NOT
	// carry it any more — otherwise every stored module finding holds the excerpt twice and a
	// reader cannot tell which copy is canonical.
	if secret.Evidence == "" {
		t.Errorf("finding carries no evidence; the redacted credential is the whole reason this "+
			"finding is actionable (description was %q)", secret.Description)
	}
	if strings.Contains(secret.Description, "Evidence:") {
		t.Errorf("description %q still carries a concatenated excerpt; it belongs in the Evidence "+
			"field alone now", secret.Description)
	}
	if strings.Contains(secret.Evidence, "wJalrXUtnFEMI") {
		t.Errorf("the stored finding carries the whole secret: %q", secret.Evidence)
	}
	if secret.Target.Host != "h" || secret.Target.Path != "/config" {
		t.Errorf("finding target is %+v; a module finding must be deduplicated and located against "+
			"the exchange that produced it, exactly like every other finding", secret.Target)
	}
	if len(secret.Occurrences) == 0 {
		t.Error("finding carries no occurrence; module findings must go through the same indexing as " +
			"every other finding so history can join them to the exchange")
	}
}

// The inverse and the important one: with no modules configured, a response containing a live
// credential produces NO module finding. Without this the wiring test above would pass even if the
// module list were ignored and the modules always ran — and a module that always runs is its own
// kind of lie, because a surface that did not ask for it would silently start reporting findings.
func TestNoModulesConfiguredMeansNoModuleFindings(t *testing.T) {
	cap, _, findings := newTestCapture()
	// ResponseModules deliberately left nil — the zero value of every existing wiring.

	body := `{"aws_secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`
	resp := "HTTP/1.1 200 OK\r\nContent-Length: " + itoaForCaptureTest(len(body)) + "\r\n\r\n" + body
	if _, err := cap.Record(CapturedExchange{
		Host: "h", Port: 80, Method: "GET", Path: "/config",
		Request: []byte("GET /config HTTP/1.1\r\nHost: h\r\n\r\n"), Response: []byte(resp),
		Started: time.Now(), Duration: 5 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	for _, f := range findings.All() {
		if strings.Contains(f.Name, "AWS secret access key") || strings.Contains(f.Name, "API key exposed") {
			t.Errorf("finding %q was produced with no modules configured; the module framework must "+
				"be inert until a surface asks for it", f.Name)
		}
	}
}

// A nil slot in the configured list must not take the scan down — and the wiring is where that
// panic would actually happen, in production, on a scan rather than in a test.
func TestANilModuleSlotDoesNotBreakTheCapturePath(t *testing.T) {
	cap, _, findings := newTestCapture()
	cap.ResponseModules = []ResponseModule{nil, &SecretsModule{}, nil}

	body := `{"api_key":"sk_live_abcdefghijklmnop1234"}`
	resp := "HTTP/1.1 200 OK\r\nContent-Length: " + itoaForCaptureTest(len(body)) + "\r\n\r\n" + body
	if _, err := cap.Record(CapturedExchange{
		Host: "h", Port: 80, Method: "GET", Path: "/k",
		Request: []byte("GET /k HTTP/1.1\r\nHost: h\r\n\r\n"), Response: []byte(resp),
		Started: time.Now(), Duration: 5 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if len(findings.All()) == 0 {
		t.Error("no findings at all; the live module in the list should still have run")
	}
}

// itoaForCaptureTest formats a length for a Content-Length header without carrying strconv for it.
func itoaForCaptureTest(n int) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}
