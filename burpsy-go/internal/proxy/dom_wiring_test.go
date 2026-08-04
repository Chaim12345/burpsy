package proxy

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// The static DOM pass is reachable from the proxy's passive-scan hook, not a library nobody calls.
//
// This project has twice shipped a ported engine that nothing invoked — the session coordinator's
// recovery path and Match&Replace — and had to come back and wire them. This test is the guard
// against a third: it asserts that a captured HTML response carrying a source-to-sink flow produces
// a finding in the shared finding store through the same call the passive check set goes through,
// with the catalogued issue name and the catalogued remediation attached.
func TestPassiveScanHookRunsStaticDomAnalysis(t *testing.T) {
	store := core.NewTrafficStore()
	findings := core.NewFindingStore()
	scope := core.NewScope()
	scope.AddInclude("*")

	ps := scanner.NewPassiveScanner(store, zap.NewNop())
	cfg := NewProxyConfig(store).WithScanner(ps)
	cfg.findings = findings
	cfg.scope = scope
	srv := &Server{config: cfg}

	reqID, err := store.Put([]byte("GET /p HTTP/1.1\r\nHost: dom.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	body := "<html><body><script>document.write(location.hash);</script></body></html>"
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+body),
		core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		Request: reqID, Response: &respID,
		Host: "dom.test", Port: 80, Method: "GET", Path: "/p", Status: &status,
	}
	store.AddExchange(ex)

	srv.runPassiveScan(ex)

	var got *core.Finding
	for _, f := range findings.All() {
		if f.Name == "Cross-site scripting (DOM-based)" {
			got = f
		}
	}
	if got == nil {
		names := make([]string, 0, findings.Count())
		for _, f := range findings.All() {
			names = append(names, f.Name)
		}
		t.Fatalf("the DOM pass did not reach the finding store; findings = %v", names)
	}
	if got.Remediation == "" {
		t.Error("the finding carries no remediation, so the catalog was not consulted")
	}
	if got.Confidence != core.ParseConfidence("tentative") {
		t.Errorf("confidence = %v, want tentative for a static-only DOM candidate", got.Confidence)
	}
	if !strings.Contains(got.Description, "DOM-based") {
		t.Error("the finding's background is not the catalogued description")
	}
}

// A response with no script gets no DOM findings and no spurious ones from the wiring itself.
func TestPassiveScanHookAddsNoDomFindingForANonScriptResponse(t *testing.T) {
	store := core.NewTrafficStore()
	findings := core.NewFindingStore()

	ps := scanner.NewPassiveScanner(store, zap.NewNop())
	cfg := NewProxyConfig(store).WithScanner(ps)
	cfg.findings = findings
	srv := &Server{config: cfg}

	reqID, _ := store.Put([]byte("GET /a.json HTTP/1.1\r\nHost: dom.test\r\n\r\n"), core.DirectionRequest)
	respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"+
		`{"u":"location.hash"}`), core.DirectionResponse)
	status := uint16(200)
	ex := &core.Exchange{
		Request: reqID, Response: &respID,
		Host: "dom.test", Port: 80, Method: "GET", Path: "/a.json", Status: &status,
	}
	store.AddExchange(ex)

	srv.runPassiveScan(ex)

	for _, f := range findings.All() {
		if strings.Contains(f.Name, "DOM-based") {
			t.Errorf("a JSON response produced a DOM finding: %q", f.Name)
		}
	}
}
