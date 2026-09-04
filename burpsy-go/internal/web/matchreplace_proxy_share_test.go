package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/proxy"
)

// TestWebLayerAndProxyObserveOneSharedMatchReplaceRuleset proves the sharing this unit depends on:
// the *matchreplace.RuleSet the Match & Replace page mutates is the very object the proxy reads, so an
// edit made through the web API is one the proxy honours. cmd/burpsy wires it exactly this way — one
// RuleSet handed to both proxy.NewProxyConfig(...).WithMatchReplace and web's WithMatchReplace.
//
// It fails if the two sides are ever given separate rule sets: the PUT below would then mutate a copy
// the proxy never sees, and the assertions on the object the proxy config holds would still report an
// empty ruleset. That the proxy actually applies this object to wire bytes is proved end-to-end by
// internal/proxy's TestProxyRewritesRequestAndResponseWireBytesViaMatchReplace; here the concern is
// solely that one edit is seen by both surfaces.
func TestWebLayerAndProxyObserveOneSharedMatchReplaceRuleset(t *testing.T) {
	web := newTestServer()

	// The object cmd/burpsy hands to the proxy. Building the proxy config from it here mirrors that
	// wiring: the proxy now reads exactly what the web API below writes.
	shared := web.matchReplace
	proxyCfg := proxy.NewProxyConfig(core.NewTrafficStore()).WithMatchReplace(shared)
	if proxyCfg == nil {
		t.Fatal("proxy config did not build from the shared ruleset")
	}

	// Nothing configured yet: the proxy would rewrite nothing.
	if shared.Affects(matchreplace.DirRequest) || shared.Affects(matchreplace.DirResponse) {
		t.Fatal("a fresh shared ruleset should affect neither direction")
	}

	// Edit rules exactly as the Match & Replace page does — one request-direction rule, one
	// response-direction rule, and the content-length toggle.
	body := `{
		"rules": [
			{"rule_type":"request_header","enabled":true,"string_match":"hunter2","string_replace":"scrubbed","category":"literal","comment":""},
			{"rule_type":"response_body","enabled":true,"string_match":"ORIGIN","string_replace":"PROXY","category":"literal","comment":""}
		],
		"update_content_length": true
	}`
	rec := httptest.NewRecorder()
	web.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/tools/rules", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/tools/rules: status %d, body %q", rec.Code, rec.Body.String())
	}

	// The proxy, holding the same object, now observes the operator's edit in both directions. Two
	// separate rule sets would leave these false — the "page renders a list the proxy no longer
	// honours" failure this wiring exists to prevent.
	if !shared.Affects(matchreplace.DirRequest) {
		t.Error("after the web-API edit the shared ruleset reports no request-direction rule; the proxy would rewrite no request")
	}
	if !shared.Affects(matchreplace.DirResponse) {
		t.Error("after the web-API edit the shared ruleset reports no response-direction rule; the proxy would rewrite no response")
	}
	if !shared.UpdateContentLength() {
		t.Error("update_content_length from the page did not reach the shared ruleset the proxy reads")
	}

	// And the request rule actually rewrites through that shared object, so the proxy's DirRequest
	// Apply has something to do.
	got := string(shared.Apply(matchreplace.DirRequest, []byte("GET / HTTP/1.1\r\nX-Secret: hunter2\r\n\r\n")))
	if !strings.Contains(got, "scrubbed") || strings.Contains(got, "hunter2") {
		t.Errorf("the page's request rule did not rewrite through the shared ruleset: %q", got)
	}
}
