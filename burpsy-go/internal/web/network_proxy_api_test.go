package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/upstream"
)

// newProxyPolicyServer is a server with an upstream proxy policy attached, which is the only state in
// which the write arms of /api/network/proxy do anything.
func newProxyPolicyServer(t *testing.T) (*Server, *upstream.Policy) {
	t.Helper()
	policy := upstream.NewPolicy()
	return newTestServer().WithUpstreamProxy(policy), policy
}

// getNetworkProxyView reads GET /api/network/proxy and decodes it.
func getNetworkProxyView(t *testing.T, s *Server) networkProxyView {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/network/proxy", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/network/proxy answered %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var view networkProxyView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	return view
}

func deleteNetworkProxy(t *testing.T, s *Server, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/network/proxy?"+query, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// A server built without a policy says so rather than presenting an empty rule list as a working panel.
//
// This is the "empty is not the same as unwired" case: both render as zero rules, and only one of them
// means an edit would take effect.
func Test_network_proxy_reports_an_unwired_process_rather_than_an_empty_policy(t *testing.T) {
	s := newTestServer()
	view := getNetworkProxyView(t, s)
	if view.Wired {
		t.Error("a server with no policy reports wired: true, which claims an edit here would apply")
	}
	if len(view.Rules) != 0 || view.Default != "direct" {
		t.Errorf("unwired view should describe nothing; got %d rule(s), default %q", len(view.Rules), view.Default)
	}
	// And the write arms must refuse rather than accept a rule into a policy nothing holds.
	rec := postJSON(t, s, "/api/network/proxy", networkProxyUpdate{Pattern: "*", Proxy: "http://127.0.0.1:3128"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("POST to an unwired server answered %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

func Test_network_proxy_upserts_a_rule_and_reports_the_surfaces_it_reaches(t *testing.T) {
	s, policy := newProxyPolicyServer(t)
	// A second holder, standing in for the proxy listener, so `attached` has something truthful to say.
	policy.Attach("proxy")

	rec := postJSON(t, s, "/api/network/proxy",
		networkProxyUpdate{Pattern: "*.internal", Proxy: "socks5://127.0.0.1:1080"})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST answered %d, want 200: %s", rec.Code, rec.Body.String())
	}

	view := getNetworkProxyView(t, s)
	if len(view.Rules) != 1 {
		t.Fatalf("want 1 rule after the POST, got %d", len(view.Rules))
	}
	if view.Rules[0].Pattern != "*.internal" || view.Rules[0].Kind != "socks5" {
		t.Errorf("rule is %+v, want pattern *.internal kind socks5", view.Rules[0])
	}
	if view.Empty {
		t.Error("a policy with a rule reports empty: true")
	}
	attached := strings.Join(view.Attached, ",")
	if !strings.Contains(attached, "proxy") || !strings.Contains(attached, "web") {
		t.Errorf("attached is %q; it must name every surface holding the policy, or the panel implies "+
			"coverage it cannot see", attached)
	}

	// Upsert, not append: the same pattern again replaces in place. This is what makes re-applying
	// flag-configured rules over restored ones a dedup rather than a duplication.
	if rec := postJSON(t, s, "/api/network/proxy",
		networkProxyUpdate{Pattern: "*.internal", Proxy: "http://127.0.0.1:3128"}); rec.Code != http.StatusOK {
		t.Fatalf("second POST answered %d: %s", rec.Code, rec.Body.String())
	}
	view = getNetworkProxyView(t, s)
	if len(view.Rules) != 1 {
		t.Fatalf("re-adding the same pattern produced %d rules; it must replace in place", len(view.Rules))
	}
	if view.Rules[0].Kind != "http" {
		t.Errorf("the upsert kept kind %q instead of replacing it with http", view.Rules[0].Kind)
	}
}

// Removal is by exact pattern, and a pattern that is not there is a 404.
//
// The case that matters: a double-clicked remove button. The second click must say "no such rule"
// rather than succeeding, because a second success would make one rule look like two had existed.
func Test_network_proxy_removal_is_exact_and_absent_patterns_are_404(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	if rec := postJSON(t, s, "/api/network/proxy",
		networkProxyUpdate{Pattern: "*.example.com", Proxy: "http://127.0.0.1:3128"}); rec.Code != http.StatusOK {
		t.Fatalf("seeding a rule answered %d: %s", rec.Code, rec.Body.String())
	}

	if rec := deleteNetworkProxy(t, s, "pattern=*.example.com"); rec.Code != http.StatusOK {
		t.Fatalf("removing the rule answered %d, want 200: %s", rec.Code, rec.Body.String())
	}
	// The same call again: the rule is gone, so this must not report success a second time.
	rec := deleteNetworkProxy(t, s, "pattern=*.example.com")
	if rec.Code != http.StatusNotFound {
		t.Errorf("a repeated remove answered %d, want 404. A second success makes one rule look like two: %s",
			rec.Code, rec.Body.String())
	}

	// A pattern that would *match* the same hosts is still not that rule. Removing "www.example.com"
	// must not take "*.example.com" with it.
	if rec := postJSON(t, s, "/api/network/proxy",
		networkProxyUpdate{Pattern: "*.example.com", Proxy: "http://127.0.0.1:3128"}); rec.Code != http.StatusOK {
		t.Fatalf("re-seeding answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec := deleteNetworkProxy(t, s, "pattern=www.example.com"); rec.Code != http.StatusNotFound {
		t.Errorf("removing a host the wildcard covers answered %d, want 404: exact-match removal must not "+
			"delete a different rule that happens to cover the same hosts", rec.Code)
	}
	if view := getNetworkProxyView(t, s); len(view.Rules) != 1 {
		t.Errorf("the wildcard rule was removed by a non-matching pattern; %d rule(s) left", len(view.Rules))
	}

	// A DELETE with no pattern is what a UI bug sends, and un-proxying everything is not a reasonable
	// reading of it.
	if rec := deleteNetworkProxy(t, s, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("DELETE with no pattern answered %d, want 400", rec.Code)
	}
	if rec := deleteNetworkProxy(t, s, "all=true"); rec.Code != http.StatusOK {
		t.Errorf("DELETE ?all=true answered %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if view := getNetworkProxyView(t, s); !view.Empty {
		t.Error("?all=true left the policy non-empty")
	}
}

// An unparseable proxy URL is refused and nothing is stored.
//
// Refuse-by-default is the house rule and this is where it bites: accepting the string would leave an
// operator looking at a configured rule while their traffic went straight to the target.
func Test_network_proxy_refuses_an_unusable_url_and_stores_nothing(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	for _, bad := range []string{
		"127.0.0.1:8080",              // no scheme; assuming http:// would pick a protocol nobody chose
		"http://127.0.0.1",            // no port, and 8080/3128/1080 are all conventions rather than answers
		"gopher://127.0.0.1:70",       // a scheme the dial path cannot speak
		"socks4://u:p@127.0.0.1:1080", // socks4 has no password field on the wire
		"http://127.0.0.1:70000",      // not a port number
	} {
		rec := postJSON(t, s, "/api/network/proxy", networkProxyUpdate{Pattern: "*", Proxy: bad})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST with proxy %q answered %d, want 400: %s", bad, rec.Code, rec.Body.String())
		}
	}
	if view := getNetworkProxyView(t, s); len(view.Rules) != 0 || !view.Empty {
		t.Errorf("a refused URL still changed the policy: %d rule(s), empty=%v", len(view.Rules), view.Empty)
	}
}

// A body carrying a good default and a bad rule changes neither.
//
// A half-applied proxy policy is the one state an operator must not be left silently holding: they would
// see the default move and the rule missing, with no indication which of the two the server acted on.
func Test_network_proxy_applies_a_mixed_body_atomically(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	good := "socks5://127.0.0.1:1080"
	rec := postJSON(t, s, "/api/network/proxy",
		networkProxyUpdate{Default: &good, Pattern: "*.internal", Proxy: "not-a-url"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mixed body with a bad rule answered %d, want 400: %s", rec.Code, rec.Body.String())
	}
	view := getNetworkProxyView(t, s)
	if view.Default != "direct" {
		t.Errorf("the default moved to %q even though the rule in the same body was refused", view.Default)
	}
	if len(view.Rules) != 0 {
		t.Errorf("%d rule(s) stored from a refused body", len(view.Rules))
	}
}

// An omitted `default` leaves the default alone; only an explicit empty string clears it.
//
// With a plain string field the two are indistinguishable, and every rule-only edit from the panel would
// silently un-proxy everything no rule covers.
func Test_network_proxy_omitted_default_is_not_a_cleared_default(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	def := "http://127.0.0.1:3128"
	if rec := postJSON(t, s, "/api/network/proxy", networkProxyUpdate{Default: &def}); rec.Code != http.StatusOK {
		t.Fatalf("setting the default answered %d: %s", rec.Code, rec.Body.String())
	}
	// A rule-only edit, with no `default` key at all.
	if rec := postJSON(t, s, "/api/network/proxy",
		networkProxyUpdate{Pattern: "*.internal", Proxy: "direct"}); rec.Code != http.StatusOK {
		t.Fatalf("rule-only POST answered %d: %s", rec.Code, rec.Body.String())
	}
	view := getNetworkProxyView(t, s)
	if view.Default != "http://127.0.0.1:3128" {
		t.Errorf("default is %q after a rule-only edit; an omitted field must leave it untouched", view.Default)
	}
	// And the explicit clear does work.
	empty := ""
	if rec := postJSON(t, s, "/api/network/proxy", networkProxyUpdate{Default: &empty}); rec.Code != http.StatusOK {
		t.Fatalf("clearing the default answered %d: %s", rec.Code, rec.Body.String())
	}
	if view := getNetworkProxyView(t, s); view.Default != "direct" {
		t.Errorf("an explicit empty default left %q", view.Default)
	}
	// A body with neither arm is a no-op request and is named as one rather than silently accepted.
	if rec := postJSON(t, s, "/api/network/proxy", networkProxyUpdate{}); rec.Code != http.StatusBadRequest {
		t.Errorf("an empty body answered %d, want 400", rec.Code)
	}
}

// The API never serves a proxy password back, on any arm, for a rule or for the default.
//
// Asserted over the raw response bytes rather than the decoded struct, so a field added later that
// happens to carry the credential fails here too.
func Test_network_proxy_never_serves_credentials_back(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	const secret = "s3cr3t-passphrase"
	withCreds := "http://operator:" + secret + "@127.0.0.1:3128"
	if rec := postJSON(t, s, "/api/network/proxy",
		networkProxyUpdate{Pattern: "*.internal", Proxy: "socks5://operator:" + secret + "@127.0.0.1:1080"}); rec.Code != http.StatusOK {
		t.Fatalf("POST with credentials answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/network/proxy", networkProxyUpdate{Default: &withCreds}); rec.Code != http.StatusOK {
		t.Fatalf("setting an authenticated default answered %d: %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/network/proxy", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Errorf("GET /api/network/proxy served the proxy password back:\n%s", body)
	}
	// The operator still has to be able to see that authentication is configured, or they cannot tell a
	// working rule from one that will fail to authenticate.
	view := getNetworkProxyView(t, s)
	if !view.Rules[0].HasCredentials || !view.DefaultHasCredentials {
		t.Error("credentials are configured but has_credentials is false, so the panel cannot report them")
	}
	if !view.CredentialsSupported {
		t.Error("credentials_supported is false, but this build honours them; the panel would tell the " +
			"operator their userinfo URL is being ignored when it is not")
	}
}
