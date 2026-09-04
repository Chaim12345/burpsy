package persist

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/upstream"
)

// The upstream proxy policy survives a restart with its ordering, its kinds and its credentials.
//
// Ordering is asserted because the rule list's order *is* its semantics — first match wins — so a
// restore that reshuffled it would silently send a host through a different proxy than the operator
// configured, which is exactly the class of failure that is invisible until someone reads a packet
// capture.
func TestUpstreamProxyPolicySurvivesARoundTrip(t *testing.T) {
	p := newTestStore(t)

	saved := upstream.NewPolicy()
	if err := saved.SetDefault("http://corp-proxy.test:3128"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	// Ordered deliberately: the specific exemption sits above the broad rule, which is the only
	// arrangement in which it has any effect.
	for _, rule := range []struct{ pattern, proxy string }{
		{"api.example.com", "direct"},
		{"*.example.com", "socks5://127.0.0.1:1080"},
		{"*", "https://egress.test:8443"},
	} {
		if _, err := saved.Set(rule.pattern, rule.proxy); err != nil {
			t.Fatalf("Set %s: %v", rule.pattern, err)
		}
	}
	p.SaveUpstreamProxy(saved)

	restored := upstream.NewPolicy()
	if err := p.LoadUpstreamProxy(restored); err != nil {
		t.Fatalf("LoadUpstreamProxy: %v", err)
	}

	if got, want := restored.Default().Display(), "http://corp-proxy.test:3128"; got != want {
		t.Errorf("restored default = %q, want %q", got, want)
	}
	rules := restored.Rules()
	if len(rules) != 3 {
		t.Fatalf("restored %d rules, want 3", len(rules))
	}
	wantOrder := []string{"api.example.com", "*.example.com", "*"}
	for i, want := range wantOrder {
		if rules[i].Pattern != want {
			t.Fatalf("restored rule %d is %q, want %q — the order is the resolution order, so a reshuffle "+
				"routes traffic through a proxy the operator did not choose", i, rules[i].Pattern, want)
		}
	}
	if !rules[0].Proxy.IsDirect() {
		t.Error("the direct exemption came back as a proxied rule, so the host it exempted is now proxied")
	}
	if rules[1].Proxy.Kind() != upstream.KindSOCKS5 {
		t.Errorf("the socks5 rule came back as %q", rules[1].Proxy.Kind())
	}
	if rules[2].Proxy.Kind() != upstream.KindHTTPS {
		t.Errorf("the https rule came back as %q", rules[2].Proxy.Kind())
	}

	// And resolution through the restored policy agrees with the rules it holds.
	if !restored.For("api.example.com").IsDirect() {
		t.Error("api.example.com resolves to a proxy after the restore; its exemption was lost")
	}
	if restored.For("www.example.com").Kind() != upstream.KindSOCKS5 {
		t.Error("a subdomain no longer resolves through the socks5 rule")
	}
	if restored.For("elsewhere.test").Kind() != upstream.KindHTTPS {
		t.Error("an unmatched host no longer falls through to the catch-all rule")
	}
}

// Credentials survive too, because a policy restored without its password would come back looking
// configured and start failing authentication — the same class of lie as a rule that silently stopped
// proxying. This is the one place they are written, and it is stated in SaveUpstreamProxy's doc.
func TestUpstreamProxyCredentialsSurviveARoundTrip(t *testing.T) {
	p := newTestStore(t)
	saved := upstream.NewPolicy()
	if _, err := saved.Set("*.internal", "socks5://operator:s3cr3t@127.0.0.1:1080"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	p.SaveUpstreamProxy(saved)

	restored := upstream.NewPolicy()
	if err := p.LoadUpstreamProxy(restored); err != nil {
		t.Fatalf("LoadUpstreamProxy: %v", err)
	}
	rules := restored.Rules()
	if len(rules) != 1 {
		t.Fatalf("restored %d rules, want 1", len(rules))
	}
	if !rules[0].Proxy.HasCredentials() {
		t.Error("the restored rule has no credentials, so it will start failing authentication while " +
			"looking correctly configured")
	}
	// The redacted rendering is still redacted after a round trip: nothing about restoring a password
	// should make Display start emitting it.
	if display := rules[0].Proxy.Display(); strings.Contains(display, "s3cr3t") {
		t.Errorf("Display() emits the restored password: %q", display)
	}
}

// An absent row is not an error and leaves the policy alone.
//
// "No row" and "a row that says direct" are the same operational state, and neither is a failure —
// a fresh database must not make the process refuse to start.
func TestLoadUpstreamProxyWithNoStoredRowLeavesThePolicyAlone(t *testing.T) {
	p := newTestStore(t)
	policy := upstream.NewPolicy()
	if _, err := policy.Set("*.internal", "http://127.0.0.1:3128"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := p.LoadUpstreamProxy(policy); err != nil {
		t.Fatalf("LoadUpstreamProxy on an empty database: %v", err)
	}
	if len(policy.Rules()) != 1 {
		t.Errorf("an absent row wiped the policy: %d rule(s) left", len(policy.Rules()))
	}
}

// A stored row that does not parse is an error, not a silent fall-back to direct.
//
// The failure this guards is the worst one available here: a hand-edited or corrupted row that loads as
// "no proxy" means traffic goes straight to the target while the operator believes it is being
// chained. Returning the error lets the caller refuse to start instead.
func TestLoadUpstreamProxyRefusesAnUnreadableRow(t *testing.T) {
	p := newTestStore(t)
	if err := p.setSetting(upstreamProxyKey, `{"default":"gopher://nope:70","rules":[]}`); err != nil {
		t.Fatalf("seed the settings row: %v", err)
	}
	policy := upstream.NewPolicy()
	err := p.LoadUpstreamProxy(policy)
	if err == nil {
		t.Fatal("a stored proxy URL this build cannot speak loaded without complaint; traffic would go " +
			"out direct while the panel showed a configured proxy")
	}
	if !strings.Contains(err.Error(), "gopher") {
		t.Errorf("the error does not name the unusable value: %v", err)
	}

	// Not JSON at all is refused the same way.
	if err := p.setSetting(upstreamProxyKey, "{not json"); err != nil {
		t.Fatalf("seed the settings row: %v", err)
	}
	if err := p.LoadUpstreamProxy(upstream.NewPolicy()); err == nil {
		t.Fatal("an unparseable settings row loaded without complaint")
	}
}

// Saving replaces the row wholesale rather than accumulating, which is the contract the key/value
// settings table gives and the reason this needed no table of its own.
func TestSaveUpstreamProxyReplacesTheStoredPolicy(t *testing.T) {
	p := newTestStore(t)
	first := upstream.NewPolicy()
	if _, err := first.Set("*.old", "http://127.0.0.1:3128"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	p.SaveUpstreamProxy(first)

	second := upstream.NewPolicy()
	if _, err := second.Set("*.new", "socks5://127.0.0.1:1080"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	p.SaveUpstreamProxy(second)

	restored := upstream.NewPolicy()
	if err := p.LoadUpstreamProxy(restored); err != nil {
		t.Fatalf("LoadUpstreamProxy: %v", err)
	}
	rules := restored.Rules()
	if len(rules) != 1 || rules[0].Pattern != "*.new" {
		t.Fatalf("restored %d rule(s) (%v); the second save must replace the first, not add to it",
			len(rules), rules)
	}
}
