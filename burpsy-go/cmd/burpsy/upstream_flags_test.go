package main

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/upstream"
)

func Test_parseUpstreamFlags_reads_a_default_and_ordered_rules(t *testing.T) {
	flags, err := parseUpstreamFlags(
		"http://corp.test:3128",
		"api.example.com=direct, *.example.com=socks5://127.0.0.1:1080 ,*=https://egress.test:8443")
	if err != nil {
		t.Fatalf("parseUpstreamFlags: %v", err)
	}
	if len(flags) != 4 {
		t.Fatalf("parsed %d entries, want 4 (one default plus three rules)", len(flags))
	}
	if flags[0].pattern != "" || flags[0].proxy != "http://corp.test:3128" {
		t.Errorf("the default is %+v, want the empty pattern carrying the -upstream-proxy value", flags[0])
	}
	// Order is the resolution order, so it has to survive parsing.
	for i, want := range []string{"api.example.com", "*.example.com", "*"} {
		if flags[i+1].pattern != want {
			t.Errorf("rule %d is %q, want %q", i, flags[i+1].pattern, want)
		}
	}

	policy := upstream.NewPolicy()
	applyUpstreamFlags(policy, flags)
	if !policy.For("api.example.com").IsDirect() {
		t.Error("the direct exemption did not survive the flag round trip")
	}
	if policy.For("www.example.com").Kind() != upstream.KindSOCKS5 {
		t.Error("the socks5 rule did not survive the flag round trip")
	}
	if policy.For("nothing.test").Kind() != upstream.KindHTTPS {
		t.Error("the catch-all rule did not survive the flag round trip")
	}
}

// Every malformed flag is refused at the command line rather than becoming a rule that fails at dial
// time. Refuse-by-default: a proxy an operator asked for and that cannot be used must never silently
// become a direct connection.
func Test_parseUpstreamFlags_refuses_bad_input(t *testing.T) {
	for name, tc := range map[string]struct{ def, rules string }{
		"default with no scheme":  {def: "127.0.0.1:8080"},
		"default with no port":    {def: "http://127.0.0.1"},
		"default unknown scheme":  {def: "gopher://127.0.0.1:70"},
		"rule without an equals":  {rules: "*.internal"},
		"rule with no pattern":    {rules: "=http://127.0.0.1:3128"},
		"rule with a bad url":     {rules: "*.internal=127.0.0.1:1080"},
		"socks4 with a password":  {rules: "*.internal=socks4://u:p@127.0.0.1:1080"},
		"one good and one broken": {rules: "*.ok=http://127.0.0.1:3128,*.bad=nope://x:1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseUpstreamFlags(tc.def, tc.rules); err == nil {
				t.Error("accepted; a mistyped proxy must stop the process at the command line")
			}
		})
	}
}

// A proxy URL whose password contains '=' keeps it. Splitting on the last '=' rather than the first
// would silently mangle exactly the credential that must not be guessed at.
func Test_parseUpstreamFlags_splits_a_rule_on_the_first_equals(t *testing.T) {
	flags, err := parseUpstreamFlags("", "*.internal=http://operator:pa=ss@127.0.0.1:3128")
	if err != nil {
		t.Fatalf("parseUpstreamFlags: %v", err)
	}
	if len(flags) != 1 || flags[0].pattern != "*.internal" {
		t.Fatalf("parsed %+v, want one rule for *.internal", flags)
	}
	policy := upstream.NewPolicy()
	applyUpstreamFlags(policy, flags)
	rules := policy.Rules()
	if len(rules) != 1 || !rules[0].Proxy.HasCredentials() {
		t.Fatalf("the credential was lost: %+v", rules)
	}
	// Raw is what persistence writes, so the password has to be intact there.
	if !strings.Contains(rules[0].Proxy.Raw(), "pa=ss") {
		t.Errorf("the password was mangled: %q", rules[0].Proxy.Raw())
	}
}

// Flag rules applied over restored ones replace in place rather than duplicating.
//
// This is the startup ordering the whole feature depends on: persisted rules are restored first, then
// the flag-named ones are applied over them. Without upsert semantics, a rule named on the command line
// that is already in the database becomes a second copy whose lower position makes it unreachable.
func Test_flag_rules_applied_over_restored_rules_deduplicate(t *testing.T) {
	// Standing in for the restored-from-database state.
	policy := upstream.NewPolicy()
	if _, err := policy.Set("*.internal", "http://old-proxy.test:3128"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := policy.Set("*.other", "http://other.test:3128"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	flags, err := parseUpstreamFlags("", "*.internal=socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("parseUpstreamFlags: %v", err)
	}
	applyUpstreamFlags(policy, flags)

	rules := policy.Rules()
	if len(rules) != 2 {
		t.Fatalf("re-applying a flag rule produced %d rules, want 2 — the flag rule duplicated a "+
			"restored one instead of replacing it", len(rules))
	}
	if rules[0].Pattern != "*.internal" || rules[0].Proxy.Kind() != upstream.KindSOCKS5 {
		t.Errorf("rule 0 is %s → %s, want *.internal replaced in place by the socks5 flag value",
			rules[0].Pattern, rules[0].Proxy.Display())
	}
	if rules[1].Pattern != "*.other" {
		t.Errorf("the untouched rule moved: rule 1 is %q", rules[1].Pattern)
	}
}

// Both flags empty is not an error and configures nothing, which is the ordinary case.
func Test_parseUpstreamFlags_with_nothing_set_configures_nothing(t *testing.T) {
	flags, err := parseUpstreamFlags("", "")
	if err != nil {
		t.Fatalf("parseUpstreamFlags: %v", err)
	}
	if len(flags) != 0 {
		t.Errorf("parsed %d entries from empty flags", len(flags))
	}
	policy := upstream.NewPolicy()
	applyUpstreamFlags(policy, flags)
	if !policy.Empty() {
		t.Error("empty flags produced a non-empty policy")
	}
}
