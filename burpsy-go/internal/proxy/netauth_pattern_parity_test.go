package proxy

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/netauth"
)

// internal/netauth's matchHost is a deliberate copy of this package's matchPattern: an
// operator who has learnt the TLS passthrough list's pattern language should not have to
// learn a second one for credentials, so the rule is copied rather than improved. It is
// copied rather than imported because matchPattern is unexported and internal/proxy sits
// above netauth in the dependency spine — importing it there would invert the direction.
//
// This test is the thing that stops the copy from drifting. It lives here because this is
// the side that can see both: netauth's matcher is reachable through Credentials.Match, and
// matchPattern is in this package.
//
// The failure it guards against is quiet and bad: a pattern that the passthrough list
// covers and the credential list does not means the operator writes `*.example.com`, sees
// it accepted on both panels, and gets a credential presented to some hosts and not others
// with nothing anywhere naming the difference.
func Test_netauth_host_patterns_agree_with_the_proxys(t *testing.T) {
	patterns := []string{
		"*",
		"example.com",
		"*.example.com",
		"*.co.uk",
		"api.example.com",
		"",
		"*.",
	}
	hosts := []string{
		"example.com",
		"api.example.com",
		"deep.api.example.com",
		"notexample.com",
		"example.com.evil.test",
		"co.uk",
		"anything.test",
		"",
	}

	for _, pattern := range patterns {
		for _, host := range hosts {
			want := matchPattern(pattern, host)

			// netauth has no exported matcher, deliberately — the rule is an internal detail of
			// how rules are looked up. It is exercised through the lookup itself, which is also
			// the only path that matters: a divergence only harms an operator by way of a
			// credential being or not being presented.
			store := netauth.NewCredentials()
			rule, err := netauth.NewCredential(pattern, netauth.SchemeBasic, "u", "p", "")
			if err != nil {
				// NewCredential refuses a blank host pattern, which matchPattern has no opinion
				// about. That is netauth being stricter at the door rather than a matcher
				// disagreement: a rule matching no host is not a working credential, and the
				// passthrough list has its own guard for the same input. Nothing to compare.
				continue
			}
			store.Add(rule)
			_, got := store.Match(host)

			if got != want {
				t.Errorf("pattern %q against host %q: proxy.matchPattern says %v, netauth says %v.\n"+
					"The two matchers have drifted. They are a deliberate copy of one rule, and an "+
					"operator who writes one pattern on both panels must get one behaviour.",
					pattern, host, want, got)
			}
		}
	}
}
