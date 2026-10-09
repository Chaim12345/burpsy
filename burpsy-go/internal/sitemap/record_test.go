package sitemap

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Record (burpsy-react-ui-4bfp): Burp's add_to_sitemap by exchange id.

func (f *fixture) last(t *testing.T) *core.Exchange {
	t.Helper()
	all := f.store.Exchanges()
	return all[len(all)-1]
}

func TestRecordingAnExchangeAlreadyOnTheMapChangesNothing(t *testing.T) {
	f := newFixture(t)
	f.put(t, "/a", 200)
	res := f.sm.Record(f.last(t))
	if !res.AlreadyOnMap || res.WasSuppressed {
		t.Fatalf("an exchange the map follows was not reported as already on it: %+v", res)
	}
	if n := len(f.sm.Hosts()[0].Paths["/a"].ExchangeIDs); n != 1 {
		t.Fatalf("recording twice counted the exchange %d times", n)
	}
}

func TestRecordingPinsAnExchangePastTheSuppressionThatHidItUntilANewerOne(t *testing.T) {
	f := newFixture(t)
	f.put(t, "/api/users", 200)
	f.put(t, "/api/orders", 200)
	users := f.store.Exchanges()[0]
	f.sm.Suppress(HostKey("h", 80, false), "/api", suppressBranch)
	if got := f.paths(t); got["/api/users"] || got["/api/orders"] {
		t.Fatalf("the branch suppression did not hide its paths: %v", got)
	}

	res := f.sm.Record(users)
	if res.AlreadyOnMap || !res.WasSuppressed {
		t.Fatalf("recording a suppressed exchange reported %+v", res)
	}
	got := f.paths(t)
	if !got["/api/users"] || got["/api/orders"] {
		t.Fatalf("the pin should show exactly the recorded exchange; map has %v", got)
	}

	// A rebuild keeps the pin: it is an operator decision, not a fold accident.
	f.sm.Sync(f.store)
	if got := f.paths(t); !got["/api/users"] || got["/api/orders"] {
		t.Fatalf("Sync dropped the pin or the suppression: %v", got)
	}

	// A LATER suppression covering it is the newer decision and removes it, across rebuilds too.
	f.sm.Suppress(HostKey("h", 80, false), "", "")
	f.sm.Sync(f.store)
	if got := f.paths(t); len(got) != 0 {
		t.Fatalf("a newer host suppression left %v on the map", got)
	}
}
