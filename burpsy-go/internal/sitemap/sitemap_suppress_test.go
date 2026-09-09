package sitemap

// Suppression semantics (burpsy-react-ui-10e). The properties pinned here are the ones the issue's
// recorded decision rests on: removal hides nodes from the map without touching the store, the
// three verbs answer differently (host = everything, branch = path and beneath it, item = exactly
// that path), and a suppressed branch stays out when traffic re-arrives or Sync rebuilds. The
// /apiary boundary matters because a prefix match on raw strings would let a deleted /api swallow
// a sibling /apiary — segment boundaries are the difference between pruning a branch and pruning
// the alphabet.

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

type fixture struct {
	store *core.TrafficStore
	sm    *SiteMap
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := core.NewTrafficStore()
	sm := New()
	sm.Follow(store)
	return &fixture{store: store, sm: sm}
}

// put captures one exchange at path with the given status, the way the proxy would have.
func (f *fixture) put(t *testing.T, path string, status uint16) {
	t.Helper()
	id, err := f.store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: h\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("Put %s: %v", path, err)
	}
	f.store.AddExchange(&core.Exchange{Request: id, Host: "h", Port: 80, Method: "GET", Path: path, Status: &status})
}

func (f *fixture) paths(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, hn := range f.sm.Hosts() {
		for p := range hn.Paths {
			out[p] = true
		}
	}
	return out
}

// The key shape Suppress and suppressedByLocked agree on, spelled out once so a change to hostKey
// shows up here as a failure rather than as silent non-suppression.
// boolToStr writes Go's %v spelling ("true"/"false" → here "0" is false's rune form); pinned via
// HostKey rather than restated, so the test fails loudly if the shape drifts.
const testHostKey = "h:80:0"

func TestSuppressHostRemovesEveryNodeAndKeepsThemOutOnRebuild(t *testing.T) {
	f := newFixture(t)
	f.put(t, "/a", 200)
	f.put(t, "/a/b", 200)

	if HostKey("h", 80, false) != testHostKey {
		t.Fatalf("HostKey = %q, want %q — the suppression key shape drifted", HostKey("h", 80, false), testHostKey)
	}
	f.sm.Suppress(testHostKey, "", "")
	if got := f.paths(t); len(got) != 0 {
		t.Fatalf("after host suppress the map still shows %v, want nothing", got)
	}

	// A re-capture on the suppressed host stays out too — the decision outlives the traffic.
	f.put(t, "/again", 200)
	if got := f.paths(t); len(got) != 0 {
		t.Fatalf("re-capture on a suppressed host reappeared: %v", got)
	}
}

func TestSuppressBranchTakesDescendantsButNotSiblings(t *testing.T) {
	f := newFixture(t)
	f.put(t, "/api", 200)
	f.put(t, "/api/data", 200)
	f.put(t, "/apiary", 200) // prefix trap: /api must not swallow /apiary

	f.sm.Suppress(HostKey("h", 80, false), "/api", "branch")
	got := f.paths(t)
	if got["/api"] || got["/api/data"] {
		t.Fatalf("branch /api still shows %v", got)
	}
	if !got["/apiary"] {
		t.Fatalf("/apiary vanished with the /api branch — the prefix matched on raw strings, not segment boundaries")
	}

	// The descendants stay out on rebuild, not just in the live tree.
	f.sm.Sync(f.store)
	got = f.paths(t)
	if got["/api"] || got["/api/data"] {
		t.Fatalf("branch /api came back on Sync rebuild: %v", got)
	}
	if !got["/apiary"] {
		t.Fatal("/apiary did not survive the rebuild")
	}
}

func TestSuppressItemLeavesSiblingsAndDescendantsAlone(t *testing.T) {
	f := newFixture(t)
	f.put(t, "/api", 200)
	f.put(t, "/api/data", 200)

	f.sm.Suppress(HostKey("h", 80, false), "/api", "item")
	got := f.paths(t)
	if got["/api"] {
		t.Fatal("the deleted item is still listed")
	}
	if !got["/api/data"] {
		t.Fatalf("an item delete of /api took /api/data with it — item and branch mean different things")
	}
}

func TestSuppressionSurvivesSyncAndStoreStaysWhole(t *testing.T) {
	f := newFixture(t)
	f.put(t, "/gone", 200)
	f.put(t, "/kept", 200)
	f.sm.Suppress(HostKey("h", 80, false), "/gone", "item")

	// Sync folds every STORED exchange again — the suppressed one is still in the store, by
	// decision, so the rebuild must re-apply the suppression rather than resurrect the node.
	f.sm.Sync(f.store)
	if got := f.paths(t); got["/gone"] {
		t.Fatal("a suppressed node walked back in on the next rebuild")
	}
	if !f.paths(t)["/kept"] {
		t.Fatal("the unsuppressed sibling did not survive the rebuild")
	}
	// And the underlying capture is intact: the message is still addressable.
	if messages, exchanges := f.store.Count(); messages == 0 || exchanges == 0 {
		t.Fatalf("store reports %d messages / %d exchanges after suppression — the capture was touched", messages, exchanges)
	}
	if _, exchanges := f.store.Count(); exchanges != 2 {
		t.Fatalf("store holds %d exchanges after suppression, want 2 — suppression deleted capture rows", exchanges)
	}
}
