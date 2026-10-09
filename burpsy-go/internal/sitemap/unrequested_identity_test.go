package sitemap

import (
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-u6f8: "already observed?" is a question about the map node (NodePath: query
// removed, normalised), not about the raw stored key, which keeps the query.

func TestNodePath(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", "/": "/", "/search": "/search", "/search?q=1": "/search", "/search/?q=1": "/search",
		"/search/": "/search", "search": "/search", "?q=1": "/", "/a/b//": "/a/b", "/r?next=/a/b": "/r",
	} {
		if got := NodePath(in); got != want {
			t.Errorf("NodePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAddUnrequestedComparesByNode(t *testing.T) {
	seen := time.Unix(1_700_000_000, 0)
	cases := []struct {
		observed, linked string
		refused          bool
	}{
		{"/search?q=1", "/search?q=1", true}, // the exact URL
		{"/search?q=1", "/search?q=2", true}, // same node, another query: q is in its parameter list
		{"/search?q=1", "/search", true},
		{"/search", "/search?q=1", true},
		{"/search/", "/search?q=1", true},
		{"/search?q=1", "/searches?q=1", false}, // a different node
		{"/search?q=1", "/search/deeper", false},
	}
	for _, c := range cases {
		sm := New()
		sm.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: c.observed})
		added := sm.AddUnrequested("app.test", 80, false, c.linked, "http://app.test/", seen)
		if added == c.refused {
			t.Errorf("observed %q, linked %q: AddUnrequested = %v, want %v", c.observed, c.linked, added, !c.refused)
		}
		// The other authority axes stay part of the identity.
		if !sm.AddUnrequested("app.test", 443, true, c.linked, "https://app.test/", seen) {
			t.Errorf("observed %q on http:80, linked %q on https:443 was refused", c.observed, c.linked)
		}
	}
}

func TestInsertOfAQueryVariantOfAnObservedNodeSaysObserved(t *testing.T) {
	sm := New()
	sm.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/search?q=1"})
	if !sm.Insert("app.test", 80, false, "/search", time.Now()) {
		t.Error("inserting /search after /search?q=1 was requested reported it as new, but GET " +
			"/api/sitemap draws /search as a requested node and drops the insert")
	}
	if len(sm.Inserts()) != 0 {
		t.Errorf("Inserts = %+v, want none", sm.Inserts())
	}
}

// The node count follows the observed tree down as well as up: a suppression that removes the last
// raw key of a node makes the node unobserved, one that leaves another raw key keeps it, and a Sync
// rebuild starts the count from the store.
func TestNodeCountFollowsSuppressAndSync(t *testing.T) {
	seen := time.Unix(1_700_000_000, 0)
	sm := New()
	sm.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/a?x=1"})
	sm.Add(&core.Exchange{ID: 2, Host: "app.test", Port: 80, Method: "GET", Path: "/a?x=2"})
	sm.Add(&core.Exchange{ID: 3, Host: "app.test", Port: 80, Method: "GET", Path: "/b/c?y=1"})
	key := HostKey("app.test", 80, false)

	sm.Suppress(key, "/a?x=1", suppressItem)
	if sm.AddUnrequested("app.test", 80, false, "/a?z=9", "", seen) {
		t.Error("/a?x=2 still holds the /a node, but a link to /a?z=9 was recorded as unrequested")
	}
	sm.Suppress(key, "/a?x=2", suppressItem)
	if !sm.AddUnrequested("app.test", 80, false, "/a?z=9", "", seen) {
		t.Error("no raw key holds /a any more, but a link to it was refused as observed")
	}

	sm.Suppress(key, "/b", suppressBranch)
	if sm.AddUnrequested("app.test", 80, false, "/b/c", "", seen) {
		t.Error("a link under a suppressed branch was recorded")
	}
	sm.mu.RLock()
	n := len(sm.nodes)
	sm.mu.RUnlock()
	if n != 0 {
		t.Errorf("node count holds %d entries after every observed path was suppressed", n)
	}

	store := core.NewTrafficStore()
	sm.Sync(store)
	sm.mu.RLock()
	n = len(sm.nodes)
	sm.mu.RUnlock()
	if n != 0 {
		t.Errorf("node count holds %d entries after a Sync from an empty store", n)
	}
}

func TestHostSuppressionClearsItsNodeCounts(t *testing.T) {
	sm := New()
	sm.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/a?x=1"})
	sm.Add(&core.Exchange{ID: 2, Host: "keep.test", Port: 80, Method: "GET", Path: "/a"})
	sm.Suppress(HostKey("app.test", 80, false), "", "host")
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.observedLocked("app.test", 80, false, "/a") {
		t.Error("a suppressed host's node still answers observed")
	}
	if !sm.observedLocked("keep.test", 80, false, "/a?q=1") {
		t.Error("another host's node was cleared with the suppressed one")
	}
}
