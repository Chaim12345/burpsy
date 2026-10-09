package sitemap

import (
	"strconv"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-vc98: the node-identity leftovers of u6f8, at the package level. The same four are
// pinned through GET /api/sitemap in internal/web/sitemap_node_identity_test.go.

func unrequestedPaths(sm *SiteMap) map[string]bool {
	out := map[string]bool{}
	for _, un := range sm.Unrequested() {
		out[un.Path] = true
	}
	return out
}

// (a) A grey item whose query carries "/" belongs to the node its path names: /r?next=/a/b is the
// /r node, so a request for /r (any query) covers it, and nothing about the slashes in its query
// makes it a /r?next=/a folder.
func TestUnrequestedWithSlashInQueryBelongsToItsNode(t *testing.T) {
	seen := time.Unix(1_700_000_000, 0)
	sm := New()
	if !sm.AddUnrequested("app.test", 80, false, "/r?next=/a/b", "http://app.test/", seen) {
		t.Fatal("AddUnrequested refused on an empty map")
	}
	if got := NodePath("/r?next=/a/b"); got != "/r" {
		t.Fatalf("NodePath = %q, want /r", got)
	}
	if got := NodeDepth("/r?next=/a/b"); got != 1 {
		t.Errorf("NodeDepth = %d, want 1: the query's slashes are not path segments", got)
	}
	// Requesting an unrelated node that shares the query's spelling covers nothing.
	sm.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/a/b"})
	if !unrequestedPaths(sm)["/r?next=/a/b"] {
		t.Fatal("a request for /a/b dropped the /r?next=/a/b item: the query is not its path")
	}
	sm.Add(&core.Exchange{ID: 2, Host: "app.test", Port: 80, Method: "GET", Path: "/r?next=/elsewhere"})
	if len(sm.Unrequested()) != 0 {
		t.Errorf("after /r was requested the /r?next=/a/b item is still stored: %+v", sm.Unrequested())
	}
}

// (b) An item delete on a clean path is a delete of the row: every raw key folded into /a goes from
// the live tree at once, and the node stops counting as observed — not on the next Sync.
func TestItemDeleteOfACleanPathTakesEveryRawKeyOfTheNode(t *testing.T) {
	seen := time.Unix(1_700_000_000, 0)
	sm := New()
	for i, p := range []string{"/a", "/a?x=1", "/a/?y=2", "/ab", "/a/child"} {
		sm.Add(&core.Exchange{ID: core.ExchangeID(i + 1), Host: "app.test", Port: 80, Method: "GET", Path: p})
	}
	key := HostKey("app.test", 80, false)
	sm.Suppress(key, "/a", suppressItem)

	left := map[string]bool{}
	for _, h := range sm.Hosts() {
		for p := range h.Paths {
			left[p] = true
		}
	}
	for _, gone := range []string{"/a", "/a?x=1", "/a/?y=2"} {
		if left[gone] {
			t.Errorf("%s is still in the live tree after an item delete of /a", gone)
		}
	}
	// Positive controls: a different node and a child are not the item.
	for _, kept := range []string{"/ab", "/a/child"} {
		if !left[kept] {
			t.Errorf("%s was removed by an item delete of /a", kept)
		}
	}
	sm.mu.RLock()
	observed := sm.observedLocked("app.test", 80, false, "/a")
	sm.mu.RUnlock()
	if observed {
		t.Error("/a still counts as observed after its row was deleted")
	}
	// And it stays out of a rebuild and of re-capture, query variants included.
	sm.Add(&core.Exchange{ID: 10, Host: "app.test", Port: 80, Method: "GET", Path: "/a?z=3"})
	for _, h := range sm.Hosts() {
		if _, ok := h.Paths["/a?z=3"]; ok {
			t.Error("a re-capture of /a?z=3 came back after the /a item was deleted")
		}
	}
	// A grey link at the deleted node is refused like any suppressed path.
	if sm.AddUnrequested("app.test", 80, false, "/a?q=1", "", seen) {
		t.Error("a link to the deleted /a node was recorded as unrequested")
	}
}

// An item delete naming one URL with its query removes that URL only, and keeps it out durably.
func TestItemDeleteOfAQueryURLIsExact(t *testing.T) {
	sm := New()
	sm.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/a?x=1"})
	sm.Add(&core.Exchange{ID: 2, Host: "app.test", Port: 80, Method: "GET", Path: "/a?x=2"})
	sm.Suppress(HostKey("app.test", 80, false), "/a?x=1", suppressItem)
	store := core.NewTrafficStore()
	store.AddExchange(&core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: "/a?x=1"})
	store.AddExchange(&core.Exchange{Host: "app.test", Port: 80, Method: "GET", Path: "/a?x=2"})
	sm.Sync(store)
	hosts := sm.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(hosts))
	}
	if _, ok := hosts[0].Paths["/a?x=1"]; ok {
		t.Error("/a?x=1 came back on a Sync after it was deleted")
	}
	if _, ok := hosts[0].Paths["/a?x=2"]; !ok {
		t.Error("/a?x=2 was removed by a delete naming /a?x=1")
	}
}

// (c) An unrequested item whose node becomes covered is dropped from the store, not merely hidden by
// the read, so it gives back its MaxUnrequested slot. Covered means its node was requested (any
// query) or something beneath it was (the map then draws it as a folder).
func TestUnrequestedItemsAreDroppedWhenTheirNodeIsCovered(t *testing.T) {
	seen := time.Unix(1_700_000_000, 0)
	sm := New()
	for _, p := range []string{"/search?q=1", "/search?q=2", "/api", "/api/v1?x=1", "/", "/other"} {
		if !sm.AddUnrequested("app.test", 80, false, p, "", seen) {
			t.Fatalf("AddUnrequested %s refused on an empty map", p)
		}
	}
	sm.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/search"})
	sm.Add(&core.Exchange{ID: 2, Host: "app.test", Port: 80, Method: "GET", Path: "/api/v1/users?id=7"})
	got := unrequestedPaths(sm)
	if len(got) != 1 || !got["/other"] {
		t.Errorf("stored unrequested = %v, want only /other: /search's queries, the /api and /api/v1 "+
			"folders and / are all covered", got)
	}
	sm.mu.RLock()
	n := sm.unrequestedN
	sm.mu.RUnlock()
	if n != 1 {
		t.Errorf("unrequestedN = %d, want 1", n)
	}
	// Folder coverage refuses at record time too, and stops when the node beneath goes away.
	if sm.AddUnrequested("app.test", 80, false, "/api/v1/", "", seen) {
		t.Error("a link to the /api/v1 folder was recorded while /api/v1/users is observed")
	}
	sm.Suppress(HostKey("app.test", 80, false), "/api/v1/users", suppressItem)
	if !sm.AddUnrequested("app.test", 80, false, "/api/v1", "", seen) {
		t.Error("nothing is observed under /api/v1 any more, but a link to it was refused")
	}
}

// The slots freed by pruning are reusable: a set filled to MaxUnrequested accepts new items again
// once the filled items' node is requested.
func TestPrunedUnrequestedItemsFreeTheirSlots(t *testing.T) {
	seen := time.Unix(1_700_000_000, 0)
	sm := New()
	for i := 0; i < MaxUnrequested; i++ {
		if !sm.AddUnrequested("app.test", 80, false, "/cal?d="+strconv.Itoa(i), "", seen) {
			t.Fatalf("item %d refused before the cap", i)
		}
	}
	if sm.AddUnrequested("app.test", 80, false, "/next", "", seen) {
		t.Fatal("the set accepted an item past MaxUnrequested")
	}
	sm.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/cal?d=0"})
	if !sm.AddUnrequested("app.test", 80, false, "/next", "", seen) {
		t.Error("requesting /cal hid every /cal item but their slots were not given back")
	}
}

// A branch or host delete drops the grey items beneath it as well.
func TestSuppressDropsUnrequestedItemsBeneathIt(t *testing.T) {
	seen := time.Unix(1_700_000_000, 0)
	sm := New()
	for _, p := range []string{"/b/x", "/b?y=1", "/bb", "/c"} {
		sm.AddUnrequested("app.test", 80, false, p, "", seen)
	}
	sm.AddUnrequested("keep.test", 80, false, "/b/x", "", seen)
	sm.Suppress(HostKey("app.test", 80, false), "/b", suppressBranch)
	got := map[string]bool{}
	for _, un := range sm.Unrequested() {
		got[un.Host+un.Path] = true
	}
	if got["app.test/b/x"] || got["app.test/b?y=1"] {
		t.Errorf("items under the deleted /b branch survive: %v", got)
	}
	if !got["app.test/bb"] || !got["app.test/c"] || !got["keep.test/b/x"] {
		t.Errorf("items outside the deleted branch were dropped: %v", got)
	}
	sm.Suppress(HostKey("app.test", 80, false), "", "host")
	for _, un := range sm.Unrequested() {
		if un.Host == "app.test" {
			t.Errorf("%s on a deleted host survives", un.Path)
		}
	}
	if len(sm.Unrequested()) != 1 {
		t.Errorf("keep.test's item was dropped with another host: %v", sm.Unrequested())
	}
}

// (d) NodeDepth is the observed fold's depth rule.
func TestNodeDepth(t *testing.T) {
	for in, want := range map[string]int{
		"/": 1, "/a": 1, "/a/": 1, "/a/b": 2, "/a/b?c=/d/e": 2, "a/b": 2, "/a/b/c/": 3,
	} {
		if got := NodeDepth(in); got != want {
			t.Errorf("NodeDepth(%q) = %d, want %d", in, got, want)
		}
	}
}
