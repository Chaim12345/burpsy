package sitemap

// Mimes folds up the tree like every other aggregation (burpsy-react-ui-36d), and the UI's MIME
// filter bucket depends on two properties pinned here: a node's set is exactly the distinct media
// types seen at that path, and a synthesised folder reports the union of its subtree — a collapsed
// folder whose children serve HTML must still be visible to a "show HTML" filter, or the filter
// silently hides a branch the operator is looking for.

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestMimeFoldsOntoThePathNodeAndUnionsUpFolders(t *testing.T) {
	store := core.NewTrafficStore()
	sm := New()
	sm.Follow(store)

	putWithMime := func(path, mime string) {
		t.Helper()
		id, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: h\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatalf("Put %s: %v", path, err)
		}
		status := uint16(200)
		store.AddExchange(&core.Exchange{
			Request: core.MsgPtr(id),
			Host:    "h",
			Port:    80,
			Method:  "GET",
			Path:    path,
			Status:  &status,
			Mime:    mime,
		})
	}

	putWithMime("/api/data", "json")
	putWithMime("/api/data", "json") // duplicate mime must not double-count
	putWithMime("/page", "html")

	// The Hosts() deep-copy is what the web layer reads, so assert against the copy.
	hosts := sm.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("map holds %d hosts, want 1", len(hosts))
	}
	leaf := hosts[0].Paths["/api/data"]
	if leaf == nil {
		t.Fatal("/api/data did not fold into a path node")
	}
	if got := len(leaf.Mimes); got != 1 {
		t.Fatalf("/api/data holds %d mimes, want 1 — a duplicate response type was counted twice", got)
	}
	if _, ok := leaf.Mimes["json"]; !ok {
		t.Fatalf("/api/data holds %v, want json", leaf.Mimes)
	}
}
