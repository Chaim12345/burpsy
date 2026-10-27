package sitemap

import (
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// "Add to site map" (amu). The decision recorded on the bead: operator-added nodes are allowed,
// kept SEPARATE from the observed tree, and labelled. This file pins the separation, because the
// failure it prevents is the project's worst one — a map that claims a host was observed when the
// only evidence is that an operator wrote it down.

func TestAnInsertedNodeSurvivesASyncRebuild(t *testing.T) {
	sm := New()
	now := time.Unix(1_700_000_000, 0)
	if observed := sm.Insert("known.test", 443, true, "/admin", now); observed {
		t.Fatal("an insert reported the node was already observed, with an empty map")
	}

	// Sync is the rebuild path: a full fold from the traffic store, which is exactly what would
	// erase an insert written into the observed tree.
	sm.Sync(core.NewTrafficStore())

	if !sm.Inserted("known.test", 443, true, "/admin") {
		t.Error("the inserted node did not survive Sync: Sync rebuilds the observed tree from " +
			"traffic, so an insert stored there would be erased on the next rebuild")
	}
	if len(sm.Hosts()) != 0 {
		t.Errorf("the observed tree holds %d host(s) after an insert into an empty map: an "+
			"operator-added node must not present as observed traffic", len(sm.Hosts()))
	}
	got := sm.Inserts()
	if len(got) != 1 || got[0].Host != "known.test" || got[0].Path != "/admin" {
		t.Fatalf("Inserts = %+v, want the one inserted node", got)
	}
}

func TestAnInsertOfAnObservedNodeSaysSo(t *testing.T) {
	sm := New()
	sm.Add(sitemapExchange(t, "seen.test", 443, true, "/app"))

	// A path that is already on the map is a second row claiming a URL was never looked at, so the
	// insert reports it and records nothing.
	if observed := sm.Insert("seen.test", 443, true, "/app", time.Now()); !observed {
		t.Error("inserting an observed path reported it as new: the operator would be told they " +
			"recorded a URL the map already carried because traffic was seen")
	}
	if sm.Inserted("seen.test", 443, true, "/app") {
		t.Error("an insert of an observed path was recorded: the observation is the stronger fact")
	}
	if len(sm.Inserts()) != 0 {
		t.Errorf("Inserts = %+v, want none for an already-observed node", sm.Inserts())
	}
}

func TestARepeatedInsertKeepsTheFirstTime(t *testing.T) {
	sm := New()
	first := time.Unix(1_700_000_000, 0)
	later := first.Add(time.Hour)
	sm.Insert("app.test", 80, false, "/x", first)
	sm.Insert("app.test", 80, false, "/x", later)

	got := sm.Inserts()
	if len(got) != 1 {
		t.Fatalf("a repeated insert produced %d nodes, want 1", len(got))
	}
	if !got[0].Added.Equal(first) {
		t.Errorf("Added = %v, want the first insert's %v: 'when did you add this' is a fact about "+
			"the decision, not about the last click", got[0].Added, first)
	}
}

func TestAnInsertWithNoPortIsRefused(t *testing.T) {
	sm := New()
	sm.Insert("app.test", 0, false, "", time.Now())
	if len(sm.Inserts()) != 0 {
		t.Error("a host with no port was recorded: a map node names one authority, and app.test:0 is " +
			"not one")
	}
}

func TestInsertsComeBackInAStableOrder(t *testing.T) {
	sm := New()
	now := time.Now()
	sm.Insert("b.test", 80, false, "/z", now)
	sm.Insert("a.test", 80, false, "/y", now)
	sm.Insert("a.test", 80, false, "/x", now)

	got := sm.Inserts()
	want := [][2]string{{"a.test", "/x"}, {"a.test", "/y"}, {"b.test", "/z"}}
	if len(got) != len(want) {
		t.Fatalf("Inserts = %+v, want %d nodes", got, len(want))
	}
	for i, w := range want {
		if got[i].Host != w[0] || got[i].Path != w[1] {
			t.Errorf("node %d = %s%s, want %s%s (sorted, so the UI and the API agree on the tree)",
				i, got[i].Host, got[i].Path, w[0], w[1])
		}
	}
}

// sitemapExchange is one observed exchange, the shape Add folds in.
func sitemapExchange(t *testing.T, host string, port uint16, tls bool, path string) *core.Exchange {
	t.Helper()
	store := core.NewTrafficStore()
	id, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	status := uint16(200)
	return &core.Exchange{Request: core.MsgPtr(id), Host: host, Port: port, TLS: tls, Method: "GET", Path: path, Status: &status}
}

// A folder with observed traffic beneath it is already on the map: the read hides an insert there,
// so storing one would be a hidden row and an already_seen:false answer for a change nobody can see
// (burpsy-react-ui-86l0).
func TestAnInsertAtAnObservedFolderSaysSo(t *testing.T) {
	sm := New()
	sm.Add(sitemapExchange(t, "seen.test", 443, true, "/app/users/7"))
	for _, folder := range []string{"/app", "/app/users", "/"} {
		if observed := sm.Insert("seen.test", 443, true, folder, time.Now()); !observed {
			t.Errorf("inserting %s, which observed traffic sits beneath, reported it as new", folder)
		}
	}
	if len(sm.Inserts()) != 0 {
		t.Errorf("Inserts = %+v, want none: every one of those folders is already covered", sm.Inserts())
	}
	// A sibling nothing was observed under is still a new insert.
	if observed := sm.Insert("seen.test", 443, true, "/admin", time.Now()); observed {
		t.Error("an uncovered sibling was reported as already observed")
	}
}
