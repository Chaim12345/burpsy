package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/sitemap"
)

// burpsy-react-ui-vc98: the node-identity leftovers of u6f8, through GET /api/sitemap. The package
// level halves are in internal/sitemap/node_identity_leftovers_test.go.

func sitemapTree(t *testing.T, s *Server) sitemapTreeResp {
	t.Helper()
	var v sitemapTreeResp
	if err := json.Unmarshal([]byte(get200(t, s, "/api/sitemap")), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// flatNodes walks the tree and records every node by host-qualified path, with the depth it reports
// and the depth it actually sits at (0 for a host row).
type flatNode struct {
	view      sitemapNodeView
	nestDepth int
}

func flatten(tree []sitemapNodeView) map[string]flatNode {
	out := map[string]flatNode{}
	var walk func(host string, ns []sitemapNodeView, depth int)
	walk = func(host string, ns []sitemapNodeView, depth int) {
		for _, n := range ns {
			h := host
			if depth == 0 {
				h = n.Path
			}
			id := h
			if depth > 0 {
				id = h + " " + n.Path
			}
			out[id] = flatNode{view: n, nestDepth: depth}
			walk(h, n.Children, depth+1)
		}
	}
	walk("", tree, 0)
	return out
}

func countNodes(tree []sitemapNodeView) int {
	n := 0
	for _, v := range tree {
		n += 1 + countNodes(v.Children)
	}
	return n
}

// (a) A grey item whose query carries "/" is drawn at its node, with its query's names as params —
// no stray /r?next= or /r?next=/a folders.
func TestSitemapGetPlacesAGreyItemWithASlashInItsQueryAtItsNode(t *testing.T) {
	s := newTestServer()
	seen := time.Unix(1_700_000_000, 0)
	for _, p := range []string{"/r?next=/a/b", "/r?back=/c"} {
		if !s.sitemap.AddUnrequested("app.test", 80, false, p, "http://app.test/", seen) {
			t.Fatalf("AddUnrequested %s refused", p)
		}
	}
	v := sitemapTree(t, s)
	nodes := flatten(v.Tree)
	for id := range nodes {
		if strings.Contains(id, "?") {
			t.Errorf("a node is keyed on a query string: %q", id)
		}
	}
	r, ok := nodes["app.test /r"]
	if !ok {
		t.Fatalf("no /r node: %v", nodes)
	}
	if !r.view.Unrequested || r.view.Segment != "r" || strings.Join(r.view.Params, ",") != "back,next" {
		t.Errorf("/r = unrequested %v segment %q params %v, want a grey r carrying back,next",
			r.view.Unrequested, r.view.Segment, r.view.Params)
	}
	if r.nestDepth != 1 {
		t.Errorf("/r sits at nesting depth %d, want 1 (directly under its host)", r.nestDepth)
	}
	// Host + /r, nothing else, and the count says so.
	if len(nodes) != 2 || v.Nodes != 2 || countNodes(v.Tree) != 2 {
		t.Errorf("nodes = %d drawn, %d counted, want 2 and 2: %v", countNodes(v.Tree), v.Nodes, nodes)
	}
	// And a request for /r (any query) clears it.
	addTraffic(t, s.store, "app.test", "GET", "/r?next=/x")
	for _, n := range flatten(sitemapTree(t, s).Tree) {
		if n.view.Unrequested {
			t.Errorf("a grey %s is left after /r was requested", n.view.Path)
		}
	}
}

// (b) "Delete item" on a clean row takes every query variant folded into it off the next read, and
// the row's node stops counting as observed, so a link to it is grey again rather than refused.
func TestSitemapDeleteItemOfACleanPathRemovesItsQueryVariants(t *testing.T) {
	s := newTestServer()
	addTraffic(t, s.store, "h", "GET", "/a")
	addTraffic(t, s.store, "h", "GET", "/a?x=1")
	addTraffic(t, s.store, "h", "GET", "/a/child")
	before := flatten(sitemapTree(t, s).Tree)
	if _, ok := before["h /a"]; !ok {
		t.Fatalf("precondition: no /a row: %v", before)
	}

	if rec := sitemapDelete(t, s, `{"host":"h","port":80,"tls":false,"path":"/a","kind":"item"}`); rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d (%s)", rec.Code, rec.Body.String())
	}
	after := flatten(sitemapTree(t, s).Tree)
	a, ok := after["h /a"]
	if ok && (a.view.Requested || a.view.Exchanges != 0 || len(a.view.Params) != 0) {
		t.Errorf("after an item delete of /a the row still shows traffic: requested %v exchanges %d params %v",
			a.view.Requested, a.view.Exchanges, a.view.Params)
	}
	// Positive control: /a/child is a different row and stays, so /a is now only its folder.
	if c, ok := after["h /a/child"]; !ok || !c.view.Requested {
		t.Fatalf("/a/child went with the /a item: %v", after)
	}
	// /a?x=1 kept the node observed before the fix; a link to /a must now be recordable — but the
	// read still covers /a as /a/child's folder, so test the record-time answer directly.
	if !s.sitemap.AddUnrequested("h", 80, false, "/a/other", "", time.Now()) {
		t.Error("a link beside the deleted item was refused")
	}
}

// (c) A grey item whose node is requested later is gone from the store too, not only from the read.
func TestSitemapRequestingANodeDropsItsStoredGreyItems(t *testing.T) {
	s := newTestServer()
	seen := time.Unix(1_700_000_000, 0)
	for _, p := range []string{"/s?q=1", "/s?q=2", "/api", "/keep"} {
		s.sitemap.AddUnrequested("h", 80, false, p, "", seen)
	}
	addTraffic(t, s.store, "h", "GET", "/s")
	addTraffic(t, s.store, "h", "GET", "/api/users")
	stored := s.sitemap.Unrequested()
	if len(stored) != 1 || stored[0].Path != "/keep" {
		t.Errorf("stored unrequested = %v, want only /keep", stored)
	}
	grey := 0
	for _, n := range flatten(sitemapTree(t, s).Tree) {
		if n.view.Unrequested {
			grey++
			if n.view.Path != "/keep" {
				t.Errorf("grey %s drawn after its node was requested", n.view.Path)
			}
		}
	}
	if grey != 1 {
		t.Errorf("drew %d grey rows, want 1 (/keep)", grey)
	}
}

// (d) Inserted and unrequested items report the depth the observed fold gives a node at the same
// path, and sit at that nesting depth, with their synthesised folders outermost first.
func TestSitemapGetGivesInsertedAndGreyItemsTheirRealDepth(t *testing.T) {
	s := newTestServer()
	seen := time.Unix(1_700_000_000, 0)
	addTraffic(t, s.store, "h", "GET", "/obs/deep/leaf")
	s.sitemap.Insert("h", 80, false, "/api/v1/users", seen)
	s.sitemap.AddUnrequested("h", 80, false, "/obs/deep/grey?x=/y", "", seen)
	s.sitemap.AddUnrequested("other.test", 80, false, "/x/y", "", seen)

	v := sitemapTree(t, s)
	nodes := flatten(v.Tree)
	want := map[string]int{
		"h":                0,
		"h /obs":           1,
		"h /obs/deep":      2,
		"h /obs/deep/leaf": 3,
		"h /obs/deep/grey": 3,
		"h /api":           1,
		"h /api/v1":        2,
		"h /api/v1/users":  3,
		"other.test":       0,
		"other.test /x":    1,
		"other.test /x/y":  2,
	}
	for id, d := range want {
		n, ok := nodes[id]
		if !ok {
			t.Errorf("missing node %s: %v", id, flatKeys(nodes))
			continue
		}
		if n.view.Depth != d || n.nestDepth != d {
			t.Errorf("%s: depth %d, nested at %d, want %d", id, n.view.Depth, n.nestDepth, d)
		}
		if n.view.Depth != 0 && n.view.Depth != sitemap.NodeDepth(n.view.Path) {
			t.Errorf("%s: depth %d disagrees with NodeDepth %d", id, n.view.Depth, sitemap.NodeDepth(n.view.Path))
		}
		if n.view.ChildCount != len(n.view.Children) {
			t.Errorf("%s: child_count %d but %d children", id, n.view.ChildCount, len(n.view.Children))
		}
	}
	if len(nodes) != len(want) || v.Nodes != len(want) {
		t.Errorf("drew %d nodes and counted %d, want %d: %v", len(nodes), v.Nodes, len(want), flatKeys(nodes))
	}
	// Nothing grafted adds traffic: the host's exchange total is the observed one, and a host with
	// only a grey link under it is neither counted as traffic nor marked as the operator's.
	if got := nodes["h"].view.SubtreeCount; got != 1 {
		t.Errorf("h subtree_exchanges = %d, want 1 (one observed exchange)", got)
	}
	if o := nodes["other.test"].view; o.SubtreeCount != 0 || o.Inserted {
		t.Errorf("other.test: subtree_exchanges %d inserted %v, want 0 and false", o.SubtreeCount, o.Inserted)
	}
	if !nodes["h /api"].view.Inserted || nodes["other.test /x"].view.Inserted {
		t.Error("synthesised folders: one above an insert is the operator's, one above a grey link is not")
	}
}

func flatKeys(m map[string]flatNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k+"@"+strconv.Itoa(m[k].view.Depth))
	}
	return out
}
