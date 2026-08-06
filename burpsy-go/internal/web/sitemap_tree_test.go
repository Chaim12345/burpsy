package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- The site map is a path tree, not a list of raw request lines ------------------------------
//
// Two defects these pin, both visible the moment a browser drove the tab:
//
//   - A query string was treated as path structure. `/search?q=<script>alert(1)</script>` was split
//     on the slash inside `</script>`, so the tree rendered a node literally named `script>`, and
//     every distinct query string became its own sibling leaf of the same resource.
//   - Folders were never synthesised. `/api/debug` produced a node only at `/api/debug`; with no
//     `/api` to nest under it was emitted as a root, so the tree rendered flat.

// findNode walks the tree for one path, so an assertion can name a node without hand-walking.
func findNode(nodes []sitemapNodeResp, path string) *sitemapNodeResp {
	for i := range nodes {
		if nodes[i].Path == path {
			return &nodes[i]
		}
		if found := findNode(nodes[i].Children, path); found != nil {
			return found
		}
	}
	return nil
}

// A query string names parameters on a node; it does not create nodes. Both requests below are the
// same resource, so they are one node — and no node is named after a fragment of the query.
func TestQueryStringsFoldOntoOnePathNodeAndNeverBecomeTreeStructure(t *testing.T) {
	s := newTestServer()
	addTraffic(t, s.store, "shop.test", "GET", "/search?q=hello")
	addTraffic(t, s.store, "shop.test", "GET", "/search?q=<script>alert(1)</script>")

	v := sitemapGet(t, s)
	paths := map[string]int{}
	nodePaths(v.Tree[0].Children, paths)

	search := findNode(v.Tree[0].Children, "/search")
	if search == nil {
		t.Fatalf("no /search node; tree holds %v", paths)
	}
	if search.Exchanges != 2 {
		t.Errorf("/search exchanges = %d, want 2 — both query strings are the same resource", search.Exchanges)
	}
	for p := range paths {
		if p != "/search" {
			t.Errorf("query string leaked into the tree as node %q", p)
		}
	}
}

// The folders on the way to a resource exist even when nothing requested them, so the tree nests.
func TestFoldersLeadingToAResourceAreSynthesisedSoTheTreeNests(t *testing.T) {
	s := newTestServer()
	addTraffic(t, s.store, "shop.test", "GET", "/api/v2/debug")

	v := sitemapGet(t, s)
	host := v.Tree[0]

	// /api is a root under the host, not a sibling of the leaf.
	if len(host.Children) != 1 || host.Children[0].Path != "/api" {
		t.Fatalf("host children = %+v, want exactly one root node /api", host.Children)
	}
	for _, want := range []string{"/api", "/api/v2", "/api/v2/debug"} {
		if findNode(host.Children, want) == nil {
			t.Errorf("folder %q missing — the tree cannot nest without it", want)
		}
	}
	// A synthesised folder holds no traffic of its own but reports what is underneath it.
	api := findNode(host.Children, "/api")
	if api.Exchanges != 0 {
		t.Errorf("/api exchanges = %d, want 0 — nothing requested the folder itself", api.Exchanges)
	}
}

// A path requested directly and also used as a folder is one node, and it is not marked synthetic.
func TestAPathThatIsBothRequestedAndAFolderIsASingleNode(t *testing.T) {
	s := newTestServer()
	addTraffic(t, s.store, "shop.test", "GET", "/api")
	addTraffic(t, s.store, "shop.test", "GET", "/api/debug")

	v := sitemapGet(t, s)
	host := v.Tree[0]
	if len(host.Children) != 1 {
		t.Fatalf("host children = %+v, want one node", host.Children)
	}
	api := host.Children[0]
	if api.Path != "/api" || api.Exchanges != 1 || len(api.Children) != 1 {
		t.Errorf("got %+v, want /api holding its own exchange and one child", api)
	}
}

// ---- Findings are visible on the tree (G3) ------------------------------------------------------

// A node reports its own findings, and every ancestor reports what is underneath it with the worst
// severity in that subtree. Without the roll-up a collapsed branch looks clean, which defeats the
// point of having a tree: it should say where to look before it is expanded.
func TestSiteMapNodesCarryTheirFindingsAndRollThemUp(t *testing.T) {
	s := newTestServer()
	shallow := addTraffic(t, s.store, "shop.test", "GET", "/api")
	deep := addTraffic(t, s.store, "shop.test", "GET", "/api/v2/debug")
	addTraffic(t, s.store, "shop.test", "GET", "/clean")

	s.findings.Add(core.NewFinding{
		Name: "low at /api", Severity: core.SeverityLow,
		Occurrences: []core.Occurrence{{ExchangeID: shallow.ID, Request: shallow.Request, Response: shallow.Response}},
	})
	s.findings.Add(core.NewFinding{
		Name: "critical deep", Severity: core.SeverityCritical,
		Occurrences: []core.Occurrence{{ExchangeID: deep.ID, Request: deep.Request, Response: deep.Response}},
	})

	host := sitemapGetFull(t, s).Tree[0]

	// The host node sums the whole site and reports the worst thing in it.
	if host.SubtreeIssues != 2 || host.WorstSeverity != "Critical" {
		t.Errorf("host: subtree_issues=%d worst=%q, want 2 / Critical", host.SubtreeIssues, host.WorstSeverity)
	}

	api := findNodeFull(host.Children, "/api")
	if api == nil {
		t.Fatal("no /api node")
	}
	if api.Issues != 1 {
		t.Errorf("/api issues = %d, want 1 (its own finding)", api.Issues)
	}
	if api.SubtreeIssues != 2 || api.WorstSeverity != "Critical" {
		t.Errorf("/api: subtree_issues=%d worst=%q, want 2 / Critical from the descendant",
			api.SubtreeIssues, api.WorstSeverity)
	}

	// A synthesised folder holds no finding of its own but still reports the one beneath it.
	v2 := findNodeFull(host.Children, "/api/v2")
	if v2 == nil {
		t.Fatal("no /api/v2 folder")
	}
	if v2.Issues != 0 || v2.SubtreeIssues != 1 || v2.WorstSeverity != "Critical" {
		t.Errorf("/api/v2: issues=%d subtree=%d worst=%q, want 0 / 1 / Critical",
			v2.Issues, v2.SubtreeIssues, v2.WorstSeverity)
	}

	// A clean branch says so with an empty severity rather than a zero-valued one.
	clean := findNodeFull(host.Children, "/clean")
	if clean == nil {
		t.Fatal("no /clean node")
	}
	if clean.SubtreeIssues != 0 || clean.WorstSeverity != "" {
		t.Errorf("/clean: subtree=%d worst=%q, want 0 and an empty severity",
			clean.SubtreeIssues, clean.WorstSeverity)
	}
}

// A finding whose path carries a query string belongs to the path node, not to a node that does not
// exist — the tree keys on the path alone, and the issue index must normalise the same way.
func TestAFindingOnAQueryStringLandsOnItsPathNode(t *testing.T) {
	s := newTestServer()
	ex := addTraffic(t, s.store, "shop.test", "GET", "/search?q=hello")
	s.findings.Add(core.NewFinding{
		Name: "reflected", Severity: core.SeverityHigh,
		Occurrences: []core.Occurrence{{ExchangeID: ex.ID, Request: ex.Request, Response: ex.Response}},
	})

	host := sitemapGetFull(t, s).Tree[0]
	search := findNodeFull(host.Children, "/search")
	if search == nil {
		t.Fatal("no /search node")
	}
	if search.Issues != 1 || search.WorstSeverity != "High" {
		t.Errorf("/search: issues=%d worst=%q, want 1 / High", search.Issues, search.WorstSeverity)
	}
}

// The continuity tests' wire shape omits the issue fields, so these use their own decode. Kept
// separate rather than widened there: that file's tests are about the subscription, and a struct
// carrying fields they never assert on would invite reading them as covered.
type siteNodeFull struct {
	Key           string         `json:"key"`
	Path          string         `json:"path"`
	Exchanges     int            `json:"exchanges"`
	Requested     bool           `json:"requested"`
	Issues        int            `json:"issues"`
	SubtreeIssues int            `json:"subtree_issues"`
	WorstSeverity string         `json:"worst_severity"`
	Children      []siteNodeFull `json:"children"`
}

type siteMapFull struct {
	Tree []siteNodeFull `json:"tree"`
}

func sitemapGetFull(t *testing.T, s *Server) siteMapFull {
	t.Helper()
	rec := get(t, s, "/api/sitemap")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/sitemap: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var v siteMapFull
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode sitemap %q: %v", rec.Body.String(), err)
	}
	return v
}

func findNodeFull(nodes []siteNodeFull, path string) *siteNodeFull {
	for i := range nodes {
		if nodes[i].Path == path {
			return &nodes[i]
		}
		if found := findNodeFull(nodes[i].Children, path); found != nil {
			return found
		}
	}
	return nil
}
