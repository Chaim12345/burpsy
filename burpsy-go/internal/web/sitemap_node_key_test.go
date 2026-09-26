package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// A site-map node's `key` is its identity, and identity has to include the scheme and port.
//
// internal/sitemap keys its own host table on (host, port, TLS), so one hostname reached over both
// http and https is genuinely two host nodes in the tree. nodeKey used to be built from the hostname
// and path alone, so those two nodes came back with the same key — and their `/` children with the
// same key again. The UI uses `key` as its React key, its expansion-state key and its cursor and
// selection id (ui/src/pages/sitemap.tsx), so two real branches collapsed onto one selectable row.
//
// The assertion is on uniqueness across the whole tree rather than on a particular key format, so the
// key can be reshaped later without rewriting this test — what must not come back is a collision.
func TestSiteMapNodeKeysAreUniqueAcrossSchemesAndPorts(t *testing.T) {
	s := newTestServer()
	// The same hostname and path over three different authorities. Under the old key these produced
	// three identical host keys and three identical "/" keys.
	addTrafficOn(t, s.store, "shop.test", 80, false, "GET", "/")
	addTrafficOn(t, s.store, "shop.test", 443, true, "GET", "/")
	addTrafficOn(t, s.store, "shop.test", 8443, true, "GET", "/")

	keys := collectNodeKeys(t, s)
	if len(keys) == 0 {
		t.Fatal("no nodes in the tree")
	}
	seen := map[string]int{}
	for _, k := range keys {
		seen[k]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("node key %q appears %d times; a key is a node's identity and must be unique", k, n)
		}
	}
	// Three authorities means three host nodes, so the collision cannot be "fixed" by merging them.
	var hostNodes int
	for _, node := range sitemapTreeRaw(t, s) {
		if node["depth"].(float64) == 0 {
			hostNodes++
		}
	}
	if hostNodes != 3 {
		t.Errorf("host nodes = %d, want 3 (http:80, https:443, https:8443 are distinct authorities)", hostNodes)
	}
}

// A finding still lands on the node belonging to the authority it was observed on, which is what the
// issue roll-up reads. issuesByNode builds its keys independently of foldPaths, so the two have to
// agree on the key shape or every finding silently counts against nothing.
func TestSiteMapIssueAttributionSurvivesTheKeyShape(t *testing.T) {
	s := newTestServer()
	secure := addTrafficOn(t, s.store, "shop.test", 443, true, "GET", "/admin")
	addTrafficOn(t, s.store, "shop.test", 80, false, "GET", "/admin")

	s.findings.Add(core.NewFinding{
		Name:       "test finding",
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceCertain,
		Occurrences: []core.Occurrence{{
			ExchangeID: secure.ID,
			Request:    secure.Request,
			Response:   secure.Response,
		}},
	})

	var withIssue, without int
	for _, node := range allNodesRaw(t, s) {
		if node["path"] != "/admin" {
			continue
		}
		if node["issues"].(float64) > 0 {
			withIssue++
		} else {
			without++
		}
	}
	if withIssue != 1 || without != 1 {
		t.Errorf("/admin nodes carrying the finding = %d, clean = %d; want exactly 1 and 1 "+
			"(the finding belongs to the https node only)", withIssue, without)
	}
}

// addTrafficOn is addTraffic with the authority spelled out, so a test can put the same host and path
// on more than one (port, TLS) pair.
func addTrafficOn(t *testing.T, store *core.TrafficStore, host string, port uint16, tls bool, method, path string) *core.Exchange {
	t.Helper()
	reqID, err := store.Put([]byte(method+" "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	status := uint16(200)
	ex := &core.Exchange{
		Request:  core.MsgPtr(reqID),
		Response: &respID,
		Host:     host,
		Port:     port,
		TLS:      tls,
		Method:   method,
		Path:     path,
		Status:   &status,
	}
	store.AddExchange(ex)
	return ex
}

// sitemapTreeRaw decodes the tree as plain maps, so a test can assert on `key` without the response
// structs having to carry every field.
func sitemapTreeRaw(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	rec := get(t, s, "/api/sitemap")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/sitemap: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Tree []map[string]any `json:"tree"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode sitemap %q: %v", rec.Body.String(), err)
	}
	return body.Tree
}

// allNodesRaw flattens the whole tree, host nodes and path nodes alike.
func allNodesRaw(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	var out []map[string]any
	var walk func(nodes []map[string]any)
	walk = func(nodes []map[string]any) {
		for _, n := range nodes {
			out = append(out, n)
			children, _ := n["children"].([]any)
			next := make([]map[string]any, 0, len(children))
			for _, c := range children {
				if m, ok := c.(map[string]any); ok {
					next = append(next, m)
				}
			}
			walk(next)
		}
	}
	walk(sitemapTreeRaw(t, s))
	return out
}

func collectNodeKeys(t *testing.T, s *Server) []string {
	t.Helper()
	var keys []string
	for _, n := range allNodesRaw(t, s) {
		key, ok := n["key"].(string)
		if !ok {
			t.Fatalf("node %v has no string key", n)
		}
		keys = append(keys, key)
	}
	return keys
}
