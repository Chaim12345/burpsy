package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-9n01: an empty site map is "tree":[] on the wire. A Go nil slice marshals as null,
// and the UI types tree as an array, so the assertion is on the marshalled body, not the struct
// (which round-trips null and [] to the same nil slice and would pass either way).
func TestSitemapGetEmptyMapMarshalsTreeAsEmptyArray(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/sitemap")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/sitemap = %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"tree":[]`) {
		t.Errorf("empty site map body lacks \"tree\":[]: %s", body)
	}
	if strings.Contains(body, "null") {
		t.Errorf("empty site map body carries a null: %s", body)
	}
	// A filter that matches nothing on a non-empty map is the same empty tree.
	s.sitemap.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/a"})
	if body := get(t, s, "/api/sitemap?host=nothing.test").Body.String(); !strings.Contains(body, `"tree":[]`) {
		t.Errorf("filtered-to-nothing site map body lacks \"tree\":[]: %s", body)
	}
}

// The same handler's other slices: every node kind the read emits — an observed host, a requested
// path, a folder synthesised to hold it, an inserted node under an unobserved host (so the merge
// synthesises that host and the folder above it), and an unrequested item — carries arrays, never
// null. last_exchange is the one nullable field by design (a *int64: "no exchange" is a fact).
func TestSitemapGetEveryNodeKindMarshalsArraysNotNull(t *testing.T) {
	s := newTestServer()
	seen := time.Unix(1_700_000_000, 0)
	st := uint16(200)
	s.sitemap.Add(&core.Exchange{ID: 1, Host: "app.test", Port: 80, Method: "GET", Path: "/api/v1/users", Status: &st})
	s.sitemap.Insert("other.test", 443, true, "/deep/added", seen)
	if !s.sitemap.AddUnrequested("app.test", 80, false, "/linked/page", "http://app.test/", seen) {
		t.Fatal("AddUnrequested refused")
	}
	body := get(t, s, "/api/sitemap").Body.String()
	// Positive control: every node kind is actually in the body being checked.
	for _, want := range []string{`"path":"/api/v1/users"`, `"path":"/api"`, `"path":"/deep/added"`,
		`"path":"/deep"`, `"path":"other.test"`, `"path":"/linked/page"`, `"path":"app.test"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body lacks %s, so the null sweep would not cover it: %s", want, body)
		}
	}
	rest := strings.ReplaceAll(body, `"last_exchange":null`, "")
	if m := regexp.MustCompile(`"[a-z_]+":null`).FindAllString(rest, -1); len(m) > 0 {
		t.Errorf("site map body carries null fields %v: %s", m, body)
	}
}
