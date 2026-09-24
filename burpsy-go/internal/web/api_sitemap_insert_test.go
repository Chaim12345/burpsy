package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// "Add to site map" (amu): the row-menu action's other half. The map package owns the insert; this
// pins what the endpoint says about it, because the two outcomes — "you recorded this" and "this was
// already observed" — are different facts the caller has to be able to tell apart.

func TestAnInsertIsRecordedAndTheResponseSaysWhichItWas(t *testing.T) {
	s := newTestServer()

	rec := postJSON(t, s, "/api/sitemap", map[string]any{
		"host": "known.test", "port": 443, "tls": true, "path": "/admin",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/sitemap = %d (%s): the row menu's action has to work", rec.Code, rec.Body.String())
	}
	var out struct {
		Inserted    string `json:"inserted"`
		AlreadySeen bool   `json:"already_seen"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.AlreadySeen {
		t.Error("a new insert reported already_seen: the operator would be told their URL was " +
			"already on the map when nothing had been observed there")
	}
	if !strings.Contains(out.Inserted, "known.test") {
		t.Errorf("inserted = %q, want it to name what was added", out.Inserted)
	}

	// The node is on the map, and marked as the operator's own.
	tree := get(t, s, "/api/sitemap")
	var body struct {
		Tree []struct {
			Key      string `json:"key"`
			Segment  string `json:"segment"`
			Path     string `json:"path"`
			Inserted bool   `json:"inserted"`
			Children []struct {
				Path     string `json:"path"`
				Segment  string `json:"segment"`
				Inserted bool   `json:"inserted"`
				Children []struct {
					Path     string `json:"path"`
					Inserted bool   `json:"inserted"`
				} `json:"children"`
			} `json:"children"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(tree.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode tree: %v", err)
	}
	found := false
	var walk func(nodes []struct {
		Path     string `json:"path"`
		Inserted bool   `json:"inserted"`
	})
	_ = walk
	for _, host := range body.Tree {
		for _, folder := range host.Children {
			for _, leaf := range folder.Children {
				if leaf.Path == "/admin" {
					found = true
					if !leaf.Inserted {
						t.Error("the node on the map is not marked inserted: the map has to be able " +
							"to say it was written down rather than observed")
					}
				}
			}
			if folder.Path == "/admin" {
				found = true
				if !folder.Inserted {
					t.Error("the inserted node is not marked inserted")
				}
			}
		}
		if host.Path == "known.test" || host.Segment == "known.test" {
			for _, folder := range host.Children {
				if folder.Path == "/admin" && !folder.Inserted {
					t.Error("the inserted node is not marked inserted")
				}
			}
		}
	}
	if !found {
		t.Errorf("the inserted node is not on the map at all: %s", tree.Body.String())
	}
}

func TestAnInsertOfAnObservedNodeSaysTheStrongerFact(t *testing.T) {
	s := newTestServer()
	captureExchange(t, s, "seen.test", "/app", 200, "text/html")

	rec := postJSON(t, s, "/api/sitemap", map[string]any{
		"host": "seen.test", "port": 443, "tls": true, "path": "/app",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		AlreadySeen bool   `json:"already_seen"`
		Note        string `json:"note"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.AlreadySeen {
		t.Error("inserting an observed path reported it as new: the operator would credit themselves " +
			"with a node the map carries because traffic was seen")
	}
	if out.Note == "" {
		t.Error("the refusal to double-record an observed node carries no reason: the operator is " +
			"told nothing happened and cannot tell a no-op from a bug")
	}
}

func TestAnInsertWithNoPortIsRefusedWithTheReason(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/sitemap", map[string]any{"host": "app.test", "port": 0, "path": "/x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with no port = %d, want 400: app.test:0 is not an authority", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "port") {
		t.Errorf("the refusal does not name what was wrong: %q", rec.Body.String())
	}
}
