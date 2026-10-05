package web

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// seedResponse stores one exchange whose response carries head and body, and returns its id.
func seedResponse(t *testing.T, s *Server, head, body string) uint64 {
	t.Helper()
	reqID, err := s.store.Put([]byte("GET /x HTTP/1.1\r\nHost: t.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := s.store.Put([]byte(head+"\r\n\r\n"+body), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Host: "t.test", Port: 80, Method: "GET", Path: "/x",
		Request: core.MsgPtr(reqID), Response: &respID}
	s.store.AddExchange(ex)
	return uint64(ex.ID)
}

// The acceptance of burpsy-react-ui-28n8: an operator defines named extractors (a JSON path, a regex
// group, a header) and each row's captured value comes back keyed by id and column name — a null when
// the response did not yield that value, distinct from an empty string it did.
func TestHistoryExtractorsRenderAValuePerRow(t *testing.T) {
	s := newTestServer()
	put := putJSON(t, s, "/api/history/extractors", map[string]any{"extractors": []map[string]any{
		{"name": "user", "how": map[string]any{"json_path": "data.user.id"}},
		{"name": "ver", "from": map[string]any{"header": "X-Version"}, "how": map[string]any{"regex": map[string]any{"pattern": `v(\d+)`, "group": 1}}},
	}})
	if put.Code != http.StatusOK {
		t.Fatalf("PUT extractors = %d: %s", put.Code, put.Body.String())
	}

	hit := seedResponse(t, s, `HTTP/1.1 200 OK
Content-Type: application/json
X-Version: v42`, `{"data":{"user":{"id":"u-7"}}}`)
	miss := seedResponse(t, s, "HTTP/1.1 500 Internal Server Error", "boom")

	rec := postJSON(t, s, "/api/history/extract", map[string]any{"ids": []uint64{hit, miss}})
	if rec.Code != http.StatusOK {
		t.Fatalf("extract = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Values map[string]map[string]*string `json:"values"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	h := resp.Values[strconv.FormatUint(hit, 10)]
	if h == nil || h["user"] == nil || *h["user"] != "u-7" {
		t.Errorf("json-path column = %v, want u-7", h["user"])
	}
	if h == nil || h["ver"] == nil || *h["ver"] != "42" {
		t.Errorf("header regex column = %v, want 42", h["ver"])
	}
	m := resp.Values[strconv.FormatUint(miss, 10)]
	if m == nil {
		t.Fatal("the missing-value row is absent; it has a response, so it must appear with null columns")
	}
	if v, ok := m["user"]; !ok || v != nil {
		t.Errorf("a response that did not yield the value should map to null, got %v", v)
	}

	// The column set comes back on GET, so the console can render the headers.
	g := get(t, s, "/api/history/extractors")
	if !jsonContains(t, g.Body.Bytes(), "user") || !jsonContains(t, g.Body.Bytes(), "ver") {
		t.Errorf("GET extractors did not list the columns: %s", g.Body.String())
	}
}

func jsonContains(t *testing.T, raw []byte, name string) bool {
	t.Helper()
	var v struct {
		Extractors []struct {
			Name string `json:"name"`
		} `json:"extractors"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, e := range v.Extractors {
		if e.Name == name {
			return true
		}
	}
	return false
}

// A definition that cannot compile is refused whole — a column that shows every row empty reads as a
// broken table, not a broken extractor — and the definitions survive a restart with the project.
func TestHistoryExtractorsAreValidatedAndSavedWithTheProject(t *testing.T) {
	s := newTestServer()
	bad := putJSON(t, s, "/api/history/extractors", map[string]any{"extractors": []map[string]any{
		{"name": "x", "how": map[string]any{"regex": map[string]any{"pattern": "([", "group": 1}}},
	}})
	if bad.Code != http.StatusBadRequest {
		t.Errorf("an uncompilable regex = %d, want 400", bad.Code)
	}

	dir := t.TempDir()
	store, err := persist.Open(filepath.Join(dir, "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s2 := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(store)
	if rec := putJSON(t, s2, "/api/history/extractors", map[string]any{"extractors": []map[string]any{
		{"name": "tok", "how": map[string]any{"json_path": "token"}},
	}}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	store.Close()

	reopened, err := persist.Open(filepath.Join(dir, "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s3 := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(reopened)
	defs, _ := s3.historyExtractors()
	if len(defs) != 1 || defs[0].Name != "tok" {
		t.Errorf("the saved extractor did not survive the restart: %+v", defs)
	}
}
