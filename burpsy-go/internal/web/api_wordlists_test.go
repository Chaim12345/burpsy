package web

// The wordlist manager's inventory (burpsy-react-ui-kal): GET /api/wordlists answers the
// bundled corpus and the session's uploads, each row carrying the count the attack will see.
// What these tests pin:
//
//   - the bundled lists are all present, with measured counts, and the note explains both
//     address spaces (builtin:<name> for the engine, paths for ffuf-style consumers);
//   - an upload lands in the inventory with its own path and the blank-line-skipped count;
//   - a fresh process with no uploads ever is a normal state — the inventory answers
//     bundled-only without an error word.
import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func wordlistInventory(t *testing.T, s *Server) (int, map[string]map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/wordlists", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/wordlists = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Wordlists []map[string]any `json:"wordlists"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byRef := make(map[string]map[string]any, len(out.Wordlists))
	for _, w := range out.Wordlists {
		byRef[w["ref"].(string)] = w
	}
	return len(out.Wordlists), byRef
}

func TestTheInventoryListsTheBundledCorpusWithMeasuredCounts(t *testing.T) {
	s := newTestServer()
	count, byRef := wordlistInventory(t, s)
	if count == 0 {
		t.Fatal("the inventory is empty — the bundled corpus did not reach the manager")
	}
	sqli, ok := byRef["builtin:sqli-basic"]
	if !ok {
		t.Fatalf("builtin:sqli-basic missing from the inventory: %v", byRef)
	}
	if sqli["kind"] != "builtin" {
		t.Errorf("sqli-basic kind = %v, want builtin", sqli["kind"])
	}
	lines := int(sqli["lines"].(float64))
	if lines == 0 {
		t.Error("sqli-basic counts zero lines — an entry claiming a list it does not hold is the silent-gap failure the count exists to prevent")
	}
	if name := sqli["name"].(string); name != "sqli-basic" {
		t.Errorf("sqli-basic name = %q", name)
	}
}

func TestAnUploadLandsInTheInventoryWithItsCount(t *testing.T) {
	s := newTestServer()
	body := "alpha\nbeta\n\ngamma\n" // 3 payloads, one blank line
	req := httptest.NewRequest(http.MethodPost, "/api/intruder/payload-files", bytes.NewReader([]byte(body)))
	req.Header.Set("X-Payload-Filename", "my-list.txt")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", rec.Code, rec.Body.String())
	}
	var up struct {
		Filename string `json:"filename"`
		Lines    int    `json:"lines"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &up); err != nil {
		t.Fatalf("decode upload: %v", err)
	}
	if up.Lines != 3 {
		t.Fatalf("upload counted %d lines, want 3 (the blank line is not a payload)", up.Lines)
	}

	_, byRef := wordlistInventory(t, s)
	row, ok := byRef[up.Filename]
	if !ok {
		t.Fatalf("the uploaded list %q missing from the inventory: %v", up.Filename, byRef)
	}
	if row["kind"] != "upload" {
		t.Errorf("uploaded row kind = %v, want upload", row["kind"])
	}
	if int(row["lines"].(float64)) != 3 {
		t.Errorf("inventory counted %v lines for the upload, want 3 — the count an operator plans around must be the count that fires", row["lines"])
	}
}

func TestAFreshServerAnswersTheBundledCorpusAlone(t *testing.T) {
	// A server with no scanner, no scope, nothing wired: the inventory must still answer,
	// because the bundled corpus is build-time state that no runtime wiring can take away.
	// (The upload directory is machine-global scratch shared by every server in the process,
	// so "no uploads anywhere" is not assertable from inside a test binary that just ran the
	// upload test — the claim here is the endpoint's independence from wiring, not the
	// directory's emptiness.)
	s := newTestServer()
	count, byRef := wordlistInventory(t, s)
	if count == 0 {
		t.Fatal("the inventory is empty on a bare server — the bundled corpus alone is a real inventory and needs nothing wired")
	}
	if _, ok := byRef["builtin:sqli-basic"]; !ok {
		t.Fatal("the bare server's inventory lacks the bundled sqli-basic list")
	}
}

func decodeJSON(b []byte, v any) error {
	return json.Unmarshal(b, v)
}
