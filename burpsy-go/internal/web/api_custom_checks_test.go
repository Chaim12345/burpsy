package web

// Console authoring of custom scan checks (burpsy-react-ui-kbu1): Validate, Import, Export/Delete,
// Reload and Run test, each asserted on the wire and on the corpus the scanners actually dispatch.

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

func draft(name, body string) string {
	return "metadata:\n  language: v2-beta\n  name: \"" + name + "\"\n" + body
}

const passiveBody = "given response then\n  if {latest.response.body} matches \"secret-token\" then\n    report issue:\n      severity: low\n      confidence: firm\n  end if\n"
const activeBody = "given request then\n  send request called probe:\n    path: \"/probe\"\n  if {probe.response.status_code} is \"200\" then\n    report issue:\n      severity: medium\n      confidence: certain\n  end if\n"

// authoringServer is a server with one file check loaded from a --bchecks directory, the scanners
// wired the way main.go wires them, and an in-scope store shared by all three.
func authoringServer(t *testing.T) (*Server, string, *core.TrafficStore) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.bcheck"), []byte(draft("from file", passiveBody)), 0o600); err != nil {
		t.Fatal(err)
	}
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	ps, err := scanner.LoadDir(dir, store, scope, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	active := scanner.NewActiveScanner(store, zap.NewNop()).WithScope(scope).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).WithCorpusChecks(ps.ActiveChecks())
	return NewServer(store, scope).WithScanner(active).WithPassiveScanner(ps), dir, store
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d %q: %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

func corpusNames(s *Server) []string {
	var out []string
	for _, c := range s.scanner.CorpusChecks() {
		out = append(out, c.Name)
	}
	return out
}

func TestValidateReportsKindNameAndTheParseErrorPosition(t *testing.T) {
	s, _, _ := authoringServer(t)
	ok := decodeMap(t, postJSON(t, s, "/api/scanner/checks/validate", map[string]string{"source": draft("x", activeBody)}))
	if ok["valid"] != true || ok["name"] != "x" || ok["kind"] != "active" {
		t.Errorf("valid draft: %v", ok)
	}
	bad := decodeMap(t, postJSON(t, s, "/api/scanner/checks/validate", map[string]string{"source": draft("x", "given host then\n  frobnicate\n")}))
	perr, _ := bad["error"].(map[string]any)
	if bad["valid"] != false || perr == nil || perr["line"] == nil || perr["message"] == "" {
		t.Errorf("invalid draft must say where: %v", bad)
	}
	clash := decodeMap(t, postJSON(t, s, "/api/scanner/checks/validate", map[string]string{"source": draft("from file", passiveBody)}))
	if clash["existing_origin"] != "file" {
		t.Errorf("a draft named like a file check must say so before import: %v", clash)
	}
}

func TestImportReachesBothScannersPersistsAndRefusesConflicts(t *testing.T) {
	s, _, _ := authoringServer(t)
	p, err := persist.Open(filepath.Join(t.TempDir(), "p.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s.WithPersist(p)

	rec := postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": draft("console active", activeBody)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("import = %d %s", rec.Code, rec.Body.String())
	}
	if names := corpusNames(s); !strings.Contains(strings.Join(names, "|"), "console active") {
		t.Errorf("the audit engine's corpus lacks the imported check: %v", names)
	}
	saved, _ := p.LoadCustomScanChecks()
	if len(saved) != 1 || !strings.Contains(saved[0], "console active") {
		t.Errorf("persisted sources = %v", saved)
	}
	// The leaf names its origin.
	list := decodeMap(t, get(t, s, "/api/scanner/checks"))
	origins := map[string]string{}
	for _, row := range list["checks"].([]any) {
		m := row.(map[string]any)
		origins[m["name"].(string)] = m["origin"].(string)
	}
	if origins["console active"] != "console" || origins["from file"] != "file" {
		t.Errorf("origins = %v", origins)
	}
	if rec := postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": draft("console active", activeBody)}); rec.Code != http.StatusConflict {
		t.Errorf("a second import of the same name without replace = %d, want 409", rec.Code)
	}
	if rec := postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": draft("console active", passiveBody), "replace": true}); rec.Code != http.StatusCreated {
		t.Errorf("replace = %d %s", rec.Code, rec.Body.String())
	}
	if names := corpusNames(s); strings.Contains(strings.Join(names, "|"), "console active") {
		t.Errorf("replaced by a passive draft, the check must leave the active corpus: %v", names)
	}
	if s.passiveScanner.Loaded() != 2 {
		t.Errorf("passive checks = %d, want the file's and the replaced console one", s.passiveScanner.Loaded())
	}
	if rec := postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": draft("from file", activeBody), "replace": true}); rec.Code != http.StatusConflict {
		t.Errorf("importing over a file check = %d, want 409", rec.Code)
	}
}

func TestSourceExportAndDeleteOnlyForConsoleChecks(t *testing.T) {
	s, _, _ := authoringServer(t)
	src := draft("mine", activeBody)
	postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": src})
	got := decodeMap(t, get(t, s, "/api/scanner/checks/source?name=mine"))
	if got["source"] != src || got["origin"] != "console" {
		t.Errorf("export = %v", got)
	}
	file := decodeMap(t, get(t, s, "/api/scanner/checks/source?name=from+file"))
	if file["origin"] != "file" || file["file"] != "file.bcheck" {
		t.Errorf("file check export = %v", file)
	}
	del := func(name string) int {
		req := httptest.NewRequest(http.MethodDelete, "/api/scanner/checks/source?name="+name, nil)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := del("from+file"); code != http.StatusConflict {
		t.Errorf("deleting a file check = %d, want 409", code)
	}
	if code := del("mine"); code != http.StatusNoContent {
		t.Errorf("deleting a console check = %d, want 204", code)
	}
	if strings.Contains(strings.Join(corpusNames(s), "|"), "mine") {
		t.Error("the deleted check is still in the audit engine's corpus")
	}
}

func TestReloadRereadsTheDirectoryAndKeepsConsoleChecks(t *testing.T) {
	s, dir, _ := authoringServer(t)
	postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": draft("console only", passiveBody)})
	postJSON(t, s, "/api/scanner/checks/import", map[string]any{"source": draft("will collide", passiveBody)})
	if err := os.WriteFile(filepath.Join(dir, "new.bcheck"), []byte(draft("new file", activeBody)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "collide.bcheck"), []byte(draft("will collide", passiveBody)), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, s, "/api/scanner/checks/reload", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("reload = %d %s", rec.Code, rec.Body.String())
	}
	out := decodeMap(t, rec)
	if sh, _ := out["shadowed"].([]any); len(sh) != 1 || sh[0] != "will collide" {
		t.Errorf("shadowed = %v, want the console check a file now names", out["shadowed"])
	}
	if !strings.Contains(strings.Join(corpusNames(s), "|"), "new file") {
		t.Errorf("the new file's active check is not in the audit corpus: %v", corpusNames(s))
	}
	if _, ok := s.passiveScanner.Entry("console only"); !ok {
		t.Error("reload dropped a console check")
	}
	if e, _ := s.passiveScanner.Entry("will collide"); e.Origin == scanner.OriginConsole {
		t.Error("the file must win a name collision on reload")
	}
}

func addCheckTestExchange(t *testing.T, store *core.TrafficStore, host string, port int, path, response string) uint64 {
	t.Helper()
	reqID, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+":"+strconv.Itoa(port)+"\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := store.Put([]byte(response), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Host: host, Port: uint16(port), Method: "GET", Path: path, Request: core.MsgPtr(reqID), Response: core.MsgPtr(respID)}
	store.AddExchange(ex)
	return uint64(ex.ID)
}

func TestRunTestRunsADraftAgainstChosenExchangesAndFilesNothing(t *testing.T) {
	s, _, store := authoringServer(t)
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probe" {
			hits.Add(1)
		}
		w.Write([]byte("ok"))
	}))
	defer origin.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	inScope := addCheckTestExchange(t, store, host, port, "/", "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nhere secret-token")
	outOfScope := addCheckTestExchange(t, store, "elsewhere.test", 80, "/", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno")

	type result struct {
		ExchangeID uint64            `json:"exchange_id"`
		Findings   []json.RawMessage `json:"findings"`
		Sent       int               `json:"sent"`
		Refused    int               `json:"refused"`
		Unresolved []string          `json:"unresolved"`
		Error      string            `json:"error"`
	}
	run := func(src string) ([]result, string) {
		rec := postJSON(t, s, "/api/scanner/checks/test", map[string]any{"source": src, "exchange_ids": []uint64{inScope, outOfScope}})
		if rec.Code != http.StatusOK {
			t.Fatalf("test = %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "null") {
			t.Errorf("a list went out as null: %s", rec.Body.String())
		}
		var out struct {
			Kind    string   `json:"kind"`
			Results []result `json:"results"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Results, out.Kind
	}

	res, kind := run(draft("draft passive", passiveBody))
	if kind != "passive" || len(res) != 2 || len(res[0].Findings) != 1 || len(res[1].Findings) != 0 || res[0].Sent != 0 {
		t.Errorf("passive run: kind %s, %+v", kind, res)
	}
	res, kind = run(draft("draft active", activeBody))
	if kind != "active" || len(res[0].Findings) != 1 || res[0].Sent != 1 || hits.Load() != 1 {
		t.Errorf("active run in scope: %+v, origin hits %d", res[0], hits.Load())
	}
	if res[1].Sent != 0 || res[1].Refused == 0 || len(res[1].Findings) != 0 {
		t.Errorf("active run out of scope must be refused, not sent: %+v", res[1])
	}
	if n := len(s.scanner.CorpusChecks()); n != 0 {
		t.Errorf("a test run loaded the draft into the corpus (%d checks)", n)
	}
	if rec := postJSON(t, s, "/api/scanner/checks/test", map[string]any{"source": draft("x", passiveBody), "exchange_ids": []uint64{}}); rec.Code != http.StatusBadRequest {
		t.Errorf("no exchanges = %d, want 400", rec.Code)
	}
}
