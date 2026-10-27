package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/skills"
)

// burpsy-react-ui-ulsy: the skill library over HTTP.

func skillsServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"a.json":   `{"name":"jwt-none","description":"Try alg=none","tools":["history","send"],"arguments":[{"name":"exchange_id","required":true}],"prompt":"Resend exchange {{exchange_id}} with alg none."}`,
		"b.json":   `{"name":"scripted","description":"Needs a runtime","prompt":"x","script":"run.js"}`,
		"bad.json": `{"name":"Bad Name","description":"d","prompt":"p"}`,
	} {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
	}
	lib, err := skills.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return newTestServer().WithSkills(lib)
}

func doReq(s *Server, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestTheSkillLibraryListsAvailabilityAndRefusals(t *testing.T) {
	s := skillsServer(t)
	rec := doReq(s, http.MethodGet, "/api/skills", "")
	var v struct {
		Configured bool `json:"configured"`
		Skills     []struct {
			Name              string   `json:"name"`
			Tools             []string `json:"tools"`
			Available         bool     `json:"available"`
			UnavailableReason string   `json:"unavailable_reason"`
			Disabled          bool     `json:"disabled"`
		} `json:"skills"`
		Refused []struct {
			File, Error string
		} `json:"refused"`
		Disabled  []string `json:"disabled"`
		Persisted bool     `json:"persisted"`
	}
	json.Unmarshal(rec.Body.Bytes(), &v)
	if !v.Configured || len(v.Skills) != 2 || len(v.Refused) != 1 || v.Refused[0].File != "bad.json" || v.Persisted {
		t.Fatalf("library view: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"disabled":[]`) {
		t.Fatalf("an empty disabled list is not []: %s", rec.Body.String())
	}
	if v.Skills[0].Name != "jwt-none" || !v.Skills[0].Available || v.Skills[1].Available || v.Skills[1].UnavailableReason == "" {
		t.Fatalf("availability: %+v", v.Skills)
	}

	// Rendered prompt, with its argument; a missing required argument is a 400.
	rec = doReq(s, http.MethodGet, "/api/skills/jwt-none?exchange_id=7", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"prompt":"Resend exchange 7 with alg none."`) {
		t.Fatalf("render: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(s, http.MethodGet, "/api/skills/jwt-none", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing argument answered %d", rec.Code)
	}
	if rec := doReq(s, http.MethodGet, "/api/skills/scripted", ""); rec.Code != http.StatusConflict {
		t.Fatalf("an unavailable skill answered %d", rec.Code)
	}
	if rec := doReq(s, http.MethodGet, "/api/skills/nope", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown skill answered %d", rec.Code)
	}

	// Disable for this project: the list says so and the prompt is refused.
	rec = doReq(s, http.MethodPut, "/api/skills/disabled", `{"disabled":["jwt-none"]}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"disabled":["jwt-none"]`) {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(s, http.MethodGet, "/api/skills/jwt-none?exchange_id=7", ""); rec.Code != http.StatusConflict {
		t.Fatalf("a disabled skill rendered: %d", rec.Code)
	}
	if rec := doReq(s, http.MethodPut, "/api/skills/disabled", `{"disabled":["typo"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown name was stored: %d", rec.Code)
	}
}

func TestTheDisabledListIsPersistedWithTheProject(t *testing.T) {
	s, _ := newTestServerWithDB(t)
	lib := skillsServer(t).skills
	s.WithSkills(lib)
	if rec := doReq(s, http.MethodPut, "/api/skills/disabled", `{"disabled":["jwt-none"]}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"persisted":true`) {
		t.Fatalf("disable with a db: %d %s", rec.Code, rec.Body.String())
	}
	names, err := s.persist.LoadDisabledSkills()
	if err != nil || len(names) != 1 || names[0] != "jwt-none" {
		t.Fatalf("stored %v %v", names, err)
	}
}

func TestNoLibrarySaysHowToLoadOne(t *testing.T) {
	rec := doReq(newTestServer(), http.MethodGet, "/api/skills", "")
	if !strings.Contains(rec.Body.String(), `"configured":false`) || !strings.Contains(rec.Body.String(), "-skills DIR") || !strings.Contains(rec.Body.String(), `"skills":[]`) {
		t.Fatalf("%s", rec.Body.String())
	}
}

// burpsy-react-ui-fxxm batch 4: GET /api/skills/{name} reads the name with r.PathValue. These pin
// what the old subtree pattern served and what the mux now decides.
func TestASkillIsServedAtItsNameWithAndWithoutATrailingSlash(t *testing.T) {
	s := skillsServer(t)
	for _, path := range []string{"/api/skills/jwt-none?exchange_id=7", "/api/skills/jwt-none/?exchange_id=7"} {
		rec := doReq(s, http.MethodGet, path, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Resend exchange 7") {
			t.Errorf("GET %s = %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if rec := doReq(s, http.MethodGet, "/api/skills/nope/", ""); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "No skill named nope is loaded") {
		t.Errorf("unknown name with a slash = %d %s", rec.Code, rec.Body.String())
	}
}

func TestTheDisabledLiteralOutranksTheSkillNameWildcard(t *testing.T) {
	s := skillsServer(t)
	rec := doReq(s, http.MethodGet, "/api/skills/disabled", "")
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "PUT" {
		t.Errorf("GET /api/skills/disabled = %d Allow=%q, want 405 PUT", rec.Code, rec.Header().Get("Allow"))
	}
	if rec := doReq(s, http.MethodPut, "/api/skills/disabled", `{"disabled":[]}`); rec.Code != http.StatusOK {
		t.Errorf("PUT /api/skills/disabled = %d %s", rec.Code, rec.Body.String())
	}
}

// /api/skills/{rest...} is the old subtree with a named remainder: the name is the remainder with
// its slashes trimmed, so a nested path is looked up whole and answers the old 404 body, and the
// bare collection slash answers the old empty-name 404.
func TestSkillRemaindersKeepTheOldNotFoundBodies(t *testing.T) {
	s := skillsServer(t)
	for path, name := range map[string]string{
		"/api/skills/":                           "",
		"/api/skills/a/b":                        "a/b",
		"/api/skills/jwt-none/extra":             "jwt-none/extra",
		"/api/skills/jwt-none/extra/":            "jwt-none/extra",
		"/api/skills/jwt-none/a/b?exchange_id=7": "jwt-none/a/b",
	} {
		rec := doReq(s, http.MethodGet, path, "")
		want := "No skill named " + name + " is loaded"
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), want) || strings.Contains(rec.Body.String(), "Resend exchange") {
			t.Errorf("GET %s = %d %q, want 404 containing %q", path, rec.Code, strings.TrimSpace(rec.Body.String()), want)
		}
	}
}
