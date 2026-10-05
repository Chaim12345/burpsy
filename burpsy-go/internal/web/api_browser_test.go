package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// burpsy-react-ui-bufa at the API. The launch itself is proven against a real Chromium in
// internal/browser; here: the refusals reach the operator by name, a non-web URL is never handed to a
// browser on the backend's machine, and the settings round-trip under Burp's keys and stay with the
// project.
func TestBrowserLaunchRefusesByNameAndOnlyOpensWebURLs(t *testing.T) {
	s := newTestServer() // no proxy server attached, so there is no listener
	rec := postJSON(t, s, "/api/browser/launch", map[string]any{})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "no Proxy listeners") {
		t.Errorf("launch with no listener = %d %q, want 503 with Burp's refusal", rec.Code, rec.Body.String())
	}
	for _, u := range []string{"file:///etc/passwd", "chrome://settings", "javascript:alert(1)"} {
		if rec := postJSON(t, s, "/api/browser/launch", map[string]any{"url": u}); rec.Code != http.StatusBadRequest {
			t.Errorf("launch url %q = %d, want 400: only http(s) URLs may reach a browser on the backend's machine", u, rec.Code)
		}
	}
}

func TestBrowserSettingsRoundTripUnderBurpsKeysAndStayWithTheProject(t *testing.T) {
	dir := t.TempDir()
	store, err := persist.Open(filepath.Join(dir, "eng.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(store)

	var view map[string]any
	rec := get(t, s, "/api/browser/settings")
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	for _, k := range []string{"browser_data_directory", "allow_saving_browser_settings", "allow_running_without_sandbox", "disable_gpu", "profile_dir"} {
		if _, ok := view[k]; !ok {
			t.Errorf("GET lacks %q: %s", k, rec.Body.String())
		}
	}
	if view["allow_saving_browser_settings"] != true || view["allow_running_without_sandbox"] != false {
		t.Errorf("defaults are not Burp's (store on, sandbox on): %s", rec.Body.String())
	}
	if pd, _ := view["profile_dir"].(string); !strings.HasPrefix(pd, dir) || !strings.Contains(pd, "eng") {
		t.Errorf("default profile %q is not beside and named for the project file", pd)
	}

	put := func(body string) int {
		req := strings.NewReader(body)
		r := httpRequest(t, s, http.MethodPut, "/api/browser/settings", req)
		return r.Code
	}
	if code := put(`{"browser_data_directory":"relative"}`); code != http.StatusBadRequest {
		t.Errorf("a relative data directory = %d, want 400", code)
	}
	if code := put(`{"disable_gpu":true,"allow_running_without_sandbox":true}`); code != http.StatusOK {
		t.Fatalf("PUT = %d", code)
	}
	store.Close()

	reopened, err := persist.Open(filepath.Join(dir, "eng.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s2 := NewServer(core.NewTrafficStore(), core.NewScope()).WithLogger(zap.NewNop()).WithPersist(reopened)
	got := s2.browserLauncher().Settings()
	if !got.DisableGPU || !got.AllowNoSandbox || !got.StoreData {
		t.Errorf("settings after restart = %+v, want disable_gpu and no-sandbox on, store still on", got)
	}
}

func httpRequest(t *testing.T, s *Server, method, path string, body *strings.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}
