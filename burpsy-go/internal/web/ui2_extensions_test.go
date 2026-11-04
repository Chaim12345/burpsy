package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/extension"
)

// ui2ExtServer is a server whose allowlist holds the web package's helper plugin as "probe".
func ui2ExtServer(t *testing.T) *Server {
	t.Helper()
	host := extension.NewHost(extension.Config{
		Plugins:       map[string]extension.PluginSpec{"probe": webHelperPlugin()},
		LoadTimeout:   10 * time.Second,
		ShutdownGrace: 2 * time.Second,
	})
	t.Cleanup(host.Close)
	return newTestServer().WithExtensions(host)
}

func ui2ExtPost(s *Server, path string, form url.Values) string {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w.Body.String()
}

// ui2ExtConfirmed drives the confirm step and returns the run form's fields.
func ui2ExtConfirmed(t *testing.T, s *Server, form url.Values) (url.Values, string) {
	t.Helper()
	sheet := ui2ExtPost(s, "/ui2/extensions/confirm", form)
	if strings.Contains(sheet, "Not run:") {
		t.Fatalf("confirm refused: %s", sheet)
	}
	run := url.Values{}
	for _, k := range []string{"review_id", "token"} {
		m := regexp.MustCompile(`name="` + k + `" value="([^"]*)"`).FindStringSubmatch(sheet)
		if len(m) != 2 {
			t.Fatalf("sheet missing hidden %s: %s", k, sheet)
		}
		run.Set(k, m[1])
	}
	return run, sheet
}

func TestUI2ExtensionsPagesRender(t *testing.T) {
	s := ui2ExtServer(t)
	for path, marker := range map[string]string{
		"/ui2/extensions":                    `data-plugin="probe"`,
		"/ui2/extensions/options":            "-plugins",
		"/ui2/extensions/apis":               "contextMenu.invoke",
		"/ui2/extensions/plugin?name=probe":  "Registrations are declared at the handshake",
		"/ui2/extensions/console?name=probe": `hx-trigger="every 3s"`,
	} {
		rec := getUI2(t, s, path)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), marker) {
			t.Errorf("GET %s = %d, missing %q", path, rec.Code, marker)
		}
	}
	if body := getUI2(t, s, "/ui2/extensions/plugin?name=nope").Body.String(); !strings.Contains(body, "not on the plugin allowlist") {
		t.Errorf("unknown plugin detail does not refuse by name")
	}
}

// The load review names the plugin key and its executable before anything runs; the run spends
// it once, and an invoke review then hands the plugin's answer back as escaped text.
func TestUI2ExtensionsLoadInvokeUnloadReviewed(t *testing.T) {
	s := ui2ExtServer(t)
	run, sheet := ui2ExtConfirmed(t, s, url.Values{"action": {"load"}, "name": {"probe"}})
	if !strings.Contains(sheet, "<code>probe</code>") || !strings.Contains(sheet, "Executable") || !strings.Contains(sheet, "disabled data-arm-on-load") {
		t.Fatalf("load review does not name the plugin and executable behind an armed button: %s", sheet)
	}
	if st := s.extensionHost().List().Extensions[0].State; st != extension.StateUnloaded {
		t.Fatalf("the review step changed the plugin state to %s", st)
	}
	if out := ui2ExtPost(s, "/ui2/extensions/run", run); !strings.Contains(out, "Loaded probe") {
		t.Fatalf("run did not load: %s", out)
	}
	if out := ui2ExtPost(s, "/ui2/extensions/run", run); !strings.Contains(out, "already used") {
		t.Errorf("a spent review ran twice: %s", out)
	}
	run, _ = ui2ExtConfirmed(t, s, url.Values{"action": {"invoke"}, "name": {"probe"}, "registration": {"act"}, "from": {"detail"}})
	if out := ui2ExtPost(s, "/ui2/extensions/run", run); !strings.Contains(out, "ran act") || !strings.Contains(out, `id="ext-detail"`) {
		t.Fatalf("invoke did not render the plugin's answer on the detail page: %s", out)
	}
	run, _ = ui2ExtConfirmed(t, s, url.Values{"action": {"unload"}, "name": {"probe"}})
	if out := ui2ExtPost(s, "/ui2/extensions/run", run); !strings.Contains(out, "Unloaded probe") {
		t.Fatalf("run did not unload: %s", out)
	}
}

func TestUI2ExtensionsConfirmRefusals(t *testing.T) {
	s := ui2ExtServer(t)
	for _, form := range []url.Values{
		{"action": {"load"}, "name": {"/bin/sh"}},                          // not an allowlist key
		{"action": {"invoke"}, "name": {"probe"}, "registration": {"act"}}, // not loaded
		{"action": {"up"}, "name": {"probe"}},                              // already first
		{"action": {"load"}, "name": {"probe"}, "path": {"/bin/sh"}},       // unknown field
		{"action": {"explode"}, "name": {"probe"}},                         // unknown action
		{"action": {"load"}, "name": {"probe"}, "exchange": {"not-an-id"}}, // bad context
	} {
		if out := ui2ExtPost(s, "/ui2/extensions/confirm", form); !strings.Contains(out, "Not run:") || strings.Contains(out, `name="review_id"`) {
			t.Errorf("confirm %v was not refused: %s", form, out)
		}
	}
	if out := ui2ExtPost(s, "/ui2/extensions/run", url.Values{"review_id": {"x"}, "token": {"y"}}); !strings.Contains(out, "unknown or was already used") {
		t.Errorf("run with an unknown review was not refused: %s", out)
	}
	run, _ := ui2ExtConfirmed(t, s, url.Values{"action": {"load"}, "name": {"probe"}})
	run.Set("token", "wrong")
	if out := ui2ExtPost(s, "/ui2/extensions/run", run); !strings.Contains(out, "does not match") {
		t.Errorf("run with a wrong token was not refused: %s", out)
	}
	if st := s.extensionHost().List().Extensions[0].State; st != extension.StateUnloaded {
		t.Errorf("a refused run changed the plugin state to %s", st)
	}
}

// Plugin console output is untrusted: it must reach the page escaped.
func TestUI2ExtensionsConsoleEscapesPluginText(t *testing.T) {
	out := string(ui2Exec("extensions_console.html", ui2ExtConsole{Name: "p", Output: []ui2ExtLine{{Text: `<script>alert(1)</script>`}}}))
	if strings.Contains(out, "<script>") || !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("console line not escaped: %s", out)
	}
}
