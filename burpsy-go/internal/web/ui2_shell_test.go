package web

import (
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/persist"
)

func ui2ShellPersistServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := persist.Open(filepath.Join(dir, "first.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return newTestServer().WithPersist(st), dir
}

func TestUI2ShellStatusRendersStatsScopeAndCA(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	rec := getUI2(t, s, "/ui2/shell/status")
	body := rec.Body.String()
	for _, want := range []string{"1 exchanges", "2 messages", "no include rules", "CA: off"} {
		if !strings.Contains(body, want) {
			t.Errorf("status bar missing %q: %s", want, body)
		}
	}
	// The layout carries the bar's stream/last-event slots for app.js.
	if page := getUI2(t, s, "/ui2/dashboard").Body.String(); !strings.Contains(page, `id="sb-stream"`) || !strings.Contains(page, `id="sb-last"`) {
		t.Errorf("layout lacks the status bar")
	}
}

func TestUI2ShellProjectRename(t *testing.T) {
	s, _ := ui2ShellPersistServer(t)
	rec := postUI2Form(t, s, "/ui2/shell/project/rename", url.Values{"name": {"Engagement <A>"}})
	if !strings.Contains(rec.Body.String(), "Project renamed to Engagement &lt;A&gt;") {
		t.Fatalf("rename did not report: %s", rec.Body.String())
	}
	if name, _ := s.persist.ProjectName(); name != "Engagement <A>" {
		t.Errorf("stored name = %q", name)
	}
	// Refusal: a blank name is not stored.
	rec = postUI2Form(t, s, "/ui2/shell/project/rename", url.Values{"name": {"  "}})
	if !strings.Contains(rec.Body.String(), "cannot be blank") {
		t.Errorf("blank rename not refused: %s", rec.Body.String())
	}
	if name, _ := s.persist.ProjectName(); name != "Engagement <A>" {
		t.Errorf("blank rename changed the name to %q", name)
	}
}

func TestUI2ShellProjectSaveCopy(t *testing.T) {
	s, dir := ui2ShellPersistServer(t)
	// Refusal first: a forged token writes nothing.
	rec := postUI2Form(t, s, "/ui2/shell/project/backup-run", url.Values{"token": {"forged"}})
	if !strings.Contains(rec.Body.String(), "Save copy refused") {
		t.Errorf("forged token not refused: %s", rec.Body.String())
	}
	if n := ui2CountBackups(dir); n != 0 {
		t.Fatalf("a refused save wrote %d snapshot(s)", n)
	}
	conf := postUI2Form(t, s, "/ui2/shell/project/backup-confirm", nil).Body.String()
	if !strings.Contains(conf, "POST /api/backup") || !strings.Contains(conf, "newest 7 snapshots") {
		t.Fatalf("review does not name the call and its pruning: %s", conf)
	}
	rec = postUI2Form(t, s, "/ui2/shell/project/backup-run", url.Values{"token": {extractHiddenInput(t, conf, "token")}})
	if !strings.Contains(rec.Body.String(), "Project copy written to") {
		t.Fatalf("save copy did not report: %s", rec.Body.String())
	}
	if n := ui2CountBackups(dir); n != 1 {
		t.Errorf("snapshots after save = %d, want 1", n)
	}
}

func TestUI2ShellProjectOpenSwitchesAfterReview(t *testing.T) {
	s, dir := ui2ShellPersistServer(t)
	conf := postUI2Form(t, s, "/ui2/shell/project/open-confirm", url.Values{"path": {"second.db"}}).Body.String()
	target := filepath.Join(dir, "second.db")
	if !strings.Contains(conf, target) || !strings.Contains(conf, "NEW EMPTY project") || !strings.Contains(conf, `{&#34;path&#34;:&#34;second.db&#34;}`) {
		t.Fatalf("review does not show the target and full body: %s", conf)
	}
	token := extractHiddenInput(t, conf, "token")
	// Refusal: the token does not cover an edited path.
	rec := postUI2Form(t, s, "/ui2/shell/project/open-run", url.Values{"token": {token}, "path": {"third.db"}})
	if !strings.Contains(rec.Body.String(), "Project switch refused") {
		t.Errorf("edited path not refused: %s", rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "third.db")); err == nil {
		t.Fatalf("a refused switch created third.db")
	}
	conf = postUI2Form(t, s, "/ui2/shell/project/open-confirm", url.Values{"path": {"second.db"}}).Body.String()
	rec = postUI2Form(t, s, "/ui2/shell/project/open-run", url.Values{"token": {extractHiddenInput(t, conf, "token")}, "path": {"second.db"}})
	if !strings.Contains(rec.Body.String(), "Switched to project") {
		t.Fatalf("switch did not report: %s", rec.Body.String())
	}
	if !sameFile(s.persist.Path(), target) {
		t.Errorf("active project = %s, want %s", s.persist.Path(), target)
	}
}

func TestUI2ShellConfigImportAppliesReviewedBundle(t *testing.T) {
	s := newTestServer()
	bundle := `{"version":1,"scope":{"rules":[{"kind":"Include","host":"in.test","enabled":true}]}}`
	conf := postUI2Form(t, s, "/ui2/shell/config/import-confirm", url.Values{"bundle": {bundle}}).Body.String()
	for _, want := range []string{"replaced by 1 rule(s)", "session_rules", "absent from the bundle", "POST /api/config/import", "in.test"} {
		if !strings.Contains(conf, want) {
			t.Errorf("review missing %q", want)
		}
	}
	token := extractHiddenInput(t, conf, "token")
	// Refusal: an edited bundle under the reviewed token applies nothing.
	edited := strings.Replace(bundle, "in.test", "evil.test", 1)
	rec := postUI2Form(t, s, "/ui2/shell/config/import-run", url.Values{"token": {token}, "bundle": {edited}})
	if !strings.Contains(rec.Body.String(), "Import refused") {
		t.Errorf("edited bundle not refused: %s", rec.Body.String())
	}
	if len(s.scope.Rules()) != 0 {
		t.Fatalf("a refused import changed scope: %v", s.scope.Rules())
	}
	conf = postUI2Form(t, s, "/ui2/shell/config/import-confirm", url.Values{"bundle": {bundle}}).Body.String()
	rec = postUI2Form(t, s, "/ui2/shell/config/import-run", url.Values{
		"token": {extractHiddenInput(t, conf, "token")}, "bundle": {html.UnescapeString(extractHiddenInput(t, conf, "bundle"))}})
	body := rec.Body.String()
	if !strings.Contains(body, "Configuration imported") || !strings.Contains(body, "Omitted section") || !strings.Contains(body, "match_replace_rules") {
		t.Fatalf("result sheet does not list applied/omitted sections: %s", body)
	}
	if rules := s.scope.Rules(); len(rules) != 1 || rules[0].Pattern != "in.test" {
		t.Errorf("scope after import = %v", rules)
	}
}

func TestUI2ShellRoutesRejectGetForWrites(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/ui2/shell/project/rename", "/ui2/shell/config/import-run"} {
		if rec := getUI2(t, s, p); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", p, rec.Code)
		}
	}
}
