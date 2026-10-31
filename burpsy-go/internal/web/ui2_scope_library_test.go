package web

// ---- ui2 scope-library controls (burpsy-react-ui-e365 review binding) ---------------------------
//
// The page gained the three library controls, and every one of them rides the confirm gate with
// content binding: the review renders the stored document AND the live list it touches, mints
// digests of both into the call, and the run refuses with a named reason when either side moved.
// These drive the real two-step the page drives — confirm, then run with the hidden fields the
// confirm page emitted — because a digest that never reaches the run form is not a binding.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
)

// ui2ScopeLibraryApply drives the full two-step the page drives for a library action: the
// run form is the page's form PLUS the hidden fields the confirm step emitted, which is
// exactly what the browser submits.
func ui2ScopeLibraryApply(t *testing.T, s *Server, form string) *httptest.ResponseRecorder {
	t.Helper()
	token, body := ui2ScopeConfirm(t, s, form)
	if token == "" {
		t.Fatalf("confirm minted no token: %s", body[:ui2Min(300, len(body))])
	}
	run := "token=" + url.QueryEscape(token) + "&" + form
	for _, f := range []string{"expected_library", "expected_rules"} {
		if v := ui2HiddenValue(body, f); v != "" {
			run += "&" + f + "=" + url.QueryEscape(v)
		}
	}
	return ui2ScopeRun(t, s, run)
}

func seedLibrary(t *testing.T, s *Server, name string, rules ...*core.ScopeRule) {
	t.Helper()
	if _, err := s.persist.SaveScopeLibrary(name, rules); err != nil {
		t.Fatalf("seed library: %v", err)
	}
}

func armed(t *testing.T, kind core.ScopeRuleKind, pattern string) *core.ScopeRule {
	t.Helper()
	r, err := core.NewScopeRuleFrom(kind, pattern, nil, nil, nil)
	if err != nil {
		t.Fatalf("build rule: %v", err)
	}
	return r
}

func TestUI2ScopePageShowsLibraryControls(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "app.test"))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/scope", nil))
	body := rec.Body.String()
	for _, want := range []string{"Libraries", `value="library-save"`, `value="library-load"`, `value="library-delete"`, "engagement", "review save"} {
		if !strings.Contains(body, want) {
			t.Errorf("scope page lacks the library control %q", want)
		}
	}

	// No database: the section says so instead of offering forms that cannot serve.
	s2 := newTestServer()
	rec2 := httptest.NewRecorder()
	s2.mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ui2/scope", nil))
	body2 := rec2.Body.String()
	if !strings.Contains(body2, "Libraries need a project database") {
		t.Errorf("no-database page does not say libraries are unavailable: %s", body2[:ui2Min(400, len(body2))])
	}
	if strings.Contains(body2, `value="library-save"`) {
		t.Errorf("no-database page offers a save form it cannot serve")
	}
}

func TestUI2ScopeLibrarySaveConfirmBindsAndRunApplies(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=app.test")

	token, body := ui2ScopeConfirm(t, s, "scope_action=library-save&name=engagement")
	if token == "" {
		t.Fatalf("no token: %s", body[:ui2Min(300, len(body))])
	}
	for _, want := range []string{`Save the current rules as library "engagement"`, "a new library", "photographs the 1 rules", "app.test", "Known credential carriers"} {
		if !strings.Contains(body, want) {
			t.Errorf("save review lacks %q", want)
		}
	}
	if ui2HiddenValue(body, "expected_library") != "absent" {
		t.Errorf("expected_library = %q, want absent for a new name", ui2HiddenValue(body, "expected_library"))
	}
	if ui2HiddenValue(body, "expected_rules") == "" {
		t.Errorf("expected_rules is not bound")
	}

	rec := ui2ScopeLibraryApply(t, s, "scope_action=library-save&name=engagement")
	if !strings.Contains(rec.Body.String(), `Applied: Saved new library &#34;engagement&#34; (1 rules)`) {
		t.Fatalf("run lacks the success note: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	stored, found, err := s.persist.LoadScopeLibrary("engagement")
	if err != nil || !found || len(stored) != 1 || stored[0].Pattern != "app.test" {
		t.Fatalf("stored = %+v (found %v, err %v)", stored, found, err)
	}
	// The live scope is a save's bystander, not its subject.
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 1 {
		t.Errorf("a save changed the live scope: %+v", rules)
	}
}

func TestUI2ScopeLibrarySaveOverwriteBindingAndDrift(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=one.test")
	ui2ScopeLibraryApply(t, s, "scope_action=library-save&name=engagement")
	ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=two.test")

	// The second save's review says it replaces, and binds the existing document.
	_, body := ui2ScopeConfirm(t, s, "scope_action=library-save&name=engagement")
	if !strings.Contains(body, "REPLACING the saved library of that name") {
		t.Errorf("overwrite review does not say it replaces: %s", body[:ui2Min(400, len(body))])
	}
	if ui2HiddenValue(body, "expected_library") == "absent" || ui2HiddenValue(body, "expected_library") == "" {
		t.Errorf("overwrite review did not bind the existing library's digest")
	}
	rec := ui2ScopeLibraryApply(t, s, "scope_action=library-save&name=engagement")
	if !strings.Contains(rec.Body.String(), "replacing the previous save") {
		t.Fatalf("overwrite run lacks the replaced note: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	stored, _, _ := s.persist.LoadScopeLibrary("engagement")
	if len(stored) != 2 {
		t.Fatalf("stored = %d rules, want the 2-rule photograph", len(stored))
	}

	// Drift on the live side: confirm, then change the rules, then run — refused by name.
	token, body2 := ui2ScopeConfirm(t, s, "scope_action=library-save&name=engagement")
	run := "token=" + url.QueryEscape(token) + "&scope_action=library-save&name=engagement" +
		"&expected_library=" + url.QueryEscape(ui2HiddenValue(body2, "expected_library")) +
		"&expected_rules=" + url.QueryEscape(ui2HiddenValue(body2, "expected_rules"))
	s.scope.Add(core.NewScopeRule(core.ScopeInclude, "three.test"))
	rec = ui2ScopeRun(t, s, run)
	if !strings.Contains(rec.Body.String(), "Not applied") || !strings.Contains(rec.Body.String(), "current rules changed since this review") {
		t.Fatalf("live-side drift was not refused: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	if stored, _, _ := s.persist.LoadScopeLibrary("engagement"); len(stored) != 2 {
		t.Fatalf("a refused save wrote anyway: %+v", stored)
	}

	// Drift on the stored side: confirm, then overwrite the library directly, then run.
	token, body3 := ui2ScopeConfirm(t, s, "scope_action=library-save&name=engagement")
	run = "token=" + url.QueryEscape(token) + "&scope_action=library-save&name=engagement" +
		"&expected_library=" + url.QueryEscape(ui2HiddenValue(body3, "expected_library")) +
		"&expected_rules=" + url.QueryEscape(ui2HiddenValue(body3, "expected_rules"))
	if _, err := s.persist.SaveScopeLibrary("engagement", []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "other.test")}); err != nil {
		t.Fatalf("direct overwrite: %v", err)
	}
	rec = ui2ScopeRun(t, s, run)
	if !strings.Contains(rec.Body.String(), "Not applied") || !strings.Contains(rec.Body.String(), "saved library changed since this review") {
		t.Fatalf("stored-side drift was not refused: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	if stored, _, _ := s.persist.LoadScopeLibrary("engagement"); len(stored) != 1 || stored[0].Pattern != "other.test" {
		t.Fatalf("a refused overwrite wrote anyway: %+v", stored)
	}
}

func TestUI2ScopeLibraryLoadConfirmShowsBothSidesAndRunReplaces(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	disabled := armed(t, core.ScopeExclude, "admin.test")
	disabled.Enabled = false
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "app.test"), disabled)
	ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=current.test")

	token, body := ui2ScopeConfirm(t, s, "scope_action=library-load&name=engagement")
	if token == "" {
		t.Fatalf("no token: %s", body[:ui2Min(300, len(body))])
	}
	for _, want := range []string{
		`Load library "engagement"`, "replaces the current rules",
		"Only requests matching the enabled include rules below will be in scope",
		"drop switch and any custom drop scope are NOT changed",
		"app.test", "admin.test",
		"The 1 current rules this load discards", "current.test",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("load review lacks %q", want)
		}
	}
	rec := ui2ScopeLibraryApply(t, s, "scope_action=library-load&name=engagement")
	if !strings.Contains(rec.Body.String(), `Applied: Loaded library &#34;engagement&#34;: 2 rules now in force`) {
		t.Fatalf("load run lacks the success note: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 2 {
		t.Fatalf("rules after load = %+v, want the 2 stored rules", rules)
	}
	// The disabled rule came back disabled: a photograph, not an edit.
	var admin *struct {
		Kind    string  `json:"kind"`
		Host    *string `json:"host"`
		Port    *uint16 `json:"port"`
		Enabled bool    `json:"enabled"`
	}
	for i := range rules {
		if rules[i].Host != nil && *rules[i].Host == "admin.test" {
			admin = &rules[i]
		}
	}
	if admin == nil || admin.Enabled {
		t.Errorf("the disabled stored rule did not come back disabled: %+v", rules)
	}
	// The load persisted the new live list (a restart must see it).
	persisted, err := s.persist.LoadScope()
	if err != nil || len(persisted) != 2 {
		t.Errorf("the loaded list was not persisted: %v %+v", err, persisted)
	}
}

func TestUI2ScopeLibraryLoadDriftRefusals(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "app.test"))

	// Live-side drift: a rule added between the review and the run is never silently discarded.
	token, body := ui2ScopeConfirm(t, s, "scope_action=library-load&name=engagement")
	run := "token=" + url.QueryEscape(token) + "&scope_action=library-load&name=engagement" +
		"&expected_library=" + url.QueryEscape(ui2HiddenValue(body, "expected_library")) +
		"&expected_rules=" + url.QueryEscape(ui2HiddenValue(body, "expected_rules"))
	s.scope.Add(core.NewScopeRule(core.ScopeInclude, "late.test"))
	rec := ui2ScopeRun(t, s, run)
	if !strings.Contains(rec.Body.String(), "current rules changed since this review") {
		t.Fatalf("live-side drift was not refused: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 1 || rules[0].Host == nil || *rules[0].Host != "late.test" {
		t.Fatalf("a refused load replaced the rules anyway: %+v", rules)
	}

	// Stored-side drift: the library rewritten between the review and the run is not loaded.
	token, body = ui2ScopeConfirm(t, s, "scope_action=library-load&name=engagement")
	run = "token=" + url.QueryEscape(token) + "&scope_action=library-load&name=engagement" +
		"&expected_library=" + url.QueryEscape(ui2HiddenValue(body, "expected_library")) +
		"&expected_rules=" + url.QueryEscape(ui2HiddenValue(body, "expected_rules"))
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "rewritten.test"))
	rec = ui2ScopeRun(t, s, run)
	if !strings.Contains(rec.Body.String(), "saved library changed since this review") {
		t.Fatalf("stored-side drift was not refused: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	rules, _ = ui2ScopeState(t, s)
	if len(rules) != 1 || *rules[0].Host != "late.test" {
		t.Fatalf("a refused load ran against the rewritten library: %+v", rules)
	}
}

func TestUI2ScopeLibraryDeleteFlow(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "app.test"))
	ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=live.test")

	_, body := ui2ScopeConfirm(t, s, "scope_action=library-delete&name=engagement")
	for _, want := range []string{`Delete library "engagement"`, "app.test", "live scope is NOT changed"} {
		if !strings.Contains(body, want) {
			t.Errorf("delete review lacks %q", want)
		}
	}
	rec := ui2ScopeLibraryApply(t, s, "scope_action=library-delete&name=engagement")
	if !strings.Contains(rec.Body.String(), `Applied: Deleted library &#34;engagement&#34;; the live scope was not changed`) {
		t.Fatalf("delete run lacks the success note: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	if _, found, _ := s.persist.LoadScopeLibrary("engagement"); found {
		t.Fatal("the library survived its confirmed delete")
	}
	rules, _ := ui2ScopeState(t, s)
	if len(rules) != 1 || *rules[0].Host != "live.test" {
		t.Errorf("a delete touched the live scope: %+v", rules)
	}

	// Delete of a library replaced mid-review refuses.
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "one.test"))
	token, body2 := ui2ScopeConfirm(t, s, "scope_action=library-delete&name=engagement")
	run := "token=" + url.QueryEscape(token) + "&scope_action=library-delete&name=engagement" +
		"&expected_library=" + url.QueryEscape(ui2HiddenValue(body2, "expected_library"))
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "two.test"))
	rec = ui2ScopeRun(t, s, run)
	if !strings.Contains(rec.Body.String(), "saved library changed since this review") {
		t.Fatalf("delete of a replaced library was not refused: %s", rec.Body.String()[:ui2Min(400, rec.Body.Len())])
	}
	if _, found, _ := s.persist.LoadScopeLibrary("engagement"); !found {
		t.Fatal("a refused delete removed the replacement")
	}
}

func TestUI2ScopeLibraryPolicyLineCoversTheFourCases(t *testing.T) {
	inc := func(enabled bool) persist.ScopeLibraryRule {
		return persist.ScopeLibraryRule{Kind: "include", Pattern: "app.test", Enabled: enabled}
	}
	exc := func(enabled bool) persist.ScopeLibraryRule {
		return persist.ScopeLibraryRule{Kind: "exclude", Pattern: "admin.test", Enabled: enabled}
	}
	cases := []struct {
		name  string
		rules []persist.ScopeLibraryRule
		want  string
	}{
		{"no rules at all", nil, "allows EVERYTHING (default allow)"},
		{"excludes only, enabled", []persist.ScopeLibraryRule{exc(true)}, "EVERYTHING not named by the enabled excludes"},
		{"excludes only, all disabled", []persist.ScopeLibraryRule{exc(false)}, "excludes are disabled (visible but inert): EVERYTHING"},
		{"includes all disabled", []persist.ScopeLibraryRule{inc(false), exc(true)}, "NOTHING will be in scope"},
		{"enabled include, enabled exclude", []persist.ScopeLibraryRule{inc(true), exc(true)}, "minus the enabled excludes"},
		{"enabled include, disabled exclude", []persist.ScopeLibraryRule{inc(true), exc(false)}, "the excludes are disabled (visible but inert)"},
	}
	for _, c := range cases {
		if got := ui2ScopeLibraryPolicyLine(c.rules); !strings.Contains(got, c.want) {
			t.Errorf("%s: policy line = %q, want it to contain %q", c.name, got, c.want)
		}
	}
}

func TestUI2ScopeLibraryReviewMasksURLCredentialCarriers(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	rule := armed(t, core.ScopeInclude, "http://operator:s3cret-password@app.test")
	path := "/reset?token=SHOULD-NOT-RENDER"
	rule.PathPrefix = &path
	seedLibrary(t, s, "engagement", rule)

	_, body := ui2ScopeConfirm(t, s, "scope_action=library-load&name=engagement")
	for _, leaked := range []string{"s3cret-password", "SHOULD-NOT-RENDER"} {
		if strings.Contains(body, leaked) {
			t.Errorf("the review sheet renders the credential %q", leaked)
		}
	}
	for _, want := range []string{redactedValue, "app.test", "Known credential carriers in URLs"} {
		if !strings.Contains(body, want) {
			t.Errorf("the review sheet lacks %q", want)
		}
	}
	// The label names what is masked; it must not claim a blanket credential sweep.
	if strings.Contains(body, "credentials are withheld in this view but bound") {
		t.Errorf("the sheet overclaims: patterns are free text and only the known URL carriers are masked")
	}
}

func TestUI2ScopeLibraryReviewEscapesAHostileName(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	hostile := `<script>alert("x")</script>`
	seedLibrary(t, s, hostile, armed(t, core.ScopeInclude, "app.test"))
	_, body := ui2ScopeConfirm(t, s, "scope_action=library-load&name="+url.QueryEscape(hostile))
	if strings.Contains(body, `<script>alert("x")</script>`) {
		t.Errorf("the review sheet renders a raw hostile library name")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the hostile name is not escaped in the sheet")
	}
	// And on the listing page.
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/scope", nil))
	if strings.Contains(rec.Body.String(), `<script>alert("x")</script>`) {
		t.Errorf("the scope page renders a raw hostile library name")
	}
}

func TestUI2ScopeLibraryConfirmWithoutDatabaseSays503Reason(t *testing.T) {
	s := newTestServer()
	_, body := ui2ScopeConfirm(t, s, "scope_action=library-save&name=engagement")
	if !strings.Contains(body, "No project database is open") {
		t.Errorf("no-database review does not say why: %s", body[:ui2Min(300, len(body))])
	}
	if ui2HiddenValue(body, "token") != "" {
		t.Errorf("a library call minted a token with no database to serve it")
	}
}

func TestUI2ScopeLibraryRunWithTamperedDigestIsRefused(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=app.test")
	token, body := ui2ScopeConfirm(t, s, "scope_action=library-save&name=engagement")
	if token == "" {
		t.Fatal("no token")
	}
	// The form the browser posts, with one digest character flipped: the token was not minted
	// for this body and the gate must refuse before the API ever runs.
	tampered := ui2HiddenValue(body, "expected_rules")
	tampered = "0" + tampered[1:]
	rec := ui2ScopeRun(t, s, "token="+url.QueryEscape(token)+"&scope_action=library-save&name=engagement"+
		"&expected_library=absent&expected_rules="+tampered)
	if !strings.Contains(rec.Body.String(), "Not applied") {
		t.Fatalf("a tampered digest ran: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	if _, found, _ := s.persist.LoadScopeLibrary("engagement"); found {
		t.Fatal("a tampered run saved the library")
	}
}

func TestUI2ScopeLibraryUnknownNameIsRefusedAtReview(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	seedLibrary(t, s, "real-one", armed(t, core.ScopeInclude, "app.test"))
	_, body := ui2ScopeConfirm(t, s, "scope_action=library-load&name=typo")
	if !strings.Contains(body, `No scope library called &#34;typo&#34;`) || !strings.Contains(body, "real-one") {
		t.Errorf("the review does not name the typo and what exists: %s", body[:ui2Min(300, len(body))])
	}
	if ui2HiddenValue(body, "token") != "" {
		t.Errorf("a load of a missing library minted a token")
	}
}

// The gate keeps digest-less calls working exactly as before: the legacy console sends none,
// and nothing about its authorisation changed.
func TestUI2ScopeLibraryLegacyDigestlessCallsStillWork(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	ui2ScopeApply(t, s, "scope_action=rule-add&kind=include&pattern=app.test")
	token, _ := ui2ScopeConfirm(t, s, "scope_action=drop-switch&enabled=true")
	if token == "" {
		t.Fatal("no token for the legacy call")
	}
	rec := ui2ScopeRun(t, s, "token="+url.QueryEscape(token)+"&scope_action=drop-switch&enabled=true")
	if strings.Contains(rec.Body.String(), "Not applied") {
		t.Fatalf("a legacy digest-less call was refused: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
	if _, drop := ui2ScopeState(t, s); !drop {
		t.Fatal("the legacy call did not apply")
	}
}

// The scope review sheet and its outcome notes survive a live-refresh: the sheet's one-time
// token and content digests exist only in the DOM, so a refresh that swapped them away would
// strand a review mid-read, and a refresh that erased the note would erase the record of what
// just happened. app.js holds the refresh to the pill for both, exactly as the session page's.
// The review copy claims the confirmation covers "exactly the call above"; the preview must
// therefore project the FULL call body - a library call's two 64-hex content digests push it
// past the shared helper's 200-character abbreviation, and an abbreviated body under that
// claim is a label the bytes do not keep.
func TestUI2ScopeLibraryConfirmPreviewShowsTheFullCallBody(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "app.test"))
	_, body := ui2ScopeConfirm(t, s, "scope_action=library-load&name=engagement")
	i := strings.Index(body, "Review before applying:")
	if i < 0 {
		t.Fatalf("no review line: %s", body[:ui2Min(300, len(body))])
	}
	line := body[i : i+ui2Min(900, len(body)-i)]
	if strings.Contains(line, "…") {
		t.Errorf("the preview abbreviates the call body while claiming exactness: %s", line[:ui2Min(300, len(line))])
	}
	// Both full content bindings appear verbatim: the stored library's digest and the live
	// list's digest, computed here from the same sources the mint used.
	_, libDigest, found, err := s.persist.LoadScopeLibraryWithDigest("engagement")
	if err != nil || !found {
		t.Fatalf("LoadScopeLibraryWithDigest: %v %v", found, err)
	}
	liveDigest := core.ScopeRulesDigest(s.scope.Rules())
	for name, d := range map[string]string{"stored library": libDigest, "live rules": liveDigest} {
		if !strings.Contains(line, d) {
			t.Errorf("the preview omits the full %s digest %s", name, d)
		}
	}
}

func TestUI2ScopeReviewSheetAndNotesSurviveLiveRefresh(t *testing.T) {
	confirm, err := ui2FS.ReadFile("ui2/scope_confirm.html")
	if err != nil {
		t.Fatalf("read scope_confirm.html: %v", err)
	}
	if !strings.Contains(string(confirm), `<div id="srows" data-review="1">`) {
		t.Error("scope_confirm.html root lacks data-review: a refresh would strand a pending review")
	}
	page, err := ui2FS.ReadFile("ui2/scope.html")
	if err != nil {
		t.Fatalf("read scope.html: %v", err)
	}
	if !strings.Contains(string(page), `id="scope-note"`) {
		t.Error("scope.html outcome notes lack #scope-note: a refresh would erase a just-rendered outcome")
	}
	js, err := ui2FS.ReadFile("ui2/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	body := string(js)
	head := body[:strings.Index(body, "function liveGuarded")+2600]
	if !strings.Contains(head, "what === 'scope'") || !strings.Contains(head, "#scope-note") {
		t.Error("liveGuarded does not hold the scope refresh for a pending review and outcome note")
	}
}

// The phone stylesheet hides the Path and Protocol columns of every scope-t table
// (layout.html's phone block), so a review table without the scope-sd detail row the main
// scope table carries would show a phone operator neither the path nor the protocol arm of
// the rules they are about to apply. Every rule row in every library review table (the
// stored rules to load, the current rules a load discards, the rules a save photographs,
// the rules a delete removes) is followed by the detail row the phone block flips visible.
func TestUI2ScopeLibraryConfirmTablesCarryPhoneDetailRows(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	seedLibrary(t, s, "engagement", armed(t, core.ScopeInclude, "app.test"))
	ui2ScopeApply(t, s, "scope_action=rule-add&kind=exclude&pattern=other.test")

	for name, tc := range map[string]struct {
		form  string
		rules int
	}{
		"load":   {"scope_action=library-load&name=engagement", 2}, // 1 stored + 1 discarded
		"save":   {"scope_action=library-save&name=snapshot", 1},
		"delete": {"scope_action=library-delete&name=engagement", 1},
	} {
		_, body := ui2ScopeConfirm(t, s, tc.form)
		if rows := strings.Count(body, `class="meta scope-sd"`); rows != tc.rules {
			t.Errorf("%s confirm: %d phone detail rows, want one per rule row (%d)", name, rows, tc.rules)
		}
		if !strings.Contains(body, "path:") || !strings.Contains(body, "protocol:") {
			t.Errorf("%s confirm: the phone detail rows omit the arms the phone hides", name)
		}
	}
}

// The phone-visible review stands on two stylesheet rules: the phone media block flips
// scope-sd rows to table-row, and .brk wraps the long content digests in the preview
// instead of letting them clip horizontally off the viewport. The confirm sheet must
// carry the class on the preview span.
func TestUI2ScopeLibraryPhoneReviewStylesheetRules(t *testing.T) {
	layout, err := ui2FS.ReadFile("ui2/layout.html")
	if err != nil {
		t.Fatalf("read layout.html: %v", err)
	}
	for _, pin := range []string{
		"table.scope-t tr.scope-sd { display:table-row; }",
		".brk { overflow-wrap:anywhere;",
	} {
		if !strings.Contains(string(layout), pin) {
			t.Errorf("layout.html is missing %q - the phone review loses it", pin)
		}
	}
	s, _ := scopeLibraryServer(t)
	_, body := ui2ScopeConfirm(t, s, "scope_action=drop-switch&enabled=true")
	if !strings.Contains(body, `<span class="meta brk">`) {
		t.Error("the confirm preview span lacks the brk wrap class")
	}
}
