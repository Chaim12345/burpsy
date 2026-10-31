package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/schedule"
)

// The whole file drives the ui2 settings write surface the way the page does: a form POST to
// confirm, the review_id and token out of the rendered review, then a POST to run carrying ONLY
// those two values. State changes outside the reviewed flow (drift) go through the internal mux
// directly, exactly as another console client would.

func ui2PostSettingsWrite(t *testing.T, s *Server, area, action string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/settings/write/"+area+"/"+action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func ui2GetSettingsWrite(t *testing.T, s *Server, area string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui2/settings/write/"+area, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// ui2ReviewedRun completes one reviewed write: confirm, extract the review fields, run. It fails
// the test when the confirm did not render a review.
func ui2ReviewedRun(t *testing.T, s *Server, area string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	conf := ui2PostSettingsWrite(t, s, area, "confirm", form)
	id, token := ui2ReviewFields(t, conf.Body.String())
	if id == "" || token == "" {
		t.Fatalf("confirm did not render a review (status %d): %s", conf.Code, conf.Body.String())
	}
	return ui2PostSettingsWrite(t, s, area, "run", url.Values{"review_id": {id}, "token": {token}})
}

func ui2PassthroughServer(t *testing.T) *Server {
	t.Helper()
	return newTestServer().WithTlsPolicy(proxy.NewTlsPolicy())
}

// ---- passthrough -------------------------------------------------------------------------------

func Test_ui2settings_passthrough_add_round_trip_with_exact_body(t *testing.T) {
	s := ui2PassthroughServer(t)
	conf := ui2PostSettingsWrite(t, s, "passthrough", "confirm", url.Values{"op": {"add"}, "pattern": {"*.example.com"}})
	body := conf.Body.String()
	if !strings.Contains(body, "*.example.com") {
		t.Errorf("the review does not show the pattern being added:\n%s", body)
	}
	if !strings.Contains(body, "POST /api/proxy/passthrough") {
		t.Errorf("the review does not show the exact call:\n%s", body)
	}
	if !strings.Contains(body, "pass through UNTOUCHED") {
		t.Errorf("the review does not state the interception consequence:\n%s", body)
	}
	rec := ui2ReviewedRun(t, s, "passthrough", url.Values{"op": {"add"}, "pattern": {"*.example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("run answered %d: %s", rec.Code, rec.Body.String())
	}
	got := get(t, s, "/api/proxy/passthrough")
	if !strings.Contains(got.Body.String(), "*.example.com") {
		t.Errorf("after the reviewed add the passthrough list is %s", got.Body.String())
	}
}

func Test_ui2settings_passthrough_add_blank_pattern_refused(t *testing.T) {
	s := ui2PassthroughServer(t)
	rec := ui2PostSettingsWrite(t, s, "passthrough", "confirm", url.Values{"op": {"add"}, "pattern": {"   "}})
	if !strings.Contains(rec.Body.String(), "non-empty host pattern") {
		t.Errorf("a blank pattern was not refused at review:\n%s", rec.Body.String())
	}
	if id, token := ui2HiddenValue(rec.Body.String(), "review_id"), ui2HiddenValue(rec.Body.String(), "token"); id != "" || token != "" {
		t.Error("a refused review still minted a token")
	}
}

func Test_ui2settings_passthrough_remove_and_double_remove_surfaces_404(t *testing.T) {
	s := ui2PassthroughServer(t)
	s.tlsPolicy.AddPassthrough("exact.example.com")

	rec := ui2ReviewedRun(t, s, "passthrough", url.Values{"op": {"remove"}, "pattern": {"exact.example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove run answered %d: %s", rec.Code, rec.Body.String())
	}
	if got := get(t, s, "/api/proxy/passthrough"); strings.Contains(got.Body.String(), "exact.example.com") {
		t.Errorf("the pattern survived its reviewed removal: %s", got.Body.String())
	}

	// A second reviewed removal of the same pattern must surface the API's 404, not report success.
	rec = ui2ReviewedRun(t, s, "passthrough", url.Values{"op": {"remove"}, "pattern": {"exact.example.com"}})
	if !strings.Contains(rec.Body.String(), "Not saved") || !strings.Contains(rec.Body.String(), "exact.example.com") {
		t.Errorf("the double-remove did not surface the API refusal naming the pattern:\n%s", rec.Body.String())
	}
}

func Test_ui2settings_passthrough_switch_writes_only_its_own_field(t *testing.T) {
	s := ui2PassthroughServer(t)
	s.tlsPolicy.SetAutoAddOnFailure(true)

	conf := ui2PostSettingsWrite(t, s, "passthrough", "confirm", url.Values{
		"op": {"switch"}, "field": {"apply_out_of_scope"}, "value": {"true"},
	})
	body := conf.Body.String()
	if !strings.Contains(body, "apply_out_of_scope") {
		t.Errorf("the review does not show the switch being written:\n%s", body)
	}
	if strings.Contains(body, "auto_add_on_failure") {
		t.Errorf("the minted call carries the OTHER switch - a stale prefill would overwrite it:\n%s", body)
	}
	rec := ui2ReviewedRun(t, s, "passthrough", url.Values{
		"op": {"switch"}, "field": {"apply_out_of_scope"}, "value": {"true"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("run answered %d: %s", rec.Code, rec.Body.String())
	}
	if !s.tlsPolicy.ApplyOutOfScope() {
		t.Error("apply_out_of_scope did not move to true")
	}
	if !s.tlsPolicy.AutoAddOnFailure() {
		t.Error("auto_add_on_failure was true before the reviewed write and is now false - the other switch was overwritten")
	}
}

func Test_ui2settings_passthrough_unknown_switch_field_refused(t *testing.T) {
	s := ui2PassthroughServer(t)
	rec := ui2PostSettingsWrite(t, s, "passthrough", "confirm", url.Values{
		"op": {"switch"}, "field": {"intercept_everything"}, "value": {"true"},
	})
	if !strings.Contains(rec.Body.String(), "unknown passthrough switch") {
		t.Errorf("a made-up switch field was not refused:\n%s", rec.Body.String())
	}
}

// ---- upstream proxy ----------------------------------------------------------------------------

func Test_ui2settings_proxy_rule_set_preserves_default_and_remove_falls_back(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	// Set the default first, so the rule write can be proven not to touch it.
	if rec := ui2ReviewedRun(t, s, "proxy-default", url.Values{"op": {"set"}, "default": {"socks5://127.0.0.1:9050"}}); rec.Code != http.StatusOK {
		t.Fatalf("default run answered %d: %s", rec.Code, rec.Body.String())
	}
	conf := ui2PostSettingsWrite(t, s, "proxy-rule", "confirm", url.Values{
		"op": {"set"}, "pattern": {"*.internal.example"}, "proxy": {"http://127.0.0.1:8888"},
	})
	body := conf.Body.String()
	for _, want := range []string{"pattern", "*.internal.example", "proxy", "http://127.0.0.1:8888"} {
		if !strings.Contains(body, want) {
			t.Errorf("the review does not show %q of the rule being written:\n%s", want, body)
		}
	}
	if strings.Contains(body, `&#34;default&#34;`) {
		t.Errorf("a rule write carries a default - the existing default would be overwritten:\n%s", body)
	}
	if !strings.Contains(body, "routed through http://127.0.0.1:8888") {
		t.Errorf("the review does not state the future-traffic consequence:\n%s", body)
	}
	rec := ui2ReviewedRun(t, s, "proxy-rule", url.Values{
		"op": {"set"}, "pattern": {"*.internal.example"}, "proxy": {"http://127.0.0.1:8888"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("rule run answered %d: %s", rec.Code, rec.Body.String())
	}
	view := getNetworkProxyView(t, s)
	if len(view.Rules) != 1 || view.Rules[0].Pattern != "*.internal.example" {
		t.Fatalf("the reviewed rule is not in force: %+v", view.Rules)
	}
	if view.Default != "socks5://127.0.0.1:9050" {
		t.Errorf("the default moved during a rule write: %q", view.Default)
	}

	conf = ui2PostSettingsWrite(t, s, "proxy-rule", "confirm", url.Values{"op": {"remove"}, "pattern": {"*.internal.example"}})
	if !strings.Contains(conf.Body.String(), "socks5://127.0.0.1:9050") {
		t.Errorf("the removal review does not name the default the rule falls back to:\n%s", conf.Body.String())
	}
	if rec := ui2ReviewedRun(t, s, "proxy-rule", url.Values{"op": {"remove"}, "pattern": {"*.internal.example"}}); rec.Code != http.StatusOK {
		t.Fatalf("remove run answered %d: %s", rec.Code, rec.Body.String())
	}
	if view := getNetworkProxyView(t, s); len(view.Rules) != 0 {
		t.Errorf("the rule survived its reviewed removal: %+v", view.Rules)
	}
}

func Test_ui2settings_proxy_default_clear_is_explicit_and_reviewed(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	if rec := ui2ReviewedRun(t, s, "proxy-default", url.Values{"op": {"set"}, "default": {"socks5://127.0.0.1:9050"}}); rec.Code != http.StatusOK {
		t.Fatalf("set answered %d: %s", rec.Code, rec.Body.String())
	}
	conf := ui2PostSettingsWrite(t, s, "proxy-default", "confirm", url.Values{"op": {"set"}, "default": {"direct"}})
	body := conf.Body.String()
	if !strings.Contains(body, "DIRECTLY") || !strings.Contains(body, "socks5://127.0.0.1:9050") {
		t.Errorf("the clear review does not state what is being cleared and where traffic goes:\n%s", body)
	}
	if rec := ui2ReviewedRun(t, s, "proxy-default", url.Values{"op": {"set"}, "default": {"direct"}}); rec.Code != http.StatusOK {
		t.Fatalf("clear answered %d: %s", rec.Code, rec.Body.String())
	}
	if view := getNetworkProxyView(t, s); view.Default != "direct" {
		t.Errorf("after the reviewed clear the default is %q", view.Default)
	}
}

// The synthetic credential: distinctive enough that any appearance in a response is a leak.
const ui2TestProxySecret = "s3cr3t-PROXY-fixture-0000"

func Test_ui2settings_proxy_userinfo_refused_and_never_echoed(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	raw := "socks5://alice:" + ui2TestProxySecret + "@127.0.0.1:1080"
	for _, area := range []string{"proxy-rule", "proxy-default"} {
		form := url.Values{"op": {"set"}, "proxy": {raw}, "pattern": {"*.example.com"}, "default": {raw}}
		rec := ui2PostSettingsWrite(t, s, area, "confirm", form)
		body := rec.Body.String()
		if !strings.Contains(body, "embedded credentials") {
			t.Errorf("%s: a credential-bearing proxy URL was not refused:\n%s", area, body)
		}
		if strings.Contains(body, ui2TestProxySecret) || strings.Contains(body, "alice") {
			t.Errorf("%s: the refusal echoes the credential:\n%s", area, body)
		}
		if id, token := ui2HiddenValue(body, "review_id"), ui2HiddenValue(body, "token"); id != "" || token != "" {
			t.Errorf("%s: a refused review still minted a token", area)
		}
	}
}

func Test_ui2settings_proxy_unparseable_url_refused(t *testing.T) {
	s, _ := newProxyPolicyServer(t)
	rec := ui2PostSettingsWrite(t, s, "proxy-rule", "confirm", url.Values{
		"op": {"set"}, "pattern": {"*.example.com"}, "proxy": {"not a proxy at all"},
	})
	if !strings.Contains(rec.Body.String(), "Not saved") {
		t.Errorf("an unparseable proxy URL reached the review sheet:\n%s", rec.Body.String())
	}
}

// ---- automatic backup --------------------------------------------------------------------------

func ui2BackupForm(interval, dir, retention string, dos bool) url.Values {
	v := url.Values{"op": {"set"}, "interval_minutes": {interval}, "dir": {dir}, "retention": {retention}}
	if dos {
		v.Set("delete_on_shutdown", "1")
	}
	return v
}

func Test_ui2settings_backup_save_round_trip_with_full_census(t *testing.T) {
	s := newTestServerWithPersist(t)
	dir := t.TempDir()
	conf := ui2PostSettingsWrite(t, s, "backup", "confirm", ui2BackupForm("30", dir, "5", true))
	body := conf.Body.String()
	for _, want := range []string{"interval_minutes", "30", "retention", "5", "delete_on_shutdown", dir, "deletes every automatic-backup file"} {
		if !strings.Contains(body, want) {
			t.Errorf("the review is missing %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "Not atomic") {
		t.Errorf("the review does not state the non-atomic limitation:\n%s", body)
	}
	rec := ui2ReviewedRun(t, s, "backup", ui2BackupForm("30", dir, "5", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("run answered %d: %s", rec.Code, rec.Body.String())
	}
	got := get(t, s, "/api/backup/config")
	var cfg backupConfig
	if err := json.Unmarshal(got.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.IntervalMinutes != 30 || cfg.Dir != dir || cfg.Retention != 5 || !cfg.DeleteOnShutdown {
		t.Errorf("the saved config is %+v, not what was reviewed", cfg)
	}
}

func Test_ui2settings_backup_drift_between_review_and_run_refuses(t *testing.T) {
	s := newTestServerWithPersist(t)
	conf := ui2PostSettingsWrite(t, s, "backup", "confirm", ui2BackupForm("30", "", "0", false))
	id, token := ui2ReviewFields(t, conf.Body.String())
	if id == "" {
		t.Fatalf("no review rendered: %s", conf.Body.String())
	}
	// Drift: another client changes the settings after the review.
	if rec := do(t, s, http.MethodPut, "/api/backup/config", map[string]any{"interval_minutes": 60, "dir": "", "retention": 0, "delete_on_shutdown": false}); rec.Code != http.StatusOK {
		t.Fatalf("the drift write answered %d: %s", rec.Code, rec.Body.String())
	}
	rec := ui2PostSettingsWrite(t, s, "backup", "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "changed between your review") {
		t.Errorf("a drifted save was not refused:\n%s", rec.Body.String())
	}
	got := get(t, s, "/api/backup/config")
	var cfg backupConfig
	_ = json.Unmarshal(got.Body.Bytes(), &cfg)
	if cfg.IntervalMinutes != 60 {
		t.Errorf("the refused run still wrote: config is %+v", cfg)
	}
}

func Test_ui2settings_backup_empty_dir_review_names_effective_dir(t *testing.T) {
	s := newTestServerWithPersist(t)
	conf := ui2PostSettingsWrite(t, s, "backup", "confirm", ui2BackupForm("15", "", "0", true))
	want := filepath.Dir(s.persist.Path())
	body := conf.Body.String()
	if !strings.Contains(body, want) {
		t.Errorf("the review does not name the effective directory %q for an empty dir:\n%s", want, body)
	}
	if !strings.Contains(body, "beside the live database") {
		t.Errorf("the review does not explain the empty-dir fallback:\n%s", body)
	}
}

func Test_ui2settings_backup_off_says_schedule_removed_not_files_deleted(t *testing.T) {
	s := newTestServerWithPersist(t)
	conf := ui2PostSettingsWrite(t, s, "backup", "confirm", ui2BackupForm("0", "", "0", false))
	body := conf.Body.String()
	if !strings.Contains(body, "managed schedule is removed") || !strings.Contains(body, "No existing backup files are deleted") {
		t.Errorf("the interval=0 review does not say what actually happens:\n%s", body)
	}
}

func Test_ui2settings_backup_garbage_interval_refused(t *testing.T) {
	s := newTestServerWithPersist(t)
	for _, bad := range []string{"soon", "-5"} {
		rec := ui2PostSettingsWrite(t, s, "backup", "confirm", ui2BackupForm(bad, "", "0", false))
		if !strings.Contains(rec.Body.String(), "Not saved") {
			t.Errorf("interval %q reached the review sheet:\n%s", bad, rec.Body.String())
		}
	}
}

// ---- pools -------------------------------------------------------------------------------------

func Test_ui2settings_pool_create_round_trip(t *testing.T) {
	s := newTestServer()
	conf := ui2PostSettingsWrite(t, s, "pools", "confirm", url.Values{
		"op": {"create"}, "name": {"out of hours"}, "max_concurrent": {"2"}, "delay_ms": {"500"},
	})
	body := conf.Body.String()
	for _, want := range []string{"name", "out of hours", "max_concurrent", "delay_ms"} {
		if !strings.Contains(body, want) {
			t.Errorf("the review does not show %q of the pool being created:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "throttling: OFF") {
		t.Errorf("the review does not state the throttle the form cannot set:\n%s", body)
	}
	rec := ui2ReviewedRun(t, s, "pools", url.Values{
		"op": {"create"}, "name": {"out of hours"}, "max_concurrent": {"2"}, "delay_ms": {"500"},
	})
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("run answered %d: %s", rec.Code, rec.Body.String())
	}
	view := decodePools(t, get(t, s, "/api/pools"), http.StatusOK)
	if view.Count != 1 || view.Pools[0].Name != "out of hours" || view.Pools[0].MaxConcurrent != 2 {
		t.Fatalf("the reviewed pool is not saved: %+v", view.Pools)
	}
	if view.Pools[0].Throttle != nil {
		t.Error("a pool created through this form has a throttle - the review said OFF")
	}
}

func Test_ui2settings_pool_create_duplicate_surfaces_409(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "taken", MaxConcurrent: 1})
	rec := ui2ReviewedRun(t, s, "pools", url.Values{
		"op": {"create"}, "name": {"taken"}, "max_concurrent": {"1"}, "delay_ms": {"0"},
	})
	if !strings.Contains(rec.Body.String(), "Not saved") {
		t.Errorf("creating a duplicate pool did not surface the API refusal:\n%s", rec.Body.String())
	}
}

func Test_ui2settings_pool_edit_preserves_throttle_and_name(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{
		Name: "keepme", MaxConcurrent: 4, DelayMs: 100, Throttle: &pool.Throttle{IncrementMs: 50},
	})
	conf := ui2PostSettingsWrite(t, s, "pools", "confirm", url.Values{
		"op": {"edit"}, "name": {"keepme"}, "max_concurrent": {"4"}, "delay_ms": {"250"},
	})
	body := conf.Body.String()
	if !strings.Contains(body, "throttle") || !strings.Contains(body, "preserved unchanged") {
		t.Errorf("the edit review does not show the throttle being preserved:\n%s", body)
	}
	if !strings.Contains(body, "PUT /api/pools/keepme") {
		t.Errorf("the edit review does not show the exact same-name call:\n%s", body)
	}
	rec := ui2ReviewedRun(t, s, "pools", url.Values{
		"op": {"edit"}, "name": {"keepme"}, "max_concurrent": {"4"}, "delay_ms": {"250"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("run answered %d: %s", rec.Code, rec.Body.String())
	}
	view := decodePools(t, get(t, s, "/api/pools"), http.StatusOK)
	if len(view.Pools) != 1 || view.Pools[0].Name != "keepme" {
		t.Fatalf("the pool's identity changed on a bounds edit: %+v", view.Pools)
	}
	if view.Pools[0].DelayMs != 250 {
		t.Errorf("the reviewed delay was not saved: %+v", view.Pools[0])
	}
	if view.Pools[0].Throttle == nil || view.Pools[0].Throttle.IncrementMs != 50 {
		t.Errorf("the throttle was reset by an edit that never mentioned it: %+v", view.Pools[0].Throttle)
	}
}

func Test_ui2settings_pool_edit_missing_pool_refused(t *testing.T) {
	s := newTestServer()
	rec := ui2PostSettingsWrite(t, s, "pools", "confirm", url.Values{
		"op": {"edit"}, "name": {"ghost"}, "max_concurrent": {"1"}, "delay_ms": {"0"},
	})
	if !strings.Contains(rec.Body.String(), "no pool named") {
		t.Errorf("editing a pool that does not exist reached the review sheet:\n%s", rec.Body.String())
	}
}

func Test_ui2settings_pool_delete_in_use_review_names_schedules_and_run_surfaces_409(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "bounded", MaxConcurrent: 2, DelayMs: 500})
	armed := do(t, s, http.MethodPost, "/api/schedules", schedule.Schedule{
		Name: "nightly", Kind: scheduleKindCrawl, Enabled: true,
		FirstMs: time.Now().Add(time.Hour).UnixMilli(), IntervalSecs: 24 * 3600,
		Pool:   "bounded",
		Params: json.RawMessage(`{"seeds":["https://example.test/"]}`),
	})
	if armed.Code != http.StatusCreated {
		t.Fatalf("arming the schedule answered %d: %s", armed.Code, armed.Body.String())
	}
	conf := ui2PostSettingsWrite(t, s, "pools", "confirm", url.Values{"op": {"delete"}, "name": {"bounded"}})
	if !strings.Contains(conf.Body.String(), "nightly") {
		t.Errorf("the delete review does not name the schedule that still references the pool:\n%s", conf.Body.String())
	}
	rec := ui2ReviewedRun(t, s, "pools", url.Values{"op": {"delete"}, "name": {"bounded"}})
	if !strings.Contains(rec.Body.String(), "Not saved") || !strings.Contains(rec.Body.String(), "nightly") {
		t.Errorf("the in-use delete did not surface the API refusal naming the schedule:\n%s", rec.Body.String())
	}
	view := decodePools(t, get(t, s, "/api/pools"), http.StatusOK)
	if view.Count != 1 {
		t.Error("the referenced pool was deleted anyway")
	}
}

func Test_ui2settings_pool_delete_happy(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "ephemeral", MaxConcurrent: 1})
	rec := ui2ReviewedRun(t, s, "pools", url.Values{"op": {"delete"}, "name": {"ephemeral"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("run answered %d: %s", rec.Code, rec.Body.String())
	}
	if view := decodePools(t, get(t, s, "/api/pools"), http.StatusOK); view.Count != 0 {
		t.Errorf("the pool survived its reviewed deletion: %+v", view.Pools)
	}
}

// ---- the review gate itself ----------------------------------------------------------------------

func Test_ui2settings_review_token_is_single_use(t *testing.T) {
	s := ui2PassthroughServer(t)
	form := url.Values{"op": {"add"}, "pattern": {"once.example.com"}}
	conf := ui2PostSettingsWrite(t, s, "passthrough", "confirm", form)
	id, token := ui2ReviewFields(t, conf.Body.String())
	if rec := ui2PostSettingsWrite(t, s, "passthrough", "run", url.Values{"review_id": {id}, "token": {token}}); rec.Code != http.StatusOK {
		t.Fatalf("first run answered %d: %s", rec.Code, rec.Body.String())
	}
	rec := ui2PostSettingsWrite(t, s, "passthrough", "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec.Body.String(), "unknown or was already used") {
		t.Errorf("a replayed token did not refuse:\n%s", rec.Body.String())
	}
	if got := get(t, s, "/api/proxy/passthrough"); strings.Count(got.Body.String(), "once.example.com") != 1 {
		t.Errorf("the replay wrote twice: %s", got.Body.String())
	}
}

func Test_ui2settings_review_unknown_id_and_wrong_token_refused(t *testing.T) {
	s := ui2PassthroughServer(t)
	conf := ui2PostSettingsWrite(t, s, "passthrough", "confirm", url.Values{"op": {"add"}, "pattern": {"guard.example.com"}})
	id, _ := ui2ReviewFields(t, conf.Body.String())
	rec := ui2PostSettingsWrite(t, s, "passthrough", "run", url.Values{"review_id": {id}, "token": {"not-the-minted-token"}})
	if !strings.Contains(rec.Body.String(), "does not match") {
		t.Errorf("a wrong token did not refuse:\n%s", rec.Body.String())
	}
	rec = ui2PostSettingsWrite(t, s, "passthrough", "run", url.Values{"review_id": {"no-such-review"}, "token": {"x"}})
	if !strings.Contains(rec.Body.String(), "unknown or was already used") {
		t.Errorf("an unknown review id did not refuse:\n%s", rec.Body.String())
	}
	if got := get(t, s, "/api/proxy/passthrough"); strings.Contains(got.Body.String(), "guard.example.com") {
		t.Error("a refused run still wrote")
	}
}

func Test_ui2settings_review_expired_refused(t *testing.T) {
	s := ui2PassthroughServer(t)
	s.ui2SettingsWriteReviews.Store("stale-id", ui2SettingsReview{
		token: "stale-token", method: http.MethodPost, callURL: "/api/proxy/passthrough",
		body: []byte(`{"pattern":"stale.example.com"}`), expires: time.Now().Add(-time.Minute),
	})
	rec := ui2PostSettingsWrite(t, s, "passthrough", "run", url.Values{"review_id": {"stale-id"}, "token": {"stale-token"}})
	if !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("an expired review did not refuse:\n%s", rec.Body.String())
	}
	if got := get(t, s, "/api/proxy/passthrough"); strings.Contains(got.Body.String(), "stale.example.com") {
		t.Error("an expired review still wrote")
	}
}

// ---- preservation --------------------------------------------------------------------------------

func Test_ui2settings_page_keeps_existing_sections_and_loads_new_ones(t *testing.T) {
	s := newTestServerWithPersist(t)
	rec := get(t, s, "/ui2/settings")
	body := rec.Body.String()
	for _, want := range []string{
		"Project", "Counters", "Triage (LLM second look)", "Network auth", "Server certificates",
		"settings-proxy", "settings-passthrough", "settings-backup", "settings-pools",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the settings page no longer contains %q", want)
		}
	}
}

func Test_ui2settings_fragments_render_on_bare_servers(t *testing.T) {
	s := newTestServer() // no tlsPolicy, no upstreamProxy, no persist
	for area, want := range map[string]string{
		"passthrough": "No TLS policy is attached",
		"proxy":       "No upstream proxy policy is wired",
		"backup":      "no project database",
		"pools":       "Create a pool",
	} {
		rec := ui2GetSettingsWrite(t, s, area)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s fragment on a bare server answered %d without %q:\n%s", area, rec.Code, want, rec.Body.String())
		}
	}
}
