package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

func ui2ScanPost(t *testing.T, s *Server, path, form string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func ui2ScanGet(t *testing.T, s *Server, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func ui2ScanHidden(body, name string) string {
	marker := `name="` + name + `" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	return html.UnescapeString(rest[:strings.IndexByte(rest, '"')])
}

// ui2ScanReviewAndRun posts one op to the review step and confirms it, returning the run's page.
func ui2ScanReviewAndRun(t *testing.T, s *Server, form string) (review, run string) {
	t.Helper()
	review = ui2ScanPost(t, s, "/ui2/scanner/review", form)
	id, token := ui2ScanHidden(review, "review_id"), ui2ScanHidden(review, "token")
	if id == "" || token == "" {
		t.Fatalf("review minted nothing: %s", review)
	}
	run = ui2ScanPost(t, s, "/ui2/scanner/review-run", "review_id="+id+"&token="+token+"&page="+ui2ScanHidden(review, "page"))
	return review, run
}

func ui2ScanFullServer(t *testing.T) *Server {
	t.Helper()
	s := libraryServer(t)
	return s.WithScanner(scanner.NewActiveScanner(s.store, zap.NewNop())).
		WithPassiveScanner(scanner.NewPassiveScanner(s.store, zap.NewNop())).
		WithLiveAudit(NewLiveAuditState())
}

func TestUI2ScannerConfigPageRendersEverySection(t *testing.T) {
	s := ui2ScanFullServer(t)
	body := ui2ScanGet(t, s, "/ui2/scanner/config")
	for _, want := range []string{"Live active audit", `id="livemetrics"`, "Secret detection", "Audit checks",
		`name="check_subdomain_takeover"`, `name="login_rate_limit_attempts"`, `name="only_rows"`, `name="xr0_root_url"`,
		"only-rows-catalogue", "Passive check coverage"} {
		if !strings.Contains(body, want) {
			t.Errorf("config page lacks %q", want)
		}
	}
	for _, key := range ui2ScanConfigBoolKeys {
		if !strings.Contains(body, `name="`+key+`"`) {
			t.Errorf("config page offers no switch for %s", key)
		}
	}
}

func TestUI2ScannerLiveFragment(t *testing.T) {
	s := ui2ScanFullServer(t)
	body := ui2ScanGet(t, s, "/ui2/scanner/live")
	for _, want := range []string{`id="livemetrics"`, "Exchanges swept", "Gated (not this source)", "Second chance", "Ledger-refused"} {
		if !strings.Contains(body, want) {
			t.Errorf("live fragment lacks %q: %s", want, body)
		}
	}
}

// Two families, a knob, the check inputs and an XSS route reviewed together: the sheet shows the
// FULL bound body (well past the old 200-byte preview), and the run applies exactly it.
func TestUI2ScanConfigReviewShowsFullBodyAndApplies(t *testing.T) {
	s := newTestServerWithScanner(t)
	form := ui2ScanConfigCurrentForm(t, s, "check_xss") + "&check_idor=on&max_concurrency=7" +
		"&reset_test_identities=" + url.QueryEscape("alice@test\nbob@test") +
		"&reset_mailbox_url=" + url.QueryEscape("https://mail.test/inbox?to={identity}") +
		"&only_rows=&only_rows_add=" + url.QueryEscape("SQL injection") +
		"&xr_count=1&xr0_root_url=" + url.QueryEscape("https://app.test/") +
		"&xr0_master_selector=nav&xr0_master_text=Search&xr0_input_selector=" + url.QueryEscape("#q") + "&xr0_sink=innerHTML"
	token, patch, body := ui2ScanConfigConfirmToken(t, s, form)
	if token == "" {
		t.Fatalf("no token: %s", body)
	}
	if len(patch) <= 200 {
		t.Fatalf("patch too short to exercise the full-body review: %d", len(patch))
	}
	pre := body[strings.Index(body, "<pre"):]
	pre = html.UnescapeString(pre[:strings.Index(pre, "</pre>")])
	for _, want := range []string{`"xss_browser_targets"`, `"input_selector": "#q"`, `"reset_mailbox_url"`, `"only_rows"`, `"max_concurrency": 7`} {
		if !strings.Contains(pre, want) {
			t.Errorf("review projection lacks %s: %s", want, pre)
		}
	}
	if strings.Contains(pre, "…") {
		t.Errorf("review projection is truncated")
	}
	run := ui2ScanConfigRun(t, s, "token="+token+"&patch="+url.QueryEscape(patch))
	if !strings.Contains(run, "Configuration applied") {
		t.Fatalf("run refused: %s", run)
	}
	view := s.ui2ScanConfigView()
	if view["check_xss"] != false || view["check_idor"] != true || view["max_concurrency"] != float64(7) {
		t.Errorf("switches/knob not applied: xss=%v idor=%v mc=%v", view["check_xss"], view["check_idor"], view["max_concurrency"])
	}
	if got := ui2StringList(view["only_rows"]); len(got) != 1 || got[0] != "SQL injection" {
		t.Errorf("only_rows = %v", got)
	}
	if routes := ui2AnyMaps(view["xss_browser_targets"]); len(routes) != 1 || routes[0]["input_selector"] != "#q" {
		t.Errorf("xss routes = %v", routes)
	}
}

func TestUI2ScanConfigReviewRefusesUnknownRowAndBadRoute(t *testing.T) {
	s := newTestServerWithScanner(t)
	base := ui2ScanConfigCurrentForm(t, s, "")
	token, _, body := ui2ScanConfigConfirmToken(t, s, base+"&only_rows=No+such+row")
	if token != "" || !strings.Contains(body, "unknown issue row") {
		t.Errorf("an unknown issue row was not refused at review: %s", body)
	}
	token, _, body = ui2ScanConfigConfirmToken(t, s, base+"&xr_count=1&xr0_root_url=notaurl&xr0_master_selector=a&xr0_master_text=b&xr0_input_selector=c")
	if token != "" || !strings.Contains(body, "root_url") {
		t.Errorf("a bad route was not refused at review: %s", body)
	}
}

// The live switch is riskAttack: its review carries a gate token, the run turns the sweep on, and
// a replayed review is refused.
func TestUI2ScannerLiveReviewEnablesAndRefusesReplay(t *testing.T) {
	s := ui2ScanFullServer(t)
	review, run := ui2ScanReviewAndRun(t, s, "op=live-enable")
	if !strings.Contains(review, "minted a one-time token") || !strings.Contains(html.UnescapeString(review), `"enabled": true`) {
		t.Errorf("live review is not gated or lacks the body: %s", review)
	}
	if !strings.Contains(run, "Live active audit is on.") || !s.liveAudit.IsEnabled() {
		t.Fatalf("live audit not enabled: %s", run)
	}
	again := ui2ScanPost(t, s, "/ui2/scanner/review-run", "review_id="+ui2ScanHidden(review, "review_id")+"&token="+ui2ScanHidden(review, "token")+"&page=config")
	if !strings.Contains(again, "unknown or was already used") {
		t.Errorf("a replayed review was not refused: %s", again)
	}
	if body := ui2ScanPost(t, s, "/ui2/scanner/review", "op=live-source&traffic_source=everything"); !strings.Contains(html.UnescapeString(body), `"traffic_source": "everything"`) {
		t.Errorf("source review lacks its body: %s", body)
	}
}

func TestUI2ScannerSecretsReviewAndTokenMismatch(t *testing.T) {
	s := ui2ScanFullServer(t)
	review := ui2ScanPost(t, s, "/ui2/scanner/review", "op=secrets-on")
	bad := ui2ScanPost(t, s, "/ui2/scanner/review-run", "review_id="+ui2ScanHidden(review, "review_id")+"&token=00&page=config")
	if !strings.Contains(bad, "does not match") || s.passiveScanner.SecretDetection() {
		t.Fatalf("a mismatched token was not refused: %s", bad)
	}
	_, run := ui2ScanReviewAndRun(t, s, "op=secrets-on")
	if !strings.Contains(run, "Secret detection is on.") || !s.passiveScanner.SecretDetection() {
		t.Errorf("secret detection not switched on: %s", run)
	}
}

func TestUI2ScannerLibraryPageAndDetail(t *testing.T) {
	s := ui2ScanFullServer(t)
	shipped := scanner.BuiltInConfigs[0].Name
	body := ui2ScanGet(t, s, "/ui2/scanner/library")
	if !strings.Contains(body, "Scan configuration library") || !strings.Contains(body, shipped) {
		t.Fatalf("library page lacks the shipped configurations: %s", body)
	}
	detail := ui2ScanGet(t, s, "/ui2/scanner/library?open="+url.QueryEscape(shipped)+"&q=sql")
	if !strings.Contains(detail, "Viewing "+html.EscapeString(shipped)) || !strings.Contains(detail, "disabled") || !strings.Contains(detail, "Run overrides") {
		t.Errorf("shipped detail is not read-only: %s", detail)
	}
}

// New, edit, rename and delete through the review; a shipped name is refused before any review.
func TestUI2ScannerLibraryLifecycle(t *testing.T) {
	s := ui2ScanFullServer(t)
	if body := ui2ScanPost(t, s, "/ui2/scanner/review", "op=lib-new&name="+url.QueryEscape(scanner.BuiltInConfigs[0].Name)); !strings.Contains(body, "read-only") || strings.Contains(body, "review_id") {
		t.Errorf("a shipped name was not refused: %s", body)
	}
	_, run := ui2ScanReviewAndRun(t, s, "op=lib-new&name=mine")
	if _, ok := s.savedScanConfig("mine"); !ok {
		t.Fatalf("new configuration not saved: %s", run)
	}
	row := s.ui2IssueCatalogue()[0]
	idx := strconv.FormatUint(uint64(row.TypeIndex), 10)
	form := "op=lib-edit&name=mine&shown=" + idx + "&skip_all=csrf"
	for _, m := range row.DetectionMethods {
		form += "&m_" + idx + "=" + url.QueryEscape(m)
	}
	review, run := ui2ScanReviewAndRun(t, s, form)
	if !strings.Contains(review, "disabled_issue_types") || !strings.Contains(run, "Saved mine.") {
		t.Fatalf("edit not reviewed/applied: %s / %s", review, run)
	}
	cfg, _ := s.savedScanConfig("mine")
	if len(cfg.DisabledIssueTypes) != 1 || cfg.DisabledIssueTypes[0] != row.TypeIndex || len(cfg.SkipAllTestsForParameters) != 1 {
		t.Errorf("edit not stored: disabled=%v skip=%v", cfg.DisabledIssueTypes, cfg.SkipAllTestsForParameters)
	}
	ui2ScanReviewAndRun(t, s, "op=lib-rename&from=mine&name=ours")
	if _, ok := s.savedScanConfig("ours"); !ok {
		t.Fatalf("rename did not land")
	}
	ui2ScanReviewAndRun(t, s, "op=lib-delete&name=ours")
	if _, ok := s.savedScanConfig("ours"); ok {
		t.Errorf("delete did not land")
	}
}

func TestUI2ScannerAuditResultBreakdown(t *testing.T) {
	v := ui2AuditResultView(map[string]any{
		"exchange_id": 3, "summary": "complete", "config": map[string]any{"time_budget_ms": 1800000},
		"outcome":      map[string]any{"state": "complete", "ran": 4},
		"dispositions": []any{map[string]any{"disposition": "ran", "reason": "dispatched", "count": 4}},
	})
	body := string(ui2Exec("scanner_audit_result.html", v))
	for _, want := range []string{"exchange #3", "30m0s", "dispatched", "4 ran"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit result lacks %q: %s", want, body)
		}
	}
}
