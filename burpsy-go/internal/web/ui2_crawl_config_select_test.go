package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The crawl launch form offers only the configurations a crawl can actually run under. The
// shipped presets are transcribed here as audit-half keys only (scanner.BuiltInConfig), so
// resolveCrawlConfig must refuse them; a form that offered them anyway taught the operator a
// control that always failed. Saved library configurations are full Burp documents and carry
// their crawler halves, so they are listed. The audit launch keeps both.
func TestUI2CrawlFormOffersOnlyCrawlResolvableConfigurations(t *testing.T) {
	s, _ := newTestServerWithDB(t)
	if _, err := s.persist.SaveScanConfigLibrary("engagement tuning",
		`{"crawler":{"crawl_optimization":{"max_link_depth":3}}}`); err != nil {
		t.Fatalf("save configuration: %v", err)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/scanner", nil))
	page := rec.Body.String()
	crawlAt := strings.Index(page, "Launch a crawl")
	if crawlAt < 0 {
		t.Fatalf("scanner page has no crawl launch section")
	}
	auditForm := page[:crawlAt]
	crawlForm := page[crawlAt:]
	if !strings.Contains(auditForm, `value="Crawl and Audit - Balanced"`) {
		t.Errorf("audit launch lost a shipped preset it can run under")
	}
	if !strings.Contains(auditForm, `value="engagement tuning"`) {
		t.Errorf("audit launch lost a saved configuration")
	}
	if strings.Contains(crawlForm, `value="Crawl and Audit - Balanced"`) {
		t.Errorf("crawl launch still offers a shipped preset resolveCrawlConfig must refuse")
	}
	if !strings.Contains(crawlForm, `value="engagement tuning"`) {
		t.Errorf("crawl launch does not offer a saved configuration it can resolve")
	}
	if !strings.Contains(crawlForm, "server default") {
		t.Errorf("crawl launch lost the server default")
	}
	if !strings.Contains(crawlForm, "shipped presets configure audits") {
		t.Errorf("crawl launch does not say why the shipped presets are absent")
	}
}

// A crawl asked for a shipped preset is refused naming the configurations a crawl can run under
// - the saved library - and not the other shipped presets, which a crawl cannot use either.
func TestCrawlRefusesAShippedPresetNamingOnlyCrawlResolvableConfigurations(t *testing.T) {
	s, _ := newTestServerWithDB(t)
	if _, err := s.persist.SaveScanConfigLibrary("engagement tuning",
		`{"crawler":{"crawl_optimization":{"max_link_depth":3}}}`); err != nil {
		t.Fatalf("save configuration: %v", err)
	}
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":  []string{"http://target.example/"},
		"config": "Crawl and Audit - Balanced",
	})
	if rec.Code == http.StatusAccepted || rec.Code == http.StatusOK {
		t.Fatalf("a crawl under a shipped preset was accepted: %s", rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "no built-in scan configuration is named Crawl and Audit - Balanced") {
		t.Errorf("refusal does not name the asked-for configuration: %s", body)
	}
	if !strings.Contains(body, "engagement tuning") {
		t.Errorf("refusal does not list the saved configuration a crawl can use: %s", body)
	}
	if strings.Contains(body, "Crawl and Audit - Lightweight") {
		t.Errorf("refusal lists another shipped preset a crawl cannot use either: %s", body)
	}
}
