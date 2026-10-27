package crawler

import (
	"context"
	"strings"
	"testing"
)

// burpsy-react-ui-browser-render-unscoped: a render whose page requested something the scope gate
// refused is recorded as incomplete, naming what was refused — not presented as the whole page.
func TestARenderWithScopeRefusalsIsRecordedAsIncomplete(t *testing.T) {
	tg := newTarget(t, map[string]string{
		"/":     `<html><body><a href="/page">page</a></body></html>`,
		"/page": `<html><body><p>app</p></body></html>`,
	})
	h := newHarness()
	cfg := h.config(tg.URL + "/")
	cfg.RenderWithOutcome = func(_ context.Context, targetURL string) (string, RenderOutcome, error) {
		out := RenderOutcome{Settled: true}
		if targetURL == tg.URL+"/page" {
			out.Blocked = []string{"GET http://cdn.other.test/app.js — host out of scope"}
		}
		return `<html><body><p>app</p></body></html>`, out, nil
	}
	rep := run(t, cfg)

	var details []string
	for _, rec := range rep.Skips.Records {
		if rec.Reason == SkipRenderUnavailable && strings.Contains(rec.Detail, "out-of-scope") {
			details = append(details, rec.URL+" "+rec.Detail)
		}
	}
	if len(details) != 1 {
		t.Fatalf("want exactly one scope-refusal record (for /page only), got %v", details)
	}
	if !strings.Contains(details[0], tg.URL+"/page") || !strings.Contains(details[0], "cdn.other.test") {
		t.Errorf("the record does not name the page and what was refused: %q", details[0])
	}
}
