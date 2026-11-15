package web

import (
	"html"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/dominvader"
)

func ui2DomReviewRun(t *testing.T, s *Server, form url.Values) (review, out string) {
	t.Helper()
	review = postUI2Form(t, s, "/ui2/dominvader/review", form).Body.String()
	id, tok := ui2ReviewFields(t, review)
	out = postUI2Form(t, s, "/ui2/dominvader/run", url.Values{"review_id": {id}, "token": {tok}}).Body.String()
	return review, out
}

func TestUI2DomInvaderSaveSettingsThroughReview(t *testing.T) {
	s := newTestServer()
	review, out := ui2DomReviewRun(t, s, url.Values{"op": {"settings"}, "enabled": {"on"}, "canary": {"canaryXYZ"}})
	if !strings.Contains(html.UnescapeString(review), "PUT /api/dominvader\n"+`{"canary":"canaryXYZ","enabled":true}`) {
		t.Fatalf("review lacks the exact PUT: %s", review)
	}
	if !strings.Contains(out, "Settings saved") || s.domInvader.Canary() != "canaryXYZ" || !s.domInvader.Enabled() {
		t.Fatalf("reviewed settings did not land: %s", out[:ui2Min(500, len(out))])
	}
	// Randomize mints a fresh canary into the reviewed body.
	_, _ = ui2DomReviewRun(t, s, url.Values{"op": {"settings"}, "canary": {"x"}, "randomize": {"1"}})
	if c := s.domInvader.Canary(); !strings.HasPrefix(c, "burpsyDI") || len(c) != len("burpsyDI")+12 || s.domInvader.Enabled() {
		t.Errorf("randomized canary = %q enabled=%v", c, s.domInvader.Enabled())
	}
}

func TestUI2DomInvaderRefusesTamperedAndInvalid(t *testing.T) {
	s := newTestServer()
	before := s.domInvader.Canary()
	review := postUI2Form(t, s, "/ui2/dominvader/review", url.Values{"op": {"settings"}, "canary": {"zzz"}}).Body.String()
	id, _ := ui2ReviewFields(t, review)
	out := postUI2Form(t, s, "/ui2/dominvader/run", url.Values{"review_id": {id}, "token": {"forged"}}).Body.String()
	if !strings.Contains(out, "does not match") || s.domInvader.Canary() != before {
		t.Fatalf("a forged token changed the canary: %s", out[:ui2Min(400, len(out))])
	}
	// A discovery review cannot be spent by the DOM auditor's run step.
	s.externalTools = map[string]string{"ffuf": "/bin/true"}
	seedUI2DiscoveryRun(s)
	disc := postUI2Form(t, s, "/ui2/discovery/review", url.Values{"op": {"browser"}, "task": {"4242"}, "idx": {"0"}}).Body.String()
	did, dtok := ui2ReviewFields(t, disc)
	if cross := postUI2Form(t, s, "/ui2/dominvader/run", url.Values{"review_id": {did}, "token": {dtok}}).Body.String(); !strings.Contains(cross, "unknown or was already used") {
		t.Error("a review from another page was spent here")
	}
	// The domain's own plan validation refuses before anything is held.
	bad := postUI2Form(t, s, "/ui2/dominvader/review", url.Values{"op": {"plan"}, "pollution_enabled": {"on"}, "target": {"https://p.test/"}, "properties": {"__proto__"}, "query": {"on"}}).Body.String()
	if !strings.Contains(bad, "Not reviewed") || strings.Contains(bad, "review_id") {
		t.Errorf("an invalid probe plan was held for review: %s", bad)
	}
}

func TestUI2DomInvaderPlanScanAndClear(t *testing.T) {
	s := newTestServer()
	// Disabled plan: no scope needed; the reviewed body is the whole plan.
	review, out := ui2DomReviewRun(t, s, url.Values{"op": {"plan"}, "target": {"https://p.test/"}, "properties": {"polluted, isAdmin"}, "hash": {"on"}})
	if !strings.Contains(html.UnescapeString(review), `"properties":["polluted","isAdmin"]`) || !strings.Contains(out, "Probe plan saved") {
		t.Fatalf("plan save: %s", out[:ui2Min(400, len(out))])
	}
	if p := s.domInvader.Pollution(); !p.Hash || p.Target != "https://p.test/" {
		t.Errorf("plan not stored: %+v", p)
	}
	// Scan with the auditor off: the API's own refusal is shown.
	if _, out := ui2DomReviewRun(t, s, url.Values{"op": {"scan"}}); !strings.Contains(out, "Not run: turn on the DOM auditor") {
		t.Errorf("scan refusal not surfaced: %s", out[:ui2Min(400, len(out))])
	}
	// Flows table escapes the attacker-controlled excerpt; clear empties it.
	s.domInvader.Add(&dominvader.Hit{Kind: "sink", Sink: "innerHTML", Sources: []string{"location.hash"}, Excerpt: `<img src=x onerror=alert(1)>`, Frame: "top"})
	page := getUI2(t, s, "/ui2/dominvader").Body.String()
	if !strings.Contains(page, "&lt;img src=x onerror=alert(1)&gt;") || strings.Contains(page, "<img src=x") || !strings.Contains(page, "location.hash") {
		t.Fatal("flow excerpt not rendered escaped")
	}
	if _, out := ui2DomReviewRun(t, s, url.Values{"op": {"clear"}}); !strings.Contains(out, "Reported flows cleared") || len(s.domInvader.Hits()) != 0 {
		t.Errorf("clear did not empty the flows: %s", out[:ui2Min(400, len(out))])
	}
}
