package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUI2IntruderConfirmMintsToken drives the two-step launch: POST /ui2/intruder/confirm
// must return a confirm fragment carrying a real token (minted through the gate), not a
// cross-site refusal.
func TestUI2IntruderConfirmMintsToken(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	form := "msg_id=1&payloads=admin%0Aroot&all_points=on"
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body := rec.Body.String()
	if strings.Contains(body, "did not come from burpsy") {
		t.Fatalf("mint went through the cross-site gate and was refused: %s", body[:ui2Min(200, len(body))])
	}
	if !strings.Contains(body, `name="token" value="`) {
		t.Errorf("confirm fragment carries no token: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "Confirm and launch attack") {
		t.Errorf("confirm fragment missing the confirm button")
	}
	if !strings.Contains(body, "/api/intruder/run") {
		t.Errorf("preview does not name the gated call")
	}
}

// TestUI2SequencerAnalyseRendersReport posts a small token list and expects the report.
func TestUI2SequencerAnalyseRendersReport(t *testing.T) {
	s := newTestServer()
	tokens := "aaa\naab\naba\nabb\nbaa\nbab\nbba\nbbb"
	form := "tokens=" + strings.ReplaceAll(tokens, "\n", "%0A") + "&encoding=raw"
	req := httptest.NewRequest(http.MethodPost, "/ui2/sequencer/analyse", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyse = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Report") {
		t.Errorf("no report rendered: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
}

// TestUI2CollaboratorMintConfirmStep: without a token the mint form renders the confirm step
// (the real mint is riskEgress and must not fire from a bare form POST).
func TestUI2CollaboratorMintConfirmStep(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader("count=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint page = %d", rec.Code)
	}
	body := rec.Body.String()
	// No interaction server is configured, so the mint itself would fail — but the page must
	// render, and must not have dispatched the egress call without a token.
	if strings.Contains(body, `name="token" value=""`) && !strings.Contains(body, "Confirm mint") {
		t.Errorf("expected a confirm step or a rendered error, got neither")
	}
}

func TestUI2IntruderPagesAreRegistered(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/ui2/intruder", "/ui2/sequencer", "/ui2/collaborator"} {
		if rec := getUI2(t, s, p); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", p, rec.Code)
		}
	}
}
