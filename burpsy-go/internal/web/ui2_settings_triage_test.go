package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/persist"
)

// The whole file works with one synthetic key value. It is distinctive enough that any
// appearance in any rendered response is a leak the pins below catch, and it is fake enough
// that committing it is safe.
const ui2TestTriageKey = "sk-test-SYNTHETIC-fixture-0000000000000000"

func ui2TriageForm(v url.Values) url.Values {
	if v == nil {
		v = url.Values{}
	}
	if v.Get("base_url") == "" {
		v.Set("base_url", "https://llm.example/v1")
	}
	if v.Get("model") == "" {
		v.Set("model", "fixture-model")
	}
	return v
}

func ui2PostTriage(t *testing.T, s *Server, action string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui2/settings/triage/"+action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// responseMustNotLeakKey asserts the synthetic key appears nowhere in the response: not the
// body, not any header value. The key's whole point is that the UI never renders it.
func responseMustNotLeakKey(t *testing.T, where string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(rec.Body.String(), ui2TestTriageKey) {
		t.Errorf("%s: response body contains the API key", where)
	}
	for name, vals := range rec.Header() {
		for _, v := range vals {
			if strings.Contains(v, ui2TestTriageKey) {
				t.Errorf("%s: response header %s contains the API key", where, name)
			}
		}
	}
}

func ui2ReviewFields(t *testing.T, body string) (id, token string) {
	t.Helper()
	id = ui2HiddenValue(body, "review_id")
	token = ui2HiddenValue(body, "token")
	if id == "" || token == "" {
		t.Fatalf("review sheet lacks review_id/token hidden inputs: %s", body[:ui2Min(400, len(body))])
	}
	return id, token
}

func ui2HiddenValue(body, name string) string {
	needle := `name="` + name + `" value="`
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	rest := body[i+len(needle):]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return ""
}

// The happy path with a key: confirm renders a redacted review that names the destination and
// the replacement; run writes exactly what was reviewed; neither step ever shows the key.
func TestUI2SettingsTriageFlow(t *testing.T) {
	s := newTestServerWithPersist(t)
	form := ui2TriageForm(nil)
	form.Set("enabled", "1")
	form.Set("api_key", ui2TestTriageKey)
	rec := ui2PostTriage(t, s, "confirm", form)
	responseMustNotLeakKey(t, "confirm", rec)
	body := rec.Body.String()
	for _, want := range []string{"Review before saving", "hidden", "REPLACE the stored key", "https://llm.example/v1", "Confirm and save", "PUT /api/settings/triage"} {
		if !strings.Contains(body, want) {
			t.Errorf("review sheet lacks %q: %s", want, body[:ui2Min(400, len(body))])
		}
	}
	id, token := ui2ReviewFields(t, body)

	runForm := url.Values{"review_id": {id}, "token": {token}}
	rec2 := ui2PostTriage(t, s, "run", runForm)
	responseMustNotLeakKey(t, "run", rec2)
	if strings.Contains(rec2.Body.String(), "Not saved") {
		t.Fatalf("run refused the reviewed call: %s", rec2.Body.String()[:ui2Min(400, rec2.Body.Len())])
	}
	stored, err := s.persist.LoadTriageSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Enabled || stored.BaseURL != "https://llm.example/v1" || stored.Model != "fixture-model" || stored.APIKey != ui2TestTriageKey {
		t.Errorf("stored settings are not what was reviewed: %+v", stored)
	}
}

// Replay: the run step is single-use - a second run with the same id/token must refuse.
func TestUI2SettingsTriageRunIsSingleUse(t *testing.T) {
	s := newTestServerWithPersist(t)
	form := ui2TriageForm(nil)
	form.Set("api_key", ui2TestTriageKey)
	rec := ui2PostTriage(t, s, "confirm", form)
	id, token := ui2ReviewFields(t, rec.Body.String())
	runForm := url.Values{"review_id": {id}, "token": {token}}
	if rec2 := ui2PostTriage(t, s, "run", runForm); strings.Contains(rec2.Body.String(), "Not saved") {
		t.Fatal("first run refused")
	}
	rec3 := ui2PostTriage(t, s, "run", runForm)
	responseMustNotLeakKey(t, "replay", rec3)
	if !strings.Contains(rec3.Body.String(), "unknown or was already used") {
		t.Errorf("replay did not refuse: %s", rec3.Body.String()[:ui2Min(300, rec3.Body.Len())])
	}
}

// Token mismatch: a run carrying the right id with the wrong token refuses, and the entry is
// burned with the attempt (no probing the same review twice).
func TestUI2SettingsTriageRunTokenMismatchBurns(t *testing.T) {
	s := newTestServerWithPersist(t)
	form := ui2TriageForm(nil)
	form.Set("api_key", ui2TestTriageKey)
	rec := ui2PostTriage(t, s, "confirm", form)
	id, token := ui2ReviewFields(t, rec.Body.String())
	bad := url.Values{"review_id": {id}, "token": {"deadbeef" + token}}
	rec2 := ui2PostTriage(t, s, "run", bad)
	responseMustNotLeakKey(t, "token mismatch", rec2)
	if !strings.Contains(rec2.Body.String(), "does not match") {
		t.Errorf("token mismatch did not refuse: %s", rec2.Body.String()[:ui2Min(300, rec2.Body.Len())])
	}
	rec3 := ui2PostTriage(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	if !strings.Contains(rec3.Body.String(), "unknown or was already used") {
		t.Errorf("entry survived a failed token check - replayable: %s", rec3.Body.String()[:ui2Min(300, rec3.Body.Len())])
	}
}

// Expiry: an entry older than ConfirmTTL refuses even with the right token.
func TestUI2SettingsTriageRunExpired(t *testing.T) {
	s := newTestServerWithPersist(t)
	form := ui2TriageForm(nil)
	form.Set("api_key", ui2TestTriageKey)
	rec := ui2PostTriage(t, s, "confirm", form)
	id, token := ui2ReviewFields(t, rec.Body.String())
	// Age the held entry past its TTL, as if the operator read the sheet too slowly.
	if v, ok := s.ui2TriageReviews.Load(id); ok {
		e := v.(ui2TriageReview)
		e.expires = time.Now().Add(-time.Minute)
		s.ui2TriageReviews.Store(id, e)
	}
	rec2 := ui2PostTriage(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	responseMustNotLeakKey(t, "expired", rec2)
	if !strings.Contains(rec2.Body.String(), "expired") {
		t.Errorf("expired review did not refuse: %s", rec2.Body.String()[:ui2Min(300, rec2.Body.Len())])
	}
}

// Capacity: the map is bounded at 8; the 9th confirm refuses and says so instead of silently
// dropping somebody's review.
func TestUI2SettingsTriageReviewCap(t *testing.T) {
	s := newTestServerWithPersist(t)
	// Literal pin: the reviewer approved a bound of exactly 8. If the constant drifts, this
	// fails even though the capacity behaviour below would still pass at the new value.
	if ui2TriageReviewCap != 8 {
		t.Fatalf("ui2TriageReviewCap = %d, the approved bound is 8", ui2TriageReviewCap)
	}
	form := ui2TriageForm(nil)
	form.Set("api_key", ui2TestTriageKey)
	for i := 0; i < ui2TriageReviewCap; i++ {
		if rec := ui2PostTriage(t, s, "confirm", form); strings.Contains(rec.Body.String(), "Not saved") {
			t.Fatalf("confirm %d refused before the cap: %s", i, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
		}
	}
	rec := ui2PostTriage(t, s, "confirm", form)
	responseMustNotLeakKey(t, "cap refusal", rec)
	if !strings.Contains(rec.Body.String(), "too many reviews") {
		t.Errorf("9th confirm was not refused by the cap: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
}

// Preserve-same: blank key + unchanged base URL needs no acknowledgement; the sheet says the
// stored key stays pointed at the SAME URL.
func TestUI2SettingsTriagePreserveSameURL(t *testing.T) {
	s := newTestServerWithPersist(t)
	if err := s.persist.SaveTriageSettings(persist.TriageSettings{Enabled: true, BaseURL: "https://llm.example/v1", Model: "old", APIKey: "stored-key"}); err != nil {
		t.Fatal(err)
	}
	form := ui2TriageForm(nil)
	form.Set("enabled", "1")
	form.Set("model", "new-model")
	rec := ui2PostTriage(t, s, "confirm", form)
	body := rec.Body.String()
	if strings.Contains(body, "Not saved") {
		t.Fatalf("preserve-same refused without a key: %s", body[:ui2Min(400, len(body))])
	}
	if !strings.Contains(body, "SAME base URL") {
		t.Errorf("sheet does not state the preserve-same destination: %s", body[:ui2Min(400, len(body))])
	}
	id, token := ui2ReviewFields(t, body)
	if rec2 := ui2PostTriage(t, s, "run", url.Values{"review_id": {id}, "token": {token}}); strings.Contains(rec2.Body.String(), "Not saved") {
		t.Fatalf("run refused: %s", rec2.Body.String()[:ui2Min(300, rec2.Body.Len())])
	}
	stored, _ := s.persist.LoadTriageSettings()
	if stored.APIKey != "stored-key" || stored.Model != "new-model" {
		t.Errorf("preserve-same wrote the wrong record: %+v", stored)
	}
}

// Preserve-changed: blank key + changed base URL is a credential transfer. Without the
// acknowledgement the confirm refuses BEFORE minting; with it, the sheet carries the transfer
// warning naming both destinations.
func TestUI2SettingsTriagePreserveChangedNeedsAck(t *testing.T) {
	s := newTestServerWithPersist(t)
	if err := s.persist.SaveTriageSettings(persist.TriageSettings{Enabled: true, BaseURL: "https://old.example/v1", Model: "m", APIKey: "stored-key"}); err != nil {
		t.Fatal(err)
	}
	form := ui2TriageForm(nil)
	form.Set("base_url", "https://new.example/v1")
	rec := ui2PostTriage(t, s, "confirm", form)
	body := rec.Body.String()
	if !strings.Contains(body, "stored key would be sent to the new URL") {
		t.Errorf("preserve-changed minted without the acknowledgement: %s", body[:ui2Min(400, len(body))])
	}
	if ui2HiddenValue(body, "token") != "" {
		t.Errorf("a token was minted for an unacknowledged key transfer")
	}
	form.Set("allow_key_forward", "1")
	rec2 := ui2PostTriage(t, s, "confirm", form)
	body2 := rec2.Body.String()
	if strings.Contains(body2, "Not saved") {
		t.Fatalf("acknowledged preserve-changed refused: %s", body2[:ui2Min(400, len(body2))])
	}
	for _, want := range []string{"CHANGED", "https://new.example/v1", "https://old.example/v1", "acknowledged this transfer"} {
		if !strings.Contains(body2, want) {
			t.Errorf("transfer warning lacks %q: %s", want, body2[:ui2Min(400, len(body2))])
		}
	}
}

// Secret-bearing or fragment base URLs are rejected with errors that name the PART, never its
// value: the userinfo password and the query secret must not appear in the refusal.
func TestUI2SettingsTriageRejectsSecretBearingBaseURL(t *testing.T) {
	s := newTestServer()
	cases := []struct {
		name    string
		baseURL string
		secret  string
	}{
		{"userinfo", "https://user:p4ssw0rd-value@llm.example/v1", "p4ssw0rd-value"},
		{"query", "https://llm.example/v1?key=qu3ry-s3cret-value", "qu3ry-s3cret-value"},
		{"fragment", "https://llm.example/v1#fr4gm3nt-value", "fr4gm3nt-value"},
		{"no scheme", "llm.example/v1", ""},
		{"bad scheme", "ftp://llm.example/v1", ""},
		{"remote http", "http://llm.example/v1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := ui2TriageForm(nil)
			form.Set("base_url", tc.baseURL)
			form.Set("api_key", ui2TestTriageKey)
			rec := ui2PostTriage(t, s, "confirm", form)
			body := rec.Body.String()
			if !strings.Contains(body, "Not saved") {
				t.Errorf("base URL %q was accepted", tc.baseURL)
			}
			if tc.secret != "" && strings.Contains(body, tc.secret) {
				t.Errorf("refusal echoed the secret part of %q", tc.baseURL)
			}
			if ui2HiddenValue(body, "token") != "" {
				t.Errorf("a token was minted for a rejected base URL")
			}
		})
	}
}

// The client-side half of key hygiene: the live-refresh dirty capture skips password fields,
// so a typed key cannot ride a swap into page state or repopulate a different sheet.
func TestUI2DirtyCaptureSkipsPasswordFields(t *testing.T) {
	s := newTestServerWithPersist(t)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	js := rec.Body.String()
	if !strings.Contains(js, "t === 'password'") {
		t.Errorf("liveDirtyFields does not skip password inputs")
	}
	// And the settings page's key field really is a password input the exclusion applies to.
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ui2/settings", nil))
	page := rec2.Body.String()
	if !strings.Contains(page, `type="password" name="api_key"`) {
		t.Errorf("settings triage form lacks the password key field")
	}
	if strings.Contains(page, ui2TestTriageKey) {
		t.Errorf("settings page renders an API key value")
	}
	// The key field is never prefilled: value attribute stays empty even when a key is stored.
	if err := s.persist.SaveTriageSettings(persist.TriageSettings{Enabled: true, BaseURL: "https://llm.example/v1", Model: "m", APIKey: ui2TestTriageKey}); err != nil {
		t.Fatal(err)
	}
	rec3 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/ui2/settings", nil))
	page3 := rec3.Body.String()
	if strings.Contains(page3, ui2TestTriageKey) {
		t.Errorf("settings page with a stored key renders the key")
	}
	if !strings.Contains(page3, "leave blank to keep the stored key") {
		t.Errorf("configured settings page lacks the keep-stored-key hint")
	}
}

// The sticky-header scroll guard: a short sheet swapped in after a mid-page submit must not
// stay hidden behind the header (film-caught on the triage refusal). Live refreshes are
// excluded - they preserve the operator's scroll.
func TestUI2ShortSheetScrollsOutFromUnderHeader(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui2/app.js", nil))
	js := rec.Body.String()
	for _, want := range []string{"window.scrollTo(0, 0)", "headEl.getBoundingClientRect().bottom", "rowsEl.offsetHeight + headBottom < window.innerHeight", "if (!tag && window.scrollY > 0)"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks the short-sheet scroll guard piece %q", want)
		}
	}
	// The sticky element the guard measures against really is the console header.
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ui2/settings", nil))
	if !strings.Contains(rec2.Body.String(), "position:sticky") {
		t.Errorf("console header is not sticky - the guard's premise changed")
	}
}

// The ui2 review route is the console's visible confirmation, not an unattended-caller API:
// it must NOT sit behind the gate it drives. This pins the live catch - a riskCredential
// manifest entry made the gate answer the browser's confirm POST with a 428 mint challenge,
// which unit tests through s.mux never see because the gate wraps only s.guarded.
func TestUI2SettingsTriageRouteIsNotGateCovered(t *testing.T) {
	s := newTestServerWithPersist(t)
	form := ui2TriageForm(nil)
	form.Set("api_key", ui2TestTriageKey)
	req := httptest.NewRequest(http.MethodPost, "/ui2/settings/triage/confirm", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := httptest.NewRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code == http.StatusPreconditionRequired {
		t.Fatalf("ui2 triage review route is gate-covered (428): %s", rec.Body.String()[:200])
	}
	responseMustNotLeakKey(t, "guarded confirm", rec)
	if !strings.Contains(rec.Body.String(), "Review before saving") {
		t.Errorf("guarded confirm did not render the review sheet: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
}

// Fresh configuration, blank key: there is nothing to transfer, so the confirm must NOT
// demand the acknowledgement and the review must NOT talk about a stored key - it says
// plainly that no key is stored and nothing will be sent (reviewer catch on 751447d).
func TestUI2SettingsTriageFreshBlankKeyClaimsNoTransfer(t *testing.T) {
	s := newTestServerWithPersist(t)
	form := ui2TriageForm(nil)
	form.Set("enabled", "1")
	rec := ui2PostTriage(t, s, "confirm", form)
	body := rec.Body.String()
	if strings.Contains(body, "stored key would be sent") || strings.Contains(body, "acknowledged this transfer") {
		t.Errorf("fresh blank-key confirm claims a stored-key transfer: %s", body[:ui2Min(400, len(body))])
	}
	if strings.Contains(body, "Not saved") {
		t.Fatalf("fresh blank-key confirm refused without the ack: %s", body[:ui2Min(400, len(body))])
	}
	if !strings.Contains(body, "none is stored") {
		t.Errorf("review does not state that no key is stored: %s", body[:ui2Min(400, len(body))])
	}
	id, token := ui2ReviewFields(t, body)
	if rec2 := ui2PostTriage(t, s, "run", url.Values{"review_id": {id}, "token": {token}}); strings.Contains(rec2.Body.String(), "Not saved") {
		t.Fatalf("run refused: %s", rec2.Body.String()[:ui2Min(300, rec2.Body.Len())])
	}
	stored, _ := s.persist.LoadTriageSettings()
	if stored.APIKey != "" || !stored.Enabled {
		t.Errorf("saved config wrong: %+v", stored)
	}
}

// The cleartext guard's other side: loopback http IS accepted here so synthetic fixtures can
// run the flow locally - the refusal is about remote destinations, not the scheme alone.
func TestUI2SettingsTriageAllowsLoopbackHTTP(t *testing.T) {
	s := newTestServerWithPersist(t)
	for _, baseURL := range []string{"http://127.0.0.1:18107/v1", "http://localhost:18107/v1", "http://[::1]:18107/v1"} {
		form := ui2TriageForm(nil)
		form.Set("base_url", baseURL)
		form.Set("api_key", ui2TestTriageKey)
		rec := ui2PostTriage(t, s, "confirm", form)
		body := rec.Body.String()
		if strings.Contains(body, "Not saved") {
			t.Errorf("loopback base URL %q refused: %s", baseURL, body[:ui2Min(200, len(body))])
		}
	}
}

// The run dispatch goes through the real gate: a run whose held body was tampered with after
// mint (as only a bug or a rewrite would) must hit the gate's 428, not write.
func TestUI2SettingsTriageTamperedBodyGets428(t *testing.T) {
	s := newTestServerWithPersist(t)
	form := ui2TriageForm(nil)
	form.Set("api_key", ui2TestTriageKey)
	rec := ui2PostTriage(t, s, "confirm", form)
	id, token := ui2ReviewFields(t, rec.Body.String())
	if v, ok := s.ui2TriageReviews.Load(id); ok {
		e := v.(ui2TriageReview)
		e.body = ui2TriageBody(false, "https://llm.example/v1", "tampered", "")
		s.ui2TriageReviews.Store(id, e)
	}
	rec2 := ui2PostTriage(t, s, "run", url.Values{"review_id": {id}, "token": {token}})
	responseMustNotLeakKey(t, "tampered run", rec2)
	if !strings.Contains(rec2.Body.String(), "428") {
		t.Errorf("tampered body did not hit the gate's 428: %s", rec2.Body.String()[:ui2Min(300, rec2.Body.Len())])
	}
	stored, _ := s.persist.LoadTriageSettings()
	if stored.APIKey == ui2TestTriageKey {
		t.Errorf("a tampered body was written to the store")
	}
}
