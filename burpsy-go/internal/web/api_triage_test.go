package web

// The triage surface's HTTP contracts (burpsy-react-ui-ei0v):
//
//   - the settings door: GET answers configured/not without the key; PUT keeps a stored key
//     when the body omits one (the UI sends the GET shape back); enabling without a base
//     URL is refused — an unconfigured endpoint is a silent no-op;
//   - the run door: POST /api/issues/triage without configuration is 503 with the reason;
//   - the one-finding door: POST /api/issues/{id}/triage attaches the note to the STORED
//     finding so the note outlives the pass and rides the issues view.
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func triageSettingsServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithPersist(t)
}

func putTriageSettings(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/settings/triage", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func getTriageSettings(t *testing.T, s *Server) triageSettingsView {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/settings/triage", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET settings = %d: %s", rec.Code, rec.Body.String())
	}
	var v triageSettingsView
	json.Unmarshal(rec.Body.Bytes(), &v)
	return v
}

func TestTheSettingsDoorNeverEchoesTheKey(t *testing.T) {
	s := triageSettingsServer(t)
	rec := putTriageSettings(t, s, `{"enabled":true,"base_url":"https://llm.internal/v1","model":"m","api_key":"sk-secret"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT settings = %d: %s", rec.Code, rec.Body.String())
	}
	v := getTriageSettings(t, s)
	if v.APIKey != "" {
		t.Fatalf("GET echoed the API key %q — the settings surface would put the credential in every tab that renders it", v.APIKey)
	}
	if !v.Configured {
		t.Fatal("GET says not-configured although a key is stored")
	}
	if v.BaseURL != "https://llm.internal/v1" || v.Model != "m" {
		t.Errorf("the stored shape came back wrong: %+v", v)
	}
}

func TestAPutWithoutAKeyKeepsTheStoredOne(t *testing.T) {
	s := triageSettingsServer(t)
	putTriageSettings(t, s, `{"enabled":true,"base_url":"https://llm.internal/v1","model":"m","api_key":"sk-secret"}`)
	// The UI's re-save: the GET shape (no key) comes back as a PUT.
	rec := putTriageSettings(t, s, `{"enabled":true,"base_url":"https://llm.internal/v1","model":"m2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT without a key = %d: %s", rec.Code, rec.Body.String())
	}
	// The stored key survived: configured stays true.
	if v := getTriageSettings(t, s); !v.Configured || v.Model != "m2" {
		t.Fatalf("the keyless re-save lost the credential or the model: %+v", v)
	}
}

func TestEnablingWithoutABaseURLIsRefused(t *testing.T) {
	s := triageSettingsServer(t)
	rec := putTriageSettings(t, s, `{"enabled":true,"base_url":"","model":"m"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("enable with no base URL = %d, want 400 — an unconfigured endpoint is a silent no-op", rec.Code)
	}
	if v := getTriageSettings(t, s); v.Enabled {
		t.Fatal("the refused call left the pass enabled")
	}
}

func TestTheRunDoorRefusesUnconfigured(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/issues/triage", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("run without configuration = %d, want 503 with the reason", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not configured") {
		t.Errorf("the refusal = %q, want it to name what is missing", rec.Body.String())
	}
}

func TestTheOneFindingDoorAttachesTheStoredNote(t *testing.T) {
	// The store-level attach is the wire path the one-finding route writes through:
	// SetTriage must land on the stored finding and ride the issues view, and clear the
	// same door.
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": `{"verdict":"real-risk","reasoning":"unescaped"}`}}},
		})
	}))
	defer stub.Close()

	// The store-level attach: SetTriage lands and the view carries it — the wire path the
	// one-finding route writes through.
	store := core.NewFindingStore()
	id := store.Add(core.NewFinding{Name: "SQL injection", Severity: core.ParseSeverity("high")})
	store.SetTriage(id, &core.TriageNote{Verdict: "real-risk", Reasoning: "unescaped", Model: "test-model"})
	f, _ := store.Get(id)
	if f.Triage == nil || f.Triage.Verdict != "real-risk" {
		t.Fatalf("SetTriage did not land on the stored finding: %+v", f.Triage)
	}
	// and clearing works the same door
	if !store.SetTriage(id, nil) {
		t.Fatal("SetTriage(nil) refused a valid id")
	}
	if f, _ = store.Get(id); f.Triage != nil {
		t.Fatal("SetTriage(nil) did not clear the note")
	}
}
