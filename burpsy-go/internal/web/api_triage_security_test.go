package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/persist"
)

// The endpoint policy at the API's write door: remote http is refused (the key travels as a
// bearer token - cleartext on a remote URL exposes it), loopback http stays for local
// endpoints, and userinfo/query/fragment forms are refused without echoing their values.
// The console enforces the same rule; this door is what non-UI clients hit.
func TestTheSettingsDoorEnforcesTheEndpointPolicy(t *testing.T) {
	s := triageSettingsServer(t)
	refusals := []struct {
		name   string
		body   string
		secret string
	}{
		{"remote http", `{"enabled":true,"base_url":"http://llm.internal/v1","model":"m","api_key":"sk-secret"}`, ""},
		{"userinfo", `{"enabled":true,"base_url":"https://user:p4ssw0rd-api@llm.internal/v1","model":"m","api_key":"sk-secret"}`, "p4ssw0rd-api"},
		{"query", `{"enabled":true,"base_url":"https://llm.internal/v1?key=qu3ry-api","model":"m","api_key":"sk-secret"}`, "qu3ry-api"},
		{"fragment", `{"enabled":true,"base_url":"https://llm.internal/v1#fr4g-api","model":"m","api_key":"sk-secret"}`, "fr4g-api"},
		{"no scheme", `{"enabled":true,"base_url":"llm.internal/v1","model":"m","api_key":"sk-secret"}`, ""},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			rec := putTriageSettings(t, s, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400: %s", tc.name, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "sk-secret") {
				t.Errorf("the refusal echoed the API key")
			}
			if tc.secret != "" && strings.Contains(rec.Body.String(), tc.secret) {
				t.Errorf("the refusal echoed the secret part of the rejected URL")
			}
		})
	}
	// Accepted shapes: https remote, loopback http.
	for _, body := range []string{
		`{"enabled":true,"base_url":"https://llm.internal/v1","model":"m","api_key":"sk-secret"}`,
		`{"enabled":true,"base_url":"http://127.0.0.1:18107/v1","model":"m","api_key":"sk-secret"}`,
	} {
		if rec := putTriageSettings(t, s, body); rec.Code != http.StatusOK {
			t.Errorf("accepted shape refused = %d: %s", rec.Code, rec.Body.String())
		}
	}
}

// A config stored BEFORE the policy existed (legacy remote http) must not run: the use-time
// guard refuses the pass instead of sending the stored key in cleartext.
func TestTheRunDoorRefusesALegacyCleartextConfig(t *testing.T) {
	s := triageSettingsServer(t)
	// Simulate the legacy store: write directly through persistence, bypassing the PUT door.
	if err := s.persist.SaveTriageSettings(persist.TriageSettings{Enabled: true, BaseURL: "http://legacy-llm.internal/v1", Model: "m", APIKey: "sk-legacy-secret"}); err != nil {
		t.Fatal(err)
	}
	req := newReq(http.MethodPost, "/api/issues/triage")
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("the pass ran with a cleartext config")
	}
	if strings.Contains(rec.Body.String(), "sk-legacy-secret") {
		t.Errorf("the refusal echoed the stored key")
	}
}
