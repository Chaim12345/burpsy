package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// The scan configuration library persists marshaled ScanConfig documents: SecondIdentity
// credentials must never appear in one, and must be inert if hand-written into one.
func TestSecondIdentityCredentialsNeverPersist(t *testing.T) {
	cfg := &ScanConfig{CheckIDORTwoIdentity: true, SecondIdentity: SecondIdentity{
		CookieHeader: "sid=secret-b", AuthorizationHeader: "Bearer b-token",
		APIKeyHeader: "X-API-Key", APIKeyValue: "b-key",
	}}
	doc, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-b", "b-token", "b-key", "SecondIdentity", "secondIdentity"} {
		if strings.Contains(string(doc), secret) {
			t.Fatalf("marshaled config leaks %q", secret)
		}
	}
	var back ScanConfig
	if err := json.Unmarshal([]byte(`{"SecondIdentity":{"CookieHeader":"sid=planted"}}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.SecondIdentity.CookieHeader != "" {
		t.Fatal("a persisted document loaded credentials into SecondIdentity")
	}
}
