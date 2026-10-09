package web

import (
	"net/http"
	"strings"
	"testing"
)

// Burp's "Prompt for credentials on platform authentication failure" (burpsy-react-ui-3xnt) through
// its routes: the switch on /api/network/auth, the failures on /api/network/auth/failures, and a
// credential added for the host clearing its failure.
func TestThePlatformAuthPromptRoutes(t *testing.T) {
	s := newTestServerWithPersist(t)
	if body := get(t, s, "/api/network/auth").Body.String(); !strings.Contains(body, `"prompt_on_authentication_failure":false`) {
		t.Fatalf("GET must report the prompt off by default: %s", body)
	}
	if body := get(t, s, "/api/network/auth/failures").Body.String(); !strings.Contains(body, `"failures":[]`) {
		t.Fatalf("no failures must marshal as []: %s", body)
	}
	if rec := putJSON(t, s, "/api/network/auth", map[string]any{"prompt_on_authentication_failure": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	if !s.persist.LoadPlatformAuthPrompt() {
		t.Error("the switch was not persisted")
	}
	if rec := putJSON(t, s, "/api/network/auth", map[string]any{"prompt": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown key = %d, want 400", rec.Code)
	}

	s.platformAuthStore().Learn("intranet.test", `NTLM`)
	body := get(t, s, "/api/network/auth/failures").Body.String()
	if !strings.Contains(body, `"host":"intranet.test","scheme":"NTLM","reason":"no_credential","count":1`) {
		t.Fatalf("the failure is not on the wire: %s", body)
	}
	if rec := postJSON(t, s, "/api/network/auth", map[string]any{"host": "intranet.test", "scheme": "Basic",
		"username": "u", "password": "p"}); rec.Code != http.StatusOK {
		t.Fatalf("adding the credential = %d %s", rec.Code, rec.Body.String())
	}
	if body := get(t, s, "/api/network/auth/failures").Body.String(); !strings.Contains(body, `"failures":[]`) {
		t.Errorf("a credential for the host did not clear its failure: %s", body)
	}

	s.platformAuthStore().Learn("other.test", `Basic realm="x"`)
	if rec := deleteReq(t, s, "/api/network/auth/failures?host=other.test"); rec.Code != http.StatusOK {
		t.Errorf("dismiss = %d", rec.Code)
	}
	if rec := deleteReq(t, s, "/api/network/auth/failures?host=other.test"); rec.Code != http.StatusNotFound {
		t.Errorf("a second dismiss = %d, want 404", rec.Code)
	}
}
