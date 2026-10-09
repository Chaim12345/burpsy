package web

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// burpsy-react-ui-sel6: an ntlmv1 rule is an opt-in downgrade, and the console is told so in both
// places it looks — on the rule where it is configured, and with the platform-authentication
// failures once a handshake has used it.
func Test_an_ntlmv1_rule_and_its_handshakes_carry_the_weak_auth_warning(t *testing.T) {
	server := networkServer()
	rec := call(t, server, http.MethodPost, "/api/network/auth",
		`{"host":"legacy.test","scheme":"ntlmv1","username":"CORP\\alice","password":"pw"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"warning":"NTLMv1 is a weak downgrade`) {
		t.Fatalf("POST ntlmv1 = %d %s, want the rule stored with its warning", rec.Code, rec.Body)
	}

	var listed platformAuthResponse
	json.Unmarshal(call(t, server, http.MethodGet, "/api/network/auth", "").Body.Bytes(), &listed)
	if len(listed.Rules) != 1 || listed.Rules[0].Warning == "" || listed.Warnings == nil || len(listed.Warnings) != 0 {
		t.Fatalf("GET /api/network/auth = %+v, want the rule's warning and an empty (not null) warnings list", listed)
	}

	// One v1 handshake against a v1-only challenge (no target info).
	x, ok := server.platformAuthStore().BeginConnectionAuth("legacy.test")
	if !ok {
		t.Fatal("no handshake for the ntlmv1 rule")
	}
	msg := make([]byte, 48)
	copy(msg, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	binary.LittleEndian.PutUint32(msg[20:24], 0x00080201)
	if _, err := x.Authenticate([]string{"NTLM " + base64.StdEncoding.EncodeToString(msg)}); err != nil {
		t.Fatalf("v1 handshake: %v", err)
	}

	for _, target := range []string{"/api/network/auth", "/api/network/auth/failures"} {
		var body struct {
			Warnings []struct {
				Host, Scheme string
				Count        int
			} `json:"warnings"`
		}
		json.Unmarshal(call(t, server, http.MethodGet, target, "").Body.Bytes(), &body)
		if len(body.Warnings) != 1 || body.Warnings[0].Host != "legacy.test" || body.Warnings[0].Scheme != "NTLMv1 (ESS)" || body.Warnings[0].Count != 1 {
			t.Errorf("GET %s warnings = %+v, want the one NTLMv1 (ESS) handshake to legacy.test", target, body.Warnings)
		}
	}
}
