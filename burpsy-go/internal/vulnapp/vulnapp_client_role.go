package vulnapp

// Privilege escalation via forged client-side state (burpsy-react-ui-0vzb.32).
//
// Each endpoint reads a session cookie holding JSON (base64) that names the user and an
// authorization attribute. The vulnerable two believe that attribute; the safe twins carry the same
// kind of cookie and either verify a signature first, never let the attribute decide anything, or
// refuse the privileged value. Several echo the attribute back, so a detector comparing raw bodies
// would see a difference the server's authorization had no part in.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const clientRoleRow = "Privilege escalation via forged client-side state"

var (
	clientRoleSeed = base64.StdEncoding.EncodeToString([]byte(`{"user":"ada","role":"USER","theme":"light"}`))
	clientFlagSeed = base64.RawURLEncoding.EncodeToString([]byte(`{"name":"ada","isAdmin":false}`))
)

func clientRoleEndpoints() []Endpoint {
	cookie := func(v string) map[string]string { return map[string]string{"Cookie": v} }
	role := cookie("session=" + clientRoleSeed)
	signedPayload := base64.StdEncoding.EncodeToString([]byte(`{"user":"ada","role":"USER"}`))
	return []Endpoint{
		{Path: "/client-state/dashboard", Row: clientRoleRow, RequestHeaders: role,
			Note: "binds the session cookie's role (an enum of USER and ADMIN, anything else refused) and " +
				"shows the administrator dashboard to an ADMIN"},
		{Path: "/client-state/account", Row: clientRoleRow, RequestHeaders: cookie("account=" + clientFlagSeed),
			Note: "reads the account cookie's isAdmin flag (unknown members ignored) and shows the " +
				"administrator tools when it is true"},

		{Path: "/safe/client-state/signed", Row: clientRoleRow, Safe: true,
			RequestHeaders: cookie("session=" + signedPayload + "." + deserSign(signedPayload)),
			Note:           "the same JSON with an HMAC after '.', verified before the role is read"},
		{Path: "/safe/client-state/echo", Row: clientRoleRow, Safe: true, RequestHeaders: role,
			Note: "accepts any role and only echoes it; every role sees the same page"},
		{Path: "/safe/client-state/server-role", Row: clientRoleRow, Safe: true, RequestHeaders: role,
			Note: "takes the user from the cookie and the role from its own records, ignoring the cookie's role"},
		{Path: "/safe/client-state/allowlist", Row: clientRoleRow, Safe: true, RequestHeaders: role,
			Note: "a cookie role other than USER is refused alike, ADMIN included, echoing the refused value"},
		{Path: "/safe/client-state/reauth", Row: clientRoleRow, Safe: true, RequestHeaders: role,
			Note: "an ADMIN role in the cookie is answered with a refusal page asking to re-authenticate, " +
				"distinct from both the user page and the malformed-session answer"},
	}
}

func registerClientRole(mux *http.ServeMux) {
	mux.HandleFunc("/client-state/dashboard", clientRoleDashboard)
	mux.HandleFunc("/client-state/account", clientRoleAccount)
	mux.HandleFunc("/safe/client-state/signed", clientRoleSigned)
	mux.HandleFunc("/safe/client-state/echo", clientRoleEcho)
	mux.HandleFunc("/safe/client-state/server-role", clientRoleServerSide)
	mux.HandleFunc("/safe/client-state/allowlist", clientRoleAllowlist)
	mux.HandleFunc("/safe/client-state/reauth", clientRoleReauth)
}

type clientSession struct {
	User  string `json:"user"`
	Role  string `json:"role"`
	Theme string `json:"theme,omitempty"`
}

// clientSessionFrom binds the session cookie strictly: base64 JSON, no unknown members.
func clientSessionFrom(r *http.Request) (clientSession, bool) {
	var s clientSession
	b, ok := deserCookieBytes(r, "session")
	if !ok {
		return s, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&s) != nil || s.User == "" {
		return s, false
	}
	return s, true
}

func clientUserPage(w http.ResponseWriter, user string) {
	deserText(w, 200, fmt.Sprintf("Welcome %s. Your tasks: update your profile, review 2 open tickets.", user))
}

func clientAdminPage(w http.ResponseWriter, user string) {
	deserText(w, 200, fmt.Sprintf("Welcome %s. Administration: 3 pending reports, 128 flagged listings, "+
		"manage users and billing.", user))
}

func clientRoleDashboard(w http.ResponseWriter, r *http.Request) {
	s, ok := clientSessionFrom(r)
	if !ok {
		deserText(w, 200, "Your session could not be read; sign in again.")
		return
	}
	switch s.Role {
	case "ADMIN":
		clientAdminPage(w, s.User)
	case "USER":
		clientUserPage(w, s.User)
	default:
		deserText(w, 200, "Your session could not be read; sign in again.")
	}
}

func clientRoleAccount(w http.ResponseWriter, r *http.Request) {
	var a struct {
		Name    string `json:"name"`
		IsAdmin bool   `json:"isAdmin"`
	}
	b, ok := deserCookieBytes(r, "account")
	if !ok || json.Unmarshal(b, &a) != nil || a.Name == "" {
		deserText(w, 200, "No account selected.")
		return
	}
	if a.IsAdmin {
		clientAdminPage(w, a.Name)
		return
	}
	clientUserPage(w, a.Name)
}

func clientRoleSigned(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		deserText(w, 401, "no session")
		return
	}
	payload, sig, found := strings.Cut(c.Value, ".")
	if !found || sig != deserSign(payload) {
		deserText(w, 200, "Your session could not be read; sign in again.")
		return
	}
	b, err := base64.StdEncoding.DecodeString(payload)
	var s clientSession
	if err != nil || json.Unmarshal(b, &s) != nil {
		deserText(w, 200, "Your session could not be read; sign in again.")
		return
	}
	if s.Role == "ADMIN" {
		clientAdminPage(w, s.User)
		return
	}
	clientUserPage(w, s.User)
}

func clientRoleEcho(w http.ResponseWriter, r *http.Request) {
	s, ok := clientSessionFrom(r)
	if !ok {
		deserText(w, 200, "Your session could not be read; sign in again.")
		return
	}
	deserText(w, 200, fmt.Sprintf("Welcome %s (%s). Your tasks: update your profile, review 2 open tickets. "+
		"<span class=\"badge-%s\"></span>", s.User, s.Role, strings.ToLower(s.Role)))
}

// clientServerRoles is the server's own record of each user's role.
var clientServerRoles = map[string]string{"ada": "USER"}

func clientRoleServerSide(w http.ResponseWriter, r *http.Request) {
	s, ok := clientSessionFrom(r)
	if !ok {
		deserText(w, 200, "Your session could not be read; sign in again.")
		return
	}
	if clientServerRoles[s.User] == "ADMIN" {
		clientAdminPage(w, s.User)
		return
	}
	clientUserPage(w, s.User)
}

func clientRoleAllowlist(w http.ResponseWriter, r *http.Request) {
	s, ok := clientSessionFrom(r)
	if !ok {
		deserText(w, 200, "Your session could not be read; sign in again.")
		return
	}
	if s.Role != "USER" {
		deserText(w, 200, fmt.Sprintf("Role %s is not available to this account.", s.Role))
		return
	}
	clientUserPage(w, s.User)
}

func clientRoleReauth(w http.ResponseWriter, r *http.Request) {
	s, ok := clientSessionFrom(r)
	if !ok {
		deserText(w, 200, "Your session could not be read; sign in again.")
		return
	}
	switch s.Role {
	case "USER":
		clientUserPage(w, s.User)
	case "ADMIN":
		deserText(w, 200, "Administrator access denied: administrator sessions must re-authenticate "+
			"with a second factor before the console opens.")
	default:
		deserText(w, 200, "Your session could not be read; sign in again.")
	}
}
