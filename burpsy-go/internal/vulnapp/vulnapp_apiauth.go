package vulnapp

// Function-level authorization fixtures (burpsy-react-ui-0vzb.46): an admin operation any
// authenticated session can invoke, and a safe twin that enforces the role.
//
//   - /api/admin/users (vulnerable) answers the admin user list to ANY known session - alice
//     (user 1, the admin) or bob (user 2, an ordinary user) - and 401 to no session;
//   - /api/safe/admin/users answers alice, refuses bob 403, and refuses no session 401.
//
// Sessions are the IDOR fixtures' (idorSessions): the sid cookie names the user, and user 1 is
// the administrator.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// APIAuthAdminCookie is alice's session: the administrator's identity for the declared
// exchanges. The scanner's second configured identity supplies the low-privilege account.
const APIAuthAdminCookie = IDORSessionCookie

func apiAuthEndpoints() []Endpoint {
	const row = "Broken access control"
	cookie := map[string]string{"Cookie": APIAuthAdminCookie}
	return []Endpoint{
		{Path: "/api/admin/users", Row: row, RequestHeaders: cookie,
			Note: "admin operation answered to any authenticated session, whatever its role; " +
				"anonymous is 401"},
		{Path: "/api/safe/admin/users", Row: row, Safe: true, RequestHeaders: cookie,
			Note: "the same operation enforcing the admin role: a non-admin session is 403, " +
				"anonymous is 401"},
		{Path: "/api/admin/settings", Row: row, Method: "POST", ContentType: "application/json",
			Body: `{"setting":"banner","value":"hello"}`, RequestHeaders: cookie,
			Note: "state-changing admin operation (a settings write) accepted from ANY authenticated " +
				"session, whatever its role; anonymous is 401"},
		{Path: "/api/safe/admin/settings", Row: row, Safe: true, Method: "POST", ContentType: "application/json",
			Body: `{"setting":"banner","value":"hello"}`, RequestHeaders: cookie,
			Note: "the same write enforcing the admin role: a non-admin session is 403 and nothing is " +
				"written, anonymous is 401"},
		{Path: "/api/envelope/admin/settings", Row: row, Safe: true, Method: "POST", ContentType: "application/json",
			Body: `{"setting":"banner","value":"hello"}`, RequestHeaders: cookie,
			Note: "the same write enforcing the admin role, but refusing with HTTP 200 and the success " +
				"envelope's shape ({\"updated\":false,...}): nothing is written for a non-admin"},
		{Path: "/api/users/2", Row: row, Method: "POST", ContentType: "application/json",
			Body:           `{"username":"bob","email":"bob@example.test"}`,
			RequestHeaders: map[string]string{"Cookie": IDORSecondSessionCookie},
			Note: "profile update that persists every field it is sent, including the server-managed " +
				"role the GET answer names: a mass-assignment target; anonymous is 401"},
		{Path: "/api/safe/users/2", Row: row, Safe: true, Method: "POST", ContentType: "application/json",
			Body:           `{"username":"bob","email":"bob@example.test"}`,
			RequestHeaders: map[string]string{"Cookie": IDORSecondSessionCookie},
			Note:           "the same update binding only username and email: an injected role is dropped"},
	}
}

func apiAuthAdminUsers(w http.ResponseWriter, r *http.Request) {
	uid := idorSession(r)
	if uid == 0 {
		idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	idorJSON(w, http.StatusOK, map[string]any{
		"users": []idorUser{idorUsers[1], idorUsers[2], idorUsers[3]},
		"total": 3,
	})
}

func apiAuthSafeAdminUsers(w http.ResponseWriter, r *http.Request) {
	uid := idorSession(r)
	if uid == 0 {
		idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if uid != 1 {
		idorJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	idorJSON(w, http.StatusOK, map[string]any{
		"users": []idorUser{idorUsers[1], idorUsers[2], idorUsers[3]},
		"total": 3,
	})
}

// apiAuthSettingWrites counts the settings writes each user id got through, so a test can pin that a
// check did (or did not) change state as the low-privilege identity.
var (
	apiAuthSettingsMu    sync.Mutex
	apiAuthSettingWrites = map[int]int{}
)

// APIAuthSettingWritesBy reports how many admin-settings writes (vulnerable twin only: the safe twin
// refuses non-admins) were accepted from user id uid.
func APIAuthSettingWritesBy(uid int) int {
	apiAuthSettingsMu.Lock()
	defer apiAuthSettingsMu.Unlock()
	return apiAuthSettingWrites[uid]
}

// apiAuthAdminSettings is a state-changing admin operation: POST writes a setting. The vulnerable
// twin accepts any authenticated session; the safe twin requires the admin (user 1).
func apiAuthAdminSettings(safe bool) http.HandlerFunc { return apiAuthAdminSettingsAs(safe, false) }

// apiAuthAdminSettingsAs is apiAuthAdminSettings; envelope makes the safe twin refuse with HTTP 200
// and {"updated":false,...}, the success answer's shape, as many APIs do.
func apiAuthAdminSettingsAs(safe, envelope bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := idorSession(r)
		if uid == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			idorJSON(w, http.StatusBadRequest, map[string]string{"error": "json body required"})
			return
		}
		if safe && uid != 1 {
			if envelope {
				idorJSON(w, http.StatusOK, map[string]any{"updated": false, "setting": body["setting"]})
				return
			}
			idorJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
			return
		}
		apiAuthSettingsMu.Lock()
		apiAuthSettingWrites[uid]++
		apiAuthSettingsMu.Unlock()
		idorJSON(w, http.StatusOK, map[string]any{"updated": true, "setting": body["setting"]})
	}
}

func registerAPIAuth(mux *http.ServeMux) {
	mux.HandleFunc("/api/admin/settings", apiAuthAdminSettings(false))
	mux.HandleFunc("/api/safe/admin/settings", apiAuthAdminSettings(true))
	mux.HandleFunc("/api/envelope/admin/settings", apiAuthAdminSettingsAs(true, true))
	mux.HandleFunc("/api/admin/users", apiAuthAdminUsers)
	mux.HandleFunc("/api/safe/admin/users", apiAuthSafeAdminUsers)
	mux.HandleFunc("/api/users/", apiAuthProfile(false))
	mux.HandleFunc("/api/safe/users/", apiAuthProfile(true))
}

// apiAuthProfiles are the mass-assignment fixtures' stored profiles, keyed by user id. bob's
// profile (user 2) is the declared target: bob may update his own profile, and the role field
// must never be writable through it.
var (
	apiAuthProfilesMu sync.Mutex // the budget matrix audits endpoints in parallel
	apiAuthProfiles   = map[int]map[string]any{
		2: {"id": 2, "username": "bob", "email": "bob@example.test", "role": "user"},
	}
)

// apiAuthProfile serves GET/POST on a user's own profile (any authenticated session may act on
// any profile here - the object-level question is the IDOR fixtures', not this fixture's).
// The vulnerable twin persists EVERY JSON field it is sent, including server-managed ones like
// role; the safe twin persists only username and email and silently drops the rest. Anonymous
// callers are 401 on both.
func apiAuthProfile(safe bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if idorSession(r) == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		tail := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		id, err := strconv.Atoi(tail)
		if err != nil {
			idorJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
			return
		}
		apiAuthProfilesMu.Lock()
		defer apiAuthProfilesMu.Unlock()
		profile, ok := apiAuthProfiles[id]
		if !ok {
			idorJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			idorJSON(w, http.StatusOK, profile)
		case http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				idorJSON(w, http.StatusBadRequest, map[string]string{"error": "json body required"})
				return
			}
			for k, v := range body {
				if k == "id" {
					continue
				}
				if safe && k != "username" && k != "email" {
					continue // the safe twin binds only the declared fields
				}
				profile[k] = v
			}
			idorJSON(w, http.StatusOK, profile)
		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}
