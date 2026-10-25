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

import "net/http"

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

func registerAPIAuth(mux *http.ServeMux) {
	mux.HandleFunc("/api/admin/users", apiAuthAdminUsers)
	mux.HandleFunc("/api/safe/admin/users", apiAuthSafeAdminUsers)
}
