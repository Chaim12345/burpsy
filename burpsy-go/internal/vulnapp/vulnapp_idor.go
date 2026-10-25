package vulnapp

// The insecure-direct-object-reference family (burpsy-react-ui-0vzb.12): endpoints that look an
// object up by a client-supplied id and return it without checking that the session's user may see
// it, and safe twins for every way a detector could confuse that with something harmless:
//
//   - /idor/safe/profile checks ownership (another user's id is 403);
//   - /idor/safe/products is a PUBLIC catalogue: any id, with or without a session, is answered with
//     a product of the same shape, so a swapped id returning a different object proves nothing;
//   - /idor/safe/echo answers every EXISTING id with the session's own record and the id repeated
//     (an unknown id is 404, so the invalid-id control passes): only the rule that an echoed id is not
//     a different object tells it apart;
//   - /idor/safe/generated computes a record from ANY number, made-up or not (a deterministic preview,
//     no object store behind it), so only the invalid-id control tells it apart;
//   - /idor/safe/doc carries a role cookie it ignores (the role comes from the server-side session),
//     so raising the cookie to admin changes nothing.
//
// Three users exist: 1 alice, 2 bob, 3 carol. The session is the sid cookie, or for /idor/orders a
// bearer JWT whose sub is the user id.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// IDORSessionCookie is alice's session cookie (user 1).
const IDORSessionCookie = "sid=s-alice-4c1e9b"

type idorUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Balance  int    `json:"balance"`
}

var idorUsers = map[int]idorUser{
	1: {1, "alice", "alice@example.test", 1200},
	2: {2, "bob", "bob@example.test", 5300},
	3: {3, "carol", "carol@example.test", 870},
}

var idorSessions = map[string]int{"s-alice-4c1e9b": 1, "s-bob-9f2c7a": 2}

// IDORSecondSessionCookie is bob's session cookie (user 2): the second configured identity a
// two-identity authorization check replays under.
const IDORSecondSessionCookie = "sid=s-bob-9f2c7a"

type idorOrder struct {
	ID      int      `json:"id"`
	OwnerID int      `json:"ownerId"`
	Total   string   `json:"total"`
	Items   []string `json:"items"`
}

var idorOrders = map[int]idorOrder{
	1000: {1000, 3, "12.50", []string{"pencil"}},
	1001: {1001, 1, "88.00", []string{"lamp", "bulb"}},
	1002: {1002, 2, "19.99", []string{"mug"}},
}

// idorBearer is alice's bearer token: an HS256 JWT whose sub is "1".
var idorBearer = jwMintHS(jwSecret, map[string]any{"alg": "HS256", "typ": "JWT"},
	map[string]any{"sub": "1", "name": "alice"})

// idorJuiceBearer is alice's Juice Shop-shaped bearer token: the payload signs the whole user row,
// so the session user id sits at the nested claim data.id, and the top level carries only the
// basket id and the timestamps. A scanner that reads only top-level claims learns nothing about
// the session from this token.
var idorJuiceBearer = jwMintHS(jwSecret, map[string]any{"alg": "HS256", "typ": "JWT"},
	map[string]any{
		"data": map[string]any{"id": 1, "email": "alice@example.test", "role": "customer"},
		"bid":  1001, "iat": 1761000000, "exp": 1761021600,
	})

// idorBaskets are the basket rows /rest/basket serves, Juice Shop-shaped: the owner's id rides in
// UserId, and the response wraps the object in {"status": ..., "data": ...}.
type idorBasket struct {
	ID       int      `json:"id"`
	UserID   int      `json:"UserId"`
	Products []string `json:"Products"`
}

var idorBaskets = map[int]idorBasket{
	1000: {1000, 3, []string{"carrot"}},
	1001: {1001, 1, []string{"apple", "banana"}},
	1002: {1002, 2, []string{"melon"}},
}

func idorEndpoints() []Endpoint {
	const row = "Insecure direct object reference"
	cookie := map[string]string{"Cookie": IDORSessionCookie}
	return []Endpoint{
		{Path: "/idor/profile?id=1", Row: row, RequestHeaders: cookie,
			Note: "returns any user's profile for the id asked, to any logged-in session; an unknown id is 404 " +
				"and no session is 401"},
		{Path: "/idor/orders/1001", Row: row,
			RequestHeaders: map[string]string{"Authorization": "Bearer " + idorBearer},
			Note: "returns any order by the id in the path to any bearer; the order's ownerId names its owner, " +
				"and the bearer JWT's sub names the session user, so the binding is demonstrable"},
		{Path: "/rest/basket/1001", Row: row,
			RequestHeaders: map[string]string{"Authorization": "Bearer " + idorJuiceBearer},
			Note: "Juice Shop-shaped: any basket by the id in the path to any bearer; the basket's UserId names " +
				"its owner and the JWT names the session user only at the nested claim data.id, so the binding " +
				"is demonstrable only by reading claims recursively"},
		{Path: "/idor/account", Row: row,
			RequestHeaders: map[string]string{"Cookie": IDORSessionCookie + "; acct_id=1"},
			Note:           "reads the account to show from the client-held acct_id cookie instead of the session"},
		{Path: "/idor/doc?id=1", Row: row,
			RequestHeaders: map[string]string{"Cookie": IDORSessionCookie + "; role=user"},
			Note:           "lets a user read only their own document, unless the client-held role cookie says admin"},

		{Path: "/idor/safe/profile?id=1", Row: row, Safe: true, RequestHeaders: cookie,
			Note: "checks ownership: another user's id is 403"},
		{Path: "/idor/safe/products?id=1", Row: row, Safe: true, RequestHeaders: cookie,
			Note: "a public catalogue: every product is served to anyone, session or not"},
		{Path: "/idor/safe/echo?id=1", Row: row, Safe: true, RequestHeaders: cookie,
			Note: "answers every existing id with the session's own record and the id repeated; an unknown id is 404"},
		{Path: "/idor/safe/generated?id=1", Row: row, Safe: true, RequestHeaders: cookie,
			Note: "computes a record from any number, made up or not, so there is no object behind the id"},
		{Path: "/idor/safe/doc?id=1", Row: row, Safe: true,
			RequestHeaders: map[string]string{"Cookie": IDORSessionCookie + "; role=user"},
			Note:           "carries a role cookie but takes the role from the server-side session, so raising it does nothing"},
	}
}

func idorJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// idorSession is the session's user id from the sid cookie, or 0.
func idorSession(r *http.Request) int {
	c, err := r.Cookie("sid")
	if err != nil {
		return 0
	}
	return idorSessions[c.Value]
}

// idorBearerUser is the session's user id from a bearer JWT signed with the fixture key, or 0.
func idorBearerUser(r *http.Request) int {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return 0
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return 0
	}
	// The algorithm is fixed by the server, never read from the token header.
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	mac := hmac.New(sha256.New, jwSecret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if err != nil || !hmac.Equal(got, mac.Sum(nil)) {
		return 0
	}
	var claims map[string]any
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		return 0
	}
	sub, _ := claims["sub"].(string)
	n, _ := strconv.Atoi(sub)
	return n
}

// idorJuiceBearerUser is the session's user id from a Juice Shop-shaped bearer token (the user id
// at the nested claim data.id), or 0. The signature check is the same fixture HMAC idorBearerUser
// applies.
func idorJuiceBearerUser(r *http.Request) int {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return 0
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return 0
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	mac := hmac.New(sha256.New, jwSecret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if err != nil || !hmac.Equal(got, mac.Sum(nil)) {
		return 0
	}
	var claims map[string]any
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		return 0
	}
	data, _ := claims["data"].(map[string]any)
	id, _ := data["id"].(float64)
	return int(id)
}

func idorID(r *http.Request) (int, bool) {
	n, err := strconv.Atoi(r.URL.Query().Get("id"))
	return n, err == nil
}

func registerIDOR(mux *http.ServeMux) {
	mux.HandleFunc("/idor/profile", func(w http.ResponseWriter, r *http.Request) {
		if idorSession(r) == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		id, _ := idorID(r)
		u, ok := idorUsers[id]
		if !ok {
			idorJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
			return
		}
		idorJSON(w, http.StatusOK, u)
	})
	mux.HandleFunc("/idor/orders/", func(w http.ResponseWriter, r *http.Request) {
		if idorBearerUser(r) == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer token required"})
			return
		}
		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/idor/orders/"))
		o, ok := idorOrders[id]
		if err != nil || !ok {
			idorJSON(w, http.StatusNotFound, map[string]string{"error": "no such order"})
			return
		}
		idorJSON(w, http.StatusOK, map[string]any{"order": o})
	})
	mux.HandleFunc("/rest/basket/", func(w http.ResponseWriter, r *http.Request) {
		if idorJuiceBearerUser(r) == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer token required"})
			return
		}
		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/rest/basket/"))
		b, ok := idorBaskets[id]
		if err != nil || !ok {
			idorJSON(w, http.StatusNotFound, map[string]string{"error": "no such basket"})
			return
		}
		// No ownership check - the vulnerability: any valid token reads any basket.
		idorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": b})
	})
	mux.HandleFunc("/idor/account", func(w http.ResponseWriter, r *http.Request) {
		if idorSession(r) == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		c, err := r.Cookie("acct_id")
		if err != nil {
			idorJSON(w, http.StatusBadRequest, map[string]string{"error": "no account selected"})
			return
		}
		id, _ := strconv.Atoi(c.Value)
		u, ok := idorUsers[id]
		if !ok {
			idorJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "account not found"})
			return
		}
		idorJSON(w, http.StatusOK, map[string]any{"ok": true, "account": u})
	})
	doc := func(trustCookieRole bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			me := idorSession(r)
			if me == 0 {
				idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
				return
			}
			role := "user" // the server-side session's role
			if c, err := r.Cookie("role"); err == nil && trustCookieRole {
				role = c.Value
			}
			id, _ := idorID(r)
			if id != me && !strings.EqualFold(role, "admin") {
				idorJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "forbidden"})
				return
			}
			u, ok := idorUsers[id]
			if !ok {
				idorJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "document not found"})
				return
			}
			idorJSON(w, http.StatusOK, map[string]any{"ok": true, "doc": map[string]any{
				"id": id, "title": u.Username + "'s tax return", "owner": u.Username, "body": "income " + strconv.Itoa(u.Balance*12)}})
		}
	}
	mux.HandleFunc("/idor/doc", doc(true))
	mux.HandleFunc("/idor/safe/doc", doc(false))

	mux.HandleFunc("/idor/safe/profile", func(w http.ResponseWriter, r *http.Request) {
		me := idorSession(r)
		if me == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		id, _ := idorID(r)
		if id != me {
			idorJSON(w, http.StatusForbidden, map[string]string{"error": "not your profile"})
			return
		}
		idorJSON(w, http.StatusOK, idorUsers[me])
	})
	mux.HandleFunc("/idor/safe/products", func(w http.ResponseWriter, r *http.Request) {
		id, _ := idorID(r)
		names := map[int]string{1: "kettle", 2: "toaster", 3: "blender"}
		name, ok := names[id]
		if !ok {
			idorJSON(w, http.StatusNotFound, map[string]string{"error": "no such product"})
			return
		}
		idorJSON(w, http.StatusOK, map[string]any{"id": id, "name": name, "price": strconv.Itoa(id*10+9) + ".99"})
	})
	mux.HandleFunc("/idor/safe/generated", func(w http.ResponseWriter, r *http.Request) {
		if idorSession(r) == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		id, _ := idorID(r)
		sum := sha256.Sum256([]byte(strconv.Itoa(id)))
		idorJSON(w, http.StatusOK, map[string]any{"seed": id, "preview": base64.RawURLEncoding.EncodeToString(sum[:9]),
			"colour": "#" + strconv.FormatInt(int64(sum[0])<<16|int64(sum[1])<<8|int64(sum[2]), 16)})
	})
	mux.HandleFunc("/idor/safe/echo", func(w http.ResponseWriter, r *http.Request) {
		me := idorSession(r)
		if me == 0 {
			idorJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		id, _ := idorID(r)
		if _, ok := idorUsers[id]; !ok {
			idorJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
			return
		}
		u := idorUsers[me]
		idorJSON(w, http.StatusOK, map[string]any{"requested": id, "username": u.Username, "email": u.Email})
	})
}
