package vulnapp

// The session-management family (burpsy-react-ui-0vzb wave 5): logins whose sessions are predictable,
// fixable, or survive logout, and safe twins for each guard the check relies on.
//
// Every variant has a JSON login (POST, {"username","password"}), a page that names the signed-in
// user, and a logout. One account exists: sessuser / pw-sess-2026.
//
//   - /session/fixation/login adopts a session cookie the client sent before logging in;
//   - /session/counter/login issues "S-<n>" from a counter; its only session page is
//     /session/counter/home, which no wordlist names, so it is found through the site map;
//   - /session/encoded/login issues unpadded base64url of "acct-<n>", n growing by 37;
//   - /session/clock/login issues hex of "t<unix microseconds>";
//   - /session/keep?action=login and ?action=logout: the logout expires the cookie but keeps the
//     server-side session.
//
// Safe twins:
//
//   - /session/secure/login: random tokens, a new one on every login (a planted cookie is ignored), and
//     a logout that destroys the session;
//   - /session/mixed/login: "S-<n>-<six random digits>": a visible counter, but the token as a whole cannot be
//     predicted, so only the confirmation step tells it apart;
//   - /session/lax/login: its page greets the last user who logged in on the server to anyone, session
//     or not, so only the page's random-token control tells it apart;
//   - /session/guest: has no logout at all; any POST without credentials just opens a guest session
//     (a new cookie), so only the rule that a logout must expire the cookie tells it apart.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessFixtureUser     = "sessuser"
	sessFixturePassword = "pw-sess-2026"
)

// SessionLoginBody is the fixture account's login body.
var SessionLoginBody = fmt.Sprintf(`{"username":%q,"password":%q}`, sessFixtureUser, sessFixturePassword)

type sessVariant struct {
	cookie string
	// mint makes the next token; n is the variant's login counter (already incremented).
	mint func(n int64) string
	// adopt keeps a session cookie the client sent with its login (fixation).
	adopt bool
	// keepOnLogout expires the cookie at logout but leaves the server-side session.
	keepOnLogout bool
	// lax serves the page to anyone, naming the last user who logged in.
	lax bool

	mu       sync.Mutex
	n        int64
	last     int64
	sessions map[string]string
	lastUser string
}

func sessRandom(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var sessVariants = map[string]*sessVariant{
	"fixation": {cookie: "fsid", adopt: true, mint: func(int64) string { return sessRandom(16) }},
	"counter":  {cookie: "csid", mint: func(n int64) string { return fmt.Sprintf("S-%d", 4000+n) }},
	"encoded": {cookie: "esid", mint: func(n int64) string {
		return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("acct-%d", 52000+37*n)))
	}},
	"keep":   {cookie: "ksid", keepOnLogout: true, mint: func(int64) string { return sessRandom(16) }},
	"secure": {cookie: "ssid", mint: func(int64) string { return sessRandom(16) }},
	"mixed": {cookie: "msid", mint: func(n int64) string {
		r, _ := rand.Int(rand.Reader, big.NewInt(1000000))
		return fmt.Sprintf("S-%d-%06d", 7000+n, r.Int64())
	}},
	"lax":   {cookie: "lsid", lax: true, mint: func(int64) string { return sessRandom(16) }},
	"guest": {cookie: "nsid", mint: func(int64) string { return sessRandom(16) }},
	"clock": {cookie: "tsid"},
}

func init() {
	clock := sessVariants["clock"]
	// Microseconds since the epoch, bumped by one when two logins land in the same microsecond, so
	// every token is distinct and still on the clock.
	clock.mint = func(int64) string {
		us := time.Now().UnixMicro()
		if us <= clock.last {
			us = clock.last + 1
		}
		clock.last = us
		return hex.EncodeToString([]byte(fmt.Sprintf("t%d", us)))
	}
}

func sessionEndpoints() []Endpoint {
	const (
		fix     = "Session fixation"
		predict = "Predictable session token"
		logout  = "Session not invalidated after logout"
		ct      = "application/json"
	)
	post := func(p, row string, safe bool, note string) Endpoint {
		return Endpoint{Path: p, Row: row, Method: http.MethodPost, Body: SessionLoginBody, ContentType: ct,
			Safe: safe, Note: note}
	}
	return []Endpoint{
		post("/session/fixation/login", fix, false,
			"a session cookie sent with the login is kept and bound to the user; /session/fixation/me then accepts it"),
		post("/session/counter/login", predict, false,
			"issues S-<n> from a counter; the session page /session/counter/home is only in the site map"),
		post("/session/encoded/login", predict, false,
			"issues unpadded base64url of acct-<n>, n growing by 37 per login"),
		post("/session/clock/login", predict, false, "issues hex of t<unix microseconds>"),
		post("/session/keep?action=login", logout, false,
			"?action=logout expires the ksid cookie but leaves the server-side session valid"),
		{Path: "/session/counter/home", RequestHeaders: map[string]string{"Cookie": "csid=S-0"},
			Note: "support route: the counter variant's session page, captured with its cookie so the site map has it"},

		post("/session/secure/login", fix, true, "ignores a planted cookie and issues a new random token"),
		post("/session/secure/login?twin=predict", predict, true, "random 128-bit tokens"),
		post("/session/secure/login?twin=logout", logout, true, "the logout destroys the session"),
		post("/session/mixed/login", predict, true,
			"S-<n>-<random>: the counter is visible but the whole token cannot be predicted"),
		post("/session/lax/login", logout, true,
			"its page greets the last user to log in, to anyone, with or without a session; the logout destroys "+
				"the session"),
		post("/session/guest?action=login", logout, true,
			"has no logout: a POST without credentials opens a guest session with a new cookie, whatever the action"),
	}
}

func sessJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (v *sessVariant) setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: v.cookie, Value: token, Path: "/session", HttpOnly: true})
}

func (v *sessVariant) expireCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: v.cookie, Value: "", Path: "/session", MaxAge: -1, HttpOnly: true})
}

// login checks the credentials; ok false means the body named none or the wrong ones.
func (v *sessVariant) login(w http.ResponseWriter, r *http.Request) (attempted bool) {
	var creds struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil || (creds.Username == "" && creds.Password == "") {
		return false
	}
	if creds.Username != sessFixtureUser || creds.Password != sessFixturePassword {
		sessJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sessions == nil {
		v.sessions = map[string]string{}
	}
	token := ""
	if c, err := r.Cookie(v.cookie); err == nil && v.adopt && c.Value != "" {
		token = c.Value
	} else {
		v.n++
		token = v.mint(v.n)
	}
	v.sessions[token] = creds.Username
	v.lastUser = creds.Username
	v.setCookie(w, token)
	sessJSON(w, http.StatusOK, map[string]any{"ok": true})
	return true
}

func (v *sessVariant) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(v.cookie); err == nil && !v.keepOnLogout {
		v.mu.Lock()
		delete(v.sessions, c.Value)
		v.mu.Unlock()
	}
	v.expireCookie(w)
	sessJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (v *sessVariant) page(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	user := ""
	if c, err := r.Cookie(v.cookie); err == nil {
		user = v.sessions[c.Value]
	}
	last := v.lastUser
	v.mu.Unlock()
	if v.lax {
		sessJSON(w, http.StatusOK, map[string]string{"greeting": "Welcome back, " + last})
		return
	}
	if user == "" {
		sessJSON(w, http.StatusUnauthorized, map[string]string{"error": "no session"})
		return
	}
	sessJSON(w, http.StatusOK, map[string]string{"user": user, "email": user + "@example.test"})
}

func registerSession(mux *http.ServeMux) {
	mux.HandleFunc("/session/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/session/"), "/"), "/")
		v := sessVariants[parts[0]]
		if v == nil {
			http.NotFound(w, r)
			return
		}
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}
		switch parts[0] {
		case "keep":
			// One URL, the operation in ?action=, as some applications do it.
			if len(parts) == 1 {
				action = r.URL.Query().Get("action")
			}
			if action == "profile" && len(parts) == 2 {
				action = "page"
			}
		case "guest":
			if len(parts) == 1 && r.Method == http.MethodPost {
				// No logout exists: the action is ignored, and a POST without credentials opens a
				// guest session.
				if !v.login(w, r) {
					v.mu.Lock()
					v.setCookie(w, "guest-"+sessRandom(8))
					v.mu.Unlock()
					sessJSON(w, http.StatusOK, map[string]string{"message": "guest session"})
				}
				return
			}
			if action == "me" {
				action = "page"
			}
		case "counter":
			if action == "home" {
				action = "page"
			} else if action == "me" {
				action = "" // only the site map names this variant's page
			}
		default:
			if action == "me" {
				action = "page"
			}
		}
		switch {
		case action == "login" && r.Method == http.MethodPost:
			if !v.login(w, r) {
				sessJSON(w, http.StatusBadRequest, map[string]string{"error": "credentials required"})
			}
		case action == "logout" && r.Method == http.MethodPost:
			v.logout(w, r)
		case action == "page" && r.Method == http.MethodGet:
			v.page(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
