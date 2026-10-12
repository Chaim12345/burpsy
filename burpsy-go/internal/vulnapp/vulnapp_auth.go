package vulnapp

// The authentication-logic family: login forms with and without brute-force protection, and with and
// without a username-enumerating answer, for the scanner's two burpsy-authored rows
// ("Authentication attempts not rate limited", CWE-307; "Username enumeration", CWE-204).
//
// # An in-memory login, and a ledger of what it was sent
//
// One account per family member, held in memory; nothing is persisted. Every handler records each
// SUCCESSFUL login in authLedger, and /auth/ledger serves the count. That is how a test proves the
// checks never log in and never send the captured (real) password: the seeded request carries the
// real password, and the checks must never replay it.
//
// # The safe twins each trip one guard
//
//   - /auth/throttled/login counts failures per submitted identifier - whether or not the account
//     exists, which is what a per-identifier throttle must do - and after authThrottleAfter failures
//     answers 429 with Retry-After and "Too many failed attempts".
//   - /auth/slow/login never refuses but slows every failure past the third by a growing delay.
//   - /auth/static/form has the same field names but ignores them: it answers every POST with the same
//     page and says nothing about authentication. Its burst is answered identically, which is exactly
//     why that sameness alone must not be read as missing rate limiting.
//   - /auth/otp/capped invalidates a code after authOTPMaxTries wrong guesses and then refuses with 429.
//   - /auth/login reflects the submitted username and a per-request id in a GENERIC failure message,
//     so only masking stops the reflection and the id from reading as an enumerating difference.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The one real account. The seeded requests log in as it, with its real password: the checks must
// never send that password back.
const (
	AuthUser     = "alice"
	AuthEmail    = "alice@corp.example"
	AuthPassword = "Wonderland-1865"
	AuthOTP      = "424242"
)

const (
	authThrottleAfter = 5
	authOTPMaxTries   = 3
	authSeedForm      = "username=" + AuthUser + "&password=" + AuthPassword
	authSeedOTPForm   = "email=alice%40corp.example&otp=" + AuthOTP
	authFormType      = "application/x-www-form-urlencoded"
)

const (
	rowRateLimit = "Authentication attempts not rate limited"
	rowUserEnum  = "Username enumeration"
)

func authEndpoints() []Endpoint {
	post := func(p, row string, safe bool, body, note string) Endpoint {
		return Endpoint{Path: p, Method: http.MethodPost, Row: row, Safe: safe, Body: body,
			ContentType: authFormType, Note: note}
	}
	return []Endpoint{
		post("/auth/login", rowRateLimit, false, authSeedForm,
			"answers every failed login with the same generic message and never slows or refuses a client"),
		post("/auth/otp/verify", rowRateLimit, false, authSeedOTPForm,
			"checks a six-digit one-time code with no limit on wrong guesses"),
		post("/auth/enum/login", rowUserEnum, false, authSeedForm,
			"says \"No account with that username\" for an unknown user and \"Incorrect password\" for a known one"),
		post("/auth/enum-redirect/login", rowUserEnum, false, authSeedForm,
			"redirects a failed login to ?error=unknown-user or ?error=bad-password: the page is the same, only the redirect differs"),
		{Path: "/auth/enum-json/login", Method: http.MethodPost, Row: rowUserEnum, ContentType: "application/json",
			Body: `{"username":"` + AuthUser + `","password":"` + AuthPassword + `"}`,
			Note: "a JSON login whose error code differs between an unknown user and a wrong password"},

		// --- safe twins ---
		post("/auth/throttled/login", rowRateLimit, true, authSeedForm,
			"after 5 failures for one identifier (existing or not) answers 429, Retry-After and \"Too many failed attempts\""),
		post("/auth/slow/login", rowRateLimit, true, authSeedForm,
			"never refuses, but delays every failure past the third by 60ms more than the last"),
		post("/auth/static/form", rowRateLimit, true, authSeedForm,
			"same field names, but ignores them and answers every POST with the same page"),
		post("/auth/otp/capped", rowRateLimit, true, authSeedOTPForm,
			"invalidates the code after 3 wrong guesses and answers 429 from then on"),
		post("/auth/login", rowUserEnum, true, authSeedForm,
			"one generic failure message for unknown users and wrong passwords alike, quoting the submitted "+
				"username and a per-request id"),
		post("/auth/throttled/login", rowUserEnum, true, authSeedForm,
			"generic failure message; also throttled"),
	}
}

// authState is one Handler's memory.
type authState struct {
	mu        sync.Mutex
	failures  map[string]int // per path+identifier
	otpTries  map[string]int
	successes map[string]int // per path
}

func newAuthState() *authState {
	return &authState{failures: map[string]int{}, otpTries: map[string]int{}, successes: map[string]int{}}
}

func (s *authState) fail(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.failures) > 100000 {
		s.failures = map[string]int{}
	}
	s.failures[key]++
	return s.failures[key]
}

func (s *authState) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures[key]
}

func (s *authState) success(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.successes[path]++
}

func authRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeAuthJSON(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// authForm reads username/password from a form or JSON body.
func authForm(r *http.Request) (user, pass string) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var b struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		return b.Username, b.Password
	}
	return r.FormValue("username"), r.FormValue("password")
}

func registerAuth(mux *http.ServeMux) {
	st := newAuthState()
	ok := func(w http.ResponseWriter, path string) {
		st.success(path)
		writeAuthJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Welcome back"})
	}
	onlyPost := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<html><body><form method="post"><input name="username"><input type="password" name="password"></form></body></html>`)
			return false
		}
		return true
	}

	// Vulnerable to brute force; generic (non-enumerating) failure message that quotes the submitted
	// username and a fresh request id.
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		user, pass := authForm(r)
		if user == AuthUser && pass == AuthPassword {
			ok(w, r.URL.Path)
			return
		}
		writeAuthJSON(w, http.StatusOK, map[string]any{"ok": false, "request": authRequestID(),
			"message": "Invalid username or password for " + html.EscapeString(user)})
	})

	mux.HandleFunc("/auth/throttled/login", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		user, pass := authForm(r)
		key := r.URL.Path + "\x00" + strings.ToLower(user)
		if st.count(key) >= authThrottleAfter {
			w.Header().Set("Retry-After", "300")
			writeAuthJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false,
				"message": "Too many failed attempts. Try again in 5 minutes."})
			return
		}
		if user == AuthUser && pass == AuthPassword {
			ok(w, r.URL.Path)
			return
		}
		st.fail(key)
		writeAuthJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Invalid username or password"})
	})

	mux.HandleFunc("/auth/slow/login", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		user, pass := authForm(r)
		if user == AuthUser && pass == AuthPassword {
			ok(w, r.URL.Path)
			return
		}
		n := st.fail(r.URL.Path + "\x00" + strings.ToLower(user))
		if n > 3 {
			time.Sleep(time.Duration(min(n-3, 40)) * 60 * time.Millisecond)
		}
		writeAuthJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Invalid username or password"})
	})

	// Not a login at all: the field names match, the behaviour does not.
	mux.HandleFunc("/auth/static/form", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><body><p>Thank you. Your submission has been received.</p></body></html>")
	})

	mux.HandleFunc("/auth/otp/verify", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		if r.FormValue("email") == AuthEmail && r.FormValue("otp") == AuthOTP {
			ok(w, r.URL.Path)
			return
		}
		writeAuthJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Invalid code"})
	})

	mux.HandleFunc("/auth/otp/capped", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		key := r.URL.Path + "\x00" + strings.ToLower(r.FormValue("email"))
		if st.count(key) >= authOTPMaxTries {
			w.Header().Set("Retry-After", "600")
			writeAuthJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false,
				"message": "This code is no longer valid. Request a new one later."})
			return
		}
		if r.FormValue("email") == AuthEmail && r.FormValue("otp") == AuthOTP {
			ok(w, r.URL.Path)
			return
		}
		st.fail(key)
		writeAuthJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Invalid code"})
	})

	mux.HandleFunc("/auth/enum/login", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		user, pass := authForm(r)
		switch {
		case user != AuthUser:
			writeAuthJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "No account with that username"})
		case pass != AuthPassword:
			writeAuthJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Incorrect password"})
		default:
			ok(w, r.URL.Path)
		}
	})

	mux.HandleFunc("/auth/enum-redirect/login", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		user, pass := authForm(r)
		switch {
		case user != AuthUser:
			http.Redirect(w, r, "/auth/enum-redirect/login?error=unknown-user", http.StatusFound)
		case pass != AuthPassword:
			http.Redirect(w, r, "/auth/enum-redirect/login?error=bad-password", http.StatusFound)
		default:
			st.success(r.URL.Path)
			http.Redirect(w, r, "/auth/home", http.StatusFound)
		}
	})

	mux.HandleFunc("/auth/enum-json/login", func(w http.ResponseWriter, r *http.Request) {
		if !onlyPost(w, r) {
			return
		}
		user, pass := authForm(r)
		switch {
		case user != AuthUser:
			writeAuthJSON(w, http.StatusUnauthorized, map[string]any{"error": "USER_NOT_FOUND"})
		case pass != AuthPassword:
			writeAuthJSON(w, http.StatusUnauthorized, map[string]any{"error": "BAD_CREDENTIALS"})
		default:
			ok(w, r.URL.Path)
		}
	})

	// The ledger: how many times each login succeeded. Not a manifest route.
	mux.HandleFunc("/auth/ledger", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		out := map[string]any{}
		for k, v := range st.successes {
			out[k] = v
		}
		st.mu.Unlock()
		writeAuthJSON(w, http.StatusOK, out)
	})
}
