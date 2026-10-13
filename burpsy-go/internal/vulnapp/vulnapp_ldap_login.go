package vulnapp

// Blind LDAP injection in a directory login (burpsy-react-ui-0vzb.32).
//
// The login builds (&(uid=<user>)) by concatenation, evaluates it with the same real filter
// evaluator as /directory, and then checks the submitted password against every entry the filter
// matched. It answers only "Login successful" or "Invalid credentials" - a parse error, an empty
// match and a wrong password all read the same - so the filter is visible only through a login that
// works. The seeded request carries a valid account, as a tester's own test account would be; with
// it, an always-true term appended to the user name keeps the login working and a negation breaks
// it. The safe twin escapes the filter metacharacters (RFC 4515) first.

import (
	"net/http"
	"strings"
)

// directoryPasswords are the fixture accounts' passwords. Nothing here protects anything.
var directoryPasswords = map[string]string{"alice": "wonderland-7", "bob": "builder-42", "carol": "carols-9"}

func ldapLoginEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/directory/login?user=alice&pass=wonderland-7", Row: "LDAP injection",
			Note: "concatenates the user name into (&(uid=...)) and answers only success or failure; an " +
				"appended always-true term keeps the valid login working, a negation breaks it"},
		{Path: "/safe/directory/login?user=alice&pass=wonderland-7", Row: "LDAP injection", Safe: true,
			Note: "same blind login, filter metacharacters escaped first, so any appended term stops the " +
				"login matching"},
	}
}

func registerLDAPLogin(mux *http.ServeMux) {
	mux.HandleFunc("/directory/login", ldapLogin(func(s string) string { return s }))
	mux.HandleFunc("/safe/directory/login", ldapLogin(strings.NewReplacer(
		`\`, `\5c`, `*`, `\2a`, `(`, `\28`, `)`, `\29`, "\x00", `\00`).Replace))
}

func ldapLogin(escape func(string) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "text/plain")
		user, pass := q.Get("user"), q.Get("pass")
		if user == "" || pass == "" {
			_, _ = w.Write([]byte("Provide user and pass\n"))
			return
		}
		uids, err := evalFilterSequence("(&(uid=" + escape(user) + "))")
		if err == nil {
			for _, uid := range uids {
				if p, ok := directoryPasswords[uid]; ok && p == pass {
					_, _ = w.Write([]byte("Login successful\n"))
					return
				}
			}
		}
		_, _ = w.Write([]byte("Invalid credentials\n"))
	}
}
