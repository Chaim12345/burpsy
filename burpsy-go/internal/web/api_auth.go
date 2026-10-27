package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// The console credential (Render deployment work).
//
// api_sameorigin.go records the gap this closes: a console bound beyond loopback ("-web 0.0.0.0:8081")
// has no credential at all, the cross-site gate validates the requester and not the requester's
// permission, and reads are not gated even though the credential-class reads (session cookies, login
// macros, scanner secrets, config export) are reads. That file declined to add a token because "a
// per-instance token is a UX decision with no safe default" for the loopback case. This is the token for
// the other case: it exists only when an operator asks for it, so the loopback default is untouched.
//
// What it is:
//
//   - One shared token, set with SetAuthToken. Unset means no gate at all, exactly as before.
//   - Checked on EVERY request before anything else, reads and streams included. It wraps the whole
//     served handler (see setupRoutes), so a route added later cannot be registered outside it.
//   - The one exception is GET/HEAD /healthz, an exact path that answers "ok" and nothing about the
//     instance, for a platform health check that cannot send credentials.
//   - The token is accepted as the HTTP Basic password (any username), which a browser prompts for and
//     then sends on every same-origin request including fetch, EventSource and WebSocket handshakes, or
//     as "Authorization: Bearer <token>" for scripts. Never as a query parameter: a URL lands in logs,
//     history and Referer headers.
//   - Compared in constant time on SHA-256 digests, so neither the length nor the content of the token
//     leaks through timing.
//   - It sits OUTSIDE the cross-site gate: an unauthenticated caller learns only "401", not which route
//     exists or what the cross-site gate would have said. A correct token does not skip the cross-site
//     gate; it runs next, so a hostile page that holds a cached Basic credential still cannot mutate.
//
// What it is not: rate limiting. A 16 character minimum random token is the assumed deployment; the
// operator who wants lockout puts a proxy in front.

// minAuthTokenLen is the shortest token SetAuthToken accepts.
const minAuthTokenLen = 16

// healthzPath is the unauthenticated liveness path.
const healthzPath = "/healthz"

// SetAuthToken turns the console credential on. It refuses a token that cannot be typed into a Basic
// prompt unambiguously (no colon, whitespace or control characters) or is too short to resist guessing.
// The token is kept only as a digest; this function does not log it and no code path returns it.
func (s *Server) SetAuthToken(token string) error {
	if err := ValidateAuthToken(token); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(token))
	s.authDigest = sum[:]
	return nil
}

// ValidateAuthToken reports whether token is acceptable as the console token. Exported so the command
// can refuse a bad token at the command line, before any listener starts.
func ValidateAuthToken(token string) error {
	if len(token) < minAuthTokenLen {
		return errors.New("auth token must be at least 16 characters")
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if c < 0x21 || c > 0x7e || c == ':' {
			return errors.New("auth token must be printable ASCII with no spaces or colons")
		}
	}
	return nil
}

// authGate wraps h behind the console credential. With no token set it only adds /healthz.
func (s *Server) authGate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthzPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte("ok\n"))
			}
			return
		}
		if s.authDigest == nil || s.authorised(r) {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="burpsy", charset="UTF-8"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, "authentication required", http.StatusUnauthorized)
	})
}

// authorised reports whether r carries the console token as a Basic password or a Bearer token.
func (s *Server) authorised(r *http.Request) bool {
	var candidate string
	if _, pass, ok := r.BasicAuth(); ok {
		candidate = pass
	} else if v := r.Header.Get("Authorization"); len(v) > 7 && strings.EqualFold(v[:7], "Bearer ") {
		candidate = v[7:]
	}
	if candidate == "" {
		return false
	}
	sum := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(sum[:], s.authDigest) == 1
}
