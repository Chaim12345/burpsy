package netauth

// Burp's "Prompt for credentials on platform authentication failure" (settings/network/connections.html,
// prompt_on_authentication_failure, off by default; burpsy-react-ui-3xnt).
//
// Burp "displays an interactive popup whenever it encounters an authentication failure". burpsy's
// engine has no screen of its own, so the failure is recorded here — where every 401 challenge the
// sender and the proxy see already arrives, through Learn — and the console asks for credentials for
// the host it names. A credential added for the host clears its failure.
//
// The difference from Burp is that the request which failed is not held and replayed with the
// answer: it has already returned its 401, and the credential applies from the next request on.
// gaps.md records it.

import (
	"sort"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// maxAuthFailures bounds the hosts recorded, per cache; the least recently seen goes first
// (the LRU caches on Credentials carry the bound - burpsy-react-ui-z5l6).
const maxAuthFailures = 32

// Failure reasons.
const (
	// FailureNoCredential: the host challenged and no rule covers it.
	FailureNoCredential = "no_credential"
	// FailureRejected: a rule covers the host and the host refused what it presented.
	FailureRejected = "rejected"
)

// AuthFailure is one host's platform-authentication failure, waiting for the operator.
type AuthFailure struct {
	Host string `json:"host"`
	// Scheme is the scheme the host challenged with, as the challenge named it (Basic, Digest,
	// NTLM, Negotiate).
	Scheme string `json:"scheme"`
	Realm  string `json:"realm,omitempty"`
	Reason string `json:"reason"`
	// Count is how many challenges have failed for this host since it was first recorded.
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// platformChallengeScheme returns the scheme token of a WWW-Authenticate value when it is one of the
// platform schemes Burp's platform authentication answers, and false for anything else (Bearer and
// other application schemes are not a platform-authentication failure).
func platformChallengeScheme(wwwAuthenticate string) (string, bool) {
	token, _, _ := strings.Cut(strings.TrimSpace(wwwAuthenticate), " ")
	switch strings.ToLower(token) {
	case "basic":
		return "Basic", true
	case "digest":
		return "Digest", true
	case "ntlm":
		return "NTLM", true
	case "negotiate":
		return "Negotiate", true
	}
	return "", false
}

// challengeRealm reads realm="..." out of a challenge, or "".
func challengeRealm(wwwAuthenticate string) string {
	lower := strings.ToLower(wwwAuthenticate)
	i := strings.Index(lower, "realm=")
	if i < 0 {
		return ""
	}
	rest := wwwAuthenticate[i+len("realm="):]
	if strings.HasPrefix(rest, `"`) {
		if end := strings.Index(rest[1:], `"`); end >= 0 {
			return rest[1 : 1+end]
		}
		return ""
	}
	if end := strings.IndexAny(rest, ", "); end >= 0 {
		return rest[:end]
	}
	return rest
}

// SetPromptOnFailure turns the prompt on or off. Off also forgets every recorded failure, so turning
// it back on does not surface stale ones.
func (c *Credentials) SetPromptOnFailure(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prompt = on
	if !on {
		c.failures = nil
	}
}

// PromptOnFailure reports whether failures are recorded for the console to prompt about.
func (c *Credentials) PromptOnFailure() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.prompt
}

// Failures returns the recorded failures, most recent first. Never nil.
func (c *Credentials) Failures() []AuthFailure {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.failures == nil {
		return []AuthFailure{}
	}
	// Values walks the cache oldest-first without touching recency: reading the panel must not
	// change which failure eviction picks next.
	values := c.failures.Values()
	out := make([]AuthFailure, 0, len(values))
	for _, f := range values {
		out = append(out, *f)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].LastSeen.After(out[b].LastSeen) })
	return out
}

// DismissFailure forgets one host's failure, reporting whether there was one.
func (c *Credentials) DismissFailure(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures == nil {
		return false
	}
	return c.failures.Remove(strings.ToLower(host))
}

// recordFailureLocked notes one failed challenge. Called with c.mu held for writing.
func (c *Credentials) recordFailureLocked(host, wwwAuthenticate, reason string) {
	if !c.prompt || host == "" {
		return
	}
	scheme, ok := platformChallengeScheme(wwwAuthenticate)
	if !ok {
		return
	}
	now := time.Now()
	key := strings.ToLower(host)
	if c.failures == nil {
		// The bound is a positive constant, the only shape lru.New can refuse.
		c.failures, _ = lru.New[string, *AuthFailure](maxAuthFailures)
	}
	// Get touches: a host that fails again is recently seen, so it is not the next eviction.
	if f, ok := c.failures.Get(key); ok {
		f.Count++
		f.LastSeen = now
		f.Scheme, f.Reason = scheme, reason
		if realm := challengeRealm(wwwAuthenticate); realm != "" {
			f.Realm = realm
		}
		return
	}
	c.failures.Add(key, &AuthFailure{Host: host, Scheme: scheme, Realm: challengeRealm(wwwAuthenticate),
		Reason: reason, Count: 1, FirstSeen: now, LastSeen: now})
}

// clearFailuresMatchingLocked forgets the failures a rule's host pattern now covers.
func (c *Credentials) clearFailuresMatchingLocked(pattern string) {
	if c.failures == nil {
		return
	}
	for _, key := range c.failures.Keys() {
		if f, ok := c.failures.Peek(key); ok && matchHost(pattern, f.Host) {
			c.failures.Remove(key)
		}
	}
}

// AuthWarning is one host where a weak platform-authentication handshake was performed — every
// NTLMv1 handshake, which the operator opted into on the rule (burpsy-react-ui-sel6). It sits
// beside AuthFailure and is served with it, because both are "what platform authentication did
// that the operator must know about"; unlike a failure it is recorded whatever the prompt setting.
type AuthWarning struct {
	Host string `json:"host"`
	// Scheme is the weak scheme used, e.g. "NTLMv1" or "NTLMv1 (ESS)".
	Scheme string `json:"scheme"`
	// Wire is the header the handshake travelled in: "NTLM" or "Negotiate".
	Wire    string `json:"wire"`
	Warning string `json:"warning"`
	// Count is how many weak handshakes have been performed for this host since it was recorded.
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Warnings returns the recorded weak-authentication handshakes, most recent first. Never nil.
func (c *Credentials) Warnings() []AuthWarning {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.warnings == nil {
		return []AuthWarning{}
	}
	values := c.warnings.Values()
	out := make([]AuthWarning, 0, len(values))
	for _, w := range values {
		out = append(out, *w)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].LastSeen.After(out[b].LastSeen) })
	return out
}

// recordWarningLocked notes one weak handshake. Called with c.mu held for writing. Bounded like
// the failures, least recently seen first out.
func (c *Credentials) recordWarningLocked(host, scheme, wire, warning string) {
	now := time.Now()
	key := strings.ToLower(host)
	if c.warnings == nil {
		c.warnings, _ = lru.New[string, *AuthWarning](maxAuthFailures)
	}
	if w, ok := c.warnings.Get(key); ok {
		w.Count++
		w.LastSeen = now
		w.Scheme, w.Wire, w.Warning = scheme, wire, warning
		return
	}
	c.warnings.Add(key, &AuthWarning{Host: host, Scheme: scheme, Wire: wire, Warning: warning,
		Count: 1, FirstSeen: now, LastSeen: now})
}
