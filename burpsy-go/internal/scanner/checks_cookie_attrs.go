package scanner

// Cookie prefix and SameSite weaknesses (burpsy-react-ui-0vzb.19): two burpsy rows read from the
// Set-Cookie headers of a captured response. Nothing is sent.
//
// What Burp's catalogue already covers, and is therefore NOT repeated here:
//   - "TLS cookie without secure flag set", "Cookie without HttpOnly flag set", "Duplicate cookies
//     set" and "Cookie scoped to parent domain" (checks_passive_analysis.go, checks_headers.go).
//   - Cookie tossing in its provable form - a session cookie whose Domain is a parent of the issuing
//     host, so any sibling host can set a cookie with the same name, domain and path and replace it -
//     is the "Cookie scoped to parent domain" row's own condition. It is reported on that row, which
//     now prefers a session cookie and says so (checkCookieScopedToParentDomain), not on a new row.
//     The weaker reading - any cookie without __Host- can be shadowed by a sibling's Domain=parent
//     cookie - is true of almost every cookie on the web and is not reported.
//
// The rules are the user-agent storage model of RFC 6265bis (draft-ietf-httpbis-rfc6265bis-21,
// section 5.7 steps 17-22, and 5.4 for case-insensitive prefix matching):
//   - "__Secure-" (any case): ignored unless the cookie is Secure;
//   - "__Host-" (any case): ignored unless Secure, host-only (no Domain attribute with a value) and
//     a Path attribute of exactly "/";
//   - a nameless cookie whose value starts with either prefix: ignored;
//   - SameSite=None without Secure: ignored;
//   - a SameSite value other than Strict, Lax or None: the attribute is ignored ("Default").
// A cookie a conformant browser ignores is a server that believes it set something it did not, which
// is why those are reported: the prefix's guarantee, or the cookie, never existed.
//
// Transport is deliberately not judged. A Secure (or prefixed) cookie set over cleartext HTTP is also
// ignored by the spec, but browsers treat http://localhost as a secure context, and the cleartext
// exchange is already reported by "Unencrypted communications".

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// IssueCookiePrefixViolated is the burpsy row for a prefixed cookie a browser rejects.
const IssueCookiePrefixViolated = "Cookie prefix requirements not met"

// IssueSessionCookieSameSite is the burpsy row for a session cookie without SameSite protection.
const IssueSessionCookieSameSite = "Session cookie without SameSite protection"

func cookieAttributesEnabled(c *ScanConfig) bool { return c != nil && c.CheckCookieAttributes }

// setCookieHeaders returns the response's Set-Cookie values, read from the header block only.
func setCookieHeaders(cc *CheckContext) []string {
	raw := responseRaw(cc.Scanner, cc.Exchange)
	head := raw
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head = raw[:i]
	}
	return headerValues(head, headerSetCookie)
}

// cookieAttrRaw is a cookie's attribute list in order, as name (lower-cased) and value, for the rules
// ParseSetCookie's last-wins struct cannot express: whether an attribute was present at all, and
// Max-Age.
type cookieAttrRaw struct{ name, value string }

func cookieAttrList(raw string) []cookieAttrRaw {
	semi := strings.Index(raw, ";")
	if semi < 0 {
		return nil
	}
	var out []cookieAttrRaw
	for _, part := range strings.Split(raw[semi+1:], ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, v, _ := strings.Cut(part, "=")
		out = append(out, cookieAttrRaw{strings.ToLower(strings.TrimSpace(n)), strings.TrimSpace(v)})
	}
	return out
}

// cookieDeletes reports whether the Set-Cookie removes the cookie (Max-Age <= 0, or an Expires in
// the past): a deletion stores nothing, so neither row applies to it.
func cookieDeletes(attrs []cookieAttrRaw, now time.Time) bool {
	for _, a := range attrs {
		switch a.name {
		case "max-age":
			if n, err := strconv.Atoi(a.value); err == nil && n <= 0 {
				return true
			}
		case "expires":
			if t, err := http.ParseTime(a.value); err == nil && t.Before(now) {
				return true
			}
		}
	}
	return false
}

// cookieHasDomain reports a Domain attribute with a value: an empty Domain is ignored by the storage
// model and leaves the cookie host-only.
func cookieHasDomain(attrs []cookieAttrRaw) (string, bool) {
	d, ok := "", false
	for _, a := range attrs {
		if a.name == "domain" && strings.TrimPrefix(a.value, ".") != "" {
			d, ok = a.value, true
		}
	}
	return d, ok
}

// cookiePath is the last Path attribute's value and whether one was present.
func cookiePath(attrs []cookieAttrRaw) (string, bool) {
	p, ok := "", false
	for _, a := range attrs {
		if a.name == "path" {
			p, ok = a.value, true
		}
	}
	return p, ok
}

// hasPrefixFold reports a case-insensitive prefix match.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// CookiePrefixViolations returns why a browser ignores this Set-Cookie under the prefix rules, or
// nil when it does not (or the cookie has no prefix).
func CookiePrefixViolations(raw string) []string {
	c := ParseSetCookie(raw)
	attrs := cookieAttrList(raw)
	name := c.Name
	if !strings.Contains(strings.SplitN(raw, ";", 2)[0], "=") {
		// "Set-Cookie: __Host-x" is a nameless cookie whose value is "__Host-x" (6265bis 5.6 step 3).
		name = ""
	}
	if name == "" {
		v := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
		v = strings.TrimPrefix(v, "=")
		if hasPrefixFold(v, "__Secure-") || hasPrefixFold(v, "__Host-") {
			return []string{"a nameless cookie whose value mimics a prefixed name"}
		}
		return nil
	}
	var why []string
	switch {
	case hasPrefixFold(name, "__Host-"):
		if !c.Secure {
			why = append(why, "no Secure attribute")
		}
		if d, ok := cookieHasDomain(attrs); ok {
			why = append(why, "a Domain attribute ("+d+")")
		}
		if p, ok := cookiePath(attrs); !ok {
			why = append(why, "no Path attribute")
		} else if p != "/" {
			why = append(why, "Path="+p+", not /")
		}
	case hasPrefixFold(name, "__Secure-"):
		if !c.Secure {
			why = append(why, "no Secure attribute")
		}
	}
	return why
}

// sessionCookieSegment matches the name segments that mark a session identifier or bearer token.
var sessionCookieSegment = regexp.MustCompile(`^(s?sid|sess|session|sessionid|sessid|sessiontoken|token|auth|authtoken|accesstoken|refreshtoken|idtoken|jwt|jsessionid|phpsessid)$`)

// sessionCookieSuffix matches compound segments ending in a session word: "usersession",
// "accesstoken" and "authjwt" are single segments once lower-cased.
var sessionCookieSuffix = regexp.MustCompile(`(session|sessionid|sessid|token|jwt)$`)

// LooksLikeSessionCookie reports whether a cookie carries a session identifier or bearer token:
// a well-known session cookie name, a name with a session/token/auth/jwt segment, or a value that
// is a signed JWT. Anti-CSRF tokens are excluded by name: they are meant to be readable and are
// not a credential.
func LooksLikeSessionCookie(name, value string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") {
		return false
	}
	if LooksLikeSessionToken(lower) || isSignedJWT(value) {
		return true
	}
	for _, seg := range strings.FieldsFunc(lower, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if sessionCookieSegment.MatchString(seg) || sessionCookieSuffix.MatchString(seg) {
			return true
		}
	}
	return false
}

// SameSiteWeakness returns why a session cookie lacks SameSite protection, or "" when it has it.
func SameSiteWeakness(raw string) string {
	c := ParseSetCookie(raw)
	var last string
	present := false
	for _, a := range cookieAttrList(raw) {
		if a.name == "samesite" {
			present = true
			// The storage model keeps the last SameSite with a recognised value (6265bis 5.7 step 17).
			switch strings.ToLower(a.value) {
			case "strict", "lax", "none":
				last = strings.ToLower(a.value)
			}
		}
	}
	switch {
	case last == "none" && !c.Secure:
		return "SameSite=None without Secure: conformant browsers ignore the cookie, and older ones send it on every cross-site request"
	case last == "" && present:
		return "SameSite has an unrecognised value (" + c.SameSite + "), which browsers ignore: the cookie gets the browser default"
	case last == "":
		return "no SameSite attribute: Firefox and Safari send the cookie on cross-site requests, and Chrome's Lax default still sends it on cross-site top-level POSTs for two minutes after it is set"
	}
	return ""
}

// checkCookiePrefixViolated reports prefixed cookies a browser rejects.
func checkCookiePrefixViolated(_ context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	var parts []string
	// Deletions are judged too: a browser ignores a prefixed deletion exactly as it ignores a prefixed
	// set, so a logout that clears a __Host- cookie without its attributes leaves the session in place.
	for _, raw := range setCookieHeaders(cc) {
		if why := CookiePrefixViolations(raw); len(why) > 0 {
			name := ParseSetCookie(raw).Name
			parts = append(parts, fmt.Sprintf("%s: %s", name, strings.Join(why, ", ")))
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, IssueCookiePrefixViolated, "low", "certain",
		"Set-Cookie "+strings.Join(parts, "; "),
		"the response sets a cookie whose name prefix (__Host- or __Secure-) promises attributes the "+
			"Set-Cookie does not carry, so a conformant browser ignores the cookie: the server either "+
			"runs without it or relies on a guarantee that was never in force")}, nil
}

// checkSessionCookieSameSite reports session cookies with no effective SameSite restriction.
func checkSessionCookieSameSite(_ context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	var parts []string
	now := time.Now()
	for _, raw := range setCookieHeaders(cc) {
		c := ParseSetCookie(raw)
		if c.Name == "" || strings.TrimSpace(c.Value) == "" || cookieDeletes(cookieAttrList(raw), now) {
			continue
		}
		if !LooksLikeSessionCookie(c.Name, c.Value) {
			continue
		}
		if why := SameSiteWeakness(raw); why != "" {
			parts = append(parts, c.Name+": "+why)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, IssueSessionCookieSameSite, "low", "certain",
		"Set-Cookie "+strings.Join(parts, "; "),
		"a session cookie is set without an effective SameSite restriction, so a browser attaches it to "+
			"requests other sites trigger, which is what cross-site request forgery needs")}, nil
}

// cookieScopedOrAttributes is the "Cookie scoped to parent domain" descriptor's runner: Burp's row
// under the passive-analysis switch, and the two burpsy cookie rows under their own switch.
func cookieScopedOrAttributes(base CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		var out []*Finding
		if passiveAnalysisEnabled(cc.Config) {
			f, err := base(ctx, cc)
			if err != nil {
				return f, err
			}
			out = append(out, f...)
		}
		if cookieAttributesEnabled(cc.Config) {
			f, _ := checkCookiePrefixViolated(ctx, cc)
			out = append(out, f...)
			f, _ = checkSessionCookieSameSite(ctx, cc)
			out = append(out, f...)
		}
		return out, nil
	}
}
