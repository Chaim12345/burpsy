package scanner

// Authenticated-vs-unauthenticated differential primitive, corresponding to two
// declined catalog rows:
//
//   - "Broken access control" (1050704 / burp.Zf8g.APR_BrokenAccessControl,
//     dispatched by burp.Zcxn). Declined reason on file: "Access-control
//     verification requires differential authenticated / unauthenticated
//     requests and session handling that burpsy does not perform; no native
//     access-control evaluator exists."
//   - "Cross-site request forgery" (2098944 / burp.Zf8g.APR_CrossSiteRequestForgery,
//     dispatched by burp.Zg8u). Declined reason on file: "CSRF detection
//     requires forging cross-domain requests within an authenticated session
//     and observing state changes; burpsy performs no session-aware request
//     forgery, so CSRF is not detected."
//
// # Evidence recovered from the decompiled classes
//
// burp.Zcxn.Zw sends the same request twice through two identity lambdas —
// var3::Zs ("with session") and var3::ZI ("without session") — and calls
// responsesHaveDifferences on the pair; responsesHaveDifferences (the two-arg
// overload) compares STATUS_CODE plus either PAGE_TITLE/JSON_NODE_COUNT or
// LINE_COUNT/JSON_NODE_COUNT depending on whether the response looks like JSON.
// When the pair does NOT differ, Zcxn reports broken access control: an
// unauthenticated caller got the same thing an authenticated one did. Grepping
// /root/burp-re/out/strings/map_root.tsv for "^burp.Zcxn\t" returns zero rows —
// unlike most check classes, Zcxn carries no literal payload string at all,
// which is expected and confirmed by reading the source: this check never
// crafts a probe body, it only diffs two already-issued requests. There is
// nothing "Burp-specific" to recover for the comparison logic below beyond
// what the source already states in the open; ClassifyAccessControl mirrors it
// with a coarser (but still correct) full-body diff instead of Zcxn's
// title/line-count heuristics, since burpsy has no HTML title parser or
// line-count differ of its own and reusing the package's existing
// responsesDiffer helper is what "do not build a second differencing layer"
// (the assignment's own constraint) means in practice.
//
// burp.Zg8u.getRefererUrl walks the *audited request's own headers* for the
// one whose lowercased text starts with the literal "referer:" — recovered
// from map_root.tsv, which lists "referer:" twice for burp.Zg8u (once for each
// of the two lambdas that filter and then strip that prefix) — and extracts
// the path component of that Referer's URL. Zg8u.ZN() refuses to run at all
// once the baseline response is already 4xx/5xx (nothing to differentiate:
// the resource was already denied), then Zg8u.Zw replays the request with a
// crafted Referer and compares the outcome against the baseline. That makes
// Zg8u a pure Referer-validation probe — it never looks for a token, session
// binding, or SameSite attribute, and no token-name literal exists anywhere in
// its class. FindAntiCSRFTokens and the token/SameSite bits of CSRFEvidence
// below therefore cover ground Zg8u itself does not: they use the
// industry-standard hidden-input naming conventions and defence checks that a
// real CSRF assessment needs beyond Referer validation, and are documented as
// such — not claimed as recovered from Burp's source.
//
// # What this file is
//
// Both Java classes assume Burp's own session-handling engine to obtain the
// "authenticated" half of every pair; burpsy's equivalent is
// internal/session's Coordinator (CookieHeader, RunMacro, SessionRule).
// This file is the pure-decision half of the port: given already-observed
// status/body/header values (however they were obtained — a live sender, a
// stored exchange, a test fixture), it classifies them with no network or
// storage access, so a future CheckRunner can wire a real sender and
// Coordinator into DifferentialSender/AuthContextsFrom and get this decision
// layer for free. It registers no check and sends no byte on its own.
import (
	"context"
	"regexp"
	"strings"

	"github.com/burpsy-go/burpsy/internal/session"
)

// ---------------------------------------------------------------------------
// Identity plumbing
// ---------------------------------------------------------------------------

// AuthContext is one identity a differential probe issues a request as.
//
// HasCredentials is the guard this whole primitive exists for. An empty
// CookieHeader is ambiguous on its own: it is the correct state for a genuine
// anonymous request, but it is ALSO what an "authenticated" context looks like
// when no session rule has ever been configured for the target authority —
// and those two situations must never be classified the same way, because the
// second one means the two requests being compared are not actually
// authenticated vs. unauthenticated at all. AuthContextsFrom always sets this
// field from real cookie-jar membership, and ClassifyAccessControl's very
// first check refuses to draw any conclusion when it is false.
type AuthContext struct {
	CookieHeader   string
	ExtraHeaders   map[string]string
	Label          string // "authenticated" or "unauthenticated", for reporting
	HasCredentials bool
}

// DifferentialSender is the seam that keeps this package free of a live
// network sender: a CheckRunner wires a real, engagement-authorised sender
// behind this interface; unit tests wire a fake that returns canned
// status/header/body triples for each identity. SendWithAuth issues one
// request to path as the given identity and returns its response.
type DifferentialSender interface {
	SendWithAuth(ctx context.Context, path string, auth AuthContext) (status int, headers map[string]string, body string, err error)
}

// AuthContextsFrom builds the authenticated/unauthenticated identity pair for
// host:port:tls from coord's cookie jar.
//
// The unauthenticated context always carries no credentials by construction —
// it is the anonymous half of the pair by definition, never derived from the
// jar. The authenticated context carries coord's current cookie header for
// that authority, and HasCredentials reports whether the jar actually held
// anything for it: an authority the coordinator has never absorbed a
// Set-Cookie for produces an authed context with CookieHeader == "" and
// HasCredentials == false. That is the exact state ClassifyAccessControl's
// no-credentials guard exists to catch: without it, a scan with no session
// rule configured at all would silently compare one anonymous request against
// another anonymous request, see identical responses (because they are the
// same request), and misreport every endpoint on the target as broken access
// control.
func AuthContextsFrom(coord *session.Coordinator, host string, port uint16, tls bool) (authed, anon AuthContext) {
	var cookieHeader string
	if coord != nil {
		cookieHeader = coord.CookieHeader(host, port, tls)
	}
	authed = AuthContext{
		CookieHeader:   cookieHeader,
		Label:          "authenticated",
		HasCredentials: cookieHeader != "",
	}
	anon = AuthContext{
		Label:          "unauthenticated",
		HasCredentials: false,
	}
	return authed, anon
}

// ---------------------------------------------------------------------------
// Broken access control (burp.Zcxn)
// ---------------------------------------------------------------------------

// AccessControlEvidence is the single classification an authenticated vs.
// unauthenticated response comparison produces. Unlike CSRFEvidence below,
// these values are mutually exclusive states, not independently-combinable
// bits: a comparison is exactly one of them.
type AccessControlEvidence uint8

const (
	// ACEvidenceNoCredentials means the comparison could not be run: the
	// "authenticated" side of the pair carried no session credentials, so
	// the two requests are not actually different identities. This MUST be
	// returned regardless of what the bodies say — see AuthContext's
	// HasCredentials doc comment for why.
	ACEvidenceNoCredentials AccessControlEvidence = iota
	// ACEvidenceIdenticalResponses is the failure state Zcxn exists to find:
	// an authenticated and an unauthenticated request against the same
	// resource came back with the same status and body — access control did
	// not distinguish the two identities.
	ACEvidenceIdenticalResponses
	// ACEvidenceAnonRedirectedToLogin is expected, correct behaviour: the
	// unauthenticated request was redirected toward a login/authentication
	// endpoint.
	ACEvidenceAnonRedirectedToLogin
	// ACEvidenceAnonForbidden is also correct: the unauthenticated request
	// was rejected outright (401/403).
	ACEvidenceAnonForbidden
	// ACEvidenceAnonPartialContent is a response that differed from the
	// authenticated one but was neither a login redirect nor a 401/403 —
	// worth a human look (e.g. a degraded page instead of an outright
	// denial), but not itself proof of broken access control.
	ACEvidenceAnonPartialContent
)

// loginRedirectMarkers are case-insensitive substrings of a redirect Location
// that conventionally name an authentication endpoint (login form, SSO
// provider, or a generic auth gateway). They exist to tell "the app correctly
// sent the anonymous request away to log in" apart from "the app redirected
// the anonymous request somewhere else for an unrelated reason" — a redirect
// to a page that is not an auth gate is not evidence that access control
// worked.
var loginRedirectMarkers = [...]string{"login", "signin", "sign-in", "sign_in", "auth", "sso"}

// looksLikeLoginRedirect reports whether a redirect Location names an
// authentication endpoint by the conventions in loginRedirectMarkers.
func looksLikeLoginRedirect(location string) bool {
	if location == "" {
		return false
	}
	lower := strings.ToLower(location)
	for _, marker := range loginRedirectMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// isRedirectStatus reports whether status is an HTTP redirect (3xx).
func isRedirectStatus(status int) bool { return status >= 300 && status < 400 }

// ClassifyAccessControl classifies an authenticated/unauthenticated response
// pair with no network access, mirroring Zcxn's own decision (see the
// file-level doc comment for exactly what Zcxn compares) with the package's
// existing responsesDiffer helper standing in for its title/line-count
// heuristics.
//
// hasCredentials is checked first and short-circuits every other signal on
// purpose: if the "authenticated" request never actually carried session
// credentials, the pair being compared is anonymous vs. anonymous, not
// authenticated vs. unauthenticated, and no other field can rescue that —
// reporting ACEvidenceIdenticalResponses in that case would be exactly the
// false positive this primitive exists to prevent (every endpoint of every
// scan with no session configured would "detect" broken access control,
// because two identical anonymous requests always produce identical
// responses). This is the honest-counting rule for this primitive.
func ClassifyAccessControl(authedStatus, anonStatus int, authedBody, anonBody string, anonLocation string, hasCredentials bool) AccessControlEvidence {
	if !hasCredentials {
		return ACEvidenceNoCredentials
	}
	if isRedirectStatus(anonStatus) && looksLikeLoginRedirect(anonLocation) {
		return ACEvidenceAnonRedirectedToLogin
	}
	if anonStatus == 401 || anonStatus == 403 {
		return ACEvidenceAnonForbidden
	}
	if anonStatus == authedStatus && !responsesDiffer(authedBody, anonBody) {
		return ACEvidenceIdenticalResponses
	}
	return ACEvidenceAnonPartialContent
}

// Text renders the access-control evidence as prose.
func (e AccessControlEvidence) Text() string {
	switch e {
	case ACEvidenceNoCredentials:
		return "no session credentials were available for the authenticated side of the comparison, so access control could not be tested"
	case ACEvidenceIdenticalResponses:
		return "authenticated and unauthenticated requests produced the same status and body: access control did not distinguish the two identities"
	case ACEvidenceAnonRedirectedToLogin:
		return "the unauthenticated request was redirected to a login/authentication endpoint"
	case ACEvidenceAnonForbidden:
		return "the unauthenticated request was rejected outright (401/403)"
	case ACEvidenceAnonPartialContent:
		return "the unauthenticated request received a different response that was neither a login redirect nor a rejection; this needs manual review"
	default:
		return "unrecognised access-control evidence"
	}
}

// ---------------------------------------------------------------------------
// Cross-site request forgery (burp.Zg8u, plus token/SameSite defences it does
// not itself cover — see the file-level doc comment)
// ---------------------------------------------------------------------------

// CSRFEvidence is the bitmask of anti-CSRF weaknesses observed across a probe
// set. Unlike AccessControlEvidence, several of these can be true at once
// (e.g. a form with no SameSite cookie AND no Referer validation), so this is
// a bitmask like CORSEvidence/CSPEvidence in checks_headers.go, not an
// exclusive enum.
type CSRFEvidence uint8

const (
	// CSRFEvidenceNoToken means no recognisable anti-CSRF token (see
	// FindAntiCSRFTokens) was present in the request/form at all — there is
	// nothing for a server-side check to validate, so a forged cross-origin
	// submission has nothing to defeat. Set by the caller from
	// FindAntiCSRFTokens's result, not by ClassifyCSRF (see its doc comment).
	CSRFEvidenceNoToken CSRFEvidence = 1 << iota
	// CSRFEvidenceTokenNotValidated means a token was present, but the
	// request succeeded anyway when resubmitted with the token stripped out
	// entirely — the server accepts a request that never carried a token.
	CSRFEvidenceTokenNotValidated
	// CSRFEvidenceTokenNotBoundToSession means the request succeeded when
	// resubmitted with a syntactically valid token drawn from a DIFFERENT,
	// foreign session — the server checks "a token was present", not "this
	// session's token was present", which defends nothing.
	CSRFEvidenceTokenNotBoundToSession
	// CSRFEvidenceRefererNotValidated means the request succeeded when
	// resubmitted with a cross-origin Referer header. This mirrors Zg8u's own
	// probe exactly (see the file-level doc comment): the server does not use
	// Referer as a CSRF defence at all.
	CSRFEvidenceRefererNotValidated
	// CSRFEvidenceSameSiteAbsent means the session cookie carries no
	// SameSite attribute (or an explicit SameSite=None) — the browser will
	// attach it to a cross-site request in the first place, which is the
	// precondition every other bit in this type assumes holds.
	CSRFEvidenceSameSiteAbsent
)

// antiCSRFTokenNameMarkers are case-insensitive substrings of a form input's
// "name" attribute that conventionally carry an anti-CSRF token across the
// mainstream web frameworks: Rails ("authenticity_token"), Django
// ("csrfmiddlewaretoken"), ASP.NET ("__RequestVerificationToken"),
// Express/csurf and Symfony's generic "_token", and the common hand-rolled
// "csrf"/"xsrf" field names, plus "nonce" for frameworks that reuse a
// per-request nonce as the anti-CSRF value. Zg8u itself carries no token-name
// literal at all (its only recovered literal is "referer:" — see the
// file-level doc comment: Burp's own CSRF check is a pure Referer-validation
// probe and never looks for a token), so this list is the documented
// industry-standard set, not a value recovered from Burp's source.
var antiCSRFTokenNameMarkers = [...]string{
	"csrf",
	"xsrf",
	"authenticity_token",
	"__requestverificationtoken",
	"_token",
	"csrfmiddlewaretoken",
	"nonce",
}

// htmlInputTagRe matches one HTML <input ...> tag, attributes and all, so its
// name attribute can be inspected in isolation from every other tag's.
var htmlInputTagRe = regexp.MustCompile(`(?is)<input\b[^>]*>`)

// inputNameAttrRe matches an input tag's name attribute value, whichever
// quoting style it uses.
var inputNameAttrRe = regexp.MustCompile(`(?is)\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)

// FindAntiCSRFTokens returns the name of every <input> in htmlBody whose name
// attribute case-insensitively contains one of antiCSRFTokenNameMarkers — the
// hidden fields a login/action form conventionally uses to carry an anti-CSRF
// token. Returns nil (not an error) when none are found; an empty result is
// itself the CSRFEvidenceNoToken signal a caller ORs in separately (see that
// constant's doc comment for why this function, not ClassifyCSRF, owns it).
func FindAntiCSRFTokens(htmlBody string) []string {
	var found []string
	for _, tag := range htmlInputTagRe.FindAllString(htmlBody, -1) {
		m := inputNameAttrRe.FindStringSubmatch(tag)
		if m == nil {
			continue
		}
		name := firstNonEmpty(m[1], m[2], m[3])
		if name == "" {
			continue
		}
		lower := strings.ToLower(name)
		for _, marker := range antiCSRFTokenNameMarkers {
			if strings.Contains(lower, marker) {
				found = append(found, name)
				break
			}
		}
	}
	return found
}

// firstNonEmpty returns the first non-empty string among vals, or "" if all
// are empty. Used to pick whichever quoting-style capture group of
// inputNameAttrRe actually matched.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ProbeOutcome is what one CSRF defence-bypass probe produced: whether the
// forged request actually succeeded (a judgement the caller makes from the
// response — a 200 with an error page is not "Succeeded" — which is why this
// is a bool the caller sets, not something ClassifyCSRF infers from Status
// alone), plus the response for a caller that wants to log or display it.
type ProbeOutcome struct {
	Status    int
	Body      string
	Succeeded bool
}

// ClassifyCSRF classifies which anti-CSRF defence(s), if any, actually
// stopped a forged request from succeeding. Each ProbeOutcome answers one
// question about a single defence in isolation:
//
//   - withoutToken: the request replayed with its anti-CSRF token removed
//     entirely.
//   - withToken: the request replayed with a syntactically valid token drawn
//     from a DIFFERENT, foreign session (not the session under test — a
//     token that only has to be present, not bound to *this* session,
//     defends nothing, which is exactly the bit this outcome feeds).
//   - crossOriginReferer: the request replayed with a Referer header naming
//     an attacker-controlled origin, mirroring Zg8u's own probe (see the
//     file-level doc comment).
//
// A defence that is actually working makes its probe fail
// (Succeeded == false); a bit is set exactly when a probe that a real
// defence should have rejected instead succeeded.
//
// CSRFEvidenceNoToken is deliberately never set here: it comes from
// FindAntiCSRFTokens over the form/request body, not from a probe outcome, so
// a caller ORs it in separately once it has looked at whatever token (if any)
// the request actually carried.
func ClassifyCSRF(withToken, withoutToken, crossOriginReferer ProbeOutcome, sameSitePresent bool) CSRFEvidence {
	var evidence CSRFEvidence
	if withoutToken.Succeeded {
		evidence |= CSRFEvidenceTokenNotValidated
	}
	if withToken.Succeeded {
		evidence |= CSRFEvidenceTokenNotBoundToSession
	}
	if crossOriginReferer.Succeeded {
		evidence |= CSRFEvidenceRefererNotValidated
	}
	if !sameSitePresent {
		evidence |= CSRFEvidenceSameSiteAbsent
	}
	return evidence
}

// Text renders the detected CSRF evidence bits as prose, in the same
// strongest-to-weakest-signal shape as corsEvidenceText/cspEvidenceText in
// checks_headers.go.
func (e CSRFEvidence) Text() string {
	if e == 0 {
		return "no anti-CSRF weakness observed in this probe set"
	}
	parts := make([]string, 0, 5)
	if e&CSRFEvidenceNoToken != 0 {
		parts = append(parts, "no anti-CSRF token present in the request")
	}
	if e&CSRFEvidenceTokenNotValidated != 0 {
		parts = append(parts, "token present but not validated (request succeeded with the token removed)")
	}
	if e&CSRFEvidenceTokenNotBoundToSession != 0 {
		parts = append(parts, "token present but not bound to the session (request succeeded with a foreign session's token)")
	}
	if e&CSRFEvidenceRefererNotValidated != 0 {
		parts = append(parts, "Referer not validated (request succeeded with a cross-origin Referer)")
	}
	if e&CSRFEvidenceSameSiteAbsent != 0 {
		parts = append(parts, "session cookie has no SameSite attribute (or SameSite=None)")
	}
	return strings.Join(parts, "; ")
}
