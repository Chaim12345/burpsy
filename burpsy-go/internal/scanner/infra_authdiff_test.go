package scanner

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/session"
)

// ---------------------------------------------------------------------------
// ClassifyAccessControl
// ---------------------------------------------------------------------------

// TestClassifyAccessControlWithNoCredentialsReturnsNoCredentialsEvenWhenBodiesMatch
// asserts the honest-counting guard this primitive exists for: two
// byte-identical responses MUST NOT be reported as broken access control when
// the "authenticated" side never actually carried a session. Without this
// guard winning over the differential, a scan with no session rule configured
// would report every endpoint as broken access control, because two identical
// anonymous requests always produce identical responses.
func TestClassifyAccessControlWithNoCredentialsReturnsNoCredentialsEvenWhenBodiesMatch(t *testing.T) {
	got := ClassifyAccessControl(200, 200, "same body", "same body", "", false)
	if got != ACEvidenceNoCredentials {
		t.Fatalf("ClassifyAccessControl with hasCredentials=false = %v, want ACEvidenceNoCredentials even though bodies matched", got)
	}
}

// TestClassifyAccessControlWithCredentialsAndIdenticalResponsesReturnsIdenticalResponses
// asserts the actual failure case Zcxn exists to find: WITH real credentials,
// an authenticated and unauthenticated request returning the same status and
// body IS broken access control.
func TestClassifyAccessControlWithCredentialsAndIdenticalResponsesReturnsIdenticalResponses(t *testing.T) {
	got := ClassifyAccessControl(200, 200, "<html>account page</html>", "<html>account page</html>", "", true)
	if got != ACEvidenceIdenticalResponses {
		t.Fatalf("ClassifyAccessControl with credentials and identical responses = %v, want ACEvidenceIdenticalResponses", got)
	}
}

// TestClassifyAccessControlAnonRedirectedToLoginIsNotTreatedAsFailure asserts
// that an unauthenticated 302 pointed at a login endpoint is classified as the
// correct-behaviour state, not folded into the identical-responses failure
// just because it is "different" the same way every other divergent response
// is.
func TestClassifyAccessControlAnonRedirectedToLoginIsNotTreatedAsFailure(t *testing.T) {
	got := ClassifyAccessControl(200, 302, "<html>account page</html>", "", "https://app.test/login?next=/account", true)
	if got != ACEvidenceAnonRedirectedToLogin {
		t.Fatalf("ClassifyAccessControl with anon redirected to /login = %v, want ACEvidenceAnonRedirectedToLogin", got)
	}
}

// TestClassifyAccessControlAnonForbiddenIsCorrectBehaviour asserts that a 403
// (or 401) response to the unauthenticated request is recognised as the other
// correct-behaviour state.
func TestClassifyAccessControlAnonForbiddenIsCorrectBehaviour(t *testing.T) {
	for _, status := range []int{401, 403} {
		got := ClassifyAccessControl(200, status, "<html>account page</html>", "<html>forbidden</html>", "", true)
		if got != ACEvidenceAnonForbidden {
			t.Fatalf("ClassifyAccessControl with anon status %d = %v, want ACEvidenceAnonForbidden", status, got)
		}
	}
}

// TestClassifyAccessControlAnonPartialContentIsNeitherFailureNorSuccess
// asserts that a response which differs from the authenticated one but is
// neither a login redirect nor a rejection is flagged for manual review
// rather than silently swallowed as either "fine" or "broken".
func TestClassifyAccessControlAnonPartialContentIsNeitherFailureNorSuccess(t *testing.T) {
	got := ClassifyAccessControl(200, 200, "<html>full account page</html>", "<html>degraded preview</html>", "", true)
	if got != ACEvidenceAnonPartialContent {
		t.Fatalf("ClassifyAccessControl with a differing, non-blocked anon body = %v, want ACEvidenceAnonPartialContent", got)
	}
}

// ---------------------------------------------------------------------------
// AuthContextsFrom
// ---------------------------------------------------------------------------

// TestAuthContextsFromWithNoCookiesMarksAuthedContextAsHavingNoCredentials
// asserts the trap AuthContextsFrom exists to avoid: a coordinator that has
// never absorbed a cookie for the target authority must not silently hand
// back an "authenticated" context indistinguishable from the anonymous one —
// it must be marked HasCredentials == false so a caller cannot mistake a
// two-anonymous-request comparison for a real differential.
func TestAuthContextsFromWithNoCookiesMarksAuthedContextAsHavingNoCredentials(t *testing.T) {
	coord := session.NewCoordinator(zap.NewNop())

	authed, anon := AuthContextsFrom(coord, "app.test", 443, true, "/")

	if authed.HasCredentials {
		t.Fatalf("AuthContextsFrom on a coordinator with no cookies gave authed.HasCredentials = true, want false")
	}
	if authed.CookieHeader != "" {
		t.Fatalf("AuthContextsFrom on a coordinator with no cookies gave authed.CookieHeader = %q, want empty", authed.CookieHeader)
	}
	if anon.HasCredentials {
		t.Fatalf("AuthContextsFrom gave anon.HasCredentials = true, want false always")
	}
	if authed.Label != "authenticated" || anon.Label != "unauthenticated" {
		t.Fatalf("AuthContextsFrom labels = %q/%q, want authenticated/unauthenticated", authed.Label, anon.Label)
	}
}

// TestAuthContextsFromWithACookieMarksAuthedContextAsHavingCredentials asserts
// the positive path: once the coordinator has actually absorbed a Set-Cookie
// for the authority, AuthContextsFrom reports real credentials and carries
// the cookie header through, so the guard in the previous test is not simply
// hard-coded to always report false.
func TestAuthContextsFromWithACookieMarksAuthedContextAsHavingCredentials(t *testing.T) {
	coord := session.NewCoordinator(zap.NewNop())
	coord.HandleResponse("app.test", 443, true, 200, map[string]string{"Set-Cookie": "session=abc123"}, nil)

	authed, anon := AuthContextsFrom(coord, "app.test", 443, true, "/")

	if !authed.HasCredentials {
		t.Fatalf("AuthContextsFrom after absorbing a cookie gave authed.HasCredentials = false, want true")
	}
	if authed.CookieHeader != "session=abc123" {
		t.Fatalf("AuthContextsFrom after absorbing a cookie gave authed.CookieHeader = %q, want %q", authed.CookieHeader, "session=abc123")
	}
	if anon.CookieHeader != "" || anon.HasCredentials {
		t.Fatalf("AuthContextsFrom leaked credentials into the anon context: %+v", anon)
	}
}

// ---------------------------------------------------------------------------
// FindAntiCSRFTokens
// ---------------------------------------------------------------------------

// TestFindAntiCSRFTokensFindsRealTokenNamesInARealisticForm asserts that both
// an ASP.NET-style and a Django-style hidden token field are recognised in a
// form that also carries ordinary, non-token inputs — proving the match is
// selective, not "every hidden input is a token".
func TestFindAntiCSRFTokensFindsRealTokenNamesInARealisticForm(t *testing.T) {
	form := `<form method="post" action="/account/update">
		<input type="hidden" name="__RequestVerificationToken" value="CfDJ8abc...">
		<input type="hidden" name="csrfmiddlewaretoken" value="xyz789">
		<input type="text" name="displayName" value="Alice">
		<input type="email" name="email" value="alice@example.test">
		<button type="submit">Save</button>
	</form>`

	got := FindAntiCSRFTokens(form)

	want := map[string]bool{"__RequestVerificationToken": true, "csrfmiddlewaretoken": true}
	if len(got) != 2 {
		t.Fatalf("FindAntiCSRFTokens found %v, want exactly the two token fields %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("FindAntiCSRFTokens returned unexpected name %q, want one of %v", name, want)
		}
	}
}

// TestFindAntiCSRFTokensReturnsEmptyForOrdinaryInputsOnly asserts the negative
// case: a form with no token-shaped input name at all returns an empty
// result, not a false positive on an unrelated field.
func TestFindAntiCSRFTokensReturnsEmptyForOrdinaryInputsOnly(t *testing.T) {
	form := `<form method="post" action="/search">
		<input type="text" name="query" value="">
		<input type="hidden" name="page" value="1">
		<select name="sort"><option value="relevance">Relevance</option></select>
	</form>`

	got := FindAntiCSRFTokens(form)
	if len(got) != 0 {
		t.Fatalf("FindAntiCSRFTokens on a token-free form = %v, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// ClassifyCSRF
// ---------------------------------------------------------------------------

// TestClassifyCSRFSetsTokenNotValidatedWhenTokenRemovedRequestSucceeds asserts
// that a request which succeeds after its anti-CSRF token was stripped out
// entirely is flagged as token-not-validated, and nothing else.
func TestClassifyCSRFSetsTokenNotValidatedWhenTokenRemovedRequestSucceeds(t *testing.T) {
	withToken := ProbeOutcome{Status: 403, Body: "forbidden", Succeeded: false}
	withoutToken := ProbeOutcome{Status: 200, Body: "saved", Succeeded: true}
	crossOriginReferer := ProbeOutcome{Status: 403, Body: "forbidden", Succeeded: false}

	got := ClassifyCSRF(withToken, withoutToken, crossOriginReferer, true)

	if got != CSRFEvidenceTokenNotValidated {
		t.Fatalf("ClassifyCSRF with only the token-removed probe succeeding = %v, want exactly CSRFEvidenceTokenNotValidated", got)
	}
}

// TestClassifyCSRFSetsRefererNotValidatedWhenCrossOriginRefererSucceeds
// asserts that a request which succeeds with a cross-origin Referer is
// flagged as Referer-not-validated — the exact defence burp.Zg8u itself
// probes for (see the file-level doc comment).
func TestClassifyCSRFSetsRefererNotValidatedWhenCrossOriginRefererSucceeds(t *testing.T) {
	withToken := ProbeOutcome{Status: 403, Succeeded: false}
	withoutToken := ProbeOutcome{Status: 403, Succeeded: false}
	crossOriginReferer := ProbeOutcome{Status: 200, Body: "saved", Succeeded: true}

	got := ClassifyCSRF(withToken, withoutToken, crossOriginReferer, true)

	if got != CSRFEvidenceRefererNotValidated {
		t.Fatalf("ClassifyCSRF with only the cross-origin-Referer probe succeeding = %v, want exactly CSRFEvidenceRefererNotValidated", got)
	}
}

// TestClassifyCSRFSetsBothBitsWhenBothProbesSucceed asserts the two bits
// combine correctly: when both the token-removed probe AND the cross-origin
// Referer probe succeed, both corresponding bits are set together in one
// result, not just the strongest one.
func TestClassifyCSRFSetsBothBitsWhenBothProbesSucceed(t *testing.T) {
	withToken := ProbeOutcome{Status: 403, Succeeded: false}
	withoutToken := ProbeOutcome{Status: 200, Succeeded: true}
	crossOriginReferer := ProbeOutcome{Status: 200, Succeeded: true}

	got := ClassifyCSRF(withToken, withoutToken, crossOriginReferer, true)

	if got&CSRFEvidenceTokenNotValidated == 0 {
		t.Fatalf("ClassifyCSRF %v is missing CSRFEvidenceTokenNotValidated when the token-removed probe succeeded", got)
	}
	if got&CSRFEvidenceRefererNotValidated == 0 {
		t.Fatalf("ClassifyCSRF %v is missing CSRFEvidenceRefererNotValidated when the cross-origin-Referer probe succeeded", got)
	}
	if got&CSRFEvidenceTokenNotBoundToSession != 0 {
		t.Fatalf("ClassifyCSRF %v unexpectedly set CSRFEvidenceTokenNotBoundToSession when the foreign-session probe did not succeed", got)
	}
}

// TestClassifyCSRFSetsTokenNotBoundToSessionWhenAForeignSessionTokenSucceeds
// asserts the third probe: a request that succeeds carrying a syntactically
// valid token from a DIFFERENT session proves the server checks only "a
// token is present", not "this session's token is present".
func TestClassifyCSRFSetsTokenNotBoundToSessionWhenAForeignSessionTokenSucceeds(t *testing.T) {
	withToken := ProbeOutcome{Status: 200, Body: "saved", Succeeded: true}
	withoutToken := ProbeOutcome{Status: 403, Succeeded: false}
	crossOriginReferer := ProbeOutcome{Status: 403, Succeeded: false}

	got := ClassifyCSRF(withToken, withoutToken, crossOriginReferer, true)

	if got != CSRFEvidenceTokenNotBoundToSession {
		t.Fatalf("ClassifyCSRF with only the foreign-session-token probe succeeding = %v, want exactly CSRFEvidenceTokenNotBoundToSession", got)
	}
}

// TestClassifyCSRFSetsSameSiteAbsentWhenCookieHasNoSameSiteAttribute asserts
// the SameSite bit is driven purely by the sameSitePresent flag and is
// independent of every probe outcome.
func TestClassifyCSRFSetsSameSiteAbsentWhenCookieHasNoSameSiteAttribute(t *testing.T) {
	allDefended := ProbeOutcome{Status: 403, Succeeded: false}

	got := ClassifyCSRF(allDefended, allDefended, allDefended, false)

	if got != CSRFEvidenceSameSiteAbsent {
		t.Fatalf("ClassifyCSRF with every probe defended but sameSitePresent=false = %v, want exactly CSRFEvidenceSameSiteAbsent", got)
	}
}

// TestClassifyCSRFReturnsZeroWhenEveryDefenceHolds asserts the clean case: no
// probe succeeded and SameSite is present, so no bit is set at all, and
// Text() reports that plainly rather than an empty string.
func TestClassifyCSRFReturnsZeroWhenEveryDefenceHolds(t *testing.T) {
	allDefended := ProbeOutcome{Status: 403, Succeeded: false}

	got := ClassifyCSRF(allDefended, allDefended, allDefended, true)

	if got != 0 {
		t.Fatalf("ClassifyCSRF with every defence holding = %v, want 0", got)
	}
	if got.Text() == "" {
		t.Fatalf("CSRFEvidence(0).Text() returned empty; want an explicit no-weakness statement")
	}
}

// ---------------------------------------------------------------------------
// DifferentialSender end-to-end (no network)
// ---------------------------------------------------------------------------

// fakeDifferentialSender is a network-free DifferentialSender: it returns a
// canned response keyed by the AuthContext's Label, so a test can drive the
// full AuthContextsFrom -> SendWithAuth -> ClassifyAccessControl pipeline
// without a real sender or session.Coordinator wiring.
type fakeDifferentialSender struct {
	byLabel map[string]struct {
		status int
		body   string
	}
}

// Compile-time proof that fakeDifferentialSender genuinely satisfies
// DifferentialSender, so a signature drift on the interface fails this test
// file to build rather than silently stranding the fake.
var _ DifferentialSender = (*fakeDifferentialSender)(nil)

func (f *fakeDifferentialSender) SendWithAuth(_ context.Context, _ string, auth AuthContext) (int, map[string]string, string, error) {
	resp := f.byLabel[auth.Label]
	return resp.status, nil, resp.body, nil
}

// TestFakeDifferentialSenderDrivesClassifyAccessControlEndToEnd asserts the
// whole seam wires together: a fake DifferentialSender stands in for a real
// authorised sender, AuthContextsFrom supplies the two identities from a real
// (cookie-bearing) session.Coordinator, and ClassifyAccessControl reaches the
// correct verdict from what the fake returned — proving DifferentialSender is
// a genuine, usable seam and not a decorative interface nothing exercises.
func TestFakeDifferentialSenderDrivesClassifyAccessControlEndToEnd(t *testing.T) {
	coord := session.NewCoordinator(zap.NewNop())
	coord.HandleResponse("app.test", 443, true, 200, map[string]string{"Set-Cookie": "session=abc123"}, nil)
	authed, anon := AuthContextsFrom(coord, "app.test", 443, true, "/")

	sender := &fakeDifferentialSender{byLabel: map[string]struct {
		status int
		body   string
	}{
		"authenticated":   {status: 200, body: "<html>account page</html>"},
		"unauthenticated": {status: 200, body: "<html>account page</html>"},
	}}

	authedStatus, _, authedBody, err := sender.SendWithAuth(context.Background(), "/account", authed)
	if err != nil {
		t.Fatalf("SendWithAuth(authed): %v", err)
	}
	anonStatus, _, anonBody, err := sender.SendWithAuth(context.Background(), "/account", anon)
	if err != nil {
		t.Fatalf("SendWithAuth(anon): %v", err)
	}

	got := ClassifyAccessControl(authedStatus, anonStatus, authedBody, anonBody, "", authed.HasCredentials)
	if got != ACEvidenceIdenticalResponses {
		t.Fatalf("end-to-end ClassifyAccessControl = %v, want ACEvidenceIdenticalResponses", got)
	}
}
