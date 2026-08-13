package scanner

// End-to-end tests for the wired passive evaluators. The pure analysers are covered by
// infra_forms_test.go, infra_response_test.go and infra_transport_test.go; what these tests
// add is the wiring — that the runner reads the right part of the exchange, and that a
// finding actually comes out with the catalog name attached.

import (
	"context"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// postureFixture seeds one exchange with full control over the request line, TLS flag and
// raw response, which the transport and override checks all need.
func postureFixture(t *testing.T, rawRequest, rawResponse string, tls bool) *CheckContext {
	t.Helper()
	store := core.NewTrafficStore()
	reqID, err := store.Put([]byte(rawRequest), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte(rawResponse), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	method, path := "GET", "/"
	if fields := strings.Fields(rawRequest); len(fields) >= 2 {
		method, path = fields[0], fields[1]
	}
	port := uint16(80)
	if tls {
		port = 443
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: "app.test", Port: port,
		TLS: tls, Method: method, Path: path}
	store.AddExchange(ex)
	return NewCheckContext(NewActiveScanner(store, zap.NewNop()), ex, nil)
}

func htmlResponse(body string, extraHeaders ...string) string {
	head := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	for _, h := range extraHeaders {
		head += h + "\r\n"
	}
	return head + "\r\n" + body
}

func runPosture(t *testing.T, fn func(context.Context, *CheckContext) ([]*Finding, error), cc *CheckContext) []*Finding {
	t.Helper()
	got, err := fn(context.Background(), cc)
	if err != nil {
		t.Fatalf("check returned error: %v", err)
	}
	return got
}

func requireOneFinding(t *testing.T, got []*Finding, wantName string) *Finding {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Name != wantName {
		t.Fatalf("finding name = %q, want %q", got[0].Name, wantName)
	}
	if got[0].URL == "" {
		t.Errorf("finding is not attributed to a URL: %+v", got[0])
	}
	// Remediation must be whatever the catalog holds — including empty. Burp ships no
	// remediation text for some info-level rows ("Cross-domain POST" is one), so demanding
	// a non-empty string would be asserting a property the evidence does not have.
	def, ok := ByName(wantName)
	if !ok {
		t.Fatalf("%q is not in the catalog", wantName)
	}
	if got[0].Solution != def.Remediation {
		t.Errorf("remediation was not passed through from the catalog entry for %q", wantName)
	}
	return got[0]
}

// ---------- password handling ----------

func TestWiredCleartextPasswordSubmissionFires(t *testing.T) {
	cc := postureFixture(t, "GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<form action="http://app.test/login" method="post"><input type="password" name="p"></form>`), true)
	f := requireOneFinding(t, runPosture(t, checkCleartextPasswordSubmission, cc), "Cleartext submission of password")
	if !strings.Contains(f.Evidence, "http://app.test/login") {
		t.Errorf("evidence does not name the action: %q", f.Evidence)
	}
}

func TestWiredCleartextPasswordSubmissionStaysQuietOnHTTPSAction(t *testing.T) {
	cc := postureFixture(t, "GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<form action="/login" method="post"><input type="password" name="p"></form>`), true)
	if got := runPosture(t, checkCleartextPasswordSubmission, cc); len(got) != 0 {
		t.Fatalf("got %d findings on an https form, want 0", len(got))
	}
}

func TestWiredPasswordViaGETFires(t *testing.T) {
	cc := postureFixture(t, "GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<form action="/login"><input type="password" name="p"></form>`), true)
	requireOneFinding(t, runPosture(t, checkPasswordSubmittedUsingGET, cc), "Password submitted using GET method")
}

func TestWiredPasswordAutocompleteFires(t *testing.T) {
	cc := postureFixture(t, "GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<form action="/login" method="post"><input type="password" name="p"></form>`), true)
	requireOneFinding(t, runPosture(t, checkPasswordAutocomplete, cc), "Password field with autocomplete enabled")
}

func TestWiredPasswordAutocompleteHonoursOff(t *testing.T) {
	cc := postureFixture(t, "GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<form action="/login" method="post" autocomplete="off"><input type="password" name="p"></form>`), true)
	if got := runPosture(t, checkPasswordAutocomplete, cc); len(got) != 0 {
		t.Fatalf("got %d findings with autocomplete=off, want 0", len(got))
	}
}

func TestWiredPasswordInURLQueryReadsTheRequestPath(t *testing.T) {
	cc := postureFixture(t, "GET /login?password=hunter2 HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok"), true)
	requireOneFinding(t, runPosture(t, checkPasswordInURLQuery, cc), "Password returned in URL query string")
}

func TestWiredPasswordInCookieReadsSetCookie(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Set-Cookie: userPassword=hunter2; Path=/"), true)
	requireOneFinding(t, runPosture(t, checkPasswordInCookie, cc), "Password value set in cookie")
}

func TestWiredPasswordInCookieIgnoresASessionCookie(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Set-Cookie: session=abc; Path=/"), true)
	if got := runPosture(t, checkPasswordInCookie, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a session cookie, want 0", len(got))
	}
}

// ---------- cross-domain POST ----------

func TestWiredCrossDomainPOSTFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<form action="https://evil.test/collect" method="post"><input name="x"></form>`), true)
	requireOneFinding(t, runPosture(t, checkCrossDomainPOST, cc), "Cross-domain POST")
}

// A cross-domain GET form is not this row: the issue is POSTing data off-site.
func TestWiredCrossDomainPOSTIgnoresGETForms(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<form action="https://search.test/q" method="get"><input name="q"></form>`), true)
	if got := runPosture(t, checkCrossDomainPOST, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a cross-domain GET form, want 0", len(got))
	}
}

// ---------- response shape ----------

func TestWiredRequestURLOverrideReadsRequestHeaders(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\nX-Original-URL: /admin\r\n\r\n",
		htmlResponse("ok"), true)
	f := requireOneFinding(t, runPosture(t, checkRequestURLOverride, cc), "Request URL override")
	if !strings.Contains(f.Evidence, "X-Original-URL") {
		t.Errorf("evidence does not name the header: %q", f.Evidence)
	}
}

func TestWiredLongRedirectionResponseFires(t *testing.T) {
	body := strings.Repeat("A", LongRedirectBodyBytes+1)
	raw := "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Type: text/html\r\n\r\n" + body
	cc := postureFixture(t, "GET /go HTTP/1.1\r\nHost: app.test\r\n\r\n", raw, true)
	requireOneFinding(t, runPosture(t, checkLongRedirectionResponse, cc), "Long redirection response")
}

func TestWiredLongRedirectionIgnoresAShortRedirect(t *testing.T) {
	raw := "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\n\r\nmoved"
	cc := postureFixture(t, "GET /go HTTP/1.1\r\nHost: app.test\r\n\r\n", raw, true)
	if got := runPosture(t, checkLongRedirectionResponse, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a short redirect body, want 0", len(got))
	}
}

func TestWiredMultipleContentTypesFires(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Type: application/json\r\n\r\nbody"
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", raw, true)
	requireOneFinding(t, runPosture(t, checkMultipleContentTypes, cc), "Multiple content types specified")
}

func TestWiredContentTypeNotSpecifiedFires(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nServer: x\r\n\r\nsome body content"
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", raw, true)
	requireOneFinding(t, runPosture(t, checkContentTypeNotSpecified, cc), "Content type is not specified")
}

func TestWiredContentTypeNotSpecifiedIgnoresAnEmptyBody(t *testing.T) {
	raw := "HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n"
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", raw, true)
	if got := runPosture(t, checkContentTypeNotSpecified, cc); len(got) != 0 {
		t.Fatalf("got %d findings on an empty body, want 0", len(got))
	}
}

func TestWiredRefererLeakageNeedsAQueryString(t *testing.T) {
	body := `<a href="https://third.test/x">out</a>`
	withQuery := postureFixture(t, "GET /p?token=abc HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse(body), true)
	requireOneFinding(t, runPosture(t, checkCrossDomainRefererLeakage, withQuery), "Cross-domain Referer leakage")

	noQuery := postureFixture(t, "GET /p HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse(body), true)
	if got := runPosture(t, checkCrossDomainRefererLeakage, noQuery); len(got) != 0 {
		t.Fatalf("got %d findings with nothing in the URL to leak, want 0", len(got))
	}
}

func TestWiredRefererLeakageIsSuppressedByPolicy(t *testing.T) {
	cc := postureFixture(t, "GET /p?token=abc HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<a href="https://third.test/x">out</a>`, "Referrer-Policy: no-referrer"), true)
	if got := runPosture(t, checkCrossDomainRefererLeakage, cc); len(got) != 0 {
		t.Fatalf("got %d findings despite Referrer-Policy: no-referrer, want 0", len(got))
	}
}

// ---------- transport posture ----------

func TestWiredUnencryptedCommunicationsFiresOnHTTP(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), false)
	requireOneFinding(t, runPosture(t, checkUnencryptedCommunications, cc), "Unencrypted communications")
}

func TestWiredUnencryptedCommunicationsQuietOnHTTPS(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	if got := runPosture(t, checkUnencryptedCommunications, cc); len(got) != 0 {
		t.Fatalf("got %d findings over TLS, want 0", len(got))
	}
}

func TestWiredHSTSFiresWhenAbsentOverTLS(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), true)
	requireOneFinding(t, runPosture(t, checkStrictTransportSecurity, cc), "Strict transport security not enforced")
}

// max-age=0 is present but disables the policy; the finding must still fire and say so.
func TestWiredHSTSFiresOnMaxAgeZeroAndExplainsWhy(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Strict-Transport-Security: max-age=0"), true)
	f := requireOneFinding(t, runPosture(t, checkStrictTransportSecurity, cc), "Strict transport security not enforced")
	if !strings.Contains(f.Description, "does not commit") {
		t.Errorf("detail should explain that the present header does not enforce: %q", f.Description)
	}
}

func TestWiredHSTSQuietOnAValidHeader(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("ok", "Strict-Transport-Security: max-age=63072000"), true)
	if got := runPosture(t, checkStrictTransportSecurity, cc); len(got) != 0 {
		t.Fatalf("got %d findings with a valid HSTS header, want 0", len(got))
	}
}

func TestWiredHSTSNotReportedOverCleartext(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), false)
	if got := runPosture(t, checkStrictTransportSecurity, cc); len(got) != 0 {
		t.Fatalf("got %d findings over cleartext, where the header is defined to be ignored", len(got))
	}
}

func TestWiredCacheableHTTPSResponseFires(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("secret"), true)
	requireOneFinding(t, runPosture(t, checkCacheableHTTPSResponse, cc), "Cacheable HTTPS response")
}

func TestWiredCacheableHTTPSResponseQuietOnNoStore(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse("secret", "Cache-Control: no-store"), true)
	if got := runPosture(t, checkCacheableHTTPSResponse, cc); len(got) != 0 {
		t.Fatalf("got %d findings with no-store, want 0", len(got))
	}
}

// The row is "Cacheable HTTPS response". A cleartext response with no cache directives is
// not it, and reporting one would name a condition the exchange does not have.
func TestWiredCacheableHTTPSResponseNotReportedOverCleartext(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("secret"), false)
	if got := runPosture(t, checkCacheableHTTPSResponse, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a cleartext response, want 0", len(got))
	}
}

func TestWiredMixedContentRaisesSeverityForActiveSubresources(t *testing.T) {
	active := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<script src="http://cdn.test/a.js"></script>`), true)
	f := requireOneFinding(t, runPosture(t, checkMixedContent, active), "Mixed content")
	if f.Severity != "low" {
		t.Errorf("severity = %q, want low for an active subresource", f.Severity)
	}

	passive := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<img src="http://cdn.test/a.png">`), true)
	f = requireOneFinding(t, runPosture(t, checkMixedContent, passive), "Mixed content")
	if f.Severity != "info" {
		t.Errorf("severity = %q, want info for a passive subresource", f.Severity)
	}
}

func TestWiredMixedContentQuietOnCleartextPage(t *testing.T) {
	cc := postureFixture(t, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
		htmlResponse(`<script src="http://cdn.test/a.js"></script>`), false)
	if got := runPosture(t, checkMixedContent, cc); len(got) != 0 {
		t.Fatalf("got %d findings on a cleartext page, want 0", len(got))
	}
}

// ---------- wiring invariants ----------

func TestEveryPassivePostureDescriptorIsRunnableAndGated(t *testing.T) {
	descs := PassivePostureCheckDescriptors()
	if len(descs) != 15 {
		t.Fatalf("got %d descriptors, want 15", len(descs))
	}
	for _, d := range descs {
		if !d.Runnable() {
			t.Errorf("%q is not runnable", d.Name)
		}
		if !d.Valid() {
			t.Errorf("%q is not Valid()", d.Name)
		}
		if d.Enabled == nil || d.Enabled(&ScanConfig{}) {
			t.Errorf("%q is admitted with the flag off; every family switch is off by default", d.Name)
		}
		if !d.Enabled(&ScanConfig{CheckPassivePosture: true}) {
			t.Errorf("%q is not admitted with CheckPassivePosture set", d.Name)
		}
	}
}

// A check must never fire on an exchange with no scanner or no response, which is the state
// the dispatcher can hand it for a request that never got a reply.
func TestPassivePostureChecksTolerateAMissingResponse(t *testing.T) {
	runners := []func(context.Context, *CheckContext) ([]*Finding, error){
		checkCleartextPasswordSubmission, checkPasswordSubmittedUsingGET, checkPasswordAutocomplete,
		checkPasswordInURLQuery, checkPasswordInCookie, checkCrossDomainPOST,
		checkRequestURLOverride, checkLongRedirectionResponse, checkMultipleContentTypes,
		checkContentTypeNotSpecified, checkCrossDomainRefererLeakage,
		checkUnencryptedCommunications, checkStrictTransportSecurity,
		checkCacheableHTTPSResponse, checkMixedContent,
	}
	for i, fn := range runners {
		got, err := fn(context.Background(), &CheckContext{})
		if err != nil {
			t.Errorf("runner %d errored on an empty context: %v", i, err)
		}
		if len(got) != 0 {
			t.Errorf("runner %d produced %d findings from an empty context", i, len(got))
		}
	}
}
