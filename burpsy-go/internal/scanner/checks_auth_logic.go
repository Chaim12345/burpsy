package scanner

// Authentication logic checks: missing login rate limiting (CWE-307) and username enumeration
// (CWE-204). Both rows are burpsy's own (burpsy_rows.go, advisories in internal/advisory/native):
// Burp's catalogue has neither. The checks ride the "Broken access control" descriptor behind their
// own switches (brokenAccessControlWithAuthLogic), so they run in that row's (light) tier and per-URL
// dispatch scope.
//
// # Which requests they act on
//
// A request is login-shaped when it carries an IDENTITY parameter (a username, login, account or
// e-mail field) and a SECRET parameter (a password field or a one-time code). Names are read from
// the query string and the body (form, JSON, XML), never guessed or appended. A request that looks
// like registration, a password change or a password reset - a second password field, a "confirm"
// or "new" field, or a path segment naming one of those flows - is left alone, because sending it
// repeatedly would create accounts or change passwords rather than fail a login. Nothing here acts
// on an identity-only request (a "forgot password" or "send me a code" form), because repeating it
// would send mail or SMS to a real person.
//
// # Missing rate limiting: what is claimed
//
// On a POST/PUT/PATCH login, the identity is replaced by one this check INVENTS (a random name, at
// the captured e-mail's domain when it is an e-mail) and the secret by a random wrong value, and a
// burst of attempts is sent one after another (LoginRateLimitAttempts, default 20). The row is
// reported only when:
//
//   - the endpoint demonstrably evaluates the credentials: the failed attempt is answered with HTTP
//     401, or differs from the captured exchange's own response once the submitted values are
//     masked, or says that authentication failed. An endpoint that ignores the fields answers
//     every request the same way too, and that sameness is not evidence of anything;
//   - every attempt got the same answer once dynamic tokens are masked - status, redirect target
//     and body. Any change across the burst (a lockout page, a CAPTCHA appearing, a different
//     status) is a defence engaging, and the check stops;
//   - no attempt was throttled: no 429 or 503, no Retry-After or rate-limit header, no "too many
//     attempts"/"locked"/CAPTCHA wording, and no growing delay (the last attempts' median latency
//     more than twice the first's and at least 750ms slower).
//
// It is reported TENTATIVE: an application that only throttles accounts that exist cannot be told
// apart from one that throttles nothing, because the check refuses to lock a real account to find
// out. The finding says so.
//
// # Username enumeration: what is claimed
//
// The captured username and three invented ones (same shape: an e-mail stays an e-mail at the same
// domain) are each sent with a random wrong password, interleaved: invented, captured, invented,
// captured, invented. Reported only when the captured username's two answers are identical, the three
// invented usernames' answers are identical, and the two sides differ - in status, redirect target or
// body, after masking the submitted values and dynamic tokens. A captured username that does not
// exist answers like the invented ones and is correctly not reported. Timing is recorded in the
// evidence but never decides: a latency difference alone is not reported.
//
// # Safety
//
// No real password is ever sent: every secret is random, and the captured request is never replayed
// as captured (no baseline is sent - the captured response is read from the store instead). The
// rate-limit burst never names a real account, so it cannot lock one. The enumeration check sends a
// real username exactly twice, each with a random wrong password. Every request goes out through the
// scope-enforcing gate like every other probe.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// Burst size bounds for the rate-limit check.
const (
	DefaultLoginRateLimitAttempts = 20
	MinLoginRateLimitAttempts     = 5
	MaxLoginRateLimitAttempts     = 100
)

// loginRateLimitEnabled and usernameEnumerationEnabled are the checks' own switches.
func loginRateLimitEnabled(c *ScanConfig) bool      { return c != nil && c.CheckLoginRateLimit }
func usernameEnumerationEnabled(c *ScanConfig) bool { return c != nil && c.CheckUsernameEnumeration }

// loginRateLimitAttempts is the configured burst, defaulted and clamped.
func loginRateLimitAttempts(c *ScanConfig) int {
	n := DefaultLoginRateLimitAttempts
	if c != nil && c.LoginRateLimitAttempts > 0 {
		n = c.LoginRateLimitAttempts
	}
	return min(max(n, MinLoginRateLimitAttempts), MaxLoginRateLimitAttempts)
}

// The burpsy-own rows these checks report (burpsy_rows.go; advisories in internal/advisory/native).
const (
	IssueLoginRateLimitMissing = "Authentication attempts not rate limited"
	IssueUsernameEnumeration   = "Username enumeration"
)

// brokenAccessControlWithAuthLogic adds the two authentication checks to the "Broken access control"
// descriptor's runner, each behind its own switch: the registry admits one descriptor per Burp
// catalogue type, and burpsy's own rows ride an existing one (burpsy_rows.go). A finding from either
// half is returned even when the other half failed, as brokenAccessControlOrIDOR does.
func brokenAccessControlWithAuthLogic(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		var innerF []*Finding
		var innerErr error
		if finalChecksEnabled(cc.Config) || idorEnabled(cc.Config) || bflaEnabled(cc.Config) {
			innerF, innerErr = inner(ctx, cc)
		}
		var authF []*Finding
		var authErr error
		for _, c := range []struct {
			on  bool
			run CheckRunner
		}{{loginRateLimitEnabled(cc.Config), checkLoginRateLimit}, {usernameEnumerationEnabled(cc.Config), checkUsernameEnumeration}} {
			if !c.on {
				continue
			}
			f, err := c.run(ctx, cc)
			authF = append(authF, f...)
			if err != nil && authErr == nil {
				authErr = err
			}
		}
		switch {
		case len(authF) > 0:
			return append(innerF, authF...), nil
		case innerErr != nil:
			return innerF, innerErr
		case authErr != nil:
			return nil, authErr
		}
		return innerF, nil
	}
}

// ---------------------------------------------------------------------------
// Recognising a login
// ---------------------------------------------------------------------------

type secretKind int

const (
	secretPassword secretKind = iota + 1
	secretOTP
)

// loginPoints is the identity and secret parameter of one login-shaped request.
type loginPoints struct {
	identity bcheck.InsertionPoint
	secret   bcheck.InsertionPoint
	kind     secretKind
}

// normParamName folds a parameter name to lower-case letters and digits, after its last path
// component (a JSON key `user.password` or `creds[password]` is read as `password`).
func normParamName(name string) string {
	if i := strings.LastIndexAny(name, ".["); i >= 0 && i+1 < len(name) {
		rest := strings.TrimSuffix(name[i+1:], "]")
		if rest != "" && !isAllDigits(rest) {
			name = rest
		}
	}
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isPasswordName recognises a password field.
func isPasswordName(n string) bool {
	switch n {
	case "pass", "pwd", "passwd", "passphrase", "passw", "pword", "pw":
		return true
	}
	return strings.Contains(n, "password") || strings.Contains(n, "passwd") || strings.HasSuffix(n, "pwd")
}

// isOTPName recognises a one-time-code field. A bare "code" is deliberately not one: it is far more
// often an OAuth authorisation code, a country code or a promotion code.
func isOTPName(n string) bool {
	switch n {
	case "otp", "totp", "hotp", "pin", "passcode", "mfa", "2fa", "tfa", "smscode", "mfacode", "otpcode",
		"twofactorcode", "verificationcode", "verifycode", "onetimecode", "onetimepassword", "authcode2fa":
		return true
	}
	return strings.HasPrefix(n, "otp") || strings.HasSuffix(n, "otp") || strings.Contains(n, "totp") ||
		strings.Contains(n, "onetime") || strings.Contains(n, "twofactor") || strings.Contains(n, "mfacode") ||
		strings.Contains(n, "2facode")
}

// isIdentityName recognises a username / login / e-mail field.
func isIdentityName(n string) bool {
	switch n {
	case "user", "username", "uname", "usr", "login", "loginid", "loginname", "email", "mail", "emailaddress",
		"account", "accountname", "acct", "userid", "useremail", "principal", "identifier", "j_username",
		"phone", "mobile", "msisdn", "phonenumber":
		return true
	}
	return strings.Contains(n, "username") || strings.Contains(n, "email") || strings.HasSuffix(n, "login") ||
		strings.HasPrefix(n, "login") || strings.HasSuffix(n, "user") || strings.HasSuffix(n, "userid")
}

// notALoginName marks a field that only registration, a password change or a reset carries.
func notALoginName(n string) bool {
	for _, w := range []string{"confirm", "repeat", "retype", "again", "newpass", "oldpass", "currentpass",
		"verifypass", "password2", "passwordconfirmation", "firstname", "lastname", "fullname"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// nonLoginPathRE matches a path segment naming a flow whose repetition is not a failed login.
var nonLoginPathRE = regexp.MustCompile(`(?i)(^|[/._-])(register|registration|signup|sign-up|sign_up|join|enrol|enroll|` +
	`create|new|invite|reset|forgot|recover|recovery|change|changepassword|update|delete|remove)([/._-]|$)`)

// findLoginPoints returns the identity and secret points of a login-shaped request, or ok=false.
func findLoginPoints(raw []byte, path string, opts bcheck.EnumerateOptions) (loginPoints, bool) {
	if nonLoginPathRE.MatchString(strings.SplitN(path, "?", 2)[0]) {
		return loginPoints{}, false
	}
	pts, _ := bcheck.EnumerateWith(raw, []string{"query", "body"}, opts)
	var ids, pws, otps []bcheck.InsertionPoint
	for _, p := range pts {
		if p.Kind != bcheck.IpQuery && p.Kind != bcheck.IpBody {
			continue
		}
		n := normParamName(p.Name)
		if n == "" {
			continue
		}
		if notALoginName(n) {
			return loginPoints{}, false
		}
		switch {
		case isPasswordName(n):
			pws = append(pws, p)
		case isOTPName(n):
			otps = append(otps, p)
		case isIdentityName(n):
			ids = append(ids, p)
		}
	}
	// Exactly one identity and one secret. Two password fields is a change or a registration form; two
	// identities cannot be told apart.
	if len(ids) != 1 || len(pws)+len(otps) != 1 {
		return loginPoints{}, false
	}
	lp := loginPoints{identity: ids[0]}
	if len(pws) == 1 {
		lp.secret, lp.kind = pws[0], secretPassword
	} else {
		lp.secret, lp.kind = otps[0], secretOTP
	}
	return lp, true
}

// decodedValue is a point's value as the application reads it.
func decodedValue(p bcheck.InsertionPoint) string {
	v := p.BaseValue
	if strings.ContainsAny(v, "%+") {
		if d, err := url.QueryUnescape(v); err == nil {
			v = d
		}
	}
	if strings.Contains(v, `\`) {
		if d, err := strconv.Unquote(`"` + v + `"`); err == nil {
			v = d
		}
	}
	return v
}

// withCredentials builds the request with the identity and secret replaced. The second point is
// found again in the rewritten request, because the first replacement moves every offset after it.
func withCredentials(raw []byte, lp loginPoints, identity, secret string, opts bcheck.EnumerateOptions) ([]byte, error) {
	idp := lp.identity
	out, err := idp.Apply(raw, identity, false)
	if err != nil {
		return nil, err
	}
	pts, _ := bcheck.EnumerateWith(out, []string{"query", "body"}, opts)
	for i := range pts {
		if pts[i].Kind == lp.secret.Kind && pts[i].Name == lp.secret.Name {
			return pts[i].Apply(out, secret, false)
		}
	}
	return nil, fmt.Errorf("the %s parameter %q was not found again after the identity was replaced", lp.secret.Kind, lp.secret.Name)
}

// ---------------------------------------------------------------------------
// Invented values
// ---------------------------------------------------------------------------

func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func randDigits(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		b.WriteByte(byte('0' + d.Int64()))
	}
	return b.String()
}

// inventIdentity returns an identity of the captured one's shape that no real account holds: an
// e-mail stays an e-mail at the same domain (so a domain allowlist answers it like a real one), a
// numeric identity gets six more digits than the captured one, anything else a random lower-case
// name.
func inventIdentity(captured string) string {
	if at := strings.LastIndex(captured, "@"); at > 0 && at < len(captured)-1 {
		return "bsy" + randHex(10) + captured[at:]
	}
	if isAllDigits(captured) {
		return "9" + randDigits(len(captured)+5)
	}
	return "bsy" + randHex(10)
}

// inventSecret returns a random wrong secret. A one-time code keeps the captured code's length when
// that is a plausible code length, so a format check does not answer it differently.
func inventSecret(kind secretKind, captured string) string {
	if kind == secretOTP {
		n := 6
		if isAllDigits(captured) && len(captured) >= 4 && len(captured) <= 8 {
			n = len(captured)
		}
		return randDigits(n)
	}
	return "Bsy!" + randHex(12)
}

// ---------------------------------------------------------------------------
// Comparing answers
// ---------------------------------------------------------------------------

var (
	authUUIDRE   = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	authHexRE    = regexp.MustCompile(`(?i)\b[0-9a-f]{8,}\b`)
	authTokenRE  = regexp.MustCompile(`[A-Za-z0-9+/_\-]{24,}={0,2}`)
	authDigitsRE = regexp.MustCompile(`[0-9]+`)
)

// authFingerprint is what two answers to a login are compared on: status, redirect target and body,
// with every submitted value (in its plain, URL-, HTML- and JSON-escaped spellings) and every dynamic
// token masked. Two answers with the same fingerprint are the same answer.
func authFingerprint(r ProbeResponse, submitted []string) string {
	body := maskSubmitted(r.Body, submitted)
	loc := maskSubmitted(headerValue(string(r.Raw), "Location"), submitted)
	return strconv.Itoa(r.Status) + "\x00" + maskDynamic(loc) + "\x00" + maskDynamic(body)
}

func maskSubmitted(s string, submitted []string) string {
	var forms []string
	for _, v := range submitted {
		if v == "" {
			continue
		}
		forms = append(forms, v, url.QueryEscape(v), url.PathEscape(v), html.EscapeString(v),
			strings.Trim(strconv.Quote(v), `"`))
	}
	// Longest first, so a value is never half-replaced by a shorter one it contains.
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	for _, f := range forms {
		s = strings.ReplaceAll(s, f, "\x01v\x01")
	}
	return s
}

func maskDynamic(s string) string {
	s = authUUIDRE.ReplaceAllString(s, "\x01u\x01")
	s = authTokenRE.ReplaceAllString(s, "\x01t\x01")
	s = authHexRE.ReplaceAllString(s, "\x01h\x01")
	return authDigitsRE.ReplaceAllString(s, "0")
}

// authFailureRE recognises an answer that says an authentication attempt failed.
var authFailureRE = regexp.MustCompile(`(?i)(` +
	`\b(invalid|incorrect|wrong|bad|unknown|unrecogni[sz]ed)\s+(user\s*name|username|user|password|passcode|credentials?|login|e-?mail|otp|one[- ]time\s+(code|password)|code|pin|account)\b` +
	`|\b(log\s*in|login|sign[- ]?in|authentication|verification)\s+(failed|unsuccessful|error|denied|rejected)\b` +
	`|\b(credentials|password|otp|code)\s+(is\s+|are\s+|was\s+|were\s+)?(invalid|incorrect|wrong|not\s+valid|did\s+not\s+match|do\s+not\s+match)\b` +
	`|\b(user(name)?|account)\s+(not\s+found|does\s+not\s+exist|doesn't\s+exist)\b` +
	`|\bauthentication\s+required\b|\bunauthori[sz]ed\b)`)

// throttleTextRE recognises an answer that says attempts are being throttled. A bare mention of
// "rate limit" is not one ("this form is not rate limited" is a sentence, not a defence); the
// throttle has to be stated as engaging.
var throttleTextRE = regexp.MustCompile(`(?i)(too\s+many|try\s+again\s+(later|in|after)|temporarily\s+(locked|blocked|disabled|suspended)|` +
	`account\s+(is\s+|has\s+been\s+)?(locked|blocked|suspended|disabled)|locked\s+out|captcha|slow\s+down|` +
	`rate[- ]?limit(ed|ing)?\s+(exceeded|reached|applied|active)|limit\s+exceeded|retry\s+after|exceeded\s+the\s+(maximum|number))`)

// throttleSignal names the first sign of throttling in one answer, or "".
func throttleSignal(r ProbeResponse) string {
	if r.Status == 429 || r.Status == 503 {
		return fmt.Sprintf("HTTP %d", r.Status)
	}
	raw := string(r.Raw)
	if v := headerValue(raw, "Retry-After"); v != "" {
		return "a Retry-After header"
	}
	head := raw
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head = raw[:i]
	}
	for _, line := range strings.Split(head, "\r\n") {
		name := strings.ToLower(strings.TrimSpace(strings.SplitN(line, ":", 2)[0]))
		if strings.HasPrefix(name, "x-ratelimit") || strings.HasPrefix(name, "ratelimit") ||
			strings.HasPrefix(name, "x-rate-limit") {
			return "a " + name + " header"
		}
	}
	if m := throttleTextRE.FindString(r.Body); m != "" {
		return fmt.Sprintf("the text %q", m)
	}
	return ""
}

// unusableLoginStatus is a status whose answer says nothing about a credential check: the route is
// missing or refuses the method, the server failed, or a gateway in front blocked the request.
func unusableLoginStatus(st int) bool {
	return st == 0 || st == 403 || st == 404 || st == 405 || st >= 500
}

func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

// authProbe holds what both checks need: the captured request, its login points, and a sender that
// never replays the captured request as it was (no baseline: that would re-send a real password).
type authProbe struct {
	cc   *CheckContext
	h    *ProbeHarness
	raw  []byte
	lp   loginPoints
	opts bcheck.EnumerateOptions
}

func newAuthProbe(cc *CheckContext, wantMethods map[string]bool) (*authProbe, bool, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, false, nil
	}
	if wantMethods != nil && !wantMethods[strings.ToUpper(cc.Exchange.Method)] {
		return nil, false, nil
	}
	raw := []byte(requestRaw(cc.Scanner, cc.Exchange))
	if len(raw) == 0 {
		return nil, false, nil
	}
	opts := cc.ProbeEnumerateOptions()
	lp, ok := findLoginPoints(raw, cc.Exchange.Path, opts)
	if !ok {
		return nil, false, nil
	}
	if cc.Scanner.sender == nil {
		return nil, false, fmt.Errorf("authentication check: no sender; an active probe cannot be sent: %w", errCapabilityMissing)
	}
	h := &ProbeHarness{scanner: cc.Scanner, exchange: cc.Exchange, reqBytes: raw}
	return &authProbe{cc: cc, h: h, raw: raw, lp: lp, opts: opts}, true, nil
}

func (a *authProbe) attempt(ctx context.Context, identity, secret string) (ProbeResponse, error) {
	req, err := withCredentials(a.raw, a.lp, identity, secret, a.opts)
	if err != nil {
		return ProbeResponse{}, err
	}
	return a.h.send(ctx, req)
}

func (a *authProbe) finding(name, severity, confidence, param, evidence, detail string) *Finding {
	f := buildHeaderFinding(a.cc, name, severity, confidence, evidence, detail)
	f.Param = param
	return f
}

// ---------------------------------------------------------------------------
// Missing rate limiting
// ---------------------------------------------------------------------------

var rateLimitMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true}

func checkLoginRateLimit(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	a, ok, err := newAuthProbe(cc, rateLimitMethods)
	if err != nil || !ok {
		return nil, err
	}
	captured := decodedValue(a.lp.identity)
	identity := inventIdentity(captured)
	capturedSecret := decodedValue(a.lp.secret)
	attempts := loginRateLimitAttempts(cc.Config)

	type sent struct {
		resp   ProbeResponse
		secret string
	}
	var got []sent
	submitted := []string{identity, captured}
	send := func() (ProbeResponse, error) {
		s := inventSecret(a.lp.kind, capturedSecret)
		r, err := a.attempt(ctx, identity, s)
		if err == nil {
			got = append(got, sent{r, s})
			submitted = append(submitted, s)
		}
		return r, err
	}
	r0, err := send()
	if err != nil {
		return nil, err
	}
	// 201 Created is not a failed login: whatever this endpoint is, repeating it makes things.
	if r0.Status == 201 || unusableLoginStatus(r0.Status) || throttleSignal(r0) != "" {
		return nil, nil
	}
	evaluates := credentialEvaluationEvidence(a, r0, submitted)
	if evaluates == "" {
		return nil, nil
	}
	fp0 := authFingerprint(r0, submitted)
	for len(got) < attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r, err := send()
		if err != nil {
			// A burst that could not be completed proves nothing about the attempts it did not send.
			return nil, fmt.Errorf("login rate-limit burst stopped after %d of %d attempts: %w", len(got), attempts, err)
		}
		if throttleSignal(r) != "" || authFingerprint(r, submitted) != fp0 {
			// A defence engaged (or the answer is not deterministic): either way, not this finding.
			return nil, nil
		}
	}
	// Every answer is compared again under the full list of submitted values: each attempt's random
	// secret is masked only once it has been sent, so an answer quoting its own secret is compared
	// fairly only now.
	fpAll := authFingerprint(got[0].resp, submitted)
	var durs []time.Duration
	for _, s := range got {
		if authFingerprint(s.resp, submitted) != fpAll {
			return nil, nil
		}
		durs = append(durs, s.resp.Duration)
	}
	k := min(5, len(durs)/3)
	early, late := medianDuration(durs[:k]), medianDuration(durs[len(durs)-k:])
	if late > 2*early && late-early >= 750*time.Millisecond {
		return nil, nil
	}

	what := "password"
	if a.lp.kind == secretOTP {
		what = "one-time code"
	}
	evidence := fmt.Sprintf("%d consecutive failed attempts (invented %s %q, a different random %s each time) were all "+
		"answered HTTP %d with the same response after masking the submitted values and dynamic tokens; no 429/503, "+
		"no Retry-After or rate-limit header, no lockout or CAPTCHA wording; median latency %s for the first %d "+
		"attempts and %s for the last %d. The endpoint evaluates the credentials: %s.",
		len(got), a.lp.identity.Name, identity, what, r0.Status, early.Round(time.Millisecond), k,
		late.Round(time.Millisecond), k, evaluates)
	detail := fmt.Sprintf("A burst of %d failed authentication attempts against %s was not throttled. The attempts used an "+
		"identity invented for the test, so no real account was locked; a defence that engages only for accounts "+
		"that exist would not show here, which is why this is tentative.", len(got), exchangeURL(cc.Exchange))
	return []*Finding{a.finding(IssueLoginRateLimitMissing, "medium", "tentative",
		a.lp.identity.Name+", "+a.lp.secret.Name, evidence, detail)}, nil
}

// credentialEvaluationEvidence says why the endpoint's answer to a failed attempt shows it evaluates
// credentials, or "" when nothing does. An endpoint that ignores the fields answers a burst
// identically too, so without this the check would report every form that has a password field.
func credentialEvaluationEvidence(a *authProbe, r ProbeResponse, submitted []string) string {
	if r.Status == 401 {
		return "the failed attempt was answered HTTP 401"
	}
	if m := authFailureRE.FindString(r.Body); m != "" {
		return fmt.Sprintf("the failed attempt was answered %q", m)
	}
	captured := responseRaw(a.cc.Scanner, a.cc.Exchange)
	if captured == "" {
		return ""
	}
	base := ProbeResponse{Raw: []byte(captured), Body: responseBody(captured), Status: responseStatus(captured)}
	all := append(append([]string(nil), submitted...), decodedValue(a.lp.secret))
	if base.Status != 0 && authFingerprint(base, all) != authFingerprint(r, all) {
		if base.Status != r.Status {
			return fmt.Sprintf("the captured request's own credentials were answered HTTP %d, a failed attempt HTTP %d",
				base.Status, r.Status)
		}
		return "the captured request's own credentials were answered with a different page or redirect than a failed attempt"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Username enumeration
// ---------------------------------------------------------------------------

func checkUsernameEnumeration(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	a, ok, err := newAuthProbe(cc, nil)
	if err != nil || !ok || a.lp.kind != secretPassword {
		return nil, err
	}
	known := decodedValue(a.lp.identity)
	if known == "" {
		return nil, nil
	}
	captured := decodedValue(a.lp.secret)
	pwA, pwB := inventSecret(secretPassword, captured), inventSecret(secretPassword, captured)
	invented := []string{inventIdentity(known), inventIdentity(known), inventIdentity(known)}
	plan := []struct {
		user, pw string
		known    bool
	}{
		{invented[0], pwA, false}, {known, pwA, true}, {invented[1], pwB, false}, {known, pwB, true}, {invented[2], pwA, false},
	}
	submitted := append([]string{known, pwA, pwB, captured}, invented...)
	var knownR, otherR []ProbeResponse
	for _, p := range plan {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r, err := a.attempt(ctx, p.user, p.pw)
		if err != nil {
			return nil, err
		}
		if unusableLoginStatus(r.Status) || r.Status == 429 || r.Status == 201 {
			return nil, nil
		}
		if p.known {
			knownR = append(knownR, r)
		} else {
			otherR = append(otherR, r)
		}
	}
	kfp := authFingerprint(knownR[0], submitted)
	for _, r := range knownR[1:] {
		if authFingerprint(r, submitted) != kfp {
			return nil, nil // the captured username's own answer is not stable
		}
	}
	ofp := authFingerprint(otherR[0], submitted)
	for _, r := range otherR[1:] {
		if authFingerprint(r, submitted) != ofp {
			return nil, nil // invented usernames are not answered alike: no single "unknown user" answer
		}
	}
	if kfp == ofp {
		return nil, nil
	}
	var kd, od []time.Duration
	for _, r := range knownR {
		kd = append(kd, r.Duration)
	}
	for _, r := range otherR {
		od = append(od, r.Duration)
	}
	kb, ob := maskDynamic(maskSubmitted(knownR[0].Body, submitted)), maskDynamic(maskSubmitted(otherR[0].Body, submitted))
	evidence := fmt.Sprintf("with the same random wrong passwords, the captured %s %q was answered HTTP %d (2 of 2 identical) "+
		"and 3 invented ones HTTP %d (3 of 3 identical), and the two answers differ: %s. Median latency %s vs %s "+
		"(recorded, not used to decide).", a.lp.identity.Name, known, knownR[0].Status, otherR[0].Status,
		describeDifference(knownR[0], otherR[0], kb, ob, submitted),
		medianDuration(kd).Round(time.Millisecond), medianDuration(od).Round(time.Millisecond))
	detail := fmt.Sprintf("A failed login at %s is answered differently for an existing username than for one that does "+
		"not exist, so the response tells an attacker which usernames are valid.", exchangeURL(cc.Exchange))
	return []*Finding{a.finding(IssueUsernameEnumeration, "low", "firm", a.lp.identity.Name, evidence, detail)}, nil
}

// describeDifference names how two answers differ, quoting the first point where the masked bodies
// part ways.
func describeDifference(k, o ProbeResponse, kb, ob string, submitted []string) string {
	var parts []string
	if k.Status != o.Status {
		parts = append(parts, fmt.Sprintf("status %d vs %d", k.Status, o.Status))
	}
	kl := maskSubmitted(headerValue(string(k.Raw), "Location"), submitted)
	ol := maskSubmitted(headerValue(string(o.Raw), "Location"), submitted)
	if maskDynamic(kl) != maskDynamic(ol) {
		parts = append(parts, fmt.Sprintf("redirect %q vs %q", kl, ol))
	}
	if kb != ob {
		i := 0
		for i < len(kb) && i < len(ob) && kb[i] == ob[i] {
			i++
		}
		from := max(0, i-20)
		excerpt := func(s string) string {
			end := min(len(s), i+60)
			if from >= end {
				return ""
			}
			return strings.ReplaceAll(strings.ReplaceAll(s[from:end], "\x01v\x01", "<submitted>"), "\x01", "")
		}
		parts = append(parts, fmt.Sprintf("body %q vs %q", excerpt(kb), excerpt(ob)))
	}
	if len(parts) == 0 {
		return "the responses differ"
	}
	return strings.Join(parts, "; ")
}
