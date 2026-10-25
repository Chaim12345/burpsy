package scanner

// Session management: predictable session tokens, session fixation, and sessions that survive logout
// (burpsy-react-ui-0vzb wave 5). burpsy-only rows; Burp's catalogue has none of the three.
//
// # What starts it
//
// A captured LOGIN: a request carrying a password-like field (query, form or JSON body) whose
// captured response set at least one cookie. Nothing is sent for any other request. The check then
// replays that login, as the operator captured it, to obtain fresh sessions of its own. Every token it
// tests is one it was issued itself; the operator's own session cookie is never sent to a logout and
// never planted anywhere.
//
// # Which cookie is the session
//
// The cookies the login response sets are compared across two replays (with those cookies stripped
// from the request): one whose value is non-empty and different every time is a per-login token.
//
// # The authenticated page (shared by all three proofs)
//
// Fixation and logout are decided by whether a token is accepted, so the check first finds a page that
// demonstrably depends on the session: a GET that, sent with a fresh token as its only credential,
// answers 2xx and names the user the login submitted (the username field's value, which must not be
// readable from the token itself), while the same GET with a format-preserving random token does not
// (the "identity" proof). Without a username, a 2xx under the fresh token against 401/403/3xx under the
// random one is accepted instead (the "status" proof). Candidates, in order: GETs in the site map on the
// same host that were sent with the session cookie, then a short list of conventional names for the
// signed-in user's own resource (me, profile, account, ...) under the login path and its parent - the
// same content-discovery technique a tester uses, not any one application's route.
//
// # Predictable session token (CWE-330)
//
// Twelve fresh tokens are collected. Each is decoded when every sample decodes the same way to
// printable text (base64 in its four spellings, hex) and re-encodes to itself. The decoded tokens must
// share one template in which exactly one number varies (decimal, or hex). Two models are tried:
//
//   - a counter: every step a positive multiple of the smallest, at most eight times it, and at least
//     half of them exactly the smallest (other clients logging in at the same time explain the rest);
//     the next token is predicted as the last plus one to eight steps;
//   - a clock: the value tracks the local clock in seconds, milliseconds, microseconds or nanoseconds
//     with a stable offset; the next token is predicted as a window around the time of the next login.
//
// The prediction is then CONFIRMED: one more login is made and the token it is issued must be one of
// the predicted values, re-encoded the same way, byte for byte. A statistical judgement alone is never
// reported. Certain when the very next counter value was issued and that token authenticates the
// authenticated page; firm when it was a few steps further on, or one of a clock window of at most 2^20
// values; tentative when no authenticated page was found and only the cookie's name says it is a
// session.
//
// # Session fixation (CWE-384)
//
// A token chosen by the check (a format-preserving random value of the session cookie's shape) is
// first shown NOT to authenticate the page, then planted as the session cookie on a login. When the
// login answers with a new, different value for the cookie the session was rotated and the test ends.
// Otherwise the planted token is sent to the page alone: it must now authenticate as the user who
// logged in. Certain: the token went from rejected to accepted because of the login, and the check
// chose it.
//
// # Session not invalidated after logout (CWE-613)
//
// A fresh session is shown to authenticate the page, then sent - as the only credential, with no body
// and so no credentials - to a logout derived from the login request itself (a parameter value or path
// segment naming the login, swapped for its logout counterpart: login/logout, signin/signout,
// logon/logoff) or to a logout-named URL in the site map. Only a response that EXPIRES the session
// cookie (empty value, Max-Age=0 or an Expires in the past) counts as a logout; anything else is not
// known to be a logout and the next candidate is tried. The same token is then replayed, read-only, to
// the page: still accepted is the finding. Firm.
//
// # Safety
//
// Logins with the operator's own captured credentials, GETs, and a logout of a session the check
// itself just created. No password is guessed, no failed login is made on purpose, and every request
// goes through the probe gate, which authorizes it against the scope on the bytes actually sent. At
// most sessMaxSends requests per audited login. Off by default (check_session_management).
//
// # Catalogue rows
//
// The three rows are burpsy's own (BurpsyNativeRows; advisories native/b5000400, b5000500, b5000600)
// and the check rides the "Broken access control" descriptor behind its own switch, as IDOR does.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The burpsy rows this check reports; see BurpsyNativeRows.
const (
	sessionFixationIssue    = "Session fixation"
	predictableSessionIssue = "Predictable session token"
	logoutInvalidationIssue = "Session not invalidated after logout"
)

// sessionMgmtEnabled is the check's own switch.
func sessionMgmtEnabled(c *ScanConfig) bool { return c != nil && c.CheckSessionManagement }

const (
	// sessMaxSends bounds every request the check sends for one audited login.
	sessMaxSends = 64
	// sessSamples is how many fresh tokens the predictability analysis reads before it predicts.
	sessSamples = 12
	// sessMaxSteps bounds how far ahead of the last sample a counter prediction may land.
	sessMaxSteps = 8
	// sessMaxWindow bounds a clock prediction's candidate count.
	sessMaxWindow = 1 << 20
	// sessMaxLogouts bounds the logout candidates tried.
	sessMaxLogouts = 3
)

var errSessBudget = errors.New("session management: request budget spent")

// withSessionManagement adds this check to the runner of the descriptor it rides. The inner runner
// keeps its own switches; a proven finding from either half is returned even when the other failed.
func withSessionManagement(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		var innerF []*Finding
		var innerErr error
		if finalChecksEnabled(cc.Config) || idorEnabled(cc.Config) || loginRateLimitEnabled(cc.Config) ||
			usernameEnumerationEnabled(cc.Config) || bflaEnabled(cc.Config) {
			innerF, innerErr = inner(ctx, cc)
		}
		var sessF []*Finding
		var sessErr error
		if sessionMgmtEnabled(cc.Config) {
			sessF, sessErr = checkSessionManagement(ctx, cc)
		}
		out := append(innerF, sessF...)
		switch {
		case len(sessF) > 0:
			return out, nil
		case innerErr != nil:
			return innerF, innerErr
		case sessErr != nil:
			return innerF, sessErr
		}
		return out, nil
	}
}

// checkSessionManagement runs the three tests against one captured login.
func checkSessionManagement(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	creds, ok := sessLoginFields(raw)
	if !ok {
		return nil, nil
	}
	issued := sessIssuedCookies(responseRaw(cc.Scanner, cc.Exchange))
	if len(issued) == 0 {
		// The captured login set no cookie: a failed login, or a session carried some other way.
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, []string{"query"})
	if err != nil {
		return nil, fmt.Errorf("session management: %w", err)
	}
	p := &sessProber{cc: cc, h: h, raw: raw, user: creds.user, issued: issued, sends: 1}
	fs, err := p.run(ctx)
	if err != nil && len(fs) == 0 {
		return nil, fmt.Errorf("session management: %w", err)
	}
	return fs, nil
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------

type sessProber struct {
	cc     *CheckContext
	h      *ProbeHarness
	raw    string
	user   string
	issued []string
	sends  int

	cookie string // the session cookie's name
	page   *sessPage
}

// sessSample is one fresh token and when the login that issued it was in flight.
type sessSample struct {
	token         string
	before, after time.Time
}

func (p *sessProber) send(ctx context.Context, raw string) (ProbeResponse, error) {
	if p.sends >= sessMaxSends {
		return ProbeResponse{}, errSessBudget
	}
	p.sends++
	return p.h.send(ctx, []byte(raw))
}

// login replays the captured login with every issued cookie removed and, when plant is set, the
// session cookie set to it. It returns the response and the session cookie's new value ("" when the
// response set none).
func (p *sessProber) login(ctx context.Context, plant string) (ProbeResponse, map[string]*http.Cookie, error) {
	drop := map[string]bool{}
	for _, n := range p.issued {
		drop[n] = true
	}
	var add [][2]string
	if plant != "" {
		add = append(add, [2]string{p.cookie, plant})
	}
	r, err := p.send(ctx, sessWithCookies(p.raw, drop, add))
	if err != nil {
		return r, nil, err
	}
	return r, sessSetCookies(string(r.Raw)), nil
}

func (p *sessProber) run(ctx context.Context) ([]*Finding, error) {
	// Two logins name the per-login cookie.
	var first []map[string]*http.Cookie
	var samples []sessSample
	for i := 0; i < 2; i++ {
		r, set, err := p.login(ctx, "")
		if err != nil {
			return nil, err
		}
		if r.Status >= 400 {
			return nil, nil
		}
		first = append(first, set)
	}
	p.cookie = sessPickCookie(p.issued, first[0], first[1])
	if p.cookie == "" {
		return nil, nil
	}
	// Samples, timed.
	for len(samples) < sessSamples {
		before := time.Now()
		r, set, err := p.login(ctx, "")
		after := time.Now()
		if err != nil {
			return nil, err
		}
		c := set[p.cookie]
		if r.Status >= 400 || c == nil || sessIsDeletion(c) {
			// The login stopped issuing sessions part-way: nothing below can be decided.
			return nil, nil
		}
		samples = append(samples, sessSample{token: c.Value, before: before, after: after})
	}

	var out []*Finding
	var failures []string
	page, err := p.findPage(ctx, samples[len(samples)-1].token)
	if err != nil {
		failures = append(failures, err.Error())
	}
	p.page = page

	if f, err := p.predictable(ctx, samples); err != nil {
		failures = append(failures, err.Error())
	} else if f != nil {
		out = append(out, f)
	}
	if p.page != nil {
		if f, err := p.fixation(ctx, samples[len(samples)-1].token); err != nil {
			failures = append(failures, err.Error())
		} else if f != nil {
			out = append(out, f)
		}
		if f, err := p.logout(ctx); err != nil {
			failures = append(failures, err.Error())
		} else if f != nil {
			out = append(out, f)
		}
	}
	if len(failures) > 0 {
		return out, errors.New(strings.Join(failures, "; "))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// the authenticated page
// ---------------------------------------------------------------------------

// sessPage is a GET whose answer demonstrably depends on the session cookie.
type sessPage struct {
	target   string // origin-form path and query
	identity bool   // proof by the username shown, else by status
	valid    ProbeResponse
	control  ProbeResponse
	controlT string
}

// get sends the page with the session cookie set to token as its only credential.
func (p *sessProber) get(ctx context.Context, target, token string) (ProbeResponse, error) {
	return p.send(ctx, sessGET(p.raw, target, p.cookie+"="+token))
}

// accepts reports whether r is the page answering an authenticated session.
func (pg *sessPage) accepts(r ProbeResponse, user string) bool {
	if r.Status < 200 || r.Status > 299 {
		return false
	}
	if pg.identity {
		return sessContainsFold(r.Body, user)
	}
	return r.Body != pg.control.Body
}

func (p *sessProber) findPage(ctx context.Context, token string) (*sessPage, error) {
	identityOK := len(p.user) >= 3 && !sessTokenNames(token, p.user)
	for _, target := range p.pageCandidates() {
		r, err := p.get(ctx, target, token)
		if err != nil {
			return nil, err
		}
		if r.Status < 200 || r.Status > 299 {
			continue
		}
		identity := identityOK && sessContainsFold(r.Body, p.user)
		ctrlT := sessLookalike(token)
		c, err := p.get(ctx, target, ctrlT)
		if err != nil {
			return nil, err
		}
		pg := &sessPage{target: target, identity: identity, valid: r, control: c, controlT: ctrlT}
		switch {
		case identity:
			if sessContainsFold(c.Body, p.user) || c.Body == r.Body {
				continue
			}
		default:
			if !(c.Status == 401 || c.Status == 403 || (c.Status >= 300 && c.Status < 400)) || c.Body == r.Body {
				continue
			}
		}
		return pg, nil
	}
	return nil, nil
}

// sessPageNames are conventional names for the signed-in user's own resource.
var sessPageNames = []string{"me", "profile", "account", "user", "whoami", "userinfo", "session", "dashboard"}

var sessLogoutPath = regexp.MustCompile(`(?i)(log[-_]?out|sign[-_]?out|log[-_]?off)`)

func (p *sessProber) pageCandidates() []string {
	loginPath := sessTargetPath(p.raw)
	seen := map[string]bool{loginPath: true}
	var out []string
	add := func(t string) {
		if t != "" && !seen[t] && !sessLogoutPath.MatchString(t) {
			seen[t] = true
			out = append(out, t)
		}
	}
	ex := p.cc.Exchange
	n := 0
	for _, e := range p.cc.Scanner.store.Exchanges() {
		if n >= 4 {
			break
		}
		if e == nil || e.ID == ex.ID || !strings.EqualFold(e.Method, "GET") || !strings.EqualFold(e.Host, ex.Host) || e.Port != ex.Port {
			continue
		}
		rr := requestRaw(p.cc.Scanner, e)
		if _, ok := sessRequestCookies(rr)[p.cookie]; !ok {
			continue
		}
		before := len(out)
		add(sessTarget(rr))
		if len(out) > before {
			n++
		}
	}
	bases := []string{strings.TrimSuffix(loginPath, "/")}
	if dir := path.Dir(strings.TrimSuffix(loginPath, "/")); dir != "." {
		bases = append(bases, strings.TrimSuffix(dir, "/"))
	}
	for _, b := range bases {
		for _, name := range sessPageNames {
			add(b + "/" + name)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// predictable session token
// ---------------------------------------------------------------------------

func (p *sessProber) predictable(ctx context.Context, samples []sessSample) (*Finding, error) {
	m := sessModel(samples)
	if m == nil {
		return nil, nil
	}
	before := time.Now()
	r, set, err := p.login(ctx, "")
	after := time.Now()
	if err != nil {
		return nil, err
	}
	c := set[p.cookie]
	if r.Status >= 400 || c == nil || sessIsDeletion(c) {
		return nil, nil
	}
	steps, ok := m.confirm(c.Value, before, after)
	if !ok {
		return nil, nil
	}
	confidence := "firm"
	if m.counter && steps == 1 {
		confidence = "certain"
	}
	verified := ""
	switch {
	case p.page != nil:
		a, err := p.get(ctx, p.page.target, c.Value)
		if err != nil {
			return nil, err
		}
		if !p.page.accepts(a, p.user) {
			// The predicted cookie does not authenticate: not the session token.
			return nil, nil
		}
		verified = fmt.Sprintf(" The issued token authenticates %s (HTTP %d), so it is the session token.",
			p.page.target, a.Status)
	case sessSessionLikeName(p.cookie):
		confidence = "tentative"
		verified = " No page that depends on the session was found, so only the cookie's name says it is the " +
			"session token."
	default:
		return nil, nil
	}
	var shown []string
	for _, s := range samples[len(samples)-4:] {
		shown = append(shown, s.token)
	}
	detail := fmt.Sprintf("The %q cookie issued by this login is predictable. %s Twelve fresh logins were "+
		"issued tokens ending %s; from them the next token was predicted as %s, and the next login was issued "+
		"%q, which is one of the predicted values.%s An attacker who logs in once can compute the tokens "+
		"issued to the users who log in after them.", p.cookie, m.describe(), strings.Join(shown, ", "),
		m.predictedText(), c.Value, verified)
	f := buildHeaderFinding(p.cc, predictableSessionIssue, "high", confidence,
		fmt.Sprintf("Set-Cookie: %s=%s (predicted: %s)", p.cookie, c.Value, m.predictedText()), detail)
	f.Param = p.cookie
	f.Solution = "Generate session tokens with a cryptographically secure random number generator, with at " +
		"least 64 bits of entropy, and never derive them from a counter, a timestamp or user data; encoding a " +
		"predictable value does not make it unpredictable."
	return f, nil
}

// sessCodec is a reversible encoding a token may be wrapped in.
type sessCodec struct {
	name   string
	decode func(string) (string, bool)
	encode func(string) string
}

func sessB64(name string, enc *base64.Encoding) sessCodec {
	return sessCodec{name: name,
		decode: func(s string) (string, bool) {
			b, err := enc.DecodeString(s)
			return string(b), err == nil
		},
		encode: func(s string) string { return enc.EncodeToString([]byte(s)) }}
}

var sessCodecs = []sessCodec{
	{name: "", decode: func(s string) (string, bool) { return s, true }, encode: func(s string) string { return s }},
	sessB64("base64", base64.StdEncoding),
	sessB64("unpadded base64", base64.RawStdEncoding),
	sessB64("base64url", base64.URLEncoding),
	sessB64("unpadded base64url", base64.RawURLEncoding),
	{name: "hex", decode: func(s string) (string, bool) {
		b, err := hex.DecodeString(s)
		return string(b), err == nil
	}, encode: func(s string) string { return hex.EncodeToString([]byte(s)) }},
	{name: "upper-case hex", decode: func(s string) (string, bool) {
		if strings.ToUpper(s) != s {
			return "", false
		}
		b, err := hex.DecodeString(s)
		return string(b), err == nil
	}, encode: func(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }},
}

// sessNumberStyle is how the varying number is written.
type sessNumberStyle struct {
	re    *regexp.Regexp
	base  int
	upper bool
}

var sessNumberStyles = []sessNumberStyle{
	{re: regexp.MustCompile(`[0-9]+`), base: 10},
	{re: regexp.MustCompile(`[0-9a-f]+`), base: 16},
	{re: regexp.MustCompile(`[0-9A-F]+`), base: 16, upper: true},
}

// sessPrediction is a fitted model of how the tokens are made.
type sessPrediction struct {
	codec   sessCodec
	style   sessNumberStyle
	lits    []string // the literal text around the numbers, len(nums)+1
	nums    []string // the last sample's numbers (the constant ones are reused)
	field   int      // which number varies
	width   int      // zero-padded width, 0 for none
	last    *big.Int
	counter bool
	step    *big.Int
	// clock model
	unit           time.Duration
	unitName       string
	offLo, offHi   *big.Int
	predictedLo    *big.Int
	predictedHi    *big.Int
	predictedSteps []*big.Int
}

// sessModel fits a counter or clock model to the samples, or returns nil.
func sessModel(samples []sessSample) *sessPrediction {
	toks := make([]string, len(samples))
	seen := map[string]bool{}
	for i, s := range samples {
		toks[i] = s.token
		if seen[s.token] {
			return nil
		}
		seen[s.token] = true
	}
	for _, codec := range sessCodecs {
		dec, ok := sessDecodeAll(codec, toks)
		if !ok {
			continue
		}
		for _, style := range sessNumberStyles {
			m := sessTemplateOf(dec, style)
			if m == nil {
				continue
			}
			m.codec = codec
			vals := make([]*big.Int, len(dec))
			for i, d := range dec {
				nums := style.re.FindAllString(d, -1)
				v, ok := new(big.Int).SetString(nums[m.field], style.base)
				if !ok {
					return nil
				}
				vals[i] = v
			}
			m.last = vals[len(vals)-1]
			if m.fitCounter(vals) || m.fitClock(vals, samples) {
				return m
			}
		}
	}
	return nil
}

// sessDecodeAll decodes every token with codec, accepting it only when every token decodes to
// printable text that re-encodes to the token exactly.
func sessDecodeAll(codec sessCodec, toks []string) ([]string, bool) {
	out := make([]string, len(toks))
	for i, t := range toks {
		d, ok := codec.decode(t)
		if !ok || d == "" || codec.encode(d) != t {
			return nil, false
		}
		for _, r := range []byte(d) {
			if r < 0x20 || r > 0x7e {
				return nil, false
			}
		}
		if codec.name != "" && d == t {
			return nil, false
		}
		out[i] = d
	}
	return out, true
}

// sessTemplateOf returns the shared template, when every decoded token has the same literal text and
// exactly one number varies.
func sessTemplateOf(dec []string, style sessNumberStyle) *sessPrediction {
	split := func(s string) ([]string, []string) {
		idx := style.re.FindAllStringIndex(s, -1)
		var lits, nums []string
		prev := 0
		for _, ix := range idx {
			lits = append(lits, s[prev:ix[0]])
			nums = append(nums, s[ix[0]:ix[1]])
			prev = ix[1]
		}
		lits = append(lits, s[prev:])
		return lits, nums
	}
	lits0, nums0 := split(dec[0])
	if len(nums0) == 0 {
		return nil
	}
	varying := map[int]bool{}
	for _, d := range dec[1:] {
		lits, nums := split(d)
		if len(nums) != len(nums0) || strings.Join(lits, "\x00") != strings.Join(lits0, "\x00") {
			return nil
		}
		for i := range nums {
			if nums[i] != nums0[i] {
				varying[i] = true
			}
		}
	}
	if len(varying) != 1 {
		return nil
	}
	field := 0
	for i := range varying {
		field = i
	}
	width, padded := 0, false
	for _, d := range dec {
		_, nums := split(d)
		n := nums[field]
		if len(n) > 30 {
			return nil
		}
		if width == 0 {
			width = len(n)
		} else if width != len(n) {
			width = -1
		}
		if len(n) > 1 && n[0] == '0' {
			padded = true
		}
	}
	m := &sessPrediction{style: style, lits: lits0, field: field}
	_, m.nums = split(dec[len(dec)-1])
	if padded && width > 0 {
		m.width = width
	}
	return m
}

func (m *sessPrediction) fitCounter(vals []*big.Int) bool {
	var deltas []*big.Int
	for i := 1; i < len(vals); i++ {
		d := new(big.Int).Sub(vals[i], vals[i-1])
		if d.Sign() <= 0 {
			return false
		}
		deltas = append(deltas, d)
	}
	step := deltas[0]
	for _, d := range deltas {
		if d.Cmp(step) < 0 {
			step = d
		}
	}
	exact := 0
	limit := new(big.Int).Mul(step, big.NewInt(sessMaxSteps))
	for _, d := range deltas {
		if new(big.Int).Mod(d, step).Sign() != 0 || d.Cmp(limit) > 0 {
			return false
		}
		if d.Cmp(step) == 0 {
			exact++
		}
	}
	if exact*2 < len(deltas) {
		return false
	}
	m.counter, m.step = true, step
	for k := int64(1); k <= sessMaxSteps; k++ {
		m.predictedSteps = append(m.predictedSteps, new(big.Int).Add(m.last, new(big.Int).Mul(step, big.NewInt(k))))
	}
	return true
}

var sessClockUnits = []struct {
	unit time.Duration
	name string
}{{time.Second, "seconds"}, {time.Millisecond, "milliseconds"}, {time.Microsecond, "microseconds"}, {time.Nanosecond, "nanoseconds"}}

func sessClockValue(t time.Time, unit time.Duration) *big.Int {
	return new(big.Int).Div(big.NewInt(t.UnixNano()), big.NewInt(int64(unit)))
}

func (m *sessPrediction) fitClock(vals []*big.Int, samples []sessSample) bool {
	for _, u := range sessClockUnits {
		day := new(big.Int).Div(big.NewInt(int64(24*time.Hour)), big.NewInt(int64(u.unit)))
		now := sessClockValue(samples[len(samples)-1].after, u.unit)
		if new(big.Int).Abs(new(big.Int).Sub(m.last, now)).Cmp(day) > 0 {
			continue
		}
		var lo, hi *big.Int
		ok := true
		for i, v := range vals {
			if i > 0 && v.Cmp(vals[i-1]) < 0 {
				ok = false
				break
			}
			// The value was minted while the login was in flight: offset bounds against both ends.
			a := new(big.Int).Sub(v, sessClockValue(samples[i].after, u.unit))
			b := new(big.Int).Sub(v, sessClockValue(samples[i].before, u.unit))
			if lo == nil || a.Cmp(lo) < 0 {
				lo = a
			}
			if hi == nil || b.Cmp(hi) > 0 {
				hi = b
			}
		}
		if !ok {
			continue
		}
		m.unit, m.unitName, m.offLo, m.offHi = u.unit, u.name, lo, hi
		return true
	}
	return false
}

// render writes the token the model would issue for value v.
func (m *sessPrediction) render(v *big.Int) string {
	n := v.Text(m.style.base)
	if m.style.upper {
		n = strings.ToUpper(n)
	}
	if m.width > 0 && len(n) < m.width {
		n = strings.Repeat("0", m.width-len(n)) + n
	}
	var b strings.Builder
	for i, lit := range m.lits {
		b.WriteString(lit)
		if i < len(m.nums) {
			if i == m.field {
				b.WriteString(n)
			} else {
				b.WriteString(m.nums[i])
			}
		}
	}
	return m.codec.encode(b.String())
}

// confirm reports whether token is one the model predicted, and for a counter at which step.
func (m *sessPrediction) confirm(token string, before, after time.Time) (int, bool) {
	if m.counter {
		for i, v := range m.predictedSteps {
			if m.render(v) == token {
				return i + 1, true
			}
		}
		return 0, false
	}
	slack := new(big.Int).Sub(m.offHi, m.offLo)
	lo := new(big.Int).Add(sessClockValue(before, m.unit), m.offLo)
	lo.Sub(lo, slack)
	hi := new(big.Int).Add(sessClockValue(after, m.unit), m.offHi)
	hi.Add(hi, slack)
	size := new(big.Int).Sub(hi, lo)
	if size.Cmp(big.NewInt(sessMaxWindow)) > 0 {
		return 0, false
	}
	m.predictedLo, m.predictedHi = lo, hi
	dec, ok := m.codec.decode(token)
	if !ok || m.codec.encode(dec) != token {
		return 0, false
	}
	nums := m.style.re.FindAllString(dec, -1)
	if len(nums) != len(m.nums) {
		return 0, false
	}
	v, ok := new(big.Int).SetString(nums[m.field], m.style.base)
	if !ok || v.Cmp(lo) < 0 || v.Cmp(hi) > 0 || m.render(v) != token {
		return 0, false
	}
	return 0, true
}

func (m *sessPrediction) describe() string {
	enc := ""
	if m.codec.name != "" {
		enc = fmt.Sprintf(" Each token is %s-encoded text; decoded, the last one reads %q.", m.codec.name,
			sessMustDecode(m.codec, m.render(m.last)))
	}
	base := "a decimal"
	if m.style.base == 16 {
		base = "a hexadecimal"
	}
	if m.counter {
		return fmt.Sprintf("Every token is the same text around %s number that grows by %s per login.%s",
			base, m.step.Text(10), enc)
	}
	return fmt.Sprintf("Every token is the same text around %s number that follows the clock in %s.%s",
		base, m.unitName, enc)
}

func (m *sessPrediction) predictedText() string {
	if m.counter {
		return fmt.Sprintf("%q (or up to %d steps further on)", m.render(m.predictedSteps[0]), sessMaxSteps-1)
	}
	if m.predictedLo == nil {
		return "a clock window"
	}
	n := new(big.Int).Sub(m.predictedHi, m.predictedLo)
	n.Add(n, big.NewInt(1))
	return fmt.Sprintf("one of %s values from %q to %q", n.Text(10), m.render(m.predictedLo), m.render(m.predictedHi))
}

func sessMustDecode(c sessCodec, s string) string {
	d, _ := c.decode(s)
	return d
}

// ---------------------------------------------------------------------------
// session fixation
// ---------------------------------------------------------------------------

func (p *sessProber) fixation(ctx context.Context, shape string) (*Finding, error) {
	planted := sessLookalike(shape)
	pre, err := p.get(ctx, p.page.target, planted)
	if err != nil {
		return nil, err
	}
	if p.page.accepts(pre, p.user) {
		// Already accepted before any login: nothing the login does can be shown.
		return nil, nil
	}
	r, set, err := p.login(ctx, planted)
	if err != nil {
		return nil, err
	}
	if r.Status >= 400 {
		return nil, nil
	}
	if c := set[p.cookie]; c != nil && !sessIsDeletion(c) && c.Value != planted {
		// Rotated: the login issued a session of its own.
		return nil, nil
	}
	post, err := p.get(ctx, p.page.target, planted)
	if err != nil {
		return nil, err
	}
	if !p.page.accepts(post, p.user) {
		return nil, nil
	}
	kept := "set no new value for it"
	if c := set[p.cookie]; c != nil && c.Value == planted {
		kept = "set it back to the same value"
	}
	detail := fmt.Sprintf("The login accepts a session token chosen by the client and keeps it after "+
		"authentication. burpsy chose the %q value %q and showed it was not a valid session: %s answered "+
		"HTTP %d without the signed-in user. It then logged in with that cookie; the login response %s. "+
		"The same token, sent alone, then made %s answer HTTP %d as the user who logged in%s. An attacker who "+
		"plants a token in a victim's browser before the victim logs in holds the victim's session afterwards.",
		p.cookie, planted, p.page.target, pre.Status, kept, p.page.target, post.Status, p.userNote())
	f := buildHeaderFinding(p.cc, sessionFixationIssue, "high", "certain",
		fmt.Sprintf("Cookie: %s=%s before login -> %s HTTP %d, after login -> HTTP %d", p.cookie, planted,
			p.page.target, pre.Status, post.Status), detail)
	f.Param = p.cookie
	f.Solution = "Issue a new session token on every successful authentication (and on any privilege change), " +
		"invalidate the one presented before it, and never adopt a session identifier the client supplied " +
		"that the server did not issue."
	return f, nil
}

func (p *sessProber) userNote() string {
	if p.page.identity {
		return fmt.Sprintf(" (the response names %q)", p.user)
	}
	return ""
}

// ---------------------------------------------------------------------------
// logout invalidation
// ---------------------------------------------------------------------------

func (p *sessProber) logout(ctx context.Context) (*Finding, error) {
	cands := p.logoutCandidates()
	if len(cands) == 0 {
		return nil, nil
	}
	r, set, err := p.login(ctx, "")
	if err != nil {
		return nil, err
	}
	c := set[p.cookie]
	if r.Status >= 400 || c == nil || sessIsDeletion(c) {
		return nil, nil
	}
	token := c.Value
	a, err := p.get(ctx, p.page.target, token)
	if err != nil {
		return nil, err
	}
	if !p.page.accepts(a, p.user) {
		return nil, nil
	}
	for i, cand := range cands {
		if i >= sessMaxLogouts {
			break
		}
		lr, err := p.send(ctx, sessWithCookies(cand.raw, sessAllCookies(cand.raw), [][2]string{{p.cookie, token}}))
		if err != nil {
			return nil, err
		}
		if lr.Status >= 400 {
			continue
		}
		lc := sessSetCookies(string(lr.Raw))[p.cookie]
		if lc == nil || !sessIsDeletion(lc) {
			// Not known to be a logout: it did not end the session cookie.
			continue
		}
		after, err := p.get(ctx, p.page.target, token)
		if err != nil {
			return nil, err
		}
		if !p.page.accepts(after, p.user) {
			// Invalidated.
			return nil, nil
		}
		detail := fmt.Sprintf("Logging out does not end the session on the server. burpsy logged in, and "+
			"%s accepted the new %q token (HTTP %d). It then sent that token to the logout %s %s, which "+
			"answered HTTP %d and expired the cookie (%s). Replaying the same token to %s afterwards was still "+
			"accepted (HTTP %d%s). Anyone who obtained the token keeps the session after the user logs out.",
			p.page.target, p.cookie, a.Status, cand.method, cand.target, lr.Status, cand.how, p.page.target,
			after.Status, strings.TrimPrefix(p.userNote(), " "))
		f := buildHeaderFinding(p.cc, logoutInvalidationIssue, "medium", "firm",
			fmt.Sprintf("%s %s -> HTTP %d (cookie expired); %s with the same token -> HTTP %d", cand.method,
				cand.target, lr.Status, p.page.target, after.Status), detail)
		f.Param = p.cookie
		f.Solution = "Destroy the session on the server at logout (and on idle and absolute timeouts), so the " +
			"token is rejected afterwards; clearing the browser's cookie is not enough."
		return f, nil
	}
	return nil, nil
}

type sessLogout struct {
	raw, method, target, how string
}

var sessLoginWord = regexp.MustCompile(`(?i)(log[-_]?in|sign[-_]?in|log[-_]?on)`)

// sessLogoutWord turns a login word into its logout counterpart, keeping its case and separator.
func sessLogoutWord(w string) string {
	stem, tail := w[:len(w)-2], w[len(w)-2:]
	out := "out"
	if strings.EqualFold(tail, "on") {
		out = "off"
	}
	switch {
	case strings.ToUpper(w) == w:
		out = strings.ToUpper(out)
	case tail[0] >= 'A' && tail[0] <= 'Z':
		out = strings.ToUpper(out[:1]) + out[1:]
	}
	return stem + out
}

// logoutCandidates derives logout requests from the login request itself, then adds logout-named
// URLs from the site map. Derived requests carry no body except a swapped action field.
func (p *sessProber) logoutCandidates() []sessLogout {
	var out []sessLogout
	method, target := sessRequestLine(p.raw)
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	// A query value naming the login.
	q := u.Query()
	for k, vs := range q {
		for i, v := range vs {
			if sessLoginWord.FindString(v) == v && v != "" {
				q2 := u.Query()
				q2[k][i] = sessLogoutWord(v)
				u2 := *u
				u2.RawQuery = q2.Encode()
				out = append(out, sessLogout{raw: sessRewrite(p.raw, method, u2.RequestURI(), "", ""),
					method: method, target: u2.RequestURI(), how: fmt.Sprintf("query %s=%s", k, q2[k][i])})
			}
		}
	}
	// A path segment naming the login.
	segs := strings.Split(u.Path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if loc := sessLoginWord.FindStringIndex(segs[i]); loc != nil {
			segs2 := append([]string(nil), segs...)
			segs2[i] = segs[i][:loc[0]] + sessLogoutWord(segs[i][loc[0]:loc[1]]) + segs[i][loc[1]:]
			u2 := *u
			u2.Path, u2.RawPath = strings.Join(segs2, "/"), ""
			out = append(out, sessLogout{raw: sessRewrite(p.raw, method, u2.RequestURI(), "", ""),
				method: method, target: u2.RequestURI(), how: "path " + u2.Path})
			break
		}
	}
	// A body field naming the login (an action field): sent alone, without the credentials.
	if k, v, ctype, ok := sessBodyLoginField(p.raw); ok {
		var body string
		if strings.Contains(strings.ToLower(ctype), "json") {
			b, _ := json.Marshal(map[string]string{k: sessLogoutWord(v)})
			body = string(b)
		} else {
			body = url.Values{k: {sessLogoutWord(v)}}.Encode()
		}
		out = append(out, sessLogout{raw: sessRewrite(p.raw, method, target, body, ctype), method: method,
			target: target, how: fmt.Sprintf("body %s=%s", k, sessLogoutWord(v))})
	}
	// Logout-named URLs in the site map, on the same host.
	ex := p.cc.Exchange
	n := 0
	for _, e := range p.cc.Scanner.store.Exchanges() {
		if n >= 2 {
			break
		}
		if e == nil || e.ID == ex.ID || !strings.EqualFold(e.Host, ex.Host) || e.Port != ex.Port {
			continue
		}
		rr := requestRaw(p.cc.Scanner, e)
		m, t := sessRequestLine(rr)
		if rr == "" || !sessLogoutPath.MatchString(t) {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || (o.method == m && o.target == t)
		}
		if dup {
			continue
		}
		out = append(out, sessLogout{raw: rr, method: m, target: t, how: "site map"})
		n++
	}
	return out
}

// ---------------------------------------------------------------------------
// request and response helpers
// ---------------------------------------------------------------------------

type sessCreds struct{ user string }

var (
	sessPasswordKey = regexp.MustCompile(`(?i)^(pass|passwd|password|pwd|passphrase|passcode|[a-z_]*password)$`)
	sessUserKey     = regexp.MustCompile(`(?i)^(user|username|user_name|login|email|e-mail|uname|account|userid|user_id|loginname|login_name)$`)
)

// sessLoginFields finds a non-empty password-like field in the query, a form body or a JSON body, and
// the username beside it.
func sessLoginFields(raw string) (sessCreds, bool) {
	var c sessCreds
	found := false
	visit := func(k, v string) {
		if v == "" {
			return
		}
		if sessPasswordKey.MatchString(k) {
			found = true
		} else if c.user == "" && sessUserKey.MatchString(k) {
			c.user = v
		}
	}
	_, target := sessRequestLine(raw)
	if u, err := url.Parse(target); err == nil {
		for k, vs := range u.Query() {
			for _, v := range vs {
				visit(k, v)
			}
		}
	}
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	ctype := strings.ToLower(headerValue(head, "content-type"))
	switch {
	case strings.Contains(ctype, "json"):
		var v any
		if json.Unmarshal([]byte(body), &v) == nil {
			sessWalkJSON(v, visit, 0)
		}
	case strings.Contains(ctype, "x-www-form-urlencoded"):
		if vals, err := url.ParseQuery(body); err == nil {
			for k, vs := range vals {
				for _, v := range vs {
					visit(k, v)
				}
			}
		}
	}
	return c, found
}

func sessWalkJSON(v any, visit func(k, v string), depth int) {
	if depth > 3 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if s, ok := x.(string); ok {
				visit(k, s)
			} else {
				sessWalkJSON(x, visit, depth+1)
			}
		}
	case []any:
		for _, x := range t {
			sessWalkJSON(x, visit, depth+1)
		}
	}
}

// sessBodyLoginField finds a top-level body field (form or JSON) whose value names the login.
func sessBodyLoginField(raw string) (key, value, ctype string, ok bool) {
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	ctype = headerValue(head, "content-type")
	lc := strings.ToLower(ctype)
	check := func(k, v string) bool {
		return v != "" && sessLoginWord.FindString(v) == v && !sessPasswordKey.MatchString(k) && !sessUserKey.MatchString(k)
	}
	switch {
	case strings.Contains(lc, "json"):
		var m map[string]any
		if json.Unmarshal([]byte(body), &m) == nil {
			for k, x := range m {
				if s, isStr := x.(string); isStr && check(k, s) {
					return k, s, ctype, true
				}
			}
		}
	case strings.Contains(lc, "x-www-form-urlencoded"):
		if vals, err := url.ParseQuery(body); err == nil {
			for k, vs := range vals {
				for _, v := range vs {
					if check(k, v) {
						return k, v, ctype, true
					}
				}
			}
		}
	}
	return "", "", "", false
}

// sessIssuedCookies names the cookies a response sets to a non-empty value.
func sessIssuedCookies(resp string) []string {
	var out []string
	for name, c := range sessSetCookies(resp) {
		if !sessIsDeletion(c) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// sessSetCookies parses a response's Set-Cookie headers, keyed by name (the last one wins).
func sessSetCookies(resp string) map[string]*http.Cookie {
	head, _, _ := strings.Cut(resp, "\r\n\r\n")
	h := http.Header{}
	for _, v := range headerValues(head, "set-cookie") {
		h.Add("Set-Cookie", v)
	}
	out := map[string]*http.Cookie{}
	for _, c := range (&http.Response{Header: h}).Cookies() {
		out[c.Name] = c
	}
	return out
}

// sessIsDeletion reports whether a Set-Cookie ends the cookie rather than setting it.
func sessIsDeletion(c *http.Cookie) bool {
	if c.Value == "" || strings.EqualFold(c.Value, "deleted") || c.MaxAge < 0 {
		return true
	}
	return !c.Expires.IsZero() && c.Expires.Before(time.Now())
}

// sessPickCookie picks the per-login cookie: issued both times, non-empty, different each time.
// A session-like name wins over another candidate.
func sessPickCookie(issued []string, a, b map[string]*http.Cookie) string {
	var cands []string
	for _, n := range issued {
		ca, cb := a[n], b[n]
		if ca == nil || cb == nil || sessIsDeletion(ca) || sessIsDeletion(cb) || ca.Value == cb.Value {
			continue
		}
		cands = append(cands, n)
	}
	for _, n := range cands {
		if sessSessionLikeName(n) {
			return n
		}
	}
	if len(cands) > 0 {
		return cands[0]
	}
	return ""
}

var sessSessionName = regexp.MustCompile(`(?i)(sess|sid|token|auth|jwt|login|ident)`)

func sessSessionLikeName(n string) bool {
	return LooksLikeSessionToken(n) || sessSessionName.MatchString(n)
}

// sessRequestCookies parses a request's Cookie headers.
func sessRequestCookies(raw string) map[string]string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	out := map[string]string{}
	for _, v := range headerValues(head, "cookie") {
		for _, c := range strings.Split(v, ";") {
			n, val, _ := strings.Cut(strings.TrimSpace(c), "=")
			if n != "" {
				out[n] = val
			}
		}
	}
	return out
}

func sessAllCookies(raw string) map[string]bool {
	out := map[string]bool{}
	for n := range sessRequestCookies(raw) {
		out[n] = true
	}
	return out
}

// sessWithCookies rewrites a request's Cookie header: the named cookies dropped, the pairs added.
func sessWithCookies(raw string, drop map[string]bool, add [][2]string) string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	var kept []string
	for _, v := range headerValues(head, "cookie") {
		for _, c := range strings.Split(v, ";") {
			c = strings.TrimSpace(c)
			n, _, _ := strings.Cut(c, "=")
			if c == "" || drop[n] {
				continue
			}
			kept = append(kept, c)
		}
	}
	for _, kv := range add {
		kept = append(kept, kv[0]+"="+kv[1])
	}
	return withCookieHeader(raw, strings.Join(kept, "; "))
}

// sessRequestLine returns a raw request's method and request target.
func sessRequestLine(raw string) (string, string) {
	line, _, _ := strings.Cut(raw, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// sessTarget is a request's origin-form target (an absolute-form target is reduced to its path).
func sessTarget(raw string) string {
	_, t := sessRequestLine(raw)
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		return u.RequestURI()
	}
	return t
}

// sessTargetPath is a request's path without its query.
func sessTargetPath(raw string) string {
	t := sessTarget(raw)
	p, _, _ := strings.Cut(t, "?")
	return p
}

// sessGET builds a GET of target on the login's host, carrying only cookie as credentials.
func sessGET(login, target, cookie string) string {
	head, _, _ := strings.Cut(login, "\r\n\r\n")
	var b strings.Builder
	b.WriteString("GET " + target + " HTTP/1.1\r\n")
	for _, line := range strings.Split(head, "\r\n")[1:] {
		name, _, _ := strings.Cut(line, ":")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "host", "user-agent", "accept-language":
			b.WriteString(line + "\r\n")
		}
	}
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Cookie: " + cookie + "\r\n\r\n")
	return b.String()
}

// sessRewrite rebuilds a request with a new method/target and body; every credential-bearing header
// except Host-level ones is dropped and the Cookie header is removed (the caller sets its own).
func sessRewrite(raw, method, target, body, ctype string) string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\n")
	for _, line := range strings.Split(head, "\r\n")[1:] {
		name, _, _ := strings.Cut(line, ":")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length", "content-type", "cookie", "authorization", "transfer-encoding":
			continue
		}
		b.WriteString(line + "\r\n")
	}
	if ctype == "" {
		ctype = headerValue(head, "content-type")
	}
	if ctype != "" && method != "GET" {
		b.WriteString("Content-Type: " + ctype + "\r\n")
	}
	if method != "GET" || body != "" {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("\r\n" + body)
	return b.String()
}

// sessLookalike returns a random token of the same shape as t: every digit, lower-case letter and
// upper-case letter replaced by a random one of its class, everything else kept. An application that
// validates the token's format sees a well-formed token that it never issued.
func sessLookalike(t string) string {
	const digits, lower, upper = "0123456789", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	pick := func(set string) byte {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return set[0]
		}
		return set[n.Int64()]
	}
	hexLike := regexp.MustCompile(`^[0-9a-f-]+$`).MatchString(t)
	for {
		out := []byte(t)
		for i, c := range out {
			switch {
			case c >= '0' && c <= '9':
				out[i] = pick(digits)
			case c >= 'a' && c <= 'z':
				if hexLike {
					out[i] = pick("abcdef")
				} else {
					out[i] = pick(lower)
				}
			case c >= 'A' && c <= 'Z':
				out[i] = pick(upper)
			}
		}
		if string(out) != t || len(t) == 0 {
			return string(out)
		}
	}
}

// sessTokenNames reports whether the token, raw or decoded, contains the username: a page echoing a
// decoded cookie would then name the user for any token, so the username cannot prove a session.
func sessTokenNames(token, user string) bool {
	if sessContainsFold(token, user) {
		return true
	}
	for _, c := range sessCodecs[1:] {
		if d, ok := c.decode(token); ok && sessContainsFold(d, user) {
			return true
		}
	}
	return false
}

func sessContainsFold(s, sub string) bool {
	return sub != "" && bytes.Contains(bytes.ToLower([]byte(s)), bytes.ToLower([]byte(sub)))
}
