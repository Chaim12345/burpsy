package scanner

// Password-reset token weaknesses: the reset flow of a TEST identity the operator declared, driven
// end to end, with every finding proved by something an echo or a reflection cannot produce.
//
// # What is tested, and the evidence each row needs
//
// A request is a password-reset REQUEST when one of its query/body parameters holds an identity the
// operator listed in ScanConfig.ResetTestIdentities, it carries no password-like parameter (a login
// or a confirm step would), and its path or parameters name a reset (reset, forgot, recover, ...).
// Nothing is done for any other request, and nothing is ever done for an identity the operator did
// not list: the check changes that account's password, so it only ever touches a test account.
//
// The reset token is read from two places: the reset request's own response, and the test inbox
// (ScanConfig.ResetMailboxURL, an operator-run HTTP endpoint that returns the identity's messages;
// see pwrMailbox). Each "issuance" is one reset request, after which the new messages are read.
//
//   - Password reset token disclosed in response: a token-shaped value in the reset request's
//     response that either IS the token mailed for the same request, or is shown to be a reset token
//     by using it: the confirm request with it succeeds where the same request with two random
//     tokens of the same shape fails.
//   - Predictable password reset token: after spaced samples, a model of the token (constant; a
//     decimal field that is the server's clock in seconds or milliseconds; or a counter with a
//     constant step) predicts the NEXT token BEFORE it is requested, and the next token issued is in
//     the predicted set.
//   - Password reset token with insufficient entropy: at least four distinct samples whose varying
//     part, after the common prefix and suffix, has a computed keyspace of at most 10^6.
//   - Reusable password reset token: the same fresh token succeeds twice in the confirm request (two
//     different new passwords), under the same two-random-token control.
//   - Password reset token without expiry: the token is a JWT with no exp claim. Tentative: a server
//     may still expire it from its own records. Nothing here waits real time.
//   - Password reset link over unencrypted HTTP: a link carrying an issued token whose scheme is
//     http://.
//   - Password reset token leaked via Referer: the reset link's page, loaded in the browser, tries to
//     fetch a resource from another origin with the token in the Referer header. Every cross-origin
//     request is FAILED in the browser before it is sent, so the token never leaves. Without a
//     browser, the same verdict is computed from the page: an effective referrer policy that sends
//     the full URL cross-origin (header or meta) AND a cross-origin subresource in the markup.
//   - Password reset poisoning: the reset request re-sent with a forwarding header (or Host) naming a
//     random canary host returns or mails a link whose host is that canary.
//
// # What it does to the target
//
// Each issuance makes the application send one reset message to the test identity, and the confirm
// step changes the test identity's password to a random value (recorded in the finding). That is the
// reason the switch, check_password_reset, is off by default and the check refuses to act without an
// operator-declared identity. Every request goes through the probe gate's scope enforcement; only the
// mailbox read, which is the operator's own infrastructure like the collaborator, does not.
//
// # Catalogue rows
//
// Burp's catalogue has no row for any of these. They are burpsy's own rows (BurpsyNativeRows, advisory
// native/b50008*.json), reported by this check riding the "SMTP header injection" descriptor — the
// other check aimed at mail-sending endpoints — behind its own switch.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	xhtml "golang.org/x/net/html"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy's own row names; see BurpsyNativeRows.
const (
	pwrTokenInResponse = "Password reset token disclosed in response"
	pwrPredictable     = "Predictable password reset token"
	pwrLowEntropy      = "Password reset token with insufficient entropy"
	pwrReusable        = "Reusable password reset token"
	pwrNoExpiry        = "Password reset token without expiry"
	pwrInsecureLink    = "Password reset link over unencrypted HTTP"
	pwrReferer         = "Password reset token leaked via Referer"
	pwrPoisoning       = "Password reset poisoning"
)

func pwresetEnabled(c *ScanConfig) bool { return c != nil && c.CheckPasswordReset }

const (
	// pwrMaxSends bounds one exchange's probes. An issuance is one send.
	pwrMaxSends = 40
	// pwrSamples is how many spaced issuances the token analysis reads.
	pwrSamples = 6
	// pwrSpacing separates the sampled issuances, so a token derived from a seconds clock changes
	// between samples instead of reading as a constant.
	pwrSpacing = 1050 * time.Millisecond
	// pwrMailWait bounds how long an issuance waits for its message.
	pwrMailWait = 6 * time.Second
	// pwrMaxKeyspace is the largest token keyspace reported as insufficient entropy: a million
	// guesses is an online brute force, not a cryptographic one.
	pwrMaxKeyspace = 1e6
)

var errPwrBudget = errors.New("password reset: request budget spent")

// smtpOrPasswordReset runs the SMTP header injection check and, behind its own switch, this one.
func smtpOrPasswordReset(smtp CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil {
			return nil, nil
		}
		var sf []*Finding
		var serr error
		if remainingChecksEnabled(cc.Config) {
			sf, serr = smtp(ctx, cc)
		}
		var pf []*Finding
		var perr error
		if pwresetEnabled(cc.Config) {
			pf, perr = checkPasswordReset(ctx, cc)
		}
		switch {
		case len(pf) > 0:
			return append(sf, pf...), serr
		case serr != nil:
			return sf, serr
		case perr != nil:
			return sf, perr
		}
		return sf, nil
	}
}

var (
	pwrResetWord    = regexp.MustCompile(`(?i)(reset|forgot|forget|recover|lost[-_]?pass|password)`)
	pwrPasswordName = regexp.MustCompile(`(?i)(pass(word|wd)?|pwd)`)
	pwrTokenName    = regexp.MustCompile(`(?i)(token|^code$|^key$|^t$|^k$|^otp$|nonce|^hash$|^sig(nature)?$|^reset$|^rt$|^secret$)`)
	pwrURLRe        = regexp.MustCompile(`https?://[^\s"'<>\\]+`)
	pwrFailWord     = regexp.MustCompile(`(?i)\b(invalid|expired|error|fail(ed|ure)?|denied|not found|incorrect|unauthori[sz]ed|forbidden|already used|reused|wrong)\b`)
	pwrSuccessWord  = regexp.MustCompile(`(?i)\b(success(ful(ly)?)?|changed|updated|complete[d]?|has been reset|was reset)\b`)
)

// checkPasswordReset runs the reset-flow tests against one exchange.
func checkPasswordReset(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil || cc.Config == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	identity, resetish := pwrIdentityIn(raw, cc.Config.ResetTestIdentities)
	if !resetish {
		return nil, nil
	}
	if identity == "" {
		if len(cc.Config.ResetTestIdentities) == 0 && pwrLooksLikeResetRequest(raw) {
			return nil, fmt.Errorf("password reset: the request looks like a reset request, but no test "+
				"identity is configured (reset_test_identities), so it was not exercised: %w", errCapabilityMissing)
		}
		return nil, nil
	}
	p := &pwrProber{cc: cc, raw: raw, identity: identity}
	if cc.Config.ResetMailboxURL != "" {
		p.mail = newPwrMailbox(cc.Config.ResetMailboxURL, identity)
		if err := p.mail.prime(ctx); err != nil {
			return nil, fmt.Errorf("password reset: the test mailbox could not be read before the first "+
				"request: %v: %w", err, errCapabilityMissing)
		}
	}
	return p.run(ctx)
}

// pwrIdentityIn returns the configured identity the request carries, and whether the request is a
// reset-request candidate at all (no password parameter, a reset word in the path or parameters).
func pwrIdentityIn(raw string, identities []string) (string, bool) {
	points, _ := bcheck.EnumerateWith([]byte(raw), []string{"query", "body"}, bcheck.EnumerateOptions{})
	resetish := pwrResetWord.MatchString(pwrRequestPath(raw))
	for _, pt := range points {
		if pwrPasswordName.MatchString(pt.Name) {
			return "", false
		}
		if pwrResetWord.MatchString(pt.Name) || pwrResetWord.MatchString(pwrDecode(pt.BaseValue)) {
			resetish = true
		}
	}
	if !resetish {
		return "", false
	}
	for _, pt := range points {
		v := pwrDecode(pt.BaseValue)
		for _, id := range identities {
			if id != "" && strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(id)) {
				return id, true
			}
		}
	}
	return "", true
}

// pwrLooksLikeResetRequest: a reset candidate carrying an email-shaped value.
func pwrLooksLikeResetRequest(raw string) bool {
	points, _ := bcheck.EnumerateWith([]byte(raw), []string{"query", "body"}, bcheck.EnumerateOptions{})
	for _, pt := range points {
		if strings.Contains(pwrDecode(pt.BaseValue), "@") {
			return true
		}
	}
	return false
}

func pwrDecode(v string) string {
	if d, err := url.QueryUnescape(v); err == nil {
		return d
	}
	return v
}

func pwrRequestPath(raw string) string {
	line, _, _ := strings.Cut(raw, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// ---------------------------------------------------------------------------
// the prober
// ---------------------------------------------------------------------------

type pwrToken struct {
	value  string
	link   string // the URL the token travelled in, when it came in one
	param  string // the parameter or JSON key that held it
	source string // "mail" or "response"
}

type pwrIssuance struct {
	resp     ProbeResponse
	tokens   []pwrToken
	links    []string // every URL seen in the new messages and the response
	sent     time.Time
	recv     time.Time
	server   int64 // the response's Date header, epoch seconds; 0 when absent
	mailText string
}

func (is *pwrIssuance) mailTokens() []pwrToken {
	var out []pwrToken
	for _, t := range is.tokens {
		if t.source == "mail" {
			out = append(out, t)
		}
	}
	return out
}

// primary is the issuance's reset token: the mailed one when there is one, else a response token.
func (is *pwrIssuance) primary() (pwrToken, bool) {
	if m := is.mailTokens(); len(m) > 0 {
		return m[len(m)-1], true
	}
	return pwrToken{}, false
}

type pwrProber struct {
	cc       *CheckContext
	h        *ProbeHarness
	raw      string
	identity string
	mail     *pwrMailbox
	sends    int
	last     time.Time
	// offset is the server clock minus the local clock, from the Date headers seen.
	offset    float64
	offsetN   int
	offsetSet bool
	notes     []string
}

func (p *pwrProber) send(ctx context.Context, raw string) (ProbeResponse, error) {
	if p.sends >= pwrMaxSends {
		return ProbeResponse{}, errPwrBudget
	}
	p.sends++
	return p.h.send(ctx, []byte(raw))
}

// issue sends one reset request (raw) and collects what it produced. first is the harness baseline,
// which was already sent.
func (p *pwrProber) issue(ctx context.Context, raw string, first *ProbeResponse, spaced bool) (*pwrIssuance, error) {
	if spaced && !p.last.IsZero() {
		if wait := pwrSpacing - time.Since(p.last); wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	is := &pwrIssuance{sent: time.Now()}
	if first != nil {
		is.resp = *first
	} else {
		r, err := p.send(ctx, raw)
		if err != nil {
			return nil, err
		}
		is.resp = r
	}
	is.recv = time.Now()
	p.last = is.recv
	if d := headerValue(string(is.resp.Raw), "Date"); d != "" {
		if t, err := http.ParseTime(d); err == nil {
			is.server = t.Unix()
			// The Date header is the server clock floored to the second at some instant between send and
			// receive; the estimate is its midpoint, averaged over every response seen.
			mid := float64(is.sent.UnixNano()+is.recv.UnixNano()) / 2e9
			off := float64(t.Unix()) + 0.5 - mid
			p.offsetN++
			p.offset += (off - p.offset) / float64(p.offsetN)
			p.offsetSet = true
		}
	}
	reqValues := pwrRequestValues(raw)
	for _, t := range pwrTokensInText(is.resp.Body) {
		if !reqValues[t.value] && !strings.EqualFold(t.value, p.identity) {
			t.source = "response"
			is.tokens = append(is.tokens, t)
		}
	}
	is.links = append(is.links, pwrURLs(is.resp.Body)...)
	if p.mail != nil {
		text, err := p.mail.waitNew(ctx, pwrMailWait)
		if err != nil {
			p.notes = append(p.notes, "mailbox: "+err.Error())
		}
		is.mailText = text
		for _, t := range pwrTokensInText(text) {
			if t.link == "" {
				continue // a mailed token is read from a link; bare values in a message are not trusted
			}
			t.source = "mail"
			is.tokens = append(is.tokens, t)
		}
		is.links = append(is.links, pwrURLs(text)...)
	}
	return is, nil
}

func (p *pwrProber) run(ctx context.Context) ([]*Finding, error) {
	kinds := []string{"query", "body"}
	h, err := NewProbeHarness(ctx, p.cc, kinds)
	if err != nil {
		return nil, fmt.Errorf("password reset: %w", err)
	}
	p.h = h
	base := h.Baseline()
	first, err := p.issue(ctx, p.raw, &base, false)
	if err != nil {
		return nil, fmt.Errorf("password reset: %w", err)
	}
	if len(first.tokens) == 0 {
		if p.mail == nil {
			// No inbox to read and nothing token-shaped in the response: the flow cannot be observed.
			return nil, nil
		}
		return nil, fmt.Errorf("password reset: no reset token arrived for %s (response nor mailbox) %s: %w",
			p.identity, strings.Join(p.notes, "; "), errCapabilityMissing)
	}
	issuances := []*pwrIssuance{first}
	var findings []*Finding
	var failures []string

	// Poisoning first: its probes are not samples.
	if f, err := p.poisoning(ctx); err != nil {
		failures = append(failures, err.Error())
	} else if f != nil {
		findings = append(findings, f)
	}

	// Spaced samples.
	samples := []*pwrIssuance{first}
	for len(samples) < pwrSamples {
		is, err := p.issue(ctx, p.raw, nil, true)
		if err != nil {
			failures = append(failures, err.Error())
			break
		}
		samples = append(samples, is)
		issuances = append(issuances, is)
	}
	if f, err := p.analyse(ctx, samples, &issuances); err != nil {
		failures = append(failures, err.Error())
	} else if f != nil {
		findings = append(findings, f)
	}
	if f := p.noExpiry(samples); f != nil {
		findings = append(findings, f)
	}

	// The link, its page, and the confirm step, on a fresh token.
	fresh, err := p.issue(ctx, p.raw, nil, true)
	if err != nil {
		failures = append(failures, err.Error())
	} else {
		issuances = append(issuances, fresh)
		fs, errs := p.useFresh(ctx, fresh)
		findings = append(findings, fs...)
		failures = append(failures, errs...)
	}
	if f := p.insecureLink(issuances); f != nil {
		findings = append(findings, f)
	}
	if len(findings) == 0 && len(failures) > 0 {
		return nil, fmt.Errorf("password reset: %s", strings.Join(failures, "; "))
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// poisoning
// ---------------------------------------------------------------------------

var pwrPoisonHeaders = []string{"X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Forwarded", "Host"}

func (p *pwrProber) poisoning(ctx context.Context) (*Finding, error) {
	for _, name := range pwrPoisonHeaders {
		canary := pwrRandLower(10) + ".burpsy-canary.invalid"
		value := canary
		if name == "Forwarded" {
			value = "host=" + canary
		}
		raw := pwrWithHeader(p.raw, name, value)
		is, err := p.issue(ctx, raw, nil, false)
		if err != nil {
			return nil, err
		}
		for _, l := range is.links {
			u, err := url.Parse(html.UnescapeString(l))
			if err != nil || !strings.EqualFold(u.Hostname(), canary) {
				continue
			}
			where := "the response"
			if strings.Contains(is.mailText, canary) {
				where = "the reset message sent to " + p.identity
			}
			detail := fmt.Sprintf("The reset request for the test identity %s was re-sent with the header "+
				"%s: %s, naming a random host that exists nowhere. %s contained a link to that host: %s. "+
				"The application builds its reset links from a request header an attacker controls, so an "+
				"attacker who requests a reset for a victim with this header receives the victim's reset "+
				"token at their own host when the victim clicks the link.", p.identity, name, value,
				strings.ToUpper(where[:1])+where[1:], pwrRedactLink(l))
			f := buildHeaderFinding(p.cc, pwrPoisoning, "high", "firm",
				fmt.Sprintf("%s: %s -> %s", name, value, pwrRedactLink(l)), detail)
			f.Solution = "Build reset links from a configured, trusted base URL, never from the Host or a " +
				"forwarding header of the request."
			return f, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// token analysis
// ---------------------------------------------------------------------------

func (p *pwrProber) analyse(ctx context.Context, samples []*pwrIssuance, all *[]*pwrIssuance) (*Finding, error) {
	var vals []string
	var servers []int64
	var locals []time.Time
	for _, s := range samples {
		if t, ok := s.primary(); ok {
			vals = append(vals, t.value)
			servers = append(servers, s.server)
			locals = append(locals, s.recv)
		}
	}
	if len(vals) < 3 {
		return nil, nil
	}
	// 1. A constant token.
	if pwrAllEqual(vals) {
		pred := map[string]bool{vals[0]: true}
		next, err := p.issue(ctx, p.raw, nil, true)
		if err != nil {
			return nil, err
		}
		*all = append(*all, next)
		got, ok := next.primary()
		if !ok || !pred[got.value] {
			return nil, nil
		}
		return p.predictableFinding(vals, got.value, fmt.Sprintf("Every reset request returned the same token "+
			"(%d samples over %s), so the next token was predicted to be that value before it was requested, "+
			"and the next reset issued exactly it.", len(vals), locals[len(locals)-1].Sub(locals[0]).Round(time.Second))), nil
	}
	// 2. A decoded template with one varying decimal field: clock or counter.
	if m := pwrNumericModel(vals); m != nil {
		if f, err := p.predictNumeric(ctx, m, vals, servers, all); err != nil || f != nil {
			return f, err
		}
		if m.digits <= 6 && len(pwrDistinct(vals)) >= 4 {
			return p.lowEntropyFinding(vals, math.Pow(10, float64(m.digits)),
				fmt.Sprintf("the %s token differs between samples only in a %d-digit decimal field", m.encoding, m.digits)), nil
		}
	}
	// 3. The varying part's keyspace.
	if len(pwrDistinct(vals)) >= 4 {
		ks, why := pwrKeyspace(vals)
		if ks > 0 && ks <= pwrMaxKeyspace {
			return p.lowEntropyFinding(vals, ks, why), nil
		}
	}
	return nil, nil
}

// pwrNumModel is a token that, decoded, is a fixed template with one varying decimal field.
type pwrNumModel struct {
	encoding string // raw, base64url, base64, hex
	parts    []string
	field    int // index into nums
	nums     [][]string
	digits   int
}

func (m *pwrNumModel) value(i int) int64 {
	n, _ := strconv.ParseInt(m.nums[i][m.field], 10, 64)
	return n
}

// render rebuilds the encoded token with the varying field set to v.
func (m *pwrNumModel) render(v int64) string {
	var b strings.Builder
	for i, part := range m.parts {
		b.WriteString(part)
		if i < len(m.nums[0]) {
			if i == m.field {
				b.WriteString(strconv.FormatInt(v, 10))
			} else {
				b.WriteString(m.nums[0][i])
			}
		}
	}
	return pwrEncode(m.encoding, b.String())
}

var pwrDigits = regexp.MustCompile(`[0-9]+`)

func pwrNumericModel(vals []string) *pwrNumModel {
	for _, enc := range []string{"base64url", "base64", "hex", "raw"} {
		var decoded []string
		ok := true
		for _, v := range vals {
			d, good := pwrDecodeAs(enc, v)
			if !good || pwrEncode(enc, d) != v {
				ok = false
				break
			}
			decoded = append(decoded, d)
		}
		if !ok {
			continue
		}
		parts := pwrDigits.Split(decoded[0], -1)
		var nums [][]string
		for _, d := range decoded {
			if strings.Join(pwrDigits.Split(d, -1), "#") != strings.Join(parts, "#") {
				ok = false
				break
			}
			nums = append(nums, pwrDigits.FindAllString(d, -1))
		}
		if !ok || len(nums[0]) == 0 {
			continue
		}
		field := -1
		for j := range nums[0] {
			varies := false
			for i := range nums {
				if nums[i][j] != nums[0][j] {
					varies = true
				}
			}
			if varies {
				if field >= 0 {
					field = -2 // more than one varying field
					break
				}
				field = j
			}
		}
		if field < 0 {
			continue
		}
		digits := 0
		for i := range nums {
			if len(nums[i][field]) > digits {
				digits = len(nums[i][field])
			}
			if len(nums[i][field]) > 18 {
				ok = false
			}
		}
		if !ok {
			continue
		}
		return &pwrNumModel{encoding: enc, parts: parts, field: field, nums: nums, digits: digits}
	}
	return nil
}

func (p *pwrProber) predictNumeric(ctx context.Context, m *pwrNumModel, vals []string, servers []int64,
	all *[]*pwrIssuance) (*Finding, error) {

	n := len(vals)
	// Clock: every sample's field within a few seconds of the server's own Date header.
	scale := int64(0)
	for _, s := range []int64{1, 1000} {
		match := true
		for i := 0; i < n; i++ {
			if servers[i] == 0 {
				match = false
				break
			}
			d := m.value(i) - servers[i]*s
			if d < -5*s || d > 5*s {
				match = false
				break
			}
		}
		if match {
			scale = s
			break
		}
	}
	var lo, hi int64
	var model string
	if scale > 0 {
		if !p.offsetSet {
			return nil, nil
		}
		// The prediction is made BEFORE the request: the server clock for the coming send.
		now := float64(time.Now().UnixNano())/1e9 + p.offset
		lo, hi = int64(math.Floor((now-2)*float64(scale))), int64(math.Ceil((now+4)*float64(scale)))
		unit := "seconds"
		if scale == 1000 {
			unit = "milliseconds"
		}
		model = fmt.Sprintf("the %s-decoded token carries the server's clock in %s (every sample within 5s of the "+
			"response's Date header)", m.encoding, unit)
	} else {
		// Counter: a constant positive step.
		step := m.value(1) - m.value(0)
		if step <= 0 {
			return nil, nil
		}
		for i := 2; i < n; i++ {
			if m.value(i)-m.value(i-1) != step {
				return nil, nil
			}
		}
		// Other requests for the same identity may advance the counter in between: allow three steps.
		lo, hi = m.value(n-1)+step, m.value(n-1)+3*step
		model = fmt.Sprintf("the %s-decoded token carries a counter that grew by %d between every sample", m.encoding, step)
	}
	next, err := p.issue(ctx, p.raw, nil, true)
	if err != nil {
		return nil, err
	}
	*all = append(*all, next)
	got, ok := next.primary()
	if !ok {
		return nil, nil
	}
	v, hit := pwrInPrediction(m, vals, lo, hi, got.value)
	if !hit {
		return nil, nil
	}
	guesses := hi - lo + 1
	return p.predictableFinding(vals, got.value, fmt.Sprintf("Model: %s. Before the next reset was requested, "+
		"its token was predicted to be one of %d values (field in [%d, %d], the rest of the token unchanged); the "+
		"token then issued was one of them (field %d).", model, guesses, lo, hi, v)), nil
}

// pwrInPrediction reports whether got is the model's token with its field inside [lo, hi]: the same
// encoding and template as the samples, and exactly the rendering of that field value.
func pwrInPrediction(m *pwrNumModel, vals []string, lo, hi int64, got string) (int64, bool) {
	m2 := pwrNumericModel(append(append([]string(nil), vals...), got))
	if m2 == nil || m2.field != m.field || m2.encoding != m.encoding {
		return 0, false
	}
	v := m2.value(len(m2.nums) - 1)
	if v < lo || v > hi || m.render(v) != got {
		return v, false
	}
	return v, true
}

func (p *pwrProber) predictableFinding(vals []string, predicted, how string) *Finding {
	detail := fmt.Sprintf("Reset tokens issued for the test identity %s: %s. %s An attacker who knows the "+
		"model can compute a victim's reset token without receiving the message.", p.identity,
		pwrList(vals), how)
	f := buildHeaderFinding(p.cc, pwrPredictable, "high", "firm",
		fmt.Sprintf("predicted and issued: %s", predicted), detail)
	f.Solution = "Generate reset tokens from a cryptographically secure random source (at least 128 bits), " +
		"never from a user id, a clock or a counter, and store only a hash of the token server-side."
	return f
}

func (p *pwrProber) lowEntropyFinding(vals []string, keyspace float64, why string) *Finding {
	detail := fmt.Sprintf("%d reset tokens issued for the test identity %s (%s): %s. Computed keyspace: at most "+
		"%.0f values, so the token can be found by trying them against the confirm step unless every attempt is "+
		"throttled and the token expires quickly.", len(vals), p.identity, why, pwrList(vals), keyspace)
	f := buildHeaderFinding(p.cc, pwrLowEntropy, "medium", "firm",
		fmt.Sprintf("keyspace <= %.0f: %s", keyspace, pwrList(vals)), detail)
	f.Solution = "Use reset tokens of at least 128 bits from a cryptographically secure random source."
	return f
}

// pwrKeyspace estimates the keyspace of the part that varies between the samples.
func pwrKeyspace(vals []string) (float64, string) {
	pre := vals[0]
	suf := vals[0]
	for _, v := range vals[1:] {
		pre = pwrCommonPrefix(pre, v)
		suf = pwrCommonSuffix(suf, v)
	}
	maxLen := 0
	digits, hexa, lower, upper, other := true, true, false, false, false
	for _, v := range vals {
		mid := v[len(pre):]
		if len(mid) >= len(suf) {
			mid = mid[:len(mid)-len(suf)]
		} else {
			mid = ""
		}
		if len(mid) > maxLen {
			maxLen = len(mid)
		}
		for _, r := range mid {
			switch {
			case r >= '0' && r <= '9':
			case r >= 'a' && r <= 'f':
				digits = false
				lower = true
			case r >= 'A' && r <= 'F':
				digits = false
				upper = true
			case unicode.IsLower(r):
				digits, hexa = false, false
				lower = true
			case unicode.IsUpper(r):
				digits, hexa = false, false
				upper = true
			default:
				digits, hexa = false, false
				other = true
			}
		}
	}
	if maxLen == 0 {
		return 0, ""
	}
	cs, name := 64.0, "mixed"
	switch {
	case digits:
		cs, name = 10, "decimal"
	case hexa && !(lower && upper):
		cs, name = 16, "hexadecimal"
	case !other && !(lower && upper):
		cs, name = 36, "single-case alphanumeric"
	case !other:
		cs, name = 62, "alphanumeric"
	}
	return math.Pow(cs, float64(maxLen)), fmt.Sprintf("the tokens share %q before and %q after a varying "+
		"%s part of at most %d characters", pre, suf, name, maxLen)
}

func pwrCommonPrefix(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return a[:i]
}

func pwrCommonSuffix(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[len(a)-1-i] == b[len(b)-1-i] {
		i++
	}
	return a[len(a)-i:]
}

// noExpiry reports a JWT reset token with no exp claim.
func (p *pwrProber) noExpiry(samples []*pwrIssuance) *Finding {
	for _, s := range samples {
		t, ok := s.primary()
		if !ok {
			continue
		}
		claims, ok := pwrJWTClaims(t.value)
		if !ok {
			return nil
		}
		if _, has := claims["exp"]; has {
			return nil
		}
		names := make([]string, 0, len(claims))
		for k := range claims {
			names = append(names, k)
		}
		sort.Strings(names)
		detail := fmt.Sprintf("The reset token issued for the test identity %s is a JWT whose claims (%s) carry no "+
			"exp. A self-contained token without an expiry stays valid until the signing key changes unless the "+
			"server tracks it separately, which this check cannot see without waiting; hence tentative.",
			p.identity, strings.Join(names, ", "))
		f := buildHeaderFinding(p.cc, pwrNoExpiry, "medium", "tentative",
			fmt.Sprintf("JWT claims without exp: %s", strings.Join(names, ", ")), detail)
		f.Solution = "Give reset tokens a short lifetime (minutes) and enforce it server-side."
		return f
	}
	return nil
}

func pwrJWTClaims(tok string) (map[string]any, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, false
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	var head map[string]any
	if json.Unmarshal(hb, &head) != nil || head["alg"] == nil {
		return nil, false
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if json.Unmarshal(pb, &claims) != nil {
		return nil, false
	}
	return claims, true
}

// ---------------------------------------------------------------------------
// insecure link
// ---------------------------------------------------------------------------

func (p *pwrProber) insecureLink(issuances []*pwrIssuance) *Finding {
	for _, is := range issuances {
		for _, t := range is.tokens {
			if t.link == "" || !strings.HasPrefix(strings.ToLower(t.link), "http://") {
				continue
			}
			where := "the reset message sent to " + p.identity
			if t.source == "response" {
				where = "the reset request's response"
			}
			transport := "The application itself was reached over HTTP as well; the link is still the token's own " +
				"exposure to anyone on the path between the user and the server."
			if p.cc.Exchange.TLS {
				transport = "The application itself is served over HTTPS, so the link downgrades the reset to " +
					"cleartext."
			}
			detail := fmt.Sprintf("A link carrying an issued reset token (parameter %q) uses http://: %s, found in "+
				"%s. Opening it sends the token over an unencrypted connection, where a network attacker can read "+
				"it and reset the password first. %s", t.param, pwrRedactLink(t.link), where, transport)
			f := buildHeaderFinding(p.cc, pwrInsecureLink, "medium", "firm", pwrRedactLink(t.link), detail)
			f.Solution = "Build reset links with https:// and serve the reset page only over HTTPS (with HSTS)."
			return f
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// the confirm step: token in response, reuse, the link's page
// ---------------------------------------------------------------------------

func (p *pwrProber) useFresh(ctx context.Context, fresh *pwrIssuance) ([]*Finding, []string) {
	var findings []*Finding
	var failures []string
	mailed, haveMail := fresh.primary()
	var respTok []pwrToken
	for _, t := range fresh.tokens {
		if t.source == "response" {
			respTok = append(respTok, t)
		}
	}
	// The link's page: the referrer verdict and, when it holds a form, the confirm template.
	var link string
	if haveMail && mailed.link != "" {
		link = mailed.link
	} else {
		for _, t := range respTok {
			if t.link != "" {
				link = t.link
				break
			}
		}
	}
	var page *ProbeResponse
	var linkTok string
	if link != "" {
		if r, tok, err := p.fetchLinkPage(ctx, link, fresh); err != nil {
			failures = append(failures, err.Error())
		} else if r != nil {
			page, linkTok = r, tok
			if f, err := p.referer(ctx, link, linkTok, page); err != nil {
				failures = append(failures, err.Error())
			} else if f != nil {
				findings = append(findings, f)
			}
		}
	}
	tmpl := p.confirmTemplate(link, linkTok, page)

	// Token disclosed in the response: identical to the mailed token, or shown to work.
	for _, t := range respTok {
		if haveMail && t.value == mailed.value {
			findings = append(findings, p.inResponseFinding(t, "it is the same value the application mailed to "+
				"the test identity for that request, so the requester receives the account's reset secret "+
				"without access to its inbox", nil))
			respTok = nil
			break
		}
	}
	if tmpl == nil {
		if len(respTok) > 0 || haveMail {
			p.notes = append(p.notes, "no confirm request could be built (no form on the link's page and none "+
				"in the history for this host), so token use and reuse were not tested")
		}
		return findings, failures
	}
	if len(respTok) > 0 {
		t := respTok[0]
		res, err := p.useTwice(ctx, tmpl, t.value, false)
		if err != nil {
			failures = append(failures, err.Error())
		} else if res != nil && res.first {
			findings = append(findings, p.inResponseFinding(t, "the confirm request with it succeeded where the "+
				"same request with two random tokens of the same shape failed", res))
			mailed, haveMail = t, true
		}
	}
	if haveMail {
		res, err := p.useTwice(ctx, tmpl, mailed.value, true)
		if err != nil {
			failures = append(failures, err.Error())
		} else if res != nil && res.first && res.second {
			detail := fmt.Sprintf("A fresh reset token for the test identity %s was used twice in the confirm "+
				"request (%s), with two different new passwords. Both uses succeeded (HTTP %d and HTTP %d, the "+
				"same response), while the same request with two random tokens of the same shape failed (HTTP %d: "+
				"%s). A token that survives its use lets anyone who later obtains it (browser history, logs, a "+
				"Referer) reset the password again. The test identity's password is now %q.",
				p.identity, tmpl.source, res.u1.Status, res.u2.Status, res.c1.Status, excerpt(res.c1.Body, 0, 120),
				res.pass2)
			f := buildHeaderFinding(p.cc, pwrReusable, "medium", "firm",
				fmt.Sprintf("second use: HTTP %d %s", res.u2.Status, excerpt(res.u2.Body, 0, 120)), detail)
			f.Solution = "Invalidate a reset token as soon as it is used, and invalidate all outstanding tokens " +
				"when the password changes."
			findings = append(findings, f)
		}
	}
	return findings, failures
}

func (p *pwrProber) inResponseFinding(t pwrToken, proof string, res *pwrUse) *Finding {
	where := fmt.Sprintf("field %q", t.param)
	if t.link != "" {
		where = fmt.Sprintf("a link (%s)", pwrRedactLink(t.link))
	}
	detail := fmt.Sprintf("The response to the reset request for the test identity %s carries the reset token in "+
		"%s; %s. Anyone can request a reset for any account and read the token from the response, which is an "+
		"account takeover.", p.identity, where, proof)
	if res != nil {
		detail += fmt.Sprintf(" The test identity's password is now %q.", res.pass1)
	}
	f := buildHeaderFinding(p.cc, pwrTokenInResponse, "high", "firm",
		fmt.Sprintf("%s = %s", t.param, t.value), detail)
	f.Solution = "Deliver the reset token only through the out-of-band channel (the account's email or phone); " +
		"the reset request's response must be the same whether or not the account exists and must never carry the token."
	return f
}

// pwrConfirm is a confirm request with the place the token and the new password go.
type pwrConfirm struct {
	raw       string
	tokenName string
	tokenKind bcheck.IpKind
	passNames map[string]bool
	source    string
}

func (c *pwrConfirm) with(token, pass string) (string, error) {
	raw := c.raw
	set := false
	for round := 0; round < 8; round++ {
		points, _ := bcheck.EnumerateWith([]byte(raw), []string{"query", "body"}, bcheck.EnumerateOptions{})
		changed := false
		for _, pt := range points {
			pt := pt
			var v string
			switch {
			case pt.Name == c.tokenName && pt.Kind == c.tokenKind && !set:
				v = token
				set = true
			case c.passNames[pt.Name] && pwrDecode(pt.BaseValue) != pass:
				v = pass
			default:
				continue
			}
			out, err := pt.Apply([]byte(raw), v, false)
			if err != nil {
				return "", err
			}
			raw = string(out)
			changed = true
			break
		}
		if !changed {
			break
		}
	}
	if !set {
		return "", fmt.Errorf("password reset: the confirm template lost its token parameter %q", c.tokenName)
	}
	return raw, nil
}

// confirmTemplate finds a confirm request: a form on the link's page, else a captured request to this
// host with a token parameter and a password parameter.
func (p *pwrProber) confirmTemplate(link, linkTok string, page *ProbeResponse) *pwrConfirm {
	if page != nil {
		if c := p.formTemplate(link, linkTok, page.Body); c != nil {
			return c
		}
	}
	return p.historyTemplate()
}

func (p *pwrProber) formTemplate(link, linkTok, body string) *pwrConfirm {
	lu, err := url.Parse(link)
	if err != nil {
		return nil
	}
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var forms []*xhtml.Node
	var walk func(n *xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode && n.Data == "form" {
			forms = append(forms, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	for _, form := range forms {
		action, method := pwrAttr(form, "action"), strings.ToUpper(pwrAttr(form, "method"))
		if method == "" {
			method = "GET"
		}
		au, err := lu.Parse(action)
		if err != nil || !pwrSameOrigin(au, lu) {
			continue
		}
		vals := url.Values{}
		var order []string
		passNames := map[string]bool{}
		tokenName := ""
		var inputs func(n *xhtml.Node)
		inputs = func(n *xhtml.Node) {
			if n.Type == xhtml.ElementNode && n.Data == "input" {
				name, typ, val := pwrAttr(n, "name"), strings.ToLower(pwrAttr(n, "type")), pwrAttr(n, "value")
				if name != "" && typ != "submit" && typ != "button" && typ != "image" {
					if typ == "password" {
						passNames[name] = true
						val = "x"
					}
					if linkTok != "" && val == linkTok {
						tokenName = name
					}
					if _, seen := vals[name]; !seen {
						order = append(order, name)
					}
					vals.Add(name, val)
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				inputs(c)
			}
		}
		inputs(form)
		if len(passNames) == 0 {
			continue
		}
		kind := bcheck.IpBody
		if tokenName == "" {
			// The token rides the action URL's query (an empty action submits to the link itself).
			for k, vs := range au.Query() {
				if len(vs) > 0 && vs[0] == linkTok {
					tokenName, kind = k, bcheck.IpQuery
				}
			}
		}
		if tokenName == "" {
			continue
		}
		var enc []string
		for _, k := range order {
			for _, v := range vals[k] {
				enc = append(enc, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
		encoded := strings.Join(enc, "&")
		target := au.EscapedPath()
		if target == "" {
			target = "/"
		}
		var raw string
		if method == "POST" {
			if au.RawQuery != "" {
				target += "?" + au.RawQuery
			}
			raw = fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: %d\r\n\r\n%s", target, au.Host, len(encoded), encoded)
		} else {
			q := au.RawQuery
			if q != "" && encoded != "" {
				q += "&"
			}
			raw = fmt.Sprintf("GET %s?%s HTTP/1.1\r\nHost: %s\r\n\r\n", target, q+encoded, au.Host)
			if kind == bcheck.IpBody {
				kind = bcheck.IpQuery
			}
		}
		if c := headerValue(p.raw, "Cookie"); c != "" {
			raw = pwrWithHeader(raw, "Cookie", c)
		}
		return &pwrConfirm{raw: raw, tokenName: tokenName, tokenKind: kind, passNames: passNames,
			source: fmt.Sprintf("the form on the reset link's page, %s %s", method, au.Path)}
	}
	return nil
}

func (p *pwrProber) historyTemplate() *pwrConfirm {
	s, ex := p.cc.Scanner, p.cc.Exchange
	if s == nil || s.store == nil {
		return nil
	}
	path, _, _ := strings.Cut(pwrRequestPath(p.raw), "?")
	var best *pwrConfirm
	bestScore := -1
	var bestID core.ExchangeID
	for _, e := range s.store.Exchanges() {
		if e == nil || e.ID == ex.ID || e.Host != ex.Host || e.Port != ex.Port || e.TLS != ex.TLS || e.Request == nil {
			continue
		}
		msg, err := s.store.Get(*e.Request)
		if err != nil {
			continue
		}
		raw := string(msg.Raw())
		points, _ := bcheck.EnumerateWith([]byte(raw), []string{"query", "body"}, bcheck.EnumerateOptions{})
		tokenName, kind := "", bcheck.IpKind("")
		passNames := map[string]bool{}
		for _, pt := range points {
			switch {
			case pwrPasswordName.MatchString(pt.Name):
				passNames[pt.Name] = true
			case tokenName == "" && pwrTokenName.MatchString(pt.Name):
				tokenName, kind = pt.Name, pt.Kind
			}
		}
		if tokenName == "" || len(passNames) == 0 {
			continue
		}
		score := 0
		if p2, _, _ := strings.Cut(pwrRequestPath(raw), "?"); p2 == path {
			score = 2
		} else if pwrResetWord.MatchString(p2) {
			score = 1
		}
		if score > bestScore || (score == bestScore && e.ID > bestID) {
			best = &pwrConfirm{raw: raw, tokenName: tokenName, tokenKind: kind, passNames: passNames,
				source: fmt.Sprintf("the captured confirm request %s (exchange %d)", e.Path, e.ID)}
			bestScore, bestID = score, e.ID
		}
	}
	return best
}

type pwrUse struct {
	c1, c2, u1, u2 ProbeResponse
	first, second  bool
	pass1, pass2   string
}

// useTwice sends the confirm request with two random tokens (the control), then with the token, and,
// when twice is set, with the token again under a second new password.
func (p *pwrProber) useTwice(ctx context.Context, c *pwrConfirm, token string, twice bool) (*pwrUse, error) {
	res := &pwrUse{pass1: pwrPassword(), pass2: pwrPassword()}
	b1, b2 := pwrBogus(token), pwrBogus(token)
	r1, err := c.with(b1, pwrPassword())
	if err != nil {
		return nil, err
	}
	r2, err := c.with(b2, pwrPassword())
	if err != nil {
		return nil, err
	}
	if res.c1, err = p.send(ctx, r1); err != nil {
		return nil, err
	}
	if res.c2, err = p.send(ctx, r2); err != nil {
		return nil, err
	}
	strip := []string{token, b1, b2}
	if res.c1.Status != res.c2.Status || pwrNorm(res.c1.Body, strip) != pwrNorm(res.c2.Body, strip) {
		// The failure answer is not stable, so nothing can be told apart from it.
		return nil, nil
	}
	u, err := c.with(token, res.pass1)
	if err != nil {
		return nil, err
	}
	if res.u1, err = p.send(ctx, u); err != nil {
		return nil, err
	}
	res.first = pwrSucceeded(res.u1, res.c1, strip)
	if !res.first || !twice {
		return res, nil
	}
	u, err = c.with(token, res.pass2)
	if err != nil {
		return nil, err
	}
	if res.u2, err = p.send(ctx, u); err != nil {
		return nil, err
	}
	res.second = pwrSucceeded(res.u2, res.c1, strip) && res.u2.Status == res.u1.Status &&
		pwrNorm(res.u2.Body, strip) == pwrNorm(res.u1.Body, strip)
	return res, nil
}

// pwrSucceeded: a 2xx answer different from the failure control, with no failure word, and either a
// success word or a control that named the failure.
func pwrSucceeded(u, control ProbeResponse, strip []string) bool {
	if u.Status < 200 || u.Status > 399 {
		return false
	}
	if u.Status == control.Status && pwrNorm(u.Body, strip) == pwrNorm(control.Body, strip) {
		return false
	}
	if pwrFailWord.MatchString(u.Body) {
		return false
	}
	return pwrSuccessWord.MatchString(u.Body) || pwrFailWord.MatchString(control.Body)
}

func pwrNorm(body string, strip []string) string {
	for _, s := range strip {
		if s != "" {
			body = strings.ReplaceAll(body, s, "")
		}
	}
	return pwrDigits.ReplaceAllString(body, "#")
}

// fetchLinkPage GETs the reset link when it points at the audited origin, and returns the page and the
// token the link carries.
func (p *pwrProber) fetchLinkPage(ctx context.Context, link string, is *pwrIssuance) (*ProbeResponse, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", nil
	}
	if !p.atAuditedOrigin(u) {
		p.notes = append(p.notes, "the reset link points outside the audited origin and was not opened: "+pwrRedactLink(link))
		return nil, "", nil
	}
	tok := ""
	for _, t := range is.tokens {
		if t.link == link {
			tok = t.value
		}
	}
	target := u.EscapedPath()
	if target == "" {
		target = "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: text/html,*/*\r\n\r\n", target, u.Host)
	if c := headerValue(p.raw, "Cookie"); c != "" {
		raw = pwrWithHeader(raw, "Cookie", c)
	}
	r, err := p.send(ctx, raw)
	if err != nil {
		return nil, "", err
	}
	return &r, tok, nil
}

func (p *pwrProber) atAuditedOrigin(u *url.URL) bool {
	ex := p.cc.Exchange
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	want := &url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%d", ex.Host, ex.Port)}
	return pwrSameOrigin(u, want)
}

func pwrSameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	ha, hb := strings.ToLower(a.Hostname()), strings.ToLower(b.Hostname())
	loop := func(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }
	return strings.EqualFold(a.Scheme, b.Scheme) && (ha == hb || (loop(ha) && loop(hb))) && port(a) == port(b)
}

// ---------------------------------------------------------------------------
// referrer
// ---------------------------------------------------------------------------

func (p *pwrProber) referer(ctx context.Context, link, token string, page *ProbeResponse) (*Finding, error) {
	if token == "" || page.Status < 200 || page.Status > 299 {
		return nil, nil
	}
	policy, from := pwrEffectivePolicy(string(page.Raw), page.Body)
	if b, err := p.cc.Browser(ctx); err == nil && b != nil {
		allow := func(u *url.URL) bool { return p.atAuditedOrigin(u) }
		sends, err := b.ObserveCrossOriginReferers(ctx, link, 2*time.Second, allow)
		if err != nil {
			return nil, fmt.Errorf("password reset: loading the reset page in the browser: %w", err)
		}
		for _, s := range sends {
			if s.Referer == "" || !strings.Contains(s.Referer, token) {
				continue
			}
			detail := fmt.Sprintf("The reset link for the test identity %s was opened in the browser. The page "+
				"requested %s (%s) from another origin with the header Referer: %s, which carries the reset "+
				"token. The request was blocked in the browser before it was sent, so the token did not leave; "+
				"a user's browser would send it. Effective referrer policy: %s (%s).", p.identity,
				pwrRedactLink(s.URL), s.ResourceType, pwrRedactLink(s.Referer), policy, from)
			f := buildHeaderFinding(p.cc, pwrReferer, "medium", "firm",
				fmt.Sprintf("Referer: %s -> %s", pwrRedactLink(s.Referer), pwrRedactLink(s.URL)), detail)
			f.Solution = "Serve the reset page with Referrer-Policy: no-referrer (or strict-origin), load no " +
				"third-party resources on it, and move the token out of the URL once the page has read it."
			return f, nil
		}
		return nil, nil
	}
	// No browser: decide from the page itself.
	if !pwrPolicyLeaksURL(policy) {
		return nil, nil
	}
	lu, _ := url.Parse(link)
	for _, ref := range pwrSubresources(page.Body) {
		ru, err := lu.Parse(ref)
		if err != nil || (ru.Scheme != "http" && ru.Scheme != "https") || pwrSameOrigin(ru, lu) {
			continue
		}
		detail := fmt.Sprintf("The page behind the reset link for the test identity %s (the URL carries the "+
			"token) declares the referrer policy %s (%s), which sends the full URL to other origins, and loads %s "+
			"from another origin. Every visit therefore sends the reset token to that origin in the Referer "+
			"header. (Decided from the page; no browser was available to observe it.)", p.identity, policy, from,
			pwrRedactLink(ru.String()))
		f := buildHeaderFinding(p.cc, pwrReferer, "medium", "firm",
			fmt.Sprintf("%s; subresource %s", policy, pwrRedactLink(ru.String())), detail)
		f.Solution = "Serve the reset page with Referrer-Policy: no-referrer (or strict-origin), load no " +
			"third-party resources on it, and move the token out of the URL once the page has read it."
		return f, nil
	}
	return nil, nil
}

// pwrEffectivePolicy returns the page's referrer policy: a meta referrer wins over the header (it is
// applied later), the last recognised token of either wins, and the browser default otherwise.
func pwrEffectivePolicy(rawResp, body string) (string, string) {
	known := map[string]bool{"no-referrer": true, "no-referrer-when-downgrade": true, "origin": true,
		"origin-when-cross-origin": true, "same-origin": true, "strict-origin": true,
		"strict-origin-when-cross-origin": true, "unsafe-url": true, "always": true, "never": true, "default": true}
	policy, from := "strict-origin-when-cross-origin", "browser default"
	for _, v := range headerValues(rawResp, "Referrer-Policy") {
		for _, tok := range strings.Split(v, ",") {
			if t := strings.ToLower(strings.TrimSpace(tok)); known[t] {
				policy, from = t, "Referrer-Policy header"
			}
		}
	}
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err == nil {
		var walk func(n *xhtml.Node)
		walk = func(n *xhtml.Node) {
			if n.Type == xhtml.ElementNode && n.Data == "meta" && strings.EqualFold(pwrAttr(n, "name"), "referrer") {
				if t := strings.ToLower(strings.TrimSpace(pwrAttr(n, "content"))); known[t] {
					policy, from = t, "meta referrer"
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(doc)
	}
	return policy, from
}

// pwrPolicyLeaksURL: does the policy send the full URL (with its query) to another origin?
func pwrPolicyLeaksURL(policy string) bool {
	switch policy {
	case "unsafe-url", "always":
		return true
	case "no-referrer-when-downgrade", "default":
		// The full URL to every destination that is not an https->http downgrade, which a third-party
		// https resource never is.
		return true
	}
	return false
}

func pwrSubresources(body string) []string {
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var out []string
	var walk func(n *xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode {
			switch n.Data {
			case "img", "script", "iframe", "source", "video", "audio", "embed", "track":
				if pol := strings.ToLower(pwrAttr(n, "referrerpolicy")); pol == "no-referrer" || pol == "origin" ||
					pol == "strict-origin" || pol == "same-origin" || pol == "strict-origin-when-cross-origin" {
					break
				}
				if v := pwrAttr(n, "src"); v != "" {
					out = append(out, v)
				}
			case "link":
				if rel := strings.ToLower(pwrAttr(n, "rel")); strings.Contains(rel, "stylesheet") ||
					strings.Contains(rel, "icon") || strings.Contains(rel, "preload") || strings.Contains(rel, "prefetch") {
					if v := pwrAttr(n, "href"); v != "" {
						out = append(out, v)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func pwrAttr(n *xhtml.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// token extraction
// ---------------------------------------------------------------------------

// pwrTokensInText finds reset-token candidates: token-named parameters of the URLs in text, and
// token-named string fields of a JSON body.
func pwrTokensInText(text string) []pwrToken {
	var out []pwrToken
	seen := map[string]bool{}
	add := func(t pwrToken) {
		key := t.value + "\x00" + t.link
		if len(t.value) < 4 || strings.ContainsAny(t.value, " \t\r\n") || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, t)
	}
	for _, l := range pwrURLs(text) {
		u, err := url.Parse(l)
		if err != nil {
			continue
		}
		q := u.Query()
		names := make([]string, 0, len(q))
		for k := range q {
			names = append(names, k)
		}
		sort.Slice(names, func(i, j int) bool {
			ti, tj := strings.Contains(strings.ToLower(names[i]), "token"), strings.Contains(strings.ToLower(names[j]), "token")
			if ti != tj {
				return ti
			}
			return names[i] < names[j]
		})
		found := false
		for _, k := range names {
			if pwrTokenName.MatchString(k) && len(q[k]) > 0 {
				add(pwrToken{value: q[k][0], link: l, param: k})
				found = true
				break
			}
		}
		if !found {
			segs := strings.Split(strings.Trim(u.Path, "/"), "/")
			if last := segs[len(segs)-1]; len(last) >= 16 && pwrMixed(last) && len(segs) > 1 &&
				pwrResetWord.MatchString(u.Path) {
				add(pwrToken{value: last, link: l, param: "path segment"})
			}
		}
	}
	var v any
	if json.Unmarshal([]byte(strings.TrimSpace(text)), &v) == nil {
		var walk func(key string, x any)
		walk = func(key string, x any) {
			switch t := x.(type) {
			case map[string]any:
				for k, c := range t {
					walk(k, c)
				}
			case []any:
				for _, c := range t {
					walk(key, c)
				}
			case string:
				if key != "" && pwrTokenName.MatchString(key) && !strings.Contains(t, "://") {
					add(pwrToken{value: t, param: key})
				}
			}
		}
		walk("", v)
	}
	return out
}

func pwrMixed(s string) bool {
	var d, l bool
	for _, r := range s {
		if unicode.IsDigit(r) {
			d = true
		} else if unicode.IsLetter(r) {
			l = true
		}
	}
	return d && l
}

// pwrURLs finds absolute URLs in text, HTML- and JSON-unescaped.
func pwrURLs(text string) []string {
	text = strings.ReplaceAll(text, `\/`, `/`)
	text = strings.ReplaceAll(text, `&`, `&`)
	text = strings.ReplaceAll(text, `=`, `=`)
	text = html.UnescapeString(text)
	var out []string
	seen := map[string]bool{}
	for _, m := range pwrURLRe.FindAllString(text, -1) {
		m = strings.TrimRight(m, ".,;)")
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func pwrRequestValues(raw string) map[string]bool {
	out := map[string]bool{}
	points, _ := bcheck.EnumerateWith([]byte(raw), []string{"query", "body", "cookie"}, bcheck.EnumerateOptions{})
	for _, pt := range points {
		out[pt.BaseValue] = true
		out[pwrDecode(pt.BaseValue)] = true
	}
	return out
}

// ---------------------------------------------------------------------------
// the test mailbox
// ---------------------------------------------------------------------------

// pwrMailbox reads the operator's test inbox: ResetMailboxURL with {identity} replaced by the
// (query-escaped) identity. The endpoint must return the identity's messages with their bodies: a
// JSON array of messages (top level, or the first array-valued field of an object) is diffed message
// by message; any other body is diffed by what was appended. It is the operator's infrastructure,
// read like the collaborator, never a target.
type pwrMailbox struct {
	url    string
	client *http.Client
	seen   map[string]int
	text   string
}

func newPwrMailbox(tmpl, identity string) *pwrMailbox {
	return &pwrMailbox{
		url:    strings.ReplaceAll(tmpl, "{identity}", url.QueryEscape(identity)),
		client: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}},
		seen:   map[string]int{},
	}
}

func (m *pwrMailbox) read(ctx context.Context) ([]string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("mailbox answered HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, "", err
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		var list []any
		switch t := v.(type) {
		case []any:
			list = t
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if a, ok := t[k].([]any); ok {
					list = a
					break
				}
			}
		}
		if list != nil {
			out := make([]string, 0, len(list))
			for _, x := range list {
				enc, _ := json.Marshal(x)
				out = append(out, string(enc))
			}
			return out, "", nil
		}
	}
	return nil, string(b), nil
}

func (m *pwrMailbox) prime(ctx context.Context) error {
	msgs, text, err := m.read(ctx)
	if err != nil {
		return err
	}
	for _, s := range msgs {
		m.seen[s]++
	}
	m.text = text
	return nil
}

// waitNew polls until new messages appear (then once more, briefly, for stragglers) or wait passes,
// and returns their text.
func (m *pwrMailbox) waitNew(ctx context.Context, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	var got []string
	var lastErr error
	settled := false
	for {
		msgs, text, err := m.read(ctx)
		if err != nil {
			lastErr = err
		} else {
			counts := map[string]int{}
			for _, s := range msgs {
				counts[s]++
				if counts[s] > m.seen[s] {
					m.seen[s]++
					got = append(got, pwrJSONText(s))
				}
			}
			if msgs == nil && text != m.text {
				switch {
				case strings.HasPrefix(text, m.text):
					got = append(got, text[len(m.text):])
				case strings.HasSuffix(text, m.text):
					got = append(got, text[:len(text)-len(m.text)])
				default:
					got = append(got, text)
				}
				m.text = text
			}
		}
		if len(got) > 0 {
			if settled {
				return strings.Join(got, "\n"), nil
			}
			settled = true
			deadline = time.Now().Add(300 * time.Millisecond)
		}
		if time.Now().After(deadline) {
			if len(got) > 0 {
				return strings.Join(got, "\n"), nil
			}
			if lastErr != nil {
				return "", lastErr
			}
			return "", fmt.Errorf("no new message within %s", wait)
		}
		select {
		case <-time.After(150 * time.Millisecond):
		case <-ctx.Done():
			return strings.Join(got, "\n"), ctx.Err()
		}
	}
}

// pwrJSONText flattens a JSON message to its string values.
func pwrJSONText(s string) string {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	var b strings.Builder
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		case string:
			b.WriteString(t)
			b.WriteString("\n")
		}
	}
	walk(v)
	return b.String()
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func pwrWithHeader(raw, name, value string) string {
	head, body, hasBody := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	out := []string{lines[0]}
	replaced := false
	for _, l := range lines[1:] {
		if k, _, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			if !replaced {
				out = append(out, name+": "+value)
				replaced = true
			}
			continue
		}
		out = append(out, l)
	}
	if !replaced {
		out = append(out, name+": "+value)
	}
	res := strings.Join(out, "\r\n") + "\r\n\r\n"
	if hasBody {
		res += body
	}
	return res
}

func pwrDecodeAs(enc, v string) (string, bool) {
	var b []byte
	var err error
	switch enc {
	case "raw":
		return v, true
	case "base64url":
		b, err = base64.RawURLEncoding.DecodeString(v)
	case "base64":
		b, err = base64.StdEncoding.DecodeString(v)
	case "hex":
		b, err = hex.DecodeString(v)
	}
	if err != nil || len(b) == 0 {
		return "", false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(b), true
}

func pwrEncode(enc, s string) string {
	switch enc {
	case "base64url":
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(s))
	case "hex":
		return hex.EncodeToString([]byte(s))
	}
	return s
}

func pwrAllEqual(vals []string) bool {
	for _, v := range vals[1:] {
		if v != vals[0] {
			return false
		}
	}
	return true
}

func pwrDistinct(vals []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range vals {
		out[v] = true
	}
	return out
}

func pwrList(vals []string) string {
	if len(vals) > 8 {
		vals = vals[:8]
	}
	return strings.Join(vals, ", ")
}

// pwrRedactLink keeps a link readable for the report; the token is the test identity's own.
func pwrRedactLink(l string) string {
	if len(l) > 220 {
		return l[:220] + "..."
	}
	return l
}

const pwrAlnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func pwrRand(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			b[i] = alphabet[0]
			continue
		}
		b[i] = alphabet[k.Int64()]
	}
	return string(b)
}

func pwrRandLower(n int) string { return pwrRand("abcdefghijklmnopqrstuvwxyz0123456789", n) }

// pwrPassword is a fresh new password that satisfies common complexity rules.
func pwrPassword() string { return "Bsy-" + pwrRand(pwrAlnum, 14) + "!9a" }

// pwrBogus is a random token of the same shape (each character replaced within its class).
func pwrBogus(tok string) string {
	out := []byte(tok)
	for i, c := range out {
		switch {
		case c >= '0' && c <= '9':
			out[i] = pwrRand("0123456789", 1)[0]
		case c >= 'a' && c <= 'z':
			out[i] = pwrRand("abcdefghijklmnopqrstuvwxyz", 1)[0]
		case c >= 'A' && c <= 'Z':
			out[i] = pwrRand("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1)[0]
		}
	}
	if string(out) == tok {
		return tok + pwrRandLower(4)
	}
	return string(out)
}
