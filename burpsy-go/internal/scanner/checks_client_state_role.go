package scanner

// Privilege escalation through forged client-held state (burpsy-react-ui-0vzb.32).
//
// # The gap this closes
//
// The insecure-deserialization check's weakest family ("unsigned JSON state") shows that a cookie
// carries JSON the server binds without an integrity check, so a client CAN forge its fields. It
// says nothing about what forging them does. When one of those fields is the user's role or an
// admin flag, the server is taking its authorization decision from a value the client wrote, which
// is an authorization failure in its own right (CWE-285; the cookie form is CWE-565) and the usual
// reason the unsigned state matters at all.
//
// # What is proved, and how
//
// Only on a GET or HEAD request (a forged administrator replaying a state-changing request would
// perform an administrative action), and only in a cookie whose whole value is a JSON object, as
// text or base64. A value with a signature beside it (a JWT, "payload.signature") does not decode as
// one JSON object and is never touched. For each top-level member whose NAME says it carries an
// authorization attribute (role, group, privilege, permission, access level, account type; or an
// is-admin style boolean), three forgeries of the same document are sent:
//
//   - the document as issued (A), re-serialised the same way as the others;
//   - the member set to a privileged value (P): "admin" or "administrator" in the issued value's
//     letter case for a string or a list of strings, true for a false admin flag;
//   - a control (C): the same member set to a random value of the same length and case (a string),
//     or the flag under a random name of the same length (a boolean).
//
// It is a finding only when P is answered 2xx, P and A each answer the same on a repeat, and P's
// answer differs from both A's and C's once every submitted value (in every case and escaping) and
// every dynamic token is masked. Against A, that says the forged value changed what the server did;
// against C, that the server recognised THIS value rather than reacting to any change of the member
// (a role it validates and rejects, or a member it echoes, answers P and C alike). P's answer must
// also carry at least two words that neither A's nor C's has, none of them a refusal: a new error
// message is a rejection, not a privilege.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// IssueForgedClientRole is burpsy's own row name; see BurpsyNativeRows.
const IssueForgedClientRole = "Privilege escalation via forged client-side state"

// csrMaxSends bounds every request this probe sends for one audited exchange.
const csrMaxSends = 20

var errCSRBudget = errors.New("forged client-side state: request budget spent")

// csrRoleKey names a member that carries a role-like authorization attribute.
var csrRoleKey = regexp.MustCompile(`(?i)^(?:user_?|account_?)?(?:role|roles|group|groups|privilege|privileges|` +
	`permission|permissions|access_?level|access|account_?type|user_?type|usertype|authority|authorities)$`)

// csrFlagKey names a boolean member that says whether the user is privileged.
var csrFlagKey = regexp.MustCompile(`(?i)^(?:is_?|has_?)?(?:admin|administrator|superuser|super_?user|staff|root|` +
	`privileged|elevated)(?:_?(?:user|role|access))?$`)

// csrRefusal recognises a word that says the forged request was refused rather than served.
var csrRefusal = regexp.MustCompile(`(?i)^(?:invalid|error|errors|failed|failure|denied|forbidden|unauthori[sz]ed|` +
	`rejected|refused|exception|illegal|malformed|unknown|unrecogni[sz]ed|unsupported|tampered|mismatch|expired)$`)

var csrWord = regexp.MustCompile(`[A-Za-z][A-Za-z']{2,}`)

// csrPrivilegedNames are the privileged values a string member is forged to, in order.
var csrPrivilegedNames = []string{"admin", "administrator"}

// csrMember is one top-level member of the JSON document, in document order.
type csrMember struct {
	key   string
	value json.RawMessage
}

// csrDoc is a cookie value that is one JSON object, and how it was written.
type csrDoc struct {
	members []csrMember
	enc     deserEncoding
}

// csrParseDoc reads a cookie value that is exactly one JSON object, raw or base64.
func csrParseDoc(v string) (*csrDoc, bool) {
	v = strings.TrimSpace(v)
	if d, err := url.PathUnescape(v); err == nil {
		v = d
	}
	if strings.HasPrefix(v, "{") {
		if m, ok := csrMembers([]byte(v)); ok {
			return &csrDoc{members: m, enc: deserRaw}, true
		}
		return nil, false
	}
	if len(v) < 4 || !deserBase64Value.MatchString(v) {
		return nil, false
	}
	b, err := decodeFlexibleBase64(v)
	if err != nil {
		return nil, false
	}
	m, ok := csrMembers(bytes.TrimSpace(b))
	if !ok {
		return nil, false
	}
	enc := deserBase64
	if strings.ContainsAny(v, "-_") {
		enc = deserBase64URL
	}
	return &csrDoc{members: m, enc: enc}, true
}

// csrMembers splits a JSON object into its top-level members, keeping their order.
func csrMembers(b []byte) ([]csrMember, bool) {
	if !json.Valid(b) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	var out []csrMember
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, false
		}
		k, ok := t.(string)
		if !ok {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		out = append(out, csrMember{key: k, value: raw})
	}
	return out, len(out) > 0
}

// with renders the document with member i replaced (or renamed, when key is not empty).
func (d *csrDoc) with(i int, key string, value json.RawMessage) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for j, m := range d.members {
		if j > 0 {
			b.WriteByte(',')
		}
		k, v := m.key, m.value
		if j == i {
			if key != "" {
				k = key
			}
			v = value
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// csrForgery is one privileged forgery of one member, with its control.
type csrForgery struct {
	key                string
	issued, priv, ctrl []byte
	privNote, ctrlNote string
	mask               []string
}

// csrMatchCase writes s in the letter case of like: upper, lower or capitalised.
func csrMatchCase(s, like string) string {
	switch {
	case like != "" && like == strings.ToUpper(like) && like != strings.ToLower(like):
		return strings.ToUpper(s)
	case like != "" && unicode.IsUpper(rune(like[0])):
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// csrRandomLike is a random letter string of len(s) in s's letter case, never equal to s.
func csrRandomLike(s string) string {
	for {
		r := []byte(randHex(len(s) * 2))
		out := make([]byte, len(s))
		for i := range out {
			out[i] = 'a' + r[i]%26
			if i < len(s) && s[i] >= 'A' && s[i] <= 'Z' {
				out[i] -= 'a' - 'A'
			}
		}
		if string(out) != s && !strings.EqualFold(string(out), "admin") {
			return string(out)
		}
	}
}

// csrForgeries lists the privileged forgeries of a document, string roles first.
func csrForgeries(d *csrDoc) []csrForgery {
	var out []csrForgery
	for i, m := range d.members {
		issued := d.with(i, "", m.value)
		switch {
		case csrRoleKey.MatchString(m.key):
			var s string
			var list []string
			isList := false
			if json.Unmarshal(m.value, &s) != nil {
				if json.Unmarshal(m.value, &list) != nil || len(list) == 0 {
					continue
				}
				isList = true
			}
			like := s
			if isList {
				like = list[0]
				for _, v := range list {
					if strings.Contains(strings.ToLower(v), "admin") {
						like = ""
					}
				}
				if like == "" {
					continue
				}
			} else if s == "" || strings.Contains(strings.ToLower(s), "admin") {
				continue
			}
			for _, name := range csrPrivilegedNames {
				pv := csrMatchCase(name, like)
				cv := csrRandomLike(pv)
				var pj, cj []byte
				if isList {
					pj, _ = json.Marshal(append(append([]string{}, list...), pv))
					cj, _ = json.Marshal(append(append([]string{}, list...), cv))
				} else {
					pj, _ = json.Marshal(pv)
					cj, _ = json.Marshal(cv)
				}
				out = append(out, csrForgery{
					key: m.key, issued: issued,
					priv: d.with(i, "", pj), ctrl: d.with(i, "", cj),
					privNote: fmt.Sprintf("%q set to %s", m.key, pj), ctrlNote: fmt.Sprintf("%q set to %s", m.key, cj),
					mask: []string{pv, cv, like},
				})
			}
		case csrFlagKey.MatchString(m.key) && string(bytes.TrimSpace(m.value)) == "false":
			ck := csrRandomLike(m.key)
			out = append(out, csrForgery{
				key: m.key, issued: issued,
				priv: d.with(i, "", json.RawMessage("true")), ctrl: d.with(i, ck, json.RawMessage("true")),
				privNote: fmt.Sprintf("%q set to true", m.key), ctrlNote: fmt.Sprintf("true under the unused name %q", ck),
				mask: []string{ck},
			})
		}
	}
	return out
}

// csrCandidates are the cookie points whose value is one JSON object with a forgeable member.
func csrCandidates(points []bcheck.InsertionPoint) []bcheck.InsertionPoint {
	var out []bcheck.InsertionPoint
	for _, p := range points {
		if p.Kind != bcheck.IpCookie || p.AppendRebuildsValue() || deserSessionCookie.MatchString(p.Name) {
			continue
		}
		if d, ok := csrParseDoc(p.BaseValue); ok && len(csrForgeries(d)) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// checkForgedClientRole probes the audited request's client-held authorization attributes.
func checkForgedClientRole(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	switch strings.ToUpper(cc.Exchange.Method) {
	case "GET", "HEAD":
	default:
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	pre, _ := bcheck.EnumerateWith([]byte(raw), []string{"cookie"}, cc.ProbeEnumerateOptions())
	if len(csrCandidates(pre)) == 0 {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, []string{"cookie"})
	if err != nil {
		return nil, fmt.Errorf("forged client-side state: %w", err)
	}
	p := &csrProber{cc: cc, h: h}
	for _, pt := range csrCandidates(h.Points()) {
		d, _ := csrParseDoc(pt.BaseValue)
		for _, fg := range csrForgeries(d) {
			f, err := p.try(ctx, pt, d.enc, fg)
			if errors.Is(err, errCSRBudget) {
				return nil, nil
			}
			if f != nil {
				return []*Finding{f}, nil
			}
		}
	}
	return nil, nil
}

type csrProber struct {
	cc    *CheckContext
	h     *ProbeHarness
	sends int
}

func (c *csrProber) send(ctx context.Context, p bcheck.InsertionPoint, value string) (ProbeResponse, error) {
	if c.sends >= csrMaxSends {
		return ProbeResponse{}, errCSRBudget
	}
	c.sends++
	return c.h.Send(ctx, p, value)
}

// csrUnusable is an answer that says the request was throttled or never reached the application.
func csrUnusable(r ProbeResponse) bool {
	switch r.Status {
	case 0, 429, 502, 503, 504:
		return true
	}
	return false
}

// csrMaskForms adds every letter case of each value, so a role echoed lower-cased is masked too.
func csrMaskForms(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v == "" {
			continue
		}
		out = append(out, v, strings.ToLower(v), strings.ToUpper(v))
		if len(v) > 1 {
			out = append(out, strings.ToUpper(v[:1])+strings.ToLower(v[1:]))
		}
	}
	return out
}

// csrNovelWords are the words of a that appear in neither b nor c.
func csrNovelWords(a, b, c string) []string {
	seen := map[string]bool{}
	for _, w := range csrWord.FindAllString(b+" "+c, -1) {
		seen[strings.ToLower(w)] = true
	}
	var out []string
	for _, w := range csrWord.FindAllString(a, -1) {
		lw := strings.ToLower(w)
		if !seen[lw] {
			seen[lw] = true
			out = append(out, w)
		}
	}
	return out
}

func (c *csrProber) try(ctx context.Context, p bcheck.InsertionPoint, enc deserEncoding, fg csrForgery) (*Finding, error) {
	ea := deserEncode(fg.issued, enc, p.Kind)
	ep := deserEncode(fg.priv, enc, p.Kind)
	ec := deserEncode(fg.ctrl, enc, p.Kind)
	mask := csrMaskForms(append(append([]string{}, fg.mask...), ea, ep, ec,
		string(fg.issued), string(fg.priv), string(fg.ctrl)))
	fp := func(r ProbeResponse) string { return authFingerprint(r, mask) }

	var rs [5]ProbeResponse
	// issued, privileged, control, issued, privileged: each side's two sends sit an odd distance
	// apart, so an answer that alternates by itself cannot repeat on both, and each side is checked
	// against its own repeat.
	for i, v := range []string{ea, ep, ec, ea, ep} {
		r, err := c.send(ctx, p, v)
		if err != nil {
			if errors.Is(err, errCSRBudget) {
				return nil, err
			}
			return nil, nil
		}
		if csrUnusable(r) {
			return nil, nil
		}
		rs[i] = r
		if i == 1 && (r.Status < 200 || r.Status > 299 || fp(r) == fp(rs[0])) {
			return nil, nil
		}
	}
	a, pr, ct := rs[0], rs[1], rs[2]
	fa, fpr, fc := fp(a), fp(pr), fp(ct)
	if fa != fp(rs[3]) || fpr != fp(rs[4]) || fpr == fa || fpr == fc {
		return nil, nil
	}
	mb := func(r ProbeResponse) string { return maskDynamic(maskSubmitted(r.Body, mask)) }
	novel := csrNovelWords(mb(pr), mb(a), mb(ct))
	for _, w := range novel {
		if csrRefusal.MatchString(w) {
			return nil, nil
		}
	}
	if len(novel) < 2 {
		return nil, nil
	}
	return c.finding(p, enc, fg, a, pr, ct, novel), nil
}

func (c *csrProber) finding(p bcheck.InsertionPoint, enc deserEncoding, fg csrForgery, a, pr, ct ProbeResponse, novel []string) *Finding {
	if len(novel) > 8 {
		novel = novel[:8]
	}
	evidence := fmt.Sprintf("cookie %q (%s JSON): %s -> HTTP %d %q; as issued -> HTTP %d %q; control -> HTTP %d %q",
		p.Name, enc, fg.privNote, pr.Status, excerpt(pr.Body, 0, 120), a.Status, excerpt(a.Body, 0, 120),
		ct.Status, excerpt(ct.Body, 0, 120))
	detail := fmt.Sprintf("The cookie %q carries an unsigned JSON object, and its member %q names the user's "+
		"authorization. Three versions of the same object were sent, each re-serialised the same way: as the "+
		"application issued it, with %s, and with %s as a control. The forged privileged value was accepted "+
		"(HTTP %d) and answered differently from both the issued value and the control once every submitted "+
		"value and dynamic token was masked, and the issued and forged answers each repeated exactly. The "+
		"forged answer adds content the other two lack (%s). The application therefore takes this "+
		"authorization decision from a value the client wrote: any user can grant themselves the privileged "+
		"role by editing the cookie. Only a GET was re-sent, and nothing was changed on the server.",
		p.Name, fg.key, fg.privNote, fg.ctrlNote, pr.Status, strings.Join(novel, ", "))
	f := buildHeaderFinding(c.cc, IssueForgedClientRole, "high", "firm", evidence, detail)
	f.Param = p.Name
	return f
}
