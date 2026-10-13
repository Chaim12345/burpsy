package scanner

// Server-side parameter pollution (burpsy-react-ui-0vzb.3).
//
// A front end that builds a request to an internal API by pasting a user value into it — a query
// string, a REST path, a JSON body — lets the value's own delimiters become the internal request's
// structure: `&` starts a new internal parameter, `#` cuts the rest of the internal URL off, `/..`
// walks the internal path, `?` ends it, and `"` closes a JSON string. PortSwigger's research and
// Academy labs ("Server-side parameter pollution") are the reference.
//
// # The differential
//
// For one parameter whose original value is V, every probe is sent twice over:
//
//   - P, the probe: V extended with the delimiter, as a value the front end decodes, so the delimiter
//     itself reaches the internal request;
//   - C, its literal control: the same characters with the delimiter encoded once more (`%26` for `&`,
//     `\"` for `"`), so the front end decodes it to text that an internal API reading it as a value
//     sees as an ordinary, if odd, string;
//   - U, the plain control: V extended by random letters only, an unknown value with no delimiter.
//
// A probe is STRUCTURAL when P answers differently from C while C answers exactly like U: the
// delimiter changed the outcome and its literal spelling did not. It is EQUIVALENT when it is
// structural and P answers exactly like the baseline (V itself) while U does not: a value that is not
// V reached V's answer, which only happens when part of it was read as structure. Every random token
// is removed from every response before comparison and so are punctuation, percent-escapes, HTML
// entities and \u escapes, so a page that echoes its input answers P, C and U alike.
//
// # Rows (each one firm unless stated)
//
// Query string: an equivalent probe among `V&r1=r2` (unknown internal parameter ignored), `V&N=r`
// (first duplicate wins) and `r&N=V` (last duplicate wins), N being the parameter's own name, AND
// at least two structural probes among those and `V#r` (fragment truncation). Tentative instead,
// with no equivalence: `V&r1=r2` and an `&N=` probe are both structural and answer differently from
// each other — the internal API distinguishes WHICH parameter followed the `&` (an unknown one is
// refused one way, its own name another), which a filter refusing the character cannot do.
//
// REST path: an equivalent probe among `V/r/..` (a dot-segment walk normalised away) and
// `V?r1=r2` (the internal path ends at `?`), AND at least two structural probes among those and
// `V#r`. Normalising a path alone is what any file lookup does; the URL delimiters are what make it
// an internal URL.
//
// Structured data: `V","r1":"r2` makes the internal JSON carry a field r1 whose value is r2, seen
// in a JSON response as a separate member (an object with key r1 and value r2) that the literal
// control's response lacks; or it is equivalent AND the bare quote `V"` is structural without being
// equivalent (the internal document broke — a sanitiser that cut the value at a quote would make the
// bare quote equivalent too).
//
// Every structural or equivalent probe is sent again with fresh random tokens and must hold with the
// same answers, and the baseline is re-fetched last and must still answer as it did.
//
// A value that is itself a URL or an absolute path (`https://...`, `//host`, `/a/b`) is not probed: the
// server is meant to request it whole, so its own `?` and `#` are the client's to write.
//
// # Safety
//
// Every probe value is the original value plus random letters, so no probe names an internal
// parameter or field the request did not already carry, and no override value is anything but the
// original value: a probe can only reach the object the captured request already reached. PUT, PATCH
// and DELETE requests and paths naming a destructive operation are not probed. Nor is a POST whose path
// or any parameter name suggests a message or payment side effect (reset, forgot, password, mail,
// email, send, notify, invite, sms, otp, verify, subscribe, contact, message, comment, order, checkout,
// pay, transfer, purchase): a probe set re-sends the request ~30 times, which for a password-reset or
// contact form is ~30 emails to a real address. The canonical PortSwigger lab (POST /forgot-password)
// is therefore not probed; a GET carrying the same value still is.
//
// # Not done
//
// No internal parameter or field names are guessed (field=, role=, ../openapi.json): exploiting the
// pollution is the tester's step, and a guessed name proves nothing a random one does not. A value
// placed in the URL path of the captured request itself (a REST front end) is not an insertion point
// here. An internal API that answers every malformed request identically and ignores nothing yields
// no structural probe and is not reported.
//
// # Catalogue rows
//
// Burp's catalogue has no server-side parameter pollution row; these are burpsy's own rows
// (BurpsyNativeRows, native/b5002c00-b5002c20), reported by a check riding "Client-side HTTP
// parameter pollution (reflected)" behind its own switch, check_server_side_parameter_pollution.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// burpsy's own row names; see BurpsyNativeRows.
const (
	IssueSSPPQuery = "Server-side parameter pollution (query string)"
	IssueSSPPPath  = "Server-side parameter pollution (REST path)"
	IssueSSPPJSON  = "Server-side parameter pollution (structured data)"
)

// ssppEnabled is the check's own switch.
func ssppEnabled(c *ScanConfig) bool { return c != nil && c.CheckServerSideParamPollution }

const (
	// ssppMaxPoints bounds the parameters probed, and ssppMaxSends every request sent, per audited
	// request.
	ssppMaxPoints = 6
	ssppMaxSends  = 240
)

var errSSPPBudget = errors.New("sspp: request budget spent")

// ssppTrace, when set (tests only), receives each decided parameter's first-round outcomes and the
// probes that held, so a test can assert which guard kept a safe twin quiet.
var ssppTrace func(target, param string, first, held map[string]*ssppOutcome)

// csHPPOrSSPP runs the "Client-side HTTP parameter pollution (reflected)" row's own check (behind
// CheckExtendedActive) and the server-side parameter pollution check (behind
// CheckServerSideParamPollution). A proven server-side finding is returned even when the sibling's
// run was undecided.
func csHPPOrSSPP(cs CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil {
			return nil, nil
		}
		var cf []*Finding
		var cerr error
		if finalChecksEnabled(cc.Config) || !ssppEnabled(cc.Config) {
			cf, cerr = cs(ctx, cc)
		}
		var sf []*Finding
		var serr error
		if ssppEnabled(cc.Config) {
			sf, serr = checkServerSideParamPollution(ctx, cc)
		}
		switch {
		case len(sf) > 0:
			return append(cf, sf...), nil
		case cerr != nil:
			return cf, cerr
		case serr != nil:
			return cf, serr
		}
		return cf, nil
	}
}

// ssppDestructive are path words naming an operation a re-sent request must not repeat.
var ssppDestructive = map[string]bool{
	"delete": true, "remove": true, "destroy": true, "drop": true, "purge": true, "transfer": true,
	"pay": true, "payment": true, "purchase": true, "checkout": true, "cancel": true, "revoke": true,
	"logout": true, "signout": true, "unsubscribe": true, "deactivate": true,
}

// ssppSideEffect are words that, in a POST's path or in one of its parameter names, suggest the request
// sends a message or moves money: re-sending it ~30 times would send ~30 emails, texts or orders to
// whoever the captured request addressed.
var ssppSideEffect = map[string]bool{
	"reset": true, "forgot": true, "password": true, "passwd": true, "mail": true, "email": true, "send": true,
	"notify": true, "notification": true, "invite": true, "invitation": true, "sms": true, "otp": true,
	"verify": true, "verification": true, "subscribe": true, "contact": true, "message": true, "comment": true,
	"order": true, "checkout": true, "pay": true, "payment": true, "transfer": true, "purchase": true,
}

// ssppProbeable reports whether the captured request may be re-sent with probes: GET or POST, no
// destructive path word, and for a POST no message or payment word in its path or parameter names.
func ssppProbeable(raw string) bool {
	line, _, _ := strings.Cut(raw, "\r\n")
	method, _, _ := strings.Cut(line, " ")
	method = strings.ToUpper(method)
	switch method {
	case "GET", "POST":
	default:
		return false
	}
	for _, w := range nosqliPathWords(raw) {
		if ssppDestructive[w] || method == "POST" && ssppSideEffect[w] {
			return false
		}
	}
	if method == "POST" {
		pts, _ := bcheck.Enumerate([]byte(raw), []string{"query", "body"})
		for _, pt := range pts {
			for _, w := range ssppNameWords(pt.Name) {
				if ssppSideEffect[w] {
					return false
				}
			}
		}
	}
	return true
}

// ssppNameWords splits a parameter name (camelCase, snake_case, a JSON path) into lower-case words,
// plus the words joined, so "e_mail" and "emailAddress" both read as mail.
func ssppNameWords(name string) []string {
	name = nosqliCamel.ReplaceAllString(name, "${1} ${2}")
	ws := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r < 'a' || r > 'z' })
	if len(ws) > 1 {
		ws = append(ws, strings.Join(ws, ""))
	}
	return ws
}

// checkServerSideParamPollution probes one audited request.
func checkServerSideParamPollution(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, fmt.Errorf("sspp: no scanner or exchange: %w", errCapabilityMissing)
	}
	if cc.Scanner.sender == nil {
		return nil, fmt.Errorf("sspp: no sender; an active probe cannot be sent: %w", errCapabilityMissing)
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" || !ssppProbeable(raw) {
		return nil, nil
	}
	var kinds []string
	for _, k := range cc.ProbeInsertionKinds() {
		if k == "query" || k == "body" {
			kinds = append(kinds, k)
		}
	}
	if len(kinds) == 0 {
		return nil, nil
	}
	pre, _ := bcheck.EnumerateWith([]byte(raw), kinds, cc.ProbeEnumerateOptions())
	if len(ssppPoints(pre)) == 0 {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, kinds)
	if err != nil {
		return nil, fmt.Errorf("sspp: %w", err)
	}
	p := &ssppProber{cc: cc, h: h, raw: raw}
	return p.run(ctx, ssppPoints(h.Points()))
}

// ssppPoints are the query and body values with an original value to extend.
func ssppPoints(pts []bcheck.InsertionPoint) []bcheck.InsertionPoint {
	var out []bcheck.InsertionPoint
	for _, pt := range pts {
		if (pt.Kind == bcheck.IpQuery || pt.Kind == bcheck.IpBody) && pt.BaseValue != "" {
			out = append(out, pt)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------

type ssppProber struct {
	cc    *CheckContext
	h     *ProbeHarness
	raw   string
	sends int
	// masks are every random token this run has sent, removed from every response before comparison.
	masks []string
}

func (p *ssppProber) send(ctx context.Context, pt bcheck.InsertionPoint, value string, appending bool) (ProbeResponse, error) {
	if p.sends >= ssppMaxSends {
		return ProbeResponse{}, errSSPPBudget
	}
	req, err := pt.Apply([]byte(p.raw), value, appending)
	if err != nil {
		return ProbeResponse{}, err
	}
	p.sends++
	return p.h.send(ctx, req)
}

// fresh is a new random token, registered for masking: lower-case letters only, so it survives every
// encoding unchanged, never reads as a number, and is never a delimiter.
func (p *ssppProber) fresh() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz"
	b := make([]byte, 9)
	for i := range b {
		b[i] = alphabet[rand.IntN(len(alphabet))]
	}
	s := string(b)
	p.masks = append(p.masks, s)
	return s
}

func (p *ssppProber) run(ctx context.Context, points []bcheck.InsertionPoint) ([]*Finding, error) {
	if len(points) > ssppMaxPoints {
		points = points[:ssppMaxPoints]
	}
	var failures []string
	for _, pt := range points {
		f, err := p.point(ctx, pt)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s %q: %v", pt.Kind, pt.Name, err))
			if errors.Is(err, errSSPPBudget) {
				break
			}
			continue
		}
		if f != nil {
			return []*Finding{f}, nil
		}
	}
	if len(failures) > 0 {
		return nil, fmt.Errorf("sspp: %s", strings.Join(failures, "; "))
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// probes
// ---------------------------------------------------------------------------

// ssppTokens are one probe's random tokens.
type ssppTokens struct{ a, b string }

// ssppProbe is one delimiter technique. build returns the probe value and its literal control; when
// whole is set they replace the parameter's decoded value, otherwise they are appended to its wire
// value (and need no decoding).
type ssppProbe struct {
	id        string
	technique string
	whole     bool
	build     func(t ssppTokens, v, name string) (probe, literal string)
}

const (
	ssppQAmp   = "query-unknown-parameter"
	ssppQFirst = "query-duplicate-first"
	ssppQLast  = "query-duplicate-last"
	ssppHash   = "fragment-truncation"
	ssppPDot   = "path-dot-segment"
	ssppPQuery = "path-query-delimiter"
	ssppJField = "json-field"
	ssppJQuote = "json-quote"
)

var ssppProbes = []ssppProbe{
	{id: ssppQAmp, technique: "an injected `&` adds an internal query parameter",
		build: func(t ssppTokens, _, _ string) (string, string) {
			return "&" + t.a + "=" + t.b, "%26" + t.a + "%3D" + t.b
		}},
	{id: ssppQFirst, technique: "an injected `&` repeats the parameter after the original value",
		build: func(t ssppTokens, _, n string) (string, string) {
			return "&" + n + "=" + t.a, "%26" + n + "%3D" + t.a
		}},
	{id: ssppQLast, technique: "an injected `&` repeats the parameter with the original value after a random one",
		whole: true,
		build: func(t ssppTokens, v, n string) (string, string) {
			return t.a + "&" + n + "=" + v, t.a + "%26" + n + "%3D" + v
		}},
	{id: ssppHash, technique: "an injected `#` truncates the internal URL",
		build: func(t ssppTokens, _, _ string) (string, string) { return "#" + t.a, "%23" + t.a }},
	{id: ssppPDot, technique: "an injected `/<random>/..` walks the internal path and is normalised away",
		build: func(t ssppTokens, _, _ string) (string, string) {
			return "/" + t.a + "/..", "%2F" + t.a + "%2F.."
		}},
	{id: ssppPQuery, technique: "an injected `?` ends the internal path",
		build: func(t ssppTokens, _, _ string) (string, string) {
			return "?" + t.a + "=" + t.b, "%3F" + t.a + "%3D" + t.b
		}},
	{id: ssppJField, technique: "an injected `\",\"` adds a member to the internal JSON document",
		build: func(t ssppTokens, _, _ string) (string, string) {
			return `","` + t.a + `":"` + t.b, `\",\"` + t.a + `\":\"` + t.b
		}},
	{id: ssppJQuote, technique: "an injected `\"` closes the internal JSON string",
		build: func(t ssppTokens, _, _ string) (string, string) { return `"`, `\"` }},
}

// ssppOutcome is one probe's round.
type ssppOutcome struct {
	tokens         ssppTokens
	probe, literal string
	P, C, U        ProbeResponse
	structural     bool
	equivalent     bool
	// field is set for the JSON member probe when P's JSON response carries the injected member and
	// C's does not.
	field bool
}

// ssppNameToken is a parameter name an injected `&name=` can repeat verbatim.
var ssppNameToken = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

// decodedValue is the point's original value as the application decodes it, for the probes that
// replace the whole value. ok is false when the container is not one this check can decode.
func ssppDecodedValue(pt bcheck.InsertionPoint) (string, bool) {
	if w, err := pt.WireValue(`"`); err == nil && w == `\"` {
		var s string
		if json.Unmarshal([]byte(`"`+pt.BaseValue+`"`), &s) != nil {
			return "", false
		}
		return s, true
	}
	s, err := url.QueryUnescape(pt.BaseValue)
	if err != nil {
		return "", false
	}
	return s, true
}

// ssppIsURL reports whether a value is an absolute URL, a scheme-relative one or an absolute path.
func ssppIsURL(value string, decodable bool, wire string) bool {
	if !decodable {
		w := strings.ToLower(wire)
		return strings.Contains(w, "://") || strings.Contains(w, "%3a%2f%2f") || strings.HasPrefix(w, "/") ||
			strings.HasPrefix(w, "%2f")
	}
	return strings.Contains(value, "://") || strings.HasPrefix(value, "/")
}

// point decides one parameter. A nil finding and nil error is "not shown".
func (p *ssppProber) point(ctx context.Context, pt bcheck.InsertionPoint) (*Finding, error) {
	base := p.h.Baseline()
	value, decodable := ssppDecodedValue(pt)
	// A value that is itself a URL or a path is one the server is meant to request whole: its own `?`
	// and `#` are the client's to write, and a fetch honouring them is the SSRF rows' concern.
	if ssppIsURL(value, decodable, pt.BaseValue) {
		return nil, nil
	}
	name := pt.Name
	if !ssppNameToken.MatchString(name) {
		name = ""
	}
	// The parameter must matter: an unknown plain value answers unlike the original one.
	u, err := p.send(ctx, pt, p.fresh()+p.fresh(), true)
	if err != nil {
		return nil, err
	}
	if p.same(u, base) {
		return nil, nil
	}
	round := func(pr ssppProbe, prevU *ProbeResponse) (*ssppOutcome, error) {
		t := ssppTokens{p.fresh(), p.fresh()}
		probe, literal := pr.build(t, value, name)
		o := &ssppOutcome{tokens: t, probe: probe, literal: literal}
		var err error
		if o.P, err = p.send(ctx, pt, probe, !pr.whole); err != nil {
			return nil, err
		}
		if o.C, err = p.send(ctx, pt, literal, !pr.whole); err != nil {
			return nil, err
		}
		if prevU != nil {
			o.U = *prevU
		} else if o.U, err = p.send(ctx, pt, p.fresh()+p.fresh(), true); err != nil {
			return nil, err
		}
		o.structural = !p.same(o.P, o.C) && p.same(o.C, o.U)
		o.equivalent = o.structural && p.same(o.P, base) && !p.same(o.U, base)
		if pr.id == ssppJField {
			o.field = p.same(o.C, o.U) && ssppHasMember(o.P.Body, t.a, t.b) && !ssppHasMember(o.C.Body, t.a, t.b)
		}
		return o, nil
	}

	first := map[string]*ssppOutcome{}
	for _, pr := range ssppProbes {
		if pr.whole && !decodable {
			continue
		}
		if (pr.id == ssppQFirst || pr.id == ssppQLast) && name == "" {
			continue
		}
		o, err := round(pr, &u)
		if err != nil {
			return nil, err
		}
		first[pr.id] = o
	}
	// Only a probe that showed something is repeated, with fresh tokens and a fresh plain control,
	// and it must answer the same way again: the same classification and the same pages.
	held := map[string]*ssppOutcome{}
	for _, pr := range ssppProbes {
		o := first[pr.id]
		if o == nil || !(o.structural || o.field) {
			continue
		}
		again, err := round(pr, nil)
		if err != nil {
			return nil, err
		}
		if again.structural == o.structural && again.equivalent == o.equivalent && again.field == o.field &&
			p.same(again.P, o.P) && p.same(again.C, o.C) {
			held[pr.id] = o
		}
	}

	if ssppTrace != nil {
		ssppTrace(exchangeURL(p.cc.Exchange), pt.Name, first, held)
	}
	row, certainty, used := ssppDecide(held, first, p.same)
	if row == "" {
		return nil, nil
	}
	// The page the original value produces must still be that page.
	if p.sends >= ssppMaxSends {
		return nil, errSSPPBudget
	}
	p.sends++
	again, err := p.h.send(ctx, p.h.RequestBytes())
	if err != nil {
		return nil, err
	}
	if !p.same(again, base) {
		return nil, nil
	}
	return p.finding(row, certainty, pt, value, used, held, u), nil
}

// ssppDecide applies the row rules to the probes that held. used lists the probes the verdict rests
// on, in the order they are reported.
//
// first holds every probe's first round, held only the probes that showed something twice.
func ssppDecide(held, first map[string]*ssppOutcome, same func(a, b ProbeResponse) bool) (row, certainty string, used []string) {
	st := func(id string) bool { return held[id] != nil && held[id].structural }
	eq := func(id string) bool { return held[id] != nil && held[id].equivalent }
	pick := func(ids ...string) []string {
		var out []string
		for _, id := range ids {
			if held[id] != nil {
				out = append(out, id)
			}
		}
		return out
	}
	count := func(ids ...string) int {
		n := 0
		for _, id := range ids {
			if st(id) {
				n++
			}
		}
		return n
	}

	// REST path.
	if (eq(ssppPDot) || eq(ssppPQuery)) && count(ssppPDot, ssppPQuery, ssppHash) >= 2 {
		return IssueSSPPPath, "firm", pick(ssppPDot, ssppPQuery, ssppHash)
	}
	// Query string.
	if (eq(ssppQAmp) || eq(ssppQFirst) || eq(ssppQLast)) && count(ssppQAmp, ssppQFirst, ssppQLast, ssppHash) >= 2 {
		return IssueSSPPQuery, "firm", pick(ssppQAmp, ssppQFirst, ssppQLast, ssppHash)
	}
	if st(ssppQAmp) {
		for _, dup := range []string{ssppQFirst, ssppQLast} {
			if st(dup) && !same(held[ssppQAmp].P, held[dup].P) {
				return IssueSSPPQuery, "tentative", pick(ssppQAmp, dup, ssppHash)
			}
		}
	}
	// Structured data.
	if f := held[ssppJField]; f != nil {
		// A member that came back is the internal document's only if the bare quote did not break the
		// RESPONSE document: a front end concatenating its own JSON reply shows the member too, and is
		// a different flaw.
		if q := first[ssppJQuote]; f.field && q != nil && ssppDocumentIntact(q.P.Body) {
			return IssueSSPPJSON, "firm", pick(ssppJField, ssppJQuote)
		}
		if f.equivalent && st(ssppJQuote) && !eq(ssppJQuote) {
			return IssueSSPPJSON, "firm", pick(ssppJField, ssppJQuote)
		}
	}
	return "", "", nil
}

// ---------------------------------------------------------------------------
// response comparison
// ---------------------------------------------------------------------------

// ssppView is what two responses must share to count as the same answer.
type ssppView struct {
	status   int
	location string
	cookies  string
	body     string
}

var (
	ssppEntity  = regexp.MustCompile(`&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);`)
	ssppUEscape = regexp.MustCompile(`\\[uU][0-9a-fA-F]{4}`)
	ssppPercent = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	ssppNonWord = regexp.MustCompile(`[^A-Za-z0-9]+`)
)

// norm removes from s everything an echo of the probe can vary in: the random tokens, the volatile
// runs nosqli masks, and every way a delimiter can be spelt (escapes, entities, punctuation itself).
func (p *ssppProber) norm(s string) string {
	for _, m := range p.masks {
		s = strings.ReplaceAll(s, m, "")
	}
	s = nosqliVolatileHex.ReplaceAllString(s, "\x00")
	s = nosqliVolatileDigits.ReplaceAllString(s, "\x00")
	s = ssppEntity.ReplaceAllString(s, " ")
	s = ssppUEscape.ReplaceAllString(s, " ")
	s = ssppPercent.ReplaceAllString(s, " ")
	return ssppNonWord.ReplaceAllString(s, "")
}

func (p *ssppProber) view(r ProbeResponse) ssppView {
	head, _, _ := strings.Cut(string(r.Raw), "\r\n\r\n")
	var names []string
	for _, sc := range headerValues(head, "set-cookie") {
		n, _, _ := strings.Cut(sc, "=")
		names = append(names, strings.TrimSpace(n))
	}
	sort.Strings(names)
	return ssppView{
		status:   r.Status,
		location: p.norm(headerValue(head, "location")),
		cookies:  strings.Join(names, ","),
		body:     p.norm(r.Body),
	}
}

func (p *ssppProber) same(a, b ProbeResponse) bool { return p.view(a) == p.view(b) }

// ssppHasMember reports whether body is (or holds) a JSON document with an object carrying the member
// key: value. A page echoing the probe as text never parses into one.
func ssppHasMember(body, key, value string) bool {
	body = strings.TrimSpace(body)
	var doc any
	if json.Unmarshal([]byte(body), &doc) != nil {
		i, j := strings.Index(body, "{"), strings.LastIndex(body, "}")
		if i < 0 || j <= i || json.Unmarshal([]byte(body[i:j+1]), &doc) != nil {
			return false
		}
	}
	var walk func(any) bool
	walk = func(n any) bool {
		switch v := n.(type) {
		case map[string]any:
			if s, ok := v[key].(string); ok && s == value {
				return true
			}
			for _, c := range v {
				if walk(c) {
					return true
				}
			}
		case []any:
			for _, c := range v {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	return walk(doc)
}

// ssppDocumentIntact reports whether a body that looks like a JSON document is one.
func ssppDocumentIntact(body string) bool {
	b := strings.TrimSpace(body)
	if !strings.HasPrefix(b, "{") && !strings.HasPrefix(b, "[") {
		return true
	}
	return json.Valid([]byte(b))
}

// ---------------------------------------------------------------------------
// the finding
// ---------------------------------------------------------------------------

func ssppShort(r ProbeResponse) string {
	return fmt.Sprintf("HTTP %d, %q", r.Status, excerpt(r.Body, 0, 120))
}

func (p *ssppProber) finding(row, certainty string, pt bcheck.InsertionPoint, value string, used []string,
	held map[string]*ssppOutcome, u ProbeResponse) *Finding {
	byID := map[string]ssppProbe{}
	for _, pr := range ssppProbes {
		byID[pr.id] = pr
	}
	render := func(pr ssppProbe, s string) string {
		if pr.whole {
			return s
		}
		return value + s
	}
	var ev strings.Builder
	fmt.Fprintf(&ev, "%s %q (original value %q). Baseline: %s. Plain unknown value: %s.\n",
		pt.Kind, pt.Name, value, ssppShort(p.h.Baseline()), ssppShort(u))
	var techniques []string
	for _, id := range used {
		o, pr := held[id], byID[id]
		verdict := "changed the answer"
		switch {
		case o.field:
			verdict = fmt.Sprintf("returned a separate JSON member %q: %q", o.tokens.a, o.tokens.b)
		case o.equivalent:
			verdict = "answered exactly like the original value"
		}
		techniques = append(techniques, pr.technique)
		fmt.Fprintf(&ev, "- %s: %q %s (%s); its literal control %q answered like the plain value (%s).\n",
			pr.technique, render(pr, o.probe), verdict, ssppShort(o.P), render(pr, o.literal), ssppShort(o.C))
	}
	ev.WriteString("Each probe held a second time with fresh random tokens, and the original request still " +
		"answered as it did.")
	detail := fmt.Sprintf("The value of %s %q is placed into a request the server makes to another component "+
		"without being encoded for it: %s. Probe values decoded by the front end changed the server's answer "+
		"in ways their once-more-encoded literal spellings did not.", pt.Kind, pt.Name,
		strings.Join(techniques, "; "))
	if certainty == "tentative" {
		detail += " No probe reproduced the original answer, so this rests on the internal request " +
			"answering differently for an unknown injected parameter and for the parameter's own name."
	}
	f := buildHeaderFinding(p.cc, row, "medium", certainty, ev.String(), detail)
	f.Param = pt.Name
	f.Solution = "Encode every value for the context it is placed in when building a request to another " +
		"component: URL-encode query parameter values and path segments (including / ? # & and =), and build " +
		"JSON and XML with a serialiser rather than string concatenation. Validate the value against what it " +
		"should be (an identifier's character set) before forwarding it, and have the internal API reject " +
		"unknown and duplicated parameters."
	return f
}
