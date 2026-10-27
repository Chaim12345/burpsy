package scanner

// Insecure deserialization, proved by a benign differential (0vzb.10).
//
// # The gap this closes
//
// The tree had one deserialization row, the passive "Serialized object in HTTP message": it says a
// blob that LOOKS serialized crossed the wire. It cannot say whether the server deserializes what a
// client sends, and it says nothing at all when the value the client holds is not yet a recognisable
// blob (an opaque cookie the application only fills in later). Burp leaves the active half to
// extensions (Java Deserialization Scanner, Freddy), whose issues carry the generic extension type.
//
// # What is proved, and how
//
// Never with a gadget. Every probe is a PAIR of values that are the same length, use the same
// alphabet and the same encoding, and differ only in whether a deserializer would accept them:
//
//   - Java object stream: a stream whose one object is a NONEXISTENT class, against the identical
//     stream with its type code corrupted. A deserializer answers ClassNotFoundException (or a
//     class filter's rejection) to the first and StreamCorruptedException to the second; anything
//     that does not run ObjectInputStream sees two equally meaningless byte strings.
//   - PHP serialize(): an object of a nonexistent class (unserialize builds __PHP_Incomplete_Class),
//     against the same text with a wrong declared length or member count (unserialize fails).
//   - Python pickle: a pickle that only pushes a small int, against the same bytes with an
//     undefined opcode where STOP was. Neither imports or calls anything.
//   - JSON with polymorphic typing (Jackson "@class", fastjson "@type"): a JDK collection class
//     that resolves (java.util.HashMap / TreeMap, which instantiate nothing but an empty map),
//     against a nonexistent class name of the same length. A binder that resolves type ids answers
//     the two differently; a plain JSON parser, or a binder bound to one class, cannot tell them
//     apart.
//   - Unsigned JSON state in a cookie: an empty object against an unterminated one. This is the
//     weakest form (the application builds a fixed type from client data it never signed) and is
//     reported at low severity and tentative confidence.
//
// # The evidence rule
//
// A pair is sent twice, the second time with fresh class names and a different corruption, in the
// order accepted, rejected, rejected, accepted (so a response that alternates by itself cannot line
// up with the pairs). It is a finding only when both accepted answers match each other, both
// rejected answers match each other, and the two sides differ. Answers are compared on status,
// redirect target and body, with every submitted value (encoded and decoded, in its URL-, HTML- and
// JSON-escaped spellings) and every dynamic token masked, so an application that echoes the value
// back - or echoes a class name in its error - is not mistaken for one that parsed it. An answer that
// looks like a filter or a throttle (403, 406, 429, 502-504) makes the pair inconclusive.
//
// # Where it probes
//
// Top-level query, body and cookie values only (a nested point would re-encode the container it
// sits in). A value that already looks serialized - by the same recogniser as the passive row, in
// base64, hex or raw text - is probed in its own format and encoding only. A value that is
// base64-encoded or raw JSON gets the JSON probes. An opaque cookie (client-held state that is not
// yet recognisable, the case the passive row cannot see) gets the whole set in base64, plus PHP as
// percent-encoded text. Anything else is not probed: an opaque query parameter is overwhelmingly a
// search term or an id, and sending it object streams would be noise.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// IssueInsecureDeserialization is burpsy's own row name; see BurpsyNativeRows.
const IssueInsecureDeserialization = "Insecure deserialization"

// insecureDeserializationEnabled is the check's own switch.
func insecureDeserializationEnabled(c *ScanConfig) bool {
	return c != nil && c.CheckInsecureDeserialization
}

// deserMaxPoints bounds how many insertion points of one request are probed; deserMaxSends bounds
// every request the check sends for one audited exchange.
const (
	deserMaxPoints = 6
	deserMaxSends  = 48
)

var errDeserBudget = errors.New("insecure deserialization: request budget spent")

// react2ShellOrDeserialization runs the React2Shell row (CheckExtendedActive) and the insecure
// deserialization check (CheckInsecureDeserialization) under one descriptor, each behind its own
// switch. React2Shell is the only active Burp row classified CWE-502, and the registry admits one
// descriptor per Burp type, so burpsy's row rides it. A proven deserialization finding is returned
// even when the React2Shell half failed: a sibling's error must not hide a proof.
func react2ShellOrDeserialization(r2s CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		var rF []*Finding
		var rErr error
		if remainingChecksEnabled(cc.Config) {
			rF, rErr = r2s(ctx, cc)
		}
		var dF []*Finding
		var dErr error
		if insecureDeserializationEnabled(cc.Config) {
			dF, dErr = checkInsecureDeserialization(ctx, cc)
			// The forged-role probe (checks_client_state_role.go) is the same switch's second
			// question about the same client-held JSON: not whether it is parsed, but whether an
			// authorization member in it is believed.
			roleF, roleErr := checkForgedClientRole(ctx, cc)
			dF = append(dF, roleF...)
			if dErr == nil {
				dErr = roleErr
			}
		}
		switch {
		case len(dF) > 0:
			return append(rF, dF...), nil
		case rErr != nil:
			return rF, rErr
		case dErr != nil:
			return nil, dErr
		}
		return rF, nil
	}
}

// deserKinds are the insertion-point kinds a serialized value is carried in.
var deserKinds = []string{"query", "body", "cookie"}

// checkInsecureDeserialization probes the audited request's deserialization candidates.
func checkInsecureDeserialization(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	// Plan before the harness exists: the harness sends a baseline, and a request with nothing to
	// probe should cost nothing.
	pre, _ := bcheck.EnumerateWith([]byte(raw), deserKinds, cc.ProbeEnumerateOptions())
	if len(deserCandidates(pre)) == 0 {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, deserKinds)
	if err != nil {
		return nil, fmt.Errorf("insecure deserialization: %w", err)
	}
	p := &deserProber{cc: cc, h: h}
	var out []*Finding
	for _, c := range deserCandidates(h.Points()) {
		f, err := p.point(ctx, c)
		if errors.Is(err, errDeserBudget) {
			break
		}
		if err != nil {
			return out, err
		}
		if f != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

// deserEncoding is how a probe's bytes are written into the point.
type deserEncoding int

const (
	deserBase64    deserEncoding = iota // standard alphabet, padded
	deserBase64URL                      // URL-safe alphabet, unpadded
	deserHex                            // lower-case hex
	deserRaw                            // the bytes as text (percent-encoded in a cookie)
)

func (e deserEncoding) String() string {
	switch e {
	case deserBase64:
		return "base64"
	case deserBase64URL:
		return "URL-safe base64"
	case deserHex:
		return "hex"
	default:
		return "text"
	}
}

// deserPair is one accepted/rejected pair of probe values, plus what to mask in the answers.
type deserPair struct {
	accepted, rejected []byte
	mask               []string
	// acceptedNote and rejectedNote say, for the finding, what each value is.
	acceptedNote, rejectedNote string
}

// deserFamily is one serialization format's probe.
type deserFamily struct {
	name                 string
	severity, confidence string
	// proves is the sentence the finding states as proved.
	proves string
	// pair builds the i-th (0 or 1) pair; the second uses fresh names and a different corruption.
	pair func(i int) deserPair
}

// deserPlan is one family in one encoding at one point.
type deserPlan struct {
	fam *deserFamily
	enc deserEncoding
}

type deserCandidate struct {
	point bcheck.InsertionPoint
	plans []deserPlan
}

// deserCandidates picks the points worth probing and the probes for each, recognised values first.
func deserCandidates(points []bcheck.InsertionPoint) []deserCandidate {
	var recognised, opaque []deserCandidate
	for _, p := range points {
		if p.AppendRebuildsValue() {
			continue
		}
		switch p.Kind {
		case bcheck.IpQuery, bcheck.IpBody, bcheck.IpCookie:
		default:
			continue
		}
		plans, known := deserPlansFor(p)
		if len(plans) == 0 {
			continue
		}
		if known {
			recognised = append(recognised, deserCandidate{p, plans})
		} else {
			opaque = append(opaque, deserCandidate{p, plans})
		}
	}
	out := append(recognised, opaque...)
	if len(out) > deserMaxPoints {
		out = out[:deserMaxPoints]
	}
	return out
}

var deserBase64Value = regexp.MustCompile(`^[A-Za-z0-9+/_-]{2,}={0,2}$`)

// deserSessionCookie names cookies that hold a server-side session or analytics id, never an object.
var deserSessionCookie = regexp.MustCompile(`(?i)^(jsessionid|phpsessid|asp\.net_sessionid|aspsessionid\w*|` +
	`cfid|cftoken|sid|sessionid|connect\.sid|_ga\w*|_gid|_gat\w*|_fbp|_hj\w*|__utm\w|__cf\w*|cf_clearance|` +
	`xsrf-token|csrftoken|_csrf|__requestverificationtoken\w*)$`)

// deserPlansFor returns the probes for one point and whether its value was recognised (as opposed to
// an opaque cookie that gets the whole set).
func deserPlansFor(p bcheck.InsertionPoint) ([]deserPlan, bool) {
	v := strings.TrimSpace(p.BaseValue)
	// A query or form value is percent-decoded by the application; a cookie has no escaping of its
	// own, so only an explicit percent layer is undone there ('+' stays '+', which base64 needs).
	unescaped := v
	if p.Kind == bcheck.IpCookie {
		if d, err := url.PathUnescape(v); err == nil {
			unescaped = d
		}
	} else if d, err := url.QueryUnescape(v); err == nil {
		unescaped = d
	}
	b64 := deserBase64
	if strings.ContainsAny(v, "-_") {
		b64 = deserBase64URL
	}
	for _, cand := range []string{v, unescaped} {
		if len(cand) < 4 || !deserBase64Value.MatchString(cand) {
			continue
		}
		if decoded, err := decodeFlexibleBase64(cand); err == nil {
			if plans := deserPlansForBytes(decoded, b64, p.Kind == bcheck.IpCookie); len(plans) > 0 {
				return plans, true
			}
		}
	}
	lower := strings.ToLower(unescaped)
	switch {
	case strings.HasPrefix(lower, javaMagicHex):
		return []deserPlan{{deserJavaFamily, deserHex}}, true
	case phpSerializedPrefix.MatchString(unescaped):
		return []deserPlan{{deserPHPFamily, deserRaw}}, true
	case strings.HasPrefix(unescaped, "{") && json.Valid([]byte(unescaped)):
		return deserJSONPlans([]byte(unescaped), deserRaw, false), true
	}
	if p.Kind != bcheck.IpCookie || deserSessionCookie.MatchString(p.Name) {
		return nil, false
	}
	// An opaque cookie: client-held state this scanner cannot read. Every format, base64 first.
	return []deserPlan{
		{deserJavaFamily, b64},
		{deserPHPFamily, b64},
		{deserPHPFamily, deserRaw},
		{deserPickleFamily, b64},
		{deserRubyFamily, b64},
		{deserJacksonFamily, b64},
		{deserTypedJSONFamily, b64},
	}, false
}

// deserPlansForBytes maps a decoded base64 value to the probes for its format.
func deserPlansForBytes(decoded []byte, enc deserEncoding, cookie bool) []deserPlan {
	switch detectSerializedPrefix(decoded) {
	case SerializedJava:
		return []deserPlan{{deserJavaFamily, enc}}
	case SerializedPHP:
		return []deserPlan{{deserPHPFamily, enc}}
	case SerializedPython:
		return []deserPlan{{deserPickleFamily, enc}}
	case SerializedRuby:
		return []deserPlan{{deserRubyFamily, enc}}
	}
	t := strings.TrimSpace(string(decoded))
	if strings.HasPrefix(t, "{") && json.Valid([]byte(t)) {
		return deserJSONPlans([]byte(t), enc, cookie)
	}
	return nil
}

// deserJSONPlans are the probes for a JSON value: the type-id probe matching the metadata the value
// already carries (Jackson's "@class" when it carries none), and for a cookie the unsigned-state
// probe.
func deserJSONPlans(doc []byte, enc deserEncoding, cookie bool) []deserPlan {
	fam := deserJacksonFamily
	if m := jsonTypeMetaPattern.FindSubmatch(doc); m != nil && string(m[1]) == "@type" {
		fam = deserFastjsonFamily
	}
	plans := []deserPlan{{fam, enc}}
	if cookie {
		plans = append(plans, deserPlan{deserTypedJSONFamily, enc})
	}
	return plans
}

// ---------------------------------------------------------------------------
// probe families
// ---------------------------------------------------------------------------

// deserClassName is a nonexistent, package-qualified class name of exactly n characters.
func deserClassName(n int) string {
	s := "bsy." + randHex(8) + ".Q" + randHex(64)
	return s[:n]
}

// deserJavaStream is a Java Object Serialization Stream holding one object of class cls with no
// fields: STREAM_MAGIC, STREAM_VERSION, then tc (TC_OBJECT, 0x73, in the accepted form), TC_CLASSDESC,
// the class name, serialVersionUID 1, SC_SERIALIZABLE, no fields, TC_ENDBLOCKDATA, no superclass.
// Reading it resolves cls and nothing else; with tc corrupted it is rejected before any class is
// looked up.
func deserJavaStream(cls string, tc byte) []byte {
	b := []byte{0xAC, 0xED, 0x00, 0x05, tc, 0x72, byte(len(cls) >> 8), byte(len(cls))}
	b = append(b, cls...)
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 1, 0x02, 0x00, 0x00, 0x78, 0x70)
	return b
}

var deserJavaFamily = &deserFamily{
	name: "Java object stream", severity: "high", confidence: "firm",
	proves: "the server reads this value with Java's ObjectInputStream: it resolves the class a client names",
	pair: func(i int) deserPair {
		cls := deserClassName(20)
		bad := []byte{0x00, 0x01}[i]
		return deserPair{
			accepted: deserJavaStream(cls, 0x73), rejected: deserJavaStream(cls, bad),
			mask:         []string{cls},
			acceptedNote: fmt.Sprintf("a stream of the nonexistent class %s", cls),
			rejectedNote: fmt.Sprintf("the same stream with type code 0x%02x", bad),
		}
	},
}

var deserPHPFamily = &deserFamily{
	name: "PHP serialize()", severity: "high", confidence: "firm",
	proves: "the server passes this value to PHP's unserialize(), which instantiates the class a client names",
	pair: func(i int) deserPair {
		cls := "Bsy" + randHex(9)
		ok := fmt.Sprintf(`O:%d:"%s":0:{}`, len(cls), cls)
		bad := fmt.Sprintf(`O:%d:"%s":0:{}`, len(cls)+1, cls)
		note := "a wrong declared class-name length"
		if i == 1 {
			bad = fmt.Sprintf(`O:%d:"%s":1:{}`, len(cls), cls)
			note = "a member count with no member"
		}
		return deserPair{
			accepted: []byte(ok), rejected: []byte(bad), mask: []string{cls},
			acceptedNote: fmt.Sprintf("an object of the nonexistent class %s", cls),
			rejectedNote: "the same text with " + note,
		}
	},
}

var deserPickleFamily = &deserFamily{
	name: "Python pickle", severity: "high", confidence: "firm",
	proves: "the server unpickles this value, and pickle can be made to call any importable function",
	pair: func(i int) deserPair {
		proto := byte(2 + i)
		n := deserRandByte()%0x60 + 0x10
		ok := []byte{0x80, proto, 'K', n, '.'}
		bad := []byte{0x80, proto, 'K', n, byte(i)}
		return deserPair{
			accepted: ok, rejected: bad,
			acceptedNote: fmt.Sprintf("a protocol-%d pickle of the int %d", proto, n),
			rejectedNote: fmt.Sprintf("the same bytes with the undefined opcode 0x%02x in place of STOP", i),
		}
	},
}

// deserRubyFamily is Ruby Marshal (0vzb.45): Marshal.dump of a small int against the same bytes
// truncated, or under a marshal version Ruby refuses.
var deserRubyFamily = &deserFamily{
	name: "Ruby Marshal", severity: "high", confidence: "firm",
	proves: "the server runs Marshal.load on this value, which instantiates any class the payload names",
	pair: func(i int) deserPair {
		n := deserRandByte()%0x60 + 0x10
		ok := []byte{0x04, 0x08, 'i', n + 5}
		bad, note := []byte{0x04, 0x08, 'i'}, "the same bytes cut before the integer"
		if i == 1 {
			bad, note = []byte{0x04, 0x09, 'i', n + 5}, "the same bytes under marshal version 4.9"
		}
		return deserPair{
			accepted: ok, rejected: bad,
			acceptedNote: fmt.Sprintf("Marshal.dump(%d)", n),
			rejectedNote: note,
		}
	},
}

func deserRandByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

// deserKnownClasses resolve on any JVM and build only an empty map.
var deserKnownClasses = [2]string{"java.util.HashMap", "java.util.TreeMap"}

func deserTypeIDFamily(key, binder string) *deserFamily {
	return &deserFamily{
		name: binder + " polymorphic JSON (" + key + ")", severity: "high", confidence: "firm",
		proves: "the server's JSON binder instantiates the class named by the client's " + key +
			" property, which is how a gadget class on the classpath is reached",
		pair: func(i int) deserPair {
			known := deserKnownClasses[i]
			unknown := deserClassName(len(known))
			return deserPair{
				accepted:     []byte(fmt.Sprintf(`{"%s":"%s"}`, key, known)),
				rejected:     []byte(fmt.Sprintf(`{"%s":"%s"}`, key, unknown)),
				mask:         []string{known, unknown},
				acceptedNote: fmt.Sprintf("%s naming %s", key, known),
				rejectedNote: fmt.Sprintf("%s naming the nonexistent %s", key, unknown),
			}
		},
	}
}

var (
	deserJacksonFamily  = deserTypeIDFamily("@class", "Jackson")
	deserFastjsonFamily = deserTypeIDFamily("@type", "fastjson")
)

var deserTypedJSONFamily = &deserFamily{
	name: "unsigned JSON state", severity: "low", confidence: "tentative",
	proves: "the server builds an object from JSON this cookie carries without any integrity check, " +
		"so a client can forge the object's fields; no class choice was shown",
	pair: func(i int) deserPair {
		ok, bad := `{}`, `{"`
		if i == 1 {
			ok, bad = `{ }`, `{ "`
		}
		return deserPair{
			accepted: []byte(ok), rejected: []byte(bad), mask: []string{`{}`, `{ }`},
			acceptedNote: fmt.Sprintf("the empty object %s, which the server never issued", ok),
			rejectedNote: fmt.Sprintf("the unterminated %s", bad),
		}
	},
}

// ---------------------------------------------------------------------------
// sending and deciding
// ---------------------------------------------------------------------------

type deserProber struct {
	cc    *CheckContext
	h     *ProbeHarness
	sends int
}

func (d *deserProber) send(ctx context.Context, p bcheck.InsertionPoint, value string) (ProbeResponse, error) {
	if d.sends >= deserMaxSends {
		return ProbeResponse{}, errDeserBudget
	}
	d.sends++
	return d.h.Send(ctx, p, value)
}

// deserEncode writes payload into the point's encoding.
func deserEncode(payload []byte, enc deserEncoding, kind bcheck.IpKind) string {
	switch enc {
	case deserBase64:
		return base64.StdEncoding.EncodeToString(payload)
	case deserBase64URL:
		return base64.RawURLEncoding.EncodeToString(payload)
	case deserHex:
		return hex.EncodeToString(payload)
	}
	if kind == bcheck.IpCookie {
		// A cookie carries no escaping of its own and refuses a quote; PHP percent-decodes cookie
		// values, which is the convention an application storing serialize() text in one relies on.
		return url.QueryEscape(string(payload))
	}
	return string(payload)
}

// deserUnusable reports an answer that says the request was filtered or throttled, not processed.
func deserUnusable(r ProbeResponse) bool {
	switch r.Status {
	case 0, 403, 406, 429, 502, 503, 504:
		return true
	}
	return false
}

func (d *deserProber) point(ctx context.Context, c deserCandidate) (*Finding, error) {
	for _, plan := range c.plans {
		f, err := d.try(ctx, c.point, plan)
		if err != nil || f != nil {
			return f, err
		}
	}
	return nil, nil
}

// try runs one family in one encoding at one point: accepted, rejected, rejected, accepted.
func (d *deserProber) try(ctx context.Context, p bcheck.InsertionPoint, plan deserPlan) (*Finding, error) {
	pairs := [2]deserPair{plan.fam.pair(0), plan.fam.pair(1)}
	var mask []string
	var enc [2][2]string // [pair][accepted=0, rejected=1]
	for i, pr := range pairs {
		enc[i][0] = deserEncode(pr.accepted, plan.enc, p.Kind)
		enc[i][1] = deserEncode(pr.rejected, plan.enc, p.Kind)
		mask = append(mask, pr.mask...)
		mask = append(mask, enc[i][0], enc[i][1], string(pr.accepted), string(pr.rejected))
	}
	fp := func(r ProbeResponse) string { return authFingerprint(r, mask) }

	a1, err := d.send(ctx, p, enc[0][0])
	if err != nil {
		return nil, deserSendErr(err)
	}
	r1, err := d.send(ctx, p, enc[0][1])
	if err != nil {
		return nil, deserSendErr(err)
	}
	if deserUnusable(a1) || deserUnusable(r1) || fp(a1) == fp(r1) {
		return nil, nil
	}
	r2, err := d.send(ctx, p, enc[1][1])
	if err != nil {
		return nil, deserSendErr(err)
	}
	a2, err := d.send(ctx, p, enc[1][0])
	if err != nil {
		return nil, deserSendErr(err)
	}
	if deserUnusable(a2) || deserUnusable(r2) {
		return nil, nil
	}
	fa1, fr1, fa2, fr2 := fp(a1), fp(r1), fp(a2), fp(r2)
	if fa1 != fa2 || fr1 != fr2 || fa1 == fr1 {
		return nil, nil
	}
	return d.finding(p, plan, pairs, a1, r1), nil
}

// deserSendErr keeps the budget sentinel and drops a single failed send: one probe that could not be
// sent leaves this pair undecided, it does not end the audit.
func deserSendErr(err error) error {
	if errors.Is(err, errDeserBudget) {
		return err
	}
	return nil
}

func (d *deserProber) finding(p bcheck.InsertionPoint, plan deserPlan, pairs [2]deserPair, a, r ProbeResponse) *Finding {
	where := fmt.Sprintf("%s %q", deserKindLabel(p.Kind), p.Name)
	evidence := fmt.Sprintf("%s (%s) in %s: accepted -> HTTP %d %q; rejected -> HTTP %d %q",
		plan.fam.name, plan.enc, where, a.Status, excerpt(a.Body, 0, 120), r.Status, excerpt(r.Body, 0, 120))
	detail := fmt.Sprintf("Two values of the same length and encoding (%s) were written into %s: %s, and %s. "+
		"They are indistinguishable to anything that treats the value as an opaque string, yet the "+
		"application answered them differently (HTTP %d versus HTTP %d, with different bodies once every "+
		"submitted value and dynamic token is masked). The pair was repeated with %s and %s, and each side "+
		"answered exactly as before. This shows %s. No gadget or code-executing payload was sent.",
		plan.enc, where, pairs[0].acceptedNote, pairs[0].rejectedNote, a.Status, r.Status,
		pairs[1].acceptedNote, pairs[1].rejectedNote, plan.fam.proves)
	if plan.fam == deserJavaFamily {
		detail += " A look-ahead class filter would answer the same way, so whether arbitrary classes are " +
			"reachable is not shown; that the stream is deserialized is."
	}
	f := buildHeaderFinding(d.cc, IssueInsecureDeserialization, plan.fam.severity, plan.fam.confidence, evidence, detail)
	f.Param = p.Name
	return f
}

func deserKindLabel(k bcheck.IpKind) string {
	switch k {
	case bcheck.IpCookie:
		return "cookie"
	case bcheck.IpQuery:
		return "query parameter"
	default:
		return "body parameter"
	}
}
