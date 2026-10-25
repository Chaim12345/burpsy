package scanner

// Insecure direct object reference (broken object-level authorization), burpsy-react-ui-0vzb.12.
//
// # What is tested
//
// A request that carries credentials (a Cookie header, an Authorization header or an API-key/token
// header) and an object reference — a numeric or UUID id in the query, a path segment, an id-named
// cookie, or a JSON/form body field of a read-only POST — is replayed with only that reference
// changed, the technique Autorize and AuthMatrix automate with a second account. burpsy has one
// identity, so the second account is replaced by three controls, and every one must hold:
//
//  1. the swapped id (a neighbour, n+1 or n-1, or another UUID the response itself names) returns a
//     2xx response with the SAME structure as the original (JSON key paths and value types, or the
//     HTML tag skeleton) but DIFFERENT content, and the difference is more than the id echoed back;
//  2. an invalid control id (a random nine-digit number or a random UUID) does NOT return that
//     structure, so the endpoint does not answer every id with the same template;
//  3. the swapped id sent with every credential stripped does NOT return the object, so the data is
//     not public (a product catalogue is not an IDOR);
//  4. the swapped request, re-sent, returns the same object again, and the original is stable across
//     two sends (fields that change between two identical sends are excluded from the comparison).
//
// # Client-controlled authorization keys
//
// When the plain swap is refused and the request also carries a role-named cookie or parameter whose
// value is an ordinary role (user, guest, member, ...; plain or base64), the swap is retried with that
// value raised to admin. All four controls are re-run on the raised request, and the finding is made
// only when the raised role turns a refused swap into another user's object: the authorization
// decision is keyed on a value the client controls, which is CWE-639 as much as the id itself is.
//
// # Confidence
//
// Tentative by default: with one identity, a neighbouring object that happens to belong to the same
// user cannot be told apart from another user's. Firm when the user-identity binding is shown: the
// request's JWT names the session user (sub, uid, user_id, userId, id), the original response has an
// owner-like field (an id-named key) equal to that user, and the swapped response has the same field
// naming someone else.
//
// # Safety
//
// Read-only probes only: GET, or a POST whose path names a read operation and no write operation.
// Nothing is modified or deleted; every request goes through the scope-enforcing probe gate.
//
// # Catalogue row
//
// Burp's catalogue has no IDOR row. "Insecure direct object reference" is burpsy's own row
// (burpsyNativeRows, advisory native/b5000100_*.json, CWE-639), and the check rides the "Broken
// access control" descriptor (CWE-284, CWE-639's ancestor) behind its own switch, check_idor,
// because the registry admits one descriptor per Burp catalogue type.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// idorIssue is burpsy's own row name; see burpsyNativeRows.
const idorIssue = "Insecure direct object reference"

// idorEnabled is the check's own switch.
func idorEnabled(c *ScanConfig) bool { return c != nil && c.CheckIDOR }

// idorMaxPoints bounds how many object references of one request are probed.
const idorMaxPoints = 4

// idorMaxSends bounds every request the check sends for one audited exchange.
const idorMaxSends = 48

// errIDORBudget stops a run that spent idorMaxSends.
var errIDORBudget = errors.New("idor: request budget spent")

// brokenAccessControlOrIDOR runs the "Broken access control" row's two techniques, each behind its own
// switch: the session-coordinator comparison (CheckExtendedActive) and the IDOR check (CheckIDOR). A
// proven IDOR finding is returned even when the access-control half could not run (it needs a session
// coordinator), because dropping a proven finding for a sibling's missing capability would hide it.
func brokenAccessControlOrIDOR(bac CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		var bacF []*Finding
		var bacErr error
		if finalChecksEnabled(cc.Config) {
			bacF, bacErr = bac(ctx, cc)
		}
		var idorF []*Finding
		var idorErr error
		if idorEnabled(cc.Config) {
			idorF, idorErr = checkIDOR(ctx, cc)
		}
		var bflaF []*Finding
		var bflaErr error
		if bflaIdentity(cc.Config) != nil {
			bflaF, bflaErr = checkBFLA(ctx, cc)
		}
		var maF []*Finding
		var maErr error
		if maEnabled(cc.Config) {
			maF, maErr = checkMassAssignment(ctx, cc)
		}
		out := append(append(append(bacF, idorF...), bflaF...), maF...)
		if len(out) > 0 {
			return out, nil
		}
		for _, err := range []error{bacErr, idorErr, bflaErr, maErr} {
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
}

// idorKinds are the insertion-point kinds an object reference can sit in.
var idorKinds = []string{"query", "body", "cookie", "url_path_filename", "url_path_folder"}

// checkIDOR probes every object reference of the audited request.
func checkIDOR(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" || !idorReadOnly(raw) || !idorHasCredentials(raw) {
		// No credentials: whatever the endpoint returns is what an anonymous client gets, so a
		// swapped id returning another object is public data, not an authorization failure.
		return nil, nil
	}
	pre, _ := bcheck.EnumerateWith([]byte(raw), idorKinds, cc.ProbeEnumerateOptions())
	if len(idorCandidates(pre, raw)) == 0 {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, idorKinds)
	if err != nil {
		return nil, fmt.Errorf("idor: %w", err)
	}
	p := &idorProber{cc: cc, h: h, raw: raw, sessionIDs: idorSessionIDs(raw), sec: idorSecondIdentity(cc.Config)}
	return p.run(ctx)
}

// idorSecondIdentity returns the configured second identity when the two-identity switch admitted
// it, else nil.
func idorSecondIdentity(c *ScanConfig) *SecondIdentity {
	if c == nil || !c.CheckIDORTwoIdentity {
		return nil
	}
	sec := &c.SecondIdentity
	if sec.CookieHeader == "" && sec.AuthorizationHeader == "" && (sec.APIKeyHeader == "" || sec.APIKeyValue == "") {
		return nil
	}
	return sec
}

// idorReidentity rewrites raw's credential headers to identity B's: cookies are replaced BY NAME so
// a non-credential cookie riding the same header (an object reference, a raised role) survives, and
// Authorization and the configured API-key header are replaced whole. covered is false when the
// request authenticates over a channel B cannot fill - a Cookie header sharing no cookie name with
// B's set, or an Authorization header B has no counterpart for - because then the replay is still
// identity A and would prove nothing.
func idorReidentity(raw string, sec *SecondIdentity) (string, bool) {
	head, body, hasBody := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	bCookies := map[string]string{}
	for _, c := range strings.Split(sec.CookieHeader, ";") {
		if n, v, ok := strings.Cut(strings.TrimSpace(c), "="); ok {
			bCookies[n] = strings.TrimSpace(v)
		}
	}
	out := []string{lines[0]}
	covered := true
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		n, v := strings.TrimSpace(name), strings.TrimSpace(value)
		switch {
		case ok && strings.EqualFold(n, "cookie"):
			var pairs []string
			replaced := false
			for _, c := range strings.Split(v, ";") {
				c = strings.TrimSpace(c)
				cn, _, _ := strings.Cut(c, "=")
				if bv, isB := bCookies[cn]; isB {
					pairs = append(pairs, cn+"="+bv)
					replaced = true
				} else {
					pairs = append(pairs, c)
				}
			}
			if !replaced {
				if len(bCookies) == 0 {
					covered = false
				}
				out = append(out, line)
				continue
			}
			out = append(out, "Cookie: "+strings.Join(pairs, "; "))
		case ok && strings.EqualFold(n, "authorization"):
			if sec.AuthorizationHeader == "" {
				covered = false
				out = append(out, line)
				continue
			}
			out = append(out, "Authorization: "+sec.AuthorizationHeader)
		case ok && sec.APIKeyHeader != "" && strings.EqualFold(n, sec.APIKeyHeader):
			out = append(out, n+": "+sec.APIKeyValue)
		default:
			out = append(out, line)
		}
	}
	res := strings.Join(out, "\r\n") + "\r\n\r\n"
	if hasBody {
		res += body
	}
	return res, covered
}

// crossRead asks whether identity B is served identity A's object: the original request - A's own
// reference - replayed under B's credentials. A match on A's baseline shape with no stable-leaf
// difference is A's object in B's hands; the echo trap (an endpoint that serves the SESSION's own
// record whatever the id) answers with B's record instead, which differs and concludes nothing.
// Controls: the same request with every credential stripped must not be served the object, and the
// cross-read repeated must be stable.
func (p *idorProber) crossRead(ctx context.Context, b *idorBase, c idorCandidate) (*Finding, error) {
	braw, covered := idorReidentity(b.raw, p.sec)
	if !covered {
		return nil, nil
	}
	br, err := p.send(ctx, braw)
	if err != nil {
		return nil, err
	}
	if !b.isObject(br) || len(b.diff(b.shape, idorShapeOf(br.Body))) > 0 {
		return nil, nil
	}
	keep := map[string]bool{}
	if c.point.Kind == bcheck.IpCookie {
		keep[c.point.Name] = true
	}
	nr, err := p.send(ctx, idorAnonymous(b.raw, keep))
	if err != nil {
		return nil, err
	}
	if b.isObject(nr) {
		return nil, nil // served without credentials: public data
	}
	again, err := p.send(ctx, braw)
	if err != nil {
		return nil, err
	}
	if !b.isObject(again) || len(b.diff(idorShapeOf(br.Body), idorShapeOf(again.Body))) > 0 {
		return nil, nil
	}
	return p.crossFinding(b, c, br, nr), nil
}

func (p *idorProber) crossFinding(b *idorBase, c idorCandidate, br, nr ProbeResponse) *Finding {
	where := fmt.Sprintf("%s %q", idorKindLabel(c.point.Kind), c.point.Name)
	if c.point.Kind == bcheck.IpURLPathFilename || c.point.Kind == bcheck.IpURLPathFolder {
		where = fmt.Sprintf("path segment %q", c.value)
	}
	detail := fmt.Sprintf("The request as captured holds the object reference in %s and returns the "+
		"captured identity's object. Replayed under a second configured identity - another account on "+
		"the same application - it returned HTTP %d with the SAME object, unchanged: the second "+
		"identity can read the first identity's object, so object-level authorization is not enforced. "+
		"Controls: the same request with every credential removed returned HTTP %d without the object, "+
		"and the cross-read repeated returned the same object again.", where, br.Status, nr.Status)
	f := buildHeaderFinding(p.cc, idorIssue, "high", "firm",
		fmt.Sprintf("second identity replay -> HTTP %d, %s", br.Status, excerpt(br.Body, 0, 160)), detail)
	f.Param = c.point.Name
	f.Solution = "Authorize every object access on the server against the authenticated identity: look the " +
		"object up within the current user's own scope, or check ownership before returning it. Never " +
		"decide authorization from a client-held id or role."
	return f
}

// idorProber holds one exchange's run.
type idorProber struct {
	cc         *CheckContext
	h          *ProbeHarness
	raw        string
	sessionIDs map[string]bool
	sec        *SecondIdentity
	sends      int
}

func (p *idorProber) send(ctx context.Context, raw string) (ProbeResponse, error) {
	if p.sends >= idorMaxSends {
		return ProbeResponse{}, errIDORBudget
	}
	p.sends++
	return p.h.send(ctx, []byte(raw))
}

// idorBase is an original request with its stable reference response: the response, its shape, and
// the JSON leaves that changed between two identical sends (excluded from every comparison).
type idorBase struct {
	raw      string
	resp     ProbeResponse
	shape    *idorShape
	volatile map[string]bool
}

func (p *idorProber) base(ctx context.Context, raw string, first *ProbeResponse) (*idorBase, error) {
	var a ProbeResponse
	if first != nil {
		a = *first
	} else {
		r, err := p.send(ctx, raw)
		if err != nil {
			return nil, err
		}
		a = r
	}
	if a.Status < 200 || a.Status > 299 {
		return nil, nil
	}
	sa := idorShapeOf(a.Body)
	if sa == nil {
		return nil, nil
	}
	a2, err := p.send(ctx, raw)
	if err != nil {
		return nil, err
	}
	sa2 := idorShapeOf(a2.Body)
	if a2.Status != a.Status || !sa.same(sa2) {
		return nil, nil
	}
	b := &idorBase{raw: raw, resp: a, shape: sa, volatile: map[string]bool{}}
	if sa.kind == "html" && a.Body != a2.Body {
		// An HTML page that differs between two identical sends gives no stable content to compare.
		return nil, nil
	}
	for k, v := range sa.leaves {
		if sa2.leaves[k] != v {
			b.volatile[k] = true
		}
	}
	return b, nil
}

func (p *idorProber) run(ctx context.Context) ([]*Finding, error) {
	baseline := p.h.Baseline()
	orig, err := p.base(ctx, p.raw, &baseline)
	if err != nil {
		return nil, fmt.Errorf("idor: %w", err)
	}
	if orig == nil {
		return nil, nil
	}
	cands := idorCandidates(p.h.Points(), p.raw)
	if len(cands) > idorMaxPoints {
		cands = cands[:idorMaxPoints]
	}
	roles := idorRoleVariants(p.h.Points())
	var failures []string
	for _, c := range cands {
		if p.sec != nil {
			cf, err := p.crossRead(ctx, orig, c)
			if err != nil {
				failures = append(failures, err.Error())
				if errors.Is(err, errIDORBudget) {
					break
				}
				continue
			}
			if cf != nil {
				return []*Finding{cf}, nil
			}
		}
		f, refused, err := p.probe(ctx, orig, c, "")
		if err != nil {
			failures = append(failures, err.Error())
			if errors.Is(err, errIDORBudget) {
				break
			}
			continue
		}
		if f != nil {
			return []*Finding{f}, nil
		}
		if !refused {
			continue
		}
		// The plain swap was refused. Retry with a client-held role raised.
		for _, rv := range roles {
			raised, err := idorApply(p.raw, rv.point, rv.raised)
			if err != nil {
				continue
			}
			rbase, err := p.base(ctx, raised, nil)
			if err != nil {
				failures = append(failures, err.Error())
				break
			}
			if rbase == nil || !rbase.shape.same(orig.shape) {
				continue
			}
			f, _, err := p.probe(ctx, rbase, c, fmt.Sprintf("%s %q raised from %q to %q", rv.point.Kind,
				rv.point.Name, rv.point.BaseValue, rv.raised))
			if err != nil {
				failures = append(failures, err.Error())
				continue
			}
			if f != nil {
				return []*Finding{f}, nil
			}
		}
	}
	if len(failures) > 0 {
		return nil, fmt.Errorf("idor: %s", strings.Join(failures, "; "))
	}
	return nil, nil
}

// probe swaps one reference against one base request. refused reports that every swapped id was
// answered with something other than the object (the precondition for the raised-role retry).
func (p *idorProber) probe(ctx context.Context, b *idorBase, c idorCandidate, raisedRole string) (*Finding, bool, error) {
	control := idorControlValue(c.value)
	craw, err := idorApplyAt(b.raw, c, control)
	if err != nil {
		return nil, false, nil
	}
	cr, err := p.send(ctx, craw)
	if err != nil {
		return nil, false, err
	}
	if b.isObject(cr) {
		// The endpoint answers a made-up id with the same structure: there is no not-found shape to
		// tell another object from a template, so nothing can be concluded here.
		return nil, false, nil
	}
	refused := true
	for _, alt := range idorAlternates(c.value, b.resp.Body) {
		sraw, err := idorApplyAt(b.raw, c, alt)
		if err != nil {
			continue
		}
		sr, err := p.send(ctx, sraw)
		if err != nil {
			return nil, false, err
		}
		if !b.isObject(sr) {
			continue
		}
		refused = false
		changed := b.changed(sr, c.value, alt)
		if len(changed) == 0 || idorSameBody(sr, cr) {
			continue
		}
		// No credentials: the same swapped request, every credential stripped.
		keep := map[string]bool{}
		if c.point.Kind == bcheck.IpCookie {
			keep[c.point.Name] = true
		}
		for _, name := range idorCookieNamesChanged(p.raw, b.raw) {
			keep[name] = true
		}
		nr, err := p.send(ctx, idorAnonymous(sraw, keep))
		if err != nil {
			return nil, false, err
		}
		if b.isObject(nr) || idorSameBody(nr, sr) {
			// Served without credentials: public data.
			return nil, false, nil
		}
		again, err := p.send(ctx, sraw)
		if err != nil {
			return nil, false, err
		}
		if !b.isObject(again) || len(b.diff(idorShapeOf(again.Body), idorShapeOf(sr.Body))) > 0 {
			continue
		}
		return p.finding(b, c, alt, control, sr, cr, nr, changed, raisedRole), false, nil
	}
	return nil, refused, nil
}

func (p *idorProber) finding(b *idorBase, c idorCandidate, alt, control string, sr, cr, nr ProbeResponse,
	changed []string, raisedRole string) *Finding {

	confidence := "tentative"
	binding := ""
	if path, owner, ok := idorOwnerBinding(p.sessionIDs, b.shape, idorShapeOf(sr.Body)); ok {
		confidence = "firm"
		binding = fmt.Sprintf(" The session's own user id is %q (from the request's JWT); the original "+
			"object's %s is that user and the swapped object's %s is %q, so the object returned belongs "+
			"to another user.", path.session, path.path, path.path, owner)
	}
	where := fmt.Sprintf("%s %q", idorKindLabel(c.point.Kind), c.point.Name)
	if c.point.Kind == bcheck.IpURLPathFilename || c.point.Kind == bcheck.IpURLPathFolder {
		where = fmt.Sprintf("path segment %q", c.value)
	}
	role := ""
	if raisedRole != "" {
		role = fmt.Sprintf(" The swap was refused with the request as captured and succeeded only with %s: "+
			"the authorization decision trusts a client-held role.", raisedRole)
	}
	sort.Strings(changed)
	if len(changed) > 6 {
		changed = changed[:6]
	}
	detail := fmt.Sprintf("Changing the object reference in %s from %q to %q returned HTTP %d with the "+
		"same structure as the original response but a different object (changed: %s). Controls: the "+
		"invalid id %q returned HTTP %d without that structure, the swapped request with every credential "+
		"removed returned HTTP %d without the object, and the swapped request re-sent returned the same "+
		"object again.%s%s", where, c.value, alt, sr.Status, strings.Join(changed, ", "), control, cr.Status,
		nr.Status, role, binding)
	if confidence == "tentative" {
		detail += " burpsy has one identity, so it could not show that the swapped object belongs to a " +
			"different user; confirm with a second account."
	}
	f := buildHeaderFinding(p.cc, idorIssue, "high", confidence,
		fmt.Sprintf("%s=%s -> HTTP %d, %s", c.point.Name, alt, sr.Status, excerpt(sr.Body, 0, 160)), detail)
	f.Param = c.point.Name
	f.Solution = "Authorize every object access on the server against the authenticated identity: look the " +
		"object up within the current user's own scope, or check ownership before returning it. Never " +
		"decide authorization from a client-held id or role."
	return f
}

// ---------------------------------------------------------------------------
// candidates
// ---------------------------------------------------------------------------

type idorCandidate struct {
	point   bcheck.InsertionPoint
	ordinal int // position among points of the same kind and name, to find it again in a new request
	value   string
}

var (
	idorNumeric = regexp.MustCompile(`^[0-9]{1,12}$`)
	idorUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	idorUUIDAny = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
)

// idorNouns are object kinds a parameter name commonly references by id.
var idorNouns = map[string]bool{
	"user": true, "account": true, "acct": true, "order": true, "invoice": true, "customer": true,
	"profile": true, "member": true, "owner": true, "document": true, "doc": true, "record": true,
	"ticket": true, "message": true, "msg": true, "patient": true, "employee": true, "booking": true,
	"reservation": true, "transaction": true, "txn": true, "report": true, "file": true, "item": true,
	"object": true, "entity": true, "resource": true, "address": true, "card": true, "cart": true,
	"payment": true, "subscription": true, "contract": true, "note": true, "post": true, "comment": true,
	"project": true, "team": true, "org": true, "organization": true, "group": true, "tenant": true,
	"client": true, "statement": true, "receipt": true, "shipment": true, "attachment": true,
}

// idorNotARefWords are name words that mark secrets, paging or metadata, never an object reference.
var idorNotARefWords = map[string]bool{
	"token": true, "session": true, "sess": true, "sid": true, "csrf": true, "xsrf": true, "nonce": true,
	"secret": true, "password": true, "passwd": true, "auth": true, "sig": true, "signature": true,
	"hash": true, "key": true, "apikey": true, "page": true, "limit": true, "offset": true, "size": true,
	"count": true, "sort": true, "ts": true, "time": true, "timestamp": true, "date": true,
	"version": true, "lang": true, "locale": true,
}

// idorNotARef reports whether any word of name marks it as something other than an object reference.
func idorNotARef(name string) bool {
	for _, w := range idorWords(name) {
		if idorNotARefWords[w] {
			return true
		}
	}
	return false
}

// idorIDName reports whether a parameter name reads as an object reference.
func idorIDName(name string) bool {
	// filter[owner_id], user.id, items[0]: the innermost key is the name.
	name = strings.TrimRight(name, "]")
	if i := strings.LastIndexAny(name, ".["); i >= 0 {
		name = name[i+1:]
	}
	if name == "" || idorNumeric.MatchString(name) {
		return false
	}
	lower := strings.ToLower(name)
	switch lower {
	case "id", "uid", "uuid", "guid", "oid", "pk":
		return true
	}
	if idorNotARef(name) {
		return false
	}
	// userId / user_id / user-id / USERID / user_no / account_number
	words := idorWords(name)
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		// user_id, userId, userId_v2: an "id" word anywhere (secrets were excluded above).
		if w == "id" || w == "uuid" || w == "guid" {
			return true
		}
	}
	last := words[len(words)-1]
	if (last == "no" || last == "num" || last == "number") && len(words) > 1 {
		return idorNouns[words[len(words)-2]]
	}
	if len(words) == 1 {
		w := words[0]
		if idorNouns[w] {
			return true
		}
		for n := range idorNouns {
			if strings.HasPrefix(w, n) && (w[len(n):] == "id" || w[len(n):] == "no") {
				return true
			}
		}
		return false
	}
	return idorNouns[last]
}

// idorWords splits snake, kebab and camel case into lowercase words.
func idorWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			flush()
		case r >= 'A' && r <= 'Z' && i > 0 && rs[i-1] >= 'a' && rs[i-1] <= 'z':
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

// idorSegmentNotAResource are path segments before a number that name paging or versions.
var idorSegmentNotAResource = map[string]bool{
	"page": true, "p": true, "v": true, "version": true, "api": true, "year": true, "month": true,
	"day": true, "size": true, "limit": true, "offset": true, "step": true, "rev": true, "revision": true,
}

var idorWordSegment = regexp.MustCompile(`^[A-Za-z][A-Za-z_-]*$`)

// idorCandidates are the points holding an object reference, in request order.
func idorCandidates(points []bcheck.InsertionPoint, raw string) []idorCandidate {
	segs := idorPathSegments(raw)
	ordinals := map[string]int{}
	var out []idorCandidate
	for _, pt := range points {
		key := string(pt.Kind) + "\x00" + pt.Name
		ord := ordinals[key]
		ordinals[key]++
		v := pt.BaseValue
		if dec, err := url.QueryUnescape(v); err == nil {
			v = dec
		}
		numeric, uuid := idorNumeric.MatchString(v), idorUUID.MatchString(v)
		if !numeric && !uuid {
			continue
		}
		ok := false
		switch pt.Kind {
		case bcheck.IpQuery, bcheck.IpCookie, bcheck.IpBody:
			if pt.Kind == bcheck.IpBody && !idorJSONOrForm(raw) {
				continue
			}
			ok = idorIDName(pt.Name) || (uuid && !idorNotARef(pt.Name))
		case bcheck.IpURLPathFilename, bcheck.IpURLPathFolder:
			ok = idorResourceSegment(segs, v)
		}
		if ok {
			out = append(out, idorCandidate{point: pt, ordinal: ord, value: v})
		}
	}
	return out
}

// idorResourceSegment reports whether value is a path segment that follows a resource name
// (/users/42, /orders/3fa8...), not a version or a page number.
func idorResourceSegment(segs []string, value string) bool {
	for i, s := range segs {
		if s != value {
			continue
		}
		if idorUUID.MatchString(value) {
			return true
		}
		if i == 0 {
			return false
		}
		prev := segs[i-1]
		return idorWordSegment.MatchString(prev) && !idorSegmentNotAResource[strings.ToLower(prev)]
	}
	return false
}

func idorPathSegments(raw string) []string {
	line, _, _ := strings.Cut(raw, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	target := parts[1]
	if u, err := url.Parse(target); err == nil {
		target = u.EscapedPath()
	}
	target, _, _ = strings.Cut(target, "?")
	var out []string
	for _, s := range strings.Split(target, "/") {
		if s != "" {
			if dec, err := url.PathUnescape(s); err == nil {
				s = dec
			}
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// safety: read-only requests
// ---------------------------------------------------------------------------

var (
	idorReadVerb  = regexp.MustCompile(`(?i)^(get|view|show|read|fetch|lookup|find|search|list|query|retrieve|details?|info)`)
	idorWriteVerb = regexp.MustCompile(`(?i)delete|remove|update|set|create|add|save|edit|modify|cancel|transfer|pay|reset|send|post|put|patch|submit|upload|approve|reject|change|insert|write|exec|run|grant|revoke|logout|login`)
)

// idorReadOnly admits GET, and a POST whose last path segment names a read operation and no write.
// Every other method, and any other POST, could change state when its id is swapped.
func idorReadOnly(raw string) bool {
	line, _, _ := strings.Cut(raw, "\r\n")
	method, _, _ := strings.Cut(line, " ")
	switch strings.ToUpper(method) {
	case "GET":
		return true
	case "POST":
		segs := idorPathSegments(raw)
		if len(segs) == 0 {
			return false
		}
		last := segs[len(segs)-1]
		return idorReadVerb.MatchString(last) && !idorWriteVerb.MatchString(last)
	}
	return false
}

func idorJSONOrForm(raw string) bool {
	ct := strings.ToLower(headerValue(raw, "content-type"))
	return strings.Contains(ct, "json") || strings.Contains(ct, "x-www-form-urlencoded")
}

// ---------------------------------------------------------------------------
// credentials
// ---------------------------------------------------------------------------

var idorCredentialHeader = regexp.MustCompile(`(?i)^(authorization|proxy-authorization|cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-session-token|x-token)$`)

func idorHasCredentials(raw string) bool {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n")[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && idorCredentialHeader.MatchString(strings.TrimSpace(name)) && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// idorAnonymous strips every credential header from raw, keeping only the named cookies (the cookie
// holding the reference under test, and a raised role cookie), which carry no identity of their own.
func idorAnonymous(raw string, keepCookies map[string]bool) string {
	head, body, hasBody := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	kept := []string{lines[0]}
	var cookies []string
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		n := strings.TrimSpace(name)
		if ok && strings.EqualFold(n, "cookie") {
			for _, c := range strings.Split(value, ";") {
				c = strings.TrimSpace(c)
				cn, _, _ := strings.Cut(c, "=")
				if keepCookies[cn] {
					cookies = append(cookies, c)
				}
			}
			continue
		}
		if ok && idorCredentialHeader.MatchString(n) {
			continue
		}
		kept = append(kept, line)
	}
	if len(cookies) > 0 {
		kept = append(kept, "Cookie: "+strings.Join(cookies, "; "))
	}
	out := strings.Join(kept, "\r\n") + "\r\n\r\n"
	if hasBody {
		out += body
	}
	return out
}

// idorCookieNamesChanged names the cookies whose value differs between two requests (a raised role).
func idorCookieNamesChanged(a, b string) []string {
	parse := func(raw string) map[string]string {
		m := map[string]string{}
		for _, v := range headerValues(raw, "cookie") {
			for _, c := range strings.Split(v, ";") {
				n, val, _ := strings.Cut(strings.TrimSpace(c), "=")
				m[n] = val
			}
		}
		return m
	}
	ma, mb := parse(a), parse(b)
	var out []string
	for n, v := range mb {
		if ma[n] != v {
			out = append(out, n)
		}
	}
	return out
}

// idorSessionClaims are the claim names a JWT names the session user by, wherever in the payload
// they appear.
var idorSessionClaims = map[string]bool{
	"sub": true, "uid": true, "user_id": true, "userId": true, "userid": true, "id": true,
}

// idorSessionIDs are the user ids the request's JWTs name for the session. The claims are read
// recursively, not only at the top level: a real token does not always carry its subject as a
// top-level claim. Juice Shop, for one, signs the whole user row - the payload is
// {data: {id: ...}, bid: ...} - so a top-level-only read finds nothing and a demonstrable owner
// binding scores Tentative where Firm was provable. The response-side rule stays the proof: a
// value here only promotes a finding when the original object's owner field equals it and the
// swapped object's does not, so a wider lookup table cannot manufacture a binding, only miss one
// less often.
func idorSessionIDs(raw string) map[string]bool {
	out := map[string]bool{}
	for _, cand := range jwtCandidatesIn(raw) {
		t := ParseJWT(cand)
		if t.ParseError != "" || t.Payload == nil {
			continue
		}
		idorCollectSessionClaims(t.Payload, out)
	}
	return out
}

// idorCollectSessionClaims folds every idorSessionClaims value in a decoded payload fragment into
// out, descending into nested objects and arrays. Values are strings rendered as themselves and
// numbers in their shortest form, the same two renderings idorShape's JSON leaves use, so a claim
// and a response field compare equal when they name the same id.
func idorCollectSessionClaims(v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if idorSessionClaims[k] {
				switch c := e.(type) {
				case string:
					if c != "" {
						out[c] = true
					}
				case float64:
					out[strconv.FormatFloat(c, 'f', -1, 64)] = true
				}
			}
			idorCollectSessionClaims(e, out)
		}
	case []any:
		for _, e := range x {
			idorCollectSessionClaims(e, out)
		}
	}
}

// ---------------------------------------------------------------------------
// role keys
// ---------------------------------------------------------------------------

type idorRoleVariant struct {
	point  bcheck.InsertionPoint
	raised string
}

var (
	idorRoleName = regexp.MustCompile(`(?i)role|priv|perm|group|access|level|type`)
	idorLowRoles = map[string]bool{"user": true, "guest": true, "member": true, "customer": true,
		"viewer": true, "reader": true, "basic": true, "standard": true, "normal": true, "default": true}
)

// idorRoleVariants are the role-named cookies and query parameters holding an ordinary role, each
// with the value raised to admin in the same spelling and encoding.
func idorRoleVariants(points []bcheck.InsertionPoint) []idorRoleVariant {
	var out []idorRoleVariant
	for _, pt := range points {
		if (pt.Kind != bcheck.IpCookie && pt.Kind != bcheck.IpQuery) || !idorRoleName.MatchString(pt.Name) {
			continue
		}
		if r, ok := idorRaise(pt.BaseValue); ok {
			out = append(out, idorRoleVariant{point: pt, raised: r})
			continue
		}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.RawURLEncoding} {
			dec, err := enc.DecodeString(pt.BaseValue)
			if err != nil {
				continue
			}
			if r, ok := idorRaise(string(dec)); ok {
				out = append(out, idorRoleVariant{point: pt, raised: enc.EncodeToString([]byte(r))})
				break
			}
		}
	}
	return out
}

func idorRaise(v string) (string, bool) {
	if !idorLowRoles[strings.ToLower(v)] {
		return "", false
	}
	switch {
	case v == strings.ToUpper(v):
		return "ADMIN", true
	case v == strings.ToLower(v):
		return "admin", true
	}
	return "Admin", true
}

// ---------------------------------------------------------------------------
// values
// ---------------------------------------------------------------------------

// idorAlternates are the ids tried in place of v: its neighbours for a number, or other UUIDs the
// original response names for a UUID.
func idorAlternates(v, body string) []string {
	if idorNumeric.MatchString(v) {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil
		}
		width := 0
		if len(v) > 1 && v[0] == '0' {
			width = len(v)
		}
		fmtN := func(x int64) string {
			if width > 0 {
				return fmt.Sprintf("%0*d", width, x)
			}
			return strconv.FormatInt(x, 10)
		}
		out := []string{fmtN(n + 1)}
		if n > 1 {
			out = append(out, fmtN(n-1))
		}
		return out
	}
	var out []string
	for _, u := range idorUUIDAny.FindAllString(body, -1) {
		if !strings.EqualFold(u, v) && !idorContains(out, u) {
			out = append(out, u)
		}
		if len(out) == 2 {
			break
		}
	}
	return out
}

func idorContains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// idorControlValue is an id no application should hold: a random nine-digit number (still inside a
// signed 32-bit integer) for a number, a random UUID for a UUID.
func idorControlValue(v string) string {
	if idorUUID.MatchString(v) {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		s := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
		if v == strings.ToUpper(v) {
			s = strings.ToUpper(s)
		}
		return s
	}
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "987654321"
	}
	return strconv.FormatInt(900000000+n.Int64()%99999999, 10)
}

// idorApply sets one point of raw to value.
func idorApply(raw string, pt bcheck.InsertionPoint, value string) (string, error) {
	out, err := pt.Apply([]byte(raw), value, false)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// idorApplyAt sets the candidate's point in raw, which may be a different request (a raised role)
// than the one the candidate was found in: the point is found again by kind, name and position.
func idorApplyAt(raw string, c idorCandidate, value string) (string, error) {
	points, _ := bcheck.EnumerateWith([]byte(raw), idorKinds, bcheck.EnumerateOptions{})
	ord := 0
	for _, pt := range points {
		if pt.Kind != c.point.Kind || pt.Name != c.point.Name {
			continue
		}
		if ord == c.ordinal {
			if pt.BaseValue != c.point.BaseValue {
				return "", fmt.Errorf("idor: %s %q moved", pt.Kind, pt.Name)
			}
			return idorApply(raw, pt, value)
		}
		ord++
	}
	return "", fmt.Errorf("idor: %s %q not found", c.point.Kind, c.point.Name)
}

func idorKindLabel(k bcheck.IpKind) string {
	switch k {
	case bcheck.IpQuery:
		return "query parameter"
	case bcheck.IpCookie:
		return "cookie"
	case bcheck.IpBody:
		return "body field"
	}
	return string(k)
}

// ---------------------------------------------------------------------------
// response structure
// ---------------------------------------------------------------------------

// idorShape is a response's structure and, for JSON, its leaf values.
type idorShape struct {
	kind   string            // "json" or "html"
	sig    map[string]string // JSON: key path (array indices collapsed) -> value type
	leaves map[string]string // JSON: key path (with indices) -> value
	skel   string            // HTML: the start-tag sequence
	body   string
}

// idorShapeOf returns nil for a body whose structure cannot be compared (empty, plain text).
func idorShapeOf(body string) *idorShape {
	t := strings.TrimSpace(body)
	if t == "" {
		return nil
	}
	if t[0] == '{' || t[0] == '[' {
		dec := json.NewDecoder(strings.NewReader(t))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil
		}
		s := &idorShape{kind: "json", sig: map[string]string{}, leaves: map[string]string{}, body: body}
		idorWalk(v, "$", "$", s)
		return s
	}
	if !strings.Contains(strings.ToLower(t[:min(len(t), 512)]), "<") {
		return nil
	}
	z := html.NewTokenizer(strings.NewReader(t))
	var tags []string
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			name, _ := z.TagName()
			tags = append(tags, string(name))
		}
	}
	if len(tags) < 3 {
		return nil
	}
	return &idorShape{kind: "html", skel: strings.Join(tags, ","), body: body}
}

func idorWalk(v any, sigPath, leafPath string, s *idorShape) {
	switch x := v.(type) {
	case map[string]any:
		s.sig[sigPath] = "object"
		for k, e := range x {
			idorWalk(e, sigPath+"."+k, leafPath+"."+k, s)
		}
	case []any:
		s.sig[sigPath] = "array"
		for i, e := range x {
			idorWalk(e, sigPath+"[]", fmt.Sprintf("%s[%d]", leafPath, i), s)
		}
	case nil:
		s.sig[sigPath] = "null"
		s.leaves[leafPath] = "null"
	case string:
		s.sig[sigPath] = "string"
		s.leaves[leafPath] = x
	case json.Number:
		s.sig[sigPath] = "number"
		s.leaves[leafPath] = x.String()
	case bool:
		s.sig[sigPath] = "bool"
		s.leaves[leafPath] = strconv.FormatBool(x)
	}
}

// same reports whether two responses have the same structure. A null matches any type, so an optional
// field that is empty on one object does not make two objects different shapes.
func (a *idorShape) same(b *idorShape) bool {
	if a == nil || b == nil || a.kind != b.kind {
		return false
	}
	if a.kind == "html" {
		return a.skel == b.skel
	}
	if len(a.sig) != len(b.sig) {
		return false
	}
	for k, t := range a.sig {
		u, ok := b.sig[k]
		if !ok {
			return false
		}
		if t != u && t != "null" && u != "null" {
			return false
		}
	}
	return true
}

// isObject reports whether r is a 2xx response with the original's structure.
func (b *idorBase) isObject(r ProbeResponse) bool {
	return r.Status >= 200 && r.Status <= 299 && b.shape.same(idorShapeOf(r.Body))
}

// diff lists the stable JSON leaves whose values differ between two shapes (for HTML, "body" when the
// bodies differ).
func (b *idorBase) diff(x, y *idorShape) []string {
	if x == nil || y == nil {
		return []string{"structure"}
	}
	if x.kind == "html" {
		if x.body != y.body {
			return []string{"body"}
		}
		return nil
	}
	var out []string
	for k, v := range x.leaves {
		if b.volatile[k] {
			continue
		}
		if w, ok := y.leaves[k]; ok && w != v {
			out = append(out, k)
		}
	}
	return out
}

// changed lists what makes the swapped response a different object: stable leaves that differ from
// the original, leaving out leaves that merely echo the swapped id. Nil when the id echo is all that
// changed — the endpoint repeating the requested id around the same object.
func (b *idorBase) changed(sr ProbeResponse, orig, alt string) []string {
	ss := idorShapeOf(sr.Body)
	d := b.diff(b.shape, ss)
	if b.shape.kind == "html" {
		if len(d) == 0 || strings.ReplaceAll(sr.Body, alt, "") == strings.ReplaceAll(b.resp.Body, orig, "") {
			return nil
		}
		return d
	}
	var out []string
	for _, k := range d {
		if ss.leaves[k] == alt {
			continue
		}
		out = append(out, strings.TrimPrefix(k, "$."))
	}
	return out
}

func idorSameBody(a, b ProbeResponse) bool {
	return a.Status == b.Status && strings.TrimSpace(a.Body) == strings.TrimSpace(b.Body)
}

// idorBindingPath names the owner field that shows the identity binding.
type idorBindingPath struct{ path, session string }

// idorOwnerBinding finds an id-named JSON field equal to the session's user id in the original and
// naming someone else in the swapped object.
func idorOwnerBinding(session map[string]bool, a, s *idorShape) (idorBindingPath, string, bool) {
	if len(session) == 0 || a == nil || s == nil || a.kind != "json" {
		return idorBindingPath{}, "", false
	}
	keys := make([]string, 0, len(a.leaves))
	for k := range a.leaves {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := a.leaves[k]
		last := k[strings.LastIndexAny(k, ".]")+1:]
		if !session[v] || !(idorIDName(last) || strings.EqualFold(last, "owner") || strings.EqualFold(last, "sub")) {
			continue
		}
		if w, ok := s.leaves[k]; ok && w != "" && w != "null" && !session[w] {
			return idorBindingPath{path: strings.TrimPrefix(k, "$."), session: v}, w, true
		}
	}
	return idorBindingPath{}, "", false
}
