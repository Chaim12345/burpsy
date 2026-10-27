package scanner

// NoSQL injection against MongoDB-style back ends (burpsy-react-ui-v0ei.6).
//
// # Techniques
//
// Operator injection. A string the request carries is replaced by a query-operator object: in a JSON
// body the value itself becomes {"$ne": ...}, and in a query string or a form body the parameter is
// re-sent in the bracket syntax Express's qs, PHP and Rack all decode into an object (name[$ne]=x,
// name[$in][]=x). Where the application passes the decoded value into a MongoDB filter, the operator
// is evaluated instead of compared.
//
// Syntax injection. A string parameter is closed and extended in JavaScript string context, the
// context a $where clause or a mapReduce/$function body concatenates input into: '||'a'=='a and
// "||"a"=="a, and the bare quote and backslash that break the script.
//
// # Evidence (a finding needs one of these, each fully held)
//
// Boolean differential (operator or syntax). For one parameter:
//
//   - two TRUE-equivalent probes, built differently ({"$ne": random} and {"$gt": ""}; or
//     r'||'x'=='x with two different random x), return the same response as each other;
//   - two FALSE-equivalent probes ({"$eq": random} and {"$in": [random]}; or r'||'x'=='y) return the
//     same response as each other AND as a plain random string, the "not found" answer;
//   - the TRUE and FALSE responses differ, and the TRUE one is a success or a redirect (an endpoint
//     refusing an operator with a 4xx is filtering it, not evaluating it);
//   - two plain random strings answer alike (the page is stable), the whole set is repeated with
//     fresh random values and holds again, and the original request re-sent at the end still returns
//     its original response.
//
// Every random value the check sends is masked out of every response before comparison, so an
// endpoint that echoes its input compares equal across TRUE and FALSE and is never reported. An
// endpoint that ignores the field, casts it to a string, or rejects every object answers TRUE and
// FALSE alike, so it fails the first test; one that errors on objects fails the FALSE-equals-plain
// test. That is the constant-response control the technique needs.
//
// Error-based. A MongoDB/Mongoose error signature (MongoServerError, CastError, BSON errors, an
// "unknown operator", a $where SyntaxError, driver exception class names) appears for a broken
// probe, is absent from the baseline, is absent for the repaired control (the same quote escaped;
// for operators, the valid {"$eq": random} instead of an unknown operator), and appears again when
// the broken probe is re-sent.
//
// # Not done
//
// Timing through $where (sleep(n)) is not sent: it holds a database worker for the delay, and the
// two proofs above decide every case the fixtures model. Numbers and booleans in JSON bodies are not
// replaced by operators (a $gt "" against a number compares by BSON type order, so the TRUE class
// would disagree with itself and nothing would be concluded; leaving them out costs requests, not
// findings).
//
// # Safety
//
// A match-everything operator sent to a write ("update where id != x") would change every record,
// so the check acts only on reads: GET whose path names no write operation, and POST whose path
// names a read or an authentication step and no write. PUT, PATCH and DELETE are never probed.
//
// # Catalogue row
//
// Burp's catalogue has no NoSQL injection row. "NoSQL injection" is burpsy's own row (BurpsyNativeRows,
// advisory native/b5002000_*.json, CWE-943) and the check rides the "Server-side JavaScript code
// injection" descriptor behind its own switch, check_nosql_injection.

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
	"github.com/burpsy-go/burpsy/internal/core"
)

// nosqliIssue is burpsy's own row name; see BurpsyNativeRows.
const nosqliIssue = "NoSQL injection"

// nosqliEnabled is the check's own switch.
func nosqliEnabled(c *ScanConfig) bool { return c != nil && c.CheckNoSQLInjection }

const (
	// nosqliMaxSites bounds the parameters probed with operators, and nosqliMaxPoints the string
	// points probed with syntax payloads, per audited request.
	nosqliMaxSites  = 6
	nosqliMaxPoints = 6
	// nosqliMaxSends bounds every request the check sends for one audited request.
	nosqliMaxSends = 220
)

var errNoSQLiBudget = errors.New("nosqli: request budget spent")

// ssjsOrNoSQLi runs the "Server-side JavaScript code injection" row's own check (behind
// CheckActiveInjection) and the NoSQL injection check (behind CheckNoSQLInjection). A proven NoSQL
// finding is returned even when the sibling's run was undecided.
func ssjsOrNoSQLi(ssjs CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil {
			return nil, nil
		}
		// The row's own check runs unless the NoSQL switch alone admitted the descriptor, so a run
		// with neither switch (a direct call) still gets the row's own verdict, including its
		// could-not-probe error, exactly as before this rider existed.
		var sf []*Finding
		var serr error
		if injectionChecksEnabled(cc.Config) || !nosqliEnabled(cc.Config) {
			sf, serr = ssjs(ctx, cc)
		}
		var nf []*Finding
		var nerr error
		if nosqliEnabled(cc.Config) {
			nf, nerr = checkNoSQLInjection(ctx, cc)
		}
		switch {
		case len(nf) > 0:
			return append(sf, nf...), nil
		case serr != nil:
			return sf, serr
		case nerr != nil:
			return sf, nerr
		}
		return sf, nil
	}
}

// checkNoSQLInjection probes one audited request.
func checkNoSQLInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, fmt.Errorf("nosqli: no scanner or exchange: %w", errCapabilityMissing)
	}
	if cc.Scanner.sender == nil {
		// Could not look: an error the engine counts as a refusal, never a clean nil.
		return nil, fmt.Errorf("nosqli: no sender; an active probe cannot be sent: %w", errCapabilityMissing)
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" || !nosqliReadOnly(raw) {
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
	skip := map[string]bool{}
	for _, n := range cc.SkipServerSideParams {
		skip[n] = true
	}
	sites := nosqliOperatorSites(raw, kinds, skip)
	pre, _ := bcheck.EnumerateWith([]byte(raw), kinds, cc.ProbeEnumerateOptions())
	if len(sites) == 0 && len(nosqliStringPoints(pre)) == 0 {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, kinds)
	if err != nil {
		return nil, fmt.Errorf("nosqli: %w", err)
	}
	p := &nosqliProber{cc: cc, h: h, raw: raw}
	return p.run(ctx, sites, nosqliStringPoints(h.Points()))
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------

type nosqliProber struct {
	cc    *CheckContext
	h     *ProbeHarness
	raw   string
	sends int
	// masks are every random value this run has sent, removed from every response before comparison.
	masks []string
}

func (p *nosqliProber) send(ctx context.Context, raw string) (ProbeResponse, error) {
	if p.sends >= nosqliMaxSends {
		return ProbeResponse{}, errNoSQLiBudget
	}
	p.sends++
	return p.h.send(ctx, []byte(raw))
}

// fresh is a new random value, registered for masking. Letters only, so it survives every encoding
// unchanged and never reads as a number.
func (p *nosqliProber) fresh(n int) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.IntN(len(alphabet))]
	}
	s := string(b)
	p.masks = append(p.masks, s)
	return s
}

func (p *nosqliProber) run(ctx context.Context, sites []nosqliSite, points []bcheck.InsertionPoint) ([]*Finding, error) {
	if len(sites) > nosqliMaxSites {
		sites = sites[:nosqliMaxSites]
	}
	if len(points) > nosqliMaxPoints {
		points = points[:nosqliMaxPoints]
	}
	var failures []string
	note := func(err error) bool {
		failures = append(failures, err.Error())
		return errors.Is(err, errNoSQLiBudget)
	}
	for _, s := range sites {
		f, err := p.operator(ctx, s)
		if err != nil {
			if note(err) {
				break
			}
			continue
		}
		if f != nil {
			return []*Finding{f}, nil
		}
	}
	for _, pt := range points {
		f, err := p.syntax(ctx, pt)
		if err != nil {
			if note(err) {
				break
			}
			continue
		}
		if f != nil {
			return []*Finding{f}, nil
		}
	}
	if len(failures) > 0 {
		return nil, fmt.Errorf("nosqli: %s", strings.Join(failures, "; "))
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// response comparison
// ---------------------------------------------------------------------------

// nosqliView is what two responses must share to count as the same answer.
type nosqliView struct {
	status   int
	location string
	cookies  string
	body     string
}

var (
	nosqliVolatileHex    = regexp.MustCompile(`[0-9a-fA-F]{16,}`)
	nosqliVolatileDigits = regexp.MustCompile(`[0-9]{6,}`)
)

func (p *nosqliProber) mask(s string) string {
	for _, m := range p.masks {
		s = strings.ReplaceAll(s, m, "\x00r")
	}
	s = nosqliVolatileHex.ReplaceAllString(s, "\x00h")
	return nosqliVolatileDigits.ReplaceAllString(s, "\x00d")
}

func (p *nosqliProber) view(r ProbeResponse) nosqliView {
	head, _, _ := strings.Cut(string(r.Raw), "\r\n\r\n")
	var names []string
	for _, sc := range headerValues(head, "set-cookie") {
		n, _, _ := strings.Cut(sc, "=")
		names = append(names, strings.TrimSpace(n))
	}
	sort.Strings(names)
	return nosqliView{
		status:   r.Status,
		location: p.mask(headerValue(head, "location")),
		cookies:  strings.Join(names, ","),
		body:     p.mask(r.Body),
	}
}

// same compares two responses under the masks registered so far (the later probe's random value is
// registered before either is compared, so masking is symmetric).
func (p *nosqliProber) same(a, b ProbeResponse) bool { return p.view(a) == p.view(b) }

func nosqliShort(r ProbeResponse) string {
	return fmt.Sprintf("HTTP %d, %s", r.Status, excerpt(r.Body, 0, 100))
}

// ---------------------------------------------------------------------------
// MongoDB error signatures
// ---------------------------------------------------------------------------

// nosqliErrorSignatures are error texts only a document store's server, driver or ODM produces:
// MongoDB, Elasticsearch (query_string / Lucene parsing) and CouchDB (Mango selectors). A bare
// "SyntaxError" is not here: any Node JSON parser produces one.
var nosqliErrorSignatures = []struct {
	re     *regexp.Regexp
	engine string
}{
	{regexp.MustCompile(`MongoServerError`), "MongoDB"},
	{regexp.MustCompile(`\bMongoError\b`), "MongoDB"},
	{regexp.MustCompile(`Mongo(Query|Command|Write|Cursor)Exception`), "MongoDB"},
	{regexp.MustCompile(`com\.mongodb\.[A-Za-z]`), "MongoDB"},
	{regexp.MustCompile(`MongoDB\\+Driver\\+Exception`), "MongoDB"},
	{regexp.MustCompile(`pymongo\.errors\.`), "MongoDB"},
	{regexp.MustCompile(`CastError: Cast to \w+ failed`), "MongoDB"},
	{regexp.MustCompile(`\bBSON(Type)?Error\b`), "MongoDB"},
	{regexp.MustCompile(`unknown operator: \$\w+`), "MongoDB"},
	{regexp.MustCompile(`\$where[^\n]{0,80}(SyntaxError|JavaScript execution failed)`), "MongoDB"},
	{regexp.MustCompile(`JavaScript execution failed`), "MongoDB"},
	{regexp.MustCompile(`Executor error during find command`), "MongoDB"},
	{regexp.MustCompile(`\$regex has to be a string`), "MongoDB"},
	{regexp.MustCompile(`query_shard_exception|search_phase_execution_exception`), "Elasticsearch"},
	{regexp.MustCompile(`Failed to parse query \[`), "Elasticsearch"},
	{regexp.MustCompile(`org\.elasticsearch\.[a-z]`), "Elasticsearch"},
	{regexp.MustCompile(`Cannot parse '[^'\n]{0,200}': (Encountered|Lexical error)`), "Elasticsearch"},
	{regexp.MustCompile(`"error"\s*:\s*"(invalid_selector|invalid_operator|no_usable_index)"`), "CouchDB"},
	{regexp.MustCompile(`Invalid operator: \$\w+`), "CouchDB"},
}

// nosqliSignature is the first document-store error signature in body, or "".
func nosqliSignature(body string) string {
	for _, sig := range nosqliErrorSignatures {
		if m := sig.re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// nosqliEngine names the store a signature belongs to.
func nosqliEngine(sig string) string {
	for _, e := range nosqliErrorSignatures {
		if e.re.MatchString(sig) {
			return e.engine
		}
	}
	return "database"
}

// ---------------------------------------------------------------------------
// operator injection
// ---------------------------------------------------------------------------

// nosqliValue is what a site is set to: a plain string (op empty), or {op: arg} where arg is a
// string or a list of strings.
type nosqliValue struct {
	op   string
	arg  string
	list bool
}

func (v nosqliValue) json() any {
	if v.op == "" {
		return v.arg
	}
	if v.list {
		return map[string]any{v.op: []any{v.arg}}
	}
	return map[string]any{v.op: v.arg}
}

// nosqliSite is one parameter that can be re-sent as an operator object.
type nosqliSite struct {
	where string // "JSON field", "query parameter", "body parameter"
	name  string
	json  bool
	build func(v nosqliValue) (string, error)
}

// render is how a value at this site reads in a finding.
func (s nosqliSite) render(v nosqliValue) string {
	if s.json {
		b, _ := json.Marshal(v.json())
		return fmt.Sprintf("%q: %s", s.name, b)
	}
	switch {
	case v.op == "":
		return s.name + "=" + v.arg
	case v.list:
		return s.name + "[" + v.op + "][]=" + v.arg
	}
	return s.name + "[" + v.op + "]=" + v.arg
}

func (p *nosqliProber) sendValue(ctx context.Context, s nosqliSite, v nosqliValue) (ProbeResponse, error) {
	raw, err := s.build(v)
	if err != nil {
		return ProbeResponse{}, err
	}
	return p.send(ctx, raw)
}

// operator decides one site. A nil finding and nil error is "not shown".
func (p *nosqliProber) operator(ctx context.Context, s nosqliSite) (*Finding, error) {
	type probe struct {
		v nosqliValue
		r ProbeResponse
	}
	var sent []probe
	get := func(v nosqliValue) (ProbeResponse, error) {
		r, err := p.sendValue(ctx, s, v)
		if err == nil {
			sent = append(sent, probe{v, r})
		}
		return r, err
	}
	t1, err := get(nosqliValue{op: "$ne", arg: p.fresh(10)})
	if err != nil {
		return nil, err
	}
	f1v := nosqliValue{op: "$eq", arg: p.fresh(10)}
	f1, err := get(f1v)
	if err != nil {
		return nil, err
	}
	// The TRUE answer is a match: a success or a redirect. A 4xx or 5xx for the always-true operator
	// is the endpoint refusing it (an operator allowlist, a type check), not evaluating it.
	if p.same(t1, f1) || t1.Status >= 400 {
		return p.operatorError(ctx, s, f1v, f1)
	}
	plain, err := get(nosqliValue{arg: p.fresh(10)})
	if err != nil {
		return nil, err
	}
	if !p.same(f1, plain) {
		return p.operatorError(ctx, s, f1v, f1)
	}
	// The rest of round one, then round two with fresh values. Every TRUE probe must answer like t1,
	// every FALSE probe and every plain string like plain.
	rounds := [][]struct {
		v      nosqliValue
		isTrue bool
	}{
		{
			{nosqliValue{op: "$gt", arg: ""}, true},
			{nosqliValue{op: "$in", arg: p.fresh(10), list: true}, false},
			{nosqliValue{arg: p.fresh(10)}, false},
		},
		{
			{nosqliValue{op: "$ne", arg: p.fresh(10)}, true},
			{nosqliValue{op: "$eq", arg: p.fresh(10)}, false},
			{nosqliValue{op: "$regex", arg: "^"}, true},
			{nosqliValue{op: "$in", arg: p.fresh(10), list: true}, false},
			{nosqliValue{arg: p.fresh(10)}, false},
		},
	}
	for _, round := range rounds {
		for _, pr := range round {
			r, err := get(pr.v)
			if err != nil {
				return nil, err
			}
			want := plain
			if pr.isTrue {
				want = t1
			}
			if !p.same(r, want) {
				return nil, nil
			}
		}
	}
	again, err := p.send(ctx, p.raw)
	if err != nil {
		return nil, err
	}
	if !p.same(again, p.h.Baseline()) {
		// The original no longer answers as it did: the page changed under the probes, so the
		// differential cannot be attributed to them.
		return nil, nil
	}
	var trues, falses []string
	for _, pr := range sent {
		if p.same(pr.r, t1) {
			trues = append(trues, s.render(pr.v))
		} else if pr.v.op != "" {
			falses = append(falses, s.render(pr.v))
		}
	}
	detail := fmt.Sprintf("The %s %q was re-sent as a MongoDB query operator object and the operator was "+
		"evaluated. The always-true operators (%s) each returned %s, while the never-true operators (%s) "+
		"returned the same response as an ordinary random value (%s). The set was sent twice with fresh "+
		"random values, two random values answered alike, every random value was masked out before the "+
		"comparison (so an echo cannot produce it), and the original request re-sent afterwards still "+
		"returned its original response. An endpoint that ignored the field, cast it to a string, echoed "+
		"it, or rejected every object would have answered the true and false operators alike.",
		s.where, s.name, strings.Join(trues, ", "), nosqliShort(t1), strings.Join(falses, ", "), nosqliShort(plain))
	return p.finding(s.name, fmt.Sprintf("%s -> HTTP %d; %s -> HTTP %d", s.render(sent[0].v), t1.Status,
		s.render(f1v), f1.Status), detail), nil
}

// operatorError is the error-based form: an unknown operator draws a MongoDB error that the valid
// {"$eq": random} control (already sent, as control) did not.
func (p *nosqliProber) operatorError(ctx context.Context, s nosqliSite, cv nosqliValue, control ProbeResponse) (*Finding, error) {
	if nosqliSignature(control.Body) != "" || nosqliSignature(p.h.Baseline().Body) != "" {
		return nil, nil
	}
	var sig string
	var first nosqliValue
	var firstR ProbeResponse
	for i := 0; i < 2; i++ {
		v := nosqliValue{op: "$" + p.fresh(8), arg: p.fresh(10)}
		r, err := p.sendValue(ctx, s, v)
		if err != nil {
			return nil, err
		}
		got := nosqliSignature(r.Body)
		if got == "" {
			return nil, nil
		}
		if i == 0 {
			sig, first, firstR = got, v, r
		}
	}
	engine := nosqliEngine(sig)
	detail := fmt.Sprintf("The %s %q was re-sent as a %s query operator object. An operator %s "+
		"does not define drew the database error %q (%s), twice with two different operator names, while "+
		"the valid operator %s drew no such error (%s) and neither did the original request. The object "+
		"reached the database query unchanged, so a client can supply query operators here; the response "+
		"does not show what a valid operator matches, which is why this rests on the error.",
		s.where, s.name, engine, engine, sig, nosqliShort(firstR), s.render(cv), nosqliShort(control))
	return p.finding(s.name, fmt.Sprintf("%s -> %s", s.render(first), sig), detail), nil
}

// ---------------------------------------------------------------------------
// syntax injection
// ---------------------------------------------------------------------------

// nosqliStringPoints keeps the query and body value points (form fields, JSON string values,
// multipart fields); headers, cookies and the path are not where a query filter is built from.
func nosqliStringPoints(pts []bcheck.InsertionPoint) []bcheck.InsertionPoint {
	var out []bcheck.InsertionPoint
	for _, pt := range pts {
		if pt.Kind == bcheck.IpQuery || pt.Kind == bcheck.IpBody {
			out = append(out, pt)
		}
	}
	return out
}

func (p *nosqliProber) sendAt(ctx context.Context, pt bcheck.InsertionPoint, payload string, appending bool) (ProbeResponse, error) {
	req, err := pt.Apply([]byte(p.raw), payload, appending)
	if err != nil {
		return ProbeResponse{}, err
	}
	return p.send(ctx, string(req))
}

func (p *nosqliProber) syntax(ctx context.Context, pt bcheck.InsertionPoint) (*Finding, error) {
	for _, q := range []string{"'", `"`} {
		f, err := p.syntaxBoolean(ctx, pt, q)
		if f != nil || err != nil {
			return f, err
		}
	}
	for _, br := range [][2]string{{"'", `\'`}, {`"`, `\"`}, {`\`, `\\`}, {"(", `\(`}} {
		f, err := p.syntaxError(ctx, pt, br[0], br[1])
		if f != nil || err != nil {
			return f, err
		}
	}
	return nil, nil
}

// syntaxBoolean closes a JavaScript string with q and appends an OR whose right side is a comparison
// of two random tokens: equal tokens make the clause true for every document, different ones leave
// it as false as the random value it starts with.
func (p *nosqliProber) syntaxBoolean(ctx context.Context, pt bcheck.InsertionPoint, q string) (*Finding, error) {
	build := func(equal bool) string {
		a := p.fresh(6)
		b := a
		if !equal {
			b = p.fresh(6)
		}
		return p.fresh(10) + q + "||" + q + a + q + "==" + q + b
	}
	tp := build(true)
	t1, err := p.sendAt(ctx, pt, tp, false)
	if err != nil {
		return nil, err
	}
	fp := build(false)
	f1, err := p.sendAt(ctx, pt, fp, false)
	if err != nil {
		return nil, err
	}
	if p.same(t1, f1) || t1.Status >= 400 {
		return nil, nil
	}
	plain, err := p.sendAt(ctx, pt, p.fresh(10), false)
	if err != nil {
		return nil, err
	}
	if !p.same(f1, plain) {
		return nil, nil
	}
	for _, step := range []struct {
		payload string
		isTrue  bool
	}{{build(true), true}, {build(false), false}, {p.fresh(10), false}} {
		r, err := p.sendAt(ctx, pt, step.payload, false)
		if err != nil {
			return nil, err
		}
		want := plain
		if step.isTrue {
			want = t1
		}
		if !p.same(r, want) {
			return nil, nil
		}
	}
	again, err := p.send(ctx, p.raw)
	if err != nil {
		return nil, err
	}
	if !p.same(again, p.h.Baseline()) {
		return nil, nil
	}
	detail := fmt.Sprintf("The %s %q is concatenated into a server-side JavaScript string, the "+
		"way a MongoDB $where clause is built. Closing the string with %s and adding an OR of two equal "+
		"random tokens (%s) returned %s; the same with two different tokens (%s) returned the same response "+
		"as an ordinary random value (%s). Each was repeated with fresh tokens and held, two random values "+
		"answered alike, every random value was masked out before the comparison (so an echo cannot "+
		"produce it), and the original request re-sent afterwards still returned its original response.",
		idorKindLabel(pt.Kind), pt.Name, q, tp, nosqliShort(t1), fp, nosqliShort(plain))
	return p.finding(pt.Name, fmt.Sprintf("%s=%s -> HTTP %d; %s=%s -> HTTP %d", pt.Name, tp, t1.Status,
		pt.Name, fp, f1.Status), detail), nil
}

// syntaxError appends a character that breaks a JavaScript string and requires a MongoDB error for
// it that the same character escaped (the repaired control) does not draw.
func (p *nosqliProber) syntaxError(ctx context.Context, pt bcheck.InsertionPoint, brk, repair string) (*Finding, error) {
	if nosqliSignature(p.h.Baseline().Body) != "" {
		return nil, nil
	}
	b1, err := p.sendAt(ctx, pt, brk, true)
	if err != nil {
		return nil, err
	}
	sig := nosqliSignature(b1.Body)
	if sig == "" {
		return nil, nil
	}
	r1, err := p.sendAt(ctx, pt, repair, true)
	if err != nil {
		return nil, err
	}
	if nosqliSignature(r1.Body) != "" {
		return nil, nil
	}
	b2, err := p.sendAt(ctx, pt, brk, true)
	if err != nil {
		return nil, err
	}
	if nosqliSignature(b2.Body) == "" {
		return nil, nil
	}
	detail := fmt.Sprintf("Appending %s to the %s %q drew the %s error %q (%s), again when "+
		"re-sent, while appending the escaped form %s drew no such error (%s) and the original request "+
		"carries none. The value is concatenated into a query the %s parses (a $where clause, a "+
		"query_string, a selector), so an attacker can rewrite the query's logic.",
		brk, idorKindLabel(pt.Kind), pt.Name, nosqliEngine(sig), sig, nosqliShort(b1), repair, nosqliShort(r1), nosqliEngine(sig))
	return p.finding(pt.Name, fmt.Sprintf("%s=%s%s -> %s", pt.Name, pt.BaseValue, brk, sig), detail), nil
}

func (p *nosqliProber) finding(param, evidence, detail string) *Finding {
	f := buildHeaderFinding(p.cc, nosqliIssue, "high", "firm", evidence, detail)
	f.Param = param
	f.Solution = "Never build a database query from a decoded value whose type the client chooses: cast every " +
		"query input to the type the field holds (a string stays a string, an object is refused), or use the " +
		"driver's filter sanitisation (Mongoose sanitizeFilter, express-mongo-sanitize). Do not concatenate " +
		"input into $where, mapReduce or $function JavaScript; express the condition with query operators " +
		"instead, and disable server-side JavaScript where it is not needed."
	return f
}

// ---------------------------------------------------------------------------
// sites
// ---------------------------------------------------------------------------

// nosqliOperatorSites lists the parameters that can be re-sent as operator objects: JSON string
// values (by their path, nested objects included), query parameters, and urlencoded form fields.
func nosqliOperatorSites(raw string, kinds []string, skip map[string]bool) []nosqliSite {
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	e, err := core.ParseRequestEdit([]byte(raw))
	if err != nil {
		return nil
	}
	var out []nosqliSite
	if want["body"] {
		ct := strings.ToLower(e.Header("content-type"))
		body := strings.TrimSpace(string(e.Body))
		switch {
		case strings.HasPrefix(body, "{"):
			out = append(out, nosqliJSONSites(raw, body, skip)...)
		case strings.Contains(ct, "x-www-form-urlencoded"):
			out = append(out, nosqliPairSites(raw, "body parameter", string(e.Body), skip, func(e *core.RequestEdit, s string) {
				e.Body = []byte(s)
			})...)
		}
	}
	if want["query"] && e.Query != "" {
		out = append(out, nosqliPairSites(raw, "query parameter", e.Query, skip, func(e *core.RequestEdit, s string) {
			e.Query = s
		})...)
	}
	return out
}

func nosqliPairSites(raw, where, encoded string, skip map[string]bool, set func(*core.RequestEdit, string)) []nosqliSite {
	pairs := splitRawQuery(encoded)
	var out []nosqliSite
	for i, pr := range pairs {
		name, err := url.QueryUnescape(pr.name)
		if err != nil || name == "" || strings.ContainsAny(name, "[]") || skip[name] {
			continue
		}
		i, name := i, name
		out = append(out, nosqliSite{where: where, name: name, build: func(v nosqliValue) (string, error) {
			e, err := core.ParseRequestEdit([]byte(raw))
			if err != nil {
				return "", err
			}
			ps := append([]rawParam(nil), pairs[:i]...)
			key := pairs[i].name
			switch {
			case v.op == "":
			case v.list:
				key += "[" + v.op + "][]"
			default:
				key += "[" + v.op + "]"
			}
			ps = append(ps, rawParam{key, url.QueryEscape(v.arg)})
			ps = append(ps, pairs[i+1:]...)
			set(e, joinRawQuery(ps))
			return string(e.ToRaw()), nil
		}})
	}
	return out
}

func nosqliJSONSites(raw, body string, skip map[string]bool) []nosqliSite {
	decode := func() (map[string]any, bool) {
		dec := json.NewDecoder(strings.NewReader(body))
		dec.UseNumber()
		var m map[string]any
		if dec.Decode(&m) != nil {
			return nil, false
		}
		return m, true
	}
	root, ok := decode()
	if !ok {
		return nil
	}
	var paths [][]string
	var walk func(m map[string]any, at []string)
	walk = func(m map[string]any, at []string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := append(append([]string(nil), at...), k)
			switch v := m[k].(type) {
			case string:
				if !skip[k] && !strings.HasPrefix(k, "$") {
					paths = append(paths, path)
				}
			case map[string]any:
				if len(path) < 4 {
					walk(v, path)
				}
			}
		}
	}
	walk(root, nil)
	var out []nosqliSite
	for _, path := range paths {
		path := path
		out = append(out, nosqliSite{where: "JSON field", name: strings.Join(path, "."), json: true,
			build: func(v nosqliValue) (string, error) {
				m, ok := decode()
				if !ok {
					return "", errors.New("nosqli: body no longer decodes")
				}
				cur := m
				for _, k := range path[:len(path)-1] {
					next, ok := cur[k].(map[string]any)
					if !ok {
						return "", errors.New("nosqli: JSON path moved")
					}
					cur = next
				}
				cur[path[len(path)-1]] = v.json()
				var b strings.Builder
				enc := json.NewEncoder(&b)
				enc.SetEscapeHTML(false)
				if err := enc.Encode(m); err != nil {
					return "", err
				}
				e, err := core.ParseRequestEdit([]byte(raw))
				if err != nil {
					return "", err
				}
				e.Body = []byte(strings.TrimSuffix(b.String(), "\n"))
				return string(e.ToRaw()), nil
			}})
	}
	return out
}

// ---------------------------------------------------------------------------
// the read-only gate
// ---------------------------------------------------------------------------

var (
	nosqliReadWords = map[string]bool{
		"login": true, "logon": true, "signin": true, "auth": true, "authenticate": true,
		"authentication": true, "session": true, "sessions": true, "token": true, "search": true,
		"find": true, "query": true, "lookup": true, "filter": true, "list": true, "get": true, "read": true,
		"view": true, "show": true, "fetch": true, "check": true, "verify": true, "validate": true,
		"browse": true, "count": true, "exists": true, "retrieve": true, "details": true, "info": true,
	}
	nosqliWriteWords = map[string]bool{
		"delete": true, "remove": true, "destroy": true, "update": true, "edit": true, "modify": true,
		"create": true, "add": true, "insert": true, "save": true, "set": true, "reset": true, "forgot": true,
		"change": true, "register": true, "signup": true, "upload": true, "transfer": true, "pay": true,
		"payment": true, "purchase": true, "checkout": true, "send": true, "invite": true, "approve": true,
		"reject": true, "cancel": true, "logout": true, "signout": true, "subscribe": true,
		"unsubscribe": true, "import": true, "write": true, "put": true, "patch": true, "submit": true,
		"grant": true, "revoke": true, "exec": true, "run": true, "drop": true, "purge": true, "merge": true,
		"move": true, "rename": true, "assign": true, "confirm": true, "activate": true, "deactivate": true,
	}
	nosqliCamel = regexp.MustCompile(`([a-z0-9])([A-Z])`)
)

// nosqliPathWords are the words of the request path: each segment split at punctuation and camelCase,
// and each segment with its punctuation removed (so sign-in also reads as signin).
func nosqliPathWords(raw string) []string {
	line, _, _ := strings.Cut(raw, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	path, _, _ := strings.Cut(parts[1], "?")
	if u, err := url.Parse(path); err == nil && u.Path != "" {
		path = u.Path
	}
	var words []string
	for _, seg := range strings.Split(path, "/") {
		seg = nosqliCamel.ReplaceAllString(seg, "${1} ${2}")
		ws := strings.FieldsFunc(strings.ToLower(seg), func(r rune) bool { return r < 'a' || r > 'z' })
		words = append(words, ws...)
		if len(ws) > 1 {
			words = append(words, strings.Join(ws, ""))
		}
	}
	return words
}

// nosqliReadOnly admits a GET whose path names no write, and a POST whose path names a read or an
// authentication step and no write. Every other method is refused.
func nosqliReadOnly(raw string) bool {
	line, _, _ := strings.Cut(raw, "\r\n")
	method, _, _ := strings.Cut(line, " ")
	words := nosqliPathWords(raw)
	read := false
	for _, w := range words {
		if nosqliWriteWords[w] {
			return false
		}
		read = read || nosqliReadWords[w]
	}
	switch strings.ToUpper(method) {
	case "GET":
		return true
	case "POST":
		return read
	}
	return false
}
