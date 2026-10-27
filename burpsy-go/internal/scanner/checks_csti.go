package scanner

// Client-side template injection (burpsy-react-ui-j1mk.39).
//
// The row is proved in the browser: a client-side template engine evaluates after the page's own
// script runs, so the served bytes never carry the result and an HTTP-only scanner cannot see it.
// The proof is a value only evaluation produces, read from the rendered DOM.
//
// # Why not 7*6
//
// The previous version planted {{7*6}} and looked for "42", which appears on its own: a result
// count, a price, a timestamp, an id. A page that printed "42 results" for any search term was
// reported as template injection, because the baseline (no fragment) had no "42" and the probe
// render did. The same weakness was fixed for the server-side evaluators in j1mk.34, and this check
// reuses that fix:
//
//   - every probe carries a fresh ArithmeticChallenge, whose nine- or ten-digit product is
//     effectively never present by chance;
//   - the product must appear neither in the payload nor in the baseline render;
//   - a hit is re-asked with a second, independent challenge, and only a second hit confirms. One
//     that does not reproduce is undecided (errCheckInconclusive), never clean and never a finding.
//
// # Client-side, not server-side
//
// A query parameter reaches the server too, and a server-side template engine produces the same
// product. For a server-reaching source the served response for the same URL is read as well: if it
// already carries the product, the evaluation happened on the server, which is the server-side
// template injection row's finding, not this one's. If the served response cannot be read, the hit
// is undecided. A page that ships the payload to its own API (an XHR or fetch carrying it) and
// renders the answer is treated the same way: the evaluator may be that API.
//
// # Engine families
//
//   - {{a*b}}: AngularJS 1.x and Vue interpolation. Plain arithmetic needs no sandbox escape in
//     either, so the probe is safe on every AngularJS version.
//   - [[a*b]]: the alternative interpolation delimiters (Polymer, and AngularJS/Vue configured with
//     custom symbols).
//   - ${a*b}: client-side rendering through JavaScript template literals.
//   - a*b, bare: an expression attribute (ng-bind, ng-init, v-text, x-text and their relatives)
//     evaluates its value without delimiters. Sent ONLY where the planted canary was seen inside
//     such an attribute, because a bare expression sent everywhere would report every page that
//     legitimately computes a sum the user typed (a calculator) as template injection.
//   - Mustache / Handlebars: these are logic-less and have no arithmetic, so the computed value is
//     a section evaluation instead: t1{{#z}}t2{{/z}}{{^z}}t3{{/z}}t4 renders as t1t3t4 when z is
//     undefined. Echo keeps the payload, a filter that strips {{...}} tags leaves t1t2t3t4, a
//     filter that strips whole blocks leaves t1t4; only an engine produces t1t3t4.

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
)

// cstiChallenge is one rendered probe: the payload, the value only evaluation produces, and a
// substring of the payload that identifies it in a request the page itself issues.
type cstiChallenge struct {
	payload  string
	expected string
	marker   string
}

// cstiForm is one engine family's expression syntax.
type cstiForm struct {
	family string
	// exprAttr limits the form to sources whose canary landed inside an expression attribute.
	exprAttr bool
	render   func() cstiChallenge
}

func cstiArithmetic(open, close string) func() cstiChallenge {
	return func() cstiChallenge {
		ch := NewArithmeticChallenge()
		return cstiChallenge{payload: open + ch.Expr() + close, expected: ch.Product(), marker: ch.Expr()}
	}
}

// cstiSection renders the Mustache/Handlebars section probe. The tokens are letters only so no
// part of the expected value can be mistaken for a number on the page.
func cstiSection() cstiChallenge {
	tok := func() string { return "bsy" + cstiLetters(8) }
	t1, t2, t3, t4, z := tok(), tok(), tok(), tok(), tok()
	return cstiChallenge{
		payload:  t1 + "{{#" + z + "}}" + t2 + "{{/" + z + "}}{{^" + z + "}}" + t3 + "{{/" + z + "}}" + t4,
		expected: t1 + t3 + t4,
		marker:   t1,
	}
}

// cstiLetters returns n random letters a-z.
func cstiLetters(n int) string {
	buf := make([]byte, n)
	if _, err := crand.Read(buf); err != nil {
		for i := range buf {
			buf[i] = byte(mrand.Intn(256))
		}
	}
	for i := range buf {
		buf[i] = 'a' + buf[i]%26
	}
	return string(buf)
}

func cstiForms() []cstiForm {
	return []cstiForm{
		{family: "AngularJS 1.x / Vue interpolation", render: cstiArithmetic("{{", "}}")},
		{family: "alternative interpolation delimiters", render: cstiArithmetic("[[", "]]")},
		{family: "JavaScript template literal", render: cstiArithmetic("${", "}")},
		{family: "expression attribute (ng-bind, v-text, x-text)", exprAttr: true, render: cstiArithmetic("", "")},
		{family: "Mustache / Handlebars section", render: cstiSection},
	}
}

// cstiExpressionAttributes are attributes whose value an engine evaluates without delimiters.
var cstiExpressionAttributes = map[string]bool{
	"ng-bind": true, "ng-bind-html": true, "ng-bind-template": true, "ng-init": true,
	"data-ng-bind": true, "data-ng-bind-html": true, "data-ng-init": true, "x-ng-bind": true,
	"v-text": true, "v-html": true, "x-text": true, "x-html": true,
}

// cstiCanaryInExpressionAttribute reports whether canary sits inside an expression attribute.
func cstiCanaryInExpressionAttribute(html, canary string) bool {
	if html == "" || !strings.Contains(html, canary) {
		return false
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return false
	}
	found := false
	doc.Find("*").EachWithBreak(func(_ int, s *goquery.Selection) bool {
		for _, a := range s.Nodes[0].Attr {
			if cstiExpressionAttributes[strings.ToLower(a.Key)] && strings.Contains(a.Val, canary) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// cstiSource is one place the payload is planted.
type cstiSource struct {
	label string
	// server reports whether the value reaches the server, which makes the served response a
	// second witness that has to be consulted.
	server bool
	build  func(value string) string
}

// cstiMaxQueryParams caps the query parameters probed per URL; each costs several renders.
const cstiMaxQueryParams = 8

// cstiSources returns the fragment and every query parameter of target (capped), and how many
// parameters the cap left out.
func cstiSources(target string) ([]cstiSource, int) {
	base, query := target, ""
	if i := strings.IndexByte(target, '#'); i >= 0 {
		base = target[:i]
	}
	if i := strings.IndexByte(base, '?'); i >= 0 {
		base, query = base[:i], base[i+1:]
	}
	withQuery := base
	if query != "" {
		withQuery += "?" + query
	}
	sources := []cstiSource{{
		label: "the URL fragment",
		build: func(v string) string {
			return withQuery + "#" + strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
		},
	}}
	if query == "" {
		return sources, 0
	}
	clauses := strings.Split(query, "&")
	skipped := 0
	for i, clause := range clauses {
		if clause == "" {
			continue
		}
		name := clause
		if j := strings.IndexByte(clause, '='); j >= 0 {
			name = clause[:j]
		}
		if len(sources)-1 >= cstiMaxQueryParams {
			skipped++
			continue
		}
		i, name := i, name
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		sources = append(sources, cstiSource{
			label:  fmt.Sprintf("the query parameter %q", decoded),
			server: true,
			build: func(v string) string {
				out := make([]string, len(clauses))
				copy(out, clauses)
				out[i] = name + "=" + url.QueryEscape(v)
				return base + "?" + strings.Join(out, "&")
			},
		})
	}
	return sources, skipped
}

// cstiRenderer is the slice of domexec.Browser this check uses, so its decision logic can be
// tested against simulated engines without a browser.
type cstiRenderer interface {
	RenderedDOMWithOptions(ctx context.Context, targetURL string, opts domexec.RenderOptions) (string, domexec.RenderOutcome, error)
}

// cstiEnv is everything the audit touches outside its own logic.
type cstiEnv struct {
	render cstiRenderer
	// served fetches the response body the server sends for targetURL; ok=false when it could not.
	served func(ctx context.Context, targetURL string) (body string, ok bool)
	// authorise refuses a navigation outside the engagement scope.
	authorise func(targetURL string) error
}

// cstiProof is a confirmed finding's evidence.
type cstiProof struct {
	source, family  string
	first, second   cstiChallenge
	servedConsulted bool
	paramsNotProbed int
}

// cstiOutcome is the audit's verdict.
type cstiOutcome struct {
	proof *cstiProof
	// undecided lists why a probe could not be decided; non-empty with no proof is not clean.
	undecided []string
	// failed counts renders that errored; a probe that never rendered decided nothing.
	failed  int
	renders int
}

func (o *cstiOutcome) undecide(format string, args ...any) {
	o.undecided = append(o.undecided, fmt.Sprintf(format, args...))
}

// cstiProbeResult is what one challenge's render showed.
type cstiProbeResult int

const (
	cstiNoEvaluation cstiProbeResult = iota
	cstiEvaluated
	cstiUndecided
)

// auditCSTI runs the check against target with the given expression forms (cstiForms in a scan).
func auditCSTI(ctx context.Context, env cstiEnv, target string, forms []cstiForm) (cstiOutcome, error) {
	var out cstiOutcome
	render := func(u string) (string, domexec.RenderOutcome, error) {
		if err := env.authorise(u); err != nil {
			return "", domexec.RenderOutcome{}, fmt.Errorf("not authorised: %w", err)
		}
		out.renders++
		html, oc, err := env.render.RenderedDOMWithOptions(ctx, u, domexec.RenderOptions{})
		if err != nil {
			out.failed++
		}
		return html, oc, err
	}

	baseline, _, err := render(target)
	if err != nil {
		return out, fmt.Errorf("client-side template injection: baseline render of %s failed: %w", target, err)
	}

	sources, skipped := cstiSources(target)
	for _, src := range sources {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		// Reflection gate: a value that never reaches the document or the served template cannot
		// be evaluated by a template engine there, so the payloads are not spent on it.
		canary := domCanary("t")
		u := src.build(canary)
		dom, _, err := render(u)
		if err != nil {
			out.undecide("%s: canary render failed: %v", src.label, err)
			continue
		}
		served := ""
		if src.server {
			served, _ = env.served(ctx, u)
		}
		if !strings.Contains(dom, canary) && !strings.Contains(served, canary) {
			continue
		}
		exprAttr := cstiCanaryInExpressionAttribute(dom, canary) || cstiCanaryInExpressionAttribute(served, canary)

		for _, form := range forms {
			if form.exprAttr && !exprAttr {
				continue
			}
			first, res := cstiProbe(ctx, env, &out, render, src, form, baseline)
			if res != cstiEvaluated {
				continue
			}
			second, res := cstiProbe(ctx, env, &out, render, src, form, baseline)
			if res != cstiEvaluated || second.payload == first.payload || second.expected == first.expected {
				out.undecide("%s, %s: %q rendered %q once but an independent second challenge did not reproduce it",
					src.label, form.family, first.payload, first.expected)
				continue
			}
			out.proof = &cstiProof{source: src.label, family: form.family, first: first, second: second,
				servedConsulted: src.server, paramsNotProbed: skipped}
			return out, nil
		}
	}
	return out, nil
}

// cstiProbe sends one fresh challenge and classifies the render.
func cstiProbe(ctx context.Context, env cstiEnv, out *cstiOutcome,
	render func(string) (string, domexec.RenderOutcome, error),
	src cstiSource, form cstiForm, baseline string) (cstiChallenge, cstiProbeResult) {

	// A challenge whose expected value the baseline already shows (or the payload spells) proves
	// nothing; draw again, a handful of times, before giving up honestly.
	var ch cstiChallenge
	ok := false
	for attempt := 0; attempt < 4; attempt++ {
		ch = form.render()
		if ch.expected != "" && !strings.Contains(ch.payload, ch.expected) && !strings.Contains(baseline, ch.expected) {
			ok = true
			break
		}
	}
	if !ok {
		out.undecide("%s, %s: no challenge could be drawn whose value was absent from the payload and the baseline", src.label, form.family)
		return ch, cstiUndecided
	}

	u := src.build(ch.payload)
	dom, oc, err := render(u)
	if err != nil {
		out.undecide("%s, %s: render failed: %v", src.label, form.family, err)
		return ch, cstiUndecided
	}
	if !strings.Contains(dom, ch.expected) {
		return ch, cstiNoEvaluation
	}
	// The page sent the payload to something and may have rendered that thing's answer.
	for _, r := range oc.Requests {
		if dec, err := url.QueryUnescape(r.URL); (err == nil && strings.Contains(dec, ch.marker)) || strings.Contains(r.URL, ch.marker) {
			out.undecide("%s, %s: the product rendered, but the page sent the payload to %s, which may be the evaluator", src.label, form.family, r.URL)
			return ch, cstiUndecided
		}
	}
	if src.server {
		served, ok := env.served(ctx, u)
		if !ok {
			out.undecide("%s, %s: the product rendered, but the served response could not be read to rule out server-side evaluation", src.label, form.family)
			return ch, cstiUndecided
		}
		if strings.Contains(served, ch.expected) {
			// Evaluated on the server: server-side template injection's finding, not this row's.
			return ch, cstiNoEvaluation
		}
	}
	return ch, cstiEvaluated
}

// checkClientSideTemplateInjection plants template expressions in the URL fragment and in each query
// parameter, and reports only a computed value the rendered DOM shows, twice, for independent
// challenges, that neither the payload nor the baseline nor the served response contains.
func checkClientSideTemplateInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Exchange == nil {
		return nil, nil
	}
	browser, err := cc.Browser(ctx)
	if err != nil {
		return nil, err
	}
	ex := cc.Exchange
	env := cstiEnv{
		render: gatedRenderer{browser: browser, scope: cc.Scanner.scope},
		served: func(ctx context.Context, target string) (string, bool) {
			uri, err := cstiRequestURI(target)
			if err != nil {
				return "", false
			}
			resp := cc.Scanner.sendTestRequestFull(ctx, ex, "GET", uri, nil)
			if resp == nil {
				return "", false
			}
			return string(resp.Body), true
		},
		authorise: func(target string) error { return cstiAuthorise(cc.Scanner.scope, ex, target) },
	}
	out, err := auditCSTI(ctx, env, exchangeURL(ex), cstiForms())
	if err != nil {
		return nil, err
	}
	if out.proof == nil {
		if len(out.undecided) > 0 {
			return nil, fmt.Errorf("client-side template injection: %d probe(s) undecided after %d render(s) (%d failed); first: %s: %w",
				len(out.undecided), out.renders, out.failed, out.undecided[0], errCheckInconclusive)
		}
		return nil, nil
	}
	p := out.proof
	where := "The fragment never reaches the server, so the evaluation is client-side by construction."
	if p.servedConsulted {
		where = "The served response for both URLs did not contain the value, so the evaluation happened in the browser, not on the server."
	}
	detail := fmt.Sprintf("Input from %s is evaluated by a client-side template engine (%s). "+
		"%q rendered as %s and an independent second challenge %q rendered as %s in the DOM read through the browser; "+
		"neither value is spelled by its payload or present in the baseline render. %s",
		p.source, p.family, p.first.payload, p.first.expected, p.second.payload, p.second.expected, where)
	if p.paramsNotProbed > 0 {
		detail += fmt.Sprintf(" %d further query parameter(s) were NOT probed: the per-URL cap of %d was reached.",
			p.paramsNotProbed, cstiMaxQueryParams)
	}
	return []*Finding{buildHeaderFinding(cc, "Client-side template injection", "high", "firm",
		p.first.payload+" -> "+p.first.expected, detail)}, nil
}

// cstiRequestURI is target's path and query, the part a request line carries.
func cstiRequestURI(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	uri := u.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	if u.RawQuery != "" {
		uri += "?" + u.RawQuery
	}
	return uri, nil
}

// cstiAuthorise refuses a navigation that leaves the exchange's origin or the engagement scope.
// The browser does not go through the probe sender, so the same request-line check the sender
// applies is applied here, on the request the navigation will actually send.
func cstiAuthorise(scope *core.Scope, ex *core.Exchange, target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	wantScheme := "http"
	if ex.TLS {
		wantScheme = "https"
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if u.Scheme != wantScheme || !strings.EqualFold(u.Hostname(), ex.Host) || port != strconv.Itoa(int(ex.Port)) {
		return errors.New("navigation leaves the audited exchange's origin")
	}
	if scope == nil {
		return nil
	}
	uri, err := cstiRequestURI(target)
	if err != nil {
		return err
	}
	return scope.AuthoriseRaw(ex.Host, ex.Port, ex.TLS, []byte("GET "+uri+" HTTP/1.1\r\nHost: "+ex.Host+"\r\n\r\n"))
}
